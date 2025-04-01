import logging
import httpx
import json
from typing import Dict, Optional, List, Any, Union
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type, before_sleep_log
import math # Import math for ceiling calculation
import time # Import time for timestamp calculation
import datetime

logger = logging.getLogger(__name__)

# Define common retry strategy for HTTP errors
http_retry_strategy = retry(
    reraise=True,
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=2, max=15),
    retry=retry_if_exception_type((httpx.RequestError, httpx.TimeoutException, httpx.ConnectError)),
    before_sleep=before_sleep_log(logger, logging.WARNING)
)

class PaymentService:
    def __init__(self, lnbits_url: str, herd_key: str, cyberherd_key: str, hex_key: str = None, nos_sec: str = None):
        if not lnbits_url:
            raise ValueError("LNBits URL is required.")
        if not herd_key or not cyberherd_key:
             raise ValueError("Both herd_key and cyberherd_key are required.")

        self.lnbits_url = lnbits_url.rstrip('/') # Ensure no trailing slash
        self.herd_key = herd_key
        self.cyberherd_key = cyberherd_key
        self.hex_key = hex_key  # Public key for zaps
        self.nos_sec = nos_sec  # Private key for signing
        self.http_client: Optional[httpx.AsyncClient] = None
        self.sign_zap_event = None
        self._we_own_client = False # Flag to track if we created the client
        self.logger = logger  # Use the module-level logger

    async def initialize(self, http_client: Optional[httpx.AsyncClient] = None, sign_zap_event_func = None):
        """Initialize the service with an HTTP client and optional signing function."""
        if http_client:
            self.http_client = http_client
            self._we_own_client = False
            self.logger.info("PaymentService initialized with provided HTTP client.")
        else:
            # If no client provided, create one
            self.http_client = httpx.AsyncClient(
                http2=True,
                timeout=30.0, # Set a default timeout
                limits=httpx.Limits(max_connections=100, max_keepalive_connections=20) # Sensible limits
            )
            self._we_own_client = True
            self.logger.info("PaymentService initialized with new internal HTTP client.")

        # Store the signing function reference if provided
        self.sign_zap_event = sign_zap_event_func

    async def close(self):
        """Close the HTTP client only if this instance created it."""
        if self.http_client and self._we_own_client:
            await self.http_client.aclose()
            self.logger.info("Closed internal HTTP client.")
        self.http_client = None # Clear reference

    @http_retry_strategy
    async def get_balance(self, wallet_key: Optional[str] = None) -> int:
        """Get wallet balance in millisatoshis."""
        key = wallet_key or self.herd_key
        if not self.http_client:
             raise RuntimeError("HTTP client not initialized. Call initialize() first.")

        try:
            url = f'{self.lnbits_url}/api/v1/wallet'
            headers = {'X-Api-Key': key}
            response = await self.http_client.get(url, headers=headers)
            response.raise_for_status()
            balance_msat = response.json().get('balance', 0)
            return int(balance_msat)

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error retrieving balance ({e.response.status_code}): {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"Error retrieving balance: {e}", exc_info=True)
            raise

    @http_retry_strategy
    async def create_invoice(self, amount: int, memo: str, wallet_key: Optional[str] = None) -> Dict[str, Any]:
        """Create a Lightning invoice."""
        if amount <= 0:
            raise ValueError("Invoice amount must be positive.")
        if not self.http_client:
             raise RuntimeError("HTTP client not initialized. Call initialize() first.")
        key = wallet_key or self.cyberherd_key

        try:
            url = f"{self.lnbits_url}/api/v1/payments"
            headers = {"X-API-KEY": key, "Content-Type": "application/json"}
            
            # Create request payload exactly as the LNBits API expects it
            data = {
                "out": False,      # False for invoice creation (incoming payment)
                "amount": amount,  # Amount in satoshis 
                "unit": "sat",     # Use 'sat' as the unit
                "memo": memo,      # Description/memo field
                "internal": False  # Not an internal payment
            }
            
            logger.debug(f"Creating invoice (key: ...{key[-4:]}) with data: {data}")
            response = await self.http_client.post(url, json=data, headers=headers)
            response.raise_for_status()
            
            # Parse and validate response
            result = response.json()
            logger.debug(f"LNBits invoice creation response: {result}")
            
            # Check for required fields in the LNBits response
            # This handles both older 'bolt11' field and newer 'payment_request' field
            required_fields = ['payment_hash', 'checking_id']
            missing_fields = []
            
            for field in required_fields:
                if field not in result:
                    missing_fields.append(field)
                    
            # Check either payment_request or bolt11 is present
            if 'payment_request' not in result and 'bolt11' not in result:
                missing_fields.append('payment_request/bolt11')
                
            if missing_fields:
                logger.error(f"LNBits create_invoice response missing fields: {missing_fields}. Got: {list(result.keys())}")
                raise ValueError(f"Invalid response from LNBits invoice creation: missing {', '.join(missing_fields)}")
            
            # Normalize response - LNBits sometimes returns 'bolt11' instead of 'payment_request'
            if 'bolt11' in result and 'payment_request' not in result:
                result['payment_request'] = result['bolt11']
                
            # Ensure checking_id is also copied to payment_hash if needed
            if 'checking_id' in result and ('payment_hash' not in result or not result['payment_hash']):
                result['payment_hash'] = result['checking_id']
                
            logger.info(f"Invoice created: hash={result['payment_hash'][:10]}...")
            return result
        
        except httpx.HTTPStatusError as e:
            error_body = e.response.text
            try:
                error_json = e.response.json()
                error_detail = error_json.get('detail', error_body)
            except:
                error_detail = error_body
                
            logger.error(f"HTTP error creating invoice ({e.response.status_code}): {error_detail}")
            raise Exception(f"Failed to create invoice: {error_detail}") from e
        except Exception as e:
            logger.error(f"Unexpected error creating invoice: {e}", exc_info=True)
            raise

    async def make_lnurl_payment(
        self, lud16: str, msat_amount: int, description: str = "",
        key: Optional[str] = None, event_id: Optional[str] = None,
        relays: Optional[List[str]] = None
    ) -> Optional[dict]:
        """Sends a payment to a LNURL address with enhanced zap support."""
        if not self.http_client:
             raise RuntimeError("HTTP client not initialized. Call initialize() first.")
        payment_key = key or self.herd_key

        try:
            local_headers = {"accept": "application/json", "X-API-KEY": payment_key, "Content-Type": "application/json"}
            lnurl_scan_url = f"{self.lnbits_url}/api/v1/lnurlscan/{lud16}"
            logger.info(f"Scanning LNURL: {lnurl_scan_url} with key ...{payment_key[-4:]}")
            lnurl_resp = await self.http_client.get(lnurl_scan_url, headers=local_headers)
            lnurl_resp.raise_for_status()
            lnurl_data = lnurl_resp.json()

            if not (lnurl_data["minSendable"] <= msat_amount <= lnurl_data["maxSendable"]):
                 logger.error(f"{lud16}: Amount {msat_amount} msat out of range ({lnurl_data['minSendable']}-{lnurl_data['maxSendable']})")
                 return None

            payment_payload = {"callback": lnurl_data["callback"], "amount": msat_amount, "description": description}
            if lnurl_data.get("commentAllowed", 0) > 0:
                 payment_payload["comment"] = description

            if lnurl_data.get("allowsNostr") and lnurl_data.get("nostrPubkey") and self.sign_zap_event and self.hex_key and self.nos_sec:
                 zapped_pubkey = lnurl_data["nostrPubkey"]
                 zapper_pubkey = self.hex_key
                 default_relays = ["wss://relay.damus.io", "wss://relay.nostr.band", "wss://nos.lol"]
                 selected_relays = relays or default_relays
                 signed_event = await self.sign_zap_event(
                     msat_amount=msat_amount, zapper_pubkey=zapper_pubkey, zapped_pubkey=zapped_pubkey,
                     private_key_hex=self.nos_sec, content=description, event_id=event_id, relays=selected_relays
                 )
                 payment_payload["nostr"] = json.dumps(signed_event)
                 logger.info(f"Added NIP-57 zap request for {lud16}" + (f" on note {event_id[:8]}..." if event_id else ""))

            payment_url = f"{self.lnbits_url}/api/v1/payments/lnurl"
            logger.info(f"Sending LNURL payment to {payment_url} via key ...{payment_key[-4:]}")
            pay_resp = await self.http_client.post(payment_url, headers=local_headers, json=payment_payload)
            pay_resp.raise_for_status()
            result = pay_resp.json()
            logger.info(f"LNURL payment submitted: {result}")
            return result
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error during LNURL payment ({e.response.status_code}): {e.response.text}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in make_lnurl_payment: {e}", exc_info=True)
            return None

    # --- CyberHerd Split Payment Methods ---

    @http_retry_strategy
    async def fetch_cyberherd_targets(self) -> Dict[str, Any]:
        """Fetch CyberHerd payment splits targets from LNbits using cyberherd_key."""
        if not self.http_client:
             raise RuntimeError("HTTP client not initialized. Call initialize() first.")

        url = f"{self.lnbits_url}/splitpayments/api/v1/targets"
        key = self.cyberherd_key # Explicitly use cyberherd_key
        headers = {"X-Api-Key": key, "Accept": "application/json"}
        logger.debug(f"Fetching CyberHerd targets from {url} using key ...{key[-4:]}")

        try:
            response = await self.http_client.get(url, headers=headers)
            response.raise_for_status() # Raise for 4xx/5xx
            response_data = response.json()
            logger.debug(f"Fetched targets response type: {type(response_data)}")

            # Handle different response formats - the API may return an array directly
            # or it might return an object with a "targets" key
            if isinstance(response_data, list):
                # If API returns a direct array, wrap it in the expected format
                logger.info(f"API returned direct array of {len(response_data)} targets, wrapping in 'targets' key")
                return {"targets": response_data}
            elif isinstance(response_data, dict) and "targets" in response_data:
                # If API returns the expected format, use it as is
                logger.debug(f"API returned expected format with 'targets' key, containing {len(response_data['targets'])} targets")
                return response_data
            else:
                # If format is unrecognized, return empty targets
                logger.warning(f"Unrecognized API response format: {type(response_data)}. Returning empty targets list.")
                return {"targets": []}

        except httpx.HTTPStatusError as e:
             # 404 might be valid if no targets set yet, return empty list
             if e.response.status_code == 404:
                  logger.info("No CyberHerd targets found (404), returning empty list.")
                  return {"targets": []}
             else:
                  logger.error(f"HTTP error fetching cyberherd targets ({e.response.status_code}): {e.response.text}")
                  # Propagate other errors
                  raise
        except (json.JSONDecodeError, TypeError) as e:
              logger.error(f"Error decoding LNbits response for fetch_cyberherd_targets: {e}")
              raise ValueError("Invalid JSON response from LNBits") from e
        except Exception as e:
            logger.error(f"Unexpected error fetching cyberherd targets: {e}", exc_info=True)
            raise # Re-raise unexpected errors


    @http_retry_strategy
    async def update_cyberherd_targets(self, targets_data: Dict[str, Any]) -> bool:
        """Update CyberHerd payment targets in LNbits using cyberherd_key."""
        if not self.http_client:
             raise RuntimeError("HTTP client not initialized. Call initialize() first.")
        if not isinstance(targets_data, dict) or "targets" not in targets_data or not isinstance(targets_data["targets"], list):
             logger.error(f"Invalid targets_data format provided: {targets_data}")
             return False

        key = self.cyberherd_key # Explicitly use cyberherd_key
        url = f"{self.lnbits_url}/splitpayments/api/v1/targets"
        headers = {"X-Api-Key": key, "Content-type": "application/json"}

        # --- Percentage Validation and Normalization ---
        try:
            # Validate entries and calculate total percentage
            total_percent = 0
            valid_targets = []
            for target in targets_data["targets"]:
                 if isinstance(target, dict) and "wallet" in target and "percent" in target:
                      try:
                           percent = int(target["percent"]) # Ensure integer
                           if percent < 0:
                                logger.warning(f"Target percentage cannot be negative: {target}. Skipping.")
                                continue
                           target["percent"] = percent # Store validated int
                           total_percent += percent
                           valid_targets.append(target)
                      except (ValueError, TypeError):
                           logger.warning(f"Invalid percent value for target: {target}. Skipping.")
                           continue
                 else:
                      logger.warning(f"Invalid target format: {target}. Skipping.")
                      continue

            # If no valid targets left, update with empty list
            if not valid_targets:
                 logger.warning("No valid targets found in input, attempting to update with empty list.")
                 targets_payload = {"targets": []}
            # Normalize if total is not 100 (and > 0)
            elif total_percent != 100 and total_percent > 0:
                logger.warning(f"Target percentages sum to {total_percent}%, normalizing to 100%.")
                scale = 100.0 / total_percent
                normalized_sum = 0
                for i, target in enumerate(valid_targets):
                     # Use floor for all but last to avoid exceeding 100 due to rounding up
                     if i < len(valid_targets) - 1:
                          target["percent"] = math.floor(target["percent"] * scale)
                     else:
                          # Assign remainder to the last target
                          target["percent"] = 100 - normalized_sum
                     normalized_sum += target["percent"]
                # Final check (should theoretically always be 100 now)
                if normalized_sum != 100:
                     logger.error(f"Normalization failed, sum is {normalized_sum}. Aborting update.")
                     return False
                targets_payload = {"targets": valid_targets}
            elif total_percent == 100:
                 targets_payload = {"targets": valid_targets}
            else: # total_percent is 0 or negative (latter shouldn't happen with validation)
                 logger.info("Total percentage is 0, updating with empty list.")
                 targets_payload = {"targets": []}

        except Exception as e:
             logger.error(f"Error during target validation/normalization: {e}", exc_info=True)
             return False
        # --- End Percentage Logic ---

        logger.debug(f"Attempting to update targets at {url} with payload: {targets_payload}")
        try:
            response = await self.http_client.put(url, headers=headers, json=targets_payload)
            response.raise_for_status() # Raise for 4xx/5xx
            logger.info(f"Successfully updated CyberHerd targets. Response status: {response.status_code}")
            return True
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error updating cyberherd targets ({e.response.status_code}): {e.response.text}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error updating cyberherd targets: {e}", exc_info=True)
            return False


    @http_retry_strategy
    async def delete_cyberherd_targets(self) -> bool:
        """Delete all CyberHerd payment targets in LNbits by setting an empty list."""
        logger.info("Attempting to delete all CyberHerd targets.")
        return await self.update_cyberherd_targets({"targets": []})


    async def zap_lud16(self, lud16: str, sats: int = 1, text: str = "CyberHerd Treats.", event_id: Optional[str] = None) -> Dict:
        """Send a zap to a Lightning address."""
        if sats <= 0:
             raise ValueError("Zap amount must be positive.")
        msat_amount = sats * 1000
        response = await self.make_lnurl_payment(
            lud16=lud16, msat_amount=msat_amount, description=text,
            key=self.herd_key, # Use herd_key for zapping *out*
            event_id=event_id
        )
        if response:
            # Check LNBits response for potential errors even if status code was 2xx
            if isinstance(response, dict) and response.get("status") == "ERROR":
                error_msg = response.get("reason", "Unknown error from LNBits during zap.")
                logger.error(f"Zap failed (LNBits Error): {error_msg}")
                raise Exception(f"Zap failed: {error_msg}")
            return {"status": "success", "result": response}
        else:
            # make_lnurl_payment returning None indicates failure
            raise Exception("Failed to send LNURL payment (zap). Check logs for details.")


    # --- L402 Relevant Methods ---

    @http_retry_strategy
    async def get_invoice_preimage(self, payment_hash: str, wallet_key: Optional[str] = None) -> Optional[str]:
        """Get the preimage for a paid invoice from LNBits."""
        if not payment_hash:
            self.logger.warning("get_invoice_preimage called with empty payment_hash")
            return None
        if not self.http_client:
             raise RuntimeError("HTTP client not initialized. Call initialize() first.")
        key = wallet_key or self.cyberherd_key

        url = f"{self.lnbits_url}/api/v1/payments/{payment_hash}"
        headers = {"X-Api-Key": key, "Accept": "application/json"}
        self.logger.debug(f"Attempting to get payment details for {payment_hash} using key ...{key[-4:]} at {url}")

        try:
            response = await self.http_client.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                self.logger.debug(f"Payment data received for {payment_hash}: {data}")
                if data.get("paid"):
                    preimage = data.get("details", {}).get("preimage")
                    if preimage and isinstance(preimage, str) and len(preimage) == 64:
                        self.logger.info(f"Preimage found for paid invoice {payment_hash}")
                        return preimage
                    else:
                        self.logger.warning(f"Invoice {payment_hash} paid, but preimage missing/invalid: {data.get('details')}")
                        return None
                else:
                    self.logger.info(f"Invoice {payment_hash} found but not paid yet.")
                    return None
            elif response.status_code == 404:
                 self.logger.warning(f"Invoice {payment_hash} not found using key ...{key[-4:]}.")
                 return None
            else:
                response.raise_for_status()
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error getting payment details for {payment_hash} ({e.response.status_code}): {e.response.text}")
            return None
        except (json.JSONDecodeError, TypeError, KeyError) as e:
             logger.error(f"Error processing LNBits response for {payment_hash}: {e}", exc_info=True)
             return None
        except Exception as e:
            logger.error(f"Unexpected error getting preimage for {payment_hash}: {e}", exc_info=True)
            return None
        return None

    @http_retry_strategy
    async def check_payment_status(self, payment_hash: str, wallet_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Check the status of a Lightning payment using its hash."""
        if not payment_hash:
            self.logger.warning("check_payment_status called with empty payment_hash")
            return None
        if not self.http_client:
             raise RuntimeError("HTTP client not initialized. Call initialize() first.")
        key = wallet_key or self.cyberherd_key

        url = f"{self.lnbits_url}/api/v1/payments/{payment_hash}"
        headers = {"X-Api-Key": key, "Accept": "application/json"}
        self.logger.debug(f"Checking payment status for {payment_hash} using key ...{key[-4:]} at {url}")

        try:
            response = await self.http_client.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                self.logger.debug(f"Payment status data received for {payment_hash}: {data}")
                data['settled'] = data.get('paid', False) # Add 'settled' field
                return data
            elif response.status_code == 404:
                self.logger.warning(f"Payment {payment_hash} not found using key ...{key[-4:]}.")
                return None
            else:
                 response.raise_for_status()
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error checking payment status for {payment_hash} ({e.response.status_code}): {e.response.text}")
            return None
        except (json.JSONDecodeError, TypeError) as e:
             logger.error(f"Error processing LNBits response for {payment_hash}: {e}", exc_info=True)
             return None
        except Exception as e:
            self.logger.error(f"Unexpected error checking payment status for {payment_hash}: {e}", exc_info=True)
            return None
        return None

    @http_retry_strategy
    async def decode_invoice(self, bolt11: str) -> Optional[Dict[str, Any]]:
        """Decode a BOLT11 invoice using LNBits."""
        if not bolt11:
            self.logger.warning("decode_invoice called with empty invoice string.")
            return None
        if not self.http_client:
             raise RuntimeError("HTTP client not initialized. Call initialize() first.")
        key = self.herd_key
        url = f"{self.lnbits_url}/api/v1/payments/decode"
        headers = {"X-Api-Key": key, "Content-Type": "application/json"}
        payload = {"data": bolt11}

        try:
            response = await self.http_client.post(url, headers=headers, json=payload)
            if response.status_code == 200:
                data = response.json()
                self.logger.debug(f"Successfully decoded invoice: {data.get('payment_hash', 'N/A')}")
                return data
            else:
                 error_detail = response.text
                 try: error_detail = response.json().get("detail", error_detail)
                 except Exception: pass
                 self.logger.warning(f"Failed to decode invoice via LNBits ({response.status_code}): {error_detail}")
                 return None
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error decoding invoice ({e.response.status_code}): {e.response.text}")
            return None
        except (json.JSONDecodeError, TypeError) as e:
             logger.error(f"Error processing LNBits decode response: {e}", exc_info=True)
             return None
        except Exception as e:
            self.logger.error(f"Unexpected error decoding invoice: {e}", exc_info=True)
            return None

    @http_retry_strategy
    async def get_recent_payments(self, wallet_key: str = None, limit: int = 50, offset: int = 0, hours_ago: int = 24) -> List[Dict[str, Any]]:
        """
        Retrieve recent payments from a wallet.
        """
        wallet_key = wallet_key or self.herd_key
        self.logger.info(f"Retrieving recent payments (limit={limit}, hours_ago={hours_ago})")
        
        # Calculate timestamp for filtering (milliseconds)
        since_timestamp = int((time.time() - (hours_ago * 3600)) * 1000)
        
        try:
            # LNBits API endpoint for listing payments
            url = f"{self.lnbits_url}/api/v1/payments"
            
            # Headers with wallet key for authentication
            headers = {
                "X-Api-Key": wallet_key,
                "Content-Type": "application/json"
            }
            
            # Query parameters
            params = {
                "limit": limit,
                "offset": offset,
            }
            
            self.logger.debug(f"Requesting payments from: {url}")
            response = await self.http_client.get(url, headers=headers, params=params)
            response.raise_for_status()
            
            # Parse response data
            response_data = response.json()
            self.logger.debug(f"Response status code: {response.status_code}")
            
            # Determine format - LNBits API can return array or object with 'payments' array
            if isinstance(response_data, list):
                payments = response_data
                self.logger.debug(f"Response contains a list of {len(payments)} payments")
            elif isinstance(response_data, dict) and "payments" in response_data:
                payments = response_data.get("payments", [])
                self.logger.debug(f"Response contains a dict with {len(payments)} payments")
            else:
                self.logger.warning(f"Unexpected response format: {type(response_data)}")
                payments = []
            
            # Filter out to only include recent payments (since LNBits API might not filter by date)
            recent_payments = []
            for payment in payments:
                payment_time = payment.get("time", 0)
                payment_amount = payment.get("amount", 0)
                
                # Include only incoming payments within the time window
                if payment_time >= since_timestamp/1000 and payment_amount > 0:
                    payment_hash = payment.get('checking_id') or payment.get('payment_hash', 'unknown')
                    payment_time_str = datetime.datetime.fromtimestamp(payment_time).strftime('%Y-%m-%d %H:%M:%S') if payment_time else 'unknown'
                    self.logger.debug(f"Including payment: {payment_hash[:8]}... ({payment_amount/1000} sats) from {payment_time_str}")
                    recent_payments.append(payment)
                elif payment_amount <= 0:
                    self.logger.debug(f"Skipping outgoing payment: {payment.get('checking_id', 'unknown')[:8]}... ({payment_amount/1000} sats)")
                elif payment_time < since_timestamp/1000:
                    self.logger.debug(f"Skipping old payment: {payment.get('checking_id', 'unknown')[:8]}... (time: {payment_time}, cutoff: {since_timestamp/1000})")
            
            self.logger.info(f"Found {len(recent_payments)} recent incoming payments in the last {hours_ago} hours")
            return recent_payments
            
        except Exception as e:
            self.logger.error(f"Error retrieving recent payments: {e}", exc_info=True)
            return []