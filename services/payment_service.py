import logging
import httpx
import json
from typing import Dict, Optional, List, Any, Union
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type, before_sleep_log

logger = logging.getLogger(__name__)

class PaymentService:
    def __init__(self, lnbits_url: str, herd_key: str, cyberherd_key: str, hex_key: str = None, nos_sec: str = None):
        self.lnbits_url = lnbits_url
        self.herd_key = herd_key
        self.cyberherd_key = cyberherd_key
        self.hex_key = hex_key  # Public key for zaps
        self.nos_sec = nos_sec  # Private key for signing
        self.http_client = None
        
    async def initialize(self, http_client=None, sign_zap_event_func=None):
        """Initialize the service with an HTTP client and optional signing function"""
        if http_client:
            self.http_client = http_client
        else:
            self.http_client = httpx.AsyncClient(http2=True)
        
        # Store the signing function reference if provided
        self.sign_zap_event = sign_zap_event_func
        
    async def close(self):
        """Close the HTTP client if we own it"""
        if self.http_client and not self.http_client is httpx:
            await self.http_client.aclose()
            
    @retry(
        reraise=True,
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(httpx.RequestError)
    )
    async def get_balance(self) -> int:
        """Get wallet balance in millisatoshis"""
        try:
            response = await self.http_client.get(
                f'{self.lnbits_url}/api/v1/wallet',
                headers={'X-Api-Key': self.herd_key}
            )
            response.raise_for_status()
            return response.json()['balance']
                
        except httpx.HTTPError as e:
            logger.error(f"HTTP error retrieving balance: {e}")
            raise
        except Exception as e:
            logger.error(f"Error retrieving balance: {e}")
            raise
            
    @retry(
        reraise=True,
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type((httpx.HTTPError, httpx.ConnectError, httpx.TimeoutException)),
        before_sleep=before_sleep_log(logger, logging.WARNING)
    )
    async def create_invoice(self, amount: int, memo: str, wallet_key: str = None) -> Dict[str, Any]:
        """
        Create a Lightning invoice with proper schema.
        
        Args:
            amount: Invoice amount in sats
            memo: Description for invoice
            wallet_key: Optional wallet key to use (defaults to CYBERHERD_KEY)
            
        Returns:
            Dict with payment request and other details
        """
        key = wallet_key or self.cyberherd_key
        
        try:
            url = f"{self.lnbits_url}/api/v1/payments"
            headers = {
                "X-API-KEY": key,
                "Content-Type": "application/json"
            }
            data = {
                "out": False,
                "amount": amount,
                "unit": "sat",  # Required field per API schema
                "memo": memo,
                "internal": False
            }
            
            logger.debug(f"Creating invoice with data: {data}")
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(url, json=data, headers=headers)
                response.raise_for_status()
                result = response.json()
                logger.debug(f"Invoice created: {result}")
                return result
                
        except Exception as e:
            logger.error(f"Error creating invoice: {e}")
            raise
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.HTTPError, httpx.ConnectError, httpx.TimeoutException)),
        before_sleep=before_sleep_log(logger, logging.WARNING)
    )
    async def pay_invoice(self, payment_request: str, wallet_key: str = None) -> Dict[str, Any]:
        """
        Pay a Lightning invoice.
        
        Args:
            payment_request: The Lightning invoice to pay (BOLT11 format)
            wallet_key: Optional wallet key to use (defaults to HERD_KEY)
            
        Returns:
            Dict with payment status and details
        """
        key = wallet_key or self.herd_key
        headers = {"X-API-KEY": key, "Content-Type": "application/json"}
        data = {
            "out": True,
            "bolt11": payment_request,
            "unit": "sat"  # Add unit field per schema
        }
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.lnbits_url}/api/v1/payments",
                    headers=headers,
                    json=data
                )
                response.raise_for_status()
                result = response.json()
                
                # Validate response format - LNBits returns payment_hash on success
                if 'payment_hash' in result:
                    logger.info(f"Payment successful: {result.get('payment_hash')}")
                    return result
                else:
                    logger.warning(f"Unexpected payment response format: {result}")
                    return result
                
        except httpx.HTTPStatusError as e:
            if e.response.status_code >= 500:
                logger.error(f"LNBits server error: {e.response.status_code} - {e.response.text}")
            else:
                logger.error(f"HTTP error paying invoice: {e.response.status_code} - {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error paying invoice: {e}")
            raise
    
    @retry(
        reraise=True,
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(httpx.RequestError)
    )
    async def make_lnurl_payment(
        self,
        lud16: str,
        msat_amount: int,
        description: str = "",
        key: Optional[str] = None,
        event_id: Optional[str] = None,  # Added parameter for zapping specific notes
        relays: Optional[List[str]] = None  # Added parameter for relay selection
    ) -> Optional[dict]:
        """
        Send a payment to a LNURL address with enhanced zap support.
        
        Args:
            lud16: Lightning address to pay
            msat_amount: Amount in millisats
            description: Optional description/comment
            key: API key to use (defaults to HERD_KEY)
            event_id: Optional event ID to zap (for note-specific zaps)
            relays: Optional list of relays to include in zap request
            
        Returns:
            Payment response or None if failed
        """
        if key is None:
            key = self.herd_key
            
        try:
            local_headers = {
                "accept": "application/json",
                "X-API-KEY": key,
                "Content-Type": "application/json"
            }
            
            # First get the LNURL-pay parameters
            lnurl_scan_url = f"{self.lnbits_url}/api/v1/lnurlscan/{lud16}"
            logger.info(f"Scanning LNURL: {lnurl_scan_url}")
            lnurl_resp = await self.http_client.get(lnurl_scan_url, headers=local_headers)
            lnurl_resp.raise_for_status()
            lnurl_data = lnurl_resp.json()

            # Verify amount is within allowed range
            if not (lnurl_data["minSendable"] <= msat_amount <= lnurl_data["maxSendable"]):
                logger.error(
                    f"{lud16}: {msat_amount} msat is out of bounds "
                    f"(min: {lnurl_data['minSendable']}, max: {lnurl_data['maxSendable']})"
                )
                return None

            # Prepare payment payload
            payment_payload = {
                "callback": lnurl_data["callback"],
                "amount": msat_amount,
                "description_hash": lnurl_data["description_hash"],
                "description": description
            }

            # Add comment if allowed
            if lnurl_data.get("commentAllowed", 0) > 0:
                payment_payload["comment"] = description

            # Add Nostr zap data if supported with enhanced metadata
            if lnurl_data.get("allowsNostr") and lnurl_data.get("nostrPubkey") and self.sign_zap_event:
                zapped_pubkey = lnurl_data["nostrPubkey"]
                zapper_pubkey = self.hex_key
                
                # Use default relays if none provided
                default_relays = [
                    "wss://relay.damus.io", 
                    "wss://relay.nostr.band", 
                    "wss://nos.lol"
                ]
                selected_relays = relays or default_relays
                
                # Use the enhanced sign_zap_event function with all parameters
                signed_event = await self.sign_zap_event(
                    msat_amount=msat_amount,
                    zapper_pubkey=zapper_pubkey,
                    zapped_pubkey=zapped_pubkey,
                    private_key_hex=self.nos_sec,
                    content=description,
                    event_id=event_id,  # Pass the event ID if we're zapping a specific note
                    relays=selected_relays  # Pass the selected relays
                )
                
                payment_payload["nostr"] = json.dumps(signed_event)
                logger.info(f"Added NIP-57 zap request for {lud16}" + 
                           (f" on note {event_id[:8]}..." if event_id else ""))

            # Send the payment
            payment_url = f"{self.lnbits_url}/api/v1/payments/lnurl"
            logger.info(f"Sending LNURL payment to {payment_url}")
            pay_resp = await self.http_client.post(payment_url, headers=local_headers, json=payment_payload)
            pay_resp.raise_for_status()

            result = pay_resp.json()
            logger.info(f"LNURL payment successful: {result}")
            return result

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error {e.response.status_code}: {e.response.text}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in make_lnurl_payment: {e}")
            return None
    
    @retry(
        reraise=True,
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(httpx.RequestError)
    )
    async def fetch_cyberherd_targets(self) -> Dict[str, Any]:
        """Fetch CyberHerd payment splits targets from LNbits."""
        try:
            # Use the correct URL format - don't append cyberherd_key
            url = f"{self.lnbits_url}/splitpayments/api/v1/targets"
            logger.debug(f"Fetching CyberHerd targets from URL: {url}")
            
            headers = {
                "X-Api-Key": self.cyberherd_key,
                "Content-type": "application/json"
            }
            
            # Use the HTTP client directly
            response = await self.http_client.get(
                url,
                headers=headers,
                timeout=10.0
            )
            
            # Check if we got a valid response
            if response.status_code < 200 or response.status_code >= 300:
                logger.warning(f"Failed to fetch cyberherd targets: HTTP {response.status_code}")
                logger.debug(f"Response content: {response.text}")
                return {"targets": []}  # Return empty targets instead of None
            
            response_data = response.json()
            logger.debug(f"Fetched targets response: {response_data}")
            
            # Validate that the response contains targets
            if not isinstance(response_data, dict):
                logger.warning(f"Unexpected response type from LNbits: {type(response_data)}")
                return {"targets": []}
                
            # If no targets field, create it for consistent response format
            if "targets" not in response_data:
                logger.warning("No targets field in LNbits response, creating empty targets list")
                response_data["targets"] = []
                
            return response_data
                
        except httpx.RequestError as e:
            logger.error(f"Request error fetching cyberherd targets: {e}")
            return {"targets": []}  # Return empty targets instead of None
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error fetching cyberherd targets: {e}")
            return {"targets": []}  # Return empty targets instead of None
        except Exception as e:
            logger.error(f"Error fetching cyberherd targets: {e}")
            return {"targets": []}  # Return empty targets instead of None

    @retry(
        reraise=True,
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(httpx.RequestError)
    )
    async def update_cyberherd_targets(self, targets_data: Dict[str, Any]) -> bool:
        """Update CyberHerd payment targets in LNbits."""
        try:
            if not targets_data or not isinstance(targets_data, dict) or "targets" not in targets_data:
                logger.error(f"Invalid targets_data format: {targets_data}")
                return False
                
            # Ensure targets is a list
            if not isinstance(targets_data["targets"], list):
                logger.error(f"targets_data['targets'] is not a list: {type(targets_data['targets'])}")
                return False
                
            # Validate percentages add up to 100
            total_percent = sum(target.get("percent", 0) for target in targets_data["targets"])
            if total_percent != 100:
                logger.warning(f"Total percentage doesn't add up to 100: {total_percent}")
                # Fix the percentages if needed
                if targets_data["targets"] and total_percent > 0:
                    logger.info("Adjusting percentages to sum to 100")
                    # Normalize to 100%
                    scale_factor = 100 / total_percent
                    for target in targets_data["targets"]:
                        target["percent"] = round(target.get("percent", 0) * scale_factor)
                    
                    # Fix any rounding errors
                    remaining = 100 - sum(target.get("percent", 0) for target in targets_data["targets"])
                    if remaining != 0 and targets_data["targets"]:
                        targets_data["targets"][0]["percent"] += remaining
            
            # Use the correct URL format - don't append cyberherd_key
            url = f"{self.lnbits_url}/splitpayments/api/v1/targets"
            headers = {
                "X-Api-Key": self.cyberherd_key,
                "Content-type": "application/json"
            }
            
            logger.debug(f"Updating targets at {url} with data: {targets_data}")
            
            # Use the HTTP client directly
            response = await self.http_client.put(
                url,
                headers=headers,
                json=targets_data,
                timeout=15.0  # Increased timeout
            )
            
            # Check status code
            if response.status_code < 200 or response.status_code >= 300:
                response_text = response.text
                logger.error(f"Failed to update targets: HTTP {response.status_code}, Response: {response_text}")
                return False
                
            # Try to parse response as JSON if possible
            try:
                response_data = response.json()
                logger.debug(f"Update targets response: {response_data}")
            except ValueError:
                # If not JSON, just log the text
                response_text = response.text
                logger.debug(f"Non-JSON response: {response_text}")
                
            return True
                
        except httpx.RequestError as e:
            logger.error(f"Request error updating cyberherd targets: {e}")
            return False
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error updating cyberherd targets: {e}")
            return False
        except Exception as e:
            logger.error(f"Error updating cyberherd targets: {e}")
            return False

    async def zap_lud16(self, lud16: str, sats: int = 1, text: str = "CyberHerd Treats.", event_id: Optional[str] = None) -> Dict:
        """
        Send a zap to a Lightning address
        
        Args:
            lud16: Lightning address
            sats: Amount in sats
            text: Comment text
            event_id: Optional event ID to zap (for note-specific zaps)
            
        Returns:
            Dict with status and result
        """
        msat_amount = sats * 1000
        response = await self.make_lnurl_payment(
            lud16=lud16,
            msat_amount=msat_amount,
            description=text,
            key=self.herd_key,
            event_id=event_id  # Pass the event ID parameter
        )
        
        if response:
            return {"status": "success", "result": response}
        else:
            raise Exception("Failed to LNURL pay")
    
    @retry(
        reraise=True,
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(httpx.RequestError)
    )
    async def delete_cyberherd_targets(self) -> bool:
        """Delete all CyberHerd payment targets in LNbits."""
        try:
            # Simply replace with empty targets
            empty_targets = {"targets": []}
            logger.info("Deleting all CyberHerd targets")
            
            result = await self.update_cyberherd_targets(empty_targets)
            if result:
                logger.info("Successfully deleted all CyberHerd targets")
            else:
                logger.error("Failed to delete CyberHerd targets")
            
            return result
            
        except Exception as e:
            logger.error(f"Error deleting cyberherd targets: {e}")
            return False
