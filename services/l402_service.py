import base64
import secrets
import time
import logging
import json
import pytz
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple
from fastapi import HTTPException, Request
from pymacaroons import Macaroon, Verifier # Ensure Verifier is imported

# Import specific utils needed
from utils.l402_utils import (
    create_lsat_macaroon,
    create_challenge_header,
    decode_lsat_header, # Use the specific header decoder
    verify_lsat_preimage, # Use the specific preimage verifier
    get_payment_hash_from_invoice, # Keep this for the helper method
    format_macaroon_for_header,
    create_token_id,
    validate_token_expiry_ts # Use timestamp version
)

# Assume PaymentService and DatabaseService are imported correctly elsewhere
# from services.payment_service import PaymentService
# from services.database_service import DatabaseService
# from services.messaging_service import MessagingService

class L402Service:
    """
    Lightning Service Authentication Token (LSAT / L402) Service.

    Manages the creation, verification, and lifecycle of LSATs,
    integrating with payment and database services.
    """

    def __init__(self, payment_service, database_service, messaging_service=None,
                 secret_key: Optional[str] = None, default_expiry_seconds: int = 3600, default_price_sats: int = 1): # Default price set to 1
        """
        Initialize the L402 service.

        Args:
            payment_service: Instance of PaymentService.
            database_service: Service to store/retrieve token data.
            messaging_service: Optional service for real-time notifications.
            secret_key: Hex-encoded root secret key for macaroon signing. MUST be kept secret.
                        Generates a random one if None (NOT suitable for production persistence).
            default_expiry_seconds: Default token validity duration (1 hour).
            default_price_sats: Default price for tokens in satoshis (default is 1).
        """
        self.payment_service = payment_service
        self.database_service = database_service
        self.messaging_service = messaging_service
        self.logger = logging.getLogger(__name__)

        # Validate dependencies
        if not payment_service: raise ValueError("PaymentService instance is required.")
        if not database_service: raise ValueError("DatabaseService instance is required.")
        if not hasattr(payment_service, 'herd_key') or not payment_service.herd_key:
             raise ValueError("PaymentService instance must have a valid 'herd_key' attribute.")
        # cyberherd_key check removed as it might not be strictly needed by L402Service itself

        # Handle Secret Key
        if secret_key is None:
            secret_key = secrets.token_hex(32)
            self.logger.warning("No L402_SECRET_KEY provided. Generated a random key. LSATs will be invalid after restart.")
        elif len(secret_key) != 64 or not all(c in '0123456789abcdefABCDEF' for c in secret_key):
             raise ValueError("Invalid L402_SECRET_KEY: Must be a 64-character hex string (32 bytes).")

        try:
             self.secret_key_bytes = bytes.fromhex(secret_key)
             if len(self.secret_key_bytes) != 32: # Double check byte length
                 raise ValueError("Decoded L402_SECRET_KEY must be 32 bytes.")
             self.logger.info("L402 service configured with secret key.")
        except ValueError as e:
             raise ValueError(f"Invalid L402_SECRET_KEY: Not a valid hex string or incorrect length. Error: {e}")

        self.default_expiry = default_expiry_seconds
        self.default_price = max(1, default_price_sats) # Ensure price is at least 1 sat

    async def initialize(self):
        """Initialize database tables and register listeners."""
        try:
            # Ensure DB service is ready
            if not self.database_service: raise RuntimeError("DatabaseService not available during L402Service initialization.")
            await self.database_service.create_l402_tables()
            self.logger.info("L402 service initialized: Database tables checked/created.")

            if self.messaging_service:
                self.logger.info("Registering L402 service with messaging service for payment notifications.")
                if hasattr(self.messaging_service, 'add_payment_listener'):
                    self.messaging_service.add_payment_listener(self.handle_payment_event)
                else:
                     self.logger.warning("Messaging service does not have 'add_payment_listener' method.")
            else:
                self.logger.info("No messaging service configured for L402 payment notifications.") # Changed from warning

            # Ensure payment service is initialized if needed (check attribute existence)
            if hasattr(self.payment_service, 'initialize') and callable(self.payment_service.initialize):
                 if asyncio.iscoroutinefunction(self.payment_service.initialize):
                     await self.payment_service.initialize()
                 else:
                     self.payment_service.initialize() # Call synchronously if not async
                 self.logger.info("PaymentService initialized via L402Service.")

            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize L402 service: {e}", exc_info=True)
            return False

    async def handle_payment_event(self, event_data: Dict[str, Any]) -> None:
        """Handle incoming payment confirmation events."""
        try:
            self.logger.debug(f"L402 service received payment event: {event_data}")

            payment_hash = event_data.get("payment_hash") or \
                           event_data.get("checking_id") or \
                           (isinstance(event_data.get("data"), dict) and event_data["data"].get("payment_hash"))

            if not payment_hash:
                # self.logger.debug("Payment event did not contain a recognizable payment hash.") # Too verbose maybe
                return

            # Check payment status using the appropriate key (herd_key for L402)
            payment_info = await self.get_payment_status_and_preimage(payment_hash)

            if payment_info and payment_info.get("status") == "paid":
                self.logger.info(f"Payment event confirmed settled payment for hash: {payment_hash[:10]}...")

                tokens = await self.database_service.get_l402_tokens({"payment_hash": payment_hash})

                if not tokens:
                    self.logger.warning(f"Received payment confirmation for hash {payment_hash[:10]}..., but no matching L402 token found in DB.")
                    return

                for token_data in tokens:
                    token_id = token_data["token_id"]
                    if not token_data.get("is_paid"):
                        self.logger.info(f"Marking L402 token '{token_id}' as paid due to payment event.")
                        await self.database_service.update_l402_token_status(token_id, {"is_paid": True})

                        # Send notification (optional)
                        if self.messaging_service and hasattr(self.messaging_service, 'send_message_to_clients'):
                             try:
                                 notification = {
                                     "type": "l402_payment_confirmed",
                                     "data": { "token_id": token_id, "payment_hash": payment_hash,
                                               "resource_id": token_data.get("resource_id"), "user_id": token_data.get("user_id") }
                                 }
                                 await self.messaging_service.send_message_to_clients(json.dumps(notification))
                             except Exception as notify_err:
                                 self.logger.error(f"Failed to send payment confirmation notification for token {token_id}: {notify_err}")
                    else:
                         self.logger.debug(f"Token '{token_id}' was already marked as paid.")
            else:
                status = payment_info.get("status", "unknown") if payment_info else "unknown"
                self.logger.debug(f"Payment event received for hash {payment_hash[:10]}..., but payment status is '{status}'")

        except Exception as e:
            self.logger.error(f"Error handling payment event: {e}", exc_info=True)

    async def create_invoice_and_token(self, resource_id: str, amount: Optional[int] = None,
                                 expiry: Optional[int] = None, user_id: Optional[str] = None,
                                 metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Create a Lightning invoice (using herd_key) and the initial macaroon part of the LSAT.
        """
        amount_sats = max(1, amount if amount is not None else self.default_price)
        expiry_seconds = expiry if expiry is not None else self.default_expiry
        token_metadata = metadata or {}

        self.logger.info(f"Creating LSAT invoice (herd_key) for resource '{resource_id}', amount: {amount_sats} sats")

        try:
            # 1. Create unique Token ID
            token_id = create_token_id()

            # 2. Create Lightning Invoice using HERD_KEY explicitly
            memo = f"LSAT for {resource_id} ({token_id[:8]})"
            invoice_result = await self.payment_service.create_invoice(
                amount=amount_sats,
                memo=memo,
                wallet_key=self.payment_service.herd_key # Pass herd_key explicitly
            )
            if not invoice_result or 'payment_hash' not in invoice_result or 'payment_request' not in invoice_result:
                self.logger.error(f"Payment service failed to return a valid invoice using herd_key. Response: {invoice_result}")
                return {"error": "Failed to create Lightning invoice via payment service.", "status_code": 503}

            payment_hash = invoice_result['payment_hash']
            payment_request = invoice_result['payment_request']
            self.logger.info(f"Invoice created (herd_key): hash={payment_hash[:10]}..., token_id={token_id}")

            # 3. Create Macaroon
            now_ts = int(time.time())
            expires_at_ts = now_ts + expiry_seconds
            token_metadata['payment_hash'] = payment_hash # Store hash in metadata for potential lookup

            macaroon = create_lsat_macaroon(
                token_id=token_id,
                resource_id=resource_id,
                user_id=user_id,
                expires_at_ts=expires_at_ts,
                root_key_bytes=self.secret_key_bytes,
                custom_caveats=token_metadata
            )

            # 4. Store Token Info in Database
            await self.database_service.store_l402_token({
                'token_id': token_id,
                'payment_hash': payment_hash,
                'resource_id': resource_id,
                'amount': amount_sats,
                'created_at': now_ts,
                'expires_at': expires_at_ts,
                'user_id': user_id,
                'metadata': json.dumps(token_metadata), # Store metadata as JSON string
                'is_paid': False
            })
            self.logger.debug(f"Stored initial token data for ID {token_id} in database.")

            # 5. Create WWW-Authenticate Challenge Header
            challenge = create_challenge_header(payment_request, macaroon)

            return {
                'token_id': token_id,
                'payment_hash': payment_hash,
                'invoice': payment_request,
                'amount': amount_sats,
                'expires_at': expires_at_ts,
                'challenge': challenge # Used for 402 response header
            }

        except Exception as e:
            self.logger.error(f"Error during LSAT invoice/token creation for resource '{resource_id}': {e}", exc_info=True)
            return {"error": f"Failed to create LSAT challenge: {str(e)}", "status_code": 500}


    async def verify_lsat(self, auth_header: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Verify a full LSAT token from an Authorization header (LSAT macaroon_b64:preimage).
        Relies on Verifier.verify() to check signature and caveats.
        """
        try:
            # 1. Decode Header
            macaroon, preimage = decode_lsat_header(auth_header)
            if not macaroon or not preimage:
                return False, {"error": "Invalid LSAT header format. Expected 'LSAT macaroon_b64:preimage'.", "status_code": 400}

            # Ensure 'macaroon' is indeed a Macaroon object after decoding
            if not isinstance(macaroon, Macaroon):
                 self.logger.error(f"Decoded macaroon is not a valid Macaroon object: Type={type(macaroon)}")
                 return False, {"error": "Invalid Macaroon: Deserialization failed.", "status_code": 400}


            # 2. Get Token ID from Macaroon (Handle bytes or str)
            macaroon_identifier = macaroon.identifier
            if isinstance(macaroon_identifier, bytes):
                # If it's bytes, decode it
                token_id = macaroon_identifier.decode('utf-8')
            elif isinstance(macaroon_identifier, str):
                # If it's already a string, use it directly
                token_id = macaroon_identifier
            else:
                # Handle unexpected type
                self.logger.error(f"Unexpected type for macaroon identifier: {type(macaroon_identifier)}")
                return False, {"error": "Invalid Macaroon: Malformed identifier.", "status_code": 400}

            if not token_id:
                return False, {"error": "Invalid Macaroon: Missing identifier (token_id).", "status_code": 400}

            self.logger.debug(f"Verifying LSAT for token ID: {token_id}")

            # --- Verification Steps using Verifier ---

            # 3. Fetch Token Data from Database (Needed for payment hash)
            token_data = await self.database_service.get_l402_token(token_id)
            if not token_data:
                 self.logger.warning(f"LSAT verification failed: Token ID '{token_id}' not found in database.")
                 return False, {"error": "Invalid LSAT: Token not found.", "status_code": 401}

            # Load metadata if stored as JSON string
            if isinstance(token_data.get('metadata'), str):
                 try:
                     token_data['metadata'] = json.loads(token_data['metadata'])
                 except json.JSONDecodeError:
                     self.logger.error(f"Failed to parse metadata JSON for token {token_id}")
                     token_data['metadata'] = {} # Use empty dict on error


            # 4. Verify Preimage against Payment Hash (Cryptographic Check First)
            payment_hash = token_data.get('payment_hash')
            if not payment_hash:
                 self.logger.error(f"Critical: Payment hash missing in DB for token ID {token_id}.")
                 return False, {"error": "Internal Server Error: Token data is incomplete.", "status_code": 500}

            if not verify_lsat_preimage(payment_hash, preimage):
                 self.logger.warning(f"Invalid LSAT Preimage for token ID: {token_id}, hash: {payment_hash[:10]}...")
                 return False, {"error": "Invalid LSAT: Preimage does not match payment hash.", "status_code": 401}
            self.logger.debug(f"Preimage cryptographically verified for token ID: {token_id}")


            # 5. Verify Macaroon Signature AND Caveats using Verifier
            verifier = Verifier()

            # Define general caveat checks (like expiry)
            def check_expiry(caveat_str):
                 prefix = "expires_at = "
                 if not caveat_str.startswith(prefix): return True # Important: Only check if caveat exists, else it's satisfied
                 try:
                     expiry_ts = int(caveat_str[len(prefix):])
                     is_valid = time.time() < expiry_ts
                     if not is_valid: self.logger.debug(f"Caveat Failed: Token {token_id} expired at {expiry_ts}")
                     return is_valid
                 except (ValueError, TypeError):
                      self.logger.warning(f"Invalid expiry caveat format: {caveat_str}")
                      return False # Fail on bad format
            verifier.satisfy_general(check_expiry)

            # Add other general checks as needed (e.g., IP address, user agent if added as caveats)

            # Perform the verification using the root key
            # This checks both the signature and the registered caveat conditions
            try:
                 # Ensure secret key bytes are valid
                 if not hasattr(self, 'secret_key_bytes') or not isinstance(self.secret_key_bytes, bytes):
                      self.logger.error("L402 Service secret_key_bytes not initialized correctly.")
                      return False, {"error": "Internal Server Error: Service configuration error.", "status_code": 500}

                 verified = verifier.verify(macaroon, self.secret_key_bytes)
            except Exception as verification_error:
                 # Catch potential errors during pymacaroons verification itself
                 self.logger.error(f"Error during verifier.verify execution for token {token_id}: {verification_error}", exc_info=True)
                 return False, {"error": "Internal Server Error: Failed during macaroon verification process.", "status_code": 500}


            if not verified:
                 # If verifier.verify returns False, either signature or caveats failed
                 self.logger.warning(f"Invalid LSAT: Macaroon signature or caveat verification failed for token ID: {token_id}")
                 # Check expiry explicitly from DB data for clearer error message
                 if time.time() >= token_data.get('expires_at', float('inf')):
                      error_msg = "Invalid LSAT: Token expired."
                 else:
                      error_msg = "Invalid LSAT: Signature or constraints not met."
                 return False, {"error": error_msg, "status_code": 401} # Use 401

            self.logger.debug(f"Macaroon signature and caveats verified for token ID: {token_id}")


            # 6. Final Check: Ensure token is marked as paid in DB (still useful)
            if not token_data.get('is_paid'):
                 # This might happen if payment confirmed but DB update failed/delayed
                 self.logger.warning(f"Token {token_id} passed checks but is not marked as paid in DB. Marking as paid now.")
                 await self.database_service.update_l402_token_status(token_id, {'is_paid': True})
                 token_data['is_paid'] = True # Update local copy

            # --- Success ---
            # Include relevant data in the success result
            success_result = {
                **token_data,  # Add all data fetched from DB
                "macaroon": macaroon, # The verified macaroon object (maybe not needed by caller?)
                "preimage": preimage, # The verified preimage (maybe not needed by caller?)
                "status_code": 200 # Indicate success clearly
            }
            return True, success_result

        except Exception as e:
            self.logger.error(f"Unexpected error during LSAT verification: {e}", exc_info=True)
            return False, {"error": f"Internal Server Error during verification: {str(e)}", "status_code": 500}


    async def get_payment_status_and_preimage(self, payment_hash: str) -> Optional[Dict[str, Any]]:
        """
        Checks payment status with the payment service (using herd_key)
        and attempts to retrieve the preimage.

        Args:
            payment_hash: The payment hash to check.

        Returns:
            Dictionary with status ('paid', 'pending', 'error', 'not_found', 'expired')
            and optionally 'preimage', or None if the check fails critically.
        """
        preimage = None
        payment_status_data = None
        l402_wallet_key = self.payment_service.herd_key # Key used for L402 invoicing/checking

        try:
            # Attempt to get preimage directly using herd_key
            self.logger.debug(f"Attempting direct preimage fetch for {payment_hash[:10]}... using herd_key")
            preimage = await self.payment_service.get_invoice_preimage(
                payment_hash,
                wallet_key=l402_wallet_key # Pass herd_key
            )

            if preimage:
                 self.logger.info(f"Preimage found directly for payment hash {payment_hash[:10]}...")
                 return {"status": "paid", "preimage": preimage}

            # If no preimage directly, check the status explicitly using herd_key
            self.logger.debug(f"Preimage not found directly, checking status for {payment_hash[:10]}... using herd_key")
            payment_status_data = await self.payment_service.check_payment_status(
                payment_hash,
                wallet_key=l402_wallet_key # Pass herd_key
            )

            # Handle case where check_payment_status returns None (e.g., error, 404)
            if payment_status_data is None:
                 self.logger.warning(f"Payment status check failed or payment {payment_hash[:10]}... not found using herd_key.")
                 # Distinguish between not found and error if payment service provides detail
                 # Assuming None means not found for simplicity here based on refactored PaymentService
                 return {"status": "not_found", "message": "Payment not found."}


            self.logger.debug(f"Payment status result for {payment_hash[:10]}...: {payment_status_data}")

            # Use the 'settled' field added by check_payment_status
            is_paid = payment_status_data.get('settled', False)

            if is_paid:
                 # Payment is confirmed by status check. Try getting preimage again (herd_key).
                 self.logger.info(f"Payment {payment_hash[:10]}... confirmed by status check. Retrying preimage fetch.")
                 try:
                     preimage_retry = await self.payment_service.get_invoice_preimage(
                         payment_hash,
                         wallet_key=l402_wallet_key # Pass herd_key again
                     )
                     if preimage_retry:
                         return {"status": "paid", "preimage": preimage_retry}
                     else:
                         self.logger.warning(f"Payment {payment_hash[:10]}... confirmed, but preimage *still* unavailable after retry.")
                         return {"status": "paid", "preimage": None, "message": "Payment confirmed, but preimage could not be retrieved."}
                 except Exception as retry_exc:
                      self.logger.error(f"Error during preimage retry for {payment_hash[:10]}...: {retry_exc}")
                      return {"status": "paid", "preimage": None, "message": "Payment confirmed, but error retrieving preimage on retry."}

            # Check for LNBits specific expired status if present
            elif payment_status_data.get('details', {}).get('expired') is True:
                return {"status": "expired", "message": "Invoice expired."}
            else: # Not paid, not expired, status is likely pending or unknown
                 status_str = payment_status_data.get('status', 'pending') # Default to pending if status field missing
                 return {"status": status_str, "message": f"Payment status: {status_str}."}


        except Exception as e:
            self.logger.error(f"Error checking payment status/preimage for {payment_hash[:10]}...: {e}", exc_info=True)
            # Return an error status
            return {"status": "error", "error": "Internal server error", "message": f"Failed to check payment: {str(e)}"}


    async def get_tokens(self, user_id: Optional[str] = None, resource_id: Optional[str] = None, include_expired: bool = False) -> List[Dict[str, Any]]:
        """Get filtered list of token data from database."""
        filter_criteria = {'is_paid': True} # Usually only interested in paid tokens
        if not include_expired:
            filter_criteria['expires_at_min'] = int(time.time()) # Filter out expired

        if user_id: filter_criteria['user_id'] = user_id
        if resource_id: filter_criteria['resource_id'] = resource_id

        try:
            tokens = await self.database_service.get_l402_tokens(filter_criteria)
            # Decode metadata if stored as JSON
            for token in tokens:
                if isinstance(token.get('metadata'), str):
                    try:
                        token['metadata'] = json.loads(token['metadata'])
                    except json.JSONDecodeError:
                        self.logger.warning(f"Failed to decode metadata for token {token.get('token_id')}")
                        token['metadata'] = {} # Use empty dict on error
            return tokens
        except Exception as e:
             self.logger.error(f"Error fetching tokens from database: {e}", exc_info=True)
             return [] # Return empty list on error


    async def refresh_token(self, token_id: str, new_expiry_seconds: Optional[int] = None) -> Dict[str, Any]:
        """
        Refreshes a token's expiry date and issues a new macaroon.
        Requires the token to exist and be paid. Does NOT require new payment.
        """
        expiry_duration = new_expiry_seconds if new_expiry_seconds is not None else self.default_expiry
        self.logger.info(f"Attempting to refresh token ID {token_id} with new expiry duration {expiry_duration}s")

        try:
            # 1. Get existing token data
            token_data = await self.database_service.get_l402_token(token_id)
            if not token_data:
                return {"error": "Token not found.", "status_code": 404}

            # 2. Check if paid
            if not token_data.get('is_paid'):
                return {"error": "Cannot refresh an unpaid token.", "status_code": 402}

            # 3. Calculate new expiry timestamp
            new_expires_at_ts = int(time.time()) + expiry_duration

            # 4. Update expiry in Database
            await self.database_service.update_l402_token_status(
                token_id,
                {'expires_at': new_expires_at_ts}
            )
            self.logger.info(f"Updated token {token_id} expiry in DB to {new_expires_at_ts}")

            # 5. Create NEW Macaroon with updated expiry
            metadata = token_data.get('metadata', {})
            if isinstance(metadata, str):
                try: metadata = json.loads(metadata)
                except json.JSONDecodeError: metadata = {}

            new_macaroon = create_lsat_macaroon(
                token_id=token_id,
                resource_id=token_data['resource_id'],
                user_id=token_data.get('user_id'),
                expires_at_ts=new_expires_at_ts,
                root_key_bytes=self.secret_key_bytes,
                custom_caveats=metadata
            )

            # 6. Format new macaroon for return
            new_macaroon_b64 = format_macaroon_for_header(new_macaroon)

            return {
                'token_id': token_id,
                'expires_at': new_expires_at_ts,
                'macaroon_b64': new_macaroon_b64 # Client combines this with original preimage
            }
        except Exception as e:
             self.logger.error(f"Error during token refresh for {token_id}: {e}", exc_info=True)
             return {"error": f"Internal server error during refresh: {str(e)}", "status_code": 500}


    async def send_resource_access_notification(self, user_id: str, resource_id: str,
                                          token_data: Dict[str, Any]) -> bool:
        """Send notification about resource access via messaging service (if configured)."""
        if not self.messaging_service or not hasattr(self.messaging_service, 'send_message_to_clients'):
            return False
        try:
            message_data = {
                "type": "l402_access_granted",
                "data": {
                    "user_id": user_id,
                    "resource_id": resource_id,
                    "token_id": token_data.get("token_id"),
                    "access_time": int(time.time()),
                    "expires_at": token_data.get("expires_at"),
                    "metadata": token_data.get("metadata", {}) # Ensure metadata is included
                }
            }
            await self.messaging_service.send_message_to_clients(json.dumps(message_data))
            self.logger.debug(f"Sent resource access notification for user '{user_id}', resource '{resource_id}'")
            return True
        except Exception as e:
            self.logger.error(f"Error sending resource access notification: {e}")
            return False


    async def extract_payment_hash(self, invoice: str) -> Optional[str]:
        """Extract payment hash from BOLT11 invoice using payment service or regex fallback."""
        if not invoice: return None
        try:
            # Try decoding via payment service first
            invoice_data = await self.payment_service.decode_invoice(invoice)
            if invoice_data and invoice_data.get('payment_hash'):
                 return invoice_data['payment_hash']
            else:
                 # Log if decode fails or hash is missing in response
                 self.logger.warning(f"Failed to decode invoice via payment service or hash missing. Response: {invoice_data}. Falling back to regex.")
        except Exception as decode_error:
            self.logger.warning(f"Error decoding invoice via payment service: {decode_error}. Falling back to regex.")

        # Fallback to regex
        return get_payment_hash_from_invoice(invoice) # Use the util function