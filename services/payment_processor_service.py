import logging
import json
from typing import Dict, Any, Optional, List
from asyncio import Lock
import time
import datetime

from services.payment_service import PaymentService
from services.goat_service import GoatStateService
from services.cyberherd_service import CyberHerdService
from services.messaging_service import MessagingService
from services.database_service import DatabaseService
from utils.cyberherd_module import MetadataFetcher, Verifier, generate_nprofile, check_cyberherd_tag, DEFAULT_RELAYS

logger = logging.getLogger(__name__)

class PaymentProcessorService:
    """Service for processing incoming payments and zaps."""
    
    def __init__(
        self, 
        payment_service: PaymentService,
        goat_service: GoatStateService, 
        cyberherd_service: CyberHerdService,
        messaging_service: MessagingService,
        database_service: Optional[DatabaseService] = None,  # Add database_service parameter
        trigger_amount: int = 1250,
        process_zaps: bool = True  # Add configuration option to enable/disable zap processing
    ):
        self.payment_service = payment_service
        self.goat_service = goat_service
        self.cyberherd_service = cyberherd_service
        self.messaging_service = messaging_service
        self.database_service = database_service  # Store database_service
        self.trigger_amount = trigger_amount
        self.process_zaps = process_zaps  # Store the configuration
        self.balance = 0
        self.balance_lock = Lock()
        
    async def update_balance(self, new_balance: int) -> None:
        """Update the wallet balance."""
        async with self.balance_lock:
            self.balance = new_balance
            
    async def get_balance(self) -> int:
        """Get the current wallet balance."""
        async with self.balance_lock:
            return self.balance
            
    async def process_payment(self, payment_data: Dict[str, Any], send_notifications: bool = True) -> Dict[str, Any]:
        """Process incoming payment data."""
        try:
            payment = payment_data.get('payment', {})
            payment_amount = payment.get('amount', 0)
            sats_received = payment_amount // 1000  # Convert payment amount from msats to sats
            checking_id = payment.get('checking_id', '')
            
            # Extract wallet_balance, checking both top-level and inside payment object
            # WebSocket wallet_balance is already in satoshis, no conversion needed
            wallet_balance_sats = payment_data.get('wallet_balance')
            if wallet_balance_sats is None and 'wallet_balance' in payment:
                wallet_balance_sats = payment.get('wallet_balance')
                
            # Update balance through payment service if none provided in webhook
            if wallet_balance_sats is None or wallet_balance_sats == 0:
                logger.warning("No valid wallet_balance in webhook, fetching from payment service...")
                try:
                    # Payment service returns msats, need to convert to sats
                    msats_balance = await self.payment_service.get_balance()
                    wallet_balance_sats = msats_balance // 1000
                    logger.info(f"Retrieved wallet balance from service: {msats_balance} msats = {wallet_balance_sats} sats")
                except Exception as e:
                    logger.error(f"Failed to get wallet balance from service: {e}")
                    
            # Update the balance state if we have a valid balance
            if wallet_balance_sats is not None and wallet_balance_sats > 0:
                # No conversion needed - wallet_balance_sats is already in satoshis
                await self.update_balance(wallet_balance_sats)
                logger.info(f"Updated wallet balance to {wallet_balance_sats} sats")
            else:
                logger.warning(f"No valid wallet balance available (value: {wallet_balance_sats})")
                # Don't update balance to zero - keep the previous value

            # Only update goat_sats for external payments (not internal transfers)
            if sats_received > 0 and not checking_id.startswith('internal_'):
                logger.info(f"Updating GoatSats with {sats_received} sats (external payment)")
                await self.goat_service.update_sats(sats_received)
            elif sats_received > 0:
                logger.info(f"Skipping GoatSats update for internal payment: {checking_id}")

            # Process nostr data if present and zap processing is enabled
            feeder_triggered = False
            new_cyberherd_record_created = False
            
            # Extract nostr data from payment extras
            nostr_data_raw = self._extract_nostr_data(payment)
            
            if nostr_data_raw:
                logger.info(f"Found nostr data in payment: {nostr_data_raw[:100]}...")
                
                if self.process_zaps:
                    # Process nostr data (zaps) if enabled
                    if sats_received >= 10:  # Changed: Allow exactly 10 sats (minimum zap amount)
                        logger.info(f"Processing zap data for {sats_received} sats payment")
                        cyberherd_result = await self._process_nostr_data(nostr_data_raw, sats_received)
                        new_cyberherd_record_created = cyberherd_result.get("success", False)
                        logger.info(f"Zap processing result: {cyberherd_result}")
                    else:
                        logger.info(f"Skipping zap processing: amount too small ({sats_received} sats, minimum 21)")
                else:
                    # Log that we're skipping zap processing due to configuration
                    logger.info(f"Skipping zap processing due to configuration (process_zaps=False)")
            else:
                logger.debug("No nostr data found in payment")

            # Handle feeder triggering if applicable
            if sats_received > 0 and not await self.goat_service.get_feeder_override_status():
                # Get the latest balance from current state, not just relying on webhook data
                current_balance = await self.get_balance()
                logger.info(f"Current wallet balance from state: {current_balance} sats, trigger amount: {self.trigger_amount} sats")
                
                # Check if we have enough to trigger the feeder
                if current_balance >= self.trigger_amount:
                    feeder_triggered = await self._trigger_feeder_and_pay(sats_received)
                
                # Send notification if neither feeder triggered nor new cyberherd record created
                # Only send if notifications are enabled (true by default, but disabled for missed zaps)
                if not feeder_triggered and not new_cyberherd_record_created and send_notifications:
                    await self._send_payment_notification(sats_received, current_balance)
            else:
                logger.info("Feeder override is ON or payment amount is non-positive. Skipping feeder logic.")

            return {
                "success": True,
                "feeder_triggered": feeder_triggered,
                "cyberherd_updated": new_cyberherd_record_created
            }

        except Exception as e:
            logger.error(f"Error processing payment data: {e}")
            return {"success": False, "error": str(e)}
            
    def _extract_nostr_data(self, payment: Dict[str, Any]) -> Optional[str]:
        """Extract nostr data from payment extras."""
        extra = payment.get('extra', {})
        if not isinstance(extra, dict):
            return None
            
        # Try to find nostr data in different locations
        if 'nostr' in extra:
            nostr_data = extra['nostr']
            logger.debug(f"Found nostr data in extra.nostr")
            return nostr_data
        elif 'extra' in extra and isinstance(extra['extra'], dict):
            nostr_data = extra['extra'].get('nostr')
            if nostr_data:
                logger.debug(f"Found nostr data in extra.extra.nostr")
            return nostr_data
        
        # Add more detailed logging about what we received
        logger.debug(f"No nostr data found in payment extra data: {extra}")
        return None
        
    async def _process_nostr_data(self, nostr_data_raw: str, sats_received: int) -> Dict[str, Any]:
        """Process nostr data from a zap payment."""
        try:
            nostr_data = json.loads(nostr_data_raw)
            pubkey = nostr_data.get('pubkey')
            note = nostr_data.get('id')
            event_kind = nostr_data.get('kind')
            
            # We specifically handle zap requests (kind 9734) here
            # Zap receipts (kind 9735) are handled by the cyberherd_listener_service
            kinds = [event_kind] if event_kind is not None else []
            
            # Extract event_id from tags
            event_id = None
            for tag in nostr_data.get('tags', []):
                if isinstance(tag, list) and len(tag) > 1 and tag[0] == 'e':
                    event_id = tag[1]
                    break
                    
            if not (pubkey and event_id):
                logger.warning("Missing pubkey or event_id in Nostr data.")
                return {"success": False}
                
            # Check if this is a cyberherd tag
            if not await check_cyberherd_tag(event_id):
                logger.info(f"No 'CyberHerd' tag found for event_id: {event_id}")
                return {"success": False}
                
            # Extract relays from tags
            user_relays = self._extract_relay_list(nostr_data)
            
            # Get user metadata
            metadata_fetcher = MetadataFetcher()
            metadata = await metadata_fetcher.lookup_metadata(pubkey, user_relays)
            
            if not metadata:
                logger.warning(f"Metadata lookup failed for pubkey: {pubkey}")
                return {"success": False}
                
            # Check if user has valid Lightning address
            lud16 = metadata.get('lud16')
            display_name = metadata.get('display_name', 'Anon')
            picture = metadata.get('picture')
            
            is_valid_lud16 = lud16 and await Verifier.verify_lud16(lud16)
            
            if not is_valid_lud16:
                logger.warning(f"Record rejected for pubkey {pubkey}: Invalid lud16")
                return {"success": False}
                
            # Create nprofile
            nprofile = await generate_nprofile(pubkey)
            if not nprofile:
                logger.warning(f"Failed to generate nprofile for pubkey: {pubkey}")
                return {"success": False}
                
            # Create user data for cyberherd
            from models import CyberHerdData  # Import here to avoid circular imports
            new_member_data = CyberHerdData(
                display_name=display_name,
                event_id=event_id,
                note=note,
                kinds=kinds,
                pubkey=pubkey,
                nprofile=nprofile,
                lud16=lud16,
                notified=None,
                payouts=0.0,
                amount=sats_received,
                picture=picture,
                relays=user_relays
            )
            
            # Add to cyberherd
            result = await self.cyberherd_service.update_cyberherd([new_member_data])
            
            return {
                "success": result.get("status") == "success" and result.get("new_members_added", 0) > 0
            }
            
        except json.JSONDecodeError:
            logger.error("Invalid JSON in Nostr data.")
            return {"success": False}
        except Exception as e:
            logger.error(f"Error processing Nostr data: {e}")
            return {"success": False}
    
    def _extract_relay_list(self, nostr_data: Dict[str, Any]) -> List[str]:
        """Extract relay list from nostr data tags."""
        relay_tag = None
        for tag in nostr_data.get("tags", []):
            if isinstance(tag, list) and tag and tag[0] == "relays":
                relay_tag = tag
                break
                
        if relay_tag and len(relay_tag) > 1:
            # Use the first three relay URLs from the tag
            user_relays = relay_tag[1:4]
            logger.info(f"Using relays from nostr data: {user_relays}")
            return user_relays
        else:
            # Use default relays
            logger.info(f"Using default relays")
            return DEFAULT_RELAYS[:3]
    
    async def _trigger_feeder_and_pay(self, sats_received: int) -> bool:
        """Trigger feeder and reset payment."""
        if await self.goat_service.trigger_feeder():
            logger.info("Feeder triggered successfully.")
            
            # Get the current balance from state
            current_balance = await self.get_balance()
            
            # Only try to send payment if balance is above zero
            if current_balance > 0:
                try:
                    # Use direct payment distribution instead of sending to reset wallet
                    payment_result = await self.cyberherd_service.distribute_payments_directly(current_balance)
                    
                    if payment_result.get('success', False):
                        logger.info(f"Direct payment distribution succeeded: {payment_result['total_distributed']} sats distributed")
                    else:
                        # If direct distribution fails or partially fails, still log but don't retry
                        logger.warning(f"Direct payment distribution status: {payment_result}")
                        
                        # For any failed payments, try to send to the reset wallet as before
                        failed_amount = sum(payment["amount"] for payment in payment_result.get("failed_payments", []))
                        if failed_amount > 0:
                            logger.info(f"Attempting to send {failed_amount} sats (from failed payments) to reset wallet")
                            status = await self._send_payment(failed_amount)
                            if status.get('success', False):
                                logger.info(f"Successfully sent {failed_amount} sats to reset wallet")
                            else:
                                logger.warning(f"Failed to send {failed_amount} sats to reset wallet: {status.get('message', 'Unknown')}")
                except Exception as e:
                    logger.error(f"Exception in direct payment distribution: {e}")
                    # Fall back to original reset payment method
                    try:
                        status = await self._send_payment(current_balance)
                        logger.info(f"Fallback payment status: {status.get('success', False)}")
                    except Exception as fallback_e:
                        logger.error(f"Fallback payment also failed: {fallback_e}")
            else:
                logger.info("Skipping payments: balance is zero or negative")

            # Send notification about feeder triggering regardless of payment status
            feeder_msg, _ = await self.messaging_service.make_messages(
                sats_received,
                0,
                "feeder_triggered"
            )
            await self.messaging_service.send_message_to_clients(feeder_msg)
            return True
        return False

    async def _send_payment(self, balance: int) -> Dict[str, Any]:
        """Send payment to reset the wallet."""
        if balance <= 0:
            logger.warning(f"Skipping payment with non-positive balance: {balance}")
            return {"success": False, "message": "Balance must be positive"}
            
        memo = 'Reset Herd Wallet'
        try:
            logger.info(f"Creating invoice for {balance} sats with memo: '{memo}'")
            
            # Create the invoice with better error handling
            try:
                invoice_data = await self.payment_service.create_invoice(
                    amount=balance,
                    memo=memo,
                    wallet_key=self.payment_service.cyberherd_key
                )
                
                if not invoice_data or 'payment_request' not in invoice_data:
                    logger.error(f"Invalid invoice response: {invoice_data}")
                    return {"success": False, "message": "Invalid invoice response from LNBits"}
                    
                # Log the payment hash right after creation for debugging
                payment_hash = invoice_data.get('payment_hash', 'unknown')
                logger.info(f"Invoice created successfully with hash: {payment_hash[:10]}...")
                
            except Exception as invoice_err:
                logger.error(f"Failed to create invoice: {invoice_err}")
                return {"success": False, "message": f"Failed to create invoice: {str(invoice_err)}"}
            
            # Pay the invoice
            try:
                payment_request = invoice_data['payment_request']
                logger.info(f"Paying invoice for {balance} sats")
                payment_result = await self.payment_service.pay_invoice(payment_request)
            except Exception as payment_err:
                logger.error(f"Failed to pay invoice {payment_hash[:10]}: {payment_err}")
                return {"success": False, "message": f"Failed to pay invoice: {str(payment_err)}"}
            
            # LNBits returns a payment_hash when successful, not a 'paid' field
            if payment_result and 'payment_hash' in payment_result:
                logger.info(f"Successfully paid {balance} sats to reset herd wallet")
                return {"success": True, "data": payment_result}
            else:
                logger.warning(f"Payment appears to have failed: {payment_result}")
                return {"success": False, "message": "No payment_hash in response"}
        
        except Exception as e:
            logger.error(f"Failed to send payment of {balance} sats: {e}")
            return {"success": False, "message": f"Failed to send payment: {str(e)}"}
    
    async def _send_payment_notification(self, sats_received: int, current_balance: int) -> None:
        """Send notification about received payment."""
        if sats_received >= 10:
            # Calculate the correct difference (how many more sats are needed)
            difference = max(0, self.trigger_amount - current_balance)
            logger.info(
                f"Sending payment notification: {sats_received} sats received, "
                f"{difference} sats needed to trigger feeder "
                f"(trigger_amount: {self.trigger_amount}, current_balance: {current_balance})"
            )
            
            # Create the message immediately and send it directly
            try:
                message, _ = await self.messaging_service.make_messages(
                    sats_received, 
                    difference, 
                    "sats_received"
                )
                
                # Log that we've created the message and are about to send it
                logger.info(f"Created payment_event message: {sats_received} sats received, {difference} sats to go")
                
                # Send immediately, with proper exception handling
                await self.messaging_service.send_message_to_clients(message)
                
                # Log successful send
                logger.info(f"Successfully sent payment notification to clients")
            except Exception as e:
                logger.error(f"Error sending payment notification: {e}", exc_info=True)

    async def process_missed_zaps(self, hours_ago: int = 24, limit: int = 100) -> Dict[str, Any]:
        """
        Retrieve and process recent payments to catch any missed zaps.
        """
        if not self.process_zaps:
            logger.info("Zap processing is disabled. Skipping missed zaps check.")
            return {"success": False, "reason": "zap_processing_disabled"}
        
        try:
            logger.info(f"Checking for missed zaps from the last {hours_ago} hours (limit: {limit})")
            
            # Get processed payments from database to avoid reprocessing
            processed_payment_hashes = []
            if self.database_service:
                try:
                    processed_payment_hashes = await self.database_service.get_processed_payment_hashes(hours_ago)
                    logger.info(f"Found {len(processed_payment_hashes)} already processed payment hashes in database")
                except Exception as db_err:
                    logger.warning(f"Could not get processed payment hashes from database: {db_err}. Will proceed without filtering.")
            else:
                logger.warning("No database_service available. Cannot filter already processed payment hashes.")
            
            # Get recent payments from LNBits via payment_service
            logger.info(f"Querying LNBits for recent payments in the last {hours_ago} hours...")
            recent_payments = await self.payment_service.get_recent_payments(
                wallet_key=self.payment_service.herd_key,
                limit=limit,
                hours_ago=hours_ago
            )
            
            if not recent_payments:
                logger.info("No recent payments found in LNBits to check for missed zaps")
                return {"success": True, "processed": 0, "found": 0, "checked": 0}
            
            # Log some sample payment data to help debug
            if recent_payments:
                sample_payment = recent_payments[0]
                logger.info(f"Sample payment: checking_id={sample_payment.get('checking_id')}, amount={sample_payment.get('amount')}")
                logger.debug(f"Sample payment extra data: {json.dumps(sample_payment.get('extra', {}))}")
            
            logger.info(f"Found {len(recent_payments)} recent payments in LNBits")
            
            # Track results
            processed_count = 0
            zaps_found = 0
            skipped_count = 0
            processed_hashes = []
            
            # Process each payment from LNBits
            for payment in recent_payments:
                # Extract payment hash (checking_id or payment_hash)
                payment_hash = payment.get('checking_id') or payment.get('payment_hash')
                
                if not payment_hash:
                    logger.warning(f"Payment missing hash/checking_id, skipping: {payment}")
                    continue
                    
                # Check if amount is positive (incoming payment)
                amount = payment.get('amount', 0)
                if amount <= 0:
                    logger.debug(f"Skipping outgoing payment {payment_hash[:10]}...")
                    continue
                    
                # Skip if already processed (in database or current session)
                if payment_hash in processed_payment_hashes or payment_hash in processed_hashes:
                    logger.debug(f"Skipping already processed payment {payment_hash[:10]}...")
                    skipped_count += 1
                    continue
                    
                # Log that we're checking this unprocessed payment
                payment_time = payment.get('time', 0)
                payment_time_str = datetime.datetime.fromtimestamp(payment_time).strftime('%Y-%m-%d %H:%M:%S') if payment_time else 'unknown'
                logger.info(f"Checking payment {payment_hash[:10]}... ({amount/1000} sats) from {payment_time_str}")
                    
                # Extract and check for nostr data - with enhanced debugging
                extra_data = payment.get('extra', {})
                logger.debug(f"Payment extra data: {json.dumps(extra_data)}")
                
                nostr_data_raw = self._extract_nostr_data(payment)
                if not nostr_data_raw:
                    logger.debug(f"No nostr data found in payment {payment_hash[:10]}")
                    continue
                
                # Found a potential zap - log the actual nostr data to help diagnose issues
                zaps_found += 1
                logger.info(f"Found missed payment with zap data: hash={payment_hash[:10]}... ({amount/1000} sats)")
                logger.debug(f"Nostr data: {nostr_data_raw[:200]}...")
                
                # Convert to the format expected by process_payment
                payment_data = {
                    'payment': payment,
                    'wallet_balance': payment.get('wallet_balance', 0)
                }
                
                # Process the payment
                try:
                    logger.info(f"Processing missed zap payment: {payment_hash[:10]}...")
                    # Pass send_notifications=False to suppress sending payment notifications for missed zaps
                    result = await self.process_payment(payment_data, send_notifications=False)
                    
                    if result.get("success"):
                        if result.get("cyberherd_updated"):
                            processed_count += 1
                            logger.info(f"Successfully processed missed zap: hash={payment_hash[:10]}... - CyberHerd updated")
                        else:
                            logger.info(f"Processed payment {payment_hash[:10]}... but no CyberHerd update was needed")
                            
                        # Track as processed regardless of cyberherd update
                        processed_hashes.append(payment_hash)
                        
                        # Store the payment hash as processed in database
                        if self.database_service:
                            metadata = {
                                "processed_by": "missed_zaps_check",
                                "timestamp": int(time.time()),
                                "result": "success",
                                "cyberherd_updated": result.get("cyberherd_updated", False),
                                "feeder_triggered": result.get("feeder_triggered", False)
                            }
                            await self.database_service.store_processed_payment_hash(payment_hash, metadata)
                            logger.debug(f"Recorded {payment_hash[:10]}... as processed in database")
                    else:
                        logger.warning(f"Failed to process missed zap {payment_hash[:10]}: {result.get('error', 'Unknown error')}")
                except Exception as process_err:
                    logger.error(f"Error processing missed zap {payment_hash[:10]}: {process_err}", exc_info=True)
            
            # Log final results
            logger.info(f"Missed zap processing complete:")
            logger.info(f"- Total payments checked: {len(recent_payments)}")
            logger.info(f"- Skipped (already processed): {skipped_count}")
            logger.info(f"- Potential zaps found: {zaps_found}")
            logger.info(f"- Successfully processed: {processed_count}")
            
            return {
                "success": True,
                "found": zaps_found,
                "processed": processed_count,
                "skipped": skipped_count,
                "checked": len(recent_payments)
            }
        
        except Exception as e:
            logger.error(f"Error during missed zap processing: {e}", exc_info=True)
            return {"success": False, "error": str(e)}
