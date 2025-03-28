import logging
import json
from typing import Dict, Any, Optional, List
from asyncio import Lock

from services.payment_service import PaymentService
from services.goat_service import GoatStateService
from services.cyberherd_service import CyberHerdService
from services.messaging_service import MessagingService
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
        trigger_amount: int = 1250,
        process_zaps: bool = True  # Add configuration option to enable/disable zap processing
    ):
        self.payment_service = payment_service
        self.goat_service = goat_service
        self.cyberherd_service = cyberherd_service
        self.messaging_service = messaging_service
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
            
    async def process_payment(self, payment_data: Dict[str, Any]) -> Dict[str, Any]:
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
            
            if nostr_data_raw and self.process_zaps:
                # Process nostr data (zaps) if enabled
                if sats_received > 21:  # Minimum zap amount is 21 sats
                    logger.info(f"Processing zap data: {nostr_data_raw}")
                    cyberherd_result = await self._process_nostr_data(nostr_data_raw, sats_received)
                    new_cyberherd_record_created = cyberherd_result.get("success", False)
            elif nostr_data_raw and not self.process_zaps:
                # Log that we're skipping zap processing due to configuration
                logger.info(f"Skipping zap processing due to configuration (process_zaps=False)")

            # Handle feeder triggering if applicable
            if sats_received > 0 and not await self.goat_service.get_feeder_override_status():
                # Get the latest balance from current state, not just relying on webhook data
                current_balance = await self.get_balance()
                logger.info(f"Current wallet balance from state: {current_balance} sats, trigger amount: {self.trigger_amount} sats")
                
                # Check if we have enough to trigger the feeder
                if current_balance >= self.trigger_amount:
                    feeder_triggered = await self._trigger_feeder_and_pay(sats_received)
                
                # Send notification if neither feeder triggered nor new cyberherd record created
                if not feeder_triggered and not new_cyberherd_record_created:
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
            return extra['nostr']
        elif 'extra' in extra and isinstance(extra['extra'], dict):
            return extra['extra'].get('nostr')
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
            
            # Create the invoice
            invoice_data = await self.payment_service.create_invoice(
                amount=balance,
                memo=memo,
                wallet_key=self.payment_service.cyberherd_key
            )
            
            if not invoice_data or 'payment_request' not in invoice_data:
                logger.error("Failed to create invoice: Invalid response")
                return {"success": False, "message": "Invalid invoice response"}
            
            payment_request = invoice_data['payment_request']
            logger.info(f"Paying invoice for {balance} sats")
            
            # Pay the invoice
            payment_result = await self.payment_service.pay_invoice(payment_request)
            
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
