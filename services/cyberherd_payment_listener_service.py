import asyncio
import logging
import json
import subprocess
import os  # Add missing import
from typing import Optional, Dict, Any, Callable, List

from services.websocket_manager import WebSocketManager

logger = logging.getLogger(__name__)

class CyberherdPaymentListenerService(WebSocketManager):
    """Service to listen for CyberHerd payment events via WebSocket"""
    
    def __init__(self, 
                 websocket_uri: str,
                 callback_handler: Optional[Callable[[Dict[str, Any]], None]] = None,
                 ignore_npubs: List[str] = None,
                 max_retries: Optional[int] = None,
                 database_service=None,
                 message_template_service=None,
                 topic_tag: str = "CyberHerd"):  # Keep the topic_tag parameter
        """
        Initialize the CyberHerd payment listener service.
        
        Args:
            websocket_uri: WebSocket URI to connect to
            callback_handler: Function to call when processing payment events
            ignore_npubs: List of pubkeys to ignore in memo field
            max_retries: Maximum number of reconnection attempts (None for unlimited)
            database_service: Database service for member lookups
            message_template_service: Service for generating message templates
            topic_tag: Topic tag to use in Nostr replies (defaults to "CyberHerd")
        """
        super().__init__(uri=websocket_uri, logger=logger, max_retries=max_retries)
        self.callback_handler = callback_handler
        self.ignore_npubs = ignore_npubs or ["Bolverker", "sat", "Unknown"]
        self.database_service = database_service
        self.message_template_service = message_template_service
        self.topic_tag = topic_tag
        self._running = False
    
    async def initialize(self) -> bool:
        """Initialize the cyberherd payment listener service"""
        logger.info("Initializing Cyberherd Payment Listener service")
        return True
    
    async def start(self) -> bool:
        """Start the cyberherd payment listener service"""
        if self._running:  # Use our internal _running attribute
            self.logger.warning("Cyberherd Payment Listener service already running")
            return False
            
        self.logger.info("Starting Cyberherd Payment Listener service")
        self._running = True  # Set our internal flag
        self.should_run = True  # Set parent class flag
        # Use the run method from WebSocketManager
        asyncio.create_task(self.run())
        return True
    
    async def stop(self) -> bool:
        """Stop the cyberherd payment listener service"""
        if not self._running:  # Use our internal _running attribute
            self.logger.warning("Cyberherd Payment Listener service not running")
            return False
            
        self.logger.info("Stopping Cyberherd Payment Listener service")
        self.should_run = False  # Set parent class flag
        await self.disconnect()
        self._running = False  # Set our internal flag
        return True
    
    def extract_pubkey(self, memo: str) -> Optional[str]:
        """Extract pubkey from payment memo."""
        words = memo.split()
        if len(words) > 0 and words[-1] not in self.ignore_npubs:
            return words[-1]
        return None
    
    async def process_payment_data(self, data: Dict[str, Any]) -> None:
        """Process payment event from WebSocket. Implementation of abstract method."""
        if "payment" in data and data["payment"].get("amount", 0) < 0:
            amount = abs(data["payment"]["amount"]) / 1000
            memo = data["payment"].get("memo", "")
            pubkey = self.extract_pubkey(memo)
            
            if pubkey:
                # Skip database lookup for known internal pubkeys
                if pubkey in ["herd", "LightningGoats"]:
                    self.logger.info(f"Processing internal payment: {amount} sats for pubkey {pubkey}")
                    # Just send directly to callback handler
                    if self.callback_handler:
                        payment_data = {
                            "pubkey": pubkey,
                            "amount": int(amount),
                            "type": "payment_event"  # Changed from cyber_herd_treats to payment_event
                        }
                        
                        try:
                            await self.callback_handler(payment_data)
                            self.logger.info(f"Processed internal payment: {amount} sats for pubkey {pubkey}")
                        except Exception as e:
                            self.logger.error(f"Error in callback handler for internal payment: {e}")
                    return
                
                # Process regular CyberHerd member payments
                if self.callback_handler:
                    payment_data = {
                        "pubkey": pubkey,
                        "amount": int(amount),
                        "type": "cyber_herd_treats"
                    }
                    
                    try:
                        await self.callback_handler(payment_data)
                        self.logger.info(f"Processed payment: {amount} sats for pubkey {pubkey}")
                    except Exception as e:
                        self.logger.error(f"Error in callback handler: {e}")
                
                # Send as DM instead of reply
                await self.send_nostr_dm(pubkey, int(amount))
    
    async def send_nostr_dm(self, pubkey: str, amount: int) -> None:
        """Send a Nostr direct message (kind 4) to the member."""
        if not self.database_service:
            logger.warning("Database service not available, cannot send Nostr DMs")
            return
        
        try:
            # Use database_service to lookup member
            member = await self.database_service.get_cyberherd_member(pubkey)
            if not member:
                logger.warning(f"Member with pubkey {pubkey} not found in database")
                return
            
            # Get template for cyberherd_treats from message template service
            content = ""
            if self.message_template_service:
                try:
                    # FIXED: Changed template name from "cyber_herd_treats" to "cyberherd_treats"
                    # to match the convention used in messaging_service.py
                    template = await self.message_template_service.get_random_template("cyberherd_treats")
                    if template:
                        # Create formatted message using the template
                        content = template.format(
                            name=member.get("display_name", "Anon"),
                            new_amount=amount,
                            difference=0  # No difference for treats
                        )
                        logger.debug(f"Using template for DM: {content}")
                except Exception as e:
                    logger.error(f"Error getting message template: {e}")
                    # Don't return here, use fallback content instead
            
            # ADDED: Fallback content if template retrieval fails
            if not content:
                display_name = member.get("display_name", "Anon")
                content = f"You've received {amount} sats, {display_name}! Thanks for being part of the ⚡ CyberHerd ⚡.\n\n https://lightning-goats.com\n\n"
                logger.info(f"Using fallback template for DM to {pubkey}")

            # Construct the nak command to send a DM (kind 4)
            nak_cmd = [
                "/usr/local/bin/nak",
                "event",
                "--sec",
                os.environ.get("NOS_SEC", ""),
                "-k",
                "4",  # Use kind 4 for DM instead of kind 1
                "-c",
                content,
            ]
            
            # Add default relays
            relays = json.loads(member.get("relays", "[]")) if member.get("relays") else []
            if not relays:
                relays = ["wss://relay.damus.io", "wss://relay.primal.net"]
            
            # Add p-tag for the member (recipient)
            nak_cmd.extend(["--tag", f'p="{pubkey}"'])
            
            # Add CyberHerd topic tag
            nak_cmd.extend(["--tag", f't="{self.topic_tag}"'])
            
            # Add relay arguments
            for relay in relays[:3]:
                nak_cmd.append(relay)
            
            logger.info(f"Sending Nostr DM to pubkey {pubkey}")
            
            # Execute the command asynchronously
            process = await asyncio.create_subprocess_exec(
                *nak_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                # Extract the new event ID from the stdout of the nak command
                try:
                    response_text = stdout.decode().strip()
                    # Parse the JSON response to get the new DM event ID
                    response_data = json.loads(response_text)
                    new_event_id = response_data.get("id")
                    
                    if new_event_id:
                        # Store the DM event ID in the notified field
                        await self.database_service.update_cyberherd_notified(pubkey, new_event_id)
                        logger.info(f"Successfully sent Nostr DM (ID: {new_event_id}) to member {pubkey}")
                    else:
                        logger.warning(f"DM sent but couldn't extract event ID for {pubkey}.")
                except (json.JSONDecodeError, ValueError) as e:
                    logger.warning(f"DM sent but couldn't parse response for {pubkey}: {e}.")
            else:
                error_output = stderr.decode().strip() if stderr else "Unknown error"
                logger.error(f"Failed to send Nostr DM: {error_output}")
        
        except Exception as e:
            logger.error(f"Error sending Nostr DM for pubkey {pubkey}: {str(e)}")
    
    async def find_root_event(self, event_id: str) -> Optional[str]:
        """Find the root event of a thread by looking at the event's tags."""
        try:
            # Use nak to fetch the event
            relays = ["wss://relay.damus.io", "wss://relay.primal.net"]
            relay_str = " ".join(relays)
            
            command = f"/usr/local/bin/nak event get {event_id} {relay_str}"
            
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.warning(f"Failed to lookup event {event_id}: {stderr.decode()}")
                return None
            
            # Parse the event data
            event_data = json.loads(stdout.decode())
            
            # Look for root or reply tags
            for tag in event_data.get("tags", []):
                if tag[0] == "e" and len(tag) >= 3:
                    if tag[2] == "root":
                        logger.debug(f"Found root event {tag[1]} for {event_id}")
                        return tag[1]
            
            # If no root tag found, check for any e tag (might be implicit root)
            for tag in event_data.get("tags", []):
                if tag[0] == "e":
                    logger.debug(f"Found potential parent event {tag[1]} for {event_id}")
                    return tag[1]
            
            return None
        except Exception as e:
            logger.error(f"Error finding root event: {e}")
            return None
