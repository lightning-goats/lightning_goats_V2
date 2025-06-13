import asyncio
import random
import logging
import json
import subprocess
from typing import Set, Optional, List, Dict, Tuple, Any
from fastapi.websockets import WebSocket
from utils.cyberherd_module import DEFAULT_RELAYS

class MessagingService:
    def __init__(self, private_key: str, default_relays: List[str], message_template_service, database_service=None):
        self.private_key = private_key
        self.default_relays = default_relays or DEFAULT_RELAYS
        self.connected_clients: Set[WebSocket] = set()
        self.logger = logging.getLogger(__name__)
        self.notified = {}
        self.message_template_service = message_template_service
        self.database_service = database_service  # Add database_service for member queries
        self.cyberherd_service = None  # Will be set after initialization in app startup
        self.trigger_amount = 1250  # Default trigger amount
        
        # Track CyberHerd members
        self.cyber_herd_members = []
        self.max_displayed_members = 10  # Maximum number to send to clients
        
        # Goat names for messages
        self.goat_names_dict = {
            "Dexter":  [
                "nostr:nprofile1qqsw4zlzyfx43mc88psnlse8sywpfl45kuap9dy05yzkepkvu6ca5wg7qyak5",
                "ea8be2224d58ef0738613fc327811c14feb4b73a12b48fa1056c86cce6b1da39"
            ],
            "Rowan":   [
                "nostr:nprofile1qqs2w94r0fs29gepzfn5zuaupn969gu3fstj3gq8kvw3cvx9fnxmaugwur22r",
                "a716a37a60a2a32112674173bc0ccba2a3914c1728a007b31d1c30c54ccdbef1"
            ],
            "Nova":    [
                "nostr:nprofile1qqsrzy7clymq5xwcfhh0dfz6zfe7h63k8r0j8yr49mxu6as4yv2084s0vf035",
                "3113d8f9360a19d84deef6a45a1273ebea3638df2390752ecdcd76152314f3d6"
            ],
            "Cosmo":   [
                "nostr:nprofile1qqsq6n8u7dzrnhhy7xy78k2ee7e4wxlgrkm5g2rgjl3napr9q54n4ncvkqcsj",
                "0d4cfcf34439dee4f189e3d959cfb3571be81db744286897e33e8465052b3acf"
            ],
            "Newton":  [
                "nostr:nprofile1qqszdsnpyzwhjcqads3hwfywt5jfmy85jvx8yup06yq0klrh93ldjxc26lmyx",
                "26c261209d79601d6c2377248e5d249d90f4930c72702fd100fb7c772c7ed91b"
            ]
        }

    # WebSocket client management
    async def connect_client(self, websocket: WebSocket) -> None:
        """Register a new WebSocket client"""
        await websocket.accept()
        self.connected_clients.add(websocket)
        self.logger.info(f"Client connected. Total clients: {len(self.connected_clients)}")

    def disconnect_client(self, websocket: WebSocket) -> None:
        """Remove a disconnected WebSocket client"""
        if websocket in self.connected_clients:
            self.connected_clients.remove(websocket)
            self.logger.info(f"Client disconnected. Total clients: {len(self.connected_clients)}")

    async def close_all_connections(self) -> None:
        """Close all active client connections"""
        if not self.connected_clients:
            return
            
        self.logger.info(f"Closing {len(self.connected_clients)} WebSocket connections")
        for client in list(self.connected_clients):
            try:
                await client.close()
            except Exception as e:
                self.logger.debug(f"Error closing WebSocket: {e}")
            self.connected_clients.discard(client)

    # Message sending methods
    async def send_message_to_clients(self, message: str) -> None:
        """Send a message to all connected WebSocket clients"""
        if not message:
            self.logger.warning("Attempted to send an empty message. Skipping.")
            return

        # Check if the message is already formatted as JSON
        message_type = "unknown"
        try:
            # If it's already valid JSON, send it as-is (already formatted by make_messages)
            parsed_message = json.loads(message)
            message_type = parsed_message.get("type", "unknown")
            json_message = message
        except (json.JSONDecodeError, TypeError):
            # If not JSON, wrap it in a legacy format for backwards compatibility
            json_message = json.dumps({
                "type": "legacy",
                "message": message
            })
            message_type = "legacy"

        # Log before client broadcast for better timing analysis
        client_count = len(self.connected_clients)
        self.logger.info(f"Broadcasting message type '{message_type}' to {client_count} clients")

        # IMPORTANT: No delay between logging and actual sending
        
        # Send immediately to all clients
        if self.connected_clients:
            send_tasks = []
            for client in self.connected_clients.copy():
                try:
                    send_tasks.append(asyncio.create_task(client.send_text(json_message)))
                except Exception as e:
                    self.logger.warning(f"Failed to create send task for client: {e}")
                    self.disconnect_client(client)
            
            if send_tasks:
                # Use a shorter timeout to prevent hanging
                try:
                    await asyncio.gather(*send_tasks, return_exceptions=True)
                    self.logger.debug(f"Message sent to all clients")
                except Exception as e:
                    self.logger.error(f"Error during message broadcast: {e}")
        else:
            self.logger.debug(f"No connected clients to send message type '{message_type}'")

    async def periodic_informational_messages(self, chance: float = 0.4, interval: int = 60) -> None:
        """Send periodic informational messages with a certain chance"""
        while True:
            await asyncio.sleep(interval)
            if random.random() < chance:  # Default 40% chance
                message, _ = await self.make_messages(0, 0, "interface_info")
                await self.send_message_to_clients(message)

    def _extract_id_from_stdout(self, stdout: str) -> Optional[str]:
        """Extract event ID from JSON stdout"""
        try:
            data = json.loads(stdout)
            return data.get('id', None)
        except json.JSONDecodeError as e:
            self.logger.error(f"Error parsing JSON from stdout: {e}. Data: {stdout}")
            return None

    def _get_random_goat_names(self, goat_names_dict: Dict[str, List[str]]) -> List[Tuple[str, str, str]]:
        """Get a random selection of goat names"""
        keys = list(goat_names_dict.keys())
        selected_keys = random.sample(keys, random.randint(1, len(keys)))
        return [(key, goat_names_dict[key][0], goat_names_dict[key][1]) for key in selected_keys]

    def _join_with_and(self, items: List[str]) -> str:
        """Format a list into a comma-separated string with 'and'"""
        if len(items) > 2:
            return ', '.join(items[:-1]) + ', and ' + items[-1]
        elif len(items) == 2:
            return ' and '.join(items)
        elif len(items) == 1:
            return items[0]
        else:
            return ''
            
    def _format_template(self, template: str, values: Dict[str, Any]) -> str:
        """Format a template with values"""
        try:
            return template.format(**values)
        except KeyError as e:
            self.logger.error(f"Missing key in template formatting: {e}")
            return template
        except Exception as e:
            self.logger.error(f"Error formatting template: {e}")
            return template

    async def _get_template_text(self, message_type: str) -> str:
        """Get a template text from the message template service"""
        try:
            # Try to get a random template from the service
            template = await self.message_template_service.get_random_template(message_type)
            if not template or template.startswith("No templates found"):
                self.logger.warning(f"No template found for type {message_type}, using fallback")
                # Create a simple fallback template if none found
                return "Lightning Goats received {new_amount} sats. Need {difference} more sats to trigger the feeder."
            return template
        except Exception as e:
            self.logger.error(f"Error getting template for {message_type}: {e}")
            return "Lightning Goats received a payment. Thank you!"

    async def load_all_cyberherd_members(self, force_reload=False):
        """Force reload all CyberHerd members from the database"""
        if not self.database_service:
            self.logger.warning("Cannot load CyberHerd members: No database_service available")
            return False
            
        try:
            # Only reload if forced or we have fewer than 3 members cached
            if not force_reload and len(self.cyber_herd_members) > 2:
                self.logger.debug(f"Using {len(self.cyber_herd_members)} cached members")
                return True
                
            # Fetch all members from the database with more debug info
            db_members = await self.database_service.get_cyberherd_list()
            self.logger.info(f"Loaded {len(db_members)} CyberHerd members from database")
            
            # Log more details to diagnose the issue
            self.logger.debug(f"CyberHerd members from DB: {[m.get('pubkey', 'unknown') for m in db_members]}")
            
            # Reset our internal list completely before repopulating
            self.cyber_herd_members = []
            
            # Convert database records to our internal format
            for member in db_members:
                member_data = {
                    "pubkey": member.get("pubkey", ""),
                    "display_name": member.get("display_name", "Anon"),
                    "picture": member.get("picture", ""),
                    "nprofile": member.get("nprofile", ""),
                    "kinds": member.get("kinds", ""),
                    "amount": member.get("amount", 0),
                    "timestamp": member.get("timestamp", int(asyncio.get_event_loop().time() * 1000))
                }
                # Add each member to our list
                self.cyber_herd_members.append(member_data)
            
            # Verify we have all members loaded
            self.logger.info(f"Successfully loaded {len(self.cyber_herd_members)} CyberHerd members into memory")
            
            # Try to ensure complete data if we have cyberherd service
            if len(self.cyber_herd_members) < 3 and self.cyberherd_service:
                await self.cyberherd_service.ensure_complete_cyberherd_data(self)
            
            return True
        except Exception as e:
            self.logger.error(f"Error loading CyberHerd members: {e}", exc_info=True)
            return False

    async def make_messages(
        self, 
        new_amount: float,
        difference: float,
        event_type: str,
        cyber_herd_item: dict = None,
        spots_remaining: int = 0,
        relays: list = None,
    ) -> Tuple[str, Optional[str]]:
        """
        Create and format nostr messages.
        Returns tuple of (message_for_clients, command_output)
        """
        self.logger.debug(f"Creating message of type '{event_type}' with amount={new_amount}, difference={difference}")
        
        if not relays:
            relays = self.default_relays
        
        # Fix: Properly clean and format relay URLs before joining them
        # This ensures any spaces or formatting issues are removed
        cleaned_relays = []
        for relay in relays:
            if relay:
                # Remove any spaces within the URL and ensure proper formatting
                cleaned_relay = ''.join(relay.strip().split())
                # Ensure it starts with wss:// or ws://
                if cleaned_relay.startswith(('wss://', 'ws://')):
                    cleaned_relays.append(cleaned_relay)
        
        # If we don't have any valid relays after cleaning, use defaults
        if not cleaned_relays:
            cleaned_relays = DEFAULT_RELAYS[:3]
        
        # Now use the cleaned relays
        relay_str = ' '.join(cleaned_relays)
        self.logger.debug(f"Using relay string: {relay_str}")
        
        # Get template based on event type - now uses message template service
        template = await self._get_template_text(event_type)
        command = None
        
        # Default to legacy message type if not specified
        message_type = "message"

        # -- Handle each event_type separately --
        if event_type == "cyber_herd":
            message_type = "cyberherd_user"
            display_name = cyber_herd_item.get("display_name", "anon")
            event_id = cyber_herd_item.get("event_id", "")
            pub_key = cyber_herd_item.get("pubkey", "")
            nprofile = cyber_herd_item.get("nprofile", "")
            amount = cyber_herd_item.get("amount", 0)
            original_note_id = cyber_herd_item.get("original_note_id", "")
            picture = cyber_herd_item.get("picture", "")
            kinds = cyber_herd_item.get("kinds", "")
            
            # Update our internal cyber_herd_members list with the new member
            self._update_cyber_herd_members(cyber_herd_item)
            
            # IMPORTANT: Force reload ALL members from database and service
            # Call the method in CyberHerd service instead of locally
            if self.cyberherd_service:
                await self.cyberherd_service.ensure_complete_cyberherd_data(self)
            else:
                # Fallback to direct database load if no cyberherd service
                await self.load_all_cyberherd_members(force_reload=True)
            
            # Additional context for repost (kind 6 events)
            repost_context = ""
            if original_note_id:
                repost_context = f" reposting note {original_note_id[:8]}..."
            
            # Decide on a "thank you" snippet
            if amount == 0:
                thanks_part = ""
            else:
                thank_you_variations = await self.message_template_service.get_template("thank_you_variations")
                if thank_you_variations and isinstance(thank_you_variations, list) and thank_you_variations:
                    chosen_variation = random.choice(thank_you_variations)
                    thanks_part = chosen_variation.format(new_amount=amount)
                else:
                    thanks_part = f"Thanks for the {amount} sats!"

            # Ensure nprofile is well-formed
            if nprofile and not nprofile.startswith("nostr:"):
                nprofile = f"nostr:{nprofile}"

            name = nprofile if nprofile else display_name

            # Spots info
            spots_info = ""
            if spots_remaining > 1:
                spots_info = f"⚡ {spots_remaining} more spots available. ⚡"
            elif spots_remaining == 1:
                spots_info = f"⚡ {spots_remaining} more spot available. ⚡"
            elif spots_remaining == 0:
                spots_info = "The ⚡ CyberHerd ⚡ is full for today!"

            try:
                message_text = template.format(
                    thanks_part=thanks_part,
                    name=name,
                    difference=difference,
                    new_amount=cyber_herd_item.get("amount", 0),
                    event_id=cyber_herd_item.get("event_id", "N/A"),
                    repost_context=repost_context
                )
            except KeyError:
                # Fallback if repost_context not in template
                message_text = template.format(
                    thanks_part=thanks_part,
                    name=name,
                    difference=difference,
                    new_amount=cyber_herd_item.get("amount", 0),
                    event_id=cyber_herd_item.get("event_id", "N/A")
                )
                if original_note_id:
                    message_text = f"{message_text} (reposting note {original_note_id[:8]}...)"

            message_text = f"{message_text} {spots_info}".strip()

            command = (
                f'/usr/local/bin/nak event --sec {self.private_key} -c "{message_text}" '
                f'--tag e="{event_id};{relays[0]};root" '
                f'-p {pub_key} '
                f'{relay_str}'
            )
            
            # Replace nprofile with name in message for web client display
            if nprofile and nprofile in message_text:
                message_text = message_text.replace(nprofile, display_name)

            # Get all CyberHerd members to include in the message
            all_members = self._get_all_cyber_herd_members(pub_key)  # Mark current member as newest

            # Log the number of members being sent to the client
            self.logger.info(f"Sending {len(all_members)} CyberHerd members to clients")
            if len(all_members) <= 2:
                self.logger.warning("Only two or fewer members being sent! This indicates a potential issue.")
                # Additional debug info to log actual members
                self.logger.debug(f"Members being sent: {[m.get('display_name', 'unknown') for m in all_members]}")

            # Create JSON message with structured data including ALL members
            message = json.dumps({
                "type": message_type,
                "message": message_text,
                "data": {
                    "pubkey": pub_key,
                    "display_name": display_name,
                    "picture": picture,
                    "nprofile": nprofile,
                    "kinds": kinds,
                    "spots_remaining": spots_remaining,
                    "amount": amount,
                    "all_members": all_members  # Include all members in one message
                }
            })

        elif event_type in ["sats_received", "feeder_triggered"]:
            message_type = "payment_event" if event_type == "sats_received" else "feeder_event"
            
            # Determine if the template contains any goat names
            goat_names = list(self.goat_names_dict.keys())  # Correct Python syntax
            mentioned_goats = []
            
            # First try to render template without goats to see what will be in the message
            temp_message = template.format(
                new_amount=new_amount,
                goat_name="",  # Empty placeholder
                difference_message=f"{difference} more sats needed!"
            )
            
            # Check if any goats should be in the message
            include_goats = "{goat_name}" in template and "goat_name" not in temp_message
            
            if include_goats:
                # Get random goats for the message only if the template requires them
                selected_goats = self._get_random_goat_names(self.goat_names_dict)
                goat_names_text = self._join_with_and([name for name, _, _ in selected_goats])
                goat_nprofiles = self._join_with_and([nprofile for _, nprofile, _ in selected_goats])
                goat_pubkeys = [pubkey for _, _, pubkey in selected_goats]
                mentioned_goats = selected_goats
            else:
                # Don't include any goats if the template doesn't need them
                goat_names_text = ""
                goat_nprofiles = ""
                goat_pubkeys = []
                mentioned_goats = []

            # Get variation for difference message from database
            difference_variations = await self.message_template_service.get_template("difference_variations")
            if difference_variations and len(difference_variations) > 0:
                variation_message = random.choice(list(difference_variations.values()))
            else:
                # Fallback if no templates found
                variation_message = "{difference} more sats needed!"
            difference_message = variation_message.format(difference=difference)

            # First formatting includes goat_nprofiles (for Nostr command)
            message_text = template.format(
                new_amount=new_amount,
                goat_name=goat_nprofiles,
                difference_message=difference_message
            )

            # Construct command only if we have goat pubkeys
            if goat_pubkeys:
                pubkey_part = " ".join(f"-p {pubkey}" for pubkey in goat_pubkeys)
                command = (
                    f'/usr/local/bin/nak event --sec {self.private_key} -c "{message_text}" '
                    f' --tag t=LightningGoats {pubkey_part} '
                    f'{relay_str}'
                )
            else:
                # Simple command without goat pubkeys
                command = (
                    f'/usr/local/bin/nak event --sec {self.private_key} -c "{message_text}" '
                    f' --tag t=LightningGoats '
                    f'{relay_str}'
                )

            # Then reformat to show goat_names in the final message
            message_text = template.format(
                new_amount=new_amount,
                goat_name=goat_names_text,
                difference_message=difference_message
            )

            # Create JSON message with structured data - include more useful data:
            message_data = {
                "amount": new_amount,
                "difference": difference,
                "balance": self.balance if hasattr(self, 'balance') else None,
            }
                            
            # For feeder_triggered, include the goat_feedings count
            if event_type == "feeder_triggered":
                try:
                    from services.goat_service import GoatStateService
                    if hasattr(self, 'goat_service') and isinstance(self.goat_service, GoatStateService):
                        feedings = await self.goat_service.get_feedings_count()
                        message_data["goat_feedings"] = feedings
                except Exception as e:
                    self.logger.error(f"Error fetching feedings for message: {e}")

            # Only add goats array if goats are actually mentioned
            if mentioned_goats:
                message_data["goats"] = [{"name": name, "pubkey": pubkey} for name, _, pubkey in mentioned_goats]
                
            message = json.dumps({
                "type": message_type,
                "message": message_text,
                "data": message_data
            })
            
            self.logger.info(f"Created {message_type} message: {new_amount} sats received, {difference} sats to go")

        elif event_type == "cyber_herd_treats":
            message_type = "cyberherd_treats"
            display_name = cyber_herd_item.get('display_name', '')
            event_id = cyber_herd_item.get('notified', '')
            pub_key = cyber_herd_item.get('pubkey', '')
            nprofile = cyber_herd_item.get('nprofile', '')
            
            # Try to find root event ID if available
            root_event = await self.find_root_event(event_id, relays)

            if nprofile and not nprofile.startswith("nostr:"):
                nprofile = f"nostr:{nprofile}"

            message_text = template.format(new_amount=new_amount, name=nprofile, difference=difference)
            
            # Create e-tags for reply
            e_tags = []
            for relay in relays[:3]:  # Use up to 3 relays for e-tags
                e_tags.append(f'--tag e="{event_id};{relay};reply"')
            
            # Add root event if different from reply-to event
            if root_event and root_event != event_id:
                for relay in relays[:3]:
                    e_tags.append(f'--tag e="{root_event};{relay};root"')
                    
            e_tags_str = ' '.join(e_tags)
            
            command = f'/usr/local/bin/nak event --sec {self.private_key} -c "{message_text}" --tag t=LightningGoats {e_tags_str} -p {pub_key} {relay_str}'
            
            # Replace nprofile with name in message for web client display
            if nprofile and nprofile in message_text:
                message_text = message_text.replace(nprofile, display_name)
            
            # Create JSON message with structured data
            message = json.dumps({
                "type": message_type,
                "message": message_text,
                "data": {
                    "pubkey": pub_key,
                    "display_name": display_name,
                    "picture": cyber_herd_item.get("picture"),
                    "amount": new_amount,
                    "nprofile": nprofile
                }
            })
            
        elif event_type == "interface_info":
            message_type = "info_message"
            # Simple usage
            message_text = template.format(
                new_amount=0, 
                goat_name="", 
                difference_message="",
                difference=0  # Add the missing difference parameter
            )
            
            # Create JSON message with structured data
            message = json.dumps({
                "type": message_type,
                "message": message_text,
                "data": {}
            })
            
            command = None
            
        # Execute command if needed - BUT DON'T MAKE WEB CLIENTS WAIT FOR IT
        command_output = None
        if command:
            # Instead of awaiting the command directly, create a background task
            asyncio.create_task(self._execute_nostr_command(command))
            # Return immediately to clients without waiting for Nostr command to finish

        # Log that we're returning the message
        self.logger.debug(f"Returning message of type '{message_type}'")
        return message, command_output

    def _update_cyber_herd_members(self, new_member):
        """Add or update a member in the cyber herd tracking list"""
        if not new_member or not new_member.get("pubkey"):
            return
        
        pubkey = new_member.get("pubkey")
        
        # Check if this member already exists
        existing_index = next((i for i, m in enumerate(self.cyber_herd_members) 
                              if m.get("pubkey") == pubkey), None)
        
        member_data = {
            "pubkey": pubkey,
            "display_name": new_member.get("display_name", "Anon"),
            "picture": new_member.get("picture", ""),
            "nprofile": new_member.get("nprofile", ""),
            "kinds": new_member.get("kinds", ""),
            "amount": new_member.get("amount", 0),
            "timestamp": new_member.get("timestamp", int(asyncio.get_event_loop().time() * 1000))
        }
        
        if existing_index is not None:
            # Update existing member but preserve their timestamp
            orig_timestamp = self.cyber_herd_members[existing_index].get("timestamp")
            member_data["timestamp"] = orig_timestamp
            self.cyber_herd_members[existing_index] = member_data
        else:
            # Add new member to front of list
            self.cyber_herd_members.insert(0, member_data)
        
        # Limit list size
        if len(self.cyber_herd_members) > self.max_displayed_members * 2:
            # Sort by timestamp (newest first) and keep only what we need
            self.cyber_herd_members.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
            self.cyber_herd_members = self.cyber_herd_members[:self.max_displayed_members * 2]
            
    def _get_all_cyber_herd_members(self, newest_pubkey=None):
        """Get all tracked cyber herd members with the newest one marked"""
        # Log the current members count before any processing
        self.logger.info(f"Getting all CyberHerd members from memory. Currently have {len(self.cyber_herd_members)} members.")
        
        # Sort members by timestamp (newest first)
        sorted_members = sorted(self.cyber_herd_members, 
                               key=lambda x: x.get("timestamp", 0),
                               reverse=True)
        
        # Use ALL members, not just max_displayed_members
        members_to_send = sorted_members
        
        # Mark the newest member
        for member in members_to_send:
            # Mark as newest if specified by pubkey or if it's the first in the sorted list
            is_newest = (newest_pubkey and member.get("pubkey") == newest_pubkey) or \
                        (not newest_pubkey and member == members_to_send[0])
                       
            member["is_newest"] = is_newest
        
        # Log how many members we're sending to help with debugging
        self.logger.info(f"Sending {len(members_to_send)} CyberHerd members to clients")
        
        if len(members_to_send) <= 2:
            self.logger.warning(f"Only {len(members_to_send)} members in cyber_herd_members list - attempting emergency reload from database")
            # Trigger an immediate reload asynchronously 
            asyncio.create_task(self._emergency_reload_members())
            
        return members_to_send

    async def _emergency_reload_members(self):
        """Emergency reload of members if we detect too few in the list"""
        try:
            # Force reload from database
            if self.cyberherd_service:
                self.logger.info("Attempting to load members from cyberherd_service...")
                members = await self.cyberherd_service.get_all_members()
                if members:
                    self.logger.info(f"Found {len(members)} members in cyberherd_service")
                    # Convert to our internal format
                    for member in members:
                        self._update_cyber_herd_members({
                            "pubkey": member.get("pubkey", ""),
                            "display_name": member.get("display_name", "Anon"),
                            "picture": member.get("picture", ""),
                            "nprofile": member.get("nprofile", ""),
                            "kinds": member.get("kinds", ""),
                            "amount": member.get("amount", 0)
                        })
            else:
                # Fallback to direct database access
                await self.load_all_cyberherd_members()
            
            self.logger.info(f"Emergency reload complete. Now have {len(self.cyber_herd_members)} members.")
        except Exception as e:
            self.logger.error(f"Emergency reload failed: {e}", exc_info=True)

    async def _execute_nostr_command(self, command: str) -> Optional[str]:
        """Execute a Nostr command in the background."""
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                self.logger.error(f"Nostr command failed with error: {stderr.decode().strip()}")
                return stderr.decode()
            else:
                self.logger.debug("Nostr command executed successfully")
                return stdout.decode()
        except Exception as e:
            self.logger.error(f"Failed to execute Nostr command: {e}")
            return f"Error: {str(e)}"

    async def find_root_event(self, event_id: str, relays: List[str]) -> Optional[str]:
        """Find the root event of a thread by looking at the event's tags."""
        try:
            if not event_id or not relays:
                return None
                
            relay_str = " ".join(relays[:3])
            command = f"/usr/local/bin/nak event get {event_id} {relay_str}"
            
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                self.logger.warning(f"Failed to lookup event {event_id}: {stderr.decode()}")
                return None
            
            # Parse the event data
            event_data = json.loads(stdout.decode())
            
            # Look for a root tag in the event tags
            if 'tags' in event_data:
                for tag in event_data['tags']:
                    if len(tag) >= 3 and tag[0] == 'e' and tag[2] == 'root':
                        return tag[1]
            
            return None
            
        except (json.JSONDecodeError, asyncio.SubprocessError) as e:
            self.logger.error(f"Error processing event {event_id}: {str(e)}")
            return None