import json
import logging
import math
import time  # Add missing import for time.time()
import asyncio  # Added missing import for async sleep and tasks
from typing import List, Dict, Set, Any, Tuple, Optional, Union
from math import floor

from services.database_service import DatabaseService
from services.payment_service import PaymentService
from services.messaging_service import MessagingService
from utils.cyberherd_module import MetadataFetcher, Verifier, generate_nprofile, DEFAULT_RELAYS

logger = logging.getLogger(__name__)

class CyberHerdService:
    def __init__(self, 
                 database_service: DatabaseService, 
                 payment_service: PaymentService, 
                 messaging_service: MessagingService,
                 max_herd_size: int = 10,
                 predefined_wallet_address: str = None,
                 predefined_wallet_alias: str = None,
                 predefined_wallet_reset_percent: int = 100,
                 trigger_amount: int = 1250):  # Added parameter
        """Initialize the CyberHerd service."""
        self.database = database_service
        self.payment_service = payment_service
        self.messaging_service = messaging_service
        self.logger = logger
        
        # Configuration
        self.max_herd_size = max_herd_size
        self.predefined_wallet_address = predefined_wallet_address
        self.predefined_wallet_alias = predefined_wallet_alias
        self.predefined_wallet_reset_percent = predefined_wallet_reset_percent
        self.trigger_amount = trigger_amount
    
    async def get_remaining_spots(self) -> int:
        """Get number of remaining spots in the CyberHerd."""
        current_size = await self.database.get_cyberherd_size()
        return max(0, self.max_herd_size - current_size)
    
    async def get_all_members(self) -> List[Dict[str, Any]]:
        """Get all current CyberHerd members."""
        return await self.database.get_cyberherd_list()
    
    async def get_member(self, pubkey: str) -> Optional[Dict[str, Any]]:
        """Get a specific member by pubkey."""
        return await self.database.get_cyberherd_member(pubkey)
    
    async def get_member_by_lud16(self, lud16: str) -> Optional[Dict[str, Any]]:
        """Get a specific member by Lightning address."""
        return await self.database.get_cyberherd_member_by_lud16(lud16)
    
    async def delete_member(self, lud16: str) -> bool:
        """Delete a member by Lightning address."""
        record = await self.get_member_by_lud16(lud16)
        if not record:
            return False
        
        try:
            # First delete from database
            await self.database.delete_cyberherd_member_by_lud16(lud16)
            self.logger.info(f"Deleted member with lud16 {lud16} from database")

            # Then update LNbits targets by removing this member
            try:
                # Get current targets from LNbits
                current_targets = await self.payment_service.fetch_cyberherd_targets()
                if not current_targets or "targets" not in current_targets:
                    self.logger.warning(f"No current targets found when deleting {lud16}")
                    return True  # Member was deleted from DB, so consider it success
                    
                # Filter out the deleted member
                updated_targets = {
                    "targets": [
                        target for target in current_targets["targets"] 
                        if target.get("wallet") != lud16
                    ]
                }
                
                # Update targets in LNbits (removing the deleted member)
                if updated_targets["targets"]:
                    await self.payment_service.update_cyberherd_targets(updated_targets)
                    self.logger.info(f"Removed {lud16} from LNbits targets")
                else:
                    self.logger.warning("No targets left after filtering - maintaining current targets")
                    
            except Exception as e:
                # Log error but don't fail the entire deletion if LNbits update fails
                self.logger.error(f"Failed to update LNbits targets after deleting {lud16}: {e}")
            
            return True
        except Exception as e:
            self.logger.error(f"Error deleting member {lud16}: {e}")
            return False
    
    async def reset_cyberherd(self) -> Dict[str, Any]:
        """Reset the CyberHerd by deleting all members and resetting targets."""
        try:
            # Delete all members from database
            await self.database.delete_all_cyberherd_members()
            logger.info("CyberHerd table cleared successfully.")
            
            # Reset payment targets
            deleted = await self.payment_service.delete_cyberherd_targets()
            if not deleted:
                logger.error("Failed to delete existing CyberHerd targets")
                return {
                    "success": False,
                    "message": "Failed to delete existing CyberHerd targets"
                }
                
            logger.info("Existing CyberHerd targets deleted successfully.")
            
            # Create default target for predefined wallet
            predefined_wallet = {
                'wallet': self.predefined_wallet_address,
                'alias': self.predefined_wallet_alias,
                'percent': self.predefined_wallet_reset_percent
            }
            new_targets = {"targets": [predefined_wallet]}
            
            await self.payment_service.update_cyberherd_targets(new_targets)
            logger.info(f"Predefined CyberHerd target created with {self.predefined_wallet_reset_percent}% allocation.")
            
            return {
                "success": True,
                "message": f"CyberHerd reset successfully with predefined target at {self.predefined_wallet_reset_percent}% allocation."
            }
        except Exception as e:
            logger.error(f"Error resetting CyberHerd: {e}")
            return {
                "success": False,
                "message": f"Error: {str(e)}"
            }
    
    def calculate_payout(self, amount: float) -> float:
        """Calculate payout based on the amount received."""
        units = (amount + 9) // 10  # Ceiling division for multiples of 10
        payout = units * 0.01  # Each 10 sats = 0.01 payout
        payout = max(0.3, min(payout, 1.0))
        return payout
    
    def parse_kinds(self, kinds: Union[List[int], str]) -> List[int]:
        """Parse kinds from either list or comma-separated string."""
        if isinstance(kinds, list):
            return kinds
        elif isinstance(kinds, str):
            try:
                return [int(k.strip()) for k in kinds.split(',') if k.strip().isdigit()]
            except ValueError as e:
                logger.error(f"Error parsing kinds string: {e}")
                return []
        else:
            logger.warning(f"Unexpected type for 'kinds': {type(kinds)}")
            return []
    
    def parse_current_kinds(self, kinds_str: str) -> Set[int]:
        """Parse current kinds from comma-separated string."""
        if not kinds_str:
            return set()
        try:
            return set(int(k.strip()) for k in kinds_str.split(',') if k.strip().isdigit())
        except ValueError as e:
            logger.error(f"Error parsing current kinds: {e}")
            return set()
    
    def calculate_member_updates(
        self,
        kinds_int: List[int],
        current_kinds: Set[int],
        new_amount: int
    ) -> Tuple[float, str]:
        """Calculate payout increments and updated kinds string."""
        payout_increment = 0.0

        # Zap-based payout for both zap request and receipt
        if 9734 in kinds_int or 9735 in kinds_int:
            zap_payout = self.calculate_payout(float(new_amount))
            payout_increment += zap_payout

        # Special kinds payouts
        new_special_kinds = [k for k in [6, 7] if k in kinds_int and k not in current_kinds]
        for k in new_special_kinds:
            if k == 7:
                payout_increment += 0.0
            elif k == 6:
                payout_increment += 0.2

        # Merge and format kinds
        updated_kinds_set = current_kinds.union(set(kinds_int))
        updated_kinds_str = ','.join(map(str, sorted(updated_kinds_set)))

        return payout_increment, updated_kinds_str
    
    async def update_lnbits_targets(self, new_targets: List[Dict] = None) -> bool:
        """Update LNbits targets with current members."""
        try:
            # Get current targets from LNbits
            max_retries = 3
            initial_targets = None
            
            # Add retry logic for fetching targets
            for attempt in range(max_retries):
                try:
                    initial_targets = await self.payment_service.fetch_cyberherd_targets()
                    if initial_targets is not None:
                        break
                    self.logger.warning(f"Attempt {attempt+1}/{max_retries}: Failed to fetch targets from LNbits, retrying...")
                    await asyncio.sleep(0.5 * (attempt + 1))  # Increasing backoff
                except Exception as e:
                    self.logger.warning(f"Attempt {attempt+1}/{max_retries}: Error fetching targets: {e}")
                    if attempt < max_retries - 1:
                        await asyncio.sleep(0.5 * (attempt + 1))
            
            # Initialize with empty targets if fetch failed
            if initial_targets is None:
                self.logger.warning("Could not fetch current targets from LNbits after retries - initializing with empty targets")
                initial_targets = {"targets": []}
            elif "targets" not in initial_targets:
                self.logger.warning("LNbits response missing 'targets' field - initializing with empty targets")
                initial_targets = {"targets": []}
                
            self.logger.debug(f"Current LNbits targets: {initial_targets}")
            
            # Always get all current members with valid Lightning addresses
            current_members = await self.database.get_cyberherd_members_with_lud16()
            
            # Log the members for debugging
            self.logger.info(f"Found {len(current_members)} members with valid lud16 in database")
            for member in current_members:
                self.logger.debug(f"Member in database: {member['lud16']} (payouts: {member['payouts']})")
            
            # Build a dictionary of existing members by lud16 for easy lookup and updating
            all_targets_dict = {
                member['lud16']: {
                    'wallet': member['lud16'],
                    'alias': member['display_name'] if 'display_name' in member else member['pubkey'],
                    'payouts': member['payouts']
                }
                for member in current_members
            }
            
            # If new targets are provided, update the dictionary with them
            if new_targets:
                self.logger.info(f"Adding {len(new_targets)} new targets to update")
                for target in new_targets:
                    wallet = target['wallet']
                    # Get existing payouts for this wallet
                    existing_payouts = all_targets_dict.get(wallet, {}).get('payouts', 0.0)
                    new_payouts = target.get('payouts', 0.0)
                    
                    # Find member by lud16 to get the pubkey for alias
                    pubkey = target.get('pubkey', 'Unknown')
                    if wallet != self.predefined_wallet_address:
                        # Look up the member by wallet/lud16 to get their pubkey
                        member = await self.database.get_cyberherd_member_by_lud16(wallet)
                        if member:
                            pubkey = member['pubkey']
                    
                    # Update or add the target, ADDING the new payouts to existing ones
                    all_targets_dict[wallet] = {
                        'wallet': wallet,
                        'alias': pubkey,  # Always use pubkey as alias
                        'payouts': existing_payouts + new_payouts
                    }
                    self.logger.debug(f"Updated target: {wallet} (existing: {existing_payouts}, new: {new_payouts}, total: {existing_payouts + new_payouts})")
            
            # Convert back to a list
            all_targets = list(all_targets_dict.values())
            
            self.logger.info(f"Updating LNbits targets with {len(all_targets)} members")
            
            # Create updated targets with appropriate allocations
            updated_targets = await self.create_cyberherd_targets(
                new_targets_data=all_targets,
                initial_targets=initial_targets
            )
            
            if not updated_targets:
                self.logger.error("Failed to create updated targets - got None response")
                return False
                
            self.logger.debug(f"Prepared updated targets: {updated_targets}")
            
            # Update targets in LNbits with retry logic
            if updated_targets:
                for attempt in range(max_retries):
                    try:
                        result = await self.payment_service.update_cyberherd_targets(updated_targets)
                        if result:
                            self.logger.info(f"LNbits targets updated successfully with {len(updated_targets['targets'])} targets")
                            return True
                        else:
                            self.logger.warning(f"Attempt {attempt+1}/{max_retries}: LNbits update_cyberherd_targets returned falsy value")
                            if attempt < max_retries - 1:
                                await asyncio.sleep(0.5 * (attempt + 1))
                    except Exception as e:
                        self.logger.warning(f"Attempt {attempt+1}/{max_retries}: Error updating LNbits targets: {e}")
                        if attempt < max_retries - 1:
                            await asyncio.sleep(0.5 * (attempt + 1))
                
                self.logger.error("All attempts to update LNbits targets failed")
                return False
            else:
                self.logger.warning("No targets to update for LNbits.")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to update LNbits targets: {e}", exc_info=True)
            return False
    
    async def create_cyberherd_targets(self, new_targets_data: List, initial_targets: Dict) -> Dict:
        """Create payment targets for CyberHerd based on member data."""
        try:
            non_predefined = [
                item for item in new_targets_data 
                if item['wallet'] != self.predefined_wallet_address
            ]
            
            # Always set predefined wallet to 90%
            predefined_wallet = {
                'wallet': self.predefined_wallet_address,
                'alias': self.predefined_wallet_alias,
                'percent': 90  # Fixed at 90%
            }
            
            # Remaining 10% to split between other wallets
            max_allocation = 10  # The remaining percentage for other wallets

            combined_wallets = []
            for item in new_targets_data:
                wallet = item['wallet']
                pubkey = item.get('pubkey', item.get('alias', 'Unknown'))  # Try to use pubkey directly or from alias
                payouts = item.get('payouts', 1.0)
                if wallet != self.predefined_wallet_address:
                    combined_wallets.append({'wallet': wallet, 'alias': pubkey, 'payouts': payouts})

            total_payouts = sum(w['payouts'] for w in combined_wallets) or 1
            min_percent_per_wallet = 1
            max_wallets_allowed = floor(max_allocation / min_percent_per_wallet)

            # Limit number of wallets if necessary
            if len(combined_wallets) > max_wallets_allowed:
                combined_wallets = sorted(
                    combined_wallets,
                    key=lambda x: x['payouts'],
                    reverse=True
                )[:max_wallets_allowed]
                total_payouts = sum(w['payouts'] for w in combined_wallets) or 1

            # Initial minimum allocation
            for wallet in combined_wallets:
                wallet['percent'] = min_percent_per_wallet
            allocated = min_percent_per_wallet * len(combined_wallets)
            remaining_allocation = max_allocation - allocated

            # Distribute remaining allocation proportionally
            if remaining_allocation > 0 and combined_wallets:
                for wallet in combined_wallets:
                    prop = wallet['payouts'] / total_payouts
                    additional = floor(prop * remaining_allocation)
                    wallet['percent'] += additional

                # Handle any leftover percent due to rounding
                current_total = sum(w['percent'] for w in combined_wallets)
                leftover = max_allocation - current_total
                
                if leftover > 0:
                    # Sort by payouts and give extra percents to top contributors
                    sorted_wallets = sorted(combined_wallets, key=lambda x: x['payouts'], reverse=True)
                    for i in range(int(leftover)):
                        sorted_wallets[i % len(sorted_wallets)]['percent'] += 1

            targets_list = [predefined_wallet] + combined_wallets
            return {"targets": targets_list}

        except Exception as e:
            logger.error(f"Error creating cyberherd targets: {e}")
            return None
    
    async def process_new_member(self, item_dict: dict) -> Tuple[Dict, Dict]:
        """Process a new member joining the cyber herd."""
        pubkey = item_dict['pubkey']
        item_dict['notified'] = None

        # Add timestamp if missing
        if 'timestamp' not in item_dict or not item_dict['timestamp']:
            item_dict['timestamp'] = int(time.time() * 1000)

        # If relays not provided, use default configuration
        if 'relays' not in item_dict or not item_dict['relays']:
            item_dict['relays'] = DEFAULT_RELAYS[:3]
        else:
            # Ensure relays are properly formatted without spaces
            if isinstance(item_dict['relays'], list):
                item_dict['relays'] = [relay.strip().replace(' ', '') for relay in item_dict['relays'] if relay]
            elif isinstance(item_dict['relays'], str):
                try:
                    # Try to parse JSON string to list
                    relays_list = json.loads(item_dict['relays'])
                    if isinstance(relays_list, list):
                        item_dict['relays'] = [relay.strip().replace(' ', '') for relay in relays_list if relay]
                    else:
                        item_dict['relays'] = DEFAULT_RELAYS[:3]
                except json.JSONDecodeError:
                    # If not valid JSON, use as a single relay
                    item_dict['relays'] = [item_dict['relays'].strip().replace(' ', '')]

        # Ensure 'kinds' is a comma-separated string
        if isinstance(item_dict['kinds'], list):
            item_dict['kinds'] = ','.join(map(str, item_dict['kinds']))
        elif isinstance(item_dict['kinds'], str):
            # Make sure it's properly formatted
            item_dict['kinds'] = item_dict['kinds'].strip()
        else:
            item_dict['kinds'] = ""

        # Parse kinds into integers and verify eligible for membership
        kinds_int = self.parse_kinds(item_dict['kinds'])
        
        # Only allow members with qualifying actions:
        # - kind 6 (reposts)
        # - kind 9734 (zap requests)
        # - kind 9735 (zap receipts)
        # - Any member with lud16 and a kind set (for manual additions)
        if not (any(k in [6, 9734, 9735] for k in kinds_int) or 
                (item_dict.get('lud16') and item_dict['kinds'])):
            self.logger.warning(f"Member {pubkey} does not qualify for membership: no eligible kinds")
            return None, None
        
        # Calculate payouts based on kind
        if 9734 in kinds_int or 9735 in kinds_int:
            if 'amount' in item_dict and item_dict['amount'] > 0:
                item_dict['payouts'] = self.calculate_payout(float(item_dict['amount']))
            else:
                item_dict['payouts'] = 0
                item_dict['amount'] = 0
        elif 6 in kinds_int:
            item_dict['payouts'] = 0.2  # Default value for reposts
            if 'amount' not in item_dict or not item_dict['amount']:
                item_dict['amount'] = 0
        else:
            item_dict['payouts'] = 0
            if 'amount' not in item_dict or not item_dict['amount']:
                item_dict['amount'] = 0

        # Prepare notification data
        notify_data = {
            'pubkey': pubkey,
            'type': 'new_member',
            'data': item_dict
        }
        
        # Prepare target data if applicable
        target_data = None
        if item_dict.get('lud16'):
            percent = min(max(round(float(item_dict['payouts']) * 100), 2), 25)
            target_data = {
                'wallet': item_dict['lud16'],
                'alias': item_dict.get('display_name', 'Anon'),
                'percent': percent
            }
        else:
            self.logger.info(f"No lud16 found for {pubkey}, not creating payment target")

        try:
            # Insert member into the database
            await self.database.insert_cyberherd_member(item_dict)
            self.logger.info(f"Added new member {pubkey}")
            return notify_data, target_data
        except Exception as e:
            self.logger.error(f"Error adding new member {pubkey}: {e}")
            return None, None
    
    async def process_existing_member(
        self, 
        item_dict: dict, 
        item: Any, 
        result: dict
    ) -> Tuple[Dict, Dict]:
        """Handle updates to an existing member in the cyber herd."""
        pubkey = item_dict['pubkey']
        new_amount = item_dict.get('amount', 0)
        kinds_int = self.parse_kinds(item_dict['kinds'])
        
        if not kinds_int:
            return None, None

        logger.debug(f"Parsed kinds for pubkey {pubkey}: {kinds_int}")

        # Only process if special kinds are present
        if not any(kind in [6, 7, 9734, 9735] for kind in kinds_int):
            return None, None
            
        current_kinds = self.parse_current_kinds(result["kinds"])
        
        # Initialize payout increment
        payout_increment = 0.0
        updated_kinds_str = ','.join(map(str, sorted(current_kinds)))
        
        # For kind 6 (repost) events, check if this specific note has been reposted before
        if 6 in kinds_int:
            original_note_id = item_dict.get("original_note_id")
            if original_note_id:
                # Check if we've already tracked this note repost for this user
                tracked_reposts = await self.database.get_user_reposted_notes(pubkey)
                
                # If this note hasn't been tracked for this user, add payout
                if original_note_id not in tracked_reposts:
                    logger.info(f"New repost of note {original_note_id} by {pubkey}")
                    payout_increment += 0.2
                    
                    # Track this note as reposted by this user
                    await self.database.track_reposted_note(pubkey, original_note_id)
                    
                    # Add kind 6 to the user's kinds if not already present
                    if 6 not in current_kinds:
                        current_kinds.add(6)
                        updated_kinds_str = ','.join(map(str, sorted(current_kinds)))
                else:
                    logger.debug(f"Note {original_note_id} already reposted by {pubkey}, not counting again")
        
        # For kind 7 (reaction) events, check if this specific note has been reacted to before
        if 7 in kinds_int:
            original_note_id = item_dict.get("original_note_id")
            if original_note_id:
                # Check if we've already tracked this note reaction for this user
                tracked_reactions = await self.database.get_user_reactions(pubkey)
                
                # If this note hasn't been reacted to by this user, add payout
                if original_note_id not in tracked_reactions:
                    logger.info(f"New reaction to note {original_note_id} by {pubkey}")
                    payout_increment += 0.1  # 0.1 payout for reactions
                    
                    # Track this note as reacted to by this user
                    await self.database.track_user_reaction(pubkey, original_note_id)
                    
                    # Add kind 7 to the user's kinds if not already present
                    if 7 not in current_kinds:
                        current_kinds.add(7)
                        updated_kinds_str = ','.join(map(str, sorted(current_kinds)))
                        logger.info(f"Added kind 7 to member {pubkey}, updated kinds: {updated_kinds_str}")
                else:
                    logger.debug(f"Note {original_note_id} already reacted to by {pubkey}, not counting again")
        
        # For zap events, calculate as usual
        if 9734 in kinds_int or 9735 in kinds_int:
            zap_payout = self.calculate_payout(float(new_amount))
            payout_increment += zap_payout

        # Prepare notification data if not previously notified
        notify_data = None
        if result["notified"] is None:
            member_data = {
                **item_dict,
                'payout_increment': payout_increment,
                'picture': item_dict.get('picture'),
                'relays': item_dict.get('relays', [])[:2]
            }
            notify_data = {
                'pubkey': pubkey,
                'type': 'special_kinds',
                'data': member_data
            }

        # Prepare target data
        target_data = None
        if item_dict['lud16'] and payout_increment > 0:
            target_data = {
                'wallet': item_dict['lud16'],
                'alias': pubkey,  # Always use pubkey as alias
                'pubkey': pubkey,  # Include pubkey explicitly for later reference
                'payouts': payout_increment
            }

        try:
            # Ensure relays are present in item_dict
            if 'relays' not in item_dict or not item_dict['relays']:
                item_dict['relays'] = DEFAULT_RELAYS[:3]

            # Convert relays list to JSON string for storage
            relays_json = json.dumps(item_dict['relays'])
            
            # Only update if there's a payout increment or kinds change
            if payout_increment > 0 or updated_kinds_str != ','.join(map(str, sorted(current_kinds))):
                # Update member in database
                await self.database.update_cyberherd_member(
                    pubkey=pubkey,
                    new_amount=new_amount,
                    payout_increment=payout_increment,
                    updated_kinds=updated_kinds_str,
                    event_id=item_dict.get("event_id"),
                    note=item_dict.get("note"),
                    display_name=item_dict.get("display_name") or "Anon",
                    nprofile=item_dict.get("nprofile"),
                    lud16=item_dict.get("lud16"),
                    picture=item_dict.get("picture"),
                    relays=relays_json
                )
                logger.info(f"Updated member with pubkey: {pubkey}, payout increment: {payout_increment}")
            else:
                logger.debug(f"No update needed for {pubkey} - no payout increment or kinds change")
                
            return notify_data, target_data
        except Exception as e:
            logger.error(f"Failed to update member with pubkey {pubkey}: {e}")
            return None, None

    async def update_notified_field(self, pubkey: str, raw_command_output: str) -> None:
        """Update the notified field for a member after a notification is sent."""
        notified_value = "notified"
        try:
            command_output_json = json.loads(raw_command_output)
            notified_value = command_output_json.get("id", "notified")
        except Exception:
            pass
        await self.database.update_cyberherd_notified(pubkey, notified_value)

    async def process_notifications(
        self,
        members_to_notify: List[Dict],
        difference: int,
        current_herd_size: int
    ) -> None:
        """Process notifications for members."""
        try:
            for member in members_to_notify:
                pubkey = member.get('pubkey', 'unknown')
                member_type = member.get('type', 'unspecified')
                member_data = member.get('data', {})
                
                # Check if this is a kind 6 event
                kinds = member_data.get('kinds', [])
                is_repost = isinstance(kinds, list) and 6 in kinds
                
                # Special handling for repost events
                if is_repost:
                    logger.info(f"Processing repost notification for {pubkey}")
                
                # Ensure member_data has relays
                if not member_data.get('relays'):
                    member_data['relays'] = DEFAULT_RELAYS[:3]
                
                try:
                    spots_remaining = self.max_herd_size - current_herd_size
                    
                    # Log the notification being created
                    logger.debug(f"Creating notification for {member_type} - {pubkey} with difference: {difference}")
                    
                    # Create message
                    message_content, raw_command_output = await self.messaging_service.make_messages(
                        member_data.get('amount', 0),
                        difference,
                        "cyber_herd",
                        member_data,
                        spots_remaining,
                        member_data.get('relays')
                    )
                    
                    # Send message to clients
                    await self.messaging_service.send_message_to_clients(message_content)
                    
                    # Update notified field in database
                    await self.update_notified_field(pubkey, raw_command_output)
                except Exception as e:
                    logger.exception(f"Failed to process notification for {member_type} - {pubkey}: {e}")
        except Exception as e:
            logger.exception(f"process_notifications failed with an error: {e}")

    async def update_cyberherd(self, data_items: List[Any]) -> Dict[str, Any]:
        """Update the CyberHerd with new member data."""
        try:
            if not data_items:
                return {"status": "success", "message": "No items to process", "new_items": 0}

            # Get current number of members
            current_size = await self.database.get_cyberherd_size()
            spots_remaining = max(0, self.max_herd_size - current_size)
            can_add_members = current_size < self.max_herd_size
            
            # Verify raw items are properly formatted
            items_to_process = []
            for item in data_items:
                if hasattr(item, "dict"):
                    item_dict = item.dict()  # Convert Pydantic model to dict
                else:
                    item_dict = dict(item)  # Ensure it's a dict
                
                # Ensure required fields
                if not item_dict.get('pubkey'):
                    self.logger.warning(f"Skipping item without pubkey: {item_dict}")
                    continue
                    
                # Add some defaults if not present
                if 'display_name' not in item_dict or not item_dict['display_name']:
                    item_dict['display_name'] = 'Anon'
                    
                if 'notified' not in item_dict:
                    item_dict['notified'] = None
                
                items_to_process.append(item_dict)

            self.logger.info(f"Processing {len(items_to_process)} items, spots remaining: {spots_remaining}")

            # Process items - track notifications and targets
            notifications = []
            targets = []

            for item_dict in items_to_process:
                pubkey = item_dict['pubkey']
                
                # Check if this user is already a member
                existing_member = await self.database.get_cyberherd_member(pubkey)
                
                if existing_member:
                    self.logger.debug(f"Found existing member: {pubkey}")
                    notify_data, target_data = await self.process_existing_member(
                        item_dict, item, existing_member)
                elif can_add_members:
                    self.logger.debug(f"Adding new member: {pubkey}")
                    notify_data, target_data = await self.process_new_member(item_dict)
                    if notify_data:
                        spots_remaining -= 1
                        can_add_members = spots_remaining > 0
                else:
                    self.logger.info(f"CyberHerd is full, skipping new member {pubkey}")
                    notify_data, target_data = None, None

                # Add notifications and targets if they were created
                if notify_data:
                    notify_data['data']['spots_remaining'] = spots_remaining
                    notifications.append(notify_data)
                if target_data:
                    targets.append(target_data)

            # Update LNBits targets if applicable
            if targets:
                self.logger.info(f"Updating {len(targets)} payment targets")
                await self.update_lnbits_targets_background(targets)

            # IMPORTANT FIX: Recalculate current size and spots remaining AFTER processing all members
            updated_size = await self.database.get_cyberherd_size()
            updated_spots_remaining = max(0, self.max_herd_size - updated_size)

            # Send notifications with the updated spots remaining - FIX: add the missing updated_size parameter
            await self.process_notifications(
                notifications,
                self.trigger_amount - await self._get_current_balance(),
                updated_size
            )

            # Return the accurate spots remaining in the response
            return {
                "status": "success", 
                "message": f"Processed {len(items_to_process)} items", 
                "new_items": len(notifications),
                "spots_remaining": updated_spots_remaining
            }
        except Exception as e:
            self.logger.error(f"Error updating CyberHerd: {e}", exc_info=True)
            return {"status": "error", "message": str(e), "new_items": 0}

    async def _get_current_balance(self):
        """Helper method to get the current wallet balance in sats."""
        try:
            # Try to get balance through payment service
            msats_balance = await self.payment_service.get_balance()
            return msats_balance // 1000
        except Exception as e:
            self.logger.error(f"Error getting current balance: {e}")
            return 0  # Default to 0 if error

    async def process_cyberherd_event(self, event):
        """Process events received from the cyberherd listener service"""
        try:
            event_type = event.get("type")
            if event_type == "new_member":
                # Process new member event
                member_data = event.get("data", {})
                lud16 = member_data.get("lud16")
                if lud16:
                    # Check if member already exists
                    existing = await self.get_member_by_lud16(lud16)
                    if not existing:
                        # Create new CyberHerdData object and add member
                        from models import CyberHerdData  # Import locally to avoid circular imports
                        member = CyberHerdData(**member_data)
                        await self.add_member(member)
                        logger.info(f"Added new cyberherd member: {lud16}")
            elif event_type == "member_update":
                # Process member update event
                member_data = event.get("data", {})
                lud16 = member_data.get("lud16")
                if lud16:
                    # Update existing member
                    from models import CyberHerdData
                    member = CyberHerdData(**member_data)
                    await self.update_member(member)
                    logger.info(f"Updated cyberherd member: {lud16}")
            elif event_type == "member_removal":
                # Process member removal event
                lud16 = event.get("data", {}).get("lud16")
                if lud16:
                    await self.delete_member(lud16)
                    logger.info(f"Removed cyberherd member: {lud16}")
            # Add other event types as needed
        except Exception as e:
            logger.error(f"Error processing cyberherd event: {e}")
    
    async def process_treats_payment(self, data: Dict[str, Any]) -> bool:
        """Process a treats payment for a CyberHerd member."""
        if not isinstance(data, dict):
            logger.error(f"Expected dict but received {type(data)}: {data}")
            return False

        pubkey = data.get("pubkey")
        amount = data.get("amount", 0)
        
        if not (pubkey and amount > 0):
            logger.warning(f"Invalid data: pubkey={pubkey}, amount={amount}")
            return False

        # Skip CyberHerd lookup for internal pubkeys
        if pubkey in ["herd", "LightningGoats"]:
            logger.info(f"Processing internal payment for {pubkey} ({amount} sats)")
            # For internal payments, just return success without sending a message
            # Let the payment_processor_service handle the messaging
            return True

        # Get the member details for actual CyberHerd members
        cyber_herd_list = await self.database.get_cyberherd_list()
        
        # Convert database records to dictionaries
        cyber_herd_dict = {}
        for item in cyber_herd_list:
            if isinstance(item, dict):
                cyber_herd_dict[item['pubkey']] = item
            else:
                # Convert to dictionary if it's a Record object
                item_dict = dict(item)
                cyber_herd_dict[item_dict['pubkey']] = item_dict

        if pubkey not in cyber_herd_dict:
            logger.warning(f"Pubkey not in CyberHerd: {pubkey}")
            return False

        # Create and send message
        member_data = cyber_herd_dict[pubkey]
        logger.debug(f"Sending treats message for member: {member_data}")
        message, _ = await self.messaging_service.make_messages(
            amount,
            0, 
            "cyber_herd_treats", 
            member_data
        )
        await self.messaging_service.send_message_to_clients(message)
        logger.info(f"Sent treats message for {pubkey} with amount {amount}")
        return True

    # New method for background updates
    async def update_lnbits_targets_background(self, new_targets: List[Dict] = None) -> None:
        """Schedule LNbits target update as a background task."""
        try:
            task = asyncio.create_task(self._update_lnbits_targets_task(new_targets))
            # Add a callback to log any exceptions
            task.add_done_callback(
                lambda t: self.logger.error(f"LNbits update task failed: {t.exception()}", exc_info=t.exception())
                if t.exception() else None
            )
        except Exception as e:
            self.logger.error(f"Failed to create background task for updating LNbits targets: {e}", exc_info=True)
    
    async def _update_lnbits_targets_task(self, new_targets: List[Dict] = None) -> bool:
        """Background task that updates LNbits targets."""
        retries = 3
        delay_seconds = 2
        
        for attempt in range(retries):
            try:
                success = await self.update_lnbits_targets(new_targets)
                if success:
                    return True
                self.logger.warning(
                    f"LNbits targets update attempt {attempt+1}/{retries} failed. "
                    f"{'Retrying after delay...' if attempt < retries-1 else 'All attempts failed.'}"
                )
                if attempt < retries-1:
                    await asyncio.sleep(delay_seconds * (attempt + 1))
                       
            except Exception as e:
                self.logger.error(
                    f"Background task for updating LNbits targets failed (attempt {attempt+1}/{retries}): {e}", 
                    exc_info=True
                )
                if attempt < retries-1:
                    await asyncio.sleep(delay_seconds * (attempt + 1))
                       
        return False

    async def distribute_payments_directly(self, total_amount: int) -> Dict[str, Any]:
        """
        Distribute payments directly to members instead of using LNbits splits.
        
        Args:
            total_amount: Total amount in sats to distribute
        
        Returns:
            Dictionary with success status and payment statistics
        """
        try:
            # Get all members with valid Lightning addresses
            members_records = await self.database.get_cyberherd_members_with_lud16()
            
            # Convert database records to dictionaries to avoid attribute access issues
            members = []
            for record in members_records:
                if isinstance(record, dict):
                    members.append(record)
                else:
                    # Convert Row object to dict
                    members.append(dict(record))
            
            # Calculate total payouts for proportional distribution
            # Reserve 90% for Lightning Goats, 10% for members
            goats_amount = int(total_amount * 0.9)  
            members_amount = total_amount - goats_amount
            
            # Track results
            successful_payments = []
            failed_payments = []
            
            # Send full amount to the CyberHerd wallet instead of individual payments
            try:
                if total_amount >= 5:  # Minimum payment threshold
                    # Create invoice for the full amount using the predefined wallet (Lightning Goats)
                    invoice_result = await self.payment_service.create_invoice(
                        amount=total_amount,
                        memo="CyberHerd Distribution",
                        wallet_key=self.payment_service.cyberherd_key
                    )
                    
                    if not invoice_result or "payment_request" not in invoice_result:
                        self.logger.error(f"Failed to create invoice for CyberHerd distribution: {invoice_result}")
                        return {
                            "success": False,
                            "error": "Failed to create invoice",
                            "successful_payments": [],
                            "failed_payments": [],
                            "total_distributed": 0
                        }
                    
                    # Pay the invoice using the CyberHerd key
                    payment_result = await self.payment_service.pay_invoice(
                        payment_request=invoice_result["payment_request"],
                        wallet_key=self.payment_service.herd_key
                    )
                    
                    if payment_result and "payment_hash" in payment_result:
                        successful_payments.append({
                            "recipient": "CyberHerd", 
                            "payment_hash": payment_result["payment_hash"],
                            "amount": total_amount
                        })
                        self.logger.info(f"Paid {total_amount} sats to CyberHerd wallet")
                    else:
                        self.logger.error(f"Failed to pay invoice for CyberHerd distribution: {payment_result}")
                        failed_payments.append({
                            "recipient": "CyberHerd",
                            "amount": total_amount
                        })
                else:
                    self.logger.warning(f"Amount {total_amount} below minimum threshold, skipping payment")
            except Exception as e:
                self.logger.error(f"Failed to pay CyberHerd {total_amount} sats: {e}")
                failed_payments.append({
                    "recipient": "CyberHerd", 
                    "amount": total_amount
                })
            
            # Record total distributed
            total_distributed = sum(p["amount"] for p in successful_payments)
            self.logger.info(f"Distribution complete: {len(successful_payments)} successful payments, {len(failed_payments)} failed payments, {total_distributed} sats distributed")
            
            return {
                "success": len(successful_payments) > 0 and len(failed_payments) == 0,
                "successful_payments": successful_payments,
                "failed_payments": failed_payments,
                "total_distributed": total_distributed
            }
        except Exception as e:
            self.logger.error(f"Error distributing payments: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "successful_payments": [],
                "failed_payments": [],
                "total_distributed": 0
            }

    async def add_member(self, member_data):
        """Add a new member to the CyberHerd.
        
        Args:
            member_data: A CyberHerdData object containing member information
        
        Returns:
            bool: True if the member was added successfully, False otherwise
        """
        try:
            # Convert the model data to a dictionary for the database service
            member_dict = {
                "pubkey": member_data.pubkey,
                "display_name": member_data.display_name or "Anon",
                "event_id": member_data.event_id,
                "note": member_data.note,
                "kinds": member_data.kinds if isinstance(member_data.kinds, str) else ','.join(map(str, member_data.kinds)),
                "nprofile": member_data.nprofile,
                "lud16": member_data.lud16,
                "notified": None,
                "payouts": member_data.payouts if hasattr(member_data, 'payouts') else 0.0,
                "amount": getattr(member_data, 'amount', 0),
                "picture": getattr(member_data, 'picture', None),
                "relays": json.dumps(member_data.relays if hasattr(member_data, 'relays') and member_data.relays else DEFAULT_RELAYS[:3])
            }
            
            # Add to database
            await self.database.insert_cyberherd_member(member_dict)
            
            # If the member has a Lightning address, update LNbits targets
            if member_dict["lud16"]:
                target_data = {
                    'wallet': member_dict["lud16"],
                    'alias': member_dict["pubkey"],
                    'pubkey': member_dict["pubkey"],
                    'payouts': member_dict["payouts"]
                }
                await self.update_lnbits_targets_background([target_data])
                
            self.logger.info(f"Added new member with pubkey: {member_dict['pubkey']}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to add new member: {e}")
            return False

    async def update_member(self, member_data):
        """Update an existing CyberHerd member.
        
        Args:
            member_data: A CyberHerdData object containing updated member information
            
        Returns:
            bool: True if the member was updated successfully, False otherwise
        """
        try:
            pubkey = member_data.pubkey
            
            # Check if member exists
            existing_member = await self.get_member(pubkey)
            if not existing_member:
                self.logger.warning(f"Cannot update non-existent member with pubkey: {pubkey}")
                return False
                
            # Prepare update parameters
            current_kinds = self.parse_current_kinds(existing_member["kinds"])
            new_kinds = self.parse_kinds(member_data.kinds)
            updated_kinds_set = current_kinds.union(set(new_kinds))
            updated_kinds_str = ','.join(map(str, sorted(updated_kinds_set)))
            
            # Calculate payout increment (if any)
            payout_increment = getattr(member_data, 'payouts', 0) - existing_member["payouts"] if hasattr(member_data, 'payouts') else 0
            
            # Update the member in the database
            await self.database.update_cyberherd_member(
                pubkey=pubkey,
                new_amount=getattr(member_data, 'amount', 0),
                payout_increment=payout_increment,
                updated_kinds=updated_kinds_str,
                event_id=member_data.event_id if hasattr(member_data, 'event_id') else existing_member["event_id"],
                note=member_data.note if hasattr(member_data, 'note') else existing_member["note"],
                display_name=member_data.display_name if hasattr(member_data, 'display_name') else existing_member["display_name"],
                nprofile=member_data.nprofile if hasattr(member_data, 'nprofile') else existing_member["nprofile"],
                lud16=member_data.lud16 if hasattr(member_data, 'lud16') else existing_member["lud16"],
                picture=member_data.picture if hasattr(member_data, 'picture') else existing_member.get("picture"),
                relays=json.dumps(member_data.relays) if hasattr(member_data, 'relays') and member_data.relays else existing_member["relays"]
            )
            
            # If the member has a Lightning address and there's a payout increment, update LNbits targets
            if existing_member["lud16"] and payout_increment > 0:
                target_data = {
                    'wallet': existing_member["lud16"],
                    'alias': pubkey,
                    'pubkey': pubkey,
                    'payouts': payout_increment
                }
                await self.update_lnbits_targets_background([target_data])
                
            self.logger.info(f"Updated member with pubkey: {pubkey}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to update member: {e}")
            return False

    async def ensure_complete_cyberherd_data(self, messaging_service=None):
        """Make sure we have complete cyberherd data from all available sources"""
        if messaging_service is None and hasattr(self, 'messaging_service'):
            messaging_service = self.messaging_service
            
        # Get members directly from our service
        members = await self.get_all_members()
        self.logger.info(f"Retrieved {len(members)} members from database")
        
        # Sync missing members if there are too few - internally updates the database
        if len(members) < 3:
            await self._sync_cyberherd_members()
            # Re-get members after sync
            members = await self.get_all_members()
            self.logger.info(f"After sync: retrieved {len(members)} members from database")
            
        # Update the messaging service's cache if provided
        if messaging_service:
            # Convert to the format expected by messaging service
            for member in members:
                if member and member.get("pubkey"):
                    messaging_service._update_cyber_herd_members({
                        "pubkey": member.get("pubkey", ""),
                        "display_name": member.get("display_name", "Anon"),
                        "picture": member.get("picture", ""),
                        "nprofile": member.get("nprofile", ""),
                        "kinds": member.get("kinds", ""),
                        "amount": member.get("amount", 0),
                        "timestamp": member.get("timestamp", int(asyncio.get_event_loop().time() * 1000))
                    })
            
            # If we still have too few members, trigger an emergency reload
            if len(messaging_service.cyber_herd_members) <= 2:
                self.logger.warning("Still have too few members after database load - trying to sync with emergency reload")
                await messaging_service._emergency_reload_members()
                
        return members
    
    async def _sync_cyberherd_members(self):
        """Sync members with external sources to ensure all qualified members are included in database.
        This internal method is used by ensure_complete_cyberherd_data to look for missing members.
        """
        try:
            # Get current members from database
            db_members = await self.get_all_members()
            
            # Extract existing pubkeys for quick lookup
            existing_pubkeys = {member.get("pubkey") for member in db_members if member.get("pubkey")}
            self.logger.info(f"Current cyberherd has {len(existing_pubkeys)} members in database")
            
            # Look for external members through messaging service if available
            if hasattr(self, 'messaging_service') and self.messaging_service:
                messaging_members = self.messaging_service.cyber_herd_members
                self.logger.info(f"Found {len(messaging_members)} members in messaging service cache")
                
                # Keep track of members to add
                to_add = []
                
                # Find members in messaging service that aren't in database
                for member in messaging_members:
                    pubkey = member.get("pubkey")
                    if not pubkey or pubkey in existing_pubkeys:
                        continue
                        
                    # Only add if they have qualifying kinds
                    kinds_str = member.get("kinds", "")
                    if not kinds_str:
                        continue
                        
                    # Parse kinds into list of integers
                    kinds_list = []
                    try:
                        if isinstance(kinds_str, str):
                            kinds_list = [int(k.strip()) for k in kinds_str.split(",") if k.strip().isdigit()]
                        elif isinstance(kinds_str, list):
                            kinds_list = [int(k) for k in kinds_str if isinstance(k, (int, str)) and str(k).isdigit()]
                    except Exception:
                        continue
                        
                    # Check if this member qualifies (has kind 6,9734 or 9735)
                    if not (6 in kinds_list or 9734 in kinds_list or 9735 in kinds_list):
                        self.logger.debug(f"Member {pubkey} doesn't have qualifying kinds: {kinds_list}")
                        continue
                        
                    # Create a complete member record for insertion
                    self.logger.info(f"Found missing qualified member {pubkey} in messaging service")
                    to_add.append({
                        "pubkey": pubkey,
                        "display_name": member.get("display_name", "Anon"),
                        "event_id": member.get("event_id", ""),
                        "note": member.get("note", ""),
                        "kinds": kinds_str if isinstance(kinds_str, str) else ",".join(map(str, kinds_list)),
                        "nprofile": member.get("nprofile", ""),
                        "lud16": member.get("lud16", ""),
                        "notified": member.get("notified", None),
                        "payouts": float(member.get("payouts", 0)),
                        "amount": int(member.get("amount", 0)),
                        "picture": member.get("picture", ""),
                        "relays": json.dumps(member.get("relays", DEFAULT_RELAYS[:3]))
                    })
                
                # Add missing members to database
                if to_add:
                    self.logger.info(f"Adding {len(to_add)} missing members to database")
                    for member in to_add:
                        try:
                            await self.database.insert_cyberherd_member(member)
                            self.logger.info(f"Added missing member {member['pubkey']} to database")
                        except Exception as e:
                            self.logger.error(f"Error adding member {member.get('pubkey')}: {e}")
        except Exception as e:
            self.logger.error(f"Error in _sync_cyberherd_members: {e}", exc_info=True)
    
    async def get_spots_remaining(self) -> int:
        """
        Calculate the number of spots remaining in the CyberHerd.
        This method ensures we get the latest count from the database.
        
        Returns:
            int: Number of spots remaining
        """
        try:
            current_size = await self.database.get_cyberherd_size()
            return max(0, self.max_herd_size - current_size)
        except Exception as e:
            logger.error(f"Error calculating spots remaining: {e}")
            return 0
