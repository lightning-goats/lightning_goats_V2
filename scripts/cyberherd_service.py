import json
import logging
import math
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

        # Zap-based payout
        if 9734 in kinds_int:
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
            initial_targets = await self.payment_service.fetch_cyberherd_targets()
            if initial_targets is None:
                self.logger.error("Failed to fetch current targets from LNbits - got None response")
                return False
                
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
                    
                    # Update or add the target, ADDING the new payouts to existing ones
                    all_targets_dict[wallet] = {
                        'wallet': wallet,
                        'alias': target.get('alias', 'Unknown'),
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
            
            # Update targets in LNbits
            if updated_targets:
                result = await self.payment_service.update_cyberherd_targets(updated_targets)
                if not result:
                    self.logger.error("LNbits update_cyberherd_targets call failed or returned falsy value")
                    return False
                
                self.logger.info(f"LNbits targets updated successfully with {len(updated_targets['targets'])} targets")
                return True
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
                name = item.get('alias', 'Unknown')
                payouts = item.get('payouts', 1.0)
                if wallet != self.predefined_wallet_address:
                    combined_wallets.append({'wallet': wallet, 'alias': name, 'payouts': payouts})

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

        # If relays not provided, use default configuration
        if 'relays' not in item_dict or not item_dict['relays']:
            item_dict['relays'] = DEFAULT_RELAYS[:3]

        # Ensure 'kinds' is a comma-separated string
        if isinstance(item_dict['kinds'], list):
            item_dict['kinds'] = ','.join(map(str, item_dict['kinds']))
        elif isinstance(item_dict['kinds'], str):
            item_dict['kinds'] = item_dict['kinds'].strip()
        else:
            logger.warning(f"Unexpected type for 'kinds': {type(item_dict['kinds'])}")
            item_dict['kinds'] = ''

        # Parse kinds into integers and verify eligible for membership
        kinds_int = self.parse_kinds(item_dict['kinds'])
        
        # Only allow kind 6 (reposts) or kind 9734 (zaps) to create new members
        if not any(k in [6, 9734] for k in kinds_int):
            logger.warning(f"Attempted to add member with ineligible kinds: {kinds_int}. Only kinds 6 and 9734 can create members.")
            return None, None
        
        # Calculate payouts based on kind
        if 9734 in kinds_int:
            item_dict["payouts"] = self.calculate_payout(item_dict.get("amount", 0))
            logger.info(f"Calculated zap payouts for {pubkey}: {item_dict['payouts']} from amount {item_dict.get('amount', 0)}")
        elif 6 in kinds_int:
            item_dict["payouts"] = 0.2  # Fixed payout for repost
            logger.info(f"Set fixed payout for repost from {pubkey}: 0.2")
        else:
            item_dict["payouts"] = 0.0

        # Prepare notification data
        notify_data = {
            'pubkey': pubkey,
            'type': 'new_member',
            'data': item_dict
        }
        
        # Prepare target data if applicable
        target_data = None
        if item_dict['lud16']:
            target_data = {
                'wallet': item_dict['lud16'],
                'alias': item_dict.get('display_name', pubkey),  # Use display_name if available
                'payouts': item_dict["payouts"]
            }
            logger.info(f"Created LNbits target for {pubkey}: wallet={item_dict['lud16']}, payouts={item_dict['payouts']}")
        else:
            logger.warning(f"No lud16 (lightning address) found for {pubkey}, cannot create LNbits target")

        try:
            # Use database service to insert new member
            await self.database.insert_cyberherd_member({
                "pubkey": item_dict["pubkey"],
                "display_name": item_dict.get("display_name") or "Anon",
                "event_id": item_dict.get("event_id"),
                "note": item_dict.get("note"),
                "kinds": item_dict["kinds"],
                "nprofile": item_dict.get("nprofile"),
                "lud16": item_dict.get("lud16"),
                "notified": None,
                "payouts": item_dict["payouts"],
                "amount": item_dict.get("amount", 0),
                "picture": item_dict.get("picture"),
                "relays": json.dumps(item_dict.get("relays"))
            })
            
            logger.info(f"Inserted new member with pubkey: {pubkey}")
            return notify_data, target_data
        except Exception as e:
            logger.error(f"Failed to insert new member with pubkey {pubkey}: {e}")
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
        if not any(kind in [6, 7, 9734] for kind in kinds_int):
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
        if 9734 in kinds_int:
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
                'alias': pubkey,
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
            # Get the current herd size
            current_herd_size = await self.database.get_cyberherd_size()
            
            # Log if the herd is full
            if current_herd_size >= self.max_herd_size:
                logger.info(f"Herd full: {current_herd_size} members – processing new data for notifications")            has_kind_9734 = False  # New flag to track zap events
            
            members_to_notify = [] item
            targets_to_update = []
            has_kind_6 = False  # Flag to track if any Kind 6 events were processed

            # Process each incoming item                logger.debug(f"Processing pubkey: {pubkey} with kinds: {item_dict['kinds']}")
            for item in data_items:
                item_dict = item.dict()4 (zap) event
                pubkey = item_dict['pubkey']arse_kinds(item_dict['kinds'])
                logger.debug(f"Processing pubkey: {pubkey} with kinds: {item_dict['kinds']}")

                # Check if this is a kind 6 (repost) event                    logger.info(f"Processing Kind 6 repost from {pubkey}")
                kinds_int = self.parse_kinds(item_dict['kinds'])
                if 6 in kinds_int:
                    has_kind_6 = True  # Set flag if we see any Kind 6 event                    logger.info(f"Processing Kind 9734 zap from {pubkey} with amount {item_dict.get('amount', 0)}")
                    logger.info(f"Processing Kind 6 repost from {pubkey}")

                # Check if member existserd_member(pubkey)
                member_record = await self.database.get_cyberherd_member(pubkey)

                if member_record is None and current_herd_size < self.max_herd_size: (reposts) or kind 9734 (zaps) to create new members
                    # Only allow kind 6 (reposts) or kind 9734 (zaps) to create new members
                    if any(k in [6, 9734] for k in kinds_int):
                        # Process new memberrget_data = await self.process_new_member(item_dict)
                        notify_data, target_data = await self.process_new_member(item_dict)
                        if notify_data:
                            members_to_notify.append(notify_data)_size += 1
                            current_herd_size += 1
                        if target_data:ets_to_update.append(target_data)
                            targets_to_update.append(target_data)                            logger.info(f"Added target for new member: {target_data['wallet']} with payouts {target_data['payouts']}")
                            logger.info(f"Added target for new member: {target_data['wallet']} with payouts {target_data['payouts']}")_int:
                    elif 7 in kinds_int:g kind 7 reaction from non-member: {pubkey}")
                        logger.info(f"Ignoring kind 7 reaction from non-member: {pubkey}")
                        continue

                elif member_record:ing member
                    # Process existing membercess_existing_member(item_dict, item, member_record)
                    notify_data, target_data = await self.process_existing_member(item_dict, item, member_record)
                    if notify_data:                        members_to_notify.append(notify_data)
                        members_to_notify.append(notify_data)
                    if target_data:o_update.append(target_data)
                        targets_to_update.append(target_data)youts {target_data['payouts']}")
                        logger.info(f"Updated target for existing member: {target_data['wallet']} with payouts {target_data['payouts']}")

            # Update LNbits targets if neededte:
            if targets_to_update:nfo(f"Updating LNbits targets with {len(targets_to_update)} new/updated members")
                logger.info(f"Updating LNbits targets with {len(targets_to_update)} new/updated members")
                ate effect
                # Always process Kind 6 events synchronously for immediate effect
                if has_kind_6:
                    try:
                        logger.info("Kind 6 repost detected - performing direct LNbits update")erforming direct LNbits update")
                        success = await self.update_lnbits_targets(targets_to_update)
                        logger.info(f"Direct LNbits update for Kind 6 event: {'succeeded' if success else 'failed'}")       logger.info("Kind 9734 zap detected - performing direct LNbits update")
                    except Exception as e:
                        logger.error(f"Error in direct LNbits update for Kind 6: {e}", exc_info=True)
                        # Still try background update as a fallbackelse 'failed'}")
                        await self.update_lnbits_targets_background(targets_to_update)
                else:
                    # Use direct update for reactions (already covered by existing code)
                    if any(t.get('payouts', 0.0) == 0.2 for t in targets_to_update) or \ted target: {target.get('wallet')} with payouts {target.get('payouts')}")
                       any(t.get('payouts', 0.0) == 0.1 for t in targets_to_update):
                        try:
                            success = await self.update_lnbits_targets(targets_to_update)
                            logger.info(f"Direct LNbits update for members: {'succeeded' if success else 'failed'}") Still try background update as a fallback
                        except Exception as e:(targets_to_update)
                            logger.error(f"Error in direct LNbits update: {e}", exc_info=True)
                            # Still try background update as a fallback                    # Use direct update for reactions (already covered by existing code)
                            await self.update_lnbits_targets_background(targets_to_update).0) == 0.2 for t in targets_to_update) or \
                    else:'payouts', 0.0) == 0.1 for t in targets_to_update):
                        # Use background update for regular updates
                        await self.update_lnbits_targets_background(targets_to_update)ets(targets_to_update)
: {'succeeded' if success else 'failed'}")
            # Process notifications if needed
            if members_to_notify:            logger.error(f"Error in direct LNbits update: {e}", exc_info=True)
                # Calculate the difference value properlyd update as a fallback
                current_balance = await self._get_current_balance().update_lnbits_targets_background(targets_to_update)
                difference = max(0, self.trigger_amount - current_balance)
                logger.info(f"Processing notifications with difference: {difference} sats (balance: {current_balance}, trigger: {self.trigger_amount})")und update for regular updates
                       await self.update_lnbits_targets_background(targets_to_update)
                await self.process_notifications(
                    members_to_notify,s notifications if needed
                    difference,  # Properly calculated difference value
                    current_herd_size
                )   current_balance = await self._get_current_balance()
                difference = max(0, self.trigger_amount - current_balance)
            return {Processing notifications with difference: {difference} sats (balance: {current_balance}, trigger: {self.trigger_amount})")
                "status": "success",
                "new_members_added": len([m for m in members_to_notify if m['type'] == 'new_member'])t self.process_notifications(
            }ify,
# Properly calculated difference value
        except Exception as e:       current_herd_size
            logger.error(f"Failed to update cyber herd: {e}")            )
            return {
                "status": "error",
                "message": str(e)    "status": "success",
            }bers_to_notify if m['type'] == 'new_member'])
    
    async def _get_current_balance(self):
        """Helper method to get the current wallet balance in sats."""
        try:
            # Try to get balance through payment service
            msats_balance = await self.payment_service.get_balance()            "status": "error",
            return msats_balance // 1000
        except Exception as e:
            self.logger.error(f"Error getting current balance: {e}")
            return 0  # Default to 0 if error
    t wallet balance in sats."""
    async def process_cyberherd_event(self, event):
        """Process events received from the cyberherd listener service"""rvice
        try:ervice.get_balance()
            event_type = event.get("type")balance // 1000
            if event_type == "new_member":
                # Process new member event
                member_data = event.get("data", {}) if error
                lud16 = member_data.get("lud16")
                if lud16:
                    # Check if member already existsr service"""
                    existing = await self.get_member_by_lud16(lud16)
                    if not existing:
                        # Create new CyberHerdData object and add member
                        from models import CyberHerdData  # Import locally to avoid circular imports
                        member = CyberHerdData(**member_data)
                        await self.add_member(member)
                        logger.info(f"Added new cyberherd member: {lud16}")
            elif event_type == "member_update":y exists
                # Process member update event_by_lud16(lud16)
                member_data = event.get("data", {})
                lud16 = member_data.get("lud16")bject and add member
                if lud16:cally to avoid circular imports
                    # Update existing member*member_data)
                    from models import CyberHerdDatamember)
                    member = CyberHerdData(**member_data)member: {lud16}")
                    await self.update_member(member)pe == "member_update":
                    logger.info(f"Updated cyberherd member: {lud16}")
            elif event_type == "member_removal":
                # Process member removal event6")
                lud16 = event.get("data", {}).get("lud16")
                if lud16:
                    await self.delete_member(lud16)                from models import CyberHerdData
                    logger.info(f"Removed cyberherd member: {lud16}")
            # Add other event types as needed
        except Exception as e:ted cyberherd member: {lud16}")
            logger.error(f"Error processing cyberherd event: {e}")
    s member removal event
    async def process_treats_payment(self, data: Dict[str, Any]) -> bool:                lud16 = event.get("data", {}).get("lud16")
        """Process a treats payment for a CyberHerd member."""
        if not isinstance(data, dict):member(lud16)
            logger.error(f"Expected dict but received {type(data)}: {data}")                    logger.info(f"Removed cyberherd member: {lud16}")
            return Falseneeded

        pubkey = data.get("pubkey")(f"Error processing cyberherd event: {e}")
        amount = data.get("amount", 0)    
ment(self, data: Dict[str, Any]) -> bool:
        if not (pubkey and amount > 0):
            logger.warning(f"Invalid data: pubkey={pubkey}, amount={amount}")if not isinstance(data, dict):
            return Falseved {type(data)}: {data}")

        # Get the member details
        cyber_herd_list = await self.database.get_cyberherd_list()
        
        # Convert database records to dictionaries
        cyber_herd_dict = {}
        for item in cyber_herd_list:ata: pubkey={pubkey}, amount={amount}")
            if isinstance(item, dict):
                cyber_herd_dict[item['pubkey']] = item
            else:
                # Convert to dictionary if it's a Record object()
                item_dict = dict(item)
                cyber_herd_dict[item_dict['pubkey']] = item_dict        # Convert database records to dictionaries

        if pubkey not in cyber_herd_dict:
            logger.warning(f"Pubkey not in CyberHerd: {pubkey}")
            return False

        # Create and send message # Convert to dictionary if it's a Record object
        member_data = cyber_herd_dict[pubkey]item)
        logger.debug(f"Sending treats message for member: {member_data}")erd_dict[item_dict['pubkey']] = item_dict
        message, _ = await self.messaging_service.make_messages(
            amount, 
            0, 
            "cyber_herd_treats", False
            member_data
        )
        await self.messaging_service.send_message_to_clients(message)        member_data = cyber_herd_dict[pubkey]
        logger.info(f"Sent treats message for {pubkey} with amount {amount}")
        return True
amount, 
    # New method for background updates

    async def update_lnbits_targets_background(self, new_targets: List[Dict] = None) -> None:
        """Schedule LNbits target update as a background task."""
        try:message_to_clients(message)
            task = asyncio.create_task(self._update_lnbits_targets_task(new_targets))r.info(f"Sent treats message for {pubkey} with amount {amount}")
            # Add a callback to log any exceptions
            task.add_done_callback(
                lambda t: self.logger.error(f"LNbits update task failed: {t.exception()}", exc_info=t.exception())# New method for background updates
                if t.exception() else None
            )argets: List[Dict] = None) -> None:
        except Exception as e: LNbits target update as a background task."""
            self.logger.error(f"Failed to create background task for updating LNbits targets: {e}", exc_info=True)
        task = asyncio.create_task(self._update_lnbits_targets_task(new_targets))
    async def _update_lnbits_targets_task(self, new_targets: List[Dict] = None) -> bool:y exceptions
        """Background task that updates LNbits targets.""".add_done_callback(
        retries = 3: {t.exception()}", exc_info=t.exception())
        delay_seconds = 2ion() else None
        
        for attempt in range(retries):tion as e:
            try:ed to create background task for updating LNbits targets: {e}", exc_info=True)
                success = await self.update_lnbits_targets(new_targets)
                if success:
                    return Trueound task that updates LNbits targets."""
                    = 3
                self.logger.warning(
                    f"LNbits targets update attempt {attempt+1}/{retries} failed. "
                    f"{'Retrying after delay...' if attempt < retries-1 else 'All attempts failed.'}"in range(retries):
                )
                lf.update_lnbits_targets(new_targets)
                if attempt < retries-1:
                    await asyncio.sleep(delay_seconds * (attempt + 1))
                       
            except Exception as e:self.logger.warning(
                self.logger.error(date attempt {attempt+1}/{retries} failed. "
                    f"Background task for updating LNbits targets failed (attempt {attempt+1}/{retries}): {e}", 1 else 'All attempts failed.'}"
                    exc_info=True        )
                )
                                if attempt < retries-1:





        return False                            await asyncio.sleep(delay_seconds * (attempt + 1))                if attempt < retries-1:                    await asyncio.sleep(delay_seconds * (attempt + 1))
                    
            except Exception as e:
                self.logger.error(
                    f"Background task for updating LNbits targets failed (attempt {attempt+1}/{retries}): {e}", 
                    exc_info=True
                )
                
                if attempt < retries-1:
                    await asyncio.sleep(delay_seconds * (attempt + 1))
        
        return False
