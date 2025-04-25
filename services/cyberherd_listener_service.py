import asyncio
import logging
import json
import subprocess
import random
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Callable, Set, List, Tuple

import httpx

from utils.cyberherd_module import (
    MetadataFetcher,
    Verifier,
    generate_nprofile,
    lookup_relay_list,
    DEFAULT_RELAYS,
    FALLBACK_RELAYS,
)

# Import the verify_event function from enhanced nostr_utils
from utils.nostr_utils import verify_event

logger = logging.getLogger(__name__)

class CyberherdListenerService:
    """Service to listen for and process cyberherd events using Nostr"""
    
    def __init__(self, 
                 nos_sec: str,
                 hex_key: str,
                 callback_handler: Optional[Callable[[Dict[str, Any]], None]] = None,
                 webhook_url: str = None,  # No longer needed, but kept for backward compatibility
                 nip05_verification: bool = True,  # Changed default to True to enable verification
                 tags: List[str] = None,
                 message_template_service=None,  # Add message template service
                 database_service=None,  # Add database_service parameter
                 nip05_required: bool = False):  # Add configurable NIP-05 requirement
        """
        Initialize the CyberHerd listener service.
        
        Args:
            nos_sec: The Nostr private key in hex format
            hex_key: The Nostr public key in hex format
            callback_handler: Function to call when processing events
            webhook_url: Deprecated parameter, kept for backward compatibility
            nip05_verification: Whether to verify NIP-05 identifiers (default: True)
            tags: List of tags to monitor, defaults to ["#CyberHerd", "CyberHerd"]
            message_template_service: Service for message templates
            database_service: Service for database operations
            nip05_required: Whether NIP-05 is strictly required
        """
        self.nos_sec = nos_sec
        self.hex_key = hex_key
        self.callback_handler = callback_handler
        self.nip05_verification = nip05_verification
        self.nip05_required = nip05_required  # Whether NIP-05 is strictly required
        self.tags = tags or ["#CyberHerd", "CyberHerd"]
        self.message_template_service = message_template_service
        self.database_service = database_service
        
        # Service state
        self.running = False
        self.start_time = None
        self._task = None
        self._stop_event = asyncio.Event()
        
        # Processing state
        self.seen_ids = set()
        self.json_objects = []
        self.active_subprocesses: Set[asyncio.subprocess.Process] = set()
        self.metadata_fetcher = MetadataFetcher()
        
        # Concurrency control
        self.subprocess_semaphore = asyncio.Semaphore(10)
        self.http_semaphore = asyncio.Semaphore(20)
        self._http_client = None
        
        # Member cache for quicker lookups
        self.member_cache = {}
        self.cache_refresh_time = datetime.min
        self.cache_ttl = 600  # 10 minutes
        
        # Active DM requests tracking (to prevent duplicate DMs if multiple events come in quickly)
        self.active_dm_requests = set()
        self.dm_request_lock = asyncio.Lock()
        
        # Add tracking for invalid events
        self.invalid_events_count = 0
        self.last_invalid_event = None
        
    async def initialize(self, http_client: Optional[httpx.AsyncClient] = None):
        """Initialize the cyberherd listener service"""
        logger.info("Initializing Cyberherd Listener service")
        self._http_client = http_client or httpx.AsyncClient(
            http2=True,
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=20)
        )
        
        # Create an index for faster lookups if database_service is available
        if self.database_service:
            await self.database_service.database.execute(
                "CREATE INDEX IF NOT EXISTS idx_cyber_herd_pubkey ON cyber_herd(pubkey)"
            )
        
        return True
        
    async def start(self):
        """Start the cyberherd listener service"""
        if self.running:
            logger.warning("Cyberherd Listener service already running")
            return False
            
        self.start_time = datetime.now()
        self._stop_event.clear()
        self._task = asyncio.create_task(self.monitor_new_notes())
        return True
        
    async def stop(self):
        """Stop the cyberherd listener service"""
        if not self.running:
            logger.warning("Cyberherd Listener service not running")
            return False
            
        logger.info("Stopping Cyberherd Listener service")
        self._stop_event.set()
        
        # Terminate all active subprocesses with timeout handling
        if self.active_subprocesses:
            logger.info(f"Terminating {len(self.active_subprocesses)} active subprocesses")
            
            # First attempt graceful termination
            termination_tasks = []
            for proc in list(self.active_subprocesses):
                try:
                    # Send SIGTERM first for graceful shutdown
                    proc.terminate()
                    # Create a task to wait for the process
                    termination_tasks.append(asyncio.create_task(proc.wait()))
                except Exception as e:
                    logger.error(f"Error terminating subprocess {proc.pid}: {e}")
            
            # Wait up to 3 seconds for all processes to terminate
            if termination_tasks:
                try:
                    done, pending = await asyncio.wait(termination_tasks, timeout=3.0)
                    
                    # For any process that didn't terminate, force kill
                    if pending:
                        logger.warning(f"{len(pending)} subprocesses didn't terminate gracefully, forcing kill")
                        for task, proc in zip(termination_tasks, list(self.active_subprocesses)):
                            if task in pending:
                                try:
                                    proc.kill()  # More forceful than terminate
                                    await proc.wait()
                                except Exception as e:
                                    logger.error(f"Error killing subprocess: {e}")
                except Exception as e:
                    logger.error(f"Error waiting for subprocesses to terminate: {e}")
        
        # Clear the subprocess set
        self.active_subprocesses.clear()
        
        # Cancel the monitoring task if it exists and is still running
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.error(f"Error cancelling monitoring task: {e}")
        
        self.running = False
        logger.info("Cyberherd Listener service stopped")
        return True
        
    async def reset(self):
        """Reset the cyberherd listener service"""
        logger.info("Resetting CyberHerd Listener service")
        await self.stop()
        # Clear the seen IDs to start fresh
        self.seen_ids.clear()
        self.json_objects.clear()
        return await self.start()
    
    async def send_json_payload(self, json_objects: list) -> bool:
        """Process JSON payload using direct callbacks"""
        if not json_objects:
            logger.warning("No JSON objects to send.")
            return False
            
        # Use callback handler for processing
        if self.callback_handler:
            try:
                # Process each object individually to match the expected signature
                for json_obj in json_objects:
                    await self.callback_handler(json_obj)
                logger.info(f"Processed {len(json_objects)} objects directly via callback")
                self.json_objects.clear()
                return True
            except Exception as e:
                logger.error(f"Error processing JSON directly: {e}")
                return False
        else:
            # Log a warning if no callback handler is configured
            logger.warning("No callback handler configured. Unable to process JSON objects.")
            return False

    async def send_dm(self, recipient_pubkey: str, plaintext: str) -> None:
        """Send a direct message (DM) to the user via nak using NIP-04 encryption."""
        try:
            # Get user's relay list
            user_relays = await lookup_relay_list(recipient_pubkey)
            # Use first 3 relays or fallback to defaults
            relay_list = user_relays[:3] if user_relays else DEFAULT_RELAYS[:3]
            relay_str = " ".join(relay_list)
            
            # Step 1: Encrypt the message using nak encrypt
            encrypt_cmd = (
                f'/usr/local/bin/nak encrypt --sec {self.nos_sec} --nip04 '
                f'--recipient-pubkey {recipient_pubkey} "{plaintext}"'
            )
            logger.info(f"Encrypting DM using command: {encrypt_cmd}")
            
            encrypt_proc = await asyncio.create_subprocess_shell(
                encrypt_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            encrypted_stdout, encrypt_stderr = await encrypt_proc.communicate()
            if encrypt_stderr and b"error" in encrypt_stderr.lower():
                logger.error(f"Encryption error: {encrypt_stderr.decode().strip()}")
                return
            encrypted_message = encrypted_stdout.decode().strip()

            # Step 2: Publish the DM event (kind 4) using the encrypted message.
            event_cmd = (
                f'/usr/local/bin/nak event --sec {self.nos_sec} -k 4 -c "{encrypted_message}" '
                f'--tag p="{recipient_pubkey}" {relay_str}'
            )
            
            event_proc = await asyncio.create_subprocess_shell(
                event_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            event_stdout, event_stderr = await event_proc.communicate()

            # Check for actual errors in stderr output
            if event_stderr:
                stderr_text = event_stderr.decode().strip()
                # Only log as error if it contains "error" or "fail" and doesn't contain "success"
                if (("error" in stderr_text.lower() or "fail" in stderr_text.lower()) 
                    and "success" not in stderr_text.lower()):
                    logger.error(f"DM event error: {stderr_text}")
                else:
                    # This is likely just informational output about successful publishing
                    logger.info(f"DM event info: {stderr_text}")

        except Exception as e:
            logger.error(f"Error sending DM: {e}")

    async def handle_event(self, data: Dict[str, Any]) -> None:
        """Process an individual event coming from Nostr"""
        try:
            event_id = data.get("cyberherd_id")
            note = data.get("id")
            pubkey = data.get("pubkey")
            kind = data.get("kind")
            amount = data.get("amount", 0)

            if note in self.seen_ids:
                logger.debug(f"Skipping already processed event: {note}")
                return

            self.seen_ids.add(note)

            if not pubkey or kind is None:
                logger.error(f"Event data missing 'pubkey' or 'kind': {data}")
                return

            logger.info(f"Handling event: event_id={note}, pubkey={pubkey}, kind={kind}, amount={amount}")

            # Only process kind 6 and kind 7; ignore other kinds
            if kind not in (6, 7):
                logger.debug(f"Kind {kind} is not 6 or 7; ignoring event {note}.")
                return

            # Skip if pubkey is our own public key
            if pubkey == self.hex_key:
                logger.debug(f"Pubkey matches HEX_KEY ({self.hex_key}), skipping event.")
                return

            # Verify the event signature to ensure it wasn't tampered with
            if not verify_event(data):
                self.invalid_events_count += 1
                self.last_invalid_event = {
                    "id": data.get('id'),
                    "pubkey": data.get('pubkey'),
                    "kind": data.get('kind'),
                    "timestamp": int(time.time())
                }
                logger.warning(f"Skipping event with invalid signature: {data.get('id')} from {data.get('pubkey')}")
                return

            # Check if this is an existing member - try cache first then database
            existing_member = self._get_cached_member(pubkey)
            if not existing_member and self.database_service:
                existing_member = await self.database_service.get_cyberherd_member(pubkey)
                if existing_member:
                    self._update_member_cache(pubkey, existing_member)
            
            # For kind 7 (reactions) from non-members, just track for analytics without further processing
            if kind == 7 and not existing_member:
                logger.info(f"Kind 7 reaction from non-member {pubkey}. Tracking event only.")
                
                # Extract the original note reference from e tags for tracking purposes
                original_note_id = self._extract_original_note_id(data)
                
                # Track the reaction for analytics but don't create a member
                if original_note_id and self.database_service:
                    try:
                        await self.database_service.track_user_reaction(pubkey, original_note_id)
                        logger.debug(f"Tracked reaction to note {original_note_id} by non-member {pubkey}")
                    except Exception as e:
                        logger.error(f"Failed to track reaction for non-member: {e}")
                
                return  # Skip further processing for kind 7 from non-members
                
            # Initialize metadata variable to avoid "referenced before assignment" errors
            metadata = {}
            
            # For existing members, use the cached or database data
            if existing_member:
                logger.info(f"Found existing member in database: {pubkey}")
                
                # Convert the database record to a dictionary if it's not already
                existing_member_dict = self._normalize_member_data(existing_member)
                
                # Use stored member data (already verified previously)
                lud16 = existing_member_dict.get("lud16")
                display_name = existing_member_dict.get("display_name", "Anon")
                picture = existing_member_dict.get("picture")
                
                # Parse stored relays from JSON string
                relays_json = existing_member_dict.get("relays")
                user_relays = json.loads(relays_json) if relays_json else DEFAULT_RELAYS[:3]
                
                # Create metadata dict from existing member data 
                metadata = {
                    "lud16": lud16,
                    "nip05": None,  # Not stored in DB
                    "display_name": display_name,
                    "picture": picture
                }
            else:
                # For new members, do the full lookup process
                user_relays = await lookup_relay_list(pubkey)
                if not user_relays:
                    # If lookup_relay_list fails, use a mix of default relays
                    user_relays = DEFAULT_RELAYS[:5]
                    
                logger.info(f"Found relays for {pubkey}: {user_relays}")

                # Fetch metadata using user's relays with improved error handling
                metadata = await self._fetch_user_metadata_with_retries(pubkey, user_relays)
                if not metadata:
                    logger.warning(f"No metadata found for pubkey {pubkey}. Skipping event.")
                    return

                lud16 = metadata.get("lud16")
                nip05 = metadata.get("nip05")
                display_name = metadata.get("display_name", "Anon")
                picture = metadata.get("picture")

                # Perform NIP-05 verification if configured
                if self.nip05_verification:
                    nip05_status = await self._verify_nip05_identifier(pubkey, nip05, display_name)
                    
                    # If NIP-05 is required and verification failed, abort processing
                    if self.nip05_required and nip05_status != "verified":
                        logger.warning(f"NIP-05 verification failed for required identifier. Status: {nip05_status}")
                        return
                else:
                    logger.debug("Skipping NIP-05 verification due to configuration.")

            # Skip if no Lightning address, but don't send a DM about it
            if not lud16:
                logger.warning(f"Missing Lightning address for pubkey {pubkey}. Skipping event.")
                return

            try:
                nprofile = await generate_nprofile(pubkey)
                if not nprofile:
                    logger.error(f"Failed to generate nprofile for pubkey: {pubkey}")
                    return

                logger.debug(f"Metadata lookup success: {metadata}")

                # Extract the original note reference from e tags
                original_note_id = self._extract_original_note_id(data)
                
                # Set default values based on kind
                if kind == 6:
                    amount = 0
                    payouts = 0.2
                elif kind == 7:
                    amount = 0
                    payouts = 0.1  # Show potential payout, actual will be determined by backend

                # Include the picture data and relays in the JSON object
                json_object = {
                    "display_name": display_name,
                    "event_id": event_id,
                    "note": note,
                    "kinds": [kind],
                    "pubkey": pubkey,
                    "nprofile": nprofile,
                    "lud16": lud16,
                    "notified": "False",
                    "payouts": payouts,
                    "amount": amount,
                    "picture": picture,
                    "relays": user_relays[:3],
                    "original_note_id": original_note_id
                }

                logger.debug(f"Appending JSON object: {json_object}")
                self.json_objects.append(json_object)
                
                # Process the data with direct call
                await self.send_json_payload([json_object])
                
            except asyncio.TimeoutError as e:
                logger.error(f"Nprofile encoding timed out: {e}")
            except Exception as e:
                logger.error(f"Unexpected error during nprofile encoding: {e}")

        except Exception as e:
            logger.error(f"Unexpected error in handle_event: {e}")

    def _extract_original_note_id(self, data: Dict[str, Any]) -> Optional[str]:
        """Extract the original note ID from event tags"""
        for tag in data.get("tags", []):
            if isinstance(tag, list) and len(tag) > 1 and tag[0] == "e":
                original_note_id = tag[1]
                return original_note_id
        return None

    def _normalize_member_data(self, member_data: Any) -> Dict[str, Any]:
        """Normalize member data to dictionary format regardless of input type"""
        if hasattr(member_data, "_mapping"):
            return dict(member_data._mapping)
        elif not isinstance(member_data, dict):
            return dict(member_data)
        else:
            return member_data

    def _get_cached_member(self, pubkey: str) -> Optional[Dict[str, Any]]:
        """Get member data from cache if available and not expired"""
        if pubkey in self.member_cache and (datetime.now() - self.cache_refresh_time).total_seconds() < self.cache_ttl:
            return self.member_cache.get(pubkey)
        return None
        
    def _update_member_cache(self, pubkey: str, member_data: Dict[str, Any]) -> None:
        """Update the member cache with new member data"""
        if not hasattr(self, 'member_cache'):
            self.member_cache = {}
        self.member_cache[pubkey] = self._normalize_member_data(member_data)

    async def _fetch_user_metadata_with_retries(self, pubkey: str, user_relays: List[str]) -> Optional[Dict[str, Any]]:
        """Fetch user metadata with multiple retries and expanded relay sets"""
        # Try with user's relays first
        try:
            metadata = await self.metadata_fetcher.lookup_metadata(pubkey, user_relays)
            if metadata:
                return metadata
        except Exception as e:
            logger.warning(f"Error during metadata lookup for {pubkey} with user relays: {e}")
        
        # First retry with default relays
        try:
            metadata = await self.metadata_fetcher.lookup_metadata(pubkey, DEFAULT_RELAYS)
            if metadata:
                logger.info(f"Found metadata on retry with DEFAULT_RELAYS for {pubkey}")
                return metadata
        except Exception as e:
            logger.warning(f"Error during metadata retry with DEFAULT_RELAYS for {pubkey}: {e}")
        
        # Second retry with expanded relay set (combine all relay types but remove duplicates)
        try:
            # Use set to remove duplicates, then convert back to list
            combined_relays = list(set(user_relays + DEFAULT_RELAYS + FALLBACK_RELAYS[:3]))
            logger.info(f"Final retry for metadata lookup for {pubkey} with {len(combined_relays)} relays")
            metadata = await self.metadata_fetcher.lookup_metadata(pubkey, combined_relays)
            if metadata:
                return metadata
        except Exception as e:
            logger.warning(f"All metadata lookup retries failed for {pubkey}: {e}")
        
        return None

    async def _verify_nip05_identifier(self, pubkey: str, nip05: Optional[str], display_name: str) -> str:
        """
        Verify NIP-05 identifier with robust error handling and DM notifications.
        
        Returns: 
            str: Status - "verified", "missing", "invalid", or "error"
        """
        # If NIP-05 verification is disabled, always return "verified"
        if not self.nip05_verification:
            logger.debug(f"NIP-05 verification disabled. Skipping for pubkey: {pubkey}")
            return "verified"
            
        if not nip05:
            # Handle missing NIP-05 - now sending DM notifications
            logger.info(f"Missing NIP-05 for {pubkey} - sending notification")
            await self._send_dm_with_rate_limit(pubkey, "missing_nip05", display_name=display_name)
            return "missing"
            
        # Basic format validation before verification
        if '@' not in nip05 or not nip05.strip():
            logger.warning(f"Invalid NIP-05 format for {pubkey}: {nip05}")
            # Enable DM sending for invalid format
            await self._send_dm_with_rate_limit(pubkey, "invalid_nip05", display_name=display_name, nip05=nip05, reason="Invalid format")
            return "invalid"
            
        # Clean the NIP-05 identifier
        nip05 = nip05.lower().strip()
        logger.debug(f"Processing NIP-05: '{nip05}' for pubkey {pubkey}")
        
        # Verify with retries
        max_retries = 2
        last_error = None
        
        for attempt in range(max_retries):
            try:
                is_valid_nip05 = await Verifier.verify_nip05(nip05, pubkey)
                if is_valid_nip05:
                    logger.info(f"Valid NIP-05 identifier for pubkey {pubkey}: {nip05}")
                    return "verified"
                
                # If verification failed, send DM on the last attempt
                if attempt == max_retries - 1:
                    logger.warning(f"Invalid NIP-05 for {pubkey}: {nip05} - sending notification")
                    await self._send_dm_with_rate_limit(pubkey, "invalid_nip05", 
                                                        display_name=display_name, 
                                                        nip05=nip05, 
                                                        reason="Verification failed")
            except Exception as e:
                last_error = e
                logger.warning(f"Error verifying NIP-05 (attempt {attempt+1}): {e}")
                # Sleep before retry (except on the final attempt)
                if attempt < max_retries - 1:
                    await asyncio.sleep(1.0)
        
        # If we get here, all verification attempts failed
        if last_error:
            logger.error(f"NIP-05 verification error after {max_retries} attempts: {last_error}")
            # Enable DM sending for verification errors
            await self._send_dm_with_rate_limit(pubkey, "invalid_nip05", 
                                                display_name=display_name, 
                                                nip05=nip05, 
                                                reason=f"Verification error: {str(last_error)}")
            return "error"
        else:
            logger.warning(f"NIP-05 verification failed for {pubkey}: {nip05}")
            # Enable DM sending for general verification failure
            await self._send_dm_with_rate_limit(pubkey, "invalid_nip05", 
                                                display_name=display_name, 
                                                nip05=nip05, 
                                                reason="Unknown verification failure")
            return "invalid"

    async def _send_dm_with_rate_limit(self, pubkey: str, dm_type: str, **template_vars) -> None:
        """
        Send a DM with rate limiting and duplicate prevention
        This consolidates all DM sending with proper rate limiting
        """
        # Create a unique key for this DM request
        request_key = f"{pubkey}:{dm_type}"
        
        # Check if we're already sending this exact DM (prevents duplicates during concurrent processing)
        async with self.dm_request_lock:
            if request_key in self.active_dm_requests:
                logger.debug(f"Already sending DM {dm_type} to {pubkey}, skipping duplicate")
                return
            
            # Check if we've already sent a DM today via database
            if self.database_service and await self.database_service.has_dm_been_sent(pubkey, dm_type, hours=24):
                logger.info(f"Already sent {dm_type} DM to {pubkey} in the last 24 hours, skipping")
                return
            
            # Mark as active before we start processing
            self.active_dm_requests.add(request_key)
        
        try:
            # Get appropriate message template based on dm_type
            dm_message = self._get_default_message(dm_type, **template_vars)
            
            # Use message template service if available
            if self.message_template_service:
                templates = await self.message_template_service.get_template(f"dm_{dm_type}")
                if templates:
                    # Get a random template and format it
                    if isinstance(templates, dict):
                        dm_message = random.choice(list(templates.values())).format(**template_vars)
                    elif isinstance(templates, list):
                        dm_message = random.choice(templates).format(**template_vars)
            
            logger.info(f"Sending {dm_type} DM to pubkey {pubkey}")
            
            # Add a small random delay to prevent all DMs being sent at exactly the same time
            await asyncio.sleep(random.uniform(0.1, 1.0))
            
            # Send the DM
            await self.send_dm(pubkey, dm_message)
            
            # Record that we sent a DM
            if self.database_service:
                await self.database_service.record_dm_sent(pubkey, dm_type)
                
        except Exception as e:
            logger.error(f"Error sending {dm_type} DM to {pubkey}: {e}")
        finally:
            # Always remove from active requests when done
            async with self.dm_request_lock:
                self.active_dm_requests.discard(request_key)
    
    def _get_default_message(self, dm_type: str, **template_vars) -> str:
        """Get the default message template for a given DM type"""
        display_name = template_vars.get("display_name", "")
        
        if dm_type == "missing_nip05":
            return (
                f"It looks like you don't have a NIP-05 identifier. "
                f"If you'd like a {display_name}@lightning-goats.com NIP‑05 address, sign up at "
                "https://lnb.bolverker.com/nostrnip5/signup/eGrBG7HWLJTiYyhxgEpMwz"
            )
        elif dm_type == "invalid_nip05":
            nip05 = template_vars.get("nip05", "")
            reason = template_vars.get("reason", "unknown reason")
            return (
                f"Your NIP-05 identifier ({nip05}) has failed validation due to: {reason}. "
                f"This could be a temporary glitch. You can retry joining the cyberherd. "
                f"If validation keeps failing, contact your NIP05 provider. "
                f"If you'd like a {display_name}@lightning-goats.com NIP‑05 address, please sign up at "
                "https://lnb.bolverker.com/nostrnip5/signup/eGrBG7HWLJTiYyhxgEpMwz"
            )
        else:
            return "Hello from the Lightning Goats CyberHerd! Join us on Nostr at #cyberherd"

    async def execute_subprocess(self, id_output: str, created_at_output: str) -> None:
        """
        Execute a subprocess to process events asynchronously.
        Handles kind 6 and kind 7 events.
        """
        relay_str = " ".join(DEFAULT_RELAYS)
        command = (
            f"/usr/local/bin/nak req --stream -k 6 -k 7 -e {id_output} "
            f"--since {created_at_output} {relay_str}"
        )
        logger.debug(f"Executing subprocess command: {command}")
        async with self.subprocess_semaphore:
            try:
                proc = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                self.active_subprocesses.add(proc)
                logger.info(f"Subprocess started with PID: {proc.pid}")

                async for line in proc.stdout:
                    if self._stop_event.is_set():
                        logger.info(f"Shutdown signal received. Terminating subprocess {proc.pid}")
                        proc.terminate()
                        break
                    try:
                        data = json.loads(line)
                        data["cyberherd_id"] = id_output
                        pubkey = data.get("pubkey")
                        note = data.get("id")

                        if data.get("kind") in (6, 7):
                            logger.debug(f"Processing event of kind {data.get('kind')}, ID: {note}")
                            await self.handle_event(data)

                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse JSON line: {line.strip()}, error: {e}")
                    except Exception as e:
                        logger.error(f"Unexpected error while processing line: {line.strip()}, error: {e}")

                await proc.wait()
                logger.info(f"Subprocess {proc.pid} terminated.")
            except Exception as e:
                logger.error(f"Error executing subprocess: {e}")
            finally:
                self.active_subprocesses.discard(proc)

    async def monitor_new_notes(self) -> None:
        """
        Monitor events and process them asynchronously.
        Focuses on new notes that have #CyberHerd or CyberHerd tags,
        then spawns subprocesses to fetch kind 6 and kind 7 events.
        """
        midnight_today = int(datetime.combine(datetime.now().date(), datetime.min.time()).timestamp())
        tag_string = " ".join(f"-t t={tag}" for tag in self.tags)
        relay_str = " ".join(DEFAULT_RELAYS)
        
        # Add explicit kinds for monitoring - include kind 6 directly
        command = (
            f"/usr/local/bin/nak req --stream -k 1 {tag_string} -a {self.hex_key} "
            f"--since {midnight_today} {relay_str}"
        )
        logger.info(f"Monitoring subprocess command: {command}")
        
        async with self.subprocess_semaphore:
            try:
                proc = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                self.active_subprocesses.add(proc)
                logger.info(f"Monitoring subprocess started with PID: {proc.pid}")

                async for line in proc.stdout:
                    if self._stop_event.is_set():
                        logger.info(f"Shutdown signal received. Terminating monitoring subprocess {proc.pid}")
                        proc.terminate()
                        break
                    try:
                        data = json.loads(line)
                        id_output = data.get("id")
                        created_at_output = data.get("created_at")
                        kind = data.get("kind")

                        if id_output and created_at_output and id_output not in self.seen_ids:
                            logger.debug(f"New event detected: {id_output}, kind: {kind}")
                            self.seen_ids.add(id_output)
                            
                            # For kind 1 posts, spawn subprocess to look for reactions/reposts
                            if kind == 1:
                                task = asyncio.create_task(self.execute_subprocess(id_output, created_at_output))
                                task.add_done_callback(
                                    lambda t: logger.error(f"Subprocess task error: {t.exception()}") if t.exception() else None
                                )

                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse JSON line: {line.strip()}, error: {e}")
                    except Exception as e:
                        logger.error(f"Unexpected error while monitoring notes: {e}")

                await proc.wait()
                logger.info(f"Monitoring subprocess {proc.pid} terminated.")
            except Exception as e:
                logger.error(f"Error in monitor_new_notes: {e}")
            finally:
                self.active_subprocesses.discard(proc)
                
    async def refresh_member_cache(self):
        """Refresh the internal cache of cyberherd members"""
        if not self.database_service:
            return False
            
        try:
            # Don't refresh if cache is still fresh
            now = datetime.now()
            cache_age = (now - self.cache_refresh_time).total_seconds()
            if cache_age < self.cache_ttl and self.member_cache:
                return True
                
            logger.info("Refreshing cyberherd member cache")
            # This assumes the database service has a method to fetch all members efficiently
            members = await self.database_service.get_cyberherd_list()
            
            # Reset cache
            self.member_cache = {}
            
            # Populate cache with member data
            for member in members:
                pubkey = member.get('pubkey')
                if pubkey:
                    # Extract key fields for our cache
                    self.member_cache[pubkey] = {
                        'lud16': member.get('lud16'),
                        'nip05': member.get('nip05'),
                        'display_name': member.get('display_name', 'Anon'),
                        'picture': member.get('picture'),
                        # Parse relays from JSON string
                        'relays': json.loads(member.get('relays')) if member.get('relays') else DEFAULT_RELAYS[:3]
                    }
            
            self.cache_refresh_time = now
            logger.info(f"Cached {len(self.member_cache)} cyberherd members")
            return True
        except Exception as e:
            logger.error(f"Error refreshing member cache: {e}")
            return False

    async def get_verification_stats(self):
        """Get statistics about event verification."""
        return {
            "invalid_events_count": self.invalid_events_count,
            "last_invalid_event": self.last_invalid_event,
            "verification_enabled": True
        }
