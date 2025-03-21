import asyncio
import logging
import json
import subprocess
import random
from datetime import datetime
from typing import Optional, Dict, Any, Callable, Set, List

import httpx

from utils.cyberherd_module import (
    MetadataFetcher,
    Verifier,
    generate_nprofile,
    lookup_relay_list,
    DEFAULT_RELAYS,
)

logger = logging.getLogger(__name__)

class CyberherdListenerService:
    """Service to listen for and process cyberherd events using Nostr"""
    
    def __init__(self, 
                 nos_sec: str,
                 hex_key: str,
                 callback_handler: Optional[Callable[[Dict[str, Any]], None]] = None,
                 webhook_url: str = None,  # No longer needed, but kept for backward compatibility
                 nip05_verification: bool = True,
                 tags: List[str] = None,
                 message_template_service=None,  # Add message template service
                 database_service=None):  # Add database_service parameter
        """
        Initialize the CyberHerd listener service.
        
        Args:
            nos_sec: The Nostr private key in hex format
            hex_key: The Nostr public key in hex format
            callback_handler: Function to call when processing events
            webhook_url: Deprecated parameter, kept for backward compatibility
            nip05_verification: Whether to verify NIP-05 identifiers
            tags: List of tags to monitor, defaults to ["#CyberHerd", "CyberHerd"]
        """
        self.nos_sec = nos_sec
        self.hex_key = hex_key
        self.callback_handler = callback_handler
        self.nip05_verification = nip05_verification
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

            # Check if this is an existing member by querying the database directly
            existing_member = None
            if self.database_service:
                existing_member = await self.database_service.get_cyberherd_member(pubkey)
            
            # For kind 7 (reactions) from non-members, just log and skip further processing
            # This avoids unnecessary relay lookups, metadata fetching, and NIP-05 verification
            if kind == 7 and not existing_member:
                logger.info(f"Kind 7 reaction from non-member {pubkey}. Tracking event but skipping member processing.")
                
                # Extract the original note reference from e tags for tracking purposes
                original_note_id = None
                for tag in data.get("tags", []):
                    if isinstance(tag, list) and len(tag) > 1 and tag[0] == "e":
                        original_note_id = tag[1]
                        break
                
                # Track the reaction for analytics but don't create a member or do further processing
                if original_note_id and self.database_service:
                    try:
                        await self.database_service.track_user_reaction(pubkey, original_note_id)
                        logger.debug(f"Tracked reaction to note {original_note_id} by non-member {pubkey}")
                    except Exception as e:
                        logger.error(f"Failed to track reaction for non-member: {e}")
                
                return  # Skip further processing for kind 7 from non-members
                
            # Initialize metadata variable to avoid "referenced before assignment" errors
            metadata = {}
            
            # For existing members, use the data we already have
            if existing_member:
                logger.info(f"Found existing member in database: {pubkey}")
                
                # Convert the database record to a dictionary if it's not already
                if hasattr(existing_member, "_mapping"):
                    existing_member_dict = dict(existing_member._mapping)
                elif not isinstance(existing_member, dict):
                    existing_member_dict = dict(existing_member)
                else:
                    existing_member_dict = existing_member
                
                # Use stored member data (already verified previously)
                lud16 = existing_member_dict.get("lud16")
                
                # The database schema doesn't have a nip05 column, so we need to fetch it
                # instead of expecting it to be in the database record
                nip05 = None
                
                # For existing members with valid lud16, we should assume they passed NIP-05
                # verification when they were first added, so don't warn about missing NIP-05
                if lud16:
                    # Skip NIP-05 warnings for existing members with valid lud16
                    pass
                elif self.nip05_verification:
                    # Only for existing members without lud16, optionally verify NIP-05
                    logger.debug(f"Existing member {pubkey} may need NIP-05 verification")
                
                display_name = existing_member_dict.get("display_name", "Anon")
                picture = existing_member_dict.get("picture")
                
                # Parse stored relays from JSON string
                relays_json = existing_member_dict.get("relays")
                user_relays = json.loads(relays_json) if relays_json else DEFAULT_RELAYS[:3]
                
                # Skip NIP-05 verification for existing members
                if self.nip05_verification and not nip05:
                    logger.warning(f"Existing member {pubkey} is missing NIP-05")
                    
                # Create metadata dict from existing member data to avoid reference before assignment
                metadata = {
                    "lud16": lud16,
                    "nip05": nip05,
                    "display_name": display_name,
                    "picture": picture
                }
            else:
                # For new members, do the full lookup process
                user_relays = await lookup_relay_list(pubkey)
                logger.info(f"Found relays for {pubkey}: {user_relays}")

                # Fetch metadata using user's relays
                metadata = await self.metadata_fetcher.lookup_metadata(pubkey, user_relays)
                if not metadata:
                    logger.warning(f"No metadata found for pubkey {pubkey}. Skipping event.")
                    return

                lud16 = metadata.get("lud16")
                nip05 = metadata.get("nip05")
                display_name = metadata.get("display_name", "Anon")
                picture = metadata.get("picture")

                # For kind 7 reactions from non-members, log but still process
                if kind == 7 and not existing_member:
                    logger.info(f"Processing kind 7 reaction from non-member: {pubkey}")

                # NIP-05 verification
                if self.nip05_verification:
                    if not nip05:
                        # Check if we've already sent a DM today
                        if self.database_service and await self.database_service.has_dm_been_sent(pubkey, "missing_nip05"):
                            logger.info(f"Already sent missing NIP-05 DM to {pubkey} today, skipping")
                        else:
                            # Fetch DM template from message template service if available
                            dm_message = (
                                f"It looks like you don't have a NIP-05 identifier. "
                                f"If you'd like a {display_name}@lightning-goats.com NIP‑05 address, sign up at "
                                "https://lnb.bolverker.com/nostrnip5/signup/eGrBG7HWLJTiYyhxgEpMwz"
                            )
                            
                            # Use message template service if available
                            if self.message_template_service:
                                templates = await self.message_template_service.get_template("dm_missing_nip05")
                                if templates:
                                    # Get a random template
                                    dm_message = random.choice(list(templates.values())).format(display_name=display_name)
                            
                            logger.error(f"NIP-05 missing for pubkey {pubkey}. DMing user.")
                            await self.send_dm(pubkey, dm_message)
                            
                            # Record that we sent a DM
                            if self.database_service:
                                await self.database_service.record_dm_sent(pubkey, "missing_nip05")
                            
                            return
                    else:
                        nip05 = nip05.lower().strip()
                        logger.debug(f"Processing NIP-05: '{nip05}' for pubkey {pubkey}")
                        try:
                            is_valid_nip05 = await Verifier.verify_nip05(nip05, pubkey)
                            if not is_valid_nip05:
                                # Check if we've already sent a DM to this user today
                                if self.database_service and await self.database_service.has_dm_been_sent(pubkey, "invalid_nip05"):
                                    logger.info(f"Already sent invalid NIP-05 DM to {pubkey} today, skipping")
                                else:
                                    # Fetch DM template from message template service if available
                                    dm_message = (
                                        f"Your NIP-05 identifier has failed validation. "
                                        f"This could be a temporary glitch. You can retry joining the cyberherd. "
                                        f"If validation keeps failing, contact your NIP05 provider. "
                                        f"If you'd like a {display_name}@lightning-goats.com NIP‑05 address, please sign up at "
                                        "https://lnb.bolverker.com/nostrnip5/signup/eGrBG7HWLJTiYyhxgEpMwz"
                                    )
                                    
                                    # Use message template service if available
                                    if self.message_template_service:
                                        templates = await self.message_template_service.get_template("dm_invalid_nip05")
                                        if templates:
                                            # Get a random template
                                            dm_message = random.choice(list(templates.values())).format(display_name=display_name)
                                    
                                    logger.error(f"Invalid NIP-05 for pubkey {pubkey}: {nip05}. DMing user.")
                                    await self.send_dm(pubkey, dm_message)
                                    
                                    # Record that we sent a DM
                                    if self.database_service:
                                        await self.database_service.record_dm_sent(pubkey, "invalid_nip05")
                                    
                                    return
                            else:
                                logger.info(f"Valid NIP-05 identifier for pubkey {pubkey}: {nip05}")
                        except Exception as verify_exc:
                            logger.exception(f"Exception during NIP-05 verification for pubkey {pubkey}: {nip05}", exc_info=verify_exc)
                            return
                else:
                    logger.debug("Skipping NIP-05 verification.")

            # If lud16 is present, generate nprofile
            if not lud16:
                logger.warning(f"Missing lud16 for pubkey {pubkey}. Skipping event.")
                return

            try:
                nprofile = await generate_nprofile(pubkey)
                if not nprofile:
                    logger.error(f"Failed to generate nprofile for pubkey: {pubkey}")
                    return

                logger.debug(f"Metadata lookup success: {metadata}")

                # Extract the original note reference from e tags for both kind 6 and 7
                original_note_id = None
                for tag in data.get("tags", []):
                    if isinstance(tag, list) and len(tag) > 1 and tag[0] == "e":
                        original_note_id = tag[1]
                        logger.info(f"Found original note ID: {original_note_id}")
                        break
                
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
                
                # Process the data with direct call or webhook
                await self.send_json_payload([json_object])
                
            except asyncio.TimeoutError as e:
                logger.error(f"Nprofile encoding timed out: {e}")
            except Exception as e:
                logger.error(f"Unexpected error during nprofile encoding: {e}")

        except Exception as e:
            logger.error(f"Unexpected error in handle_event: {e}")

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
                            
                            # Direct processing for kind 6 (reposts) with CyberHerd tag
                            if kind == 6:
                                # Check for tags before processing
                                has_tag = False
                                for tag in data.get("tags", []):
                                    if (isinstance(tag, list) and len(tag) > 1 and 
                                        tag[0] == 't' and any(t in tag[1] for t in self.tags)):
                                        has_tag = True
                                        break
                                        
                                if has_tag:
                                    logger.info(f"Processing kind 6 repost directly: {id_output}")
                                    await self.handle_event(data)
                                else:
                                    logger.debug(f"Skipping kind 6 repost without CyberHerd tag: {id_output}")
                            
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
