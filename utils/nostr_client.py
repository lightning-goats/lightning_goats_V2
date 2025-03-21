"""
Nostr client utility for Lightning Goats application.
This module replaces the external 'nak' command-line tool with native Python code.
"""
import json
import time
import asyncio
import logging
import httpx
from typing import Optional, List, Dict, Any, Tuple, Set, Union
import ssl
from urllib.parse import urlparse

# Import the nostr Python library
try:
    # With secp256k1 (faster)
    import nostr.event
    from nostr.event import Event
    from nostr.key import PrivateKey
    from nostr.relay_manager import RelayManager
    from nostr.filter import Filter, Filters
    from nostr.message_type import ClientMessageType
except ImportError:
    try:
        # Fallback to pure Python implementation
        import nostr.event
        from nostr.event import Event
        from nostr.key import PrivateKey
        from nostr.relay_manager import RelayManager
        from nostr.filter import Filter, Filters
        from nostr.message_type import ClientMessageType
    except ImportError:
        logging.error("Required 'nostr' package not found. Install with: pip install nostr")
        raise

logger = logging.getLogger(__name__)

# Default relays to use when none are provided
DEFAULT_RELAYS = [
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://nos.lol",
    "wss://nostr.mom",
    "wss://relay.nostr.band"
]

class NostrClient:
    """Native Python Nostr client to replace the 'nak' command-line tool."""
    
    def __init__(self, private_key_hex: Optional[str] = None):
        """
        Initialize the Nostr client.
        
        Args:
            private_key_hex: Optional hex-encoded private key. If not provided,
                            a read-only client will be created.
        """
        self.private_key = PrivateKey(bytes.fromhex(private_key_hex)) if private_key_hex else None
        self.public_key = self.private_key.public_key.hex() if self.private_key else None
        self.relay_manager = RelayManager()
        self._relay_connection_tasks = {}
        self._connected_relays = set()
        self._ssl_context = self._create_ssl_context()
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create an SSL context that doesn't verify certificates."""
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        return ssl_context
    
    async def connect_to_relays(self, relay_urls: List[str], timeout: float = 3.0) -> Set[str]:
        """
        Connect to multiple relays concurrently.
        
        Args:
            relay_urls: List of relay WebSocket URLs
            timeout: Maximum time to wait for connections
            
        Returns:
            Set of successfully connected relay URLs
        """
        if not relay_urls:
            relay_urls = DEFAULT_RELAYS.copy()
        
        # Add relays to the manager (doesn't connect yet)
        for url in relay_urls:
            if url not in self._relay_connection_tasks:
                try:
                    self.relay_manager.add_relay(url)
                    self._relay_connection_tasks[url] = None
                except Exception as e:
                    logger.warning(f"Failed to add relay {url}: {e}")
        
        # Create tasks for connecting to relays
        connection_tasks = []
        for url in relay_urls:
            if url in self._connected_relays:
                continue  # Skip already connected relays
                
            task = asyncio.create_task(self._connect_to_relay(url))
            connection_tasks.append(task)
            self._relay_connection_tasks[url] = task
        
        # Wait for connections with timeout
        if connection_tasks:
            done, pending = await asyncio.wait(
                connection_tasks, 
                timeout=timeout,
                return_when=asyncio.ALL_COMPLETED
            )
            
            # Cancel any pending tasks
            for task in pending:
                task.cancel()
        
        return self._connected_relays
    
    async def _connect_to_relay(self, url: str) -> bool:
        """
        Connect to a single relay.
        
        Args:
            url: Relay WebSocket URL
            
        Returns:
            True if connection successful, False otherwise
        """
        try:
            await self.relay_manager.add_relay_async(url, ssl=self._ssl_context)
            self._connected_relays.add(url)
            logger.debug(f"Connected to relay: {url}")
            return True
        except Exception as e:
            logger.warning(f"Failed to connect to relay {url}: {e}")
            return False
    
    async def close(self):
        """Close all relay connections."""
        # Cancel all pending connection tasks
        for task in self._relay_connection_tasks.values():
            if task and not task.done():
                task.cancel()
        
        # Close all relay connections
        self.relay_manager.close_connections()
        self._connected_relays.clear()
    
    async def publish_event(self, 
                          kind: int, 
                          content: str, 
                          tags: List[List[str]] = None, 
                          relays: List[str] = None,
                          pow_difficulty: int = 0) -> Optional[str]:
        """
        Create and publish a Nostr event.
        
        Args:
            kind: Event kind (1=text note, 4=DM, etc.)
            content: Event content
            tags: Optional list of tags
            relays: Optional list of relay URLs to publish to
            pow_difficulty: Optional proof-of-work difficulty
            
        Returns:
            Event ID if successful, None otherwise
        """
        if not self.private_key:
            logger.error("Cannot publish event: No private key provided")
            return None
        
        # Ensure we're connected to relays
        if relays:
            await self.connect_to_relays(relays)
        elif not self._connected_relays:
            await self.connect_to_relays(DEFAULT_RELAYS)
        
        if not self._connected_relays:
            logger.error("Cannot publish event: No connected relays")
            return None
        
        # Create the event
        tags = tags or []
        event = Event(
            public_key=self.public_key,
            kind=kind,
            content=content,
            tags=tags,
            created_at=int(time.time())
        )
        
        # Sign the event
        event.sign(self.private_key.hex())
        
        if pow_difficulty > 0:
            # Do proof of work (not implemented in this example)
            pass
        
        # Publish to connected relays
        self.relay_manager.publish_event(event)
        logger.info(f"Published event {event.id} to {len(self._connected_relays)} relays")
        
        return event.id
    
    async def query_events(self, 
                         filters: Dict[str, Any], 
                         relays: List[str] = None, 
                         timeout: float = 3.0, 
                         limit: int = 5) -> List[Dict[str, Any]]:
        """
        Query events from relays.
        
        Args:
            filters: Nostr filters (authors, kinds, etc.)
            relays: Optional list of relay URLs to query
            timeout: Maximum time to wait for responses
            limit: Maximum number of events to return
            
        Returns:
            List of events matching the filters
        """
        # Ensure we're connected to relays
        if relays:
            await self.connect_to_relays(relays)
        elif not self._connected_relays:
            await self.connect_to_relays(DEFAULT_RELAYS)
        
        if not self._connected_relays:
            logger.error("Cannot query events: No connected relays")
            return []
        
        # Create nostr filter
        nostr_filter = Filter(**filters, limit=limit)
        
        # Set up subscription
        subscription_id = f"sub_{int(time.time())}"
        self.relay_manager.add_subscription(subscription_id, [nostr_filter])
        
        # Request events
        self.relay_manager.request_events(subscription_id=subscription_id)
        
        # Collect events with timeout
        events = []
        start_time = time.time()
        
        while time.time() - start_time < timeout and len(events) < limit:
            message = self.relay_manager.message_pool.get_message()
            if not message:
                await asyncio.sleep(0.1)
                continue
                
            if message.subscription_id == subscription_id and message.type == ClientMessageType.EVENT:
                # Convert to dict and add to results
                event_dict = message.event.to_dict()
                events.append(event_dict)
        
        # Remove subscription
        self.relay_manager.close_subscription(subscription_id)
        
        return events
    
    async def get_user_metadata(self, pubkey: str, relays: List[str] = None) -> Optional[Dict[str, Any]]:
        """
        Get user metadata (kind 0 event).
        
        Args:
            pubkey: User's public key in hex format
            relays: Optional list of relay URLs to query
            
        Returns:
            Parsed metadata dictionary or None if not found
        """
        events = await self.query_events(
            filters={"authors": [pubkey], "kinds": [0]},
            relays=relays,
            limit=1
        )
        
        if not events:
            return None
        
        try:
            content = json.loads(events[0]["content"])
            return {
                "display_name": content.get("display_name") or content.get("displayName") or content.get("name", "Anon"),
                "lud16": content.get("lud16") or content.get("lightning_address"),
                "nip05": content.get("nip05"),
                "picture": content.get("picture") or content.get("avatar"),
                "about": content.get("about"),
                "event_id": events[0]["id"],
                "created_at": events[0]["created_at"]
            }
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Error parsing metadata for {pubkey}: {e}")
            return None
    
    async def get_user_relays(self, pubkey: str, relays: List[str] = None) -> List[str]:
        """
        Get user's preferred relays (kind 3 event).
        
        Args:
            pubkey: User's public key in hex format
            relays: Optional list of relay URLs to query
            
        Returns:
            List of relay URLs from the user's most recent kind 3 event
        """
        events = await self.query_events(
            filters={"authors": [pubkey], "kinds": [3]},
            relays=relays,
            limit=1
        )
        
        if not events:
            return DEFAULT_RELAYS[:3]
        
        # Extract relays from tags
        user_relays = []
        for tag in events[0].get("tags", []):
            if len(tag) >= 2 and tag[0] == "r":
                relay_url = tag[1]
                # Validate the URL starts with ws:// or wss://
                if relay_url.startswith(("ws://", "wss://")):
                    user_relays.append(relay_url)
        
        # Default to a subset of DEFAULT_RELAYS if no relays found
        return user_relays[:5] if user_relays else DEFAULT_RELAYS[:3]
    
    async def verify_nip05(self, identifier: str, pubkey: str) -> bool:
        """
        Verify a NIP-05 identifier (user@domain.com).
        
        Args:
            identifier: NIP-05 identifier
            pubkey: Public key to verify against
            
        Returns:
            True if verified, False otherwise
        """
        if '@' not in identifier:
            return False
        
        name, domain = identifier.split('@', 1)
        name = name.lower()  # NIP-05 is case-insensitive
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                url = f"https://{domain}/.well-known/nostr.json"
                params = {}
                if name == '_':
                    params["name"] = name
                
                response = await client.get(url, params=params)
                response.raise_for_status()
                
                data = response.json()
                if "names" not in data or not isinstance(data["names"], dict):
                    return False
                
                # Check if the name exists and matches the pubkey
                if name in data["names"] and data["names"][name].lower() == pubkey.lower():
                    return True
                
                # Case-insensitive check for the name
                for key, value in data["names"].items():
                    if key.lower() == name.lower() and value.lower() == pubkey.lower():
                        return True
                
                return False
        except Exception as e:
            logger.error(f"Error verifying NIP-05 {identifier}: {e}")
            return False
    
    @staticmethod
    async def encode_npub(pubkey: str) -> str:
        """
        Encode a hex public key as an npub.
        
        Args:
            pubkey: Hex-encoded public key
            
        Returns:
            npub-encoded public key
        """
        try:
            from nostr.key import PublicKey
            pk = PublicKey(bytes.fromhex(pubkey))
            return pk.bech32()
        except Exception as e:
            logger.error(f"Error encoding npub for {pubkey}: {e}")
            return pubkey  # Return the original hex key if encoding fails
    
    @staticmethod
    async def decode_npub(npub: str) -> Optional[str]:
        """
        Decode an npub to a hex public key.
        
        Args:
            npub: npub-encoded public key
            
        Returns:
            Hex-encoded public key or None if invalid
        """
        try:
            if not npub.startswith("npub"):
                return None
                
            from nostr.key import PublicKey
            pk = PublicKey.from_npub(npub)
            return pk.hex()
        except Exception as e:
            logger.error(f"Error decoding npub {npub}: {e}")
            return None
    
    @staticmethod
    async def generate_nprofile(pubkey: str, relays: List[str] = None) -> Optional[str]:
        """
        Generate an nprofile string.
        
        Args:
            pubkey: Hex-encoded public key
            relays: Optional list of relays to include
            
        Returns:
            nprofile string or None if error
        """
        try:
            # Not directly supported by nostr library yet
            # This is a placeholder for future implementation
            return f"nprofile1{pubkey}"
        except Exception as e:
            logger.error(f"Error generating nprofile for {pubkey}: {e}")
            return None
    
    async def check_event_has_tag(self, event_id: str, tag_name: str, tag_value: str, relays: List[str] = None) -> bool:
        """
        Check if an event has a specific tag.
        
        Args:
            event_id: Event ID to check
            tag_name: Tag name to look for (e.g., "t")
            tag_value: Tag value to match (e.g., "CyberHerd")
            relays: Optional list of relay URLs to query
            
        Returns:
            True if the event has the tag, False otherwise
        """
        events = await self.query_events(
            filters={"ids": [event_id]},
            relays=relays,
            limit=1
        )
        
        if not events:
            return False
        
        # Check if any tag matches the specified name and value
        for tag in events[0].get("tags", []):
            if len(tag) >= 2 and tag[0] == tag_name and tag[1].lower() == tag_value.lower():
                return True
        
        return False

# Singleton instance for global use
nostr_client_instance = None

async def get_nostr_client(private_key_hex: Optional[str] = None) -> NostrClient:
    """
    Get or create a singleton NostrClient instance.
    
    Args:
        private_key_hex: Optional hex-encoded private key
        
    Returns:
        NostrClient instance
    """
    global nostr_client_instance
    if nostr_client_instance is None:
        nostr_client_instance = NostrClient(private_key_hex)
    return nostr_client_instance
