import asyncio
import logging
from typing import Dict, List, Optional, Any, Set
from utils.nostr_client import NostrClient
from services.websocket_manager import websocket_retry

class NostrClientManager:
    """
    Singleton service to manage Nostr client connections and operations.
    Creates and maintains a persistent connection to Nostr relays.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(NostrClientManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, private_key_hex: Optional[str] = None):
        if self._initialized:
            return
            
        self.logger = logging.getLogger(__name__)
        self.private_key_hex = private_key_hex
        self.client = NostrClient(private_key_hex)
        self.connected_relays: Set[str] = set()
        self.lock = asyncio.Lock()
        self.initialized_event = asyncio.Event()
        self._initialized = True

    async def initialize(self, default_relays: List[str]) -> bool:
        """Initialize the client and connect to default relays."""
        try:
            self.logger.info(f"Initializing NostrClientManager with {len(default_relays)} default relays")
            connected = await self.client.connect_to_relays(default_relays)
            self.connected_relays = set(connected)
            self.initialized_event = True
            return bool(self.connected_relays)
        except Exception as e:
            self.logger.error(f"Failed to initialize NostrClientManager: {e}")
            return False

    async def ensure_initialized(self, timeout: float = 5.0) -> bool:
        """Wait for initialization to complete."""
        try:
            await asyncio.wait_for(self.initialized_event.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            self.logger.warning("Timeout waiting for NostrClientManager initialization")
            return False
    
    async def publish_event(self, kind: int, content: str, tags: List[List[str]] = None, 
                           relays: List[str] = None) -> Optional[str]:
        """Publish a Nostr event."""
        async with self.lock:
            if relays:
                await self.client.connect_to_relays(relays)
            return await self.client.publish_event(kind, content, tags, relays)
    
    async def get_event(self, event_id: str, relays: List[str] = None) -> Optional[Dict[str, Any]]:
        """Get an event by ID."""
        async with self.lock:
            if relays:
                await self.client.connect_to_relays(relays)
            events = await self.client.query_events({"ids": [event_id]}, relays, timeout=3.0, limit=1)
            return events[0] if events else None
    
    async def encrypt_dm(self, content: str, recipient_pubkey: str) -> str:
        """Encrypt a direct message for a recipient."""
        return await self.client.encrypt_dm(content, self.private_key_hex, recipient_pubkey)
    
    async def send_dm(self, content: str, recipient_pubkey: str, relays: List[str] = None) -> Optional[str]:
        """Encrypt and send a direct message."""
        encrypted = await self.encrypt_dm(content, recipient_pubkey)
        tags = [['p', recipient_pubkey]]
        return await self.publish_event(4, encrypted, tags, relays)
    
    async def get_user_metadata(self, pubkey: str, relays: List[str] = None) -> Optional[Dict[str, Any]]:
        """Get a user's metadata."""
        async with self.lock:
            if relays:
                await self.client.connect_to_relays(relays)
            return await self.client.get_user_metadata(pubkey, relays)
    
    async def generate_nprofile(self, pubkey: str, relays: List[str] = None) -> Optional[str]:
        """Generate an nprofile for a pubkey."""
        return await self.client.generate_nprofile(pubkey, relays)
    
    async def check_event_tag(self, event_id: str, tag_name: str, tag_value: str, 
                             relays: List[str] = None) -> bool:
        """Check if an event has a specific tag."""
        return await self.client.check_event_has_tag(event_id, tag_name, tag_value, relays)
    
    async def close(self):
        """Close all connections."""
        await self.client.close()
