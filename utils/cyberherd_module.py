import asyncio
import json
import logging
import re
import time
import socket
from typing import Optional, Dict, Any, List, Tuple, Union
import httpx
import urllib.parse
import random

# Import core Nostr functionality cleanly
from utils.nostr_utils import (
    # Core key/event functions
    validate_pub_key, normalize_identifier, hex_to_npub, is_ws_url,
    
    # Relay-related functions
    DEFAULT_RELAYS, FALLBACK_RELAYS, get_best_relays, lookup_relay_list,
    
    # Event handling
    check_event_tag,
    
    # Import generate_nprofile explicitly to fix the error
    generate_nprofile,
    
    # Classes to be extended
    NostrVerifier, NostrMetadataFetcher
)

# Logging Configuration
logger = logging.getLogger(__name__)

# Cache for domain resolutions
# Structure: {domain: {"ip": str, "timestamp": int}}
dns_cache = {}
DNS_CACHE_TTL = 3600  # 1 hour

async def resolve_domain(domain: str) -> Optional[str]:
    """Resolve domain to IP address with caching."""
    now = time.time()
    
    # Check cache first
    if domain in dns_cache:
        cache_entry = dns_cache[domain]
        if now - cache_entry["timestamp"] < DNS_CACHE_TTL:
            return cache_entry["ip"]
    
    # If not in cache or cache expired, resolve domain
    try:
        # Use getaddrinfo for proper async DNS resolution
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None, 
            lambda: socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        )
        if result and len(result) > 0:
            ip = result[0][4][0]  # Extract IP address
            dns_cache[domain] = {"ip": ip, "timestamp": now}
            return ip
    except (socket.gaierror, socket.herror, socket.timeout) as e:
        logger.warning(f"Failed to resolve domain {domain}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error resolving domain {domain}: {e}")
    
    return None

# For backward compatibility - extend NostrVerifier with cyberherd-specific verification
class Verifier(NostrVerifier):
    """CyberHerd extension of NostrVerifier with additional verification methods"""
    
    @staticmethod
    async def verify_lud16(lud16: str) -> bool:
        """
        Verify a Lightning Address (LUD-16) format and connectivity.
        
        Args:
            lud16: Lightning address to verify
            
        Returns:
            bool: True if the Lightning address is valid and reachable
        """
        if not lud16 or '@' not in lud16:
            logger.warning(f"Invalid Lightning address format: {lud16}")
            return False
            
        try:
            # Basic format validation
            username, domain = lud16.split('@', 1)
            if not username or not domain or '.' not in domain:
                logger.warning(f"Invalid Lightning address components: {lud16}")
                return False
                
            # Validate username format
            if not re.match(r'^[a-zA-Z0-9_.]+$', username):
                logger.warning(f"Invalid username in Lightning address: {username}")
                return False
                
            # Verify domain resolution
            domain_ip = await resolve_domain(domain)
            if not domain_ip:
                logger.warning(f"Could not resolve domain in Lightning address: {domain}")
                return False
                
            # Try to fetch the LN URL
            url = f"https://{domain}/.well-known/lnurlp/{username}"
            
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                response = await client.get(url)
                
                if response.status_code != 200:
                    logger.warning(f"LN URL endpoint returned {response.status_code} for {lud16}")
                    return False
                    
                # Parse JSON response
                data = response.json()
                
                # Verify the response has the required fields for a valid LN URL
                if not all(field in data for field in ["callback", "maxSendable", "minSendable"]):
                    logger.warning(f"LN URL response missing required fields for {lud16}")
                    return False
                    
                logger.info(f"Successfully verified Lightning address: {lud16}")
                return True
                
        except httpx.RequestError as e:
            logger.warning(f"Network error verifying Lightning address {lud16}: {e}")
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON response from Lightning address endpoint for {lud16}: {e}")
        except Exception as e:
            logger.warning(f"Error verifying Lightning address {lud16}: {e}")
            
        return False

    @staticmethod
    async def verify_nip05(nip05_id: str, pubkey: str) -> bool:
        """
        Verify a NIP-05 identifier against a given pubkey.
        This method has been modified to explicitly NOT cache results.
        
        Args:
            nip05_id: The NIP-05 identifier to verify (username@domain)
            pubkey: The public key to verify against
            
        Returns:
            bool: True if verification succeeded, False otherwise
        """
        if not nip05_id or not pubkey:
            logger.debug(f"Missing NIP-05 or pubkey: {nip05_id}, {pubkey}")
            return False
            
        try:
            # Split the NIP-05 identifier
            parts = nip05_id.split('@')
            if len(parts) != 2:
                logger.debug(f"Invalid NIP-05 format (missing @): {nip05_id}")
                return False
                
            name, domain = parts
            
            # Normalize pubkey (strip any prefixes)
            normalized_pubkey = pubkey.lower()
            if normalized_pubkey.startswith("npub"):
                logger.warning(f"Received npub format instead of hex pubkey: {pubkey}")
                # If we had hex_key conversion it would go here
                return False
            
            # Construct the verification URL
            url = f"https://{domain}/.well-known/nostr.json?name={name}"
            logger.debug(f"Verifying NIP-05 {nip05_id} against pubkey {pubkey}")
            logger.debug(f"Requesting URL: {url}")
            
            # Make a direct request without caching
            async with httpx.AsyncClient(timeout=15.0) as client:
                # Explicitly disable caching with Cache-Control headers
                headers = {
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "Pragma": "no-cache"
                }
                response = await client.get(url, headers=headers, follow_redirects=True)
                
                # Log response status
                logger.debug(f"NIP-05 verify response status: {response.status_code}")
                
                if response.status_code != 200:
                    logger.warning(f"NIP-05 verify received non-200 response: {response.status_code}")
                    return False
                    
                # Try to parse the JSON response
                try:
                    data = response.json()
                except json.JSONDecodeError as je:
                    logger.warning(f"Invalid JSON response for NIP-05 verification: {je}")
                    return False
                
                # Log the complete response for debugging
                logger.debug(f"NIP-05 JSON response: {data}")
                
                # Find the pubkey in the response
                if "names" in data and name in data["names"]:
                    verified_pubkey = data["names"][name]
                    logger.debug(f"NIP-05 comparison: {verified_pubkey.lower()} == {normalized_pubkey}")
                    # Compare with provided pubkey
                    return verified_pubkey.lower() == normalized_pubkey
                else:
                    logger.warning(f"NIP-05 verify: 'names' missing or name not found. Response data: {data}")
                    
            return False
        except httpx.TimeoutException as te:
            logger.warning(f"NIP-05 verification timeout: {te}")
            return False
        except httpx.RequestError as re:
            logger.warning(f"NIP-05 verification request error: {re}")
            return False
        except Exception as e:
            logger.warning(f"NIP-05 verification error: {e}")
            return False

# For backward compatibility - extend NostrMetadataFetcher with cyberherd-specific methods
class MetadataFetcher(NostrMetadataFetcher):
    """CyberHerd extension of NostrMetadataFetcher with additional metadata functionality"""
    
    async def lookup_metadata(self, pubkey: str, relays: Optional[List[str]] = None, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        """
        Look up metadata for a pubkey from the specified relays.
        
        Args:
            pubkey: The public key to look up
            relays: List of relay URLs to query
            use_cache: Whether to use cached results (now defaults to True for backward compatibility)
            
        Returns:
            Dict containing metadata if found, None otherwise
        """
        # We'll ignore use_cache parameter since we're removing caching
        if not pubkey or not relays:
            return None
            
        try:
            # Just pass through to the parent class method
            return await self.fetch_metadata(pubkey, relays)
        except Exception as e:
            logger.warning(f"Error looking up metadata for {pubkey}: {e}")
            return None
    
    async def lookup_metadata_with_relays(self, pubkey: str, relays: Optional[List[str]] = None) -> Tuple[Optional[Dict[str, Any]], List[str]]:
        """Fetch metadata and return with the relays used."""
        if not relays:
            relays = DEFAULT_RELAYS[:3]
            
        metadata = await self.fetch_metadata(pubkey, relays)
        
        if metadata:
            # Also try to get user-preferred relays
            user_relays = await lookup_relay_list(pubkey, relays)
            return metadata, user_relays or relays
        
        return None, relays

    async def lookup_relays(self, pubkey: str, relays: Optional[List[str]] = None) -> List[str]:
        """Legacy wrapper for lookup_relay_list function."""
        return await lookup_relay_list(pubkey, relays)

async def check_cyberherd_tag(event_id: str, relays: Optional[List[str]] = None) -> bool:
    """
    Check if the event identified by `event_id` has a 'CyberHerd' tag.

    Args:
        event_id (str): The ID of the event to check.
        relays (Optional[List[str]]): List of relay URLs. Defaults to DEFAULT_RELAYS.

    Returns:
        bool: True if the event has a 'CyberHerd' tag, False otherwise.
    """
    return await check_event_tag(event_id, "CyberHerd", relays)

# Helper function to format kinds data consistently
def format_kinds(kinds: Union[List[int], str, None]) -> str:
    """Format kinds data to a consistent string format."""
    if not kinds:
        return ""
    
    if isinstance(kinds, list):
        # Convert list of kinds to string if needed
        return ",".join(map(str, sorted(kinds)))
    
    if isinstance(kinds, str):
        # If already a string, ensure proper format
        try:
            # Split, parse and rejoin to ensure consistent format
            kind_list = [int(k.strip()) for k in kinds.split(',') if k.strip()]
            return ",".join(map(str, sorted(kind_list)))
        except ValueError:
            logger.warning(f"Invalid kinds string format: {kinds}")
            return kinds.strip()
    
    # Any other type, convert to string
    return str(kinds)

# Helper function to parse kinds from various formats
def parse_kinds(kinds: Union[List[int], str, None]) -> List[int]:
    """Parse kinds data to a list of integers."""
    if not kinds:
        return []
    
    if isinstance(kinds, list):
        # If already a list, return a copy to avoid modifying the original
        return list(kinds)
    
    if isinstance(kinds, str):
        # Parse from string
        try:
            return [int(k.strip()) for k in kinds.split(',') if k.strip()]
        except ValueError:
            logger.warning(f"Invalid kinds string format: {kinds}")
            return []
    
    # Try single value conversion
    try:
        return [int(kinds)]
    except (ValueError, TypeError):
        logger.warning(f"Unsupported kinds format: {kinds}")
        return []