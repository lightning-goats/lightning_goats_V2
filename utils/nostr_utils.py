"""
Comprehensive Nostr utilities for Lightning Goats.

This module provides core Nostr protocol utilities:
- Key operations (generation, conversion, normalization)
- Event signing and verification
- Content encryption/decryption
- NIP-57 zap functionality
- Base verification and metadata functionality
"""
import json
import time
import secrets
import hashlib
import base64
import logging
import asyncio  # Added missing import for Semaphore
import random   # Added for random.random() function
import re       # Added for regular expressions
import subprocess  # Added for subprocess calls
import urllib.parse  # Added for URL encoding
import httpx      # Added for HTTP requests in NIP-05 verification
from typing import Dict, Any, List, Optional, Tuple, Union, Set
from urllib.parse import urlparse

# Try to import secp256k1, fall back to coincurve if not available
try:
    import secp256k1
    HAS_SECP256K1 = True
except ImportError:
    HAS_SECP256K1 = False
    try:
        import coincurve
        HAS_COINCURVE = True
    except ImportError:
        HAS_COINCURVE = False

# Import cryptography modules
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# Create logger
logger = logging.getLogger(__name__)

# Constants
SUPPORTED_NIPS = [1, 4, 5, 9, 10, 19, 57]  # NIPs supported by this implementation
KIND_METADATA = 0
KIND_TEXT_NOTE = 1
KIND_RECOMMEND_RELAY = 2
KIND_CONTACTS = 3
KIND_ENCRYPTED_DM = 4
KIND_EVENT_DELETION = 5
KIND_REPOST = 6
KIND_REACTION = 7
KIND_BADGE_AWARD = 8
KIND_ZAP_REQUEST = 9734
KIND_ZAP_RECEIPT = 9735

###########################
# Key and Address Management
###########################

def generate_key_pair() -> Tuple[str, str]:
    """
    Generate a new Nostr keypair.
    
    Returns:
        Tuple[str, str]: (private_key_hex, public_key_hex)
    """
    if HAS_SECP256K1:
        private_key = secp256k1.PrivateKey()
        return private_key.private_key.hex(), private_key.pubkey.serialize()[1:].hex()
    elif HAS_COINCURVE:
        private_key = coincurve.PrivateKey()
        return private_key.secret, private_key.public_key.format().hex()[2:]
    else:
        raise ImportError("No compatible EC library found. Install either secp256k1 or coincurve")

def get_public_key(private_key_hex: str) -> str:
    """
    Derive public key from a private key.
    
    Args:
        private_key_hex: Private key as hex string
        
    Returns:
        str: Public key as hex string
    """
    if not private_key_hex or len(private_key_hex) != 64:
        raise ValueError("Invalid private key format")
        
    try:
        if HAS_SECP256K1:
            private_key = secp256k1.PrivateKey(bytes.fromhex(private_key_hex), raw=True)
            return private_key.pubkey.serialize()[1:].hex()
        elif HAS_COINCURVE:
            private_key = coincurve.PrivateKey(bytes.fromhex(private_key_hex))
            return private_key.public_key.format().hex()[2:]
        else:
            raise ImportError("No compatible EC library found. Install either secp256k1 or coincurve")
    except Exception as e:
        logger.error(f"Error getting public key: {e}")
        raise ValueError(f"Failed to derive public key: {e}")

def normalize_public_key(key: str) -> str:
    """Convert a public key from npub or hex to normalized hex format."""
    return normalize_bech32_key("npub1", key)

def normalize_private_key(key: str) -> str:
    """Convert a private key from nsec or hex to normalized hex format."""
    return normalize_bech32_key("nsec1", key)

def normalize_bech32_key(hrp: str, key: str) -> str:
    """Convert a bech32 encoded key to hex format."""
    if key.startswith(hrp):
        _, decoded_data = bech32_decode(key)
        assert decoded_data, f"Key is not valid {hrp}."

        decoded_data_bits = convertbits(decoded_data, 5, 8, False)
        assert decoded_data_bits, f"Key is not valid {hrp}."

        return bytes(decoded_data_bits).hex()

    assert len(key) == 64, "Key has wrong length."
    try:
        int(key, 16)
    except Exception as exc:
        raise AssertionError("Key is not valid hex.") from exc
    return key

def hex_to_npub(hex_pubkey: str) -> str:
    """Convert a hex public key to bech32 npub format."""
    normalize_public_key(hex_pubkey)
    pubkey_bytes = bytes.fromhex(hex_pubkey)
    bits = convertbits(pubkey_bytes, 8, 5, True)
    assert bits
    return bech32_encode("npub", bits)

def validate_pub_key(pubkey: str) -> str:
    """Validate and normalize a public key."""
    if pubkey.startswith("npub"):
        _, data = bech32_decode(pubkey)
        if data:
            decoded_data = convertbits(data, 5, 8, False)
            if decoded_data:
                pubkey = bytes(decoded_data).hex()
    try:
        _hex = bytes.fromhex(pubkey)
    except Exception as exc:
        raise ValueError("Pubkey must be in npub or hex format.") from exc

    if len(_hex) != 32:
        raise ValueError("Pubkey length incorrect.")

    return pubkey

def normalize_identifier(identifier: str):
    """Normalize a Lightning identifier (local part of address)."""
    identifier = identifier.lower().split("@")[0]
    validate_identifier(identifier)
    return identifier

def validate_identifier(local_part: str):
    """Validate a Lightning address local part."""
    regex = re.compile(r"^[a-z0-9_.]+$")
    if not re.fullmatch(regex, local_part.lower()):
        raise ValueError(
            f"Identifier '{local_part}' not allowed! "
            "Only a-z, 0-9 and .-_ are allowed characters, case insensitive."
        )

###########################
# Event Serialization & Signing
###########################

def json_dumps(data: Union[Dict, list]) -> str:
    """Convert data to compact JSON string format."""
    if isinstance(data, Dict):
        data = {k: v for k, v in data.items() if v is not None}
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False)

def remove_id_and_sig(event: dict) -> dict:
    """Remove 'id' and 'sig' fields from an event."""
    return {k: v for k, v in event.items() if k not in ["id", "sig"]}

def serialize_event(event: dict) -> bytes:
    """Serialize a Nostr event for signing."""
    return json_dumps(
        [
            0,
            event["pubkey"],
            event["created_at"],
            event["kind"],
            event.get("tags", []),
            event.get("content", "")
        ]
    ).encode("utf-8")

def compute_event_hash(serialized_event: bytes) -> bytes:
    """Compute the SHA-256 hash of the serialized event."""
    return hashlib.sha256(serialized_event).digest()

def sign_event_hash(event_hash: bytes, private_key_hex: str) -> str:
    """Sign the event hash with a Nostr private key."""
    sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    signature = sk.sign_deterministic(event_hash)
    return signature.hex()

def update_event_with_id_and_sig(event: dict, event_hash: bytes, signature_hex: str) -> dict:
    """Update an event with its ID and signature."""
    event["id"] = event_hash.hex()
    event["sig"] = signature_hex
    return event

def verify_event(event: Dict) -> bool:
    """Verify the signature of a Nostr event."""
    signature_data = json_dumps(
        [
            0,
            event["pubkey"],
            event["created_at"],
            event["kind"],
            event["tags"],
            event["content"],
        ]
    )
    event_id = hashlib.sha256(signature_data.encode()).hexdigest()
    if event_id != event["id"]:
        return False
    pubkey_hex = event["pubkey"]
    pubkey = secp256k1.PublicKey(bytes.fromhex("02" + pubkey_hex), True)
    if not pubkey.schnorr_verify(
        bytes.fromhex(event_id), bytes.fromhex(event["sig"]), None, raw=True
    ):
        return False
    return True

async def sign_event(event: dict, private_key_hex: str) -> dict:
    """Sign a Nostr event with a private key."""
    unsigned_event = remove_id_and_sig(event)
    serialized = serialize_event(unsigned_event)
    event_hash = compute_event_hash(serialized)
    signature_hex = sign_event_hash(event_hash, private_key_hex)
    return update_event_with_id_and_sig(event, event_hash, signature_hex)

def create_event(
    content: str,
    kind: int,
    private_key_hex: str,
    tags: List[List[str]] = None,
    created_at: Optional[int] = None
) -> Dict[str, Any]:
    """
    Create and sign a Nostr event.
    
    Args:
        content: Event content (message)
        kind: Event kind (type)
        private_key_hex: Private key in hex format
        tags: Optional list of tags
        created_at: Optional timestamp (defaults to current time)
        
    Returns:
        Dict: Signed Nostr event
    """
    # Ensure tags is a list
    tags = tags or []
    
    # Derive public key
    pubkey = get_public_key(private_key_hex)
    
    # Get timestamp if not provided
    if created_at is None:
        created_at = int(time.time())
    
    # Create the event
    event = {
        "content": content,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "pubkey": pubkey
    }
    
    # Calculate event ID (hash of the serialized event)
    event_id = calc_event_id(event)
    event["id"] = event_id
    
    # Sign the event
    event["sig"] = sign_event_id(event_id, private_key_hex)
    
    return event

def sign_event_id(event_id: str, private_key_hex: str) -> str:
    """
    Sign an event ID with a private key.
    
    Args:
        event_id: Event ID to sign
        private_key_hex: Private key in hex format
        
    Returns:
        str: Signature as hex string
    """
    if HAS_SECP256K1:
        private_key = secp256k1.PrivateKey(bytes.fromhex(private_key_hex), raw=True)
        sig = private_key.schnorr_sign(bytes.fromhex(event_id), None, raw=True)
        return sig.hex()
    elif HAS_COINCURVE:
        private_key = coincurve.PrivateKey(bytes.fromhex(private_key_hex))
        sig = private_key.schnorr_sign(bytes.fromhex(event_id), None)
        return sig.hex()
    else:
        raise ImportError("No compatible EC library found. Install either secp256k1 or coincurve")

def calc_event_id(event: Dict[str, Any]) -> str:
    """
    Calculate the event ID (hash of the serialized event).
    
    Args:
        event: Nostr event object
        
    Returns:
        str: Event ID as hex string
    """
    event_data = [
        0,  # Reserved for future use
        event["pubkey"],
        event["created_at"],
        event["kind"],
        event["tags"],
        event["content"]
    ]
    event_str = json.dumps(event_data, separators=(',', ':'), ensure_ascii=False)
    event_hash = hashlib.sha256(event_str.encode()).hexdigest()
    return event_hash

def verify_event(event: Dict[str, Any]) -> bool:
    """
    Verify the signature of a Nostr event.
    
    Args:
        event: Nostr event object
        
    Returns:
        bool: True if the signature is valid
    """
    try:
        event_id = calc_event_id(event)
        if event_id != event["id"]:
            logger.warning(f"Event ID mismatch: {event_id} != {event['id']}")
            return False
            
        pubkey = event["pubkey"]
        sig = event["sig"]
        
        if HAS_SECP256K1:
            pubkey_obj = secp256k1.PublicKey(bytes.fromhex("02" + pubkey), raw=True)
            return pubkey_obj.schnorr_verify(
                bytes.fromhex(event_id),
                bytes.fromhex(sig),
                None,
                raw=True
            )
        elif HAS_COINCURVE:
            public_key = coincurve.PublicKey(bytes.fromhex("02" + pubkey))
            return public_key.verify_schnorr(
                bytes.fromhex(sig),
                bytes.fromhex(event_id)
            )
        else:
            raise ImportError("No compatible EC library found. Install either secp256k1 or coincurve")
    except Exception as e:
        logger.error(f"Error verifying event: {e}")
        return False

###########################
# Content Encryption
###########################

def encrypt_content(
    content: str, service_pubkey: secp256k1.PublicKey, account_private_key_hex: str
) -> str:
    """Encrypt content for a specific recipient using shared secret."""
    shared = service_pubkey.tweak_mul(
        bytes.fromhex(account_private_key_hex)
    ).serialize()[1:]
    # random iv (16B)
    iv = Random.new().read(AES.block_size)
    aes = AES.new(shared, AES.MODE_CBC, iv)

    content_bytes = content.encode("utf-8")

    # padding
    content_bytes = pad(content_bytes, AES.block_size)

    # Encrypt
    encrypted_b64 = base64.b64encode(aes.encrypt(content_bytes)).decode("ascii")
    iv_b64 = base64.b64encode(iv).decode("ascii")
    encrypted_content = encrypted_b64 + "?iv=" + iv_b64
    return encrypted_content

def decrypt_content(
    content: str, service_pubkey: secp256k1.PublicKey, account_private_key_hex: str
) -> str:
    """Decrypt content that was encrypted with a shared secret."""
    shared = service_pubkey.tweak_mul(
        bytes.fromhex(account_private_key_hex)
    ).serialize()[1:]
    # extract iv and content
    (encrypted_content_b64, iv_b64) = content.split("?iv=")
    encrypted_content = base64.b64decode(encrypted_content_b64.encode("ascii"))
    iv = base64.b64decode(iv_b64.encode("ascii"))
    # Decrypt
    aes = AES.new(shared, AES.MODE_CBC, iv)
    decrypted_bytes = aes.decrypt(encrypted_content)
    decrypted_bytes = unpad(decrypted_bytes, AES.block_size)
    decrypted = decrypted_bytes.decode("utf-8")

    return decrypted

def encrypt_dm(content: str, sender_private_key: str, recipient_pubkey: str) -> str:
    """
    Encrypt a direct message using NIP-04.
    
    Args:
        content: Message content to encrypt
        sender_private_key: Sender's private key
        recipient_pubkey: Recipient's public key
        
    Returns:
        str: Encrypted message as a string
    """
    if not HAS_CRYPTOGRAPHY:
        logger.error("Failed to encrypt message: cryptography library not installed")
        raise ImportError("The 'cryptography' package is required for NIP-04 encryption")
    
    try:
        # Decode keys
        sender_key = ec.derive_private_key(
            int.from_bytes(bytes.fromhex(sender_private_key), byteorder="big"),
            ec.SECP256K1(),
            default_backend()
        )
        
        recipient_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(),
            b'\x02' + bytes.fromhex(recipient_pubkey)
        )
        
        # Derive shared point and create shared key
        shared_point = sender_key.exchange(ec.ECDH(), recipient_pub)
        shared_key = hashlib.sha256(shared_point).digest()
        
        # Create initialization vector
        iv = secrets.token_bytes(16)
        
        # Pad the content
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(content.encode()) + padder.finalize()
        
        # Encrypt the content
        cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv), default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encode and return
        return base64.b64encode(iv + ciphertext).decode('utf-8')
    except Exception as e:
        logger.error(f"Failed to encrypt message: {e}")
        raise ValueError(f"Encryption failed: {e}")

def decrypt_dm(encrypted_content: str, recipient_private_key: str, sender_pubkey: str) -> str:
    """
    Decrypt a direct message using NIP-04.
    
    Args:
        encrypted_content: Encrypted message
        recipient_private_key: Recipient's private key
        sender_pubkey: Sender's public key
        
    Returns:
        str: Decrypted message
    """
    if not HAS_CRYPTOGRAPHY:
        logger.error("Failed to decrypt message: cryptography library not installed")
        raise ImportError("The 'cryptography' package is required for NIP-04 decryption")
    
    try:
        # Decode data
        decoded = base64.b64decode(encrypted_content)
        iv, ciphertext = decoded[:16], decoded[16:]
        
        # Decode keys
        recipient_key = ec.derive_private_key(
            int.from_bytes(bytes.fromhex(recipient_private_key), byteorder="big"),
            ec.SECP256K1(),
            default_backend()
        )
        
        sender_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(),
            b'\x02' + bytes.fromhex(sender_pubkey)
        )
        
        # Derive shared point and create shared key
        shared_point = recipient_key.exchange(ec.ECDH(), sender_pub)
        shared_key = hashlib.sha256(shared_point).digest()
        
        # Decrypt the message
        cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv), default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad the content
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext.decode('utf-8')
    except Exception as e:
        logger.error(f"Failed to decrypt message: {e}")
        raise ValueError(f"Decryption failed: {e}")

###########################
# LNURL Zap (NIP-57) Functionality
###########################

def build_zap_event(
    msat_amount: int,
    zapper_pubkey: str,
    zapped_pubkey: str,
    note_id: Optional[str] = None,
    relays: Optional[List[str]] = None,
    content: str = "LNURL Zap"
) -> dict:
    """
    Build a NIP-57 zap event (unsigned).
    
    Args:
        msat_amount: Amount in millisats
        zapper_pubkey: Public key of the zapper (sender)
        zapped_pubkey: Public key of the zapped user (recipient)
        note_id: Optional note ID if zapping a specific note
        relays: List of relay URLs to include in the event
        content: Message content for the zap
        
    Returns:
        An unsigned zap event
    """
    if not relays:
        relays = [
            "wss://primal.net",
            "wss://relay.damus.io",
            "wss://relay.nostr.band/"
        ]

    # Basic set of NIP-57 zap tags
    tags = [
        ["relays", *relays],
        ["amount", str(msat_amount)],
        ["p", zapped_pubkey]
    ]

    # If referencing a specific note
    if note_id:
        # "root" marker is typical if zapping an original post
        tags.append(["e", note_id, relays[0], "root"])

    # Build the partial event
    event = {
        "kind": 9734,
        "content": content,
        "created_at": int(time.time()),
        "tags": tags,
        # The pubkey who is *sending* the zap
        "pubkey": zapper_pubkey,
    }

    return event

async def sign_zap_event(
    msat_amount: int,
    zapper_pubkey: str,
    zapped_pubkey: str,
    private_key_hex: str,
    content: str = "",
    event_id: Optional[str] = None,
    relays: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Create a zap request event (NIP-57) properly formatted.
    
    Args:
        msat_amount: Amount in millisatoshis
        zapper_pubkey: Public key of the zapper
        zapped_pubkey: Public key of the user being zapped
        private_key_hex: Private key of the zapper
        content: Optional content for the zap note
        event_id: Optional ID of the event being zapped
        relays: Optional list of relay URLs
    
    Returns:
        Dict: Signed zap request event
    """
    tags = [
        ['p', zapped_pubkey],
        ['amount', str(msat_amount)],
        ['relays', *(relays or [])]
    ]
    
    # Add event reference if provided
    if event_id:
        tags.append(['e', event_id])
    
    return create_event(
        content=content,
        kind=KIND_ZAP_REQUEST,
        private_key_hex=private_key_hex,
        tags=tags
    )

###########################
# Base Verification Classes
###########################
# Base verification class that can be extended by domain-specific modules
class NostrVerifier:
    @staticmethod
    async def verify_nip05(nip05: str, pubkey: str, cache=None, ttl=3600) -> bool:
        """Verify a NIP-05 identifier with caching."""
        if not nip05 or not pubkey:
            logging.error("Missing nip05 or pubkey")
            return False
            
        # Generate a cache key combining nip05 and pubkey
        cache_key = f"{nip05.lower()}:{pubkey.lower()}"
        
        # Check our internal cache first
        now = time.time()
        if cache_key in nip05_cache:
            cache_entry = nip05_cache[cache_key]
            # Use different TTLs for successful and failed verifications
            cache_ttl = ttl if cache_entry["result"] else NIP05_FAILURE_CACHE_TTL
            if now - cache_entry["timestamp"] < cache_ttl:
                logging.debug(f"Using cached NIP-05 verification result for {nip05}: {cache_entry['result']}")
                return cache_entry["result"]
        
        # If not in cache or expired, do actual verification
        result = await NostrVerifier._actual_verify_nip05(nip05, pubkey)
        
        # Update cache with result
        nip05_cache[cache_key] = {"result": result, "timestamp": now}
        
        # Cleanup old cache entries periodically (1% chance)
        if random.random() < 0.01:
            await NostrVerifier._cleanup_nip05_cache(ttl)
            
        return result

    @staticmethod
    async def _cleanup_nip05_cache(ttl: int):
        """Clean up expired NIP-05 cache entries."""
        try:
            now = time.time()
            expired_keys = []
            
            for key, entry in nip05_cache.items():
                # Use appropriate TTL based on verification result
                cache_ttl = ttl if entry["result"] else NIP05_FAILURE_CACHE_TTL
                if now - entry["timestamp"] >= cache_ttl:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del nip05_cache[key]
                
            if expired_keys:
                logging.debug(f"Cleaned up {len(expired_keys)} expired NIP-05 cache entries")
        except Exception as e:
            logging.error(f"Error cleaning up NIP-05 cache: {e}")

    @staticmethod
    async def _actual_verify_nip05(nip05: str, pubkey: str) -> bool:
        """
        Verify a NIP-05 identifier according to the specification.
        """
        if not nip05 or not pubkey:
            logging.error("Missing nip05 or pubkey")
            return False
            
        try:
            # Parse NIP-05 identifier
            if '@' not in nip05:
                logging.error(f"Invalid NIP-05 format (missing @): {nip05}")
                return False
                
            name, domain = nip05.split('@', 1)
            
            # Basic domain validation
            if not domain or '.' not in domain or len(domain) < 3:
                logging.error(f"Invalid domain in NIP-05: {domain}")
                return False
                
            # Convert name to lowercase as per NIP-05 spec (case-insensitive)
            name = name.lower()
            logging.debug(f"Parsed NIP-05: name='{name}', domain='{domain}'")
            
            # Validate domain resolution before continuing
            from utils.cyberherd_module import resolve_domain
            domain_ip = await resolve_domain(domain)
            if not domain_ip:
                logging.error(f"Failed to resolve domain for NIP-05 verification: {domain}")
                return False
            
            # Convert pubkey to hex format if it's in npub format
            hex_pubkey = pubkey
            if pubkey.startswith('npub'):
                try:
                    hex_pubkey = normalize_identifier(pubkey)
                    logging.debug(f"Converted npub to hex: {hex_pubkey}")
                except Exception as e:
                    logging.error(f"Error normalizing pubkey {pubkey}: {e}")
                    return False
            
            # Properly URL encode the name part for query parameter
            encoded_name = urllib.parse.quote(name)
            
            # Construct URL for well-known JSON file
            url = f"https://{domain}/.well-known/nostr.json"
            query_params = {}
            if name == '_':
                query_params["name"] = encoded_name
                
            logging.debug(f"Fetching NIP-05 data from: {url}")
            
            # Multiple try attempts with increasing timeouts
            max_retries = 3
            verification_success = False
            
            for attempt in range(1, max_retries + 1):
                timeout = 5.0 * attempt  # Increase timeout with each retry
                
                try:
                    # Create a client with specific options for this request
                    async with httpx.AsyncClient(
                        timeout=timeout,
                        follow_redirects=True,
                        http2=True
                    ) as client:
                        # Make the request with query parameters if needed
                        response = await client.get(
                            url, 
                            headers={"Accept": "application/json"}, 
                            params=query_params
                        )
                        response.raise_for_status()
                        
                        # Parse and validate the JSON response
                        try:
                            nip05_data = response.json()
                        except json.JSONDecodeError as e:
                            logging.warning(f"Invalid JSON in NIP-05 response: {e}")
                            continue
                        
                        # Check if the name exists in the names section
                        if "names" not in nip05_data:
                            logging.warning(f"NIP-05 validation failed: Missing 'names' field in response")
                            continue
                        
                        if not isinstance(nip05_data["names"], dict):
                            logging.warning(f"NIP-05 validation failed: 'names' is not a dictionary")
                            continue
                        
                        # Try to find the name (case-insensitively)
                        found = False
                        registered_pubkey = None
                        
                        # First try exact match
                        if name in nip05_data["names"]:
                            registered_pubkey = nip05_data["names"][name]
                            found = True
                        else:
                            # Then try case-insensitive match
                            for key, value in nip05_data["names"].items():
                                if key.lower() == name.lower():
                                    registered_pubkey = value
                                    found = True
                                    break
                        
                        if not found:
                            logging.warning(f"NIP-05 validation failed: Name '{name}' not found")
                            continue
                        
                        # Compare normalized pubkeys (case-insensitive)
                        if registered_pubkey.lower() == hex_pubkey.lower():
                            logging.info(f"NIP-05 verification successful for {nip05}")
                            verification_success = True
                            break
                        else:
                            logging.warning(f"NIP-05 verification failed: pubkey mismatch")
                            return False
                            
                except httpx.HTTPStatusError as e:
                    logging.warning(f"HTTP error during NIP-05 verification (attempt {attempt}): {e}")
                except httpx.RequestError as e:
                    logging.warning(f"Request error during NIP-05 verification (attempt {attempt}): {e}")
                except Exception as e:
                    logging.warning(f"Error during NIP-05 verification (attempt {attempt}): {e}")
                
                # If this wasn't the last attempt, sleep before retrying
                if attempt < max_retries and not verification_success:
                    await asyncio.sleep(1.0 * attempt)
            
            return verification_success
                
        except Exception as e:
            logging.error(f"Error in NIP-05 verification process: {e}", exc_info=True)
            return False

    @staticmethod
    async def verify_lud16(lud16: str) -> bool:
        """
        Base implementation for Lightning Address verification.
        Cyberherd module should override this with its implementation.
        """
        logger.warning(f"Base LUD16 verification not implemented. Use cyberherd_module.Verifier instead.")
        return False

###########################
# Base Metadata Classes
###########################
# Core metadata functionality that can be extended
class NostrMetadataFetcher:
    """Fetch and parse metadata from Nostr"""
    
    def __init__(self, cache_ttl: int = 3600):
        self.logger = logging.getLogger(__name__)
        self._cache = {}
        self._cache_timestamps = {}
        self._cache_ttl = cache_ttl
        self.subprocess_semaphore = subprocess_semaphore
    
    async def fetch_metadata(self, pubkey: str, relays: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        """
        Fetch metadata for a given pubkey with improved JSON parsing and error recovery.
        """
        if not pubkey:
            self.logger.error("Missing pubkey for metadata fetch")
            return None

        # Cache check code remains the same
        now = time.time()
        if pubkey in self._cache:
            cache_entry = self._cache[pubkey]
            if now - self._cache_timestamps[pubkey] < self._cache_ttl:
                self.logger.debug(f"Using cached metadata for {pubkey}")
                return cache_entry

        selected_relays = get_best_relays(relays)
        relay_str = " ".join(selected_relays)
        command = f"/usr/local/bin/nak req -k 0 --limit 1 --author {pubkey} {relay_str}"

        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=3.0)
            except asyncio.TimeoutError:
                self.logger.warning(f"Timeout fetching metadata for {pubkey}")
                return None

            metadata_event = stdout.decode().strip()
            if not metadata_event:
                self.logger.warning(f"No metadata found for {pubkey}")
                return None

            # New robust parsing approach
            try:
                # First try standard JSON parsing
                data = json.loads(metadata_event)
                if not isinstance(data, dict):
                    self.logger.warning(f"Metadata event is not a dictionary for {pubkey}")
                    return None

                content = data.get('content', '')
                if not content:
                    self.logger.warning(f"Empty content in metadata for {pubkey}")
                    return None

                # Clean the content string before parsing
                content = self._clean_json_string(content)
                
                try:
                    # Try parsing the cleaned content
                    metadata = json.loads(content)
                except json.JSONDecodeError as e:
                    # If standard parsing fails, try recovery parsing
                    self.logger.info(f"Standard JSON parse failed for {pubkey}, attempting recovery: {e}")
                    metadata = self._recover_json_content(content)
                    if not metadata:
                        return None

                # Validate and clean the metadata
                cleaned_metadata = self._clean_metadata(metadata)
                if cleaned_metadata:
                    # Update cache
                    self._cache[pubkey] = cleaned_metadata
                    self._cache_timestamps[pubkey] = now
                    return cleaned_metadata

            except Exception as e:
                self.logger.error(f"Error processing metadata for {pubkey}: {e}")
                return None

        except Exception as e:
            self.logger.error(f"Error fetching metadata: {e}")
            return None

    def _clean_json_string(self, content: str) -> str:
        """Clean a JSON string for more reliable parsing."""
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='ignore')
        
        # Remove null bytes and other control characters
        content = content.replace('\x00', '')
        content = ''.join(char for char in content if ord(char) >= 32 or char in '\n\r\t')
        
        # Fix common JSON formatting issues
        content = content.replace('\\n', ' ')
        content = content.replace('\\"', '"')
        
        # Try to extract the first complete JSON object if multiple exist
        try:
            # Find the first opening brace
            start = content.find('{')
            if start == -1:
                return "{}"
            
            # Track nested braces
            depth = 0
            in_string = False
            escape_next = False
            end = start
            
            for i, char in enumerate(content[start:], start):
                if escape_next:
                    escape_next = False
                    continue
                    
                if char == '\\':
                    escape_next = True
                    continue
                    
                if char == '"' and not escape_next:
                    in_string = not in_string
                    continue
                    
                if not in_string:
                    if char == '{':
                        depth += 1
                    elif char == '}':
                        depth -= 1
                        if depth == 0:
                            end = i + 1
                            break
            
            if depth == 0 and end > start:
                content = content[start:end]
            else:
                # If we couldn't find a complete object, wrap the content
                content = "{" + content.strip() + "}"
                
        except Exception as e:
            self.logger.debug(f"Error during JSON extraction: {e}")
            content = "{" + content.strip() + "}"
        
        # Ensure the content is a valid JSON object
        if not content.startswith('{'):
            content = '{' + content
        if not content.endswith('}'):
            content = content + '}'
        
        return content.strip()

    def _recover_json_content(self, content: str) -> Optional[Dict[str, Any]]:
        """Attempt to recover valid metadata from malformed JSON."""
        try:
            # First try loading just the content as-is
            try:
                cleaned = content.strip()
                if cleaned.count('{') == 1 and cleaned.count('}') == 1:
                    return json.loads(cleaned)
            except json.JSONDecodeError:
                pass
            
            # Extract JSON patterns more aggressively
            metadata = {}
            patterns = {
                'name': [r'"name"\s*:\s*"([^"]+)"', r"'name'\s*:\s*'([^']+)'"],
                'display_name': [r'"display_name"\s*:\s*"([^"]+)"', r"'display_name'\s*:\s*'([^']+)'"],
                'picture': [r'"picture"\s*:\s*"([^"]+)"', r"'picture'\s*:\s*'([^']+)'"],
                'nip05': [r'"nip05"\s*:\s*"([^"]+)"', r"'nip05'\s*:\s*'([^']+)'"],
                'lud16': [r'"lud16"\s*:\s*"([^"]+)"', r"'lud16'\s*:\s*'([^']+)'"]
            }
            
            # Try each pattern style (double and single quotes)
            for field, pattern_list in patterns.items():
                for pattern in pattern_list:
                    match = re.search(pattern, content)
                    if match:
                        metadata[field] = match.group(1)
                        break
            
            return metadata if metadata else None
            
        except Exception as e:
            self.logger.error(f"Error in JSON recovery: {e}")
            return None

    def _clean_metadata(self, metadata: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Validate and clean metadata fields."""
        if not isinstance(metadata, dict):
            return None

        cleaned = {}
        
        # Process string fields
        string_fields = ['name', 'display_name', 'picture', 'nip05', 'lud16', 'about', 'banner']
        for field in string_fields:
            if field in metadata:
                value = metadata[field]
                if isinstance(value, str):
                    cleaned[field] = value.strip()

        # Ensure we have at least a name
        if 'name' in cleaned and not cleaned.get('display_name'):
            cleaned['display_name'] = cleaned['name']
        elif 'display_name' in cleaned and not cleaned.get('name'):
            cleaned['name'] = cleaned['display_name']

        return cleaned if cleaned else None

    async def fetch_profile(self, pubkey: str, relays: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        """
        Fetch profile metadata for a given pubkey from Nostr relays.
        
        Args:
            pubkey: Public key to fetch profile metadata for
            relays: Optional list of relay URLs to query
        
        Returns:
            Dict: Profile metadata if found, None otherwise
        """
        metadata = await self.fetch_metadata(pubkey, relays)
        if not metadata:
            return None
        
        profile_fields = ["name", "display_name", "picture", "about", "website", "banner", "lud16", "nip05"]
        profile = {field: metadata.get(field) for field in profile_fields}
        
        return profile

    async def fetch_contacts(self, pubkey: str, relays: Optional[List[str]] = None) -> Optional[List[str]]:
        """
        Fetch contacts (following list) for a given pubkey from Nostr relays.
        
        Args:
            pubkey: Public key to fetch contacts for
            relays: Optional list of relay URLs to query
        
        Returns:
            List: List of pubkeys being followed, None if not found
        """
        if not pubkey:
            self.logger.error("Missing pubkey for contacts fetch")
            return None
        
        selected_relays = get_best_relays(relays)
        relay_str = " ".join(selected_relays)
        command = f"/usr/local/bin/nak req -k 3 --limit 1 --author {pubkey} {relay_str}"
        
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=3.0)
            except asyncio.TimeoutError:
                self.logger.warning(f"Timeout fetching contacts for {pubkey}")
                return None
                
            if process.returncode != 0:
                self.logger.error(f"Error fetching contacts for {pubkey}: {stderr.decode().strip()}")
                return None
                
            contacts_event = stdout.decode().strip()
            if not contacts_event:
                self.logger.warning(f"No contacts found for {pubkey}")
                return None
                
            try:
                data = json.loads(contacts_event)
                if 'tags' not in data:
                    self.logger.warning(f"Invalid contacts event for {pubkey}")
                    return None
                    
                contacts = [tag[1] for tag in data['tags'] if tag[0] == 'p']
                
                return contacts
                
            except json.JSONDecodeError:
                self.logger.warning(f"Invalid JSON in contacts event for {pubkey}")
                return None
            
        except Exception as e:
            self.logger.error(f"Error fetching contacts: {e}")
            return None

    async def fetch_relays(self, pubkey: str, relays: Optional[List[str]] = None) -> Optional[List[str]]:
        """
        Fetch relay list for a given pubkey from Nostr relays.
        
        Args:
            pubkey: Public key to fetch relay list for
            relays: Optional list of relay URLs to query
        
        Returns:
            List: List of relay URLs, None if not found
        """
        if not pubkey:
            self.logger.error("Missing pubkey for relay list fetch")
            return None
        
        selected_relays = get_best_relays(relays)
        relay_str = " ".join(selected_relays)
        command = f"/usr/local/bin/nak req -k 10002 --limit 1 --author {pubkey} {relay_str}"
        
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=3.0)
            except asyncio.TimeoutError:
                self.logger.warning(f"Timeout fetching relay list for {pubkey}")
                return None
                
            if process.returncode != 0:
                self.logger.error(f"Error fetching relay list for {pubkey}: {stderr.decode().strip()}")
                return None
                
            relay_event = stdout.decode().strip()
            if not relay_event:
                self.logger.warning(f"No relay list found for {pubkey}")
                return None
                
            try:
                data = json.loads(relay_event)
                if 'tags' not in data:
                    self.logger.warning(f"Invalid relay list event for {pubkey}")
                    return None
                    
                relays = extract_relays_from_10002_tags(data['tags'])
                
                return relays
                
            except json.JSONDecodeError:
                self.logger.warning(f"Invalid JSON in relay list event for {pubkey}")
                return None
            
        except Exception as e:
            self.logger.error(f"Error fetching relay list: {e}")
            return None

###########################
# Relay & Event Utilities
###########################

def is_ws_url(url: str) -> bool:
    """Check if a URL is a valid WebSocket URL."""
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False
        return result.scheme in ["ws", "wss"]
    except ValueError:
        return False

def create_direct_message(
    content: str,
    sender_private_key: str,
    recipient_pubkey: str,
    tags: List[List[str]] = None
) -> Dict[str, Any]:
    """
    Create an encrypted direct message as a kind 4 event.
    
    Args:
        content: Message content
        sender_private_key: Sender's private key
        recipient_pubkey: Recipient's public key
        tags: Additional tags to include
    
    Returns:
        Dict: Signed Nostr event with encrypted content
    """
    # Encrypt the content
    encrypted = encrypt_dm(content, sender_private_key, recipient_pubkey)
    
    # Initialize tags if not provided
    tags = tags or []
    
    # Add recipient tag if not already present
    recipient_tag_exists = False
    for tag in tags:
        if len(tag) >= 2 and tag[0] == 'p' and tag[1] == recipient_pubkey:
            recipient_tag_exists = True
            break
    
    if not recipient_tag_exists:
        tags.append(['p', recipient_pubkey])
    
    # Create the event
    return create_event(
        content=encrypted,
        kind=KIND_ENCRYPTED_DM,
        private_key_hex=sender_private_key,
        tags=tags
    )

def create_basic_note(
    content: str,
    private_key_hex: str,
    tags: List[List[str]] = None
) -> Dict[str, Any]:
    """
    Create a basic text note (kind 1).
    
    Args:
        content: Note content
        private_key_hex: Private key
        tags: Optional tags
    
    Returns:
        Dict: Signed Nostr event
    """
    return create_event(
        content=content,
        kind=KIND_TEXT_NOTE,
        private_key_hex=private_key_hex,
        tags=tags
    )

def create_reaction(
    reaction: str,
    event_id: str,
    event_pubkey: str,
    event_relay: Optional[str],
    private_key_hex: str
) -> Dict[str, Any]:
    """
    Create a reaction event (kind 7).
    
    Args:
        reaction: Reaction content (usually an emoji)
        event_id: ID of the event being reacted to
        event_pubkey: Public key of the event author
        event_relay: Relay where the event was seen (can be None)
        private_key_hex: Private key
    
    Returns:
        Dict: Signed Nostr event
    """
    tags = [
        ['e', event_id],
        ['p', event_pubkey]
    ]
    
    # Add relay hint if provided
    if event_relay:
        tags[0].append(event_relay)
    
    return create_event(
        content=reaction,
        kind=KIND_REACTION,
        private_key_hex=private_key_hex,
        tags=tags
    )

def create_repost(
    event_id: str,
    relay_url: str,
    note_content: str,
    private_key_hex: str
) -> Dict[str, Any]:
    """
    Create a repost event (kind 6).
    
    Args:
        event_id: ID of the event being reposted
        relay_url: URL of the relay where the event was found
        note_content: Optional comment for the repost
        private_key_hex: Private key
    
    Returns:
        Dict: Signed Nostr event
    """
    tags = [
        ['e', event_id, relay_url, 'mention']
    ]
    
    return create_event(
        content=note_content,
        kind=KIND_REPOST,
        private_key_hex=private_key_hex,
        tags=tags
    )

def validate_nostr_keys(private_key_hex: Optional[str] = None, pubkey_hex: Optional[str] = None) -> bool:
    """
    Validate Nostr keys. If both are provided, verifies they match.
    
    Args:
        private_key_hex: Optional private key to validate
        pubkey_hex: Optional public key to validate
    
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        # Validate private key if provided
        if private_key_hex:
            if not isinstance(private_key_hex, str) or len(private_key_hex) != 64:
                logger.warning("Invalid private key format")
                return False
                
            try:
                # Try to convert to bytes - will fail if not valid hex
                bytes.fromhex(private_key_hex)
            except ValueError:
                logger.warning("Private key is not valid hex")
                return False
        
        # Validate public key if provided
        if pubkey_hex:
            if not isinstance(pubkey_hex, str) or len(pubkey_hex) != 64:
                logger.warning("Invalid public key format")
                return False
                
            try:
                # Try to convert to bytes - will fail if not valid hex
                bytes.fromhex(pubkey_hex)
            except ValueError:
                logger.warning("Public key is not valid hex")
                return False
        
        # If both are provided, verify they match
        if private_key_hex and pubkey_hex:
            derived_pubkey = get_public_key(private_key_hex)
            if derived_pubkey != pubkey_hex:
                logger.warning("Private key does not match public key")
                return False
        
        return True
    except Exception as e:
        logger.error(f"Error validating Nostr keys: {e}")
        return False

def calculate_best_relay_options(relays: List[str], min_required: int = 3) -> List[str]:
    """
    Calculate the best relay options from a list of relays.
    Prioritizes secure (wss:// over ws://) and known-reliable relays.
    
    Args:
        relays: List of relay URLs
        min_required: Minimum number of relays to return
    
    Returns:
        List[str]: Selected relay URLs
    """
    if not relays:
        return []
    
    # Ensure all relays are properly formatted
    formatted_relays = []
    for relay in relays:
        if relay and isinstance(relay, str):
            # Remove spaces and ensure proper format
            cleaned_relay = relay.strip()
            if not (cleaned_relay.startswith('wss://') or cleaned_relay.startswith('ws://')):
                cleaned_relay = 'wss://' + cleaned_relay
            formatted_relays.append(cleaned_relay)
    
    # Sort relays: prioritize secure (wss) over unsecure (ws)
    secure_relays = [r for r in formatted_relays if r.startswith('wss://')]
    insecure_relays = [r for r in formatted_relays if r.startswith('ws://')]
    
    # Combine with secure first
    sorted_relays = secure_relays + insecure_relays
    
    # Return at least min_required relays or all if fewer are available
    return sorted_relays[:max(min_required, len(sorted_relays))]

# Sign event wrapper for backward compatibility
def sign_event(content: str, private_key_hex: str, public_key_hex: Optional[str] = None) -> Dict[str, Any]:
    """
    Legacy wrapper for creating a basic note.
    
    Args:
        content: Note content
        private_key_hex: Private key
        public_key_hex: Optional public key for validation
    
    Returns:
        Dict: Signed Nostr event
    """
    # Validate keys if public key provided
    if public_key_hex:
        derived_pubkey = get_public_key(private_key_hex)
        if derived_pubkey != public_key_hex:
            raise ValueError("Private key does not match public key")
    
    # Create a basic note event
    return create_basic_note(content, private_key_hex)

# Default relays to use when none are provided
DEFAULT_RELAYS = [
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://nos.lol",
    "wss://nostr.mom",
    "wss://relay.nostr.band",
    "wss://nostr.mutinywallet.com",
    "wss://relay.nostr.bg",
    "wss://purplepag.es",
]

# Additional reliable relays to try as fallback
FALLBACK_RELAYS = [
    "wss://relay.snort.social",
    "wss://eden.nostr.land",
    "wss://nostr.fmt.wiz.biz",
    "wss://relay.current.fyi",
    "wss://nostr-pub.wellorder.net"
]

# Subprocess semaphore for controlling concurrency
subprocess_semaphore = asyncio.Semaphore(5)  # Adjust the limit as needed

# Cache for NIP-05 verifications
# Structure: {nip05_pubkey_pair: {"result": bool, "timestamp": int}}
nip05_cache = {}
NIP05_CACHE_TTL = 3600  # 1 hour for successful verifications
NIP05_FAILURE_CACHE_TTL = 300  # 5 minutes for failed verifications

# Helper function to get the best relays
def get_best_relays(relays: Optional[List[str]] = None) -> List[str]:
    """Get the best 3 relays from provided list or defaults."""
    if relays and len(relays) > 0:
        # Filter out invalid relays
        valid_relays = [r for r in relays if isinstance(r, str) and r.startswith(('wss://', 'ws://'))]
        # Take up to first 3 user relays
        return valid_relays[:3] if valid_relays else DEFAULT_RELAYS[:3]
    return DEFAULT_RELAYS[:3]

async def run_subprocess(command: list, timeout: int = 30) -> subprocess.CompletedProcess:
    """
    Run a subprocess asynchronously with a timeout.
    """
    proc = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return subprocess.CompletedProcess(args=command, returncode=proc.returncode, stdout=stdout, stderr=stderr)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise subprocess.TimeoutExpired(cmd=command, timeout=timeout)

# Relay list lookup
async def lookup_relay_list(pubkey: str, relays: Optional[List[str]] = None) -> List[str]:
    """
    Look up Kind 10002 (Relay List Metadata) events for a given pubkey and extract relay URLs.
    Falls back to cached results if available.
    """
    if not pubkey:
        return DEFAULT_RELAYS

    selected_relays = get_best_relays(relays)
    relay_str = " ".join(selected_relays)
    command = f"/usr/local/bin/nak req -k 3 --limit 1 --author {pubkey} {relay_str}"
    
    try:
        # Try the nak command for kind 3 (contacts with relay metadata)
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=3.0)
        except asyncio.TimeoutError:
            logging.warning(f"Timeout looking up relay list for {pubkey}")
            return DEFAULT_RELAYS[:3]
            
        if process.returncode != 0:
            return DEFAULT_RELAYS[:3]
            
        relay_event = stdout.decode().strip()
        if not relay_event:
            return DEFAULT_RELAYS[:3]
            
        try:
            data = json.loads(relay_event)
            if 'tags' not in data:
                return DEFAULT_RELAYS[:3]
                
            # Extract relay list from tags
            user_relays = []
            for tag in data.get('tags', []):
                if len(tag) >= 2 and tag[0] == 'r':
                    relay_url = tag[1]
                    if isinstance(relay_url, str) and relay_url.startswith(('wss://', 'ws://')):
                        user_relays.append(relay_url)
                    
            # If we found relays, return them
            if user_relays:
                logging.debug(f"Found user relays for {pubkey}: {user_relays[:5]}")
                return user_relays[:5]  # Return up to 5 relays
                
        except json.JSONDecodeError:
            logging.warning(f"Invalid JSON in relay list event for {pubkey}")
        
    except Exception as e:
        logging.warning(f"Error looking up relay list: {e}")
        
    # Fallback to default relays
    return DEFAULT_RELAYS[:3]

def extract_relays_from_10002_tags(tags: list) -> list:
    """Extract relay URLs specifically from Kind 10002 event tags."""
    relays = []
    if not tags:
        return relays
        
    # For Kind 10002, each relay is in a tag starting with 'r'
    for tag in tags:
        if not tag or len(tag) < 2:
            continue
            
        if tag[0] == 'r':  # Kind 10002 uses 'r' tags for relays
            relay_url = tag[1]
            if isinstance(relay_url, str) and relay_url.startswith(('ws://', 'wss://')):
                relays.append(relay_url)
            
    return relays

# Nostr event utilities
async def generate_nprofile(pubkey: str) -> Optional[str]:
    """
    Generate an nprofile using the nak command.
    """
    nprofile_command = ['/usr/local/bin/nak', 'encode', 'nprofile', pubkey]
    async with subprocess_semaphore:
        try:
            result = await run_subprocess(nprofile_command, timeout=10)
            if result.returncode != 0:
                logging.error(f"Error generating nprofile: {result.stderr.decode().strip()}")
                return None
            return result.stdout.decode().strip()
        except asyncio.TimeoutError as e:
            logging.error(f"Timeout generating nprofile for pubkey {pubkey}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error generating nprofile: {e}")
        return None

async def check_event_tag(event_id: str, tag_name: str, relays: Optional[List[str]] = None) -> bool:
    """
    Check if the event identified by `event_id` has a specific tag.

    Args:
        event_id (str): The ID of the event to check.
        tag_name (str): The tag name to check for
        relays (Optional[List[str]]): List of relay URLs. Defaults to DEFAULT_RELAYS.

    Returns:
        bool: True if the event has the specified tag, False otherwise.
    """
    selected_relays = get_best_relays(relays)
    nak_command = ["nak", "req", "-i", event_id, *selected_relays]
    
    try:
        result = subprocess.run(nak_command, capture_output=True, text=True, check=True)
        event_data = json.loads(result.stdout)
        logging.debug(f"nak command output: {event_data}")

        # Ensure the `tags` field exists and is a list of lists
        tags = event_data.get("tags", [])
        if isinstance(tags, list) and all(isinstance(tag, list) and len(tag) >= 2 for tag in tags):
            # Check if any tag has "t" as the first element and tag_name (case insensitive) as the second
            for tag in tags:
                if tag[0] == "t" and tag[1].lower() == tag_name.lower():
                    return True

        # Log unexpected format or absence of the tag
        logging.info(f"No '{tag_name}' tag found for event_id: {event_id}")
        return False

    except subprocess.CalledProcessError as e:
        logging.error(f"Error running nak command: {e.stderr}")
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON output from nak command: {e}")
    except Exception as e:
        logging.error(f"Unexpected error while checking tag: {e}")

    return False
