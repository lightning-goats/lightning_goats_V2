import base64
import hashlib
import logging
import json
import uuid
import time # Import time for expiry validation
from datetime import datetime, timedelta, timezone # Use timezone-aware datetime
from typing import Dict, Any, Optional, Tuple, List
from pymacaroons import Macaroon, Verifier

logger = logging.getLogger(__name__)

# --- LSAT Standard Components ---

def create_token_id() -> str:
    """Generate a unique identifier for an LSAT token."""
    return str(uuid.uuid4())

def create_lsat_macaroon(token_id: str, resource_id: str, expires_at_ts: int,
                         root_key_bytes: bytes, user_id: Optional[str] = None,
                         version: int = 1,
                         custom_caveats: Optional[Dict[str, Any]] = None) -> Macaroon:
    """
    Create a standard LSAT macaroon with common caveats.

    Args:
        token_id: Unique ID for this token (becomes macaroon identifier).
        resource_id: Identifier of the resource(s) this token grants access to.
        expires_at_ts: Unix timestamp (integer seconds since epoch) when the token expires.
        root_key_bytes: The root secret key (bytes) for signing.
        user_id: Optional user identifier.
        version: LSAT version number (default 1).
        custom_caveats: Optional dictionary for additional first-party caveats (key=value).

    Returns:
        A pymacaroons.Macaroon object.
    """
    if not isinstance(token_id, str) or not token_id:
         raise ValueError("token_id must be a non-empty string")
    if not isinstance(root_key_bytes, bytes) or len(root_key_bytes) != 32:
        raise ValueError("root_key_bytes must be 32 bytes")
    if not isinstance(expires_at_ts, int) or expires_at_ts <= 0:
         raise ValueError("expires_at_ts must be a positive integer timestamp")

    macaroon = Macaroon(
        location="lightning-goats.com".encode('utf-8'), # Use your service domain/name
        identifier=token_id.encode('utf-8'), # Use token_id as the unique identifier
        key=root_key_bytes
    )

    # --- Standard LSAT Caveats ---
    # Version Caveat (Recommended)
    macaroon.add_first_party_caveat(f"version = {version}".encode('utf-8'))

    # Expiration Caveat (Crucial) - Store as Unix timestamp string
    macaroon.add_first_party_caveat(f"expires_at = {expires_at_ts}".encode('utf-8'))

    # Resource/Service Caveat (Important for scoping)
    macaroon.add_first_party_caveat(f"resource_id = {resource_id}".encode('utf-8'))

    # User ID Caveat (Optional but common)
    if user_id:
        macaroon.add_first_party_caveat(f"user_id = {user_id}".encode('utf-8'))

    # --- Custom Caveats ---
    if custom_caveats:
        for key, value in custom_caveats.items():
            # Basic sanitization/validation
            if isinstance(key, str) and key and isinstance(value, (str, int, float, bool)):
                 # Ensure value is stringified for the caveat
                 value_str = str(value)
                 # Avoid adding overly long caveats
                 if len(key) < 50 and len(value_str) < 100:
                      # Exclude keys already handled or sensitive internal ones
                      if key not in ['version', 'expires_at', 'resource_id', 'user_id', 'payment_hash', 'internal_flag']:
                         try:
                             caveat_str = f"{key} = {value_str}"
                             macaroon.add_first_party_caveat(caveat_str.encode('utf-8'))
                         except Exception as e:
                             logger.warning(f"Failed to add custom caveat '{key}={value_str}': {e}")
                 else:
                      logger.warning(f"Skipping long custom caveat: key='{key}', value='{value_str[:50]}...'")
            else:
                 logger.warning(f"Skipping invalid custom caveat type: key={key}, value type={type(value)}")

    return macaroon

def create_challenge_header(payment_request: str, macaroon: Macaroon) -> str:
    """
    Format the WWW-Authenticate header value for a 402 Payment Required response.

    Args:
        payment_request: The BOLT11 Lightning invoice string.
        macaroon: The initial macaroon (without preimage).

    Returns:
        The formatted WWW-Authenticate header string.
    """
    macaroon_b64 = format_macaroon_for_header(macaroon)
    # Ensure invoice doesn't contain quotes that break the header
    safe_invoice = payment_request.replace('"', "'")
    return f'LSAT macaroon="{macaroon_b64}", invoice="{safe_invoice}"'

def decode_lsat_header(auth_header: str) -> Tuple[Optional[Macaroon], Optional[str]]:
    """
    Parse the Authorization header for LSAT (LSAT macaroon_b64:preimage).

    Args:
        auth_header: The full Authorization header string.

    Returns:
        Tuple (Macaroon object, preimage string) or (None, None) if invalid.
    """
    if not auth_header or not auth_header.startswith('LSAT '):
        logger.debug("Invalid LSAT header: Does not start with 'LSAT '")
        return None, None

    token_part = auth_header[5:] # Remove 'LSAT ' prefix
    parts = token_part.split(':')

    if len(parts) != 2:
        logger.debug(f"Invalid LSAT header format: Expected 2 parts separated by ':', found {len(parts)}")
        return None, None

    macaroon_b64, preimage_hex = parts

    if not macaroon_b64 or not preimage_hex:
        logger.debug("Invalid LSAT header: Empty macaroon or preimage part.")
        return None, None

    # Validate preimage format (should be 64 hex chars)
    if len(preimage_hex) != 64 or not all(c in '0123456789abcdefABCDEF' for c in preimage_hex):
        logger.debug(f"Invalid LSAT header: Preimage part is not 64 hex characters: '{preimage_hex[:10]}...'")
        return None, None

    try:
        macaroon_bytes = base64.urlsafe_b64decode(macaroon_b64) # Use urlsafe variant if needed
        macaroon = Macaroon.deserialize(macaroon_bytes)
        return macaroon, preimage_hex
    except (base64.binascii.Error, ValueError, Exception) as e: # Catch specific exceptions
        logger.warning(f"Failed to decode/deserialize macaroon from LSAT header: {e}")
        return None, None

def verify_lsat_preimage(payment_hash: str, preimage_hex: str) -> bool:
    """
    Cryptographically verify if a preimage matches a payment hash (SHA256).

    Args:
        payment_hash: The expected payment hash (64 hex chars).
        preimage_hex: The provided preimage (64 hex chars).

    Returns:
        True if sha256(bytes.fromhex(preimage_hex)) == payment_hash, False otherwise.
    """
    if not payment_hash or len(payment_hash) != 64 or \
       not preimage_hex or len(preimage_hex) != 64:
        logger.debug("Invalid input for preimage verification (length != 64).")
        return False
    try:
        preimage_bytes = bytes.fromhex(preimage_hex)
        computed_hash = hashlib.sha256(preimage_bytes).hexdigest()
        is_valid = computed_hash == payment_hash.lower() # Compare lowercase
        if not is_valid:
            logger.debug(f"Preimage verification failed: computed {computed_hash[:10]} != expected {payment_hash[:10]}")
        return is_valid
    except ValueError:
        logger.warning(f"Invalid hex string provided for preimage verification: '{preimage_hex[:10]}...'")
        return False
    except Exception as e:
        logger.error(f"Error during preimage verification: {e}", exc_info=True)
        return False

# --- Helper Utilities ---

def format_macaroon_for_header(macaroon: Macaroon) -> str:
    """Serialize and Base64 encode a macaroon for use in headers."""
    try:
        serialized = macaroon.serialize()
        # Ensure bytes before encoding
        if isinstance(serialized, str):
            serialized = serialized.encode('utf-8')
        # Use urlsafe encoding for headers? Standard base64 usually works.
        return base64.urlsafe_b64encode(serialized).decode('utf-8')
    except Exception as e:
        logger.error(f"Failed to format macaroon for header: {e}")
        return "" # Return empty string on error

def get_payment_hash_from_invoice(invoice: str) -> Optional[str]:
    """Extract payment hash from BOLT11 invoice using simple regex (fallback)."""
    if not invoice or not invoice.startswith("lnbc"):
        return None
    try:
        import re
        # Regex for 64 hex characters, often preceded by 'payment_hash=' or within payment details
        # This is a basic guess, a proper BOLT11 decoder is preferred.
        # Look for '1' followed by 64 hex chars (common structure part)
        match = re.search(r'1([0-9a-fA-F]{64})', invoice)
        if match:
            return match.group(1)
        # Broader search if the above fails
        match = re.search(r'([0-9a-fA-F]{64})', invoice)
        if match:
             return match.group(1)
        return None
    except Exception as e:
        logger.error(f"Error extracting payment hash via regex: {e}")
        return None

def validate_token_expiry_ts(expiry_timestamp: int) -> bool:
    """Check if an expiry timestamp (Unix seconds) is in the future."""
    try:
        return int(time.time()) < expiry_timestamp
    except (TypeError, ValueError):
        return False # Invalid timestamp format

# --- Deprecated/Alternative Utilities (Kept for reference/compatibility if needed) ---

def extract_macaroon_caveats(macaroon: Macaroon) -> Dict[str, str]:
    """Extract all first-party caveats into a dictionary."""
    caveats = {}
    try:
        for caveat in macaroon.first_party_caveats:
            caveat_str = caveat.caveat_id.decode('utf-8')
            parts = caveat_str.split(' = ', 1)
            if len(parts) == 2:
                caveats[parts[0].strip()] = parts[1].strip()
    except Exception as e:
         logger.error(f"Error extracting caveats: {e}")
    return caveats

def verify_macaroon_signature_with_caveats(macaroon: Macaroon, secret_key_bytes: bytes, expected_caveats: Dict[str, str]) -> bool:
    """Verify macaroon signature AND specific exact caveats (less flexible)."""
    try:
        verifier = Verifier()
        for key, value in expected_caveats.items():
             verifier.satisfy_exact(f"{key} = {value}".encode('utf-8'))
        return verifier.verify(macaroon, secret_key_bytes)
    except Exception as e:
        logger.error(f"Macaroon verification with exact caveats failed: {e}")
        return False

def extract_token_id_from_macaroon(macaroon: Macaroon) -> Optional[str]:
    """Extract the identifier from the macaroon."""
    if not macaroon: return None
    try:
        identifier = macaroon.identifier
        return identifier.decode('utf-8') if isinstance(identifier, bytes) else str(identifier)
    except Exception as e:
        logger.error(f"Failed to extract token ID (identifier) from macaroon: {e}")
        return None

# (Keep other potentially useful helpers like parse_challenge_header, extract_auth_header_from_request if needed)