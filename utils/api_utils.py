import asyncio
import json
import logging
import re
import time
import socket
from typing import Optional, Dict, Any, List, Tuple
import httpx
import subprocess
import urllib.parse
import random

from subprocess import TimeoutExpired, CompletedProcess
from utils.nostr_utils import (
    validate_pub_key, normalize_identifier, hex_to_npub, is_ws_url,
    DEFAULT_RELAYS, FALLBACK_RELAYS, get_best_relays, lookup_relay_list,
    generate_nprofile, NostrVerifier, NostrMetadataFetcher
)
from utils.cyberherd_module import check_cyberherd_tag, resolve_domain

# Logging Configuration
logger = logging.getLogger(__name__)

# Semaphore for controlling subprocess concurrency
subprocess_semaphore = asyncio.Semaphore(5)  # Adjust the limit as needed

# Cache for NIP-05 verifications
# Structure: {nip05_pubkey_pair: {"result": bool, "timestamp": int}}
nip05_cache = {}
NIP05_CACHE_TTL = 3600  # 1 hour for successful verifications
NIP05_FAILURE_CACHE_TTL = 300  # 5 minutes for failed verifications

# Cache for domain resolutions
# Structure: {domain: {"ip": str, "timestamp": int}}
dns_cache = {}
DNS_CACHE_TTL = 3600  # 1 hour

# Utility Functions
async def run_subprocess(command: list, timeout: int = 30) -> CompletedProcess:
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
        return CompletedProcess(args=command, returncode=proc.returncode, stdout=stdout, stderr=stderr)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise TimeoutExpired(cmd=command, timeout=timeout)

# For backward compatibility - delegate to NostrVerifier
class Verifier:
    @staticmethod
    async def verify_nip05(nip05: str, pubkey: str, cache=None, ttl=3600) -> bool:
        return await NostrVerifier.verify_nip05(nip05, pubkey, cache, ttl)

    @staticmethod
    async def verify_lud16(lud16: str) -> bool:
        return await NostrVerifier.verify_lud16(lud16)

# For backward compatibility - delegate to NostrMetadataFetcher
class MetadataFetcher(NostrMetadataFetcher):
    pass

async def get_user_metadata(pubkey):
    fetcher = NostrMetadataFetcher()
    metadata, relays = await fetcher.lookup_metadata_with_relays(pubkey)
    return metadata, relays