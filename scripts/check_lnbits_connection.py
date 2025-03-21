#!/usr/bin/env python3
import asyncio
import sys
import os
import logging
import httpx
from dotenv import load_dotenv

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def check_lnbits_connection():
    """Check LNBits connectivity and diagnose issues."""
    # Load environment variables
    load_dotenv()
    
    lnbits_url = os.getenv('LNBITS_URL')
    herd_key = os.getenv('HERD_KEY')
    
    if not lnbits_url or not herd_key:
        logger.error("Missing required environment variables LNBITS_URL or HERD_KEY")
        return False
    
    logger.info(f"Testing connection to LNBits at: {lnbits_url}")
    
    # Test 1: Basic connectivity
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Simple GET to check if service is up
            response = await client.get(f"{lnbits_url}/api/v1/health")
            if response.status_code == 200:
                logger.info("✓ Basic LNBits connectivity test passed")
            else:
                logger.error(f"✗ LNBits health check failed: {response.status_code} - {response.text}")
                return False
    except Exception as e:
        logger.error(f"✗ Could not connect to LNBits: {e}")
        return False
    
    # Test 2: API key validity
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Test wallet info endpoint which requires authentication
            response = await client.get(
                f"{lnbits_url}/api/v1/wallet",
                headers={"X-Api-Key": herd_key}
            )
            
            if response.status_code == 200:
                wallet_data = response.json()
                logger.info(f"✓ API key valid. Wallet name: {wallet_data.get('name')}, "
                           f"Balance: {wallet_data.get('balance')/1000} sats")
            else:
                logger.error(f"✗ API key invalid or wallet issue: {response.status_code} - {response.text}")
                return False
    except Exception as e:
        logger.error(f"✗ Error checking wallet info: {e}")
        return False
    
    # Test 3: Invoice creation
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Attempt to create a test invoice (we won't pay it)
            invoice_data = {
                "out": False,
                "amount": 10,
                "unit": "sat",
                "memo": "LNBits Connection Test",
                "internal": False
            }
            
            response = await client.post(
                f"{lnbits_url}/api/v1/payments",
                headers={"X-Api-Key": herd_key, "Content-Type": "application/json"},
                json=invoice_data
            )
            
            if response.status_code == 201 or response.status_code == 200:
                invoice_result = response.json()
                logger.info(f"✓ Successfully created test invoice: {invoice_result.get('payment_hash', 'No hash')}")
            else:
                logger.error(f"✗ Failed to create test invoice: {response.status_code} - {response.text}")
                return False
    except Exception as e:
        logger.error(f"✗ Error creating test invoice: {e}")
        return False
    
    logger.info("All LNBits connection tests passed successfully!")
    return True

if __name__ == "__main__":
    success = asyncio.run(check_lnbits_connection())
    sys.exit(0 if success else 1)
