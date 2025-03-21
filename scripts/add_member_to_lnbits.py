#!/usr/bin/env python3
import asyncio
import logging
import os
import sys
import json

# Add parent directory to path so we can import from services
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.payment_service import PaymentService

logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def add_member_to_lnbits():
    """Add a single member to the LNbits splits targets."""
    # Initialize payment service
    payment_service = PaymentService(
        lnbits_url=os.getenv('LNBITS_URL'),
        herd_key=os.getenv('HERD_KEY'),
        cyberherd_key=os.getenv('CYBERHERD_KEY'),
        hex_key=os.getenv('HEX_KEY'),
        nos_sec=os.getenv('NOS_SEC')
    )
    
    # Create HTTP client
    import httpx
    http_client = httpx.AsyncClient(http2=True)
    
    # Initialize the payment service
    await payment_service.initialize(http_client)
    
    try:
        # Get current targets
        current_targets = await payment_service.fetch_cyberherd_targets()
        
        if not current_targets or "targets" not in current_targets:
            logger.error("Failed to fetch current targets")
            # Create a default structure with predefined wallet
            current_targets = {
                "targets": [
                    {
                        "wallet": os.getenv('PREDEFINED_WALLET_ADDRESS'),
                        "alias": os.getenv('PREDEFINED_WALLET_ALIAS'),
                        "percent": 90
                    }
                ]
            }
            logger.info("Created default targets with predefined wallet at 90%")
        
        # Display current targets
        if "targets" in current_targets:
            logger.info("Current targets:")
            for target in current_targets["targets"]:
                logger.info(f"  {target.get('wallet')}: {target.get('percent')}% - {target.get('alias')}")
        
        # Ask for member details
        lud16 = input("Enter Lightning address (lud16): ")
        if not lud16:
            logger.error("Lightning address cannot be empty")
            return
        
        # Check if member already exists in targets
        existing_targets = current_targets.get("targets", [])
        for target in existing_targets:
            if target.get("wallet") == lud16:
                logger.info(f"Member {lud16} already exists in targets with {target.get('percent')}%")
                update = input("Update this member? (y/n): ").lower()
                if update != 'y':
                    return
        
        alias = input("Enter alias (pubkey or name): ")
        if not alias:
            alias = lud16.split('@')[0]  # Use first part of lightning address as alias
        
        # For a new member, allocate 1% from the predefined wallet
        new_target = {
            "wallet": lud16,
            "alias": alias,
            "percent": 1  # Start with 1%
        }
        
        # Update targets list
        updated_targets = {"targets": []}
        predefined_wallet = os.getenv('PREDEFINED_WALLET_ADDRESS')
        predefined_found = False
        
        # Process existing targets
        for target in existing_targets:
            # If this is the predefined wallet, reduce its percent by 1
            if target.get("wallet") == predefined_wallet:
                predefined_found = True
                target["percent"] = max(1, target.get("percent", 90) - 1)  # Reduce by 1%, minimum 1%
                updated_targets["targets"].append(target)
            # Otherwise just add the target as is if it's not the member we're adding
            elif target.get("wallet") != lud16:
                updated_targets["targets"].append(target)
        
        # Add new target
        updated_targets["targets"].append(new_target)
        
        # If predefined wallet wasn't found, add it
        if not predefined_found:
            updated_targets["targets"].append({
                "wallet": predefined_wallet,
                "alias": os.getenv('PREDEFINED_WALLET_ALIAS', "Predefined"),
                "percent": 89  # 90% - 1% for the new member
            })
        
        # Verify total percent is 100%
        total_percent = sum(target.get("percent", 0) for target in updated_targets["targets"])
        if total_percent != 100:
            logger.warning(f"Total percentage is {total_percent}%, adjusting predefined wallet")
            # Find predefined wallet and adjust
            for target in updated_targets["targets"]:
                if target.get("wallet") == predefined_wallet:
                    target["percent"] += (100 - total_percent)
                    break
        
        # Show the updated targets
        logger.info("Updated targets:")
        for target in updated_targets["targets"]:
            logger.info(f"  {target.get('wallet')}: {target.get('percent')}% - {target.get('alias')}")
        
        # Ask for confirmation
        confirm = input("Confirm update? (y/n): ").lower()
        if confirm != 'y':
            logger.info("Operation canceled")
            return
        
        # Update targets in LNbits
        result = await payment_service.update_cyberherd_targets(updated_targets)
        if result:
            logger.info("Successfully updated LNbits targets")
        else:
            logger.error("Failed to update LNbits targets")
        
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
    finally:
        await http_client.aclose()
        await payment_service.close()

if __name__ == "__main__":
    asyncio.run(add_member_to_lnbits())
