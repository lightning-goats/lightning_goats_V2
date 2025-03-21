#!/usr/bin/env python3
import asyncio
import logging
import os
import sys
import json
import httpx
import sqlite3

# Add parent directory to path so we can import from services
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def get_members_from_db(db_path):
    """Get members directly from database."""
    try:
        # Connect directly to the SQLite database to fetch members
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row  # This enables column access by name
        cursor = conn.cursor()
        
        # Find the cyberherd table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%cyber%herd%';")
        table_name = cursor.fetchone()
        
        if not table_name:
            logger.error("Could not find cyberherd table")
            return []
        
        table_name = table_name[0]
        logger.info(f"Found cyberherd table: {table_name}")
        
        # Check if lud16 column exists
        cursor.execute(f"PRAGMA table_info({table_name});")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]
        
        if 'lud16' not in column_names:
            logger.error(f"No lud16 column in {table_name} table")
            return []
        
        # Get members with valid lud16
        cursor.execute(f"SELECT * FROM {table_name} WHERE lud16 IS NOT NULL AND lud16 != ''")
        members = cursor.fetchall()
        
        # Convert to list of dictionaries
        result = []
        for member in members:
            member_dict = {column: member[column] for column in column_names}
            result.append(member_dict)
        
        conn.close()
        return result
    except Exception as e:
        logger.error(f"Error fetching members from database: {e}")
        return []

async def direct_update_lnbits():
    """Directly update LNbits targets using HTTP requests."""
    # Get environment variables
    lnbits_url = os.getenv('LNBITS_URL', '').strip()
    cyberherd_key = os.getenv('CYBERHERD_KEY', '').strip()
    predefined_wallet = os.getenv('PREDEFINED_WALLET_ADDRESS', '').strip()
    predefined_alias = os.getenv('PREDEFINED_WALLET_ALIAS', '').strip()
    
    if not all([lnbits_url, cyberherd_key, predefined_wallet, predefined_alias]):
        logger.error("Missing required environment variables")
        return
    
    # Database path
    db_path = input("Enter path to cyberherd.db: ")
    if not os.path.exists(db_path):
        logger.error(f"Database file not found: {db_path}")
        return
    
    # Get members from database
    members = await get_members_from_db(db_path)
    logger.info(f"Found {len(members)} members with lud16 in database")
    
    # Create HTTP client
    async with httpx.AsyncClient(http2=True) as client:
        # 1. Check if splits extension exists
        try:
            logger.info("Checking if splits extension exists...")
            headers = {"X-Api-Key": cyberherd_key}
            response = await client.get(f"{lnbits_url}/api/v1/extensions", headers=headers)
            
            if response.status_code != 200:
                logger.error(f"Failed to check extensions: {response.status_code} - {response.text}")
                return
            
            extensions = response.json()
            splits_enabled = any(ext.get("code") == "splitpayments" and ext.get("active") for ext in extensions)
            
            if not splits_enabled:
                logger.error("Splits extension not enabled on this wallet")
                return
                
            logger.info("Splits extension is enabled")
        except Exception as e:
            logger.error(f"Error checking extensions: {e}")
            return
        
        # 2. Try to get current targets
        try:
            logger.info("Fetching current targets...")
            headers = {
                "X-Api-Key": cyberherd_key,
                "Content-type": "application/json"
            }
            response = await client.get(f"{lnbits_url}/splitpayments/api/v1/targets", headers=headers)
            
            if response.status_code == 200:
                current_targets = response.json()
                logger.info(f"Current targets: {current_targets}")
            else:
                logger.warning(f"Failed to get targets: {response.status_code} - {response.text}")
                current_targets = {"targets": []}
        except Exception as e:
            logger.error(f"Error fetching targets: {e}")
            current_targets = {"targets": []}
        
        # 3. Create updated targets
        try:
            logger.info("Creating updated targets...")
            updated_targets = {"targets": []}
            
            # Add predefined wallet with 90%
            updated_targets["targets"].append({
                "wallet": predefined_wallet,
                "alias": predefined_alias,
                "percent": 90
            })
            
            # Add up to 10 members with 1% each
            max_members = 10
            members_to_add = members[:max_members]
            
            for member in members_to_add:
                updated_targets["targets"].append({
                    "wallet": member["lud16"],
                    "alias": member.get("display_name", member.get("pubkey", "Unknown")),
                    "percent": 1
                })
            
            # If we have fewer than 10 members, adjust predefined wallet
            total_percent = sum(target["percent"] for target in updated_targets["targets"])
            if total_percent != 100:
                # Find predefined wallet and adjust
                for target in updated_targets["targets"]:
                    if target["wallet"] == predefined_wallet:
                        target["percent"] += (100 - total_percent)
                        break
            
            logger.info(f"Updated targets payload: {json.dumps(updated_targets)}")
        except Exception as e:
            logger.error(f"Error creating updated targets: {e}")
            return
            
        # 4. Update targets in LNbits
        try:
            logger.info("Updating targets in LNbits...")
            headers = {
                "X-Api-Key": cyberherd_key,
                "Content-type": "application/json"
            }
            response = await client.put(
                f"{lnbits_url}/splitpayments/api/v1/targets", 
                headers=headers,
                json=updated_targets
            )
            
            if response.status_code == 200:
                logger.info("Successfully updated targets")
                result = response.json()
                logger.info(f"Response: {result}")
            else:
                logger.error(f"Failed to update targets: {response.status_code} - {response.text}")
        except Exception as e:
            logger.error(f"Error updating targets: {e}")

if __name__ == "__main__":
    asyncio.run(direct_update_lnbits())
