#!/usr/bin/env python3
import asyncio
import logging
import os
import sys
import sqlite3

# Add parent directory to path so we can import from services
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.database_service import DatabaseService
from services.payment_service import PaymentService
from services.cyberherd_service import CyberHerdService

logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def check_db_schema(db_path):
    """Check database schema and tables."""
    try:
        # Connect directly to the SQLite database to inspect schema
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # List all tables in the database
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        table_names = [table[0] for table in tables]
        logger.info(f"Found tables in database: {table_names}")
        
        # Check if cyberherd table exists (could be named differently)
        cyberherd_table = None
        for table in table_names:
            if 'cyber' in table.lower() and 'herd' in table.lower():
                cyberherd_table = table
                break
        
        if not cyberherd_table:
            logger.error("No cyberherd-like table found in the database")
            return False
        
        logger.info(f"Found cyberherd table: {cyberherd_table}")
        
        # Check table structure
        cursor.execute(f"PRAGMA table_info({cyberherd_table});")
        columns = cursor.fetchall()
        logger.info(f"Table structure for {cyberherd_table}:")
        for column in columns:
            logger.info(f"  {column[1]}: {column[2]}")
        
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error checking database schema: {e}")
        return False

async def validate_environment_vars():
    """Validate required environment variables are set properly."""
    required_vars = [
        'LNBITS_URL', 
        'HERD_KEY', 
        'CYBERHERD_KEY', 
        'HEX_KEY', 
        'NOS_SEC',
        'PREDEFINED_WALLET_ADDRESS',
        'PREDEFINED_WALLET_ALIAS'
    ]
    
    missing_vars = []
    empty_vars = []
    
    for var in required_vars:
        if var not in os.environ:
            missing_vars.append(var)
        elif os.environ.get(var) is None or os.environ.get(var).strip() == '':
            empty_vars.append(var)
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
        return False
    
    if empty_vars:
        logger.error(f"These environment variables are empty: {', '.join(empty_vars)}")
        return False
    
    logger.info("All required environment variables are set")
    return True

async def fix_lnbits_targets():
    """Fix LNbits targets by re-syncing from the database."""
    # First validate environment variables
    if not await validate_environment_vars():
        logger.error("Environment validation failed. Please set all required variables.")
        return
    
    # Database file path
    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'cyberherd.db')
    logger.info(f"Using database at: {db_path}")
    
    # Check if database file exists
    if not os.path.exists(db_path):
        logger.error(f"Database file not found: {db_path}")
        logger.info("Current directory: " + os.getcwd())
        db_path = input("Enter the correct path to the database file: ")
        if not os.path.exists(db_path):
            logger.error(f"Database file still not found: {db_path}")
            return
    
    # Check database schema
    schema_ok = await check_db_schema(db_path)
    if not schema_ok:
        logger.warning("Database schema check failed - proceeding with caution")
    
    # Initialize database service
    db_service = DatabaseService(f'sqlite:///{db_path}')
    await db_service.connect()
    
    # Get and validate API keys
    lnbits_url = os.getenv('LNBITS_URL', '').strip()
    herd_key = os.getenv('HERD_KEY', '').strip()
    cyberherd_key = os.getenv('CYBERHERD_KEY', '').strip()
    hex_key = os.getenv('HEX_KEY', '').strip()
    nos_sec = os.getenv('NOS_SEC', '').strip()
    
    if not all([lnbits_url, herd_key, cyberherd_key, hex_key, nos_sec]):
        logger.error("One or more required API keys are empty")
        return
    
    logger.info(f"Using LNbits URL: {lnbits_url}")
    
    # Initialize payment service
    payment_service = PaymentService(
        lnbits_url=lnbits_url,
        herd_key=herd_key,
        cyberherd_key=cyberherd_key,
        hex_key=hex_key,
        nos_sec=nos_sec
    )
    
    # Since this is a script, we don't need to do full init
    # but we need to create an HTTP client for the payment service
    import httpx
    http_client = httpx.AsyncClient(http2=True)
    
    # Initialize the payment service with the HTTP client
    await payment_service.initialize(http_client)
    
    # Create CyberHerd service with minimal dependencies
    cyberherd_service = CyberHerdService(
        database_service=db_service,
        payment_service=payment_service,
        messaging_service=None,
        predefined_wallet_address=os.getenv('PREDEFINED_WALLET_ADDRESS'),
        predefined_wallet_alias=os.getenv('PREDEFINED_WALLET_ALIAS'),
        predefined_wallet_reset_percent=int(os.getenv('PREDEFINED_WALLET_PERCENT_RESET', '90'))
    )
    
    try:
        # Initialize database tables if needed
        try:
            # Check if we need to initialize tables
            if hasattr(db_service, 'initialize_tables'):
                logger.info("Initializing database tables...")
                await db_service.initialize_tables()
        except Exception as e:
            logger.warning(f"Failed to initialize tables: {e}")
        
        # Get all members with lud16
        try:
            members = await db_service.get_cyberherd_members_with_lud16()
            logger.info(f"Found {len(members)} members with lud16 in database")
            
            # Log first few members for verification
            for i, member in enumerate(members[:3]):
                logger.info(f"Member {i+1}: lud16={member.get('lud16')}, pubkey={member.get('pubkey')}")
        except Exception as e:
            logger.error(f"Failed to get members: {e}")
            logger.info("Attempting manual query to get members...")
            
            # Try direct query as fallback
            try:
                # First check table name
                tables = await db_service.database.fetch_all(
                    "SELECT name FROM sqlite_master WHERE type='table';"
                )
                table_names = [t[0] for t in tables]
                logger.info(f"Available tables: {table_names}")
                
                # Find the cyberherd table
                found_table = None
                for table_name in table_names:
                    if 'cyber' in table_name.lower() and 'herd' in table_name.lower():
                        found_table = table_name
                        break
                
                if found_table:
                    logger.info(f"Using table name: {found_table}")
                    
                    # Check columns to see if we have lud16
                    columns = await db_service.database.fetch_all(
                        f"PRAGMA table_info({found_table})"
                    )
                    column_names = [col[1] for col in columns]
                    logger.info(f"Table columns: {column_names}")
                    
                    if 'lud16' in column_names:
                        members = await db_service.database.fetch_all(
                            f"SELECT * FROM {found_table} WHERE lud16 IS NOT NULL AND lud16 != ''"
                        )
                        logger.info(f"Found {len(members)} members with direct query")
                    else:
                        logger.error(f"No lud16 column found in table {found_table}")
                        return
                else:
                    logger.error("Could not find cyberherd table")
                    return
            except Exception as query_error:
                logger.error(f"Manual query failed: {query_error}")
                return
        
        # Get current targets from LNbits
        try:
            logger.info("Fetching current targets from LNbits...")
            current_targets = await payment_service.fetch_cyberherd_targets()
            if current_targets and "targets" in current_targets:
                current_wallets = [t["wallet"] for t in current_targets["targets"]]
                logger.info(f"Current LNbits targets: {current_wallets}")
            else:
                logger.warning("No current targets found in LNbits, will create from scratch")
                current_targets = {"targets": []}
        except Exception as e:
            logger.error(f"Error fetching current targets: {e}")
            logger.warning("Will create targets from scratch")
            current_targets = {"targets": []}
        
        # Ask for confirmation
        response = input("Are you sure you want to update the LNbits targets? (y/n): ").lower()
        if response != 'y':
            logger.info("Operation canceled")
            return
        
        # Create targets manually from database records
        manual_targets = []
        
        # Add predefined wallet
        predefined_wallet = {
            'wallet': os.getenv('PREDEFINED_WALLET_ADDRESS'),
            'alias': os.getenv('PREDEFINED_WALLET_ALIAS'),
            'percent': 90
        }
        manual_targets.append(predefined_wallet)
        
        # Process members and calculate percentages
        remaining_percent = 10  # 10% for members
        member_percent = 1  # minimum 1% per member
        
        # Limit to 10 members max (10% / 1%)
        members_to_add = members[:10] if len(members) > 10 else members
        
        # If we have fewer than 10 members, distribute evenly
        if len(members_to_add) > 0:
            per_member = min(remaining_percent // len(members_to_add), 10)
            if per_member < 1:
                per_member = 1
        
        # Add members
        for member in members_to_add:
            lud16 = member.get('lud16')
            if lud16:
                target = {
                    'wallet': lud16,
                    'alias': member.get('display_name', member.get('pubkey', 'Unknown')),
                    'percent': per_member
                }
                manual_targets.append(target)
                logger.info(f"Adding target: {lud16} with {per_member}%")
        
        # Calculate total percent and adjust if needed
        total_percent = sum(target['percent'] for target in manual_targets)
        logger.info(f"Total percentage: {total_percent}%")
        
        if total_percent != 100:
            # Adjust predefined wallet to make total 100%
            adjustment = 100 - total_percent
            predefined_wallet['percent'] += adjustment
            logger.info(f"Adjusted predefined wallet to {predefined_wallet['percent']}%")
        
        # Build targets payload
        targets_payload = {"targets": manual_targets}
        
        # Update targets in LNbits
        try:
            logger.info("Updating LNbits targets...")
            result = await payment_service.update_cyberherd_targets(targets_payload)
            if result:
                logger.info("Successfully updated LNbits targets")
            else:
                logger.error("Failed to update LNbits targets: No response from API")
        except Exception as e:
            logger.error(f"Error updating LNbits targets: {e}")
            return
            
        # Get updated targets to verify
        try:
            updated_targets = await payment_service.fetch_cyberherd_targets()
            if updated_targets and "targets" in updated_targets:
                updated_wallets = [t["wallet"] for t in updated_targets["targets"]]
                logger.info(f"Updated LNbits targets: {updated_wallets}")
                
                # Check if specific members are in the targets
                check_members = input("Enter Lightning addresses to check (comma separated): ")
                if check_members:
                    members_to_check = [m.strip() for m in check_members.split(",")]
                    for member in members_to_check:
                        if member in updated_wallets:
                            logger.info(f"✅ Member {member} found in LNbits targets")
                        else:
                            logger.warning(f"❌ Member {member} NOT found in LNbits targets!")
            else:
                logger.warning("Failed to fetch updated targets for verification")
        except Exception as e:
            logger.error(f"Error verifying targets: {e}")
        
    except Exception as e:
        logger.error(f"Error fixing LNbits targets: {e}", exc_info=True)
    finally:
        # Clean up
        await db_service.disconnect()
        await http_client.aclose()
        await payment_service.close()

if __name__ == "__main__":
    asyncio.run(fix_lnbits_targets())
