import asyncio
import os
import sys
import logging

# Add parent directory to path so we can import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import messages first for the migration
from messages import (
    cyber_herd_dict,
    cyber_herd_info_dict,
    cyber_herd_treats_dict,
    interface_info_dict,
    thank_you_variations,
    sats_received_dict,
    feeder_trigger_dict
)

from services.database_service import DatabaseService

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def run_migration():
    """
    Migrate message templates from Python dictionaries to database.
    """
    logger.info("Starting message migration...")
    
    # Initialize database service
    db_service = DatabaseService('sqlite:///cyberherd.db')
    await db_service.connect()
    await db_service.initialize_tables()
    
    # Check if migration has already run
    if await db_service.has_migration_run('message_templates_initial'):
        logger.info("Message template migration already completed.")
        await db_service.disconnect()
        return
    
    # Verify message_templates table exists
    if not await db_service.verify_table_exists('message_templates'):
        logger.error("Cannot proceed with migration: message_templates table doesn't exist")
        await db_service.disconnect()
        return
    
    # Migration map: (source_dict, category_name)
    migrations = [
        (cyber_herd_dict, "cyber_herd"),
        (cyber_herd_info_dict, "cyber_herd_info"),
        (cyber_herd_treats_dict, "cyber_herd_treats"),
        (interface_info_dict, "interface_info"),
        (sats_received_dict, "sats_received"),
        (feeder_trigger_dict, "feeder_triggered")
    ]
    
    # Migrate dictionaries
    success = True
    for source_dict, category in migrations:
        logger.info(f"Migrating {category}...")
        for key, template in source_dict.items():
            try:
                result = await db_service.save_message_template(category, int(key), template)
                if result:
                    logger.info(f"Saved template {category}:{key}")
                else:
                    logger.warning(f"Failed to save template {category}:{key}")
                    success = False
            except Exception as e:
                logger.error(f"Error saving template {category}:{key}: {e}")
                success = False
    
    # Migrate thank you variations (special case - list)
    logger.info("Migrating thank you variations...")
    for i, template in enumerate(thank_you_variations):
        try:
            result = await db_service.save_message_template("thank_you_variations", i, template)
            if result:
                logger.info(f"Saved thank you variation {i}")
            else:
                logger.warning(f"Failed to save thank you variation {i}")
                success = False
        except Exception as e:
            logger.error(f"Error saving thank you variation {i}: {e}")
            success = False
    
    if success:
        # Mark migration as complete
        await db_service.mark_migration_complete('message_templates_initial')
        logger.info("Message template migration completed successfully")
    else:
        logger.warning("Message template migration completed with errors")
    
    await db_service.disconnect()

if __name__ == "__main__":
    asyncio.run(run_migration())
