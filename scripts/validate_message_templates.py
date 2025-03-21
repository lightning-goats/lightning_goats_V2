#!/usr/bin/env python3
import asyncio
import sys
import os
import logging

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.database_service import DatabaseService

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Required template categories
REQUIRED_CATEGORIES = [
    "cyber_herd",
    "cyber_herd_info",
    "cyber_herd_treats",
    "interface_info",
    "sats_received",
    "feeder_triggered",
    "thank_you_variations"
]

async def validate_templates():
    """Check if all required template categories exist in the database."""
    db_service = DatabaseService('sqlite:///cyberherd.db')
    await db_service.connect()
    
    try:
        missing_categories = []
        empty_categories = []
        
        # Check migration status
        migration_run = await db_service.has_migration_run('message_templates_initial')
        if not migration_run:
            logger.error("Message template migration has not been run!")
            logger.error("Please run the migrate_messages_to_db.py script first.")
            return False
        
        # Check each required category
        for category in REQUIRED_CATEGORIES:
            templates = await db_service.get_message_template(category)
            if templates is None:
                missing_categories.append(category)
            elif not templates:
                empty_categories.append(category)
            else:
                logger.info(f"✓ Category '{category}' has {len(templates)} templates")
        
        if missing_categories:
            logger.error(f"Missing template categories: {', '.join(missing_categories)}")
        
        if empty_categories:
            logger.warning(f"Empty template categories: {', '.join(empty_categories)}")
        
        if not missing_categories and not empty_categories:
            logger.info("All required template categories exist and contain templates.")
            return True
        else:
            return False
            
    finally:
        await db_service.disconnect()

if __name__ == "__main__":
    success = asyncio.run(validate_templates())
    sys.exit(0 if success else 1)
