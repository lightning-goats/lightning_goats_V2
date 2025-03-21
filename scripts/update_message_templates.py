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

async def update_templates():
    """Update the cyber_herd templates to support repost_context."""
    db_service = DatabaseService('sqlite:///cyberherd.db')
    await db_service.connect()
    
    try:
        # Get the current cyber_herd templates
        templates = await db_service.get_message_template('cyber_herd')
        if not templates:
            logger.error("No cyber_herd templates found in database!")
            return False
        
        # Update each template to include repost_context if not already present
        for key, template in templates.items():
            if "{repost_context}" not in template:
                updated_template = template + "{repost_context}"
                logger.info(f"Updating template {key} to include repost_context")
                await db_service.save_message_template('cyber_herd', key, updated_template)
            else:
                logger.info(f"Template {key} already has repost_context")
        
        logger.info("Templates updated successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error updating templates: {e}")
        return False
        
    finally:
        await db_service.disconnect()

if __name__ == "__main__":
    success = asyncio.run(update_templates())
    sys.exit(0 if success else 1)
