#!/usr/bin/env python3
import asyncio
import logging
import os
import sys

# Add parent directory to path so we can import from services
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.database_service import DatabaseService

logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def add_difference_templates():
    """Add difference variation templates to the database."""
    # Initialize database connection
    db_service = DatabaseService('sqlite:///cyberherd.db')
    await db_service.connect()
    
    try:
        # Check if templates already exist
        templates = await db_service.get_message_template("difference_variations")
        if templates:
            logger.info("Difference variation templates already exist:")
            for key, template in templates.items():
                logger.info(f"  {key}: {template}")
            
            response = input("Do you want to overwrite existing templates? (y/n): ").lower()
            if response != 'y':
                logger.info("Operation cancelled. No changes made.")
                return
        
        # Define the difference variation templates
        difference_templates = {
            1: "Donate {difference} sats to feed the goats!",
            2: "The goats need {difference} more sats to get fed!",
            3: "Feed our hungry goats with {difference} sats!",
            4: "Just {difference} sats away from feeding time!",
            5: "The goats are hungry! {difference} more sats to go!"
        }
        
        # Allow user to customize templates
        print("Current templates (press Enter to keep existing template):")
        for key, template in difference_templates.items():
            new_template = input(f"Template {key} [{template}]: ")
            if new_template:
                difference_templates[key] = new_template
        
        # Save templates to database
        for key, template in difference_templates.items():
            await db_service.save_message_template("difference_variations", key, template)
            logger.info(f"Added template {key}: {template}")
        
        logger.info("All difference variation templates added successfully!")
        
    except Exception as e:
        logger.error(f"Error adding templates: {e}")
    finally:
        await db_service.disconnect()

if __name__ == "__main__":
    asyncio.run(add_difference_templates())
