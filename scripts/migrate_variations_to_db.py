#!/usr/bin/env python3
import asyncio
import sys
import os
import logging

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import original variations from messages.py
try:
    from messages import variations as original_variations
    has_original_variations = True
    print(f"Successfully imported {len(original_variations)} original variations from messages.py")
except ImportError:
    has_original_variations = False
    print("Could not import original variations from messages.py")

from services.database_service import DatabaseService

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def run_migration():
    """Migrate difference variations to database."""
    logger.info("Starting difference variations migration...")
    
    # Initialize database service
    db_service = DatabaseService('sqlite:///cyberherd.db')
    await db_service.connect()
    await db_service.initialize_tables()
    
    # Check if migration has already run
    if await db_service.has_migration_run('difference_variations_migration'):
        logger.info("Difference variations migration already completed.")
        await db_service.disconnect()
        return
    
    # Define the expanded variations
    expanded_variations = {
        1: "{difference} more sats needed!",
        2: "Only {difference} more sats until the goats get treats!",
        3: "Just {difference} more sats to go until feeding time!",
        4: "The goats need {difference} more sats for treats!",
        5: "Send {difference} more sats to make the goats happy!",
        6: "{difference} sats away from triggering the goat feeder!",
        7: "The goats are bleating for {difference} more sats!",
        8: "Feed the hungry goats with {difference} more sats!",
        9: "Want to see happy goats? Just {difference} more sats!",
        10: "Goat party in {difference} more sats!",
        11: "Trigger the feeder in {difference} more sats!",
        12: "{difference} more sats until goat feeding frenzy!",
        13: "Goats are waiting for {difference} more sats...",
        14: "Almost there! Just {difference} more sats to go!",
        15: "Feed the Lightning Goats: {difference} sats remaining!"
    }
    
    # Merge original variations if available
    all_variations = expanded_variations.copy()
    
    if has_original_variations:
        # Add original variations with keys starting from 101 to avoid conflicts
        for i, (key, value) in enumerate(original_variations.items(), start=101):
            all_variations[i] = value
        logger.info(f"Added {len(original_variations)} original variations from messages.py")
    
    # Migrate variations to database
    success = True
    logger.info(f"Migrating {len(all_variations)} total difference variations...")
    
    for key, template in all_variations.items():
        try:
            result = await db_service.save_message_template("difference_variations", key, template)
            if result:
                logger.info(f"Saved variation {key}: {template}")
            else:
                logger.warning(f"Failed to save variation {key}")
                success = False
        except Exception as e:
            logger.error(f"Error saving variation {key}: {e}")
            success = False
    
    if success:
        # Mark migration as complete
        await db_service.mark_migration_complete('difference_variations_migration')
        logger.info("Difference variations migration completed successfully")
    else:
        logger.warning("Difference variations migration completed with errors")
    
    await db_service.disconnect()

if __name__ == "__main__":
    asyncio.run(run_migration())
