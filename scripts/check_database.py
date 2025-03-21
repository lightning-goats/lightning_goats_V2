import asyncio
import logging
import os
import sys
from sqlalchemy import inspect

# Add parent directory to path so we can import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.database_service import DatabaseService

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def check_database_schema():
    """
    Check the existing database schema and print details.
    This helps diagnose issues with table creation.
    """
    db_service = DatabaseService('sqlite:///cyberherd.db')
    await db_service.connect()
    
    try:
        # Get inspector
        connection = await db_service.engine.connect()
        inspector = await db_service.engine.run_sync(lambda conn: inspect(conn))
        
        # Get all tables
        tables = await db_service.engine.run_sync(lambda conn: inspector.get_table_names())
        
        logger.info(f"Found {len(tables)} tables in database:")
        for table_name in tables:
            logger.info(f"- {table_name}")
            
            # Get table columns
            columns = await db_service.engine.run_sync(lambda conn: inspector.get_columns(table_name))
            logger.info(f"  Columns in {table_name}:")
            for column in columns:
                logger.info(f"  - {column['name']} ({column['type']})")
            
            # Get primary key
            pk = await db_service.engine.run_sync(lambda conn: inspector.get_pk_constraint(table_name))
            logger.info(f"  Primary key: {pk['constrained_columns']}")
    
    except Exception as e:
        logger.error(f"Error inspecting database: {e}")
    
    finally:
        await db_service.disconnect()
        
    # Check if message_templates table exists
    if 'message_templates' not in tables:
        logger.warning("message_templates table is missing! You need to run initialize_tables() first.")
        logger.info("Attempting to initialize tables...")
        
        # Try to initialize tables
        await db_service.connect()
        await db_service.initialize_tables()
        await db_service.disconnect()
        
        logger.info("Tables initialization complete. Please run this script again to verify.")

if __name__ == "__main__":
    asyncio.run(check_database_schema())
