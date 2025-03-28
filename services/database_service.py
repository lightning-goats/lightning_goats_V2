import json
import time
import logging
from asyncio import Lock
from typing import Any, Optional, Dict, List, Union
from databases import Database
from sqlalchemy import Table, Column, Integer, String, Text, MetaData, Boolean, DateTime, create_engine
import datetime

logger = logging.getLogger(__name__)

class DatabaseService:
    def __init__(self, connection_string: str, min_size=5, max_size=20):
        """Initialize database service with connection pooling."""
        self.connection_string = connection_string
        
        # Check if this is SQLite (doesn't support min_size/max_size)
        if connection_string.startswith('sqlite:'):
            self.database = Database(connection_string)
        else:
            # For PostgreSQL, MySQL, etc. which support connection pooling
            self.database = Database(connection_string, min_size=min_size, max_size=max_size)
        
        self.cache = DatabaseCache(self.database)
        # Create SQLAlchemy engine for schema operations
        self.engine = create_engine(connection_string)
        self.logger = logger
        
        # Initialize metadata before creating tables
        self.metadata = MetaData()
        
        # Define migrations table
        self.migrations = Table(
            'migrations', 
            self.metadata,
            Column('id', Integer, primary_key=True),
            Column('name', String(255), nullable=False, unique=True),
            Column('applied_at', DateTime, default=datetime.datetime.utcnow),
        )
        
    async def connect(self):
        await self.database.connect()
        
    async def disconnect(self):
        await self.database.disconnect()
        
    async def initialize_tables(self):
        # Create tables using raw SQL for backward compatibility
        await self.database.execute('''
            CREATE TABLE IF NOT EXISTS cyber_herd (
                pubkey TEXT PRIMARY KEY,
                display_name TEXT,
                event_id TEXT,
                note TEXT,
                kinds TEXT,
                nprofile TEXT,
                lud16 TEXT,
                notified TEXT,
                payouts REAL,
                amount INTEGER,
                picture TEXT,
                relays TEXT,
                timestamp INTEGER DEFAULT (strftime('%s','now') * 1000)
            )
        ''')
        await self.database.execute('''
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                expires_at REAL NOT NULL
            )
        ''')
        # New message templates table
        await self.database.execute('''
            CREATE TABLE IF NOT EXISTS message_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                key INTEGER NOT NULL,
                template TEXT NOT NULL,
                active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(category, key)
            )
        ''')
        # Create migrations table using raw SQL
        await self.database.execute('''
            CREATE TABLE IF NOT EXISTS migrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Add cyberherd_reposts table
        await self.database.execute("""
            CREATE TABLE IF NOT EXISTS cyberherd_reposts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pubkey TEXT NOT NULL,
                original_note_id TEXT NOT NULL,
                reposted_at TIMESTAMP NOT NULL,
                UNIQUE(pubkey, original_note_id)
            )
        """)
        # Create index for faster lookups
        await self.database.execute("""
            CREATE INDEX IF NOT EXISTS idx_cyberherd_reposts_pubkey
            ON cyberherd_reposts(pubkey)
        """)
        # Add cyberherd_reactions table
        await self.database.execute("""
            CREATE TABLE IF NOT EXISTS cyberherd_reactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pubkey TEXT NOT NULL,
                original_note_id TEXT NOT NULL,
                reacted_at TIMESTAMP NOT NULL,
                UNIQUE(pubkey, original_note_id)
            )
        """)
        # Create index for faster lookups
        await self.database.execute("""
            CREATE INDEX IF NOT EXISTS idx_cyberherd_reactions_pubkey
            ON cyberherd_reactions(pubkey)
        """)
        # Add dm_notifications table
        await self.database.execute("""
            CREATE TABLE IF NOT EXISTS dm_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pubkey TEXT NOT NULL,
                notification_type TEXT NOT NULL,
                sent_at TIMESTAMP NOT NULL,
                UNIQUE(pubkey, notification_type)
            )
        """)
        # Create index for faster lookups
        await self.database.execute("""
            CREATE INDEX IF NOT EXISTS idx_dm_notifications_pubkey
            ON dm_notifications(pubkey)
        """)
    # Add specialized database methods for cyber_herd table operations
    async def get_cyberherd_list(self):
        """Get a list of all current CyberHerd members"""
        try:
            query = """
            SELECT * FROM cyber_herd 
            ORDER BY timestamp DESC
            """
            
            records = await self.database.fetch_all(query)
            
            # Log the number of records found for debugging
            member_count = len(records) if records else 0
            self.logger.info(f"Retrieved {member_count} CyberHerd members from database")
            
            # Convert Records to dicts for easier handling
            members = []
            for record in records:
                if hasattr(record, "_mapping"):
                    # Modern SQLAlchemy/databases Record object
                    members.append(dict(record._mapping))
                else:
                    # Fallback for different record types
                    members.append(dict(record))
            
            return members
        except Exception as e:
            self.logger.error(f"Error retrieving CyberHerd list: {e}", exc_info=True)
            return []

    async def get_cyberherd_size(self) -> int:
        query = "SELECT COUNT(*) as count FROM cyber_herd"
        result = await self.database.fetch_one(query)
        return result['count']
        
    async def get_cyberherd_member(self, pubkey: str) -> Optional[Dict[str, Any]]:
        """Get a cyber herd member by pubkey."""
        query = "SELECT * FROM cyber_herd WHERE pubkey = :pubkey"
        return await self.database.fetch_one(query, values={"pubkey": pubkey})
        
    async def get_cyberherd_member_by_lud16(self, lud16: str) -> Optional[Dict[str, Any]]:
        """Get a cyber herd member by lud16."""
        query = "SELECT * FROM cyber_herd WHERE lud16 = :lud16"
        return await self.database.fetch_one(query, values={"lud16": lud16})
        
    async def insert_cyberherd_member(self, member_data: Dict[str, Any]) -> None:
        """Insert a new cyber herd member."""
        # Ensure timestamp exists in the data
        if 'timestamp' not in member_data or not member_data['timestamp']:
            member_data['timestamp'] = int(time.time() * 1000)
            
        # Validate data types for each field to prevent SQLite binding errors
        # Ensure picture is a string
        if 'picture' in member_data:
            if member_data['picture'] is None:
                member_data['picture'] = ""
            elif not isinstance(member_data['picture'], str):
                member_data['picture'] = str(member_data['picture'])
                
        # Ensure relays is a JSON string with properly formatted URLs
        if 'relays' in member_data:
            try:
                if member_data['relays'] is None:
                    member_data['relays'] = json.dumps([])
                elif isinstance(member_data['relays'], list):
                    # Clean up URLs by removing spaces
                    cleaned_relays = [relay.strip().replace(' ', '') for relay in member_data['relays'] if relay]
                    member_data['relays'] = json.dumps(cleaned_relays)
                elif isinstance(member_data['relays'], str):
                    try:
                        # Try to parse as JSON first to handle already JSON-encoded strings
                        relays_list = json.loads(member_data['relays'])
                        if isinstance(relays_list, list):
                            cleaned_relays = [relay.strip().replace(' ', '') for relay in relays_list if relay]
                            member_data['relays'] = json.dumps(cleaned_relays)
                        else:
                            member_data['relays'] = json.dumps([])
                    except json.JSONDecodeError:
                        # If not valid JSON, use default relays
                        member_data['relays'] = json.dumps(["wss://relay.damus.io", "wss://relay.primal.net", "wss://nos.lol"])
            except Exception as e:
                self.logger.warning(f"Error processing relays: {e}, using default relays")
                member_data['relays'] = json.dumps(["wss://relay.damus.io", "wss://relay.primal.net", "wss://nos.lol"])
                
        # Ensure numeric fields are proper numbers
        if 'amount' in member_data and member_data['amount'] is not None:
            try:
                member_data['amount'] = int(member_data['amount'])
            except (ValueError, TypeError):
                member_data['amount'] = 0
                
        if 'payouts' in member_data and member_data['payouts'] is not None:
            try:
                member_data['payouts'] = float(member_data['payouts'])
            except (ValueError, TypeError):
                member_data['payouts'] = 0.0
                
        query = """
            INSERT INTO cyber_herd (
                pubkey, display_name, event_id, note, kinds, nprofile, lud16, 
                notified, payouts, amount, picture, relays, timestamp
            ) VALUES (
                :pubkey, :display_name, :event_id, :note, :kinds, :nprofile, :lud16, 
                :notified, :payouts, :amount, :picture, :relays, :timestamp
            )
        """
        await self.database.execute(query, values=member_data)
        
    async def update_cyberherd_member(self, 
                                    pubkey: str, 
                                    new_amount: float, 
                                    payout_increment: float, 
                                    updated_kinds: str,
                                    event_id: str = None,
                                    note: str = None,
                                    display_name: str = None,
                                    nprofile: str = None,
                                    lud16: str = None,
                                    picture: str = None,
                                    relays: str = None) -> None:
        """Update an existing cyber herd member."""
        query = """
            UPDATE cyber_herd
            SET amount = amount + :new_amount,
                payouts = payouts + :payout_increment,
                kinds = :updated_kinds,
                event_id = :event_id,
                note = :note,
                display_name = :display_name,
                nprofile = :nprofile,
                lud16 = :lud16,
                picture = :picture,
                relays = :relays
            WHERE pubkey = :pubkey
        """
        await self.database.execute(query, values={
            "new_amount": new_amount,
            "payout_increment": payout_increment,
            "updated_kinds": updated_kinds,
            "event_id": event_id,
            "note": note,
            "display_name": display_name,
            "nprofile": nprofile,
            "lud16": lud16,
            "picture": picture,
            "relays": relays,
            "pubkey": pubkey,
        })
        
    async def update_cyberherd_notified(self, pubkey: str, notified_value: str) -> None:
        """Update the notified field for a cyber herd member."""
        query = "UPDATE cyber_herd SET notified = :notified_value WHERE pubkey = :pubkey"
        await self.database.execute(query, values={"notified_value": notified_value, "pubkey": pubkey})
        
    async def delete_cyberherd_member_by_lud16(self, lud16: str) -> None:
        """Delete a cyber herd member by lud16."""
        query = "DELETE FROM cyber_herd WHERE lud16 = :lud16"
        await self.database.execute(query, values={"lud16": lud16})
        
    async def delete_all_cyberherd_members(self) -> None:
        """Delete all cyber herd members."""
        query = "DELETE FROM cyber_herd"
        await self.database.execute(query)
        
    async def get_cyberherd_members_with_lud16(self) -> List[Dict[str, Any]]:
        """Get all cyber herd members that have a lud16 value."""
        query = "SELECT pubkey, lud16, payouts FROM cyber_herd WHERE lud16 IS NOT NULL"
        return await self.database.fetch_all(query)
        
    # Add methods to manage message templates
    async def get_message_template(self, category: str, key: Optional[int] = None) -> Union[Dict[int, str], Optional[str]]:
        """Get message template(s) from database.
        Args:
            category: Message category (e.g., 'cyber_herd', 'treats')
            key: Optional specific template key
        Returns:
            Dictionary of templates or single template string
        """
        if key is not None:
            # Get specific template
            query = "SELECT template FROM message_templates WHERE category = :category AND key = :key AND active = TRUE"
            result = await self.database.fetch_one(query, values={"category": category, "key": key})
            return result['template'] if result else None
        else:
            # Get all templates for category
            query = "SELECT key, template FROM message_templates WHERE category = :category AND active = TRUE"
            results = await self.database.fetch_all(query, values={"category": category})
            return {row['key']: row['template'] for row in results} if results else {}
            
    async def save_message_template(self, category: str, key: int, template: str) -> bool:
        """Save or update a message template."""
        query = """
            INSERT INTO message_templates (category, key, template, updated_at)
            VALUES (:category, :key, :template, CURRENT_TIMESTAMP)
            ON CONFLICT(category, key) DO UPDATE SET
                template = :template,
                updated_at = CURRENT_TIMESTAMP
        """
        try:
            await self.database.execute(query, values={
                "category": category,
                "key": key,
                "template": template
            })
            return True
        except Exception as e:
            logger.error(f"Failed to save message template: {e}")
            return False
            
    async def has_migration_run(self, migration_name):
        """Check if a specific migration has been run."""
        try:
            query = "SELECT name FROM migrations WHERE name = :name"
            result = await self.database.fetch_one(query, values={"name": migration_name})
            return result is not None
        except Exception as e:
            self.logger.error(f"Error checking migration status: {e}")
            return False
            
    async def mark_migration_complete(self, migration_name):
        """Mark a migration as complete."""
        try:
            query = "INSERT INTO migrations (name) VALUES (:name)"
            await self.database.execute(query, values={"name": migration_name})
            return True
        except Exception as e:
            self.logger.error(f"Error marking migration as complete: {e}")
            return False
            
    async def verify_table_exists(self, table_name):
        """Verify that a table exists in the database."""
        try:
            query = f"SELECT name FROM sqlite_master WHERE type='table' AND name=:table_name"
            result = await self.database.fetch_one(query, values={"table_name": table_name})
            if not result:
                self.logger.error(f"Table '{table_name}' does not exist!")
                return False
            self.logger.info(f"Table '{table_name}' exists.")
            return True
        except Exception as e:
            self.logger.error(f"Error checking if table '{table_name}' exists: {e}")
            return False
            
    async def migrate_message_templates(self):
        """Check if message templates migration has been run.
        This no longer imports from messages.py directly.
        """
        self.logger.info("Checking message template migration status...")
        # Check if migration has already been run
        if await self.has_migration_run('message_templates_initial'):
            self.logger.info("Message template migration already completed")
            return True
        # Verify message_templates table exists before continuing
        if not await self.verify_table_exists('message_templates'):
            self.logger.error("Cannot proceed with migration: message_templates table doesn't exist")
            return False
        self.logger.warning("Message templates have not been migrated. "
                          "Please run the migrate_messages_to_db.py script to populate templates.")
        return False
        
    async def get_user_reposted_notes(self, pubkey: str) -> List[str]:
        """Get all notes reposted by a specific user."""
        try:
            query = """
                SELECT original_note_id FROM cyberherd_reposts 
                WHERE pubkey = :pubkey
            """
            # Fix: use self.database instead of self.db
            rows = await self.database.fetch_all(query, {"pubkey": pubkey})
            return [row["original_note_id"] for row in rows]
        except Exception as e:
            self.logger.error(f"Failed to get reposted notes for {pubkey}: {e}")
            return []
            
    async def track_reposted_note(self, pubkey: str, original_note_id: str) -> bool:
        """Record that a user has reposted a specific note."""
        try:
            query = """
                INSERT OR IGNORE INTO cyberherd_reposts (pubkey, original_note_id, reposted_at)
                VALUES (:pubkey, :original_note_id, :reposted_at)
            """
            # Fix: use self.database instead of self.db
            await self.database.execute(
                query, 
                {"pubkey": pubkey, "original_note_id": original_note_id, "reposted_at": datetime.datetime.now()}
            )
            return True
        except Exception as e:
            self.logger.error(f"Failed to track reposted note: {e}")
            return False
            
    async def get_user_reactions(self, pubkey: str) -> List[str]:
        """Get all notes that a specific user has reacted to."""
        try:
            query = """
                SELECT original_note_id FROM cyberherd_reactions 
                WHERE pubkey = :pubkey
            """
            rows = await self.database.fetch_all(query, {"pubkey": pubkey})
            return [row["original_note_id"] for row in rows]
        except Exception as e:
            self.logger.error(f"Failed to get reaction notes for {pubkey}: {e}")
            return []
            
    async def track_user_reaction(self, pubkey: str, original_note_id: str) -> bool:
        """Record that a user has reacted to a specific note."""
        try:
            query = """
                INSERT OR IGNORE INTO cyberherd_reactions (pubkey, original_note_id, reacted_at)
                VALUES (:pubkey, :original_note_id, :reacted_at)
            """
            await self.database.execute(
                query, 
                {
                    "pubkey": pubkey, 
                    "original_note_id": original_note_id, 
                    "reacted_at": datetime.datetime.now() 
                }
            )
            return True
        except Exception as e:
            self.logger.error(f"Failed to track user reaction: {e}")
            return False
            
    async def has_dm_been_sent(self, pubkey: str, dm_type: str, hours: int = 24) -> bool:
        """Check if a DM of a specific type has been sent to a user within the specified hours"""
        try:
            # Use a cache key to avoid frequent DB lookups
            cache_key = f"dm_sent:{pubkey}:{dm_type}"
            cached_result = await self.cache.get(cache_key)
            if cached_result is not None:
                return cached_result
                
            # Calculate the time threshold
            time_threshold = (datetime.datetime.now() - datetime.timedelta(hours=hours)).isoformat()
            
            query = """
            SELECT COUNT(*) as count FROM dm_notifications
            WHERE pubkey = :pubkey AND notification_type = :dm_type AND sent_at > :time_threshold
            """
            
            result = await self.database.fetch_one(
                query=query,
                values={"pubkey": pubkey, "dm_type": dm_type, "time_threshold": time_threshold}
            )
            
            has_been_sent = result["count"] > 0 if result else False
            
            # Cache the result for 1 hour to reduce database queries
            if has_been_sent:
                await self.cache.set(cache_key, has_been_sent, ttl=3600)
                
            return has_been_sent
        except Exception as e:
            logger.error(f"Error checking if DM has been sent: {e}")
            # Default to False if there's an error, which means we'll allow sending the DM
            return False

    async def record_dm_sent(self, pubkey: str, dm_type: str) -> None:
        """Record that a DM has been sent to a user"""
        try:
            current_time = datetime.datetime.now().isoformat()
            query = """
            INSERT INTO dm_notifications (pubkey, notification_type, sent_at)
            VALUES (:pubkey, :notification_type, :sent_at)
            """
            await self.database.execute(
                query=query,
                values={"pubkey": pubkey, "notification_type": dm_type, "sent_at": current_time}
            )
            
            # Update the cache to reflect the sent message
            cache_key = f"dm_sent:{pubkey}:{dm_type}"
            await self.cache.set(cache_key, True, ttl=86400)  # Cache for 24 hours
        except Exception as e:
            logger.error(f"Error recording DM sent: {e}")

    async def clear_old_dm_notifications(self, days: int = 7) -> int:
        """Clear DM notifications older than the specified number of days"""
        try:
            time_threshold = (datetime.datetime.now() - datetime.timedelta(days=days)).isoformat()
            
            query = """
            DELETE FROM dm_notifications WHERE sent_at < :time_threshold
            """
            
            result = await self.database.execute(
                query=query,
                values={"time_threshold": time_threshold}
            )
            
            return result
        except Exception as e:
            logger.error(f"Error clearing old DM notifications: {e}")
            return 0
            
    async def clear_old_dm_notifications(self) -> int:
        """Clear DM notifications older than today."""
        try:
            # Get today's date at midnight
            today = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            query = "DELETE FROM dm_notifications WHERE sent_at < :today"
            result = await self.database.execute(query, {"today": today})
            self.logger.info(f"Cleared {result} old DM notifications")
            return result
        except Exception as e:
            self.logger.error(f"Failed to clear old DM notifications: {e}")
            return 0
            
    async def get_dm_notifications(
        self, 
        notification_type: Optional[str] = None, 
        since: Optional[datetime.datetime] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get list of DM notifications that have been sent."""
        try:
            # Build query based on parameters
            query = """
                SELECT 
                    pubkey,
                    notification_type,
                    sent_at
                FROM dm_notifications
                WHERE 1=1
            """
            params = {}
            # Add filters if provided
            if notification_type:
                query += " AND notification_type = :notification_type"
                params["notification_type"] = notification_type
            if since:
                query += " AND sent_at >= :since"
                params["since"] = since
            # Add order by and limit
            query += " ORDER BY sent_at DESC LIMIT :limit"
            params["limit"] = limit
            # Execute query
            results = await self.database.fetch_all(query, params)
            # Convert to dict and format datetime to ISO string for JSON
            return [
                {
                    "pubkey": row["pubkey"],
                    "notification_type": row["notification_type"],
                    "sent_at": row["sent_at"].isoformat() if isinstance(row["sent_at"], datetime.datetime) else row["sent_at"]
                }
                for row in results
            ]
        except Exception as e:
            self.logger.error(f"Error retrieving DM notifications: {e}")
            raise
            
    # Add methods for batch operations

    async def batch_update_cyberherd_members(self, updates: List[Dict[str, Any]]) -> bool:
        """Perform multiple member updates in a single transaction."""
        try:
            async with self.database.transaction():
                for update in updates:
                    await self.update_cyberherd_member(**update)
            return True
        except Exception as e:
            self.logger.error(f"Batch update failed: {e}")
            return False
            
    async def add_timestamp_column_if_needed(self):
        """Add timestamp column to cyber_herd table if it doesn't exist"""
        try:
            # Check if the column exists
            query = """
                SELECT COUNT(*) as count FROM pragma_table_info('cyber_herd') 
                WHERE name='timestamp'
            """
            result = await self.database.fetch_one(query)
            
            if result and result['count'] == 0:
                # Column doesn't exist, add it
                self.logger.info("Adding timestamp column to cyber_herd table")
                await self.database.execute("""
                    ALTER TABLE cyber_herd 
                    ADD COLUMN timestamp INTEGER DEFAULT (strftime('%s','now') * 1000)
                """)
                
                # Update existing rows with current timestamp
                current_time = int(time.time() * 1000)
                await self.database.execute("""
                    UPDATE cyber_herd SET timestamp = ? WHERE timestamp IS NULL
                """, (current_time,))
                
                return True
            return False  # No changes needed
        except Exception as e:
            self.logger.error(f"Error adding timestamp column: {e}")
            return False

    async def create_l402_tables(self):
        """Create tables for L402 tokens"""
        queries = [
            """
            CREATE TABLE IF NOT EXISTS l402_tokens (
                token_id TEXT PRIMARY KEY,
                payment_hash TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                user_id TEXT,
                metadata TEXT,
                is_paid BOOLEAN NOT NULL DEFAULT 0
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_l402_payment_hash 
            ON l402_tokens(payment_hash)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_l402_user_id 
            ON l402_tokens(user_id)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_l402_resource_id 
            ON l402_tokens(resource_id)
            """
        ]
        
        for query in queries:
            await self.database.execute(query)
    
    async def store_l402_token(self, token_data):
        """Store a new L402 token"""
        metadata_json = json.dumps(token_data.get('metadata', {}))
        
        query = """
        INSERT INTO l402_tokens (
            token_id, payment_hash, resource_id, amount, 
            created_at, expires_at, user_id, metadata, is_paid
        ) VALUES (
            :token_id, :payment_hash, :resource_id, :amount,
            :created_at, :expires_at, :user_id, :metadata, :is_paid
        )
        """
        
        values = {
            'token_id': token_data['token_id'],
            'payment_hash': token_data['payment_hash'],
            'resource_id': token_data['resource_id'],
            'amount': token_data['amount'],
            'created_at': token_data['created_at'],
            'expires_at': token_data['expires_at'],
            'user_id': token_data.get('user_id'),
            'metadata': metadata_json,
            'is_paid': token_data.get('is_paid', False)
        }
        
        await self.database.execute(query, values)
        
    async def get_l402_token(self, token_id):
        """Get a single L402 token by ID"""
        query = "SELECT * FROM l402_tokens WHERE token_id = :token_id"
        row = await self.database.fetch_one(query, {'token_id': token_id})
        
        if not row:
            return None
            
        result = dict(row)
        
        # Parse the metadata JSON
        if result.get('metadata'):
            try:
                result['metadata'] = json.loads(result['metadata'])
            except:
                result['metadata'] = {}
                
        return result
    
    async def get_l402_tokens(self, filters=None):
        """Get L402 tokens matching the filters"""
        filters = filters or {}
        
        query = "SELECT * FROM l402_tokens WHERE 1=1"
        params = {}
        
        if 'user_id' in filters:
            query += " AND user_id = :user_id"
            params['user_id'] = filters['user_id']
            
        if 'resource_id' in filters:
            query += " AND resource_id = :resource_id"
            params['resource_id'] = filters['resource_id']
            
        if 'is_paid' in filters:
            query += " AND is_paid = :is_paid"
            params['is_paid'] = filters['is_paid']
            
        if 'payment_hash' in filters:
            query += " AND payment_hash = :payment_hash"
            params['payment_hash'] = filters['payment_hash']
            
        if 'expires_at_min' in filters:
            query += " AND expires_at > :expires_at_min"
            params['expires_at_min'] = filters['expires_at_min']
            
        if 'expires_at_max' in filters:
            query += " AND expires_at < :expires_at_max"
            params['expires_at_max'] = filters['expires_at_max']
            
        rows = await self.database.fetch_all(query, params)
        
        result = []
        for row in rows:
            item = dict(row)
            
            # Parse the metadata JSON
            if item.get('metadata'):
                try:
                    item['metadata'] = json.loads(item['metadata'])
                except:
                    item['metadata'] = {}
                    
            result.append(item)
            
        return result
    
    async def update_l402_token_status(self, token_id, update_data):
        """Update the status of an L402 token"""
        set_clauses = []
        params = {'token_id': token_id}
        
        for key, value in update_data.items():
            if key in ['is_paid', 'expires_at']:
                set_clauses.append(f"{key} = :{key}")
                params[key] = value
                
        if not set_clauses:
            return False
            
        query = f"""
        UPDATE l402_tokens 
        SET {', '.join(set_clauses)}
        WHERE token_id = :token_id
        """
        
        await self.database.execute(query, params)
        return True
    
    async def is_l402_payment_settled(self, payment_hash):
        """Check if a payment is already settled"""
        query = """
        SELECT is_paid FROM l402_tokens 
        WHERE payment_hash = :payment_hash
        """
        
        row = await self.database.fetch_one(query, {'payment_hash': payment_hash})
        return row and row['is_paid']

class DatabaseCache:
    def __init__(self, db):
        self.db = db
        self.lock = Lock()

    async def get(self, key, default=None):
        async with self.lock:
            query = "SELECT value, expires_at FROM cache WHERE key = :key"
            row = await self.db.fetch_one(query, values={"key": key})
            if row and row["expires_at"] > time.time():
                return json.loads(row["value"])
            return default

    async def set(self, key, value, ttl=300):
        async with self.lock:
            expires_at = time.time() + ttl
            query = """
                INSERT INTO cache (key, value, expires_at)
                VALUES (:key, :value, :expires_at)
                ON CONFLICT(key) DO UPDATE SET
                    value = :value,
                    expires_at = :expires_at
            """
            await self.db.execute(query, values={
                "key": key,
                "value": json.dumps(value),
                "expires_at": expires_at
            })

    async def cleanup(self):
        """Delete expired cache entries"""
        current_time = time.time()
        query = "DELETE FROM cache WHERE expires_at < :current_time"
        await self.db.execute(query, values={"current_time": current_time})