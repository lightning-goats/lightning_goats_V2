import os
import logging
import asyncio
import json  # Added for JSON handling
import datetime  # Added for datetime operations
from datetime import datetime, timedelta
import time
from threading import Lock
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, Request, HTTPException, WebSocket
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

# Import all service classes
from services.database_service import DatabaseService
from services.cyberherd_service import CyberHerdService
from services.payment_service import PaymentService
from services.messaging_service import MessagingService
from services.message_template_service import MessageTemplateService
from services.goat_service import GoatStateService
from services.price_service import PriceService
from services.payment_processor_service import PaymentProcessorService
from services.cyberherd_listener_service import CyberherdListenerService
from services.cyberherd_payment_listener_service import CyberherdPaymentListenerService  # Added
from services.openhab_service import OpenHABService  # Added missing import
from services.websocket_manager import WebSocketManager

from routers import payment_routes, cyberherd_routes, goat_routes, messaging_routes, health_routes
from routers.websocket_routes import register_websocket_routes

from utils.cyberherd_module import MetadataFetcher, Verifier, generate_nprofile, check_cyberherd_tag, DEFAULT_RELAYS
from utils.nostr_utils import sign_event, sign_zap_event  # Updated import path
from utils.env_utils import load_env_vars, get_env_int, get_env_bool
from utils.http_utils import create_http_client, http_retry

# Import models module for data classes
from models import CyberHerdData  # Added for model access

# Configuration and Constants
MAX_HERD_SIZE = get_env_int('MAX_HERD_SIZE', 10)
PREDEFINED_WALLET_PERCENT_RESET = get_env_int('PREDEFINED_WALLET_PERCENT_RESET', 100)
TRIGGER_AMOUNT_SATS = get_env_int('TRIGGER_AMOUNT_SATS', 1250)
DEBUG_MODE = get_env_bool('DEBUG_MODE', False)
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

required_env_vars = [
    'OH_AUTH_1', 'HERD_KEY', 'SAT_KEY', 'NOS_SEC', 'HEX_KEY', 
    'CYBERHERD_KEY', 'LNBITS_URL', 'OPENHAB_URL', 'HERD_WEBSOCKET', 
    'PREDEFINED_WALLET_ADDRESS', 'PREDEFINED_WALLET_ALIAS'
]

optional_env_vars = [
    'MAX_HERD_SIZE', 'PREDEFINED_WALLET_PERCENT_RESET', 'TRIGGER_AMOUNT_SATS',
    'DEBUG_MODE', 'LOG_LEVEL', 'DAILY_RESET_HOUR', 'RETRY_MAX_ATTEMPTS', 'CACHE_TTL'
]

config = load_env_vars(required_env_vars, optional_env_vars)

# Logging Configuration
logging_level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
logging.basicConfig(
    level=logging_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# FastAPI app setup
app = FastAPI()

# App state management
class AppState:
    def __init__(self):
        self.balance: int = 0
        self.lock = Lock()

app_state = AppState()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Retry configurations
http_retry = retry(
    reraise=True,
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=4, max=10),
    retry=retry_if_exception_type(httpx.RequestError)
)

# Initialize service instances
database_service = DatabaseService('sqlite:///cyberherd.db')
http_client = None
messaging_service = None
message_template_service = None
openhab_service = None
payment_service = None
cyberherd_service = None
goat_service = None
price_service = None
payment_processor_service = None
cyberherd_listener_service = None
cyberherd_payment_listener_service = None

class PaymentWebSocketManager(WebSocketManager):
    """Custom WebSocketManager that processes payment data for our application"""
    
    async def process_payment_data(self, payment_data):
        """Implementation of the abstract method to handle our specific payment data"""
        if not payment_processor_service:
            logger.warning("Payment processor service not initialized yet")
            return
            
        try:
            await payment_processor_service.process_payment(payment_data)
        except Exception as e:
            logger.error(f"Error processing payment data: {e}")

# Create the WebSocket manager instance
websocket_manager = PaymentWebSocketManager(
    uri=config['HERD_WEBSOCKET'],
    logger=logger,
    max_retries=5
)

async def handle_cyberherd_webhook(data: Dict[str, Any]):
    """Direct handler for CyberHerd data that bypasses HTTP"""
    if not cyberherd_service:
        logger.warning("CyberHerd service not initialized yet")
        return False
    
    try:
        # Process a single event
        from models import CyberHerdData
        cyberherd_item = CyberHerdData(**data)
        result = await cyberherd_service.update_cyberherd([cyberherd_item])
        return result["status"] == "success"
    except Exception as e:
        logger.error(f"Error processing webhook data directly: {e}")
        return False

async def handle_cyberherd_treats(data: Dict[str, Any]):
    """Direct handler for cyberherd treats payments - delegates to service"""
    if not cyberherd_service:
        logger.warning("CyberHerd service not initialized yet")
        return False
    
    try:
        return await cyberherd_service.process_treats_payment(data)
    except Exception as e:
        logger.error(f"Error handling cyberherd treats: {e}")
        logger.error(f"Received data: {data}")
        return False

@app.on_event("startup")
async def startup():
    # Initialize HTTP client and services
    global http_client, messaging_service, openhab_service, payment_service
    global cyberherd_service, goat_service, price_service, payment_processor_service
    global message_template_service, cyberherd_listener_service, cyberherd_payment_listener_service
    
    # Initialize shared HTTP client
    http_client = await create_http_client(http2=True)

    # Connect to database and initialize tables early - BEFORE other services
    await database_service.connect()
    await database_service.initialize_tables() 
    
    # Initialize message template service
    message_template_service = MessageTemplateService(database_service)
    
    # Initialize messaging service with message template service and database service
    messaging_service = MessagingService(
        private_key=config['NOS_SEC'],
        default_relays=DEFAULT_RELAYS,
        message_template_service=message_template_service,
        database_service=database_service  # Pass database_service to messaging_service
    )
    
    # Initialize default templates if needed
    await message_template_service.initialize_default_templates()

    # Initialize OpenHAB service
    openhab_service = OpenHABService(
        openhab_url=config["OPENHAB_URL"],
        auth=(config['OH_AUTH_1'], ''),
        http_client=http_client
    )
    await openhab_service.initialize(http_client)

    # Initialize payment service
    payment_service = PaymentService(
        lnbits_url=config['LNBITS_URL'],
        herd_key=config['HERD_KEY'],
        cyberherd_key=config['CYBERHERD_KEY'],
        hex_key=config['HEX_KEY'],
        nos_sec=config['NOS_SEC']
    )
    await payment_service.initialize(http_client, sign_zap_event)

    # Initialize goat state service
    goat_service = GoatStateService(
        openhab_service=openhab_service,
        cache=database_service.cache
    )
    
    # Initialize price service
    price_service = PriceService(
        openhab_url=config["OPENHAB_URL"],
        auth_credentials=(config['OH_AUTH_1'], ''),
        http_client=http_client
    )
    await price_service.initialize(http_client)

    # Initialize CyberHerd service - after database is connected
    cyberherd_service = CyberHerdService(
        database_service=database_service,
        payment_service=payment_service,
        messaging_service=messaging_service,
        max_herd_size=MAX_HERD_SIZE,
        predefined_wallet_address=config['PREDEFINED_WALLET_ADDRESS'],
        predefined_wallet_alias=config['PREDEFINED_WALLET_ALIAS'],
        predefined_wallet_reset_percent=PREDEFINED_WALLET_PERCENT_RESET
    )
    
    # Now give messaging service a reference to the cyberherd service for retrieving members
    messaging_service.cyberherd_service = cyberherd_service
    
    # Initialize payment processor service
    payment_processor_service = PaymentProcessorService(
        payment_service=payment_service,
        goat_service=goat_service,
        cyberherd_service=cyberherd_service,
        messaging_service=messaging_service,
        trigger_amount=TRIGGER_AMOUNT_SATS
    )

    cyberherd_listener_service = CyberherdListenerService(
         nos_sec=config['NOS_SEC'],
         hex_key=config['HEX_KEY'],
         callback_handler=handle_cyberherd_webhook,  # Use the direct handler
         nip05_verification=True,  # Enable NIP-05 verification
         message_template_service=message_template_service,
         database_service=database_service
     )
    await cyberherd_listener_service.initialize(http_client)
    await cyberherd_listener_service.start()
    
    # Connect to database and initialize tables
    await database_service.connect()
    await database_service.initialize_tables()

    # Ensure timestamp column exists in cyber_herd table
    await database_service.add_timestamp_column_if_needed()

    # Start WebSocket manager for payment notifications
    websocket_task = asyncio.create_task(websocket_manager.connect())
    connected = await websocket_manager.wait_for_connection(timeout=30)
    if not connected:
        logger.warning("Initial WebSocket connection attempt timed out")

    try:
        # Initialize wallet balance
        balance = await payment_service.get_balance()
        await payment_processor_service.update_balance(balance // 1000)
        async with app_state.lock:
            app_state.balance = balance // 1000
        
    except Exception as e:
        logger.error(f"Failed to initialize states: {e}. Defaulting to 0.")
        app_state.balance = 0

    # Start background tasks
    asyncio.create_task(cleanup_cache())
    asyncio.create_task(schedule_daily_reset())
    asyncio.create_task(messaging_service.periodic_informational_messages())
    asyncio.create_task(schedule_database_maintenance())

    # Initialize services and routers
    payment_routes.initialize_services(
        payment_service=payment_service,
        price_service=price_service
    )
    
    cyberherd_routes.initialize_services(
        cyberherd_service=cyberherd_service,
        database_service=database_service  # Pass database_service to the router
    )
    
    goat_routes.initialize_services(
        goat_service=goat_service
    )
    
    messaging_routes.initialize_services(
        messaging_service=messaging_service,
        cyberherd_service=cyberherd_service
    )
    
    # Include routers
    app.include_router(payment_routes.router)
    app.include_router(cyberherd_routes.router)
    app.include_router(goat_routes.router)
    app.include_router(messaging_routes.router)
    app.include_router(health_routes.router)  # Add this line to include health routes
    
    # Register websocket routes
    register_websocket_routes(app, messaging_service)

    # DISABLED: Initialize cyberherd payment listener service
    # websocket_uri = os.getenv(
    #     'WS_CYBERHERD',
    #     "ws://127.0.0.1:3002/api/v1/ws/39f4aed2967d492884446e8c7aa734af"
    # )
    # cyberherd_payment_listener_service = CyberherdPaymentListenerService(
    #     websocket_uri=websocket_uri,
    #     callback_handler=handle_cyberherd_treats,
    #     ignore_npubs=["Bolverker", "sat", "Unknown"],
    #     database_service=database_service,
    #     message_template_service=message_template_service
    # )
    # await cyberherd_payment_listener_service.initialize()
    # await cyberherd_payment_listener_service.start()
    
    # Set to None so shutdown handler knows it's not running
    cyberherd_payment_listener_service = None

async def schedule_daily_reset():
    """Schedule a daily reset at 01:00 local time."""
    while True:
        # Get current time
        now = datetime.now()  # Use local time, not UTC
        
        # Calculate next 01:00 reset time
        if now.hour < 1:
            # If current time is before 1 AM, set next reset to today at 1 AM
            next_reset = now.replace(hour=1, minute=0, second=0, microsecond=0)
        else:
            # If current time is after 1 AM, set next reset to tomorrow at 1 AM
            next_reset = (now + timedelta(days=1)).replace(hour=1, minute=0, second=0, microsecond=0)
        
        # Calculate seconds until next reset
        sleep_seconds = (next_reset - now).total_seconds()
        logger.info(f"Next CyberHerd reset scheduled for {next_reset} (in {sleep_seconds/3600:.2f} hours)")
        
        await asyncio.sleep(sleep_seconds)

        # Reset the cyberherd listener service
        if cyberherd_listener_service:
            try:
                await cyberherd_listener_service.reset()
                logger.info("Cyberherd listener service reset successfully")
            except Exception as e:
                logger.error(f"Failed to reset Cyberherd listener service: {e}")

        # Perform the reset
        status = await cyberherd_service.reset_cyberherd()
        
        if status['success'] and app_state.balance:
            balance = await payment_processor_service.get_balance()
            await payment_processor_service._send_payment(balance)
        
        # Clear old DM notifications as part of the daily reset
        if database_service:
            try:
                await database_service.clear_old_dm_notifications()
                logger.info("Cleared old DM notifications")
            except Exception as e:
                logger.error(f"Failed to clear old DM notifications: {e}")

async def cleanup_cache():
    """Periodically clean up expired cache entries."""
    while True:
        await asyncio.sleep(1800)  # 30 minutes
        try:
            await database_service.cache.cleanup()
        except Exception as e:
            logger.error(f"Error cleaning up cache: {e}")

async def schedule_database_maintenance():
    """Schedule periodic database maintenance."""
    while True:
        # Run once a week
        await asyncio.sleep(7 * 24 * 60 * 60)
        logger.info("Running database maintenance")
        try:
            # VACUUM the SQLite database
            await database_service.database.execute("VACUUM")
            # Analyze tables for query optimization
            await database_service.database.execute("ANALYZE")
            logger.info("Database maintenance complete")
        except Exception as e:
            logger.error(f"Database maintenance failed: {e}")

# API Routes

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.error(f"HTTPException: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception occurred", exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error"}
    )

# Add this function to configure logging during shutdown
def suppress_cancellation_errors():
    """Configure loggers to suppress cancellation errors."""
    # Set asyncio and uvloop error levels higher to ignore cancellation errors
    logging.getLogger("asyncio").setLevel(logging.CRITICAL)
    logging.getLogger("uvloop").setLevel(logging.CRITICAL)
    # Also silence the root logger from printing CancelledError exceptions
    for handler in logging.getLogger().handlers:
        if isinstance(handler, logging.StreamHandler):
            handler.setLevel(logging.WARNING)

@app.on_event("shutdown")
async def shutdown():
    """Clean up resources when shutting down."""
    logger.info("Application shutdown initiated - beginning graceful shutdown sequence")
    
    # Suppress cancellation errors in logs during shutdown
    suppress_cancellation_errors()
    
    # Define shutdown timeout
    shutdown_timeout = 5.0  # seconds
    
    # First close all client websocket connections
    if messaging_service:
        logger.info("Closing client WebSocket connections...")
        await messaging_service.close_all_connections()
    
    # Stop background tasks and listeners
    tasks = []
    
    # Create a helper function to safely stop a service
    async def safe_stop_service(service, service_name, timeout=shutdown_timeout):
        """Safely stop a service without propagating cancellation errors."""
        if not service:
            return
            
        logger.info(f"Stopping {service_name}...")
        try:
            await asyncio.wait_for(service.stop(), timeout=timeout)
            logger.info(f"Successfully stopped {service_name}")
        except asyncio.TimeoutError:
            logger.info(f"{service_name} stop timed out")
        except asyncio.CancelledError:
            # Don't log anything for cancellation
            pass
        except Exception:
            # Don't log full exception details
            logger.info(f"Error stopping {service_name}")
    
    # Stop services concurrently but handle errors individually
    if cyberherd_payment_listener_service:
        tasks.append(safe_stop_service(
            cyberherd_payment_listener_service, 
            "cyberherd payment listener service"
        ))
    
    if cyberherd_listener_service:
        tasks.append(safe_stop_service(
            cyberherd_listener_service,
            "cyberherd listener service"
        ))
    
    if websocket_manager:
        try:
            logger.info("Disconnecting payment WebSocket manager...")
            await asyncio.wait_for(websocket_manager.disconnect(), timeout=3.0)
            logger.info("Payment WebSocket manager disconnected")
        except asyncio.TimeoutError:
            logger.info("Payment WebSocket disconnect timed out")
        except Exception as e:
            logger.info(f"Error disconnecting payment WebSocket: {str(e)}")
    
    # Run all shutdown tasks concurrently with a timeout
    if tasks:
        logger.info(f"Waiting for services to shut down...")
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except Exception:
            # Ignore any errors during shutdown
            pass
    
    # Close database and HTTP connections with minimal logging
    try:
        if database_service:
            await database_service.disconnect()
    except Exception:
        pass
    
    try:
        if http_client:
            await http_client.aclose()
    except Exception:
        pass
    
    logger.info("Application shutdown complete")
