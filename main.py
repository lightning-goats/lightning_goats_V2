import os
import logging
import asyncio
import json
import datetime
from datetime import datetime, timedelta
import time
from threading import Lock
from typing import Dict, Any, List, Optional

# Set environment variable for protobuf before any other imports
os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"

from fastapi import FastAPI, Request, HTTPException, WebSocket, Response # Added Response
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
from services.cyberherd_payment_listener_service import CyberherdPaymentListenerService
from services.openhab_service import OpenHABService
from services.websocket_manager import WebSocketManager
from services.l402_service import L402Service

from routers import payment_routes, cyberherd_routes, goat_routes, messaging_routes, health_routes
from routers.websocket_routes import register_websocket_routes
from routers import l402_routes

from utils.cyberherd_module import MetadataFetcher, Verifier, generate_nprofile, check_cyberherd_tag, DEFAULT_RELAYS
from utils.nostr_utils import sign_event, sign_zap_event
from utils.env_utils import load_env_vars, get_env_int, get_env_bool
from utils.http_utils import create_http_client, http_retry

# Import models module for data classes
from models import CyberHerdData

# Configuration and Constants
MAX_HERD_SIZE = get_env_int('MAX_HERD_SIZE', 10)
PREDEFINED_WALLET_PERCENT_RESET = get_env_int('PREDEFINED_WALLET_PERCENT_RESET', 100)
TRIGGER_AMOUNT_SATS = get_env_int('TRIGGER_AMOUNT_SATS', 1250)
DEBUG_MODE = get_env_bool('DEBUG_MODE', False)
LOG_LEVEL = os.getenv('LOG_LEVEL', 'DEBUG' if DEBUG_MODE else 'INFO') # Set DEBUG if DEBUG_MODE is True

required_env_vars = [
    'OH_AUTH_1', 'HERD_KEY', 'SAT_KEY', 'NOS_SEC', 'HEX_KEY',
    'CYBERHERD_KEY', 'LNBITS_URL', 'OPENHAB_URL', 'HERD_WEBSOCKET',
    'PREDEFINED_WALLET_ADDRESS', 'PREDEFINED_WALLET_ALIAS'
]

optional_env_vars = [
    'MAX_HERD_SIZE', 'PREDEFINED_WALLET_PERCENT_RESET', 'TRIGGER_AMOUNT_SATS',
    'DEBUG_MODE', 'LOG_LEVEL', 'DAILY_RESET_HOUR', 'RETRY_MAX_ATTEMPTS', 'CACHE_TTL',
    'NIP05_REQUIRED', 'L402_SECRET_KEY', 'L402_DEFAULT_EXPIRY_SECONDS', 'L402_DEFAULT_PRICE_SATS' # Added L402 vars
]

config = load_env_vars(required_env_vars, optional_env_vars)

# Logging Configuration
logging_level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
logging.basicConfig(
    level=logging_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler() # Ensure logs go to stdout/stderr for Gunicorn/Docker
    ]
)
# Silence overly verbose libraries if needed
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)
logger.info(f"Logging level set to: {LOG_LEVEL.upper()}")


# FastAPI app setup
app = FastAPI(title="Lightning Goats API", version="1.0.0")

# App state management
class AppState:
    def __init__(self):
        self.balance: int = 0
        self.lock = Lock()

app_state = AppState()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Consider restricting in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Retry configurations (might not be needed globally if applied per service)
# http_retry = retry(...) # If needed globally

# Initialize service instances (declared as None initially)
database_service: Optional[DatabaseService] = None
http_client: Optional[httpx.AsyncClient] = None
messaging_service: Optional[MessagingService] = None
message_template_service: Optional[MessageTemplateService] = None
openhab_service: Optional[OpenHABService] = None
payment_service: Optional[PaymentService] = None
cyberherd_service: Optional[CyberHerdService] = None
goat_service: Optional[GoatStateService] = None
price_service: Optional[PriceService] = None
payment_processor_service: Optional[PaymentProcessorService] = None
cyberherd_listener_service: Optional[CyberherdListenerService] = None
cyberherd_payment_listener_service: Optional[CyberherdPaymentListenerService] = None
l402_service: Optional[L402Service] = None
websocket_manager: Optional[WebSocketManager] = None


class PaymentWebSocketManager(WebSocketManager):
    """Custom WebSocketManager that processes payment data via PaymentProcessorService"""

    async def process_payment_data(self, payment_data):
        """Handle incoming payment data from the websocket."""
        if not payment_processor_service:
            logger.warning("Payment processor service not initialized when processing payment data.")
            return

        try:
            payment_result = await payment_processor_service.process_payment(payment_data)
            # No need to call messaging_service here, process_payment should handle notifications

        except Exception as e:
            logger.error(f"Error processing payment data in WebSocketManager: {e}", exc_info=True)

# --- Direct Callback Handlers ---

async def handle_cyberherd_webhook(data: Dict[str, Any]) -> bool:
    """Direct handler for CyberHerd metadata updates."""
    if not cyberherd_service:
        logger.warning("CyberHerd service not initialized for webhook.")
        return False
    try:
        cyberherd_item = CyberHerdData(**data) # Validate data using the model
        result = await cyberherd_service.update_cyberherd([cyberherd_item])
        return result.get("success", False)
    except Exception as e:
        logger.error(f"Error processing CyberHerd webhook data directly: {e}", exc_info=True)
        return False

async def handle_cyberherd_treats(data: Dict[str, Any]) -> bool:
    """Direct handler for CyberHerd treats payments."""
    if not cyberherd_service:
        logger.warning("CyberHerd service not initialized for treats payment.")
        return False
    try:
        return await cyberherd_service.process_treats_payment(data)
    except Exception as e:
        logger.error(f"Error handling cyberherd treats: {e}", exc_info=True)
        return False

# --- FastAPI Events ---

@app.on_event("startup")
async def startup():
    logger.info("Application startup sequence initiated...")
    global http_client, database_service, messaging_service, message_template_service
    global openhab_service, payment_service, cyberherd_service, goat_service
    global price_service, payment_processor_service, cyberherd_listener_service
    global cyberherd_payment_listener_service, l402_service, websocket_manager

    # Initialize shared HTTP client
    http_client = await create_http_client(http2=True)
    logger.info("Shared HTTP client created.")

    # Initialize Database Service
    try:
        database_service = DatabaseService('sqlite:///cyberherd.db') # Use relative path or configure absolute path
        await database_service.connect()
        await database_service.initialize_tables()
        await database_service.add_timestamp_column_if_needed() # Ensure schema is up-to-date
        logger.info("Database service initialized and connected.")
    except Exception as e:
        logger.critical(f"FATAL: Failed to initialize database: {e}", exc_info=True)
        # Optionally raise the error to prevent startup if DB is critical
        raise RuntimeError("Database initialization failed") from e

    # Initialize dependent services (order matters)
    message_template_service = MessageTemplateService(database_service)
    await message_template_service.initialize_default_templates()
    logger.info("Message template service initialized.")

    messaging_service = MessagingService(
        private_key=config['NOS_SEC'],
        default_relays=DEFAULT_RELAYS,
        message_template_service=message_template_service,
        database_service=database_service
    )
    logger.info("Messaging service initialized.")

    openhab_service = OpenHABService(
        openhab_url=config["OPENHAB_URL"],
        auth=(config['OH_AUTH_1'], ''),
        http_client=http_client
    )
    # No async init needed for OpenHAB service based on its code
    logger.info("OpenHAB service initialized.")

    payment_service = PaymentService(
        lnbits_url=config['LNBITS_URL'],
        herd_key=config['HERD_KEY'],
        cyberherd_key=config['CYBERHERD_KEY'],
        hex_key=config['HEX_KEY'],
        nos_sec=config['NOS_SEC']
    )
    await payment_service.initialize(http_client, sign_zap_event) # Pass http_client and signing func
    logger.info("Payment service initialized.")

    goat_service = GoatStateService(
        openhab_service=openhab_service,
        cache=database_service.cache # Use cache from database service
    )
    logger.info("Goat state service initialized.")

    price_service = PriceService(
        openhab_url=config["OPENHAB_URL"],
        auth_credentials=(config['OH_AUTH_1'], ''),
        http_client=http_client
    )
    # No async init needed for Price service based on its code
    logger.info("Price service initialized.")

    cyberherd_service = CyberHerdService(
        database_service=database_service,
        payment_service=payment_service,
        messaging_service=messaging_service,
        max_herd_size=MAX_HERD_SIZE,
        predefined_wallet_address=config['PREDEFINED_WALLET_ADDRESS'],
        predefined_wallet_alias=config['PREDEFINED_WALLET_ALIAS'],
        predefined_wallet_reset_percent=PREDEFINED_WALLET_PERCENT_RESET
    )
    logger.info("CyberHerd service initialized.")

    # Inject dependencies back into messaging_service
    messaging_service.cyberherd_service = cyberherd_service
    messaging_service.goat_service = goat_service
    logger.info("Injected dependencies into Messaging service.")

    payment_processor_service = PaymentProcessorService(
        payment_service=payment_service,
        goat_service=goat_service,
        cyberherd_service=cyberherd_service,
        messaging_service=messaging_service,
        trigger_amount=TRIGGER_AMOUNT_SATS,
        process_zaps=True
    )
    logger.info("Payment processor service initialized.")

    # Initialize L402 Service
    try:
        l402_service = L402Service(
            payment_service=payment_service,
            database_service=database_service,
            messaging_service=messaging_service,
            secret_key=config.get('L402_SECRET_KEY'),
            default_expiry_seconds=get_env_int('L402_DEFAULT_EXPIRY_SECONDS', 3600),
            default_price_sats=get_env_int('L402_DEFAULT_PRICE_SATS', 1)
        )
        await l402_service.initialize()
        logger.info("L402 service initialized.")
    except Exception as e:
        logger.error(f"Failed to initialize L402 service: {e}", exc_info=True)
        # Decide if this is fatal or not
        l402_service = None # Ensure it's None if init fails

    # Initialize Routers (pass initialized services)
    payment_routes.initialize_services(payment_service=payment_service, price_service=price_service)
    cyberherd_routes.initialize_services(cyberherd_service=cyberherd_service, database_service=database_service)
    goat_routes.initialize_services(goat_service=goat_service)
    messaging_routes.initialize_services(messaging_service=messaging_service, cyberherd_service=cyberherd_service)
    health_routes.initialize_services(cyberherd_listener_service=cyberherd_listener_service) # Listener might be None initially
    if l402_service:
        l402_routes.initialize_services(l402_service=l402_service)
    else:
         logger.warning("L402 service not initialized, skipping L402 route initialization.")

    # Include Routers
    app.include_router(payment_routes.router)
    app.include_router(cyberherd_routes.router)
    app.include_router(goat_routes.router)
    app.include_router(messaging_routes.router)
    app.include_router(health_routes.router)
    if l402_service: # Only include router if service initialized
        app.include_router(l402_routes.router)
    else:
         logger.warning("L402 router not included as service failed to initialize.")


    # Register WebSocket Routes
    register_websocket_routes(app, messaging_service)
    logger.info("Registered routers and WebSocket routes.")

    # Initialize and Start CyberHerd Metadata Listener
    try:
        cyberherd_listener_service = CyberherdListenerService(
             nos_sec=config['NOS_SEC'],
             hex_key=config['HEX_KEY'],
             callback_handler=handle_cyberherd_webhook,
             nip05_verification=True,
             message_template_service=message_template_service,
             database_service=database_service,
             nip05_required=get_env_bool('NIP05_REQUIRED', True)
         )
        await cyberherd_listener_service.initialize(http_client) # Pass client
        await cyberherd_listener_service.start()
        # Update health routes now that listener is potentially running
        health_routes.initialize_services(cyberherd_listener_service=cyberherd_listener_service)
        logger.info("CyberHerd listener service started.")
    except Exception as e:
        logger.error(f"Failed to start CyberHerd listener service: {e}", exc_info=True)
        cyberherd_listener_service = None # Ensure it's None if start fails

    # Initialize and Start Payment WebSocket Manager (HERD_WEBSOCKET)
    websocket_manager = PaymentWebSocketManager(
        uri=config['HERD_WEBSOCKET'],
        logger=logger,
        max_retries=5
    )
    # Don't await connection here, let it run in background
    _ = asyncio.create_task(websocket_manager.connect(), name="PaymentWebSocketManagerTask")
    logger.info(f"Initiated connection task for payment websocket: {config['HERD_WEBSOCKET']}")


    # Initialize Wallet Balance (best effort)
    try:
        # Use herd_key for the main balance check
        balance_msat = await payment_service.get_balance(wallet_key=config['HERD_KEY'])
        balance_sats = balance_msat // 1000
        await payment_processor_service.update_balance(balance_sats)
        # Use a lock for app_state if needed, but direct assignment might be okay here if only read elsewhere
        app_state.balance = balance_sats
        logger.info(f"Initial wallet balance fetched: {balance_sats} sats")
    except Exception as e:
        logger.error(f"Failed to initialize wallet balance: {e}. Defaulting balance to 0.", exc_info=True)
        app_state.balance = 0
        if payment_processor_service: await payment_processor_service.update_balance(0)

    # Start Background Tasks
    asyncio.create_task(cleanup_cache(), name="CacheCleanupTask")
    asyncio.create_task(schedule_daily_reset(), name="DailyResetTask")
    asyncio.create_task(messaging_service.periodic_informational_messages(), name="InfoMessagesTask")
    asyncio.create_task(schedule_database_maintenance(), name="DbMaintenanceTask")
    logger.info("Scheduled background tasks.")

    logger.info("Application startup complete.")


async def schedule_daily_reset():
    """Schedule daily resets and maintenance."""
    reset_hour = get_env_int('DAILY_RESET_HOUR', 1) # Default to 1 AM local time
    logger.info(f"Daily reset scheduled for {reset_hour:02d}:00 local time.")
    while True:
        now = datetime.now()
        # Calculate next reset time
        if now.hour < reset_hour:
            next_reset = now.replace(hour=reset_hour, minute=0, second=0, microsecond=0)
        else:
            next_reset = (now + timedelta(days=1)).replace(hour=reset_hour, minute=0, second=0, microsecond=0)

        sleep_seconds = (next_reset - now).total_seconds()
        logger.info(f"Next daily reset in {sleep_seconds/3600:.2f} hours at {next_reset}.")
        await asyncio.sleep(sleep_seconds)

        logger.info("Performing daily reset...")
        # Reset cyberherd listener first if running
        if cyberherd_listener_service:
            try:
                await cyberherd_listener_service.reset()
                logger.info("Cyberherd listener service daily reset successful.")
            except Exception as e:
                logger.error(f"Failed to reset Cyberherd listener service: {e}", exc_info=True)

        # Perform CyberHerd reset (splits)
        if cyberherd_service:
            try:
                status = await cyberherd_service.reset_cyberherd()
                logger.info(f"CyberHerd split reset status: {status}")
                # Trigger payout if reset was successful and balance exists
                if status.get('success') and payment_processor_service and app_state.balance > 0:
                    try:
                         # Fetch latest balance before payout
                         current_balance_msat = await payment_service.get_balance(wallet_key=config['HERD_KEY'])
                         current_balance_sats = current_balance_msat // 1000
                         if current_balance_sats > 0:
                              logger.info(f"Triggering payout of remaining balance: {current_balance_sats} sats")
                              await payment_processor_service._send_payment(current_balance_sats) # Use internal method if needed
                         else:
                              logger.info("Balance is zero, skipping payout.")
                    except Exception as payout_e:
                         logger.error(f"Error during daily payout: {payout_e}", exc_info=True)

            except Exception as e:
                logger.error(f"Failed to perform CyberHerd reset: {e}", exc_info=True)

        # Clear old DM notifications
        if database_service:
            try:
                deleted_count = await database_service.clear_old_dm_notifications()
                logger.info(f"Cleared {deleted_count} old DM notifications.")
            except Exception as e:
                logger.error(f"Failed to clear old DM notifications: {e}", exc_info=True)
        logger.info("Daily reset complete.")


async def cleanup_cache():
    """Periodically clean up expired cache entries."""
    cache_ttl = get_env_int('CACHE_TTL', 3600) # Default 1 hour TTL
    check_interval = max(600, cache_ttl // 6) # Check every 10 mins or 1/6th TTL
    logger.info(f"Cache cleanup task started. Checking every {check_interval} seconds.")
    while True:
        await asyncio.sleep(check_interval)
        if database_service and hasattr(database_service, 'cache') and database_service.cache:
            try:
                #logger.debug("Running cache cleanup...") # Too noisy for INFO
                await database_service.cache.cleanup()
            except Exception as e:
                logger.error(f"Error during cache cleanup: {e}", exc_info=True)


async def schedule_database_maintenance():
    """Schedule periodic database maintenance (VACUUM, ANALYZE)."""
    maintenance_interval_hours = 24 * 7 # Once a week
    logger.info(f"Database maintenance task started. Running every {maintenance_interval_hours} hours.")
    while True:
        await asyncio.sleep(maintenance_interval_hours * 3600)
        if database_service and database_service.database and database_service.database.is_connected:
            logger.info("Running scheduled database maintenance (VACUUM, ANALYZE)...")
            try:
                await database_service.database.execute("VACUUM;")
                await database_service.database.execute("ANALYZE;")
                logger.info("Database maintenance complete.")
            except Exception as e:
                logger.error(f"Database maintenance failed: {e}", exc_info=True)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Log details of the exception
    logger.warning(f"HTTPException caught: Status={exc.status_code}, Detail='{exc.detail}', Path='{request.url.path}'")
    # Return standard JSON response
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=getattr(exc, "headers", None) # Include headers if the exception has them
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Log the full traceback for unexpected errors
    logger.error(f"Unhandled exception for request: {request.method} {request.url.path}", exc_info=exc)
    # Return a generic 500 error response
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error"}
    )

# --- Shutdown Handler ---
def suppress_cancellation_errors():
    """Configure loggers to suppress Task cancellation errors during shutdown."""
    logging.getLogger("asyncio").setLevel(logging.CRITICAL)
    # Suppress potential uvloop errors if used
    try: logging.getLogger("uvloop").setLevel(logging.CRITICAL)
    except Exception: pass

@app.on_event("shutdown")
async def shutdown():
    logger.info("Application shutdown sequence initiated...")
    suppress_cancellation_errors()
    shutdown_timeout = 5.0 # seconds

    # Close client websockets first
    if messaging_service:
        logger.info("Closing client WebSocket connections...")
        await messaging_service.close_all_connections()

    # Stop listeners and managers
    tasks_to_cancel = []
    services_to_stop = [
        (cyberherd_payment_listener_service, "CyberHerd Payment Listener"), # Already None if disabled
        (cyberherd_listener_service, "CyberHerd Metadata Listener"),
        (websocket_manager, "Payment WebSocket Manager"), # Use disconnect method
    ]

    # Gather stop/disconnect tasks
    stop_tasks = []
    for service, name in services_to_stop:
        if service:
             logger.info(f"Requesting stop/disconnect for {name}...")
             if hasattr(service, 'stop') and callable(service.stop):
                  stop_tasks.append(asyncio.create_task(service.stop(), name=f"Stop_{name.replace(' ','')}"))
             elif hasattr(service, 'disconnect') and callable(service.disconnect):
                  stop_tasks.append(asyncio.create_task(service.disconnect(), name=f"Disconnect_{name.replace(' ','')}"))


    # Wait for stop/disconnect tasks with timeout
    if stop_tasks:
        logger.info(f"Waiting up to {shutdown_timeout}s for services to stop...")
        done, pending = await asyncio.wait(stop_tasks, timeout=shutdown_timeout)

        for task in pending:
            service_name = task.get_name().replace('Stop_','').replace('Disconnect_','')
            logger.warning(f"{service_name} did not stop/disconnect gracefully within timeout. Cancelling task.")
            task.cancel()
        # Log results for completed tasks (optional, might show errors)
        # for task in done:
        #     try: task.result()
        #     except Exception as e: logger.warning(f"Error during service stop/disconnect: {e}")

    # Cancel background tasks explicitly
    logger.info("Cancelling background tasks...")
    for task in asyncio.all_tasks():
         task_name = task.get_name()
         if task_name in ["CacheCleanupTask", "DailyResetTask", "InfoMessagesTask", "DbMaintenanceTask", "PaymentWebSocketManagerTask"]:
              if not task.done():
                   logger.debug(f"Cancelling task: {task_name}")
                   task.cancel()

    # Allow cancellation to propagate briefly
    await asyncio.sleep(0.1)

    # Close external connections
    logger.info("Closing external connections (Database, HTTP Client)...")
    if database_service:
        try: await database_service.disconnect()
        except Exception as e: logger.warning(f"Error disconnecting database: {e}")
    if payment_service and hasattr(payment_service, 'close'): # Close payment service client if needed
         try: await payment_service.close()
         except Exception as e: logger.warning(f"Error closing payment service client: {e}")
    elif http_client: # Fallback to closing global client if payment service doesn't own it
        try: await http_client.aclose()
        except Exception as e: logger.warning(f"Error closing global HTTP client: {e}")


    logger.info("Application shutdown complete.")

# Note: Running with Gunicorn/Uvicorn should handle the main event loop.
# If running directly (e.g., uvicorn main:app), ensure proper setup.