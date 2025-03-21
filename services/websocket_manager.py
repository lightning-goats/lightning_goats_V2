# websocket_manager.py
import asyncio
import json
import logging
from typing import Optional
from asyncio import Lock, Event
import websockets
from websockets.exceptions import (
    ConnectionClosedError,
    ConnectionClosedOK,
    InvalidURI,
    InvalidHandshake,
)
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type, before_log

# Retry decorator for WebSocket connections
websocket_retry = retry(
    reraise=True,
    stop=stop_after_attempt(None),  # Infinite retries
    wait=wait_exponential(multiplier=1, min=4, max=60),
    retry=retry_if_exception_type((
        ConnectionClosedError,
        ConnectionClosedOK,
        InvalidURI,
        InvalidHandshake,
        OSError,
    )),
    before=before_log(logging.getLogger(__name__), logging.WARNING)
)


class WebSocketManager:
    def __init__(self, uri: str, logger: logging.Logger, max_retries: Optional[int] = None):
        self.uri = uri
        self.logger = logger
        self.max_retries = max_retries
        self.websocket = None
        self.lock = Lock()
        self.should_run = True
        self.connected = Event()
        self.listen_task = None
        self._retry_count = 0
        self._is_connected = False  # Add an explicit connection flag

    @property
    def is_connected(self) -> bool:
        """Property to check if the websocket is currently connected."""
        return self._is_connected and self.websocket is not None

    @websocket_retry
    async def connect(self):
        async with self.lock:
            while self.should_run:
                try:
                    if self.websocket:
                        await self.websocket.close()
                    
                    self.websocket = await websockets.connect(
                        self.uri,
                        ping_interval=30,
                        ping_timeout=10,
                        close_timeout=10
                    )
                    
                    self.logger.info(f"Connected to WebSocket: {self.uri}")
                    self.connected.set()
                    self._retry_count = 0  # Reset retry count on successful connection
                    self._is_connected = True  # Set the connected flag
                    
                    # Start listening in a separate task
                    self.listen_task = asyncio.create_task(self.listen())
                    
                    # Wait for the listen task to complete
                    await self.listen_task

                except (ConnectionClosedError, ConnectionClosedOK, InvalidURI, InvalidHandshake, OSError) as e:
                    self.logger.warning(f"WebSocket connection error: {e}")
                    self.connected.clear()
                    self._is_connected = False  # Clear the connected flag
                    
                    if self.should_run:
                        if self.max_retries is not None and self._retry_count >= self.max_retries:
                            self.logger.error("Maximum reconnection attempts reached. Stopping reconnection.")
                            break
                        
                        backoff = min(60, (2 ** self._retry_count))
                        self.logger.info(f"Attempting reconnection in {backoff} seconds (Retry {self._retry_count + 1})...")
                        self._retry_count += 1
                        await asyncio.sleep(backoff)
                    else:
                        break
                except Exception as e:
                    self.logger.error(f"Unexpected error in WebSocket connection: {e}")
                    self.connected.clear()
                    self._is_connected = False  # Clear the connected flag
                    if self.should_run:
                        self.logger.info("Retrying connection in 5 seconds due to unexpected error.")
                        await asyncio.sleep(5)
                    else:
                        break

    async def listen(self):
        try:
            async for message in self.websocket:
                try:
                    self.logger.debug(f"Received message: {message}")
                    payment_data = json.loads(message)
                    await self.process_payment_data(payment_data)
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to decode WebSocket message: {e}")
                except Exception as e:
                    self.logger.error(f"Error processing message: {e}")
                    # Continue listening even if processing fails
        except (ConnectionClosedError, ConnectionClosedOK) as e:
            self.logger.warning(f"WebSocket connection closed during listen: {e}")
            # Propagate to trigger reconnection
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error in listen: {e}")
            raise

    async def disconnect(self) -> None:
        """
        Disconnect from the WebSocket server.
        """
        self.logger.info("Disconnecting from WebSocket server...")
        self.should_run = False
        
        if self.websocket:
            try:
                # Send a close frame with a normal closure code
                await asyncio.wait_for(
                    self.websocket.close(code=1000),
                    timeout=2.0
                )
                self.logger.info("WebSocket closed normally")
            except asyncio.TimeoutError:
                self.logger.warning("WebSocket close timed out")
            except Exception as e:
                if "the handler is closed" not in str(e):
                    self.logger.warning(f"Error during WebSocket close: {e}")
            finally:
                # Ensure we mark as disconnected even if close fails
                self.websocket = None
                self._is_connected = False
                self.connected.clear()
        
        # Cancel listen task if running
        if self.listen_task and not self.listen_task.done():
            try:
                self.listen_task.cancel()
                await asyncio.shield(asyncio.gather(self.listen_task, return_exceptions=True))
            except asyncio.CancelledError:
                pass
            except Exception as e:
                self.logger.warning(f"Error canceling listen task: {e}")
        
        self.logger.info("WebSocket disconnected")

    async def wait_for_connection(self, timeout: Optional[float] = None) -> bool:
        """Wait for the WebSocket to be connected within the specified timeout."""
        try:
            await asyncio.wait_for(self.connected.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            self.logger.warning("Timeout while waiting for WebSocket connection.")
            return False

    async def run(self):
        """Convenience method to start the connection management."""
        await self.connect()

    async def process_payment_data(self, payment_data):
        """Override this method to handle payment data."""
        raise NotImplementedError("Subclasses should implement this method")

