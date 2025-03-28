from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, status
import logging
import json
from typing import Dict, Any, Callable, Awaitable

from services.messaging_service import MessagingService

logger = logging.getLogger(__name__)

# Reference to the messaging service
_messaging_service = None

def register_websocket_routes(app: FastAPI, messaging_service: MessagingService):
    """
    Register WebSocket routes to the main FastAPI app.
    
    WebSocket routes cannot be included in APIRouter, so they must be registered
    directly on the FastAPI app instance.
    
    Args:
        app: The FastAPI app instance
        messaging_service: The messaging service for handling WebSocket connections
    """
    global _messaging_service
    _messaging_service = messaging_service
    
    @app.get("/ws", tags=["websocket"])
    async def websocket_info():
        """
        Get information about the WebSocket endpoint.
        
        Returns:
            Information about the WebSocket endpoint and how to connect
        """
        return {
            "endpoint": "/ws/",
            "status": "active",
            "client_count": len(messaging_service.connected_clients),
            "info": "Connect to the WebSocket endpoint to receive real-time updates"
        }
    
    @app.websocket("/ws/")
    async def websocket_endpoint(websocket: WebSocket):
        """
        WebSocket endpoint for real-time updates.
        
        This endpoint accepts WebSocket connections and:
        1. Broadcasts important app events to all connected clients
        2. Receives commands from clients (future feature)
        """
        logger.info(f"WebSocket connection request from {websocket.client}")
        
        try:
            # Accept the connection without any validation
            await _messaging_service.connect_client(websocket)
            
            # Keep the connection alive
            try:
                while True:
                    # Wait for messages from the client
                    data = await websocket.receive_text()
                    
                    # Handle client messages
                    if data == "ping":
                        await websocket.send_text('{"type":"pong"}')
                    # Ignore other messages for now
            except WebSocketDisconnect:
                logger.info(f"WebSocket client disconnected normally: {websocket.client}")
            except Exception as e:
                logger.error(f"Error in websocket communication: {e}")
        except Exception as e:
            logger.error(f"Failed to establish WebSocket connection: {e}")
            # Try to close the connection if it's still open
            try:
                await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
            except:
                pass
        finally:
            # Always ensure client is properly disconnected
            _messaging_service.disconnect_client(websocket)
    
    @app.websocket("/ws/status")
    async def websocket_status(websocket: WebSocket):
        """
        WebSocket endpoint for system status updates.
        
        This endpoint sends periodic status updates about the system.
        """
        try:
            await websocket.accept()
            await websocket.send_json({
                "type": "status",
                "status": "connected",
                "message": "Status WebSocket connected"
            })
            
            # We don't track these connections in the messaging service
            # as they're separate from the main broadcast channel
            
            # Keep the connection alive and just report status
            # Client can disconnect whenever they want
            while True:
                try:
                    # Just keep the connection alive by receiving messages
                    await websocket.receive_text()
                except WebSocketDisconnect:
                    logger.info("Status WebSocket disconnected normally")
                    break
                except Exception as e:
                    logger.warning(f"Status WebSocket error: {e}")
                    break
                    
        except Exception as e:
            logger.warning(f"Status WebSocket connection error: {e}")
