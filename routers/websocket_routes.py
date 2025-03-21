from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
import logging
import json
from typing import Dict, Any, Callable, Awaitable

from services.messaging_service import MessagingService

logger = logging.getLogger(__name__)

def register_websocket_routes(app: FastAPI, messaging_service: MessagingService):
    """
    Register WebSocket routes to the main FastAPI app.
    
    WebSocket routes cannot be included in APIRouter, so they must be registered
    directly on the FastAPI app instance.
    
    Args:
        app: The FastAPI app instance
        messaging_service: The messaging service for handling WebSocket connections
    """
    
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
        try:
            # Accept the connection and register the client
            await messaging_service.connect_client(websocket)
            
            # Send a welcome message to the client
            await websocket.send_text(json.dumps({
                "type": "connection_established",
                "message": "Connected to Lightning Goats WebSocket server",
                "client_count": len(messaging_service.connected_clients)
            }))
            
            # Keep the connection alive and handle incoming messages
            while True:
                try:
                    # Wait for messages from the client
                    message = await websocket.receive_text()
                    
                    # Process client commands (future feature)
                    if message.strip():
                        logger.debug(f"Received message from client: {message}")
                        # Currently just echo the message back
                        await websocket.send_text(json.dumps({
                            "type": "echo",
                            "content": message
                        }))
                
                except WebSocketDisconnect:
                    logger.info("WebSocket disconnected normally")
                    break
                except Exception as e:
                    logger.warning(f"Error receiving message: {e}")
                    await websocket.send_text(json.dumps({
                        "type": "error", 
                        "message": "Error processing your message"
                    }))
        
        except Exception as e:
            logger.warning(f"WebSocket connection error: {e}")
        
        finally:
            # Always clean up the connection
            messaging_service.disconnect_client(websocket)
    
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
