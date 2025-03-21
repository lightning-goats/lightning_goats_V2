from fastapi import APIRouter, HTTPException, Depends, Body, Query
from typing import Dict, Any, Optional, List
import logging

from services.messaging_service import MessagingService
from services.cyberherd_service import CyberHerdService
from models import CyberHerdTreats

# Initialize logger
logger = logging.getLogger(__name__)

# Create router with prefix and tags
router = APIRouter(
    prefix="/messages",
    tags=["messages"],
    responses={404: {"description": "Not found"}},
)

# Store service instances for dependency injection
_messaging_service: Optional[MessagingService] = None
_cyberherd_service: Optional[CyberHerdService] = None

def initialize_services(messaging_service: MessagingService, cyberherd_service: CyberHerdService):
    """Initialize the services needed for this router."""
    global _messaging_service, _cyberherd_service
    _messaging_service = messaging_service
    _cyberherd_service = cyberherd_service

# Dependency functions to get services
async def get_messaging_service() -> MessagingService:
    if _messaging_service is None:
        raise HTTPException(status_code=500, detail="MessagingService not initialized")
    return _messaging_service

async def get_cyberherd_service() -> CyberHerdService:
    if _cyberherd_service is None:
        raise HTTPException(status_code=500, detail="CyberHerdService not initialized")
    return _cyberherd_service

@router.post("/treats")
async def send_cyberherd_treats(
    data: CyberHerdTreats,
    messaging_service: MessagingService = Depends(get_messaging_service),
    cyberherd_service: CyberHerdService = Depends(get_cyberherd_service)
) -> Dict[str, Any]:
    """
    Send treats to a CyberHerd member.
    
    - **pubkey**: The public key of the member
    - **amount**: The amount of treats to send
    
    Returns:
    - Status message confirming the treats were sent
    """
    try:
        pubkey = data.pubkey
        amount = data.amount
        
        if amount <= 0:
            return {"status": "error", "message": "Amount must be positive"}
        
        # Get member details
        cyber_herd_list = await cyberherd_service.get_all_members()
        cyber_herd_dict = {item['pubkey']: item for item in cyber_herd_list}

        if pubkey in cyber_herd_dict:
            # Create and send message
            message, _ = await messaging_service.make_messages(
                amount, 
                0, 
                "cyber_herd_treats", 
                cyber_herd_dict[pubkey]
            )
            await messaging_service.send_message_to_clients(message)
            return {"status": "success"}
        else:
            return {"status": "error", "message": "Invalid pubkey"}
    except Exception as e:
        logger.error(f"Error sending treats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/broadcast")
async def broadcast_message(
    message: str = Body(..., embed=True),
    messaging_service: MessagingService = Depends(get_messaging_service)
) -> Dict[str, Any]:
    """
    Broadcast a message to all connected clients.
    
    - **message**: The message to broadcast
    
    Returns:
    - Status message confirming the broadcast
    """
    try:
        if not message:
            return {"status": "error", "message": "Message cannot be empty"}
            
        await messaging_service.send_message_to_clients(message)
        return {"status": "success", "message": "Message broadcasted to all connected clients"}
    except Exception as e:
        logger.error(f"Error broadcasting message: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to broadcast message: {str(e)}")

@router.get("/clients/count")
async def get_connected_clients_count(
    messaging_service: MessagingService = Depends(get_messaging_service)
) -> Dict[str, int]:
    """
    Get the count of currently connected WebSocket clients.
    
    Returns:
    - **client_count**: Number of connected clients
    """
    try:
        client_count = len(messaging_service.connected_clients)
        return {"client_count": client_count}
    except Exception as e:
        logger.error(f"Error getting connected client count: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get client count: {str(e)}")

# Legacy routes - keeping old paths for backward compatibility
@router.post("/messages/cyberherd_treats", include_in_schema=False)
async def legacy_handle_cyberherd_treats(
    data: CyberHerdTreats,
    messaging_service: MessagingService = Depends(get_messaging_service),
    cyberherd_service: CyberHerdService = Depends(get_cyberherd_service)
):
    """Legacy route - send treats to a CyberHerd member."""
    try:
        cyber_herd_list = await cyberherd_service.get_all_members()
        cyber_herd_dict = {item['pubkey']: item for item in cyber_herd_list}

        if data.pubkey in cyber_herd_dict:
            message, _ = await messaging_service.make_messages(
                data.amount, 
                0, 
                "cyber_herd_treats", 
                cyber_herd_dict[data.pubkey]
            )
            await messaging_service.send_message_to_clients(message)
            return {"status": "success"}
        else:
            return {"status": "error", "message": "Invalid pubkey"}
    except Exception as e:
        logger.error(f"Error sending treats: {e}")
        raise HTTPException(status_code=500, detail=str(e))
