from fastapi import APIRouter, HTTPException, Depends, Path, Query, Body
from typing import Dict, Any, Optional
import logging

from services.payment_service import PaymentService
from services.price_service import PriceService
from services.payment_processor_service import PaymentProcessorService
from models import PaymentRequest

# Initialize logger
logger = logging.getLogger(__name__)

# Create router with prefix and tags
router = APIRouter(
    prefix="/payments",
    tags=["payments"],
    responses={404: {"description": "Not found"}},
)

# Store service instances for dependency injection
_payment_service: Optional[PaymentService] = None
_price_service: Optional[PriceService] = None
_payment_processor_service: Optional[PaymentProcessorService] = None

def initialize_services(payment_service: PaymentService, price_service: PriceService, payment_processor_service: PaymentProcessorService):
    """Initialize the services needed for this router."""
    global _payment_service, _price_service, _payment_processor_service
    _payment_service = payment_service
    _price_service = price_service
    _payment_processor_service = payment_processor_service

# Dependency function to get services
async def get_payment_service() -> PaymentService:
    if _payment_service is None:
        raise HTTPException(status_code=500, detail="PaymentService not initialized")
    return _payment_service

async def get_price_service() -> PriceService:
    if _price_service is None:
        raise HTTPException(status_code=500, detail="PriceService not initialized")
    return _price_service

async def get_payment_processor_service() -> PaymentProcessorService:
    if _payment_processor_service is None:
        raise HTTPException(status_code=500, detail="PaymentProcessorService not initialized")
    return _payment_processor_service

@router.get("/balance")
async def get_balance(
    force_refresh: bool = False,
    payment_service: PaymentService = Depends(get_payment_service)
) -> Dict[str, Any]:
    """
    Get the current wallet balance in millisatoshis.
    
    - **force_refresh**: If True, bypass cache and get fresh balance
    
    Returns:
    - **balance**: Current balance in millisatoshis
    """
    try:
        balance = await payment_service.get_balance()
        return {"balance": balance}
    except Exception as e:
        logger.error(f"Error retrieving balance: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve balance")

@router.post("/send")
async def send_payment(
    data: PaymentRequest, 
    payment_service: PaymentService = Depends(get_payment_service)
) -> Dict[str, Any]:
    """
    Send payment to a specified address.
    
    - **data**: Payment details including balance to send
    
    Returns:
    - Payment status information
    """
    try:
        if not data.balance or data.balance <= 0:
            raise HTTPException(status_code=400, detail="Invalid payment amount")
        
        memo = 'Reset Herd Wallet'
        # Create invoice and pay it (internal transfer)
        payment_request = await payment_service.create_invoice(data.balance, memo)
        payment_status = await payment_service.pay_invoice(payment_request)
        
        return {
            "success": True, 
            "data": payment_status
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to send payment: {e}")
        raise HTTPException(status_code=500, detail="Failed to send payment")

@router.get("/convert/{amount}")
async def convert_usd_to_sats(
    amount: float = Path(..., description="USD amount to convert"),
    price_service: PriceService = Depends(get_price_service)
) -> Dict[str, int]:
    """
    Convert USD amount to satoshis.
    
    - **amount**: USD amount to convert
    
    Returns:
    - **sats**: Equivalent amount in satoshis
    """
    try:
        if amount <= 0:
            raise HTTPException(status_code=400, detail="Amount must be greater than zero")
        
        sats = await price_service.convert_usd_to_sats(amount)
        return {"sats": sats}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error converting amount: {e}")
        raise HTTPException(status_code=500, detail="Failed to convert amount")

@router.get("/trigger_amount")
async def get_trigger_amount(
    trigger_amount: int = 1250
) -> Dict[str, int]:
    """
    Get the amount of satoshis needed to trigger the feeder.
    
    Returns:
    - **trigger_amount**: Satoshis needed to trigger the feeder
    """
    return {"trigger_amount": trigger_amount}

@router.get("/zap/{lud16}")
async def zap_lightning_address(
    lud16: str = Path(..., description="Lightning address to zap"),
    sats: int = Query(1, description="Amount in sats to zap"),
    text: str = Query("CyberHerd Treats.", description="Message to include with zap"),
    payment_service: PaymentService = Depends(get_payment_service)
) -> Dict[str, Any]:
    """
    Send a zap to a Lightning address.
    
    - **lud16**: Lightning address (user@domain.com format)
    - **sats**: Amount in satoshis to send
    - **text**: Optional message to include
    
    Returns:
    - Payment status information
    """
    try:
        if not '@' in lud16:
            raise HTTPException(status_code=400, detail="Invalid Lightning address format")
        
        if sats <= 0:
            raise HTTPException(status_code=400, detail="Sats amount must be positive")
        
        result = await payment_service.zap_lud16(lud16, sats, text)
        return {"status": "success", "result": result}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to zap {lud16}: {e}")
        raise HTTPException(status_code=500, detail="Failed to send zap")

@router.post("/check-missed-zaps",
             summary="Check for missed zaps in recent payments",
             description="Query LNBits for recent payments and process any missed zaps")
async def check_missed_zaps(
    hours: int = Body(24, description="Look back this many hours"),
    limit: int = Body(100, description="Maximum number of payments to check"),
    payment_service: PaymentService = Depends(get_payment_service),
    payment_processor_service: PaymentProcessorService = Depends(get_payment_processor_service)
):
    """
    Check for and process any missed zaps in recent payments.
    This is useful to recover after downtime or if events were missed.
    """
    try:
        result = await payment_processor_service.process_missed_zaps(
            hours_ago=hours,
            limit=limit
        )
        return result
    except Exception as e:
        logger.error(f"Error checking for missed zaps: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error processing missed zaps: {str(e)}")

# Legacy routes - keeping old paths for backward compatibility
@router.get("/balance", include_in_schema=False)
async def legacy_get_balance(
    payment_service: PaymentService = Depends(get_payment_service)
):
    """Legacy route - get current wallet balance."""
    try:
        balance = await payment_service.get_balance()
        return {"balance": balance}
    except Exception as e:
        logger.error(f"Error retrieving balance: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve balance")

@router.get("/trigger_amount", include_in_schema=False)
async def legacy_get_trigger_amount(
    trigger_amount: int = 1250
):
    """Legacy route - get the amount of sats needed to trigger the feeder."""
    return {"trigger_amount": trigger_amount}

@router.get("/convert/{amount}", include_in_schema=False)
async def legacy_convert(
    amount: float = Path(..., description="USD amount to convert"),
    price_service: PriceService = Depends(get_price_service)
):
    """Legacy route - convert USD to satoshis."""
    try:
        if amount <= 0:
            raise HTTPException(status_code=400, detail="Amount must be greater than zero")
            
        sats = await price_service.convert_usd_to_sats(amount)
        return {"sats": sats}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error converting amount: {e}")
        raise HTTPException(status_code=500, detail="Failed to convert amount")
