from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, Optional
import logging

from services.goat_service import GoatStateService
from models import SetGoatSatsData

# Initialize logger
logger = logging.getLogger(__name__)

# Create router with prefix and tags
router = APIRouter(
    prefix="/goats",
    tags=["goats"],
    responses={404: {"description": "Not found"}},
)

# Store service instance for dependency injection
_goat_service: Optional[GoatStateService] = None

def initialize_services(goat_service: GoatStateService):
    """Initialize the services needed for this router."""
    global _goat_service
    _goat_service = goat_service

# Dependency function to get service
async def get_goat_service() -> GoatStateService:
    if _goat_service is None:
        raise HTTPException(status_code=500, detail="GoatStateService not initialized")
    return _goat_service

@router.get("/sats")
async def get_goat_sats(
    goat_service: GoatStateService = Depends(get_goat_service)
) -> Dict[str, int]:
    """
    Get the total goat sats received today.
    
    Returns:
    - **sum_goat_sats**: Total satoshis received today
    """
    try:
        return await goat_service.get_sats_today()
    except Exception as e:
        logger.error(f"Error getting goat sats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get goat sats")

@router.put("/sats")
async def set_goat_sats(
    data: SetGoatSatsData,
    goat_service: GoatStateService = Depends(get_goat_service)
) -> Dict[str, Any]:
    """
    Manually set the goat sats counter to a specific value.
    
    - **new_amount**: New sats amount to set
    
    Returns:
    - Status message confirming update
    """
    try:
        if data.new_amount < 0:
            raise HTTPException(status_code=400, detail="Amount cannot be negative")
            
        success = await goat_service.set_sats(data.new_amount)
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to update GoatSats")
            
        return {"status": "success", "new_state": data.new_amount}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error setting GoatSats: {e}")
        raise HTTPException(status_code=500, detail="Unexpected error setting GoatSats")

@router.put("/sats/sum")
async def set_goat_sats_sum(
    data: SetGoatSatsData,
    goat_service: GoatStateService = Depends(get_goat_service)
) -> Dict[str, Any]:
    """
    Update the total GoatSatsSum counter in OpenHAB.
    
    - **new_amount**: New total satoshis to set
    
    Returns:
    - Status message confirming update
    """
    try:
        if data.new_amount < 0:
            raise HTTPException(status_code=400, detail="Amount cannot be negative")
            
        success = await goat_service.update_sats_sum(data.new_amount)
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to update GoatSatsSum")
            
        return {"status": "success", "new_state": data.new_amount}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error setting GoatSatsSum: {e}")
        raise HTTPException(status_code=500, detail="Unexpected error setting GoatSatsSum")

@router.get("/feedings")
async def get_goat_feedings(
    goat_service: GoatStateService = Depends(get_goat_service)
) -> Dict[str, int]:
    """
    Get the number of goat feedings today.
    
    Returns:
    - **goat_feedings**: Number of feedings today
    """
    try:
        feedings = await goat_service.get_feedings_count()
        return {"goat_feedings": feedings}
    except Exception as e:
        logger.error(f"Error getting goat feedings: {e}")
        raise HTTPException(status_code=500, detail="Failed to get goat feedings")

@router.get("/feeder/status")
async def get_feeder_status(
    goat_service: GoatStateService = Depends(get_goat_service)
) -> Dict[str, bool]:
    """
    Check if feeder override is enabled.
    
    Returns:
    - **feeder_override_enabled**: True if override is enabled, false otherwise
    """
    try:
        status = await goat_service.get_feeder_override_status()
        return {"feeder_override_enabled": status}
    except Exception as e:
        logger.error(f"Error checking feeder status: {e}")
        raise HTTPException(status_code=500, detail="Failed to check feeder status")

@router.post("/feeder/trigger")
async def trigger_feeder(
    goat_service: GoatStateService = Depends(get_goat_service)
) -> Dict[str, Any]:
    """
    Manually trigger the feeder.
    
    Returns:
    - Status message confirming feeder was triggered
    """
    try:
        success = await goat_service.trigger_feeder()
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to trigger feeder")
            
        return {"status": "success", "message": "Feeder triggered successfully"}
    except Exception as e:
        logger.error(f"Error triggering feeder: {e}")
        raise HTTPException(status_code=500, detail="Failed to trigger feeder")

# Legacy routes - keeping old paths for backward compatibility
@router.get("/goat_sats/feedings", include_in_schema=False)
async def legacy_get_goat_feedings_endpoint(
    goat_service: GoatStateService = Depends(get_goat_service)
):
    """Legacy route - get the number of goat feedings today."""
    feedings = await goat_service.get_feedings_count()
    return {"goat_feedings": feedings}  # Return in expected dict format for client compatibility

@router.get("/goat_sats/sum_today", include_in_schema=False)
async def legacy_get_goat_sats_sum_today_endpoint(
    goat_service: GoatStateService = Depends(get_goat_service)
):
    """Legacy route - get the total goat sats received today."""
    return await goat_service.get_sats_today()

@router.put("/goat_sats/set", include_in_schema=False)
async def legacy_set_goat_sats_endpoint(
    data: SetGoatSatsData,
    goat_service: GoatStateService = Depends(get_goat_service)
):
    """Legacy route - manually set the goat sats counter."""
    success = await goat_service.set_sats(data.new_amount)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to update GoatSats")
    return {"status": "success", "new_state": data.new_amount}

@router.get("/feeder_status", include_in_schema=False)
async def legacy_feeder_status(
    goat_service: GoatStateService = Depends(get_goat_service)
):
    """Legacy route - check if the feeder override is enabled."""
    status = await goat_service.get_feeder_override_status()
    return {"feeder_override_enabled": status}

@router.post("/trigger_feeder", include_in_schema=False)
async def legacy_trigger_feeder(
    goat_service: GoatStateService = Depends(get_goat_service)
):
    """Legacy route - manually trigger the goat feeder."""
    success = await goat_service.trigger_feeder()
    if not success:
        raise HTTPException(status_code=500, detail="Failed to trigger feeder")
    return {"status": "success", "message": "Feeder triggered successfully"}
