from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Dict, Any, Optional
import logging
import time
import datetime
from pydantic import BaseModel

from services.database_service import DatabaseService
from services.payment_service import PaymentService
from services.cyberherd_listener_service import CyberherdListenerService
from routers.payment_routes import get_payment_service
from routers.cyberherd_routes import get_database_service
from utils.cyberherd_module import Verifier

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/health",
    tags=["health"],
)

# Global service reference to be set by the main application
_cyberherd_listener_service = None

# Set up dependency
def get_cyberherd_listener_service() -> CyberherdListenerService:
    if _cyberherd_listener_service is None:
        raise HTTPException(status_code=503, detail="CyberHerd listener service not initialized")
    return _cyberherd_listener_service

def initialize_services(cyberherd_listener_service: CyberherdListenerService):
    """Initialize the router with required services."""
    global _cyberherd_listener_service
    _cyberherd_listener_service = cyberherd_listener_service

@router.get("/")
async def health_check(
    database_service = Depends(get_database_service),
    payment_service = Depends(get_payment_service)
):
    """Health check endpoint."""
    start_time = time.time()
    results = {"status": "healthy", "services": {}}
    
    # Check database
    try:
        await database_service.database.fetch_one("SELECT 1")
        results["services"]["database"] = {"status": "up"}
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        results["services"]["database"] = {"status": "down", "error": str(e)}
        results["status"] = "degraded"
    
    # Check payment service
    try:
        await payment_service.get_balance()
        results["services"]["payments"] = {"status": "up"}
    except Exception as e:
        logger.error(f"Payment service health check failed: {e}")
        results["services"]["payments"] = {"status": "down", "error": str(e)}
        results["status"] = "degraded"
    
    results["response_time_ms"] = round((time.time() - start_time) * 1000)
    return results

@router.get("/verification-stats")
async def get_verification_stats(
    cyberherd_listener_service: CyberherdListenerService = Depends(get_cyberherd_listener_service)
):
    """Get statistics about event verification."""
    try:
        stats = await cyberherd_listener_service.get_verification_stats()
        return {
            "status": "success",
            "stats": stats
        }
    except Exception as e:
        logger.error(f"Error getting verification stats: {e}")
        raise HTTPException(status_code=500, detail="Error getting verification stats")

# Data model for NIP-05 verification request & response
class NIP05VerificationRequest(BaseModel):
    nip05: str
    pubkey: str

class NIP05VerificationResponse(BaseModel):
    is_valid: bool
    nip05: str
    pubkey: str
    details: Dict[str, Any]

@router.post("/verify-nip05", response_model=NIP05VerificationResponse)
async def verify_nip05(request: NIP05VerificationRequest):
    """Test NIP-05 verification for a given identifier and pubkey"""
    
    try:
        # Call the Verifier.verify_nip05 method to perform the verification
        is_valid = await Verifier.verify_nip05(request.nip05, request.pubkey)
        
        # Prepare the response with detailed information
        response = {
            "is_valid": is_valid,
            "nip05": request.nip05,
            "pubkey": request.pubkey,
            "details": {
                "verification_enabled": True,
                "verification_method": "direct",
                "timestamp": datetime.datetime.now().isoformat()
            }
        }
        
        # If validation failed, add additional details
        if not is_valid:
            # Parse the NIP-05 identifier to add more diagnostic info
            if '@' in request.nip05:
                name, domain = request.nip05.split('@', 1)
                response["details"]["name"] = name
                response["details"]["domain"] = domain
                response["details"]["well_known_url"] = f"https://{domain}/.well-known/nostr.json?name={name}"
            else:
                response["details"]["error"] = "Invalid NIP-05 format (missing @)"
        
        return response
    except Exception as e:
        # Provide detailed error information
        logger.exception(f"Error during NIP-05 verification: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error during NIP-05 verification: {str(e)}"
        )

# Also add a simple GET endpoint for browser testing
@router.get("/verify-nip05", response_model=NIP05VerificationResponse)
async def verify_nip05_get(
    nip05: str = Query(..., description="NIP-05 identifier (username@domain)"),
    pubkey: str = Query(..., description="Public key to verify against")
):
    """Test NIP-05 verification via GET request"""
    
    # Reuse the POST endpoint logic
    request = NIP05VerificationRequest(nip05=nip05, pubkey=pubkey)
    return await verify_nip05(request)
