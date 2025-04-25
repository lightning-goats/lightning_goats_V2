from fastapi import APIRouter, HTTPException, Depends, Path, Body, Query
from typing import Dict, Any, List, Optional
import logging
from datetime import datetime, timedelta
import re
from pydantic import BaseModel

from services.cyberherd_service import CyberHerdService
from services.database_service import DatabaseService
from models import CyberHerdData
from utils.cyberherd_module import MetadataFetcher, generate_nprofile, DEFAULT_RELAYS

# Initialize logger
logger = logging.getLogger(__name__)

# Create router with prefix and tags
router = APIRouter(
    prefix="/cyberherd",
    tags=["cyberherd"],
    responses={404: {"description": "Not found"}},
)

# Store service instances for dependency injection
_cyberherd_service: Optional[CyberHerdService] = None
_database_service: Optional[DatabaseService] = None

def initialize_services(cyberherd_service: CyberHerdService, database_service: Optional[DatabaseService] = None):
    """Initialize the services needed for this router."""
    global _cyberherd_service, _database_service
    _cyberherd_service = cyberherd_service
    _database_service = database_service

# Dependency function to get service
async def get_cyberherd_service() -> CyberHerdService:
    if _cyberherd_service is None:
        raise HTTPException(status_code=500, detail="CyberHerdService not initialized")
    return _cyberherd_service

# Add dependency for database service
async def get_database_service() -> DatabaseService:
    if _database_service is None:
        raise HTTPException(status_code=500, detail="DatabaseService not initialized")
    return _database_service

@router.get("/members")
async def get_members(
    cyberherd_service: CyberHerdService = Depends(get_cyberherd_service)
) -> List[Dict[str, Any]]:
    """
    Get all current CyberHerd members.
    
    Returns:
    - List of all CyberHerd members with their details
    """
    try:
        return await cyberherd_service.get_all_members()
    except Exception as e:
        logger.error(f"Error retrieving cyber herd members: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve CyberHerd members")

@router.post("/members")
async def update_members(
    data: List[CyberHerdData],
    cyberherd_service: CyberHerdService = Depends(get_cyberherd_service)
) -> Dict[str, Any]:
    """
    Add or update members in the CyberHerd.
    
    - **data**: List of member data to add or update
    
    Returns:
    - Status information and count of new members added
    """
    try:
        result = await cyberherd_service.update_cyberherd(data)
        
        if result["status"] == "error":
            raise HTTPException(status_code=500, detail=result["message"])
            
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update cyber herd: {e}")
        raise HTTPException(status_code=500, detail="Failed to update CyberHerd")

@router.delete("/members/{lud16}")
async def delete_member(
    lud16: str = Path(..., description="Lightning address of the member to delete"),
    cyberherd_service: CyberHerdService = Depends(get_cyberherd_service)
) -> Dict[str, Any]:
    """
    Delete a member from the CyberHerd by Lightning address.
    
    - **lud16**: Lightning address of the member to delete
    
    Returns:
    - Status message confirming deletion
    """
    try:
        logger.info(f"Attempting to delete member with lud16: {lud16}")
        success = await cyberherd_service.delete_member(lud16)
        
        if not success:
            logger.warning(f"No member found with lud16: {lud16}")
            raise HTTPException(status_code=404, detail="Member not found")
            
        logger.info(f"Member with lud16 {lud16} deleted successfully")
        return {"status": "success", "message": f"Member with lud16 {lud16} deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete member: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete CyberHerd member")

@router.get("/reset")
async def reset_cyberherd(
    cyberherd_service: CyberHerdService = Depends(get_cyberherd_service)
) -> Dict[str, Any]:
    """
    Reset the CyberHerd by deleting all members and targets.
    
    Returns:
    - Status message confirming reset
    """
    try:
        result = await cyberherd_service.reset_cyberherd()
        
        if not result["success"]:
            raise HTTPException(status_code=500, detail=result["message"])
            
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resetting CyberHerd: {e}")
        raise HTTPException(status_code=500, detail="Failed to reset CyberHerd")

@router.get("/spots_remaining")
async def get_spots_remaining(
    cyberherd_service: CyberHerdService = Depends(get_cyberherd_service)
) -> Dict[str, int]:
    """
    Get the number of spots remaining in the CyberHerd.
    
    Returns:
    - **spots_remaining**: Number of spots remaining
    """
    try:
        spots_remaining = await cyberherd_service.get_remaining_spots()
        return {"spots_remaining": spots_remaining}
    except Exception as e:
        logger.error(f"Error getting spots remaining: {e}")
        raise HTTPException(status_code=500, detail="Failed to get remaining spots")

@router.get("/dm_notifications")
async def get_dm_notifications(
    notification_type: Optional[str] = None,
    since: Optional[str] = None,
    limit: int = 100,
    database_service: DatabaseService = Depends(get_database_service)
):
    """
    Get a list of users who have been sent DM notifications.
    
    Args:
        notification_type: Filter by notification type (e.g., 'missing_nip05', 'invalid_nip05')
        since: ISO format datetime string to filter notifications since a specific time
        limit: Maximum number of records to return (default: 100)
    """
    try:
        # Convert since parameter to datetime if provided
        since_dt = None
        if since:
            try:
                since_dt = datetime.fromisoformat(since)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid 'since' parameter format. Use ISO format (YYYY-MM-DDTHH:MM:SS)")
        
        # Query the database for DM notifications
        results = await database_service.get_dm_notifications(
            notification_type=notification_type,
            since=since_dt,
            limit=limit
        )
        
        return {
            "count": len(results),
            "notifications": results
        }
    except Exception as e:
        logger.error(f"Error retrieving DM notifications: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve DM notifications")

@router.get("/member/{pubkey}", response_model=Dict[str, Any])
async def get_cyberherd_member(
    pubkey: str = Path(..., description="Public key of the member to retrieve"),
    cyberherd_service: CyberHerdService = Depends(get_cyberherd_service)
):
    """Get a specific CyberHerd member by pubkey."""
    member = await cyberherd_service.get_member(pubkey)
    if not member:
        raise HTTPException(status_code=404, detail=f"Member with pubkey {pubkey} not found")
    
    return {
        "status": "success",
        "member": member
    }

def validate_pub_key(pubkey: str) -> bool:
    """Validate that a string is a valid hex pubkey format."""
    # Check if it's a valid hex string of correct length (64 characters for Nostr)
    return bool(re.match(r'^[0-9a-f]{64}$', pubkey.lower()))

async def check_user_participation(
    pubkey: str, 
    database_service: DatabaseService
) -> dict:
    """
    Check if a user has already participated in CyberHerd via reposts or zaps.
    Returns a dict with participation info.
    """
    result = {
        "has_reposted": False,
        "has_zapped": False,
        "eligible": False,
        "kinds": []
    }
    
    # Check for reposts (kind 6)
    try:
        user_reposts = await database_service.get_user_reposted_notes(pubkey)
        if user_reposts:
            result["has_reposted"] = True
            result["kinds"].append(6)
    except Exception as e:
        logger.warning(f"Error checking reposts for {pubkey}: {e}")
    
    # Check for zaps (kind 9734) through member record
    try:
        member = await database_service.get_cyberherd_member(pubkey)
        if member:
            kinds_str = member.get("kinds", "")
            if kinds_str:
                kinds = [int(k.strip()) for k in kinds_str.split(',') if k.strip().isdigit()]
                if 9734 in kinds:
                    result["has_zapped"] = True
                    if 9734 not in result["kinds"]:
                        result["kinds"].append(9734)
    except Exception as e:
        logger.warning(f"Error checking zaps for {pubkey}: {e}")
    
    # User is eligible if they have either reposted or zapped
    result["eligible"] = result["has_reposted"] or result["has_zapped"]
    
    return result

@router.post("/add_by_pubkey", response_model=Dict[str, Any])
async def add_member_by_pubkey(
    pubkey: str = Query(..., description="The Nostr pubkey in hex format to add to the CyberHerd"),
    force: bool = Query(False, description="Force add even if user hasn't participated via reposts or zaps"),
    db: DatabaseService = Depends(get_database_service),
    cyberherd_service: CyberHerdService = Depends(get_cyberherd_service)
):
    """Add a new member to the CyberHerd using just their pubkey, checking for participation first."""
    try:
        # Check if pubkey is valid
        if not validate_pub_key(pubkey):
            raise HTTPException(status_code=400, detail="Invalid pubkey format")
        
        # Check if the user already exists in CyberHerd
        existing_member = await cyberherd_service.get_member(pubkey)
        if existing_member:
            return {
                "status": "success", 
                "message": "Member already exists in CyberHerd", 
                "pubkey": pubkey,
                "member": existing_member
            }
        
        # Check if the user has participated (repost or zap)
        participation = await check_user_participation(pubkey, db)
        
        # If user hasn't participated and force is not enabled, return an error
        if not participation["eligible"] and not force:
            raise HTTPException(
                status_code=400, 
                detail=f"Member has not participated via reposts or zaps. Use force=true to add anyway."
            )
        
        # Fetch metadata for this pubkey from relays
        fetcher = MetadataFetcher()
        metadata = await fetcher.fetch_metadata(pubkey, DEFAULT_RELAYS)
        
        if not metadata:
            raise HTTPException(
                status_code=400,
                detail=f"Could not fetch metadata for pubkey. Please try again later."
            )
        
        # Determine kinds based on participation
        kinds_str = ",".join(map(str, participation["kinds"])) if participation["kinds"] else "6"
        
        # If forcing without participation, default to kind 6 (repost)
        if not participation["eligible"] and force:
            kinds_str = "6"
        
        # Create the member data with available information
        member_data = CyberHerdData(
            pubkey=pubkey,
            display_name=metadata.get("name", "Anon") if metadata else "Anon",
            nprofile=generate_nprofile(pubkey, DEFAULT_RELAYS[:2]),
            lud16=metadata.get("lud16", "") if metadata else "",
            picture=metadata.get("picture", "") if metadata else "",
            kinds=kinds_str,
            event_id="",
            note="Added manually via API" + (" (force)" if force and not participation["eligible"] else ""),
            relays=DEFAULT_RELAYS[:3]
        )
        
        # Add the member to the CyberHerd
        success = await cyberherd_service.add_member(member_data)
        
        if success:
            return {
                "status": "success", 
                "message": "Member added successfully", 
                "pubkey": pubkey,
                "participation": participation
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to add member")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding member by pubkey: {e}")
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
