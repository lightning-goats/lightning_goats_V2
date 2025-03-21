import logging
from typing import Dict, Any, Optional
from services.openhab_service import OpenHABService
from services.database_service import DatabaseCache

logger = logging.getLogger(__name__)

class GoatStateService:
    """Service for managing goat-related state."""
    
    def __init__(self, openhab_service: OpenHABService, cache: DatabaseCache):
        self.openhab = openhab_service
        self.cache = cache
        
    async def get_feeder_override_status(self) -> bool:
        """Check if feeder override is enabled."""
        try:
            state = await self.openhab.get_item_state("FeederOverride")
            return state == 'ON'
        except Exception as e:
            logger.error(f"Error checking feeder status: {e}")
            raise
            
    async def trigger_feeder(self) -> bool:
        """Trigger the goat feeder."""
        try:
            rule_id = "88bd9ec4de"  # Hard-coded rule ID
            return await self.openhab.trigger_rule(rule_id)
        except Exception as e:
            logger.error(f"Error triggering feeder: {e}")
            raise
    
    async def get_feedings_count(self) -> int:
        """Get the number of goat feedings today."""
        try:
            state_text = await self.openhab.get_item_state("GoatFeedings")
            try:
                feedings = int(state_text)
            except ValueError as e:
                logger.warning(f"Failed to parse GoatFeedings state '{state_text}': {e}. Defaulting to 0.")
                feedings = 0
            
            logger.info(f"Returning latest GoatFeedings state: {feedings}")
            return feedings
        except Exception as e:
            logger.error(f"Unexpected error retrieving GoatFeedings state: {e}")
            raise
            
    async def get_sats_today(self) -> Dict[str, int]:
        """Get GoatSats state, preferring cached value if available."""
        try:
            # Try to get from cache first
            cached_state = await self.cache.get("goat_sats_state")
            if cached_state is not None:
                logger.debug("Using cached GoatSats state")
                return {"sum_goat_sats": cached_state}

            # If not in cache, fetch from OpenHAB
            state_text = await self.openhab.get_item_state("GoatSats")
            
            try:
                latest_state = int(float(state_text))
                # Cache the result without TTL
                await self.cache.set("goat_sats_state", latest_state)
                logger.info(f"Updated cached GoatSats state to: {latest_state}")
                return {"sum_goat_sats": latest_state}
            except ValueError as e:
                logger.warning(f"Failed to parse GoatSats state '{state_text}': {e}. Defaulting to 0.")
                return {"sum_goat_sats": 0}
        
        except Exception as e:
            logger.error(f"Unexpected error retrieving GoatSats state: {e}")
            raise
    
    async def update_sats(self, sats_received: int) -> None:
        """Update GoatSats state in both cache and OpenHAB."""
        try:
            # Get current state (preferring cache)
            current_state_data = await self.get_sats_today()
            current_state = current_state_data["sum_goat_sats"]
            new_state = current_state + sats_received
            
            # Update OpenHAB
            await self.openhab.set_item_state("GoatSats", str(new_state))
            
            # Update cache without TTL
            await self.cache.set("goat_sats_state", new_state)
            logger.info(f"Updated GoatSats state to {new_state} (cache + OpenHAB)")
        
        except Exception as e:
            logger.error(f"Unexpected error updating GoatSats: {e}")
            raise
            
    async def set_sats(self, new_amount: int) -> bool:
        """Manually set the sats counter to a specific value."""
        try:
            # Update OpenHAB
            success = await self.openhab.set_item_state("GoatSats", str(new_amount))
            
            if not success:
                return False
            
            # Update cache without TTL
            await self.cache.set("goat_sats_state", new_amount)
            logger.info(f"Manually set GoatSats in OpenHAB to {new_amount} sats")
            return True
        
        except Exception as e:
            logger.error(f"Unexpected error setting GoatSats: {e}")
            return False
