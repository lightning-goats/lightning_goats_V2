import logging
import httpx
from typing import Tuple, Optional, Union, Any

logger = logging.getLogger(__name__)

class OpenHABService:
    def __init__(self, openhab_url: str, auth: Tuple[str, str], http_client=None):
        self.openhab_url = openhab_url
        self.auth = auth
        self.http_client = http_client
        
    async def initialize(self, http_client=None):
        if http_client:
            self.http_client = http_client
        else:
            self.http_client = httpx.AsyncClient(http2=True)
    
    async def close(self):
        if self.http_client and self.http_client is not httpx:
            await self.http_client.aclose()
            
    async def get_item_state(self, item_name: str) -> str:
        """Get the state of an openHAB item as a string"""
        headers = {"accept": "text/plain"}
        get_url = f"{self.openhab_url}/rest/items/{item_name}/state"
        
        try:
            response = await self.http_client.get(get_url, headers=headers, auth=self.auth)
            response.raise_for_status()
            return response.text.strip()
        except httpx.HTTPError as e:
            logger.error(f"HTTP error retrieving {item_name} state from OpenHAB: {e}")
            raise Exception(f"Failed to fetch {item_name} state from OpenHAB")
        except Exception as e:
            logger.error(f"Unexpected error retrieving {item_name} state: {e}")
            raise
    
    async def get_item_state_as_int(self, item_name: str, default: int = 0) -> int:
        """Get the state of an openHAB item as an integer"""
        try:
            state_text = await self.get_item_state(item_name)
            return int(float(state_text))
        except (ValueError, TypeError) as e:
            logger.warning(f"Failed to parse {item_name} state as int: {e}. Using default: {default}")
            return default
        except Exception as e:
            logger.error(f"Error getting {item_name} state as int: {e}")
            raise
    
    async def set_item_state(self, item_name: str, state: str) -> bool:
        """Set the state of an openHAB item"""
        headers = {
            "accept": "application/json",
            "Content-Type": "text/plain"
        }
        put_url = f"{self.openhab_url}/rest/items/{item_name}/state"
        
        try:
            response = await self.http_client.put(put_url, headers=headers, auth=self.auth, content=state)
            response.raise_for_status()
            return True
        except httpx.HTTPError as e:
            logger.error(f"HTTP error setting {item_name} state in OpenHAB: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error setting {item_name} state: {e}")
            raise
    
    async def trigger_rule(self, rule_id: str) -> bool:
        """Trigger an openHAB rule by ID"""
        try:
            response = await self.http_client.post(
                f'{self.openhab_url}/rest/rules/{rule_id}/runnow',
                auth=self.auth
            )
            response.raise_for_status()
            return response.status_code == 200
        except httpx.HTTPError as e:
            logger.error(f"HTTP error triggering rule {rule_id}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error triggering rule {rule_id}: {e}")
            raise
