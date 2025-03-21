import logging
import httpx
from typing import Tuple

logger = logging.getLogger(__name__)

class PriceService:
    """Service for handling price-related operations."""
    
    def __init__(self, openhab_url: str, auth_credentials: Tuple[str, str], http_client=None):
        self.openhab_url = openhab_url
        self.auth = auth_credentials
        self.http_client = http_client
        
    async def initialize(self, http_client=None):
        if http_client:
            self.http_client = http_client
        else:
            self.http_client = httpx.AsyncClient(http2=True)
    
    async def close(self):
        if self.http_client and not self.http_client is httpx:
            await self.http_client.aclose()
            
    async def get_btc_price(self) -> float:
        """Fetch the current BTC price in USD from OpenHAB."""
        try:
            response = await self.http_client.get(
                f'{self.openhab_url}/rest/items/BTC_Price_Output/state',
                auth=self.auth
            )
            response.raise_for_status()
            btc_price = float(response.text)
            return btc_price
        except httpx.HTTPError as e:
            logger.error(f"HTTP error fetching BTC price: {e}")
            raise
        except Exception as e:
            logger.error(f"Error fetching BTC price: {e}")
            raise
    
    async def convert_usd_to_sats(self, usd_amount: float) -> int:
        """Convert USD amount to satoshis using current BTC price."""
        try:
            # Get the current BTC price in USD
            btc_price = await self.get_btc_price()

            # Calculate the number of satoshis (1 BTC = 100,000,000 sats)
            sats = int(round((usd_amount / btc_price) * 100_000_000))
            return sats
        except Exception as e:
            logger.error(f"Error converting ${usd_amount} to sats: {e}")
            raise
