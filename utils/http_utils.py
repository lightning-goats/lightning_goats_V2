"""HTTP utilities for common request patterns and error handling."""
import logging
import httpx
from typing import Any, Dict, Optional, Union, TypeVar, Callable
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type, before_log

logger = logging.getLogger(__name__)

# Create a TypeVar for the return type
T = TypeVar('T')

# Standard retry configuration for HTTP requests
http_retry = retry(
    reraise=True,
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=4, max=10),
    retry=retry_if_exception_type(httpx.RequestError),
    before=before_log(logger, logging.WARNING)
)

async def safe_http_request(
    method: str,
    url: str,
    client: httpx.AsyncClient,
    expected_status_code: Optional[int] = 200,
    raise_for_status: bool = True,
    log_response: bool = False,
    **kwargs
) -> httpx.Response:
    """
    Make an HTTP request with proper error handling and logging.
    
    Args:
        method: HTTP method (GET, POST, etc.)
        url: Request URL
        client: Async HTTP client
        expected_status_code: Status code expected for success
        raise_for_status: Whether to raise an exception for non-2xx status codes
        log_response: Whether to log the response content
        **kwargs: Additional arguments to pass to the request method
        
    Returns:
        HTTP Response object
    """
    try:
        logger.debug(f"Making {method} request to {url}")
        response = await client.request(method, url, **kwargs)
        
        if raise_for_status:
            response.raise_for_status()
            
        if expected_status_code and response.status_code != expected_status_code:
            logger.warning(f"Expected status code {expected_status_code} but got {response.status_code} from {url}")
            
        if log_response:
            logger.debug(f"Response from {url}: {response.text[:500]}...")
            
        return response
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP status error for {url}: {e.response.status_code} - {e.response.text}")
        raise
    except httpx.RequestError as e:
        logger.error(f"Request error for {url}: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error making request to {url}: {str(e)}")
        raise

async def parse_json_response(response: httpx.Response, fallback: Any = None) -> Any:
    """
    Parse JSON response with proper error handling.
    
    Args:
        response: HTTP response object
        fallback: Value to return if parsing fails
        
    Returns:
        Parsed JSON content or fallback
    """
    try:
        return response.json()
    except Exception as e:
        logger.error(f"Failed to parse JSON response: {e}")
        return fallback

# Create a shared HTTP client for the application
async def create_http_client(
    http2: bool = True,
    timeout: float = 30.0,
    limits: Optional[httpx.Limits] = None
) -> httpx.AsyncClient:
    """Create and configure a shared HTTP client."""
    return httpx.AsyncClient(
        http2=http2,
        timeout=timeout,
        limits=limits or httpx.Limits(max_connections=100, max_keepalive_connections=20)
    )
