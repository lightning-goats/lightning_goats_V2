"""Environment utilities for loading and validating environment variables."""
import os
from typing import Dict, List, Any, Optional, Union
from dotenv import load_dotenv
import logging

logger = logging.getLogger(__name__)

def load_env_vars(required_vars: List[str], optional_vars: Optional[List[str]] = None, 
                  dotenv_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load environment variables from .env file and validate required variables.
    
    Args:
        required_vars: List of environment variable names that must be present
        optional_vars: List of optional environment variable names
        dotenv_path: Path to .env file, if not using default location
        
    Returns:
        Dictionary with environment variables as key-value pairs
        
    Raises:
        ValueError: If any required variables are missing
    """
    # Load variables from .env file if it exists
    load_dotenv(dotenv_path)
    
    # Check for missing required variables
    missing_vars = [var for var in required_vars if os.getenv(var) is None]
    if missing_vars:
        raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")
        
    # Create result dict with all required variables
    result = {var: os.getenv(var) for var in required_vars}
    
    # Add optional variables if specified and present
    if optional_vars:
        for var in optional_vars:
            value = os.getenv(var)
            if value is not None:
                result[var] = value
    
    return result

def get_env_int(name: str, default: Optional[int] = None) -> int:
    """Get environment variable as integer with optional default."""
    value = os.getenv(name)
    if value is None:
        if default is None:
            raise ValueError(f"Environment variable {name} not set and no default provided")
        return default
    try:
        return int(value)
    except ValueError:
        if default is not None:
            logger.warning(f"Invalid integer value for {name}: '{value}'. Using default {default}")
            return default
        raise ValueError(f"Invalid integer value for {name}: '{value}'")

def get_env_bool(name: str, default: Optional[bool] = None) -> bool:
    """Get environment variable as boolean with optional default."""
    value = os.getenv(name)
    if value is None:
        if default is None:
            raise ValueError(f"Environment variable {name} not set and no default provided")
        return default
    
    true_values = ('true', 'yes', '1', 'y', 't')
    false_values = ('false', 'no', '0', 'n', 'f')
    
    if value.lower() in true_values:
        return True
    if value.lower() in false_values:
        return False
    
    if default is not None:
        logger.warning(f"Invalid boolean value for {name}: '{value}'. Using default {default}")
        return default
    raise ValueError(f"Invalid boolean value for {name}: '{value}'")
