"""
Router package for Lightning Goats API.

This package contains all API route handlers organized by domain:
- payment_routes: Payment-related endpoints
- cyberherd_routes: CyberHerd management endpoints
- goat_routes: Goat feeding and stats endpoints
- messaging_routes: Client messaging endpoints
- system_routes: System configuration and health endpoints
"""

from . import payment_routes
from . import cyberherd_routes
from . import goat_routes
from . import messaging_routes
# Other route modules will be imported here as they are created
