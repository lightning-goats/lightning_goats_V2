import time
import logging
import asyncio
from enum import Enum
from typing import Callable, Any, Optional

logger = logging.getLogger(__name__)

class CircuitState(Enum):
    CLOSED = "closed"  # Normal operation, requests allowed
    OPEN = "open"      # Circuit broken, requests fail fast
    HALF_OPEN = "half_open"  # Testing if service is back

class CircuitBreaker:
    def __init__(self, 
                 failure_threshold: int = 5,
                 recovery_timeout: int = 30,
                 timeout_factor: int = 2,
                 max_timeout: int = 120):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.timeout_factor = timeout_factor
        self.max_timeout = max_timeout
        
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time = 0
        self.current_timeout = recovery_timeout
    
    async def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute a function with circuit breaker protection."""
        if self.state == CircuitState.OPEN:
            # Check if recovery timeout has elapsed
            if time.time() - self.last_failure_time > self.current_timeout:
                logger.info("Circuit half-open, allowing test request")
                self.state = CircuitState.HALF_OPEN
            else:
                raise Exception("Circuit open, request rejected")
        
        try:
            result = await func(*args, **kwargs)
            
            # Reset on success if in half-open state
            if self.state == CircuitState.HALF_OPEN:
                logger.info("Circuit test successful, closing circuit")
                self.reset()
                
            return result
            
        except Exception as e:
            self._handle_failure()
            raise e
    
    def _handle_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.state == CircuitState.HALF_OPEN or self.failure_count >= self.failure_threshold:
            # Open circuit and increase timeout
            self.state = CircuitState.OPEN
            self.current_timeout = min(self.current_timeout * self.timeout_factor, self.max_timeout)
            logger.warning(f"Circuit opened, timeout set to {self.current_timeout}s")
    
    def reset(self):
        """Reset the circuit breaker to closed state."""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.current_timeout = self.recovery_timeout
