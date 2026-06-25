"""
NeuralShield AI - Strategic Error Resilience for Threat Detection Pipeline
Dimension E: Error Resilience - Strategic Fallback Chain Orchestration v38

Implements:
- Priority-based threat detection degradation strategies
- Deadline propagation with operation cancellation
- Fallback chain orchestration with SLO awareness
- Threat-specific graceful degradation policies
- Happy path behavior 100% preserved - all instrumentation OPT-IN

STABILITY: STABLE
BACKWARD COMPATIBLE: YES
"""

import time
import threading
import functools
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, Union
from datetime import datetime, timedelta

# Configure logging - disabled by default (OPT-IN)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class ThreatDetectionPriority(Enum):
    """Priority levels for threat detection operations."""
    CRITICAL = 0    # Must never fail - prompt injection, jailbreak
    HIGH = 1        # High importance - malware, backdoors
    MEDIUM = 2      # Standard detection
    LOW = 3         # Optional enhancements
    BEST_EFFORT = 4 # Cosmetic/analytics only


class FallbackStrategy(Enum):
    """Fallback strategies for graceful degradation."""
    FAIL_CLOSED = "fail_closed"          # Block on failure (secure default)
    FAIL_OPEN = "fail_open"              # Allow on failure (availability)
    FALLBACK_TO_SIMPLE = "simple"        # Use simpler detector
    FALLBACK_TO_CACHED = "cached"        # Use cached result
    FALLBACK_TO_CONSERVATIVE = "conservative"  # Err on side of caution
    RETRY_WITH_BACKOFF = "retry"         # Retry operation


@dataclass
class OperationDeadline:
    """Deadline tracking with propagation support."""
    deadline_time: float
    operation_name: str
    parent_deadline: Optional['OperationDeadline'] = None
    created_at: float = field(default_factory=time.time)
    
    @property
    def remaining_ms(self) -> float:
        """Get remaining time in milliseconds."""
        return max(0.0, (self.deadline_time - time.time()) * 1000)
    
    @property
    def expired(self) -> bool:
        """Check if deadline has expired."""
        return time.time() > self.deadline_time
    
    @classmethod
    def from_timeout(cls, timeout_ms: float, operation_name: str, 
                     parent: Optional['OperationDeadline'] = None) -> 'OperationDeadline':
        """Create deadline from timeout in milliseconds."""
        deadline = time.time() + (timeout_ms / 1000.0)
        # Respect parent deadline if it's earlier
        if parent and parent.deadline_time < deadline:
            deadline = parent.deadline_time
        return cls(deadline, operation_name, parent)
    
    def create_child(self, timeout_ms: float, operation_name: str) -> 'OperationDeadline':
        """Create child deadline respecting parent deadline."""
        return self.from_timeout(timeout_ms, operation_name, self)


@dataclass
class FallbackChainResult:
    """Result from fallback chain execution."""
    success: bool
    result: Any
    strategy_used: Optional[FallbackStrategy]
    fallback_level: int
    total_time_ms: float
    deadline_expired: bool = False
    error: Optional[Exception] = None


class DeadlineExceededError(Exception):
    """Raised when operation deadline is exceeded."""
    def __init__(self, operation: str, remaining_ms: float, deadline_ms: float):
        self.operation = operation
        self.remaining_ms = remaining_ms
        self.deadline_ms = deadline_ms
        super().__init__(f"Operation '{operation}' exceeded deadline by {abs(remaining_ms):.1f}ms")


class ThreatDetectionFallbackOrchestrator:
    """
    Orchestrates fallback chains for threat detection with priority awareness.
    
    All operations are OPT-IN wrappers - existing code works without modification.
    Happy path behavior is 100% preserved when no errors occur.
    """
    
    def __init__(self, default_timeout_ms: float = 5000.0):
        self.default_timeout_ms = default_timeout_ms
        self._fallback_chains: Dict[str, List[Tuple[FallbackStrategy, Callable]]] = {}
        self._priority_configs: Dict[ThreatDetectionPriority, Dict] = {}
        self._lock = threading.RLock()
        self._initialize_default_configs()
    
    def _initialize_default_configs(self) -> None:
        """Initialize default priority-based configurations."""
        self._priority_configs = {
            ThreatDetectionPriority.CRITICAL: {
                "timeout_ms": 10000.0,
                "max_retries": 3,
                "strategy": FallbackStrategy.FAIL_CLOSED,
                "allow_degradation": False,
                "retry_backoff_ms": [100, 200, 400]
            },
            ThreatDetectionPriority.HIGH: {
                "timeout_ms": 5000.0,
                "max_retries": 2,
                "strategy": FallbackStrategy.FALLBACK_TO_CONSERVATIVE,
                "allow_degradation": True,
                "retry_backoff_ms": [50, 100]
            },
            ThreatDetectionPriority.MEDIUM: {
                "timeout_ms": 2000.0,
                "max_retries": 2,
                "strategy": FallbackStrategy.FALLBACK_TO_SIMPLE,
                "allow_degradation": True,
                "retry_backoff_ms": [50, 100]
            },
            ThreatDetectionPriority.LOW: {
                "timeout_ms": 1000.0,
                "max_retries": 1,
                "strategy": FallbackStrategy.FAIL_OPEN,
                "allow_degradation": True,
                "retry_backoff_ms": [50]
            },
            ThreatDetectionPriority.BEST_EFFORT: {
                "timeout_ms": 500.0,
                "max_retries": 0,
                "strategy": FallbackStrategy.FAIL_OPEN,
                "allow_degradation": True,
                "retry_backoff_ms": []
            }
        }
    
    def register_fallback_chain(self, operation_name: str,
                                primary: Callable,
                                fallbacks: List[Tuple[FallbackStrategy, Callable]]) -> None:
        """
        Register a fallback chain for an operation.
        
        Args:
            operation_name: Name of the operation
            primary: Primary implementation
            fallbacks: List of (strategy, fallback_callable)
        """
        with self._lock:
            self._fallback_chains[operation_name] = [(FallbackStrategy.RETRY_WITH_BACKOFF, primary)] + fallbacks
            logger.debug(f"Registered fallback chain for {operation_name} with {len(fallbacks) + 1} levels")
    
    def get_config_for_priority(self, priority: ThreatDetectionPriority) -> Dict:
        """Get configuration for a priority level."""
        return self._priority_configs.get(priority, self._priority_configs[ThreatDetectionPriority.MEDIUM])
    
    def execute_with_fallback(self,
                              operation_name: str,
                              *args,
                              priority: ThreatDetectionPriority = ThreatDetectionPriority.MEDIUM,
                              deadline: Optional[OperationDeadline] = None,
                              **kwargs) -> FallbackChainResult:
        """
        Execute operation with fallback chain orchestration.
        
        Happy path: Primary function executes normally, no overhead.
        Error path: Falls through configured strategies gracefully.
        """
        start_time = time.time()
        config = self.get_config_for_priority(priority)
        
        # Create deadline if not provided
        if deadline is None:
            deadline = OperationDeadline.from_timeout(
                config["timeout_ms"], operation_name
            )
        
        # Check deadline first
        if deadline and deadline.expired:
            logger.warning(f"Deadline already exceeded for {operation_name}")
            return FallbackChainResult(
                success=False,
                result=self._get_degraded_result(priority, config["strategy"]),
                strategy_used=config["strategy"],
                fallback_level=0,
                total_time_ms=(time.time() - start_time) * 1000,
                deadline_expired=True,
                error=DeadlineExceededError(operation_name, deadline.remaining_ms, config["timeout_ms"])
            )
        
        chain = self._fallback_chains.get(operation_name, [])
        if not chain:
            # No fallbacks registered - execute directly
            try:
                result = args[0](*args[1:], **kwargs) if args else None
                return FallbackChainResult(
                    success=True,
                    result=result,
                    strategy_used=None,
                    fallback_level=0,
                    total_time_ms=(time.time() - start_time) * 1000
                )
            except Exception as e:
                return FallbackChainResult(
                    success=False,
                    result=None,
                    strategy_used=None,
                    fallback_level=0,
                    total_time_ms=(time.time() - start_time) * 1000,
                    error=e
                )
        
        last_error = None
        
        for level, (strategy, handler) in enumerate(chain):
            if deadline.expired:
                logger.warning(f"Deadline exceeded for {operation_name} at level {level}")
                return FallbackChainResult(
                    success=False,
                    result=self._get_degraded_result(priority, strategy),
                    strategy_used=strategy,
                    fallback_level=level,
                    total_time_ms=(time.time() - start_time) * 1000,
                    deadline_expired=True,
                    error=DeadlineExceededError(operation_name, deadline.remaining_ms, config["timeout_ms"])
                )
            
            try:
                if strategy == FallbackStrategy.RETRY_WITH_BACKOFF:
                    result = self._execute_with_retry(
                        handler, config, deadline, *args, **kwargs
                    )
                else:
                    result = handler(*args, **kwargs)
                
                if level > 0:
                    logger.info(f"Operation {operation_name} succeeded at fallback level {level} using {strategy}")
                
                return FallbackChainResult(
                    success=True,
                    result=result,
                    strategy_used=strategy,
                    fallback_level=level,
                    total_time_ms=(time.time() - start_time) * 1000
                )
            
            except DeadlineExceededError:
                raise
            except Exception as e:
                last_error = e
                logger.debug(f"Fallback level {level} failed for {operation_name}: {e}")
                continue
        
        # All fallbacks failed - apply final strategy
        final_result = self._get_degraded_result(priority, config["strategy"])
        logger.warning(f"All fallbacks failed for {operation_name}, applying {config['strategy']}")
        
        return FallbackChainResult(
            success=False,
            result=final_result,
            strategy_used=config["strategy"],
            fallback_level=len(chain),
            total_time_ms=(time.time() - start_time) * 1000,
            error=last_error
        )
    
    def _execute_with_retry(self, handler: Callable, config: Dict,
                            deadline: OperationDeadline, *args, **kwargs) -> Any:
        """Execute handler with retry and exponential backoff."""
        max_retries = config["max_retries"]
        backoffs = config["retry_backoff_ms"]
        
        last_error = None
        for attempt in range(max_retries + 1):
            if deadline.expired:
                raise DeadlineExceededError(
                    handler.__name__ if hasattr(handler, '__name__') else 'unknown',
                    deadline.remaining_ms, config["timeout_ms"]
                )
            
            try:
                return handler(*args, **kwargs)
            except Exception as e:
                last_error = e
                if attempt < max_retries and attempt < len(backoffs):
                    sleep_ms = min(backoffs[attempt], deadline.remaining_ms * 0.5)
                    if sleep_ms > 0:
                        time.sleep(sleep_ms / 1000.0)
                    continue
                raise
        
        raise last_error
    
    def _get_degraded_result(self, priority: ThreatDetectionPriority, 
                             strategy: FallbackStrategy) -> Any:
        """Get appropriate degraded result based on priority and strategy."""
        if strategy == FallbackStrategy.FAIL_CLOSED:
            # Secure default - assume threat detected
            return {"threat_detected": True, "confidence": 0.5, "degraded": True, "reason": "fallback_fail_closed"}
        elif strategy == FallbackStrategy.FAIL_OPEN:
            # Availability default - assume safe
            return {"threat_detected": False, "confidence": 0.0, "degraded": True, "reason": "fallback_fail_open"}
        elif strategy == FallbackStrategy.FALLBACK_TO_CONSERVATIVE:
            # Conservative - flag for review
            return {"threat_detected": True, "confidence": 0.3, "degraded": True, "reason": "fallback_conservative", "needs_review": True}
        else:
            return {"threat_detected": False, "confidence": 0.0, "degraded": True, "reason": "fallback_default"}


def with_deadline_propagation(timeout_ms: float = 2000.0,
                              priority: ThreatDetectionPriority = ThreatDetectionPriority.MEDIUM):
    """
    Decorator for deadline propagation and enforcement.
    
    OPT-IN: Only applies to decorated functions.
    Happy path behavior 100% preserved.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Extract deadline from kwargs or create new
            deadline = kwargs.pop('deadline', None)
            
            if deadline is None:
                deadline = OperationDeadline.from_timeout(timeout_ms, func.__name__)
            else:
                # Create child deadline respecting parent
                deadline = deadline.create_child(timeout_ms, func.__name__)
            
            if deadline.expired:
                raise DeadlineExceededError(func.__name__, deadline.remaining_ms, timeout_ms)
            
            # Pass deadline down to child calls
            kwargs['deadline'] = deadline
            return func(*args, **kwargs)
        return wrapper
    return decorator


def with_graceful_degradation(fallback_result: Any = None,
                              priority: ThreatDetectionPriority = ThreatDetectionPriority.MEDIUM):
    """
    Decorator for graceful function degradation.
    
    OPT-IN: Only applies to decorated functions.
    Returns fallback_result on exception without breaking callers.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logger.debug(f"Graceful degradation for {func.__name__}: {e}")
                if fallback_result is not None:
                    return fallback_result
                # Return priority-appropriate default
                if priority in (ThreatDetectionPriority.CRITICAL, ThreatDetectionPriority.HIGH):
                    return {"threat_detected": True, "confidence": 0.5, "degraded": True}
                return {"threat_detected": False, "confidence": 0.0, "degraded": True}
        return wrapper
    return decorator


# Global orchestrator instance (lazy initialization)
_global_orchestrator: Optional[ThreatDetectionFallbackOrchestrator] = None


def get_orchestrator() -> ThreatDetectionFallbackOrchestrator:
    """Get the global fallback orchestrator instance."""
    global _global_orchestrator
    if _global_orchestrator is None:
        _global_orchestrator = ThreatDetectionFallbackOrchestrator()
    return _global_orchestrator


# Export public API
__all__ = [
    'ThreatDetectionPriority',
    'FallbackStrategy',
    'OperationDeadline',
    'FallbackChainResult',
    'DeadlineExceededError',
    'ThreatDetectionFallbackOrchestrator',
    'with_deadline_propagation',
    'with_graceful_degradation',
    'get_orchestrator',
]
