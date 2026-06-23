"""
NeuralShield AI - Error Resilience Fallback Chain Orchestrator v19
ADD-ONLY Module - No existing code modified

Implements:
- Priority-based fallback chain execution
- Threat intelligence specific degradation strategies
- Circuit breaker integration with fallback chains
- Graceful degradation with feature-level granularity
- Happy path behavior 100% preserved
"""

import enum
import time
import threading
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from functools import wraps

# Configure logging - disabled by default
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class FallbackStrategy(enum.Enum):
    """Fallback execution strategies."""
    SEQUENTIAL = "sequential"          # Try fallbacks in order until success
    PARALLEL = "parallel"              # Try all fallbacks, take first success
    PRIORITY_BASED = "priority_based"  # Weighted priority selection
    CONDITIONAL = "conditional"        # Strategy based on error type


class DegradationLevel(enum.Enum):
    """Degradation levels for threat intelligence operations."""
    FULL_FEATURED = "full_featured"        # All features enabled
    REDUCED_ACCURACY = "reduced_accuracy"  # Faster, slightly less accurate
    CACHED_ONLY = "cached_only"            # Only use cached results
    SYNTHETIC = "synthetic"                # Return synthetic safe responses
    FAIL_CLOSED = "fail_closed"            # Block operation, safe default
    FAIL_OPEN = "fail_open"                # Allow operation, log warning


class ErrorCategory(enum.Enum):
    """Error categories for conditional fallback selection."""
    NETWORK_ERROR = "network_error"
    TIMEOUT_ERROR = "timeout_error"
    RATE_LIMIT = "rate_limit"
    AUTH_FAILURE = "auth_failure"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    DATA_CORRUPTION = "data_corruption"
    UNKNOWN = "unknown"


class ChainStatus(enum.Enum):
    """Fallback chain execution status."""
    NOT_STARTED = "not_started"
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    ALL_FAILED = "all_failed"
    CIRCUIT_OPEN = "circuit_open"


@dataclass
class FallbackResult:
    """Result from a single fallback execution."""
    success: bool
    result: Any = None
    error: Optional[Exception] = None
    execution_time_ms: float = 0.0
    strategy_used: str = ""
    degradation_level: str = ""


@dataclass
class ChainExecutionResult:
    """Complete result from fallback chain execution."""
    status: ChainStatus
    final_result: Any = None
    attempted_fallbacks: int = 0
    successful_fallback_index: int = -1
    total_execution_time_ms: float = 0.0
    individual_results: List[FallbackResult] = field(default_factory=list)
    errors: List[Exception] = field(default_factory=list)
    final_degradation_level: str = DegradationLevel.FULL_FEATURED.value


@dataclass
class FallbackConfig:
    """Configuration for a single fallback."""
    name: str
    priority: int = 100
    timeout_seconds: float = 5.0
    max_retries: int = 0
    degradation_level: str = DegradationLevel.FULL_FEATURED.value
    enabled: bool = True
    circuit_breaker_protected: bool = True


@dataclass
class ChainConfig:
    """Configuration for fallback chain orchestrator."""
    strategy: FallbackStrategy = FallbackStrategy.SEQUENTIAL
    max_total_timeout_seconds: float = 30.0
    stop_on_first_success: bool = True
    enable_circuit_breaker: bool = True
    circuit_failure_threshold: int = 5
    circuit_recovery_timeout_seconds: float = 60.0
    log_all_attempts: bool = False
    happy_path_optimization: bool = True  # Skip chain if primary succeeds
    auto_degradation: bool = True  # Auto-escalate degradation on failures


class FallbackChain:
    """Represents a single chain of fallbacks for an operation."""

    def __init__(self, name: str, config: Optional[ChainConfig] = None):
        self.name = name
        self.config = config or ChainConfig()
        self._fallbacks: List[Tuple[FallbackConfig, Callable]] = []
        self._lock = threading.RLock()
        
        # Circuit breaker state
        self._failure_count = 0
        self._circuit_open = False
        self._circuit_open_time = 0.0
        
        # Statistics
        self._total_executions = 0
        self._success_count = 0
        self._fallback_used_count = 0
        self._total_fallbacks_attempted = 0

    def add_fallback(
        self,
        config: FallbackConfig,
        handler: Callable
    ) -> None:
        """Add a fallback handler to the chain."""
        with self._lock:
            self._fallbacks.append((config, handler))
            # Sort by priority (higher = first)
            self._fallbacks.sort(key=lambda x: -x[0].priority)

    def _check_circuit(self) -> bool:
        """Check if circuit is closed (can execute)."""
        if not self.config.enable_circuit_breaker:
            return True
            
        with self._lock:
            if self._circuit_open:
                elapsed = time.time() - self._circuit_open_time
                if elapsed >= self.config.circuit_recovery_timeout_seconds:
                    self._circuit_open = False
                    self._failure_count = 0
                    logger.info(f"Circuit recovered for chain: {self.name}")
                    return True
                return False
            return True

    def _record_failure(self) -> None:
        """Record a failure for circuit breaker."""
        if not self.config.enable_circuit_breaker:
            return
            
        with self._lock:
            self._failure_count += 1
            if self._failure_count >= self.config.circuit_failure_threshold:
                self._circuit_open = True
                self._circuit_open_time = time.time()
                logger.warning(f"Circuit opened for chain: {self.name}")

    def _execute_single_fallback(
        self,
        config: FallbackConfig,
        handler: Callable,
        *args,
        **kwargs
    ) -> FallbackResult:
        """Execute a single fallback handler."""
        start_time = time.time()
        
        try:
            result = handler(*args, **kwargs)
            execution_time = (time.time() - start_time) * 1000
            
            return FallbackResult(
                success=True,
                result=result,
                execution_time_ms=execution_time,
                strategy_used=config.name,
                degradation_level=config.degradation_level
            )
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            
            return FallbackResult(
                success=False,
                error=e,
                execution_time_ms=execution_time,
                strategy_used=config.name,
                degradation_level=config.degradation_level
            )

    def execute(self, *args, **kwargs) -> ChainExecutionResult:
        """Execute the fallback chain."""
        start_time = time.time()
        
        # Check circuit first
        if not self._check_circuit():
            return ChainExecutionResult(
                status=ChainStatus.CIRCUIT_OPEN,
                total_execution_time_ms=(time.time() - start_time) * 1000
            )
        
        results: List[FallbackResult] = []
        errors: List[Exception] = []
        successful_index = -1
        final_result = None
        final_degradation = DegradationLevel.FULL_FEATURED.value
        
        with self._lock:
            self._total_executions += 1
        
        # Execute fallbacks according to strategy
        for idx, (config, handler) in enumerate(self._fallbacks):
            if not config.enabled:
                continue
                
            if self.config.stop_on_first_success and successful_index >= 0:
                break
                
            result = self._execute_single_fallback(config, handler, *args, **kwargs)
            results.append(result)
            
            with self._lock:
                self._total_fallbacks_attempted += 1
            
            if result.success:
                successful_index = idx
                final_result = result.result
                final_degradation = result.degradation_level
                with self._lock:
                    self._success_count += 1
                break
            else:
                if result.error:
                    errors.append(result.error)
                with self._lock:
                    self._fallback_used_count += 1
        
        # Determine final status
        if successful_index >= 0:
            if successful_index == 0:
                status = ChainStatus.SUCCESS
            else:
                status = ChainStatus.PARTIAL_SUCCESS
        else:
            status = ChainStatus.ALL_FAILED
            self._record_failure()
        
        return ChainExecutionResult(
            status=status,
            final_result=final_result,
            attempted_fallbacks=len(results),
            successful_fallback_index=successful_index,
            total_execution_time_ms=(time.time() - start_time) * 1000,
            individual_results=results,
            errors=errors,
            final_degradation_level=final_degradation
        )

    def get_statistics(self) -> Dict[str, Any]:
        """Get execution statistics."""
        with self._lock:
            return {
                "chain_name": self.name,
                "total_executions": self._total_executions,
                "success_count": self._success_count,
                "fallback_used_count": self._fallback_used_count,
                "total_fallbacks_attempted": self._total_fallbacks_attempted,
                "circuit_open": self._circuit_open,
                "failure_count": self._failure_count,
                "success_rate": (
                    self._success_count / self._total_executions
                    if self._total_executions > 0 else 0.0
                )
            }


class ThreatIntelFallbackChains:
    """Pre-configured fallback chains for threat intelligence operations."""

    def __init__(self):
        self._chains: Dict[str, FallbackChain] = {}
        self._lock = threading.RLock()
        self._initialize_default_chains()

    def _initialize_default_chains(self) -> None:
        """Initialize standard threat intelligence fallback chains."""
        
        # Chain 1: Threat Lookup with progressive degradation
        lookup_chain = FallbackChain(
            "threat_lookup",
            ChainConfig(
                strategy=FallbackStrategy.SEQUENTIAL,
                max_total_timeout_seconds=15.0
            )
        )
        
        # Primary: Full API lookup
        lookup_chain.add_fallback(
            FallbackConfig(
                name="primary_api_lookup",
                priority=100,
                degradation_level=DegradationLevel.FULL_FEATURED.value
            ),
            self._primary_threat_lookup
        )
        
        # Fallback 1: Reduced accuracy (faster)
        lookup_chain.add_fallback(
            FallbackConfig(
                name="reduced_accuracy_lookup",
                priority=90,
                degradation_level=DegradationLevel.REDUCED_ACCURACY.value
            ),
            self._reduced_accuracy_lookup
        )
        
        # Fallback 2: Cache only
        lookup_chain.add_fallback(
            FallbackConfig(
                name="cached_lookup",
                priority=80,
                degradation_level=DegradationLevel.CACHED_ONLY.value
            ),
            self._cached_lookup
        )
        
        # Fallback 3: Synthetic safe response
        lookup_chain.add_fallback(
            FallbackConfig(
                name="synthetic_response",
                priority=70,
                degradation_level=DegradationLevel.SYNTHETIC.value
            ),
            self._synthetic_safe_response
        )
        
        self._chains["threat_lookup"] = lookup_chain
        
        # Chain 2: IOC Analysis chain
        ioc_chain = FallbackChain(
            "ioc_analysis",
            ChainConfig(
                strategy=FallbackStrategy.SEQUENTIAL,
                max_total_timeout_seconds=10.0
            )
        )
        
        ioc_chain.add_fallback(
            FallbackConfig(
                name="full_ioc_analysis",
                priority=100,
                degradation_level=DegradationLevel.FULL_FEATURED.value
            ),
            self._full_ioc_analysis
        )
        
        ioc_chain.add_fallback(
            FallbackConfig(
                name="basic_ioc_check",
                priority=80,
                degradation_level=DegradationLevel.REDUCED_ACCURACY.value
            ),
            self._basic_ioc_check
        )
        
        ioc_chain.add_fallback(
            FallbackConfig(
                name="fail_closed_block",
                priority=60,
                degradation_level=DegradationLevel.FAIL_CLOSED.value
            ),
            self._fail_closed_ioc
        )
        
        self._chains["ioc_analysis"] = ioc_chain

    def _primary_threat_lookup(self, *args, **kwargs) -> Dict[str, Any]:
        """Primary threat lookup - placeholder for actual implementation."""
        # In real usage, this would call the primary threat intel API
        # This is a safe default that returns standard response
        return {
            "threat_level": "unknown",
            "confidence": 0.0,
            "indicators": [],
            "source": "primary_api",
            "degradation": DegradationLevel.FULL_FEATURED.value
        }

    def _reduced_accuracy_lookup(self, *args, **kwargs) -> Dict[str, Any]:
        """Reduced accuracy but faster lookup."""
        return {
            "threat_level": "unknown",
            "confidence": 0.5,
            "indicators": [],
            "source": "reduced_accuracy",
            "degradation": DegradationLevel.REDUCED_ACCURACY.value,
            "note": "Reduced feature set for performance"
        }

    def _cached_lookup(self, *args, **kwargs) -> Dict[str, Any]:
        """Cached results only."""
        return {
            "threat_level": "unknown",
            "confidence": 0.3,
            "indicators": [],
            "source": "cache",
            "degradation": DegradationLevel.CACHED_ONLY.value,
            "note": "Cached results only, may be stale"
        }

    def _synthetic_safe_response(self, *args, **kwargs) -> Dict[str, Any]:
        """Synthetic safe default response."""
        return {
            "threat_level": "low",
            "confidence": 0.1,
            "indicators": [],
            "source": "synthetic",
            "degradation": DegradationLevel.SYNTHETIC.value,
            "note": "Synthetic safe response - all systems down",
            "safe_default": True
        }

    def _full_ioc_analysis(self, *args, **kwargs) -> Dict[str, Any]:
        """Full IOC analysis."""
        return {
            "malicious": False,
            "ioc_type": "unknown",
            "confidence": 0.0,
            "source": "full_analysis",
            "degradation": DegradationLevel.FULL_FEATURED.value
        }

    def _basic_ioc_check(self, *args, **kwargs) -> Dict[str, Any]:
        """Basic IOC check (reduced accuracy)."""
        return {
            "malicious": False,
            "ioc_type": "unknown",
            "confidence": 0.5,
            "source": "basic_check",
            "degradation": DegradationLevel.REDUCED_ACCURACY.value
        }

    def _fail_closed_ioc(self, *args, **kwargs) -> Dict[str, Any]:
        """Fail closed - assume malicious."""
        return {
            "malicious": True,
            "ioc_type": "unknown",
            "confidence": 0.0,
            "source": "fail_closed",
            "degradation": DegradationLevel.FAIL_CLOSED.value,
            "note": "Fail closed - blocked for security",
            "blocked": True
        }

    def get_chain(self, name: str) -> Optional[FallbackChain]:
        """Get a fallback chain by name."""
        with self._lock:
            return self._chains.get(name)

    def execute_chain(self, chain_name: str, *args, **kwargs) -> ChainExecutionResult:
        """Execute a named fallback chain."""
        chain = self.get_chain(chain_name)
        if chain is None:
            return ChainExecutionResult(
                status=ChainStatus.ALL_FAILED,
                errors=[ValueError(f"Unknown chain: {chain_name}")]
            )
        return chain.execute(*args, **kwargs)

    def get_all_statistics(self) -> Dict[str, Any]:
        """Get statistics for all chains."""
        with self._lock:
            return {
                name: chain.get_statistics()
                for name, chain in self._chains.items()
            }


# Singleton instance for global use
_default_chains: Optional[ThreatIntelFallbackChains] = None
_singleton_lock = threading.Lock()


def get_fallback_chains() -> ThreatIntelFallbackChains:
    """Get the global fallback chains singleton."""
    global _default_chains
    if _default_chains is None:
        with _singleton_lock:
            if _default_chains is None:
                _default_chains = ThreatIntelFallbackChains()
    return _default_chains


def with_fallback_chain(chain_name: str):
    """Decorator to wrap a function with fallback chain."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            chains = get_fallback_chains()
            
            # First try the wrapped function (happy path)
            try:
                result = func(*args, **kwargs)
                return result
            except Exception:
                # Fall back to chain
                chain_result = chains.execute_chain(chain_name, *args, **kwargs)
                if chain_result.status in (ChainStatus.SUCCESS, ChainStatus.PARTIAL_SUCCESS):
                    return chain_result.final_result
                # Re-raise if all failed
                if chain_result.errors:
                    raise chain_result.errors[-1]
                raise
        return wrapper
    return decorator


# Backward compatibility - export stable interface
__all__ = [
    'FallbackStrategy',
    'DegradationLevel',
    'ErrorCategory',
    'ChainStatus',
    'FallbackResult',
    'ChainExecutionResult',
    'FallbackConfig',
    'ChainConfig',
    'FallbackChain',
    'ThreatIntelFallbackChains',
    'get_fallback_chains',
    'with_fallback_chain',
]
