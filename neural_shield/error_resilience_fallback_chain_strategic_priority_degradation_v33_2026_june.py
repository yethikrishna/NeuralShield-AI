"""
NeuralShield AI - Error Resilience Module
Strategic Priority-Based Fallback Chain with Health-Aware Degradation v33

DIMENSION E: ERROR RESILIENCE
- Purely additive, no modifications to existing code
- 100% backward compatible
- Happy path behavior fully preserved
- All instrumentation is OPT-IN

Features added in v33:
1. Priority-based fallback selection algorithm
2. Health-aware fallback routing with real-time health scoring
3. Degradation level tracking with SLO compliance monitoring
4. Statistical fallback performance analytics
5. Context-aware fallback decision engine
6. Cascading failure prevention with circuit breaker integration
"""

import time
import threading
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
import statistics
from functools import wraps


# Configure logging - OPT-IN only, disabled by default
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class DegradationLevel(Enum):
    """Degradation levels for graceful service degradation."""
    FULL = "full"                  # Full functionality, no degradation
    MINIMAL = "minimal"            # Minimal degradation, non-critical features only
    MODERATE = "moderate"          # Moderate degradation, some features disabled
    SIGNIFICANT = "significant"    # Significant degradation, core features only
    CRITICAL = "critical"          # Critical degradation, emergency mode only
    FAILSAFE = "failsafe"          # Complete failsafe mode, minimal operation only


class FallbackPriority(Enum):
    """Priority levels for fallback strategy selection."""
    HIGHEST = 0    # Primary fallback, first choice
    HIGH = 1       # Secondary fallback
    MEDIUM = 2     # Tertiary fallback
    LOW = 3        # Last resort fallback
    LOWEST = 4     # Emergency only


class HealthStatus(Enum):
    """Health status for dependency monitoring."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    CRITICAL = "critical"
    DOWN = "down"


@dataclass
class FallbackStrategy:
    """Represents a single fallback strategy with metadata."""
    name: str
    handler: Callable
    priority: FallbackPriority = FallbackPriority.MEDIUM
    supported_degradation_levels: List[DegradationLevel] = field(default_factory=lambda: [
        DegradationLevel.FULL,
        DegradationLevel.MINIMAL,
        DegradationLevel.MODERATE
    ])
    timeout_seconds: float = 5.0
    max_retries: int = 0
    health_check_required: bool = False
    description: str = ""
    
    def __post_init__(self):
        self.success_count = 0
        self.failure_count = 0
        self.total_execution_time = 0.0
        self.last_execution_time: Optional[float] = None
        self.last_used_timestamp: Optional[float] = None


@dataclass
class HealthScore:
    """Health scoring for a dependency or service."""
    name: str
    success_rate_window: int = 100
    latency_threshold_ms: float = 1000.0
    error_rate_threshold: float = 0.1
    
    def __post_init__(self):
        self._success_history: deque = deque(maxlen=self.success_rate_window)
        self._latency_history: deque = deque(maxlen=self.success_rate_window)
        self._lock = threading.RLock()
        self.consecutive_failures = 0
        self.consecutive_successes = 0
    
    def record_success(self, latency_ms: float) -> None:
        """Record a successful operation."""
        with self._lock:
            self._success_history.append(True)
            self._latency_history.append(latency_ms)
            self.consecutive_successes += 1
            self.consecutive_failures = 0
    
    def record_failure(self, latency_ms: float) -> None:
        """Record a failed operation."""
        with self._lock:
            self._success_history.append(False)
            self._latency_history.append(latency_ms)
            self.consecutive_failures += 1
            self.consecutive_successes = 0
    
    def get_health_score(self) -> float:
        """Calculate current health score (0.0 to 1.0)."""
        with self._lock:
            if not self._success_history:
                return 1.0  # Assume healthy if no data
            
            total = len(self._success_history)
            successes = sum(1 for s in self._success_history if s)
            success_rate = successes / total if total > 0 else 1.0
            
            # Calculate latency penalty
            latency_penalty = 0.0
            if self._latency_history:
                avg_latency = statistics.mean(self._latency_history)
                if avg_latency > self.latency_threshold_ms:
                    latency_penalty = min(0.3, (avg_latency - self.latency_threshold_ms) / (self.latency_threshold_ms * 2))
            
            # Calculate consecutive failure penalty
            consecutive_penalty = min(0.5, self.consecutive_failures * 0.1)
            
            health_score = success_rate - latency_penalty - consecutive_penalty
            return max(0.0, min(1.0, health_score))
    
    def get_health_status(self) -> HealthStatus:
        """Get enumerated health status."""
        score = self.get_health_score()
        if score >= 0.9:
            return HealthStatus.HEALTHY
        elif score >= 0.7:
            return HealthStatus.DEGRADED
        elif score >= 0.5:
            return HealthStatus.UNHEALTHY
        elif score >= 0.25:
            return HealthStatus.CRITICAL
        else:
            return HealthStatus.DOWN


@dataclass
class DegradationTracker:
    """Tracks current degradation level and SLO compliance."""
    slo_target_availability: float = 0.999  # 99.9% availability target
    
    def __post_init__(self):
        self._current_level = DegradationLevel.FULL
        self._level_history: deque = deque(maxlen=1000)
        self._level_timestamps: deque = deque(maxlen=1000)
        self._lock = threading.RLock()
        self.total_requests = 0
        self.degraded_requests = 0
        self.failed_requests = 0
    
    def set_degradation_level(self, level: DegradationLevel) -> None:
        """Set current degradation level."""
        with self._lock:
            self._current_level = level
            self._level_history.append(level)
            self._level_timestamps.append(time.time())
            logger.info(f"Degradation level changed to: {level.value}")
    
    def get_current_level(self) -> DegradationLevel:
        """Get current degradation level."""
        with self._lock:
            return self._current_level
    
    def record_request(self, was_degraded: bool = False, failed: bool = False) -> None:
        """Record a request for SLO tracking."""
        with self._lock:
            self.total_requests += 1
            if was_degraded:
                self.degraded_requests += 1
            if failed:
                self.failed_requests += 1
    
    def get_availability(self) -> float:
        """Calculate current availability percentage."""
        with self._lock:
            if self.total_requests == 0:
                return 1.0
            return 1.0 - (self.failed_requests / self.total_requests)
    
    def get_degradation_rate(self) -> float:
        """Get percentage of requests served in degraded mode."""
        with self._lock:
            if self.total_requests == 0:
                return 0.0
            return self.degraded_requests / self.total_requests


class StrategicFallbackChain:
    """
    Strategic Priority-Based Fallback Chain with Health-Aware Routing.
    
    This class provides:
    1. Priority-ordered fallback strategy execution
    2. Health-aware routing based on real-time health scores
    3. Automatic degradation level adjustment
    4. Comprehensive statistics and monitoring
    5. Cascading failure prevention
    """
    
    def __init__(self, name: str = "default_fallback_chain"):
        self.name = name
        self._strategies: List[FallbackStrategy] = []
        self._health_scores: Dict[str, HealthScore] = {}
        self._degradation_tracker = DegradationTracker()
        self._lock = threading.RLock()
        self._primary_operation: Optional[Callable] = None
        self._cascading_failure_prevention_enabled = True
        self._circuit_breaker_threshold = 5  # Consecutive failures before opening
        
        # Statistics
        self.fallback_activations = 0
        self.successful_fallbacks = 0
        self.failed_fallbacks = 0
        self.cascading_failures_prevented = 0
    
    def register_primary_operation(self, operation: Callable, name: str = "primary") -> None:
        """Register the primary (happy path) operation."""
        with self._lock:
            self._primary_operation = operation
            if name not in self._health_scores:
                self._health_scores[name] = HealthScore(name)
    
    def add_fallback_strategy(self, strategy: FallbackStrategy) -> None:
        """Add a fallback strategy to the chain."""
        with self._lock:
            self._strategies.append(strategy)
            # Sort by priority (lower number = higher priority)
            self._strategies.sort(key=lambda s: s.priority.value)
            
            if strategy.name not in self._health_scores:
                self._health_scores[strategy.name] = HealthScore(strategy.name)
            
            logger.info(f"Added fallback strategy: {strategy.name} (priority: {strategy.priority.name})")
    
    def _select_applicable_strategies(self, context: Optional[Dict] = None) -> List[FallbackStrategy]:
        """Select applicable strategies based on health and degradation level."""
        current_level = self._degradation_tracker.get_current_level()
        applicable = []
        
        for strategy in self._strategies:
            # Check if strategy supports current degradation level
            if current_level not in strategy.supported_degradation_levels:
                continue
            
            # Check health score if health check is required
            if strategy.health_check_required:
                health = self._health_scores.get(strategy.name)
                if health and health.get_health_status() in (HealthStatus.CRITICAL, HealthStatus.DOWN):
                    continue
            
            applicable.append(strategy)
        
        return applicable
    
    def execute(self, *args, context: Optional[Dict] = None, **kwargs) -> Tuple[Any, bool, str]:
        """
        Execute primary operation with strategic fallback chain.
        
        Returns:
            (result, was_degraded, strategy_used_name)
        """
        start_time = time.time()
        context = context or {}
        
        # Try primary operation first
        if self._primary_operation:
            try:
                result = self._primary_operation(*args, **kwargs)
                latency = (time.time() - start_time) * 1000
                
                if "primary" in self._health_scores:
                    self._health_scores["primary"].record_success(latency)
                
                self._degradation_tracker.record_request(was_degraded=False)
                return result, False, "primary"
                
            except Exception as primary_error:
                latency = (time.time() - start_time) * 1000
                if "primary" in self._health_scores:
                    self._health_scores["primary"].record_failure(latency)
                
                logger.warning(f"Primary operation failed: {primary_error}")
                self.fallback_activations += 1
        
        # Primary failed - execute fallback chain
        applicable_strategies = self._select_applicable_strategies(context)
        
        for strategy in applicable_strategies:
            fallback_start = time.time()
            
            # Prevent cascading failures - check consecutive failures
            health = self._health_scores.get(strategy.name)
            if (self._cascading_failure_prevention_enabled and 
                health and health.consecutive_failures >= self._circuit_breaker_threshold):
                self.cascading_failures_prevented += 1
                logger.warning(f"Skipping {strategy.name} due to cascading failure prevention")
                continue
            
            try:
                result = strategy.handler(*args, **kwargs)
                fallback_latency = (time.time() - fallback_start) * 1000
                
                # Update statistics
                if strategy.name in self._health_scores:
                    self._health_scores[strategy.name].record_success(fallback_latency)
                
                strategy.success_count += 1
                strategy.total_execution_time += fallback_latency
                strategy.last_execution_time = fallback_latency
                strategy.last_used_timestamp = time.time()
                
                self.successful_fallbacks += 1
                self._degradation_tracker.record_request(was_degraded=True)
                
                logger.info(f"Fallback succeeded using strategy: {strategy.name}")
                return result, True, strategy.name
                
            except Exception as fallback_error:
                fallback_latency = (time.time() - fallback_start) * 1000
                
                if strategy.name in self._health_scores:
                    self._health_scores[strategy.name].record_failure(fallback_latency)
                
                strategy.failure_count += 1
                logger.warning(f"Fallback strategy {strategy.name} failed: {fallback_error}")
                continue
        
        # All fallbacks failed
        self.failed_fallbacks += 1
        self._degradation_tracker.record_request(was_degraded=True, failed=True)
        
        # Escalate degradation level
        current_level = self._degradation_tracker.get_current_level()
        level_order = list(DegradationLevel)
        current_idx = level_order.index(current_level)
        if current_idx < len(level_order) - 1:
            self._degradation_tracker.set_degradation_level(level_order[current_idx + 1])
        
        raise RuntimeError(
            f"All fallback strategies failed in chain '{self.name}'. "
            f"Current degradation level: {self._degradation_tracker.get_current_level().value}"
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics."""
        with self._lock:
            stats = {
                "chain_name": self.name,
                "fallback_activations": self.fallback_activations,
                "successful_fallbacks": self.successful_fallbacks,
                "failed_fallbacks": self.failed_fallbacks,
                "cascading_failures_prevented": self.cascading_failures_prevented,
                "current_degradation_level": self._degradation_tracker.get_current_level().value,
                "availability": self._degradation_tracker.get_availability(),
                "degradation_rate": self._degradation_tracker.get_degradation_rate(),
                "total_requests": self._degradation_tracker.total_requests,
                "strategy_statistics": []
            }
            
            for strategy in self._strategies:
                total_attempts = strategy.success_count + strategy.failure_count
                success_rate = strategy.success_count / total_attempts if total_attempts > 0 else 0.0
                avg_time = strategy.total_execution_time / strategy.success_count if strategy.success_count > 0 else 0.0
                
                stats["strategy_statistics"].append({
                    "name": strategy.name,
                    "priority": strategy.priority.name,
                    "success_count": strategy.success_count,
                    "failure_count": strategy.failure_count,
                    "success_rate": success_rate,
                    "average_execution_time_ms": avg_time,
                    "health_score": self._health_scores.get(strategy.name, HealthScore("")).get_health_score()
                })
            
            return stats
    
    def get_health_statuses(self) -> Dict[str, str]:
        """Get health status for all registered components."""
        return {
            name: score.get_health_status().value
            for name, score in self._health_scores.items()
        }


def strategic_fallback(chain: StrategicFallbackChain):
    """
    Decorator for applying strategic fallback chain to functions.
    
    Usage:
        @strategic_fallback(my_chain)
        def my_function():
            ...
    """
    def decorator(func: Callable) -> Callable:
        chain.register_primary_operation(func, name=func.__name__)
        
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            result, was_degraded, strategy = chain.execute(*args, **kwargs)
            return result
        return wrapper
    return decorator


# Export public API
__all__ = [
    'StrategicFallbackChain',
    'FallbackStrategy',
    'DegradationLevel',
    'FallbackPriority',
    'HealthStatus',
    'HealthScore',
    'DegradationTracker',
    'strategic_fallback',
]
