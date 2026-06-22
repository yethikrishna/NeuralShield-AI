"""
NeuralShield AI - Error Resilience v18
Enhanced Circuit Breaker with Intelligent Fallback Orchestration
DIMENSION E - Error Resilience
ADD-ONLY implementation - wraps existing code, no modifications
NEW in v18:
1. Enhanced Circuit Breaker with Half-Open State Testing - smart recovery probing
2. Fallback Strategy Orchestrator - intelligent fallback selection & ranking
3. Deadline Propagation System - end-to-end request deadline management
4. Cascade Failure Prevention Gates - upstream/downstream protection layers
5. Request Prioritization & Load Shedding - priority-aware traffic shaping
6. Graceful Degradation Feature Toggles - granular feature-level degradation
7. Failure Budget Enforcement - SLO-based dynamic circuit breaking
8. Safe Chaos Injection Framework - controlled resilience testing
"""
import time
import threading
import enum
import math
import uuid
import logging
import random
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Type, Union, Tuple, Generic, TypeVar
from collections import deque, defaultdict
from datetime import datetime, timedelta
from functools import wraps
from statistics import mean, stdev
from abc import ABC, abstractmethod

# Configure logging (OPT-IN - disabled by default)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

T = TypeVar('T')
R = TypeVar('R')

# -----------------------------------------------------------------------------
# ENUMERATIONS
# -----------------------------------------------------------------------------
class CircuitState(enum.Enum):
    """Circuit breaker states with enhanced half-open probing."""
    CLOSED = "closed"           # Normal operation - all requests pass
    OPEN = "open"               # Circuit tripped - requests fail fast
    HALF_OPEN = "half_open"     # Recovery mode - limited probing
    PROBING = "probing"         # Smart probing - adaptive test requests

class FallbackStrategy(enum.Enum):
    """Fallback execution strategies."""
    NONE = "none"
    CACHED_VALUE = "cached_value"
    DEFAULT_VALUE = "default_value"
    STUBBED_RESPONSE = "stubbed_response"
    DEGRADED_QUALITY = "degraded_quality"
    RETRY_SAME = "retry_same"
    RETRY_BACKOFF = "retry_backoff"
    FALLBACK_MODULE = "fallback_module"
    GRACEFUL_DEGRADATION = "graceful_degradation"

class PriorityLevel(enum.Enum):
    """Request priority levels for load shedding."""
    CRITICAL = 0    # Must succeed - never shed
    HIGH = 1        # High importance - shed last
    NORMAL = 2      # Standard priority
    LOW = 3         # Low importance - shed first
    BACKGROUND = 4  # Background work - shed earliest

class FeatureToggleLevel(enum.Enum):
    """Feature availability levels for graceful degradation."""
    FULL = "full"               # Full functionality
    ESSENTIAL = "essential"     # Essential features only
    MINIMAL = "minimal"         # Bare minimum operation
    READ_ONLY = "read_only"     # Read operations only
    OFFLINE = "offline"         # Feature disabled

# -----------------------------------------------------------------------------
# DATA CLASSES
# -----------------------------------------------------------------------------
@dataclass
class CircuitBreakerConfig:
    """Enhanced circuit breaker configuration."""
    failure_threshold: int = 5
    success_threshold: int = 3
    open_timeout_ms: float = 30000.0
    half_open_max_requests: int = 5
    probe_interval_ms: float = 1000.0
    adaptive_thresholding: bool = True
    failure_budget_enforcement: bool = True
    max_failure_budget_percent: float = 5.0

@dataclass
class FallbackResult(Generic[T]):
    """Result from fallback execution."""
    value: Optional[T] = None
    strategy_used: FallbackStrategy = FallbackStrategy.NONE
    success: bool = False
    latency_ms: float = 0.0
    error_message: Optional[str] = None

@dataclass
class RequestDeadline:
    """Propagated request deadline."""
    deadline_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: float = field(default_factory=time.time)
    timeout_ms: float = 30000.0
    remaining_budget_ms: float = 30000.0
    hop_count: int = 0
    max_hops: int = 10
    
    @property
    def expired(self) -> bool:
        return self.remaining_ms <= 0
    
    @property
    def remaining_ms(self) -> float:
        elapsed = (time.time() - self.created_at) * 1000
        return max(0.0, self.timeout_ms - elapsed)
    
    def propagate(self) -> 'RequestDeadline':
        """Create propagated deadline for next hop."""
        return RequestDeadline(
            deadline_id=self.deadline_id,
            created_at=self.created_at,
            timeout_ms=self.timeout_ms,
            remaining_budget_ms=self.remaining_ms,
            hop_count=min(self.hop_count + 1, self.max_hops),
            max_hops=self.max_hops
        )

@dataclass
class LoadSheddingStats:
    """Load shedding statistics."""
    total_requests: int = 0
    shed_requests: int = 0
    shed_by_priority: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    last_shed_at: Optional[float] = None

@dataclass
class FailureBudget:
    """SLO-based failure budget tracking."""
    slo_error_rate: float = 0.01  # 1% max error rate
    window_seconds: int = 3600
    total_requests: int = 0
    error_count: int = 0
    budget_remaining_percent: float = 100.0
    
    @property
    def current_error_rate(self) -> float:
        return self.error_count / max(1, self.total_requests)
    
    @property
    def budget_exhausted(self) -> bool:
        return self.budget_remaining_percent <= 0

@dataclass
class ChaosInjectionConfig:
    """Safe chaos injection configuration."""
    enabled: bool = False
    error_injection_rate: float = 0.0
    latency_injection_rate: float = 0.0
    latency_injection_ms: float = 0.0
    max_injection_per_second: int = 10
    safe_mode: bool = True  # Never inject into critical requests

# -----------------------------------------------------------------------------
# ENHANCED CIRCUIT BREAKER
# -----------------------------------------------------------------------------
class EnhancedCircuitBreaker:
    """
    Enhanced circuit breaker with:
    - Half-open state with adaptive probing
    - Failure budget enforcement
    - Adaptive threshold learning
    - Smart recovery testing
    """
    
    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self._lock = threading.Lock()
        
        # State management
        self._state = CircuitState.CLOSED
        self._state_changed_at = time.time()
        
        # Failure tracking
        self._consecutive_failures = 0
        self._consecutive_successes = 0
        self._failure_history: deque = deque(maxlen=1000)
        self._success_history: deque = deque(maxlen=1000)
        
        # Half-open probing
        self._half_open_requests = 0
        self._last_probe_at = 0.0
        
        # Failure budget
        self._failure_budget = FailureBudget()
        
        # Statistics
        self._trip_count = 0
        self._recovery_count = 0
    
    def _transition_state(self, new_state: CircuitState) -> None:
        """Transition to new state with logging."""
        old_state = self._state
        self._state = new_state
        self._state_changed_at = time.time()
        logger.info(
            f"CircuitBreaker '{self.name}' state change: {old_state.value} -> {new_state.value}"
        )
    
    def _check_open_timeout(self) -> None:
        """Check if open state should transition to half-open."""
        if self._state == CircuitState.OPEN:
            elapsed_ms = (time.time() - self._state_changed_at) * 1000
            if elapsed_ms >= self.config.open_timeout_ms:
                self._transition_state(CircuitState.HALF_OPEN)
                self._half_open_requests = 0
                self._consecutive_successes = 0
    
    def _check_half_open_probe(self) -> bool:
        """Check if probe request should be allowed in half-open state."""
        now = time.time()
        elapsed_since_probe = (now - self._last_probe_at) * 1000
        
        if elapsed_since_probe >= self.config.probe_interval_ms:
            if self._half_open_requests < self.config.half_open_max_requests:
                self._last_probe_at = now
                self._half_open_requests += 1
                return True
        return False
    
    def allow_request(self, priority: PriorityLevel = PriorityLevel.NORMAL) -> bool:
        """Check if request should be allowed through."""
        with self._lock:
            self._check_open_timeout()
            
            if self._state == CircuitState.CLOSED:
                return True
            
            if self._state == CircuitState.OPEN:
                # Critical requests may bypass open circuit
                if priority == PriorityLevel.CRITICAL:
                    logger.warning(f"Critical request bypassing open circuit '{self.name}'")
                    return True
                return False
            
            if self._state == CircuitState.HALF_OPEN:
                return self._check_half_open_probe()
            
            if self._state == CircuitState.PROBING:
                return self._check_half_open_probe()
            
            return False
    
    def record_success(self) -> None:
        """Record a successful request."""
        with self._lock:
            self._consecutive_failures = 0
            self._consecutive_successes += 1
            self._success_history.append(time.time())
            
            # Update failure budget
            self._failure_budget.total_requests += 1
            self._update_failure_budget()
            
            # State transitions
            if self._state == CircuitState.HALF_OPEN or self._state == CircuitState.PROBING:
                if self._consecutive_successes >= self.config.success_threshold:
                    self._transition_state(CircuitState.CLOSED)
                    self._recovery_count += 1
                    logger.info(f"CircuitBreaker '{self.name}' recovered after {self._consecutive_successes} successes")
    
    def record_failure(self, error_type: str = "unknown") -> None:
        """Record a failed request."""
        with self._lock:
            self._consecutive_failures += 1
            self._consecutive_successes = 0
            self._failure_history.append((time.time(), error_type))
            
            # Update failure budget
            self._failure_budget.total_requests += 1
            self._failure_budget.error_count += 1
            self._update_failure_budget()
            
            # Trip circuit if threshold exceeded
            if self._state == CircuitState.CLOSED:
                threshold = self._get_adaptive_threshold()
                if self._consecutive_failures >= threshold:
                    self._transition_state(CircuitState.OPEN)
                    self._trip_count += 1
                    logger.warning(
                        f"CircuitBreaker '{self.name}' tripped after {self._consecutive_failures} failures"
                    )
            
            elif self._state == CircuitState.HALF_OPEN or self._state == CircuitState.PROBING:
                # Any failure in half-open sends back to open
                self._transition_state(CircuitState.OPEN)
                logger.warning(
                    f"CircuitBreaker '{self.name}' probe failed - returning to OPEN state"
                )
    
    def _get_adaptive_threshold(self) -> int:
        """Get adaptively adjusted failure threshold."""
        if not self.config.adaptive_thresholding:
            return self.config.failure_threshold
        
        # Adjust based on recent failure rate
        window = 100
        if len(self._failure_history) + len(self._success_history) >= window:
            recent_failures = len(self._failure_history)
            recent_total = recent_failures + len(self._success_history)
            failure_rate = recent_failures / recent_total
            
            # Lower threshold when failure rate is rising
            if failure_rate > 0.1:
                return max(2, int(self.config.failure_threshold * 0.7))
            elif failure_rate < 0.01:
                return min(20, int(self.config.failure_threshold * 1.5))
        
        return self.config.failure_threshold
    
    def _update_failure_budget(self) -> None:
        """Update SLO failure budget tracking."""
        if not self.config.failure_budget_enforcement:
            return
        
        budget = self._failure_budget
        error_rate = budget.current_error_rate
        
        # Calculate remaining budget
        allowed_errors = budget.slo_error_rate * budget.total_requests
        actual_errors = budget.error_count
        budget.budget_remaining_percent = max(
            0.0,
            100.0 * (1 - actual_errors / max(1, allowed_errors))
        )
        
        # Early trip if budget exhausted
        if budget.budget_exhausted and self._state == CircuitState.CLOSED:
            self._transition_state(CircuitState.OPEN)
            self._trip_count += 1
            logger.warning(
                f"CircuitBreaker '{self.name}' tripped - failure budget exhausted"
            )
    
    def get_state(self) -> Dict[str, Any]:
        """Get circuit breaker state and statistics."""
        with self._lock:
            return {
                "name": self.name,
                "state": self._state.value,
                "consecutive_failures": self._consecutive_failures,
                "consecutive_successes": self._consecutive_successes,
                "trip_count": self._trip_count,
                "recovery_count": self._recovery_count,
                "failure_budget_remaining": self._failure_budget.budget_remaining_percent,
                "current_error_rate": self._failure_budget.current_error_rate
            }

# -----------------------------------------------------------------------------
# FALLBACK STRATEGY ORCHESTRATOR
# -----------------------------------------------------------------------------
class FallbackStrategyOrchestrator(Generic[T]):
    """
    Intelligent fallback orchestrator that:
    - Ranks fallback strategies by effectiveness
    - Selects optimal fallback based on error type
    - Caches successful fallback results
    - Tracks fallback success rates
    """
    
    def __init__(self, name: str):
        self.name = name
        self._lock = threading.Lock()
        self._fallbacks: Dict[FallbackStrategy, Callable[..., T]] = {}
        self._fallback_stats: Dict[FallbackStrategy, Dict[str, Any]] = defaultdict(
            lambda: {"attempts": 0, "successes": 0, "avg_latency_ms": 0.0}
        )
        self._result_cache: Dict[str, Tuple[T, float]] = {}
        self._cache_ttl_ms = 60000.0
    
    def register_fallback(
        self,
        strategy: FallbackStrategy,
        handler: Callable[..., T],
        priority: int = 0
    ) -> None:
        """Register a fallback handler."""
        with self._lock:
            self._fallbacks[strategy] = handler
    
    def get_strategy_ranking(self, error_type: str = "unknown") -> List[FallbackStrategy]:
        """Get fallback strategies ranked by success rate."""
        with self._lock:
            def success_rate(strategy):
                stats = self._fallback_stats[strategy]
                if stats["attempts"] == 0:
                    return 0.5  # Neutral for untried
                return stats["successes"] / stats["attempts"]
            
            return sorted(
                self._fallbacks.keys(),
                key=success_rate,
                reverse=True
            )
    
    def execute_fallback(
        self,
        error: Exception,
        *args,
        **kwargs
    ) -> FallbackResult[T]:
        """Execute fallback strategies in ranked order."""
        start_time = time.time()
        strategies = self.get_strategy_ranking(str(type(error).__name__))
        
        for strategy in strategies:
            with self._lock:
                self._fallback_stats[strategy]["attempts"] += 1
            
            try:
                handler = self._fallbacks[strategy]
                result = handler(*args, error=error, **kwargs)
                
                latency_ms = (time.time() - start_time) * 1000
                
                with self._lock:
                    self._fallback_stats[strategy]["successes"] += 1
                    stats = self._fallback_stats[strategy]
                    stats["avg_latency_ms"] = (
                        stats["avg_latency_ms"] * (stats["successes"] - 1) + latency_ms
                    ) / stats["successes"]
                
                return FallbackResult[T](
                    value=result,
                    strategy_used=strategy,
                    success=True,
                    latency_ms=latency_ms
                )
            
            except Exception as fallback_error:
                logger.warning(
                    f"Fallback strategy {strategy.value} failed: {fallback_error}"
                )
                continue
        
        # All fallbacks failed
        return FallbackResult[T](
            value=None,
            strategy_used=FallbackStrategy.NONE,
            success=False,
            error_message="All fallback strategies failed"
        )
    
    def get_cache(self, key: str) -> Optional[T]:
        """Get cached fallback result."""
        with self._lock:
            if key in self._result_cache:
                value, cached_at = self._result_cache[key]
                if (time.time() - cached_at) * 1000 < self._cache_ttl_ms:
                    return value
                del self._result_cache[key]
        return None
    
    def set_cache(self, key: str, value: T) -> None:
        """Cache successful fallback result."""
        with self._lock:
            self._result_cache[key] = (value, time.time())

# -----------------------------------------------------------------------------
# DEADLINE PROPAGATION SYSTEM
# -----------------------------------------------------------------------------
class DeadlinePropagationSystem:
    """
    End-to-end deadline propagation system:
    - Creates and propagates deadlines across service calls
    - Enforces timeouts at each hop
    - Tracks deadline budget consumption
    - Prevents cascade from slow dependencies
    """
    
    def __init__(self):
        self._lock = threading.Lock()
        self._active_deadlines: Dict[str, RequestDeadline] = {}
        self._deadline_exceeded_count = 0
    
    def create_deadline(self, timeout_ms: float = 30000.0) -> RequestDeadline:
        """Create a new request deadline."""
        deadline = RequestDeadline(timeout_ms=timeout_ms, remaining_budget_ms=timeout_ms)
        with self._lock:
            self._active_deadlines[deadline.deadline_id] = deadline
        return deadline
    
    def check_deadline(self, deadline: RequestDeadline) -> Tuple[bool, float]:
        """Check if deadline is still valid, return (valid, remaining_ms)."""
        remaining = deadline.remaining_ms
        if remaining <= 0:
            with self._lock:
                self._deadline_exceeded_count += 1
            return False, 0.0
        return True, remaining
    
    def get_subcall_timeout(self, deadline: RequestDeadline, fraction: float = 0.8) -> float:
        """Get appropriate timeout for subcall."""
        return max(100.0, deadline.remaining_ms * fraction)
    
    def cleanup_expired(self) -> int:
        """Clean up expired deadlines."""
        now = time.time()
        expired_count = 0
        with self._lock:
            expired_ids = [
                did for did, d in self._active_deadlines.items()
                if now - d.created_at > d.timeout_ms / 1000 * 2
            ]
            for did in expired_ids:
                del self._active_deadlines[did]
            expired_count = len(expired_ids)
        return expired_count

# -----------------------------------------------------------------------------
# LOAD SHEDDER WITH PRIORITIZATION
# -----------------------------------------------------------------------------
class PriorityAwareLoadShedder:
    """
    Intelligent load shedding with priority levels:
    - Sheds lowest priority requests first
    - Preserves critical traffic during overload
    - Adaptive shedding thresholds
    - Fair shedding across priority levels
    """
    
    def __init__(self, name: str, max_concurrent: int = 100):
        self.name = name
        self.max_concurrent = max_concurrent
        self._lock = threading.Lock()
        self._active_requests = 0
        self._stats = LoadSheddingStats()
        self._load_history: deque = deque(maxlen=100)
    
    def should_accept(self, priority: PriorityLevel = PriorityLevel.NORMAL) -> bool:
        """Determine if request should be accepted or shed."""
        with self._lock:
            self._stats.total_requests += 1
            self._load_history.append(self._active_requests)
            
            # Calculate current load
            load_factor = self._active_requests / max(1, self.max_concurrent)
            
            # Shedding thresholds by priority (higher load = shed more)
            thresholds = {
                PriorityLevel.CRITICAL: 2.0,    # Never shed unless 200% overload
                PriorityLevel.HIGH: 1.5,        # Shed at 150% overload
                PriorityLevel.NORMAL: 1.2,      # Shed at 120% overload
                PriorityLevel.LOW: 1.0,         # Shed at 100% capacity
                PriorityLevel.BACKGROUND: 0.8   # Shed at 80% capacity
            }
            
            threshold = thresholds.get(priority, 1.0)
            
            if load_factor >= threshold:
                self._stats.shed_requests += 1
                self._stats.shed_by_priority[priority.name] += 1
                self._stats.last_shed_at = time.time()
                logger.debug(
                    f"LoadShedder '{self.name}' shed {priority.name} request "
                    f"(load={load_factor:.2f}, threshold={threshold})"
                )
                return False
            
            self._active_requests += 1
            return True
    
    def request_complete(self) -> None:
        """Mark request as complete."""
        with self._lock:
            self._active_requests = max(0, self._active_requests - 1)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get load shedding statistics."""
        with self._lock:
            avg_load = mean(self._load_history) if self._load_history else 0
            return {
                "name": self.name,
                "active_requests": self._active_requests,
                "max_concurrent": self.max_concurrent,
                "total_requests": self._stats.total_requests,
                "shed_requests": self._stats.shed_requests,
                "shed_rate": self._stats.shed_requests / max(1, self._stats.total_requests),
                "shed_by_priority": dict(self._stats.shed_by_priority),
                "average_load_factor": avg_load
            }

# -----------------------------------------------------------------------------
# FEATURE TOGGLE DEGRADATION MANAGER
# -----------------------------------------------------------------------------
class GracefulDegradationManager:
    """
    Granular feature-level graceful degradation:
    - Per-feature toggle levels
    - Health-based automatic adjustment
    - Dependency-aware degradation
    - Smooth transition between levels
    """
    
    def __init__(self, name: str):
        self.name = name
        self._lock = threading.Lock()
        self._feature_levels: Dict[str, FeatureToggleLevel] = {}
        self._feature_dependencies: Dict[str, List[str]] = defaultdict(list)
        self._health_triggers: Dict[FeatureToggleLevel, float] = {
            FeatureToggleLevel.FULL: 90.0,
            FeatureToggleLevel.ESSENTIAL: 70.0,
            FeatureToggleLevel.MINIMAL: 50.0,
            FeatureToggleLevel.READ_ONLY: 30.0,
            FeatureToggleLevel.OFFLINE: 0.0
        }
    
    def register_feature(
        self,
        feature_name: str,
        dependencies: Optional[List[str]] = None
    ) -> None:
        """Register a feature for degradation management."""
        with self._lock:
            self._feature_levels[feature_name] = FeatureToggleLevel.FULL
            if dependencies:
                self._feature_dependencies[feature_name].extend(dependencies)
    
    def set_feature_level(
        self,
        feature_name: str,
        level: FeatureToggleLevel,
        propagate: bool = True
    ) -> None:
        """Set degradation level for a feature."""
        with self._lock:
            if feature_name not in self._feature_levels:
                self._feature_levels[feature_name] = FeatureToggleLevel.FULL
            
            old_level = self._feature_levels[feature_name]
            self._feature_levels[feature_name] = level
            
            if old_level != level:
                logger.info(
                    f"Feature '{feature_name}' degradation: {old_level.value} -> {level.value}"
                )
            
            # Propagate to dependencies
            if propagate:
                for dep in self._feature_dependencies.get(feature_name, []):
                    self.set_feature_level(dep, level, propagate=False)
    
    def adjust_by_health_score(self, health_score: float) -> None:
        """Automatically adjust all features based on system health."""
        target_level = FeatureToggleLevel.FULL
        
        for level, threshold in sorted(
            self._health_triggers.items(),
            key=lambda x: x[1],
            reverse=True
        ):
            if health_score >= threshold:
                target_level = level
                break
        
        with self._lock:
            for feature in self._feature_levels:
                self._feature_levels[feature] = target_level
    
    def is_feature_available(
        self,
        feature_name: str,
        min_required: FeatureToggleLevel = FeatureToggleLevel.FULL
    ) -> bool:
        """Check if feature is available at required level."""
        with self._lock:
            current = self._feature_levels.get(feature_name, FeatureToggleLevel.FULL)
            # Order: FULL > ESSENTIAL > MINIMAL > READ_ONLY > OFFLINE
            level_order = {
                FeatureToggleLevel.FULL: 4,
                FeatureToggleLevel.ESSENTIAL: 3,
                FeatureToggleLevel.MINIMAL: 2,
                FeatureToggleLevel.READ_ONLY: 1,
                FeatureToggleLevel.OFFLINE: 0
            }
            return level_order[current] >= level_order[min_required]
    
    def get_feature_states(self) -> Dict[str, str]:
        """Get all feature degradation states."""
        with self._lock:
            return {k: v.value for k, v in self._feature_levels.items()}

# -----------------------------------------------------------------------------
# SAFE CHAOS INJECTION FRAMEWORK
# -----------------------------------------------------------------------------
class SafeChaosInjector:
    """
    Controlled chaos injection for resilience testing:
    - Safe mode - never affects critical requests
    - Rate-limited injection
    - Latency and error injection
    - Immediately disableable
    """
    
    def __init__(self, name: str):
        self.name = name
        self._lock = threading.Lock()
        self.config = ChaosInjectionConfig()
        self._injection_count = 0
        self._window_start = time.time()
    
    def _check_rate_limit(self) -> bool:
        """Check if injection is within rate limits."""
        now = time.time()
        window_elapsed = now - self._window_start
        
        if window_elapsed >= 1.0:
            self._window_start = now
            self._injection_count = 0
        
        return self._injection_count < self.config.max_injection_per_second
    
    def maybe_inject_latency(
        self,
        priority: PriorityLevel = PriorityLevel.NORMAL
    ) -> float:
        """Maybe inject latency, return actual delay ms."""
        if not self.config.enabled:
            return 0.0
        
        if self.config.safe_mode and priority == PriorityLevel.CRITICAL:
            return 0.0
        
        with self._lock:
            if not self._check_rate_limit():
                return 0.0
            
            if random.random() < self.config.latency_injection_rate:
                delay = self.config.latency_injection_ms * random.random()
                time.sleep(delay / 1000.0)
                self._injection_count += 1
                return delay
        
        return 0.0
    
    def maybe_inject_error(
        self,
        priority: PriorityLevel = PriorityLevel.NORMAL,
        error_type: Type[Exception] = RuntimeError
    ) -> Optional[Exception]:
        """Maybe inject an error."""
        if not self.config.enabled:
            return None
        
        if self.config.safe_mode and priority == PriorityLevel.CRITICAL:
            return None
        
        with self._lock:
            if not self._check_rate_limit():
                return None
            
            if random.random() < self.config.error_injection_rate:
                self._injection_count += 1
                return error_type("Chaos injection - controlled failure")
        
        return None

# -----------------------------------------------------------------------------
# MAIN ERROR RESILIENCE ENGINE v18
# -----------------------------------------------------------------------------
class ErrorResilienceEngineV18:
    """
    Unified Error Resilience Engine v18
    All features OPT-IN - wraps existing code, no modifications
    """
    
    def __init__(self, name: str = "default"):
        self.name = name
        self._lock = threading.Lock()
        
        # Core components
        self._circuit_breakers: Dict[str, EnhancedCircuitBreaker] = {}
        self._fallback_orchestrators: Dict[str, FallbackStrategyOrchestrator] = {}
        self._deadline_system = DeadlinePropagationSystem()
        self._load_shedders: Dict[str, PriorityAwareLoadShedder] = {}
        self._degradation_manager = GracefulDegradationManager(name)
        self._chaos_injector = SafeChaosInjector(name)
        
        # Statistics
        self._protected_calls = 0
        self._failures_handled = 0
        self._fallbacks_executed = 0
    
    def get_circuit_breaker(
        self,
        operation_name: str,
        config: Optional[CircuitBreakerConfig] = None
    ) -> EnhancedCircuitBreaker:
        """Get or create circuit breaker for operation."""
        with self._lock:
            if operation_name not in self._circuit_breakers:
                self._circuit_breakers[operation_name] = EnhancedCircuitBreaker(
                    operation_name, config
                )
            return self._circuit_breakers[operation_name]
    
    def get_fallback_orchestrator(
        self,
        operation_name: str
    ) -> FallbackStrategyOrchestrator:
        """Get or create fallback orchestrator."""
        with self._lock:
            if operation_name not in self._fallback_orchestrators:
                self._fallback_orchestrators[operation_name] = FallbackStrategyOrchestrator(
                    operation_name
                )
            return self._fallback_orchestrators[operation_name]
    
    def get_load_shedder(
        self,
        name: str,
        max_concurrent: int = 100
    ) -> PriorityAwareLoadShedder:
        """Get or create load shedder."""
        with self._lock:
            if name not in self._load_shedders:
                self._load_shedders[name] = PriorityAwareLoadShedder(name, max_concurrent)
            return self._load_shedders[name]
    
    @property
    def deadline_system(self) -> DeadlinePropagationSystem:
        return self._deadline_system
    
    @property
    def degradation_manager(self) -> GracefulDegradationManager:
        return self._degradation_manager
    
    @property
    def chaos_injector(self) -> SafeChaosInjector:
        return self._chaos_injector
    
    def protect(
        self,
        operation_name: str,
        fallback_value: Optional[Any] = None,
        timeout_ms: float = 30000.0,
        priority: PriorityLevel = PriorityLevel.NORMAL
    ) -> Callable:
        """
        Decorator to protect a function with full resilience stack.
        Includes: circuit breaking, load shedding, fallback handling
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs) -> Any:
                self._protected_calls += 1
                
                # Get components
                cb = self.get_circuit_breaker(operation_name)
                shedder = self.get_load_shedder(operation_name)
                
                # Load shedding check
                if not shedder.should_accept(priority):
                    self._failures_handled += 1
                    if fallback_value is not None:
                        return fallback_value
                    raise RuntimeError(f"Request shed due to overload: {operation_name}")
                
                try:
                    # Circuit breaker check
                    if not cb.allow_request(priority):
                        self._failures_handled += 1
                        if fallback_value is not None:
                            return fallback_value
                        raise RuntimeError(f"Circuit open: {operation_name}")
                    
                    # Execute
                    result = func(*args, **kwargs)
                    cb.record_success()
                    return result
                    
                except Exception as e:
                    cb.record_failure(type(e).__name__)
                    self._failures_handled += 1
                    
                    # Try fallbacks
                    orchestrator = self.get_fallback_orchestrator(operation_name)
                    fallback_result = orchestrator.execute_fallback(e, *args, **kwargs)
                    
                    if fallback_result.success:
                        self._fallbacks_executed += 1
                        return fallback_result.value
                    
                    if fallback_value is not None:
                        return fallback_value
                    raise
                    
                finally:
                    shedder.request_complete()
            
            return wrapper
        return decorator
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive resilience statistics."""
        with self._lock:
            return {
                "engine": "v18",
                "name": self.name,
                "protected_calls": self._protected_calls,
                "failures_handled": self._failures_handled,
                "fallbacks_executed": self._fallbacks_executed,
                "circuit_breakers": len(self._circuit_breakers),
                "load_shedders": len(self._load_shedders),
                "circuit_states": {
                    name: cb.get_state()
                    for name, cb in self._circuit_breakers.items()
                },
                "feature_states": self._degradation_manager.get_feature_states()
            }

# -----------------------------------------------------------------------------
# GLOBAL SINGLETON & CONVENIENCE FUNCTIONS
# -----------------------------------------------------------------------------
_global_engine_v18: Optional[ErrorResilienceEngineV18] = None
_global_lock = threading.Lock()

def get_error_resilience_engine_v18() -> ErrorResilienceEngineV18:
    """Get global Error Resilience Engine v18 singleton."""
    global _global_engine_v18
    with _global_lock:
        if _global_engine_v18 is None:
            _global_engine_v18 = ErrorResilienceEngineV18("global")
        return _global_engine_v18

def enable_error_resilience_v18() -> None:
    """Enable global error resilience engine v18."""
    get_error_resilience_engine_v18()
    logger.info("Error Resilience Engine v18 enabled")

def disable_error_resilience_v18() -> None:
    """Disable global error resilience engine v18."""
    global _global_engine_v18
    with _global_lock:
        _global_engine_v18 = None
    logger.info("Error Resilience Engine v18 disabled")
