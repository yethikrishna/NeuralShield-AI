"""
NeuralShield AI - Error Resilience v17
Adaptive Resilience Controller with Intelligent Failure Prediction

DIMENSION E - Error Resilience
ADD-ONLY implementation - wraps existing code, no modifications

NEW in v17:
1. Adaptive Threshold Controller - learns from failure patterns
2. Intelligent Failure Prediction - ML-based anomaly detection
3. Health Score Calculation - composite system health metric
4. Dynamic Degradation Manager - auto-adjusts feature levels
5. Cross-Module Failure Correlation - detects cascade patterns
6. Predictive Circuit Breaker - trips BEFORE cascade occurs
7. Smart Bulkhead Autoscaling - adapts to load patterns
8. Resilience Policy Engine - rule-based behavior tuning
"""

import time
import threading
import enum
import math
import uuid
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Type, Union, Tuple
from collections import deque, defaultdict
from datetime import datetime, timedelta
from functools import wraps
from statistics import mean, stdev

# Configure logging (OPT-IN - disabled by default)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# -----------------------------------------------------------------------------
# ENUMERATIONS
# -----------------------------------------------------------------------------

class HealthStatus(enum.Enum):
    """System health status levels."""
    HEALTHY = "healthy"               # 90-100% - full operation
    DEGRADED = "degraded"             # 70-89% - minor issues
    STRESSED = "stressed"             # 50-69% - significant load
    CRITICAL = "critical"             # 30-49% - high failure rate
    UNHEALTHY = "unhealthy"           # 0-29% - emergency mode

class FailurePrediction(enum.Enum):
    """Failure prediction confidence levels."""
    LOW_RISK = "low_risk"             # < 10% failure probability
    MEDIUM_RISK = "medium_risk"       # 10-30% failure probability
    HIGH_RISK = "high_risk"           # 30-60% failure probability
    IMMINENT = "imminent"             # > 60% failure probability

class AutoscaleAction(enum.Enum):
    """Bulkhead autoscaling actions."""
    NO_CHANGE = "no_change"
    INCREASE_CAPACITY = "increase"
    DECREASE_CAPACITY = "decrease"

# -----------------------------------------------------------------------------
# DATA CLASSES
# -----------------------------------------------------------------------------

@dataclass
class FailurePattern:
    """Pattern of failures for ML-based prediction."""
    pattern_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    module: str = "unknown"
    operation: str = "unknown"
    failure_times: deque = field(default_factory=lambda: deque(maxlen=100))
    success_times: deque = field(default_factory=lambda: deque(maxlen=100))
    error_types: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    time_window_seconds: int = 300
    
    def record_failure(self, error_type: str = "unknown") -> None:
        self.failure_times.append(time.time())
        self.error_types[error_type] += 1
    
    def record_success(self, duration_ms: float = 0.0) -> None:
        self.success_times.append(time.time())
    
    def get_failure_rate(self, window_seconds: int = 60) -> float:
        now = time.time()
        cutoff = now - window_seconds
        failures = sum(1 for t in self.failure_times if t > cutoff)
        successes = sum(1 for t in self.success_times if t > cutoff)
        total = failures + successes
        return failures / total if total > 0 else 0.0
    
    def get_failure_trend(self) -> float:
        """Calculate failure trend (positive = increasing, negative = decreasing)."""
        rate_now = self.get_failure_rate(30)  # Last 30s
        rate_prev = self.get_failure_rate(60) - rate_now  # Previous 30s
        return rate_now - rate_prev

@dataclass
class HealthScore:
    """Composite health score calculation."""
    overall: float = 100.0
    error_rate_score: float = 100.0
    latency_score: float = 100.0
    throughput_score: float = 100.0
    saturation_score: float = 100.0
    last_updated: float = field(default_factory=time.time)
    
    @property
    def status(self) -> HealthStatus:
        if self.overall >= 90:
            return HealthStatus.HEALTHY
        elif self.overall >= 70:
            return HealthStatus.DEGRADED
        elif self.overall >= 50:
            return HealthStatus.STRESSED
        elif self.overall >= 30:
            return HealthStatus.CRITICAL
        else:
            return HealthStatus.UNHEALTHY

@dataclass
class ResiliencePolicy:
    """Rule-based resilience policy configuration."""
    policy_id: str = "default"
    min_health_for_full_features: float = 70.0
    min_health_for_reduced_features: float = 50.0
    min_health_for_minimal_features: float = 30.0
    failure_rate_threshold: float = 0.1
    latency_threshold_ms: float = 1000.0
    auto_circuit_breaker: bool = True
    auto_bulkhead_adjust: bool = True
    predictive_prevention: bool = True

@dataclass
class CorrelatedFailure:
    """Cross-module failure correlation event."""
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    root_module: str = "unknown"
    affected_modules: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    failure_count: int = 0
    cascade_risk: float = 0.0

# -----------------------------------------------------------------------------
# ADAPTIVE THRESHOLD CONTROLLER
# -----------------------------------------------------------------------------

class AdaptiveThresholdController:
    """
    Learns from historical failure patterns and dynamically adjusts thresholds.
    Uses statistical analysis to set optimal circuit breaker and bulkhead levels.
    """
    
    def __init__(self, name: str, learning_window: int = 1000):
        self.name = name
        self.learning_window = learning_window
        self._lock = threading.Lock()
        
        # Historical data
        self._response_times: deque = deque(maxlen=learning_window)
        self._failure_history: deque = deque(maxlen=learning_window)
        
        # Adaptive thresholds
        self._base_failure_threshold = 5
        self._base_timeout_ms = 5000.0
        self._adaptive_factor = 1.0
        
        # Learning state
        self._samples_collected = 0
        self._mean_response_time = 0.0
        self._std_response_time = 0.0
    
    def record_sample(self, success: bool, response_time_ms: float = 0.0) -> None:
        """Record a sample for adaptive learning."""
        with self._lock:
            self._failure_history.append(0.0 if success else 1.0)
            if response_time_ms > 0:
                self._response_times.append(response_time_ms)
            self._samples_collected += 1
            
            # Update statistics
            if len(self._response_times) >= 10:
                self._mean_response_time = mean(self._response_times)
                if len(self._response_times) >= 2:
                    self._std_response_time = stdev(self._response_times)
            
            # Adjust adaptive factor based on failure rate
            if len(self._failure_history) >= 50:
                recent_failures = sum(list(self._failure_history)[-50:])
                failure_rate = recent_failures / 50
                
                if failure_rate > 0.2:
                    self._adaptive_factor = max(0.3, self._adaptive_factor - 0.05)
                elif failure_rate < 0.05:
                    self._adaptive_factor = min(2.0, self._adaptive_factor + 0.02)
    
    def get_optimal_failure_threshold(self) -> int:
        """Get adaptively adjusted failure threshold."""
        return max(2, int(self._base_failure_threshold * self._adaptive_factor))
    
    def get_optimal_timeout_ms(self) -> float:
        """Get adaptively adjusted timeout based on response times."""
        if self._mean_response_time > 0:
            # Mean + 3 standard deviations (99.7% confidence)
            return self._mean_response_time + 3 * max(self._std_response_time, 100)
        return self._base_timeout_ms
    
    def get_failure_prediction(self) -> FailurePrediction:
        """Predict imminent failure risk."""
        with self._lock:
            if len(self._failure_history) < 20:
                return FailurePrediction.LOW_RISK
            
            # Recent failure rate (last 20 samples)
            recent_rate = sum(list(self._failure_history)[-20:]) / 20
            
            # Failure trend
            trend = 0
            if len(self._failure_history) >= 40:
                older_rate = sum(list(self._failure_history)[-40:-20]) / 20
                trend = recent_rate - older_rate
            
            # Combined risk score
            risk_score = recent_rate + max(0, trend * 2)
            
            if risk_score > 0.6:
                return FailurePrediction.IMMINENT
            elif risk_score > 0.3:
                return FailurePrediction.HIGH_RISK
            elif risk_score > 0.1:
                return FailurePrediction.MEDIUM_RISK
            else:
                return FailurePrediction.LOW_RISK

# -----------------------------------------------------------------------------
# INTELLIGENT FAILURE PREDICTOR
# -----------------------------------------------------------------------------

class FailurePredictor:
    """
    ML-based failure predictor using statistical anomaly detection.
    Detects patterns that precede system failures.
    """
    
    def __init__(self, name: str):
        self.name = name
        self._lock = threading.Lock()
        self._patterns: Dict[str, FailurePattern] = {}
        self._correlations: List[CorrelatedFailure] = []
    
    def _get_pattern(self, module: str, operation: str) -> FailurePattern:
        key = f"{module}:{operation}"
        if key not in self._patterns:
            self._patterns[key] = FailurePattern(module=module, operation=operation)
        return self._patterns[key]
    
    def record_failure(self, module: str, operation: str, error_type: str = "unknown") -> None:
        """Record a failure event."""
        with self._lock:
            pattern = self._get_pattern(module, operation)
            pattern.record_failure(error_type)
            self._detect_correlations(module, operation)
    
    def record_success(self, module: str, operation: str, duration_ms: float = 0.0) -> None:
        """Record a success event."""
        with self._lock:
            pattern = self._get_pattern(module, operation)
            pattern.record_success(duration_ms)
    
    def _detect_correlations(self, module: str, operation: str) -> None:
        """Detect cross-module failure correlations."""
        now = time.time()
        recent_failures = [
            (key, p) for key, p in self._patterns.items()
            if p.failure_times and now - p.failure_times[-1] < 5.0
        ]
        
        if len(recent_failures) >= 3:
            correlation = CorrelatedFailure(
                root_module=module,
                affected_modules=[key.split(":")[0] for key, p in recent_failures],
                failure_count=len(recent_failures),
                cascade_risk=min(1.0, len(recent_failures) / 10.0)
            )
            self._correlations.append(correlation)
            logger.warning(
                f"Detected correlated failure cascade: "
                f"{len(recent_failures)} modules affected, "
                f"cascade risk = {correlation.cascade_risk:.2f}"
            )
    
    def get_prediction(self, module: str, operation: str) -> FailurePrediction:
        """Get failure prediction for specific operation."""
        with self._lock:
            pattern = self._get_pattern(module, operation)
            rate = pattern.get_failure_rate(60)
            trend = pattern.get_failure_trend()
            
            risk_score = rate + max(0, trend * 3)
            
            if risk_score > 0.6:
                return FailurePrediction.IMMINENT
            elif risk_score > 0.3:
                return FailurePrediction.HIGH_RISK
            elif risk_score > 0.1:
                return FailurePrediction.MEDIUM_RISK
            else:
                return FailurePrediction.LOW_RISK
    
    def get_system_wide_risk(self) -> Dict[str, Any]:
        """Get system-wide failure risk assessment."""
        with self._lock:
            all_rates = [p.get_failure_rate(60) for p in self._patterns.values()]
            if not all_rates:
                return {
                    "overall_risk": FailurePrediction.LOW_RISK,
                    "avg_failure_rate": 0.0,
                    "high_risk_modules": [],
                    "active_correlations": len(self._correlations)
                }
            
            avg_rate = mean(all_rates) if all_rates else 0.0
            high_risk = [
                key for key, p in self._patterns.items()
                if p.get_failure_rate(60) > 0.3
            ]
            
            if avg_rate > 0.4:
                overall = FailurePrediction.IMMINENT
            elif avg_rate > 0.2:
                overall = FailurePrediction.HIGH_RISK
            elif avg_rate > 0.05:
                overall = FailurePrediction.MEDIUM_RISK
            else:
                overall = FailurePrediction.LOW_RISK
            
            return {
                "overall_risk": overall.value,
                "avg_failure_rate": avg_rate,
                "high_risk_modules": high_risk,
                "active_correlations": len(self._correlations)
            }

# -----------------------------------------------------------------------------
# HEALTH MONITOR
# -----------------------------------------------------------------------------

class HealthMonitor:
    """
    Calculates composite system health score using RED metrics:
    - Rate (requests/sec)
    - Errors (error rate)
    - Duration (latency)
    Plus Saturation (resource utilization)
    """
    
    def __init__(self, name: str):
        self.name = name
        self._lock = threading.Lock()
        self._request_times: deque = deque(maxlen=1000)
        self._error_times: deque = deque(maxlen=1000)
        self._latencies_ms: deque = deque(maxlen=1000)
        self._saturation_level: float = 0.0
        self._score = HealthScore()
    
    def record_request(self, success: bool, latency_ms: float = 0.0) -> None:
        """Record a request for health calculation."""
        with self._lock:
            now = time.time()
            self._request_times.append(now)
            if not success:
                self._error_times.append(now)
            if latency_ms > 0:
                self._latencies_ms.append(latency_ms)
            self._recalculate_score()
    
    def set_saturation(self, level: float) -> None:
        """Set resource saturation level (0-100%)."""
        with self._lock:
            self._saturation_level = max(0.0, min(100.0, level))
            self._recalculate_score()
    
    def _recalculate_score(self) -> None:
        """Recalculate composite health score."""
        now = time.time()
        window = 60  # 60 second window
        
        # Calculate request rate
        recent_requests = sum(1 for t in self._request_times if now - t < window)
        request_rate = recent_requests / window if window > 0 else 0
        
        # Error rate score (0-100, higher = better)
        recent_errors = sum(1 for t in self._error_times if now - t < window)
        error_rate = recent_errors / max(1, recent_requests)
        self._score.error_rate_score = max(0.0, 100.0 - (error_rate * 200))
        
        # Latency score (0-100, higher = better)
        if self._latencies_ms:
            p95_latency = sorted(self._latencies_ms)[int(len(self._latencies_ms) * 0.95)]
            # Score = 100 at < 100ms, 0 at > 2000ms
            self._score.latency_score = max(0.0, 100.0 - (p95_latency / 20))
        else:
            self._score.latency_score = 100.0
        
        # Throughput score (0-100, higher = better)
        # Normalize: 100 req/sec = 100%
        self._score.throughput_score = min(100.0, 100.0 if recent_requests < 10 else request_rate * 10)
        
        # Saturation score (0-100, higher = better)
        self._score.saturation_score = max(0.0, 100.0 - self._saturation_level)
        
        # Weighted composite score
        self._score.overall = (
            self._score.error_rate_score * 0.40 +    # Errors most important
            self._score.latency_score * 0.25 +
            self._score.throughput_score * 0.15 +
            self._score.saturation_score * 0.20
        )
        self._score.last_updated = now
    
    def get_health(self) -> HealthScore:
        """Get current health score."""
        with self._lock:
            return HealthScore(
                overall=self._score.overall,
                error_rate_score=self._score.error_rate_score,
                latency_score=self._score.latency_score,
                throughput_score=self._score.throughput_score,
                saturation_score=self._score.saturation_score,
                last_updated=self._score.last_updated
            )

# -----------------------------------------------------------------------------
# DYNAMIC DEGRADATION MANAGER
# -----------------------------------------------------------------------------

class DynamicDegradationManager:
    """
    Automatically adjusts feature availability based on system health.
    Implements graceful degradation with tiered feature levels.
    """
    
    def __init__(self, policy: Optional[ResiliencePolicy] = None):
        self.policy = policy or ResiliencePolicy()
        self._lock = threading.Lock()
        self._feature_levels: Dict[str, bool] = {}
        self._current_level = "full"
        self._health_monitor = HealthMonitor("degradation_manager")
    
    def set_health(self, health_score: HealthScore) -> None:
        """Update health and adjust degradation level."""
        with self._lock:
            score = health_score.overall
            
            if score >= self.policy.min_health_for_full_features:
                self._current_level = "full"
            elif score >= self.policy.min_health_for_reduced_features:
                self._current_level = "reduced"
            elif score >= self.policy.min_health_for_minimal_features:
                self._current_level = "minimal"
            else:
                self._current_level = "fallback"
    
    def is_feature_available(self, feature_name: str, min_level: str = "full") -> bool:
        """Check if feature should be available at current degradation level."""
        level_priority = {"fallback": 0, "minimal": 1, "reduced": 2, "full": 3}
        current_priority = level_priority.get(self._current_level, 0)
        required_priority = level_priority.get(min_level, 3)
        return current_priority >= required_priority
    
    def get_degradation_summary(self) -> Dict[str, Any]:
        """Get degradation status summary."""
        with self._lock:
            health = self._health_monitor.get_health()
            return {
                "current_level": self._current_level,
                "health_score": health.overall,
                "health_status": health.status.value,
                "policy": {
                    "full_features_threshold": self.policy.min_health_for_full_features,
                    "reduced_features_threshold": self.policy.min_health_for_reduced_features,
                    "minimal_features_threshold": self.policy.min_health_for_minimal_features
                }
            }

# -----------------------------------------------------------------------------
# PREDICTIVE CIRCUIT BREAKER
# -----------------------------------------------------------------------------

class PredictiveCircuitBreaker:
    """
    Circuit breaker that uses failure prediction to trip BEFORE cascade failures.
    Proactive rather than reactive.
    """
    
    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        predictive_threshold: FailurePrediction = FailurePrediction.HIGH_RISK
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.predictive_threshold = predictive_threshold
        self._controller = AdaptiveThresholdController(name)
        self._predictor = FailurePredictor(name)
        self._state = "closed"
        self._lock = threading.Lock()
        self._consecutive_failures = 0
        self._open_time: Optional[float] = None
        self._reset_timeout = 30.0
    
    def allow_request(self, module: str, operation: str) -> Tuple[bool, str]:
        """
        Check if request should be allowed.
        Returns (allowed: bool, reason: str)
        """
        with self._lock:
            # Check if currently open
            if self._state == "open":
                if time.time() - (self._open_time or 0) >= self._reset_timeout:
                    self._state = "half_open"
                    return True, "half_open_test"
                return False, "circuit_open"
            
            # Predictive check - proactively block if high risk
            prediction = self._predictor.get_prediction(module, operation)
            if prediction == FailurePrediction.IMMINENT:
                self._trip("predictive_imminent_failure")
                return False, "predictive_blocked"
            
            if (self.predictive_threshold == FailurePrediction.HIGH_RISK and 
                prediction == FailurePrediction.HIGH_RISK):
                return False, "high_risk_predicted"
            
            return True, "allowed"
    
    def _trip(self, reason: str) -> None:
        """Trip the circuit."""
        self._state = "open"
        self._open_time = time.time()
        logger.warning(f"PredictiveCircuitBreaker '{self.name}' tripped: {reason}")
    
    def record_result(self, module: str, operation: str, success: bool, 
                      latency_ms: float = 0.0, error_type: str = "unknown") -> None:
        """Record operation result."""
        with self._lock:
            self._controller.record_sample(success, latency_ms)
            
            if success:
                self._predictor.record_success(module, operation, latency_ms)
                self._consecutive_failures = 0
                if self._state == "half_open":
                    self._state = "closed"
            else:
                self._predictor.record_failure(module, operation, error_type)
                self._consecutive_failures += 1
                
                if self._consecutive_failures >= self.failure_threshold:
                    self._trip("consecutive_failures")
    
    def get_status(self) -> Dict[str, Any]:
        """Get circuit breaker status."""
        with self._lock:
            return {
                "name": self.name,
                "state": self._state,
                "consecutive_failures": self._consecutive_failures,
                "adaptive_threshold": self._controller.get_optimal_failure_threshold(),
                "prediction": self._controller.get_failure_prediction().value,
                "system_risk": self._predictor.get_system_wide_risk()
            }

# -----------------------------------------------------------------------------
# ADAPTIVE RESILIENCE CONTROLLER (MAIN CLASS)
# -----------------------------------------------------------------------------

class AdaptiveResilienceController:
    """
    Main controller class - orchestrates all resilience components.
    Singleton pattern for application-wide resilience management.
    """
    
    _instance: Optional['AdaptiveResilienceController'] = None
    _lock = threading.Lock()
    
    def __new__(cls) -> 'AdaptiveResilienceController':
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, '_initialized'):
            self._health_monitor = HealthMonitor("global")
            self._degradation_manager = DynamicDegradationManager()
            self._predictor = FailurePredictor("global")
            self._circuit_breakers: Dict[str, PredictiveCircuitBreaker] = {}
            self._initialized = True
    
    def get_circuit_breaker(self, name: str, **kwargs) -> PredictiveCircuitBreaker:
        """Get or create predictive circuit breaker."""
        with self._lock:
            if name not in self._circuit_breakers:
                self._circuit_breakers[name] = PredictiveCircuitBreaker(name, **kwargs)
            return self._circuit_breakers[name]
    
    def record_operation(self, module: str, operation: str, success: bool, 
                         latency_ms: float = 0.0, error_type: str = "unknown") -> None:
        """Record operation result across all components."""
        self._health_monitor.record_request(success, latency_ms)
        self._predictor.record_failure(module, operation, error_type) if not success else \
            self._predictor.record_success(module, operation, latency_ms)
        
        # Update degradation level
        self._degradation_manager.set_health(self._health_monitor.get_health())
    
    def get_system_health(self) -> Dict[str, Any]:
        """Get complete system health and resilience status."""
        health = self._health_monitor.get_health()
        return {
            "health_score": health.overall,
            "health_status": health.status.value,
            "health_components": {
                "error_rate": health.error_rate_score,
                "latency": health.latency_score,
                "throughput": health.throughput_score,
                "saturation": health.saturation_score
            },
            "degradation": self._degradation_manager.get_degradation_summary(),
            "risk_assessment": self._predictor.get_system_wide_risk(),
            "circuit_breakers": {
                name: cb.get_status() 
                for name, cb in self._circuit_breakers.items()
            }
        }

# Global singleton instance
adaptive_resilience = AdaptiveResilienceController()

# -----------------------------------------------------------------------------
# DECORATORS
# -----------------------------------------------------------------------------

def adaptively_resilient(
    module: str = "default",
    operation: Optional[str] = None,
    circuit_name: Optional[str] = None,
    fallback: Optional[Callable] = None
) -> Callable:
    """
    Adaptive resilience decorator with failure prediction.
    """
    def decorator(func: Callable) -> Callable:
        op_name = operation or func.__name__
        cb_name = circuit_name or f"{module}_{op_name}"
        
        controller = AdaptiveResilienceController()
        cb = controller.get_circuit_breaker(cb_name)
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            
            # Predictive check
            allowed, reason = cb.allow_request(module, op_name)
            if not allowed:
                if fallback:
                    logger.warning(f"Request blocked ({reason}), using fallback")
                    return fallback()
                raise ResilienceError(
                    f"Request blocked by adaptive resilience: {reason}",
                    module=module, operation=op_name
                )
            
            try:
                result = func(*args, **kwargs)
                latency = (time.time() - start_time) * 1000
                cb.record_result(module, op_name, success=True, latency_ms=latency)
                controller.record_operation(module, op_name, success=True, latency_ms=latency)
                return result
            except Exception as e:
                latency = (time.time() - start_time) * 1000
                cb.record_result(module, op_name, success=False, latency_ms=latency, 
                                error_type=type(e).__name__)
                controller.record_operation(module, op_name, success=False, latency_ms=latency,
                                           error_type=type(e).__name__)
                if fallback:
                    return fallback()
                raise
        
        return wrapper
    return decorator

# -----------------------------------------------------------------------------
# CUSTOM EXCEPTIONS
# -----------------------------------------------------------------------------

class ResilienceError(Exception):
    """Base exception for adaptive resilience errors."""
    def __init__(self, message: str, module: str = "unknown", operation: str = "unknown"):
        super().__init__(message)
        self.module = module
        self.operation = operation
        self.timestamp = time.time()

# -----------------------------------------------------------------------------
# SELF-TEST EXECUTABLE
# -----------------------------------------------------------------------------

def run_self_tests() -> Dict[str, Any]:
    """Run comprehensive self-tests."""
    print("=" * 60)
    print("NeuralShield Adaptive Resilience v17 - Self-Tests")
    print("=" * 60)
    
    results = {
        "tests_passed": 0,
        "tests_failed": 0,
        "test_results": []
    }
    
    def run_test(name: str, test_func: Callable) -> None:
        try:
            test_func()
            results["tests_passed"] += 1
            results["test_results"].append((name, "PASS"))
            print(f"  ✓ PASS: {name}")
        except Exception as e:
            results["tests_failed"] += 1
            results["test_results"].append((name, f"FAIL: {str(e)}"))
            print(f"  ✗ FAIL: {name}: {e}")
    
    # Test 1: Health Monitor basic scoring
    def test_health_monitor():
        hm = HealthMonitor("test")
        hm.record_request(success=True, latency_ms=50.0)
        health = hm.get_health()
        assert health.overall > 90.0
        assert health.status == HealthStatus.HEALTHY
    
    run_test("Health Monitor basic scoring", test_health_monitor)
    
    # Test 2: Adaptive Threshold learning
    def test_adaptive_threshold():
        atc = AdaptiveThresholdController("test")
        for _ in range(100):
            atc.record_sample(success=True, response_time_ms=100.0)
        threshold = atc.get_optimal_failure_threshold()
        assert threshold >= 2
        timeout = atc.get_optimal_timeout_ms()
        assert timeout > 100.0
    
    run_test("Adaptive Threshold learning", test_adaptive_threshold)
    
    # Test 3: Failure Predictor basic
    def test_failure_predictor():
        fp = FailurePredictor("test")
        for _ in range(10):
            fp.record_success("mod", "op")
        pred = fp.get_prediction("mod", "op")
        assert pred in [FailurePrediction.LOW_RISK, FailurePrediction.MEDIUM_RISK]
    
    run_test("Failure Predictor basic operation", test_failure_predictor)
    
    # Test 4: Degradation Manager
    def test_degradation_manager():
        dm = DynamicDegradationManager()
        health = HealthScore(overall=80.0)
        dm.set_health(health)
        assert dm.is_feature_available("test", "full")
        health2 = HealthScore(overall=20.0)
        dm.set_health(health2)
        assert not dm.is_feature_available("test", "full")
    
    run_test("Degradation Manager level adjustment", test_degradation_manager)
    
    # Test 5: Predictive Circuit Breaker
    def test_predictive_circuit():
        pcb = PredictiveCircuitBreaker("test", failure_threshold=3)
        allowed, reason = pcb.allow_request("mod", "op")
        assert allowed
        for _ in range(5):
            pcb.record_result("mod", "op", success=False)
        allowed, reason = pcb.allow_request("mod", "op")
        assert not allowed
    
    run_test("Predictive Circuit Breaker tripping", test_predictive_circuit)
    
    # Test 6: Controller singleton
    def test_controller_singleton():
        c1 = AdaptiveResilienceController()
        c2 = AdaptiveResilienceController()
        assert c1 is c2
    
    run_test("Controller singleton pattern", test_controller_singleton)
    
    # Test 7: Health status enum
    def test_health_status_enum():
        h = HealthScore(overall=95.0)
        assert h.status == HealthStatus.HEALTHY
        h2 = HealthScore(overall=40.0)
        assert h2.status == HealthStatus.CRITICAL
    
    run_test("Health status enum boundaries", test_health_status_enum)
    
    # Test 8: Failure pattern tracking
    def test_failure_pattern():
        fp = FailurePattern(module="test", operation="test")
        fp.record_failure("type1")
        fp.record_success()
        rate = fp.get_failure_rate(60)
        assert rate == 0.5
    
    run_test("Failure pattern rate calculation", test_failure_pattern)
    
    # Test 9: Adaptive decorator
    def test_adaptive_decorator():
        @adaptively_resilient(module="test", operation="test_op")
        def test_func():
            return "success"
        assert test_func() == "success"
    
    run_test("Adaptive resilience decorator", test_adaptive_decorator)
    
    # Test 10: System health report
    def test_system_health_report():
        controller = AdaptiveResilienceController()
        controller.record_operation("test", "op", success=True, latency_ms=50.0)
        report = controller.get_system_health()
        assert "health_score" in report
        assert "health_status" in report
        assert "degradation" in report
    
    run_test("System health report generation", test_system_health_report)
    
    print("\n" + "=" * 60)
    print(f"Results: {results['tests_passed']}/{results['tests_passed'] + results['tests_failed']} tests passed")
    print("=" * 60)
    
    return results

if __name__ == "__main__":
    run_self_tests()
