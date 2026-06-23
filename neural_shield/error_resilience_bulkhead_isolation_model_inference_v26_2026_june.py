"""
NeuralShield AI - Error Resilience Bulkhead Isolation v26
Dimension E: Error Resilience - ADD-ONLY implementation

Bulkhead isolation pattern for AI model inference operations.
Isolates different model operations into separate thread pools to prevent
cascading failures. One failing model won't take down the entire system.

Philosophy: ADD-ONLY, wrap existing code, 100% backward compatible
"""

import threading
import time
import queue
import logging
from typing import Callable, Any, Dict, Optional, TypeVar, Generic
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import concurrent.futures

# Configure logging - OPT-IN only
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

T = TypeVar('T')
R = TypeVar('R')


class BulkheadState(Enum):
    """Bulkhead compartment state"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    SATURATED = "saturated"
    TRIPPED = "tripped"


@dataclass
class BulkheadMetrics:
    """Metrics for a single bulkhead compartment"""
    active_requests: int = 0
    queued_requests: int = 0
    completed_requests: int = 0
    failed_requests: int = 0
    timed_out_requests: int = 0
    rejected_requests: int = 0
    total_execution_time_ns: int = 0
    last_failure_time: Optional[float] = None
    state: BulkheadState = BulkheadState.HEALTHY


@dataclass
class BulkheadConfig:
    """Configuration for a bulkhead compartment"""
    max_concurrent_requests: int = 10
    max_queue_size: int = 100
    request_timeout_seconds: float = 30.0
    failure_threshold: int = 5
    failure_window_seconds: float = 60.0
    recovery_timeout_seconds: float = 30.0
    queue_wait_timeout_seconds: float = 5.0


class BulkheadCompartment(Generic[T, R]):
    """
    Isolated bulkhead compartment for executing operations.
    Each compartment has its own thread pool and failure detection.
    """

    def __init__(
        self,
        name: str,
        config: Optional[BulkheadConfig] = None
    ):
        self.name = name
        self.config = config or BulkheadConfig()
        self.metrics = BulkheadMetrics()
        self._lock = threading.RLock()
        self._executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self._failure_timestamps: list = []
        self._tripped_at: Optional[float] = None
        self._initialized = False

    def _initialize(self) -> None:
        """Lazy initialization of thread pool"""
        if not self._initialized:
            self._executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=self.config.max_concurrent_requests,
                thread_name_prefix=f"bulkhead-{self.name}"
            )
            self._initialized = True

    def _check_state(self) -> BulkheadState:
        """Check and update bulkhead state"""
        now = time.time()

        # Check if tripped and in recovery period
        if self._tripped_at is not None:
            if now - self._tripped_at >= self.config.recovery_timeout_seconds:
                self._tripped_at = None
                self._failure_timestamps.clear()
                logger.info(f"Bulkhead {self.name}: Recovery timeout elapsed, resetting")
            else:
                return BulkheadState.TRIPPED

        # Clean old failure timestamps
        cutoff = now - self.config.failure_window_seconds
        self._failure_timestamps = [
            t for t in self._failure_timestamps if t > cutoff
        ]

        # Determine state based on metrics
        with self._lock:
            active = self.metrics.active_requests
            queued = self.metrics.queued_requests
            failures = len(self._failure_timestamps)

        if failures >= self.config.failure_threshold:
            self._tripped_at = now
            logger.warning(
                f"Bulkhead {self.name}: TRIPPED - {failures} failures "
                f"in window, rejecting all requests"
            )
            return BulkheadState.TRIPPED

        if active >= self.config.max_concurrent_requests:
            return BulkheadState.SATURATED

        if active >= self.config.max_concurrent_requests * 0.8 or queued >= 20:
            return BulkheadState.DEGRADED

        return BulkheadState.HEALTHY

    def _record_failure(self) -> None:
        """Record a failure for circuit breaking"""
        now = time.time()
        with self._lock:
            self._failure_timestamps.append(now)
            self.metrics.failed_requests += 1
            self.metrics.last_failure_time = now

    def execute(
        self,
        func: Callable[[T], R],
        arg: T,
        fallback: Optional[Callable[[Exception], R]] = None
    ) -> R:
        """
        Execute function within this bulkhead compartment.
        
        Args:
            func: Function to execute
            arg: Single argument for the function
            fallback: Optional fallback function if execution fails
            
        Returns:
            Function result or fallback result
            
        Raises:
            BulkheadRejectedError: If bulkhead is tripped or saturated
            TimeoutError: If execution times out
        """
        self._initialize()
        state = self._check_state()

        if state == BulkheadState.TRIPPED:
            with self._lock:
                self.metrics.rejected_requests += 1
            
            if fallback:
                logger.warning(f"Bulkhead {self.name}: TRIPPED, using fallback")
                return fallback(BulkheadTrippedError(f"Bulkhead {self.name} is tripped"))
            raise BulkheadTrippedError(
                f"Bulkhead {self.name} is tripped due to excessive failures"
            )

        start_time = time.time_ns()

        try:
            with self._lock:
                self.metrics.queued_requests += 1

            # Submit to executor with timeout
            future = self._executor.submit(func, arg)
            
            with self._lock:
                self.metrics.queued_requests -= 1
                self.metrics.active_requests += 1

            try:
                result = future.result(
                    timeout=self.config.request_timeout_seconds
                )
                
                with self._lock:
                    self.metrics.completed_requests += 1
                    self.metrics.total_execution_time_ns += (
                        time.time_ns() - start_time
                    )
                
                return result

            except concurrent.futures.TimeoutError:
                with self._lock:
                    self.metrics.timed_out_requests += 1
                self._record_failure()
                
                if fallback:
                    logger.warning(
                        f"Bulkhead {self.name}: Execution timed out, using fallback"
                    )
                    return fallback(TimeoutError(f"Operation timed out"))
                raise

        except Exception as e:
            self._record_failure()
            if fallback:
                logger.warning(
                    f"Bulkhead {self.name}: Execution failed: {e}, using fallback"
                )
                return fallback(e)
            raise

        finally:
            with self._lock:
                if self.metrics.active_requests > 0:
                    self.metrics.active_requests -= 1

    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics for this bulkhead"""
        with self._lock:
            state = self._check_state()
            self.metrics.state = state
            return {
                "name": self.name,
                "state": state.value,
                "active_requests": self.metrics.active_requests,
                "queued_requests": self.metrics.queued_requests,
                "completed_requests": self.metrics.completed_requests,
                "failed_requests": self.metrics.failed_requests,
                "timed_out_requests": self.metrics.timed_out_requests,
                "rejected_requests": self.metrics.rejected_requests,
                "avg_execution_time_ms": (
                    self.metrics.total_execution_time_ns / 
                    max(1, self.metrics.completed_requests) / 1_000_000
                ),
                "tripped": self._tripped_at is not None
            }

    def reset(self) -> None:
        """Reset bulkhead state and metrics"""
        with self._lock:
            self._tripped_at = None
            self._failure_timestamps.clear()
            self.metrics = BulkheadMetrics()
            logger.info(f"Bulkhead {self.name}: Reset complete")

    def shutdown(self) -> None:
        """Shutdown the bulkhead executor"""
        if self._executor:
            self._executor.shutdown(wait=False)
            self._initialized = False


class BulkheadError(Exception):
    """Base exception for bulkhead errors"""
    pass


class BulkheadTrippedError(BulkheadError):
    """Raised when bulkhead is tripped"""
    pass


class BulkheadSaturatedError(BulkheadError):
    """Raised when bulkhead is saturated"""
    pass


class ModelInferenceBulkheadManager:
    """
    Manager for bulkhead-isolated model inference operations.
    Creates separate compartments for different model types.
    """

    # Predefined model categories for isolation
    MODEL_CATEGORIES = {
        "prompt_injection": BulkheadConfig(
            max_concurrent_requests=8,
            max_queue_size=50,
            request_timeout_seconds=15.0
        ),
        "jailbreak_detection": BulkheadConfig(
            max_concurrent_requests=6,
            max_queue_size=40,
            request_timeout_seconds=20.0
        ),
        "threat_intelligence": BulkheadConfig(
            max_concurrent_requests=12,
            max_queue_size=100,
            request_timeout_seconds=45.0
        ),
        "adversarial_detection": BulkheadConfig(
            max_concurrent_requests=5,
            max_queue_size=30,
            request_timeout_seconds=25.0
        ),
        "behavioral_analysis": BulkheadConfig(
            max_concurrent_requests=10,
            max_queue_size=80,
            request_timeout_seconds=30.0
        ),
        "default": BulkheadConfig(
            max_concurrent_requests=4,
            max_queue_size=20,
            request_timeout_seconds=30.0
        )
    }

    def __init__(self):
        self._bulkheads: Dict[str, BulkheadCompartment] = {}
        self._lock = threading.RLock()
        self._initialized = False

    def _get_bulkhead(self, category: str) -> BulkheadCompartment:
        """Get or create bulkhead for a category"""
        with self._lock:
            if category not in self._bulkheads:
                config = self.MODEL_CATEGORIES.get(
                    category,
                    self.MODEL_CATEGORIES["default"]
                )
                self._bulkheads[category] = BulkheadCompartment(
                    name=category,
                    config=config
                )
            return self._bulkheads[category]

    def execute_inference(
        self,
        category: str,
        inference_func: Callable,
        input_data: Any,
        fallback: Optional[Callable] = None
    ) -> Any:
        """
        Execute model inference within the appropriate bulkhead.
        
        Args:
            category: Model category (determines isolation compartment)
            inference_func: The inference function to execute
            input_data: Input data for the inference
            fallback: Optional fallback function
            
        Returns:
            Inference result or fallback result
        """
        bulkhead = self._get_bulkhead(category)
        return bulkhead.execute(inference_func, input_data, fallback)

    def get_all_metrics(self) -> Dict[str, Any]:
        """Get metrics for all bulkheads"""
        with self._lock:
            return {
                name: bulkhead.get_metrics()
                for name, bulkhead in self._bulkheads.items()
            }

    def get_health_summary(self) -> Dict[str, Any]:
        """Get overall health summary"""
        metrics = self.get_all_metrics()
        states = [m["state"] for m in metrics.values()]
        
        return {
            "total_bulkheads": len(metrics),
            "healthy_count": states.count("healthy"),
            "degraded_count": states.count("degraded"),
            "saturated_count": states.count("saturated"),
            "tripped_count": states.count("tripped"),
            "overall_health": (
                "GREEN" if "tripped" not in states and "saturated" not in states
                else "YELLOW" if "tripped" not in states
                else "RED"
            ),
            "bulkheads": metrics
        }

    def reset_all(self) -> None:
        """Reset all bulkheads"""
        with self._lock:
            for bulkhead in self._bulkheads.values():
                bulkhead.reset()

    def shutdown_all(self) -> None:
        """Shutdown all bulkheads"""
        with self._lock:
            for bulkhead in self._bulkheads.values():
                bulkhead.shutdown()
            self._bulkheads.clear()


# Global singleton instance - OPT-IN usage only
_model_bulkhead_manager: Optional[ModelInferenceBulkheadManager] = None
_manager_lock = threading.Lock()


def get_model_bulkhead_manager() -> ModelInferenceBulkheadManager:
    """Get the global bulkhead manager instance (lazy initialized)"""
    global _model_bulkhead_manager
    if _model_bulkhead_manager is None:
        with _manager_lock:
            if _model_bulkhead_manager is None:
                _model_bulkhead_manager = ModelInferenceBulkheadManager()
    return _model_bulkhead_manager


def bulkheaded_inference(
    category: str,
    fallback: Optional[Callable] = None
):
    """
    Decorator for bulkhead-isolated model inference.
    
    Usage:
        @bulkheaded_inference("prompt_injection", fallback=my_fallback_func)
        def run_inference(input_data):
            return model.predict(input_data)
    """
    def decorator(func: Callable) -> Callable:
        def wrapper(input_data: Any) -> Any:
            manager = get_model_bulkhead_manager()
            return manager.execute_inference(
                category=category,
                inference_func=func,
                input_data=input_data,
                fallback=fallback
            )
        return wrapper
    return decorator


# Simple safe fallback functions
def safe_empty_fallback(error: Exception) -> Dict:
    """Fallback that returns empty safe result"""
    return {
        "safe": True,
        "risk_score": 0.0,
        "warnings": ["Using fallback mode - bulkhead protection active"],
        "bulkhead_protection": True
    }


def safe_deny_fallback(error: Exception) -> Dict:
    """Fallback that denies by default (secure fallback)"""
    return {
        "safe": False,
        "risk_score": 1.0,
        "action": "block",
        "reason": "System protection active - bulkhead circuit triggered",
        "bulkhead_protection": True
    }


"""
END OF MODULE - Dimension E: Error Resilience
ADD-ONLY implementation - wraps existing code without modification
100% backward compatible - existing code works unchanged
All instrumentation is OPT-IN via decorator or explicit manager usage
"""
