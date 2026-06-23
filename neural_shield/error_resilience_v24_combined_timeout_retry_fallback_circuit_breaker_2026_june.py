"""
NeuralShield AI - Error Resilience Module v24
Combined Timeout + Retry + Fallback + Circuit Breaker Integration
DIMENSION E - Error Resilience
- Custom exception hierarchy with metadata
- 6 backoff strategies (exponential, linear, fixed, fibonacci, jitter)
- Advanced circuit breaker with health tracking
- Bulkhead resource isolation
- Fallback chain orchestration with 4 priority strategies
- Combined resilience decorator (sync/async)
- Global orchestrator singleton
ADD-ONLY implementation - wraps existing code, no modifications
Happy path behavior 100% preserved
All instrumentation OPT-IN, never required
"""
import time
import random
import threading
import functools
import logging
import inspect
from typing import Any, Callable, Dict, List, Optional, Type, Union, Tuple, Awaitable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import asyncio
from contextlib import contextmanager
import uuid

# Configure logging (disabled by default - OPT-IN)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ============================================================================
# CUSTOM EXCEPTION HIERARCHY
# ============================================================================

class ErrorResilienceBaseError(Exception):
    """Base exception for all error resilience operations."""
    def __init__(self, message: str, operation_id: Optional[str] = None, **kwargs):
        self.operation_id = operation_id or str(uuid.uuid4())
        self.timestamp = time.time()
        self.metadata = kwargs
        super().__init__(f"[{self.operation_id}] {message}")


class TimeoutExceededError(ErrorResilienceBaseError):
    """Raised when operation exceeds timeout threshold."""
    pass


class MaxRetriesExceededError(ErrorResilienceBaseError):
    """Raised when maximum retry attempts exhausted."""
    def __init__(self, message: str, attempts: int, last_exception: Optional[Exception] = None, **kwargs):
        self.attempts = attempts
        self.last_exception = last_exception
        super().__init__(message, attempts=attempts, **kwargs)


class CircuitBreakerOpenError(ErrorResilienceBaseError):
    """Raised when circuit breaker is in OPEN state."""
    def __init__(self, message: str, reset_timeout: float, **kwargs):
        self.reset_timeout = reset_timeout
        super().__init__(message, reset_timeout=reset_timeout, **kwargs)


class BulkheadCapacityExceededError(ErrorResilienceBaseError):
    """Raised when bulkhead concurrency limit exceeded."""
    def __init__(self, message: str, current_concurrency: int, max_concurrency: int, **kwargs):
        self.current_concurrency = current_concurrency
        self.max_concurrency = max_concurrency
        super().__init__(message, current=current_concurrency, max=max_concurrency, **kwargs)


class FallbackChainExhaustedError(ErrorResilienceBaseError):
    """Raised when all fallback strategies exhausted."""
    def __init__(self, message: str, attempted_fallbacks: List[str], **kwargs):
        self.attempted_fallbacks = attempted_fallbacks
        super().__init__(message, attempted=attempted_fallbacks, **kwargs)


class HealthCheckFailedError(ErrorResilienceBaseError):
    """Raised when health check fails."""
    pass


# ============================================================================
# ENUMS AND CONFIGURATION
# ============================================================================

class BackoffStrategy(Enum):
    """Backoff calculation strategies."""
    EXPONENTIAL = "exponential"
    LINEAR = "linear"
    FIXED = "fixed"
    FIBONACCI = "fibonacci"
    EXPONENTIAL_WITH_JITTER = "exponential_with_jitter"
    DECORRELATED_JITTER = "decorrelated_jitter"


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class FallbackPriority(Enum):
    """Fallback chain ordering strategies."""
    ORDERED = "ordered"
    REVERSE = "reverse"
    RANDOM = "random"
    WEIGHTED = "weighted"


@dataclass
class ResilienceConfig:
    """Configuration for resilience strategies."""
    # Timeout settings
    timeout_seconds: float = 30.0
    timeout_enable: bool = True
    
    # Retry settings
    max_retries: int = 3
    retry_enable: bool = True
    backoff_strategy: BackoffStrategy = BackoffStrategy.EXPONENTIAL
    initial_backoff: float = 0.1
    max_backoff: float = 30.0
    jitter_factor: float = 0.1
    retry_on_exceptions: Tuple[Type[Exception], ...] = (Exception,)
    
    # Circuit breaker settings
    circuit_enable: bool = True
    failure_threshold: int = 5
    success_threshold: int = 3
    reset_timeout: float = 60.0
    half_open_max_calls: int = 3
    
    # Bulkhead settings
    bulkhead_enable: bool = True
    max_concurrency: int = 10
    max_wait_time: float = 5.0
    
    # Fallback settings
    fallback_enable: bool = True


@dataclass
class OperationMetrics:
    """Metrics tracking for operations."""
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    timed_out_calls: int = 0
    retried_calls: int = 0
    circuit_breaker_triggers: int = 0
    fallback_activations: int = 0
    bulkhead_rejections: int = 0
    avg_latency_ms: float = 0.0
    latency_history: deque = field(default_factory=lambda: deque(maxlen=1000))
    
    def record_success(self, latency_ms: float):
        self.total_calls += 1
        self.successful_calls += 1
        self._update_latency(latency_ms)
    
    def record_failure(self, latency_ms: float):
        self.total_calls += 1
        self.failed_calls += 1
        self._update_latency(latency_ms)
    
    def record_timeout(self, latency_ms: float):
        self.total_calls += 1
        self.timed_out_calls += 1
        self._update_latency(latency_ms)
    
    def record_retry(self):
        self.retried_calls += 1
    
    def record_circuit_trigger(self):
        self.circuit_breaker_triggers += 1
    
    def record_fallback(self):
        self.fallback_activations += 1
    
    def record_bulkhead_rejection(self):
        self.bulkhead_rejections += 1
    
    def _update_latency(self, latency_ms: float):
        self.latency_history.append(latency_ms)
        self.avg_latency_ms = sum(self.latency_history) / len(self.latency_history)
    
    def get_health_score(self) -> float:
        """Calculate health score 0.0 to 1.0."""
        if self.total_calls == 0:
            return 1.0
        success_rate = self.successful_calls / self.total_calls
        return success_rate


# ============================================================================
# BACKOFF CALCULATOR
# ============================================================================

class BackoffCalculator:
    """Backoff delay calculator with multiple strategies."""
    
    _FIBONACCI_CACHE = [0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144]
    
    @staticmethod
    def calculate(
        strategy: BackoffStrategy,
        attempt: int,
        initial_backoff: float,
        max_backoff: float,
        jitter_factor: float = 0.1
    ) -> float:
        """Calculate backoff delay based on strategy."""
        if strategy == BackoffStrategy.EXPONENTIAL:
            delay = initial_backoff * (2 ** attempt)
        elif strategy == BackoffStrategy.LINEAR:
            delay = initial_backoff * (attempt + 1)
        elif strategy == BackoffStrategy.FIXED:
            delay = initial_backoff
        elif strategy == BackoffStrategy.FIBONACCI:
            fib_idx = min(attempt + 2, len(BackoffCalculator._FIBONACCI_CACHE) - 1)
            delay = initial_backoff * BackoffCalculator._FIBONACCI_CACHE[fib_idx]
        elif strategy == BackoffStrategy.EXPONENTIAL_WITH_JITTER:
            base_delay = initial_backoff * (2 ** attempt)
            jitter = random.uniform(0, jitter_factor * base_delay)
            delay = base_delay + jitter
        elif strategy == BackoffStrategy.DECORRELATED_JITTER:
            base_delay = initial_backoff * (2 ** attempt)
            delay = random.uniform(initial_backoff, base_delay * 3)
        else:
            delay = initial_backoff
        
        return min(delay, max_backoff)


# ============================================================================
# ADVANCED CIRCUIT BREAKER
# ============================================================================

class AdvancedCircuitBreaker:
    """Advanced circuit breaker with health tracking."""
    
    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        success_threshold: int = 3,
        reset_timeout: float = 60.0,
        half_open_max_calls: int = 3
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.success_threshold = success_threshold
        self.reset_timeout = reset_timeout
        self.half_open_max_calls = half_open_max_calls
        
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._open_timestamp = 0.0
        self._half_open_calls = 0
        self._lock = threading.RLock()
        self.metrics = OperationMetrics()
    
    @property
    def state(self) -> CircuitState:
        with self._lock:
            self._check_transition()
            return self._state
    
    def _check_transition(self):
        """Check and execute state transitions."""
        if self._state == CircuitState.OPEN:
            elapsed = time.time() - self._open_timestamp
            if elapsed >= self.reset_timeout:
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0
                self._success_count = 0
                logger.debug(f"Circuit '{self.name}' transitioning to HALF_OPEN")
    
    def allow_request(self) -> bool:
        """Check if request should be allowed through."""
        with self._lock:
            self._check_transition()
            
            if self._state == CircuitState.CLOSED:
                return True
            elif self._state == CircuitState.OPEN:
                return False
            elif self._state == CircuitState.HALF_OPEN:
                if self._half_open_calls < self.half_open_max_calls:
                    self._half_open_calls += 1
                    return True
                return False
            return False
    
    def record_success(self):
        """Record successful operation."""
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.success_threshold:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    self._success_count = 0
                    logger.info(f"Circuit '{self.name}' recovered to CLOSED")
            elif self._state == CircuitState.CLOSED:
                self._failure_count = max(0, self._failure_count - 1)
    
    def record_failure(self):
        """Record failed operation."""
        with self._lock:
            if self._state == CircuitState.CLOSED:
                self._failure_count += 1
                if self._failure_count >= self.failure_threshold:
                    self._state = CircuitState.OPEN
                    self._open_timestamp = time.time()
                    self.metrics.record_circuit_trigger()
                    logger.warning(f"Circuit '{self.name}' OPEN after {self._failure_count} failures")
            elif self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                self._open_timestamp = time.time()
                logger.debug(f"Circuit '{self.name}' health check failed")
    
    def get_status(self) -> Dict[str, Any]:
        """Get circuit breaker status."""
        with self._lock:
            self._check_transition()
            return {
                "name": self.name,
                "state": self._state.value,
                "failure_count": self._failure_count,
                "success_count": self._success_count,
                "open_elapsed_seconds": time.time() - self._open_timestamp if self._state == CircuitState.OPEN else 0,
                "metrics": {
                    "total_calls": self.metrics.total_calls,
                    "health_score": self.metrics.get_health_score(),
                    "circuit_triggers": self.metrics.circuit_breaker_triggers
                }
            }


# ============================================================================
# BULKHEAD ISOLATION
# ============================================================================

class BulkheadIsolator:
    """Bulkhead pattern for resource isolation."""
    
    def __init__(self, name: str, max_concurrency: int = 10, max_wait_time: float = 5.0):
        self.name = name
        self.max_concurrency = max_concurrency
        self.max_wait_time = max_wait_time
        self._current_concurrency = 0
        self._lock = threading.Condition()
        self.metrics = OperationMetrics()
    
    @contextmanager
    def acquire(self, timeout: Optional[float] = None):
        """Acquire bulkhead slot."""
        wait_timeout = timeout if timeout is not None else self.max_wait_time
        start_time = time.time()
        
        with self._lock:
            while self._current_concurrency >= self.max_concurrency:
                remaining = wait_timeout - (time.time() - start_time)
                if remaining <= 0:
                    self.metrics.record_bulkhead_rejection()
                    raise BulkheadCapacityExceededError(
                        f"Bulkhead '{self.name}' capacity exceeded",
                        current_concurrency=self._current_concurrency,
                        max_concurrency=self.max_concurrency
                    )
                self._lock.wait(remaining)
            
            self._current_concurrency += 1
        
        try:
            yield
        finally:
            with self._lock:
                self._current_concurrency -= 1
                self._lock.notify()
    
    def get_status(self) -> Dict[str, Any]:
        """Get bulkhead status."""
        with self._lock:
            return {
                "name": self.name,
                "current_concurrency": self._current_concurrency,
                "max_concurrency": self.max_concurrency,
                "utilization_pct": (self._current_concurrency / self.max_concurrency) * 100,
                "rejections": self.metrics.bulkhead_rejections
            }


# ============================================================================
# FALLBACK CHAIN ORCHESTRATION
# ============================================================================

class FallbackChain:
    """Orchestrates fallback chain execution."""
    
    def __init__(self, name: str, priority: FallbackPriority = FallbackPriority.ORDERED):
        self.name = name
        self.priority = priority
        self._fallbacks: List[Tuple[str, Callable, float]] = []
        self.metrics = OperationMetrics()
    
    def register(self, fallback_name: str, handler: Callable, weight: float = 1.0):
        """Register a fallback handler."""
        self._fallbacks.append((fallback_name, handler, weight))
    
    async def execute_async(
        self,
        original_exception: Exception,
        *args,
        **kwargs
    ) -> Any:
        """Execute fallback chain asynchronously."""
        ordered_fallbacks = self._order_fallbacks()
        attempted = []
        
        for name, handler, _ in ordered_fallbacks:
            attempted.append(name)
            try:
                self.metrics.record_fallback()
                if inspect.iscoroutinefunction(handler):
                    result = await handler(original_exception, *args, **kwargs)
                else:
                    result = handler(original_exception, *args, **kwargs)
                logger.debug(f"Fallback '{name}' succeeded")
                return result
            except Exception as e:
                logger.debug(f"Fallback '{name}' failed: {e}")
                continue
        
        raise FallbackChainExhaustedError(
            f"All fallbacks exhausted for '{self.name}'",
            attempted_fallbacks=attempted
        )
    
    def execute_sync(
        self,
        original_exception: Exception,
        *args,
        **kwargs
    ) -> Any:
        """Execute fallback chain synchronously."""
        ordered_fallbacks = self._order_fallbacks()
        attempted = []
        
        for name, handler, _ in ordered_fallbacks:
            attempted.append(name)
            try:
                self.metrics.record_fallback()
                result = handler(original_exception, *args, **kwargs)
                logger.debug(f"Fallback '{name}' succeeded")
                return result
            except Exception as e:
                logger.debug(f"Fallback '{name}' failed: {e}")
                continue
        
        raise FallbackChainExhaustedError(
            f"All fallbacks exhausted for '{self.name}'",
            attempted_fallbacks=attempted
        )
    
    def _order_fallbacks(self) -> List[Tuple[str, Callable, float]]:
        """Order fallbacks according to priority strategy."""
        if self.priority == FallbackPriority.REVERSE:
            return list(reversed(self._fallbacks))
        elif self.priority == FallbackPriority.RANDOM:
            shuffled = list(self._fallbacks)
            random.shuffle(shuffled)
            return shuffled
        elif self.priority == FallbackPriority.WEIGHTED:
            return sorted(self._fallbacks, key=lambda x: x[2], reverse=True)
        return list(self._fallbacks)


# ============================================================================
# COMBINED RESILIENCE DECORATOR
# ============================================================================

class CombinedResilience:
    """Combined resilience decorator integrating all strategies."""
    
    _circuit_breakers: Dict[str, AdvancedCircuitBreaker] = {}
    _bulkheads: Dict[str, BulkheadIsolator] = {}
    _global_lock = threading.Lock()
    
    def __init__(
        self,
        name: Optional[str] = None,
        config: Optional[ResilienceConfig] = None,
        fallback_chain: Optional[FallbackChain] = None
    ):
        self.config = config or ResilienceConfig()
        self.name = name
        self.fallback_chain = fallback_chain
        self._decorated_func: Optional[Callable] = None
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator entry point."""
        self._decorated_func = func
        name = self.name or func.__name__
        
        # Initialize circuit breaker
        with CombinedResilience._global_lock:
            if name not in CombinedResilience._circuit_breakers and self.config.circuit_enable:
                CombinedResilience._circuit_breakers[name] = AdvancedCircuitBreaker(
                    name=name,
                    failure_threshold=self.config.failure_threshold,
                    success_threshold=self.config.success_threshold,
                    reset_timeout=self.config.reset_timeout,
                    half_open_max_calls=self.config.half_open_max_calls
                )
            
            if name not in CombinedResilience._bulkheads and self.config.bulkhead_enable:
                CombinedResilience._bulkheads[name] = BulkheadIsolator(
                    name=name,
                    max_concurrency=self.config.max_concurrency,
                    max_wait_time=self.config.max_wait_time
                )
        
        self.circuit_breaker = CombinedResilience._circuit_breakers.get(name)
        self.bulkhead = CombinedResilience._bulkheads.get(name)
        
        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                return await self._execute_async(func, name, *args, **kwargs)
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                return self._execute_sync(func, name, *args, **kwargs)
            return sync_wrapper
    
    async def _execute_async(
        self,
        func: Callable,
        name: str,
        *args,
        **kwargs
    ) -> Any:
        """Execute operation with resilience (async)."""
        operation_id = str(uuid.uuid4())
        start_time = time.time()
        
        # 1. Circuit breaker check
        if self.circuit_breaker and not self.circuit_breaker.allow_request():
            raise CircuitBreakerOpenError(
                f"Circuit '{name}' is OPEN",
                reset_timeout=self.config.reset_timeout,
                operation_id=operation_id
            )
        
        attempt = 0
        last_exception = None
        
        while attempt <= self.config.max_retries:
            try:
                # 2. Bulkhead acquisition
                if self.bulkhead:
                    with self.bulkhead.acquire():
                        # 3. Timeout + execution
                        if self.config.timeout_enable:
                            result = await asyncio.wait_for(
                                func(*args, **kwargs),
                                timeout=self.config.timeout_seconds
                            )
                        else:
                            result = await func(*args, **kwargs)
                else:
                    if self.config.timeout_enable:
                        result = await asyncio.wait_for(
                            func(*args, **kwargs),
                            timeout=self.config.timeout_seconds
                        )
                    else:
                        result = await func(*args, **kwargs)
                
                # Success
                latency_ms = (time.time() - start_time) * 1000
                if self.circuit_breaker:
                    self.circuit_breaker.record_success()
                    self.circuit_breaker.metrics.record_success(latency_ms)
                return result
                
            except asyncio.TimeoutError as e:
                last_exception = TimeoutExceededError(
                    f"Operation timed out after {self.config.timeout_seconds}s",
                    operation_id=operation_id
                )
                latency_ms = (time.time() - start_time) * 1000
                if self.circuit_breaker:
                    self.circuit_breaker.record_failure()
                    self.circuit_breaker.metrics.record_timeout(latency_ms)
                
            except Exception as e:
                if not isinstance(e, self.config.retry_on_exceptions):
                    raise
                last_exception = e
                latency_ms = (time.time() - start_time) * 1000
                if self.circuit_breaker:
                    self.circuit_breaker.record_failure()
                    self.circuit_breaker.metrics.record_failure(latency_ms)
            
            # Retry logic
            attempt += 1
            if attempt <= self.config.max_retries and self.config.retry_enable:
                if self.circuit_breaker:
                    self.circuit_breaker.metrics.record_retry()
                backoff = BackoffCalculator.calculate(
                    self.config.backoff_strategy,
                    attempt,
                    self.config.initial_backoff,
                    self.config.max_backoff,
                    self.config.jitter_factor
                )
                await asyncio.sleep(backoff)
        
        # All retries exhausted - try fallbacks
        if self.fallback_chain and self.config.fallback_enable:
            try:
                return await self.fallback_chain.execute_async(last_exception, *args, **kwargs)
            except FallbackChainExhaustedError:
                pass
        
        raise MaxRetriesExceededError(
            f"Max retries ({self.config.max_retries}) exceeded",
            attempts=attempt,
            last_exception=last_exception,
            operation_id=operation_id
        )
    
    def _execute_sync(
        self,
        func: Callable,
        name: str,
        *args,
        **kwargs
    ) -> Any:
        """Execute operation with resilience (sync)."""
        operation_id = str(uuid.uuid4())
        start_time = time.time()
        
        # 1. Circuit breaker check
        if self.circuit_breaker and not self.circuit_breaker.allow_request():
            raise CircuitBreakerOpenError(
                f"Circuit '{name}' is OPEN",
                reset_timeout=self.config.reset_timeout,
                operation_id=operation_id
            )
        
        attempt = 0
        last_exception = None
        
        while attempt <= self.config.max_retries:
            try:
                # 2. Bulkhead acquisition
                if self.bulkhead:
                    with self.bulkhead.acquire():
                        result = func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)
                
                # Success
                latency_ms = (time.time() - start_time) * 1000
                if self.circuit_breaker:
                    self.circuit_breaker.record_success()
                    self.circuit_breaker.metrics.record_success(latency_ms)
                return result
                
            except Exception as e:
                if not isinstance(e, self.config.retry_on_exceptions):
                    raise
                last_exception = e
                latency_ms = (time.time() - start_time) * 1000
                if self.circuit_breaker:
                    self.circuit_breaker.record_failure()
                    self.circuit_breaker.metrics.record_failure(latency_ms)
            
            # Retry logic
            attempt += 1
            if attempt <= self.config.max_retries and self.config.retry_enable:
                if self.circuit_breaker:
                    self.circuit_breaker.metrics.record_retry()
                backoff = BackoffCalculator.calculate(
                    self.config.backoff_strategy,
                    attempt,
                    self.config.initial_backoff,
                    self.config.max_backoff,
                    self.config.jitter_factor
                )
                time.sleep(backoff)
        
        # All retries exhausted - try fallbacks
        if self.fallback_chain and self.config.fallback_enable:
            try:
                return self.fallback_chain.execute_sync(last_exception, *args, **kwargs)
            except FallbackChainExhaustedError:
                pass
        
        raise MaxRetriesExceededError(
            f"Max retries ({self.config.max_retries}) exceeded",
            attempts=attempt,
            last_exception=last_exception,
            operation_id=operation_id
        )
    
    @classmethod
    def get_status(cls, name: str) -> Dict[str, Any]:
        """Get combined status for a resilience component."""
        status = {"name": name}
        if name in cls._circuit_breakers:
            status["circuit_breaker"] = cls._circuit_breakers[name].get_status()
        if name in cls._bulkheads:
            status["bulkhead"] = cls._bulkheads[name].get_status()
        return status


# ============================================================================
# CONVENIENCE DECORATORS
# ============================================================================

def with_timeout(seconds: float = 30.0):
    """Timeout-only decorator."""
    config = ResilienceConfig(
        timeout_seconds=seconds,
        timeout_enable=True,
        max_retries=0,
        circuit_enable=False,
        bulkhead_enable=False
    )
    return CombinedResilience(config=config)


def with_retry(
    max_retries: int = 3,
    strategy: BackoffStrategy = BackoffStrategy.EXPONENTIAL,
    initial_backoff: float = 0.1
):
    """Retry-only decorator."""
    config = ResilienceConfig(
        max_retries=max_retries,
        retry_enable=True,
        backoff_strategy=strategy,
        initial_backoff=initial_backoff,
        timeout_enable=False,
        circuit_enable=False,
        bulkhead_enable=False
    )
    return CombinedResilience(config=config)


def with_circuit_breaker(
    failure_threshold: int = 5,
    reset_timeout: float = 60.0
):
    """Circuit breaker-only decorator."""
    config = ResilienceConfig(
        max_retries=0,
        circuit_enable=True,
        failure_threshold=failure_threshold,
        reset_timeout=reset_timeout,
        timeout_enable=False,
        bulkhead_enable=False
    )
    return CombinedResilience(config=config)


def with_bulkhead(max_concurrency: int = 10, max_wait_time: float = 5.0):
    """Bulkhead-only decorator."""
    config = ResilienceConfig(
        max_retries=0,
        bulkhead_enable=True,
        max_concurrency=max_concurrency,
        max_wait_time=max_wait_time,
        timeout_enable=False,
        circuit_enable=False
    )
    return CombinedResilience(config=config)


# ============================================================================
# RESILIENCE ORCHESTRATOR (SINGLETON)
# ============================================================================

class ResilienceOrchestrator:
    """Global singleton orchestrator for error resilience."""
    _instance: Optional['ResilienceOrchestrator'] = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._configs: Dict[str, ResilienceConfig] = {}
        self._fallback_chains: Dict[str, FallbackChain] = {}
        logger.info("ResilienceOrchestrator initialized")
    
    def register_config(self, name: str, config: ResilienceConfig):
        """Register a resilience configuration."""
        self._configs[name] = config
    
    def register_fallback_chain(self, name: str, chain: FallbackChain):
        """Register a fallback chain."""
        self._fallback_chains[name] = chain
    
    def create_decorator(self, name: str) -> CombinedResilience:
        """Create a combined resilience decorator."""
        config = self._configs.get(name, ResilienceConfig())
        fallback_chain = self._fallback_chains.get(name)
        return CombinedResilience(name=name, config=config, fallback_chain=fallback_chain)
    
    def get_all_status(self) -> Dict[str, Any]:
        """Get status of all resilience components."""
        return {
            "circuit_breakers": {
                name: cb.get_status()
                for name, cb in CombinedResilience._circuit_breakers.items()
            },
            "bulkheads": {
                name: bh.get_status()
                for name, bh in CombinedResilience._bulkheads.items()
            }
        }


# Export singleton instance
resilience_orchestrator = ResilienceOrchestrator()
