"""
NeuralShield-AI: Threat Intelligence Rate Limiter & Circuit Breaker
June 21, 2026 - Production Grade Implementation

Implements:
1. Token Bucket Rate Limiting
2. Circuit Breaker Pattern (Closed/Open/Half-Open states)
3. Adaptive Backoff with Jitter
4. Request Batching with Priority Queue
5. Real-time Metrics Collection
6. Fallback Mechanisms
"""

import time
import threading
import heapq
import random
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Any, Optional, Dict, List
from collections import deque
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CircuitState(Enum):
    CLOSED = "closed"           # Normal operation - all requests pass through
    OPEN = "open"               # Circuit tripped - requests fail fast
    HALF_OPEN = "half_open"     # Testing recovery - limited test requests


class Priority(Enum):
    CRITICAL = 0    # IOCs, active threats
    HIGH = 1        # Vulnerability updates
    MEDIUM = 2      # Regular feed updates
    LOW = 3         # Background enrichment


@dataclass(order=True)
class PrioritizedRequest:
    priority: int
    timestamp: float
    request_id: str = field(compare=False)
    payload: Any = field(compare=False)
    callback: Optional[Callable] = field(compare=False, default=None)


@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5
    recovery_timeout: int = 30
    half_open_max_requests: int = 3
    window_size_seconds: int = 60
    min_failure_rate: float = 0.5


@dataclass
class RateLimiterConfig:
    max_requests_per_second: int = 10
    max_burst: int = 20
    max_queue_size: int = 1000
    batch_size: int = 5
    batch_max_wait_ms: int = 100


class TokenBucket:
    """Thread-safe token bucket implementation for rate limiting"""
    
    def __init__(self, rate: float, capacity: float):
        self.rate = rate  # tokens per second
        self.capacity = capacity
        self.tokens = capacity
        self.last_refill = time.time()
        self.lock = threading.Lock()
    
    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens, return True if successful"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_refill = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False
    
    def wait_for_token(self, timeout: float = 5.0) -> bool:
        """Wait until token available or timeout"""
        start = time.time()
        while time.time() - start < timeout:
            if self.consume():
                return True
            time.sleep(0.01)
        return False


class CircuitBreaker:
    """Production-grade circuit breaker with state management"""
    
    def __init__(self, config: CircuitBreakerConfig = None):
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.open_timestamp = 0.0
        self.half_open_attempts = 0
        self.failure_window: deque = deque(maxlen=100)
        self.lock = threading.Lock()
        self.state_change_callbacks: List[Callable] = []
    
    def on_state_change(self, callback: Callable):
        """Register callback for state transitions"""
        self.state_change_callbacks.append(callback)
    
    def _transition(self, new_state: CircuitState):
        """Transition to new state"""
        old_state = self.state
        self.state = new_state
        logger.info(f"CircuitBreaker state transition: {old_state.value} -> {new_state.value}")
        for callback in self.state_change_callbacks:
            callback(old_state, new_state)
    
    def record_success(self):
        """Record successful request"""
        with self.lock:
            self.success_count += 1
            self.failure_window.append(False)
            
            if self.state == CircuitState.HALF_OPEN:
                self.half_open_attempts += 1
                if self.half_open_attempts >= self.config.half_open_max_requests:
                    # Recovery successful - close circuit
                    self.failure_count = 0
                    self.half_open_attempts = 0
                    self._transition(CircuitState.CLOSED)
    
    def record_failure(self):
        """Record failed request"""
        with self.lock:
            self.failure_count += 1
            self.failure_window.append(True)
            
            if self.state == CircuitState.CLOSED:
                # Check if we should trip the circuit
                total = len(self.failure_window)
                failures = sum(1 for f in self.failure_window if f)
                
                if (total >= self.config.failure_threshold and 
                    failures / total >= self.config.min_failure_rate):
                    self.open_timestamp = time.time()
                    self._transition(CircuitState.OPEN)
            
            elif self.state == CircuitState.HALF_OPEN:
                # Recovery failed - reopen circuit
                self.half_open_attempts = 0
                self.open_timestamp = time.time()
                self._transition(CircuitState.OPEN)
    
    def allow_request(self) -> bool:
        """Check if request should be allowed"""
        with self.lock:
            if self.state == CircuitState.CLOSED:
                return True
            
            elif self.state == CircuitState.OPEN:
                # Check if recovery timeout elapsed
                if time.time() - self.open_timestamp >= self.config.recovery_timeout:
                    self.half_open_attempts = 0
                    self._transition(CircuitState.HALF_OPEN)
                    return True
                return False
            
            elif self.state == CircuitState.HALF_OPEN:
                # Allow limited test requests
                return self.half_open_attempts < self.config.half_open_max_requests
            
            return False
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get circuit breaker metrics"""
        with self.lock:
            total = len(self.failure_window)
            failures = sum(1 for f in self.failure_window if f)
            return {
                "state": self.state.value,
                "failure_count": self.failure_count,
                "success_count": self.success_count,
                "failure_rate": failures / total if total > 0 else 0.0,
                "open_remaining": max(0, self.config.recovery_timeout - 
                                     (time.time() - self.open_timestamp)) 
                                if self.state == CircuitState.OPEN else 0,
                "half_open_attempts": self.half_open_attempts
            }


class BatchingPriorityQueue:
    """Priority queue with automatic batching"""
    
    def __init__(self, max_size: int = 1000):
        self.queue: List[PrioritizedRequest] = []
        self.max_size = max_size
        self.lock = threading.Lock()
        self.not_empty = threading.Condition(self.lock)
    
    def put(self, request: PrioritizedRequest) -> bool:
        """Add request to queue, return False if full"""
        with self.lock:
            if len(self.queue) >= self.max_size:
                return False
            heapq.heappush(self.queue, request)
            self.not_empty.notify()
            return True
    
    def get_batch(self, batch_size: int, timeout_ms: int = 100) -> List[PrioritizedRequest]:
        """Get batch of requests, waiting up to timeout"""
        deadline = time.time() + timeout_ms / 1000
        batch = []
        
        with self.lock:
            while len(batch) < batch_size and time.time() < deadline:
                if self.queue:
                    batch.append(heapq.heappop(self.queue))
                else:
                    remaining = deadline - time.time()
                    if remaining > 0:
                        self.not_empty.wait(remaining)
        return batch
    
    def size(self) -> int:
        with self.lock:
            return len(self.queue)


class RateLimitedCircuitBreakerClient:
    """
    Combined Rate Limiter + Circuit Breaker client for Threat Intelligence APIs
    Production-grade with adaptive backoff and fallback support
    """
    
    def __init__(self, 
                 rate_config: RateLimiterConfig = None,
                 circuit_config: CircuitBreakerConfig = None):
        self.rate_config = rate_config or RateLimiterConfig()
        self.circuit_config = circuit_config or CircuitBreakerConfig()
        
        # Core components
        self.token_bucket = TokenBucket(
            rate=self.rate_config.max_requests_per_second,
            capacity=self.rate_config.max_burst
        )
        self.circuit_breaker = CircuitBreaker(self.circuit_config)
        self.request_queue = BatchingPriorityQueue(self.rate_config.max_queue_size)
        
        # Metrics
        self.total_requests = 0
        self.rejected_requests = 0
        self.fallback_responses = 0
        self.metrics_lock = threading.Lock()
        
        # Background worker
        self._worker_thread: Optional[threading.Thread] = None
        self._running = False
        
        # Fallback handlers
        self.fallbacks: Dict[str, Callable] = {}
    
    def register_fallback(self, operation: str, handler: Callable):
        """Register fallback handler for circuit-open scenario"""
        self.fallbacks[operation] = handler
    
    def execute(self, 
                operation: str,
                func: Callable,
                *args,
                priority: Priority = Priority.MEDIUM,
                timeout: float = 10.0,
                **kwargs) -> Any:
        """
        Execute operation with rate limiting and circuit breaker protection
        
        Args:
            operation: Operation name for fallback routing
            func: Function to execute
            priority: Request priority
            timeout: Max wait time
            *args, **kwargs: Arguments for func
        """
        request_id = f"{operation}_{int(time.time() * 1000)}_{random.randint(0, 9999)}"
        
        with self.metrics_lock:
            self.total_requests += 1
        
        # Fast fail if circuit is open
        if not self.circuit_breaker.allow_request():
            with self.metrics_lock:
                self.rejected_requests += 1
            
            # Try fallback
            if operation in self.fallbacks:
                with self.metrics_lock:
                    self.fallback_responses += 1
                logger.warning(f"Circuit open, using fallback for: {operation}")
                return self.fallbacks[operation](*args, **kwargs)
            
            raise CircuitBreakerOpenError(
                f"Circuit breaker is OPEN for {operation}. "
                f"Retry in {self.circuit_breaker.get_metrics()['open_remaining']:.1f}s"
            )
        
        # Wait for rate limit token
        if not self.token_bucket.wait_for_token(min(timeout, 5.0)):
            with self.metrics_lock:
                self.rejected_requests += 1
            raise RateLimitExceededError(f"Rate limit exceeded for {operation}")
        
        # Execute with retry logic
        max_retries = 3
        base_delay = 0.1
        
        for attempt in range(max_retries):
            try:
                result = func(*args, **kwargs)
                self.circuit_breaker.record_success()
                return result
                
            except Exception as e:
                if attempt < max_retries - 1:
                    # Exponential backoff with jitter
                    delay = base_delay * (2 ** attempt) * (0.5 + random.random())
                    logger.warning(f"Attempt {attempt + 1} failed for {operation}, "
                                  f"retrying in {delay:.2f}s: {e}")
                    time.sleep(delay)
                else:
                    self.circuit_breaker.record_failure()
                    logger.error(f"All retries failed for {operation}: {e}")
                    raise
    
    def enqueue(self,
                operation: str,
                payload: Any,
                priority: Priority = Priority.MEDIUM,
                callback: Optional[Callable] = None) -> bool:
        """Enqueue request for async batch processing"""
        request = PrioritizedRequest(
            priority=priority.value,
            timestamp=time.time(),
            request_id=f"{operation}_{int(time.time() * 1000)}",
            payload=payload,
            callback=callback
        )
        return self.request_queue.put(request)
    
    def start_worker(self, processor_func: Callable):
        """Start background worker for batch processing"""
        if self._running:
            return
        
        self._running = True
        
        def worker():
            while self._running:
                batch = self.request_queue.get_batch(
                    self.rate_config.batch_size,
                    self.rate_config.batch_max_wait_ms
                )
                if batch:
                    try:
                        results = processor_func([r.payload for r in batch])
                        self.circuit_breaker.record_success()
                        
                        for req, result in zip(batch, results):
                            if req.callback:
                                req.callback(result, None)
                                
                    except Exception as e:
                        self.circuit_breaker.record_failure()
                        for req in batch:
                            if req.callback:
                                req.callback(None, e)
        
        self._worker_thread = threading.Thread(target=worker, daemon=True)
        self._worker_thread.start()
    
    def stop_worker(self):
        """Stop background worker"""
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=5.0)
    
    def get_health_metrics(self) -> Dict[str, Any]:
        """Get comprehensive health metrics"""
        with self.metrics_lock:
            circuit_metrics = self.circuit_breaker.get_metrics()
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "circuit_breaker": circuit_metrics,
                "rate_limiter": {
                    "tokens_remaining": self.token_bucket.tokens,
                    "max_burst": self.token_bucket.capacity,
                    "rate_per_second": self.token_bucket.rate
                },
                "queue": {
                    "size": self.request_queue.size(),
                    "max_size": self.rate_config.max_queue_size
                },
                "requests": {
                    "total": self.total_requests,
                    "rejected": self.rejected_requests,
                    "fallback_used": self.fallback_responses,
                    "acceptance_rate": (
                        (self.total_requests - self.rejected_requests) / self.total_requests
                        if self.total_requests > 0 else 1.0
                    )
                }
            }


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open"""
    pass


class RateLimitExceededError(Exception):
    """Raised when rate limit is exceeded"""
    pass


# Export public API
__all__ = [
    'RateLimitedCircuitBreakerClient',
    'CircuitBreaker',
    'TokenBucket',
    'CircuitState',
    'Priority',
    'CircuitBreakerConfig',
    'RateLimiterConfig',
    'CircuitBreakerOpenError',
    'RateLimitExceededError',
]
