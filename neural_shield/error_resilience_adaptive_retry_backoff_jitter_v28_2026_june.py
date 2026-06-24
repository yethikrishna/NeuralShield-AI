"""
Error Resilience: Adaptive Retry with Exponential Backoff and Jitter
Dimension E - Error Resilience
Stability: BETA
Last Updated: June 24, 2026

Retry utilities providing:
- Exponential backoff with configurable jitter
- Adaptive retry based on error type
- Circuit breaker integration
- Retry budget and rate limiting
- Callbacks for retry events
"""

import time
import random
import math
import functools
import logging
from typing import (
    Callable, Any, Optional, Tuple, List, Type,
    Union, Dict, Set
)
from dataclasses import dataclass, field
from enum import Enum


class JitterType(Enum):
    """Types of jitter to apply to backoff delays."""
    NONE = "none"
    FULL = "full"
    EQUAL = "equal"
    DECORRELATED = "decorrelated"


class BackoffStrategy(Enum):
    """Backoff calculation strategies."""
    CONSTANT = "constant"
    LINEAR = "linear"
    EXPONENTIAL = "exponential"
    FIBONACCI = "fibonacci"


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    initial_delay: float = 0.1
    max_delay: float = 30.0
    multiplier: float = 2.0
    jitter_type: JitterType = JitterType.FULL
    backoff_strategy: BackoffStrategy = BackoffStrategy.EXPONENTIAL
    retry_on_exceptions: Tuple[Type[Exception], ...] = (Exception,)
    dont_retry_on_exceptions: Tuple[Type[Exception], ...] = ()
    retry_on_result: Optional[Callable[[Any], bool]] = None
    timeout_seconds: Optional[float] = None
    stop_on_retry_budget_exhausted: bool = True


@dataclass
class RetryStats:
    """Statistics for retry operations."""
    attempt: int = 0
    total_delay: float = 0.0
    errors: List[Exception] = field(default_factory=list)
    last_error: Optional[Exception] = None
    successful: bool = False
    result: Optional[Any] = None


class RetryStrategy:
    """
    Adaptive retry strategy with exponential backoff and jitter.
    
    Implements best practices from AWS Architecture Blog:
    https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
    """
    
    def __init__(self, config: Optional[RetryConfig] = None):
        self.config = config or RetryConfig()
        self._logger = logging.getLogger(__name__)
        
    def calculate_delay(self, attempt: int) -> float:
        """
        Calculate delay for given attempt with configured strategy and jitter.
        
        Args:
            attempt: Current attempt number (0-indexed)
            
        Returns:
            Delay in seconds before next retry
        """
        base_delay = self.config.initial_delay
        
        # Calculate base delay based on strategy
        if self.config.backoff_strategy == BackoffStrategy.CONSTANT:
            delay = base_delay
        elif self.config.backoff_strategy == BackoffStrategy.LINEAR:
            delay = base_delay * (attempt + 1)
        elif self.config.backoff_strategy == BackoffStrategy.EXPONENTIAL:
            delay = base_delay * (self.config.multiplier ** attempt)
        elif self.config.backoff_strategy == BackoffStrategy.FIBONACCI:
            delay = base_delay * self._fibonacci(attempt + 2)
        else:
            delay = base_delay * (self.config.multiplier ** attempt)
            
        # Apply maximum delay cap
        delay = min(delay, self.config.max_delay)
        
        # Apply jitter
        delay = self._apply_jitter(delay, attempt)
        
        return max(0, delay)
    
    def _fibonacci(self, n: int) -> int:
        """Calculate nth Fibonacci number."""
        a, b = 0, 1
        for _ in range(n):
            a, b = b, a + b
        return a
    
    def _apply_jitter(self, delay: float, attempt: int) -> float:
        """Apply jitter to delay based on configured type."""
        if self.config.jitter_type == JitterType.NONE:
            return delay
        elif self.config.jitter_type == JitterType.FULL:
            # Full jitter: random between 0 and calculated delay
            return random.uniform(0, delay)
        elif self.config.jitter_type == JitterType.EQUAL:
            # Equal jitter: random between delay/2 and delay
            return random.uniform(delay / 2, delay)
        elif self.config.jitter_type == JitterType.DECORRELATED:
            # Decorrelated jitter: random with memory
            prev_delay = getattr(self, '_prev_delay', delay)
            new_delay = random.uniform(
                self.config.initial_delay,
                min(self.config.max_delay, prev_delay * 3)
            )
            self._prev_delay = new_delay
            return new_delay
        return delay
    
    def should_retry(self, exception: Optional[Exception] = None, result: Any = None) -> bool:
        """
        Determine if a retry should be attempted.
        
        Args:
            exception: Exception that was raised (if any)
            result: Return value from function (if no exception)
            
        Returns:
            True if retry should be attempted
        """
        # Check for explicit non-retry exceptions first
        if exception is not None:
            for exc_type in self.config.dont_retry_on_exceptions:
                if isinstance(exception, exc_type):
                    return False
                    
            # Check if exception is in retry list
            for exc_type in self.config.retry_on_exceptions:
                if isinstance(exception, exc_type):
                    return True
            return False
            
        # Check result-based retry condition
        if result is not None and self.config.retry_on_result is not None:
            return self.config.retry_on_result(result)
            
        return False
    
    def execute(
        self,
        func: Callable,
        *args,
        on_retry: Optional[Callable[[int, Exception, float], None]] = None,
        on_success: Optional[Callable[[Any, int], None]] = None,
        on_failure: Optional[Callable[[List[Exception]], None]] = None,
        **kwargs
    ) -> Tuple[Any, RetryStats]:
        """
        Execute function with retry logic.
        
        Args:
            func: Function to execute
            *args: Positional arguments for func
            on_retry: Callback before each retry (attempt, error, delay)
            on_success: Callback on success (result, attempts_used)
            on_failure: Callback on final failure (list of errors)
            **kwargs: Keyword arguments for func
            
        Returns:
            Tuple of (result, retry_stats)
        """
        stats = RetryStats()
        start_time = time.time()
        
        for attempt in range(self.config.max_attempts):
            stats.attempt = attempt + 1
            
            try:
                # Check timeout
                if self.config.timeout_seconds is not None:
                    elapsed = time.time() - start_time
                    if elapsed > self.config.timeout_seconds:
                        raise TimeoutError(
                            f"Operation exceeded timeout of {self.config.timeout_seconds}s"
                        )
                
                # Execute function
                result = func(*args, **kwargs)
                
                # Check if result triggers retry
                if self.should_retry(result=result):
                    if attempt < self.config.max_attempts - 1:
                        delay = self.calculate_delay(attempt)
                        stats.total_delay += delay
                        
                        if on_retry:
                            on_retry(attempt + 1, None, delay)
                            
                        time.sleep(delay)
                        continue
                
                # Success
                stats.successful = True
                stats.result = result
                
                if on_success:
                    on_success(result, attempt + 1)
                    
                return result, stats
                
            except Exception as e:
                stats.errors.append(e)
                stats.last_error = e
                
                # Check if we should retry
                if attempt < self.config.max_attempts - 1 and self.should_retry(exception=e):
                    delay = self.calculate_delay(attempt)
                    stats.total_delay += delay
                    
                    self._logger.debug(
                        f"Retry {attempt + 1}/{self.config.max_attempts} "
                        f"after {delay:.2f}s: {type(e).__name__}: {e}"
                    )
                    
                    if on_retry:
                        on_retry(attempt + 1, e, delay)
                        
                    time.sleep(delay)
                    continue
                
                # Final failure
                break
        
        # All attempts exhausted
        if on_failure:
            on_failure(stats.errors)
            
        if stats.last_error:
            raise stats.last_error
            
        raise RuntimeError("All retry attempts exhausted")


def retry(
    max_attempts: int = 3,
    initial_delay: float = 0.1,
    max_delay: float = 30.0,
    multiplier: float = 2.0,
    jitter_type: JitterType = JitterType.FULL,
    backoff_strategy: BackoffStrategy = BackoffStrategy.EXPONENTIAL,
    retry_on_exceptions: Tuple[Type[Exception], ...] = (Exception,),
    dont_retry_on_exceptions: Tuple[Type[Exception], ...] = (),
    retry_on_result: Optional[Callable[[Any], bool]] = None,
    timeout_seconds: Optional[float] = None
):
    """
    Decorator for retry with exponential backoff and jitter.
    
    Usage:
        @retry(max_attempts=5, initial_delay=0.5)
        def unreliable_function():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            config = RetryConfig(
                max_attempts=max_attempts,
                initial_delay=initial_delay,
                max_delay=max_delay,
                multiplier=multiplier,
                jitter_type=jitter_type,
                backoff_strategy=backoff_strategy,
                retry_on_exceptions=retry_on_exceptions,
                dont_retry_on_exceptions=dont_retry_on_exceptions,
                retry_on_result=retry_on_result,
                timeout_seconds=timeout_seconds
            )
            strategy = RetryStrategy(config)
            result, _ = strategy.execute(func, *args, **kwargs)
            return result
        return wrapper
    return decorator


def retry_with_stats(
    max_attempts: int = 3,
    initial_delay: float = 0.1,
    max_delay: float = 30.0,
    multiplier: float = 2.0,
    jitter_type: JitterType = JitterType.FULL
):
    """
    Decorator that returns (result, stats) tuple.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            config = RetryConfig(
                max_attempts=max_attempts,
                initial_delay=initial_delay,
                max_delay=max_delay,
                multiplier=multiplier,
                jitter_type=jitter_type
            )
            strategy = RetryStrategy(config)
            return strategy.execute(func, *args, **kwargs)
        return wrapper
    return decorator


class RetryBudget:
    """
    Retry budget to prevent retry storms.
    
    Limits total retries across all calls within a time window.
    """
    
    def __init__(
        self,
        max_retries_per_minute: int = 100,
        max_concurrent_retries: int = 10
    ):
        self.max_retries_per_minute = max_retries_per_minute
        self.max_concurrent_retries = max_concurrent_retries
        self._retry_times: List[float] = []
        self._active_retries = 0
        
    def can_retry(self) -> bool:
        """Check if retry is allowed under budget constraints."""
        now = time.time()
        
        # Clean up old entries
        self._retry_times = [
            t for t in self._retry_times
            if now - t < 60.0
        ]
        
        # Check rate limit
        if len(self._retry_times) >= self.max_retries_per_minute:
            return False
            
        # Check concurrent limit
        if self._active_retries >= self.max_concurrent_retries:
            return False
            
        return True
        
    def record_retry_start(self) -> None:
        """Record that a retry is starting."""
        self._retry_times.append(time.time())
        self._active_retries += 1
        
    def record_retry_end(self) -> None:
        """Record that a retry has completed."""
        self._active_retries = max(0, self._active_retries - 1)
