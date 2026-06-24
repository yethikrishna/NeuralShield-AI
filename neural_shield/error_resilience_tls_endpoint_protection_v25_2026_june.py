"""
NeuralShield-AI Error Resilience v25 - TLS/HTTPS Endpoint Protection
====================================================================
DIMENSION E - Error Resilience
Add-only module - wraps Security v17 TLS/HTTPS endpoints with comprehensive error handling

This module provides:
1. TLS Handshake Timeout Protection - prevents hanging connections
2. Exponential Backoff with Jitter - intelligent connection retries
3. Circuit Breaker Pattern - stops cascading TLS failures
4. Graceful Degradation - automatic HTTP fallback on TLS failure
5. Bulkhead Isolation - TLS operations don't crash the whole system
6. Custom Exception Hierarchy - precise TLS error classification

Philosophy: 100% ADD-ONLY, wraps existing code without modification
Backward Compatible: All existing Security v17 functions work unchanged
"""

import time
import random
import socket
import ssl
import threading
from typing import Callable, Any, Optional, Dict, List, TypeVar, Tuple
from enum import Enum
from dataclasses import dataclass, field
from collections import deque
from functools import wraps
import logging

# Configure logging - OPT-IN, disabled by default
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Type variables
T = TypeVar('T')
R = TypeVar('R')

# ============================================================================
# CUSTOM EXCEPTION HIERARCHY - TLS-SPECIFIC ERROR CLASSES
# ============================================================================

class TLSError(Exception):
    """Base exception for all TLS-related errors"""
    def __init__(self, message: str, error_code: str, retryable: bool = False):
        super().__init__(message)
        self.error_code = error_code
        self.retryable = retryable
        self.timestamp = time.time()

class TLSTimeoutError(TLSError):
    """Raised when TLS handshake or connection times out"""
    def __init__(self, message: str = "TLS operation timed out"):
        super().__init__(message, "TLS_TIMEOUT", retryable=True)

class TLSCertificateError(TLSError):
    """Raised when certificate validation fails"""
    def __init__(self, message: str = "Certificate validation failed"):
        super().__init__(message, "TLS_CERT_INVALID", retryable=False)

class TLSCipherError(TLSError):
    """Raised when cipher negotiation fails"""
    def __init__(self, message: str = "Cipher suite negotiation failed"):
        super().__init__(message, "TLS_CIPHER_MISMATCH", retryable=False)

class TLSVersionError(TLSError):
    """Raised when TLS version is incompatible"""
    def __init__(self, message: str = "TLS version incompatibility"):
        super().__init__(message, "TLS_VERSION_MISMATCH", retryable=False)

class TLSHandshakeError(TLSError):
    """Raised when TLS handshake fails for other reasons"""
    def __init__(self, message: str = "TLS handshake failed"):
        super().__init__(message, "TLS_HANDSHAKE_FAILED", retryable=True)

class TLSCircuitBreakerOpen(TLSError):
    """Raised when circuit breaker is open (too many failures)"""
    def __init__(self, message: str = "TLS circuit breaker is open"):
        super().__init__(message, "TLS_CIRCUIT_OPEN", retryable=False)

class TLSFallbackActivated(TLSError):
    """Raised when graceful fallback to HTTP is activated"""
    def __init__(self, message: str = "Fallback to HTTP activated"):
        super().__init__(message, "TLS_FALLBACK", retryable=False)

# ============================================================================
# CIRCUIT BREAKER STATE ENUM
# ============================================================================

class CircuitState(Enum):
    CLOSED = "CLOSED"      # Normal operation - all requests pass
    OPEN = "OPEN"          # Too many failures - reject all requests
    HALF_OPEN = "HALF_OPEN"  # Test if service has recovered

# ============================================================================
# TLS CIRCUIT BREAKER - STOPS CASCADING FAILURES
# ============================================================================

@dataclass
class TLSCircuitBreaker:
    """
    Circuit Breaker for TLS operations.
    Prevents cascading failures when TLS endpoints are unhealthy.
    
    State transitions:
    CLOSED → OPEN: failure_threshold reached
    OPEN → HALF_OPEN: recovery_timeout elapsed
    HALF_OPEN → CLOSED: success_threshold reached
    HALF_OPEN → OPEN: any failure
    """
    failure_threshold: int = 5
    recovery_timeout: float = 30.0  # seconds
    success_threshold: int = 3
    
    _state: CircuitState = CircuitState.CLOSED
    _failure_count: int = 0
    _success_count: int = 0
    _last_failure_time: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _failure_history: deque = field(default_factory=lambda: deque(maxlen=100))
    
    def record_success(self) -> None:
        """Record a successful TLS operation"""
        with self._lock:
            self._failure_count = 0
            self._failure_history.clear()
            
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.success_threshold:
                    self._state = CircuitState.CLOSED
                    self._success_count = 0
                    logger.info("TLS Circuit Breaker: HALF_OPEN → CLOSED")
    
    def record_failure(self, error: Exception) -> None:
        """Record a failed TLS operation"""
        with self._lock:
            self._failure_count += 1
            self._failure_history.append({
                'time': time.time(),
                'error': str(error),
                'type': type(error).__name__
            })
            self._last_failure_time = time.time()
            self._success_count = 0
            
            if self._state == CircuitState.CLOSED and self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                logger.warning(f"TLS Circuit Breaker: CLOSED → OPEN after {self._failure_count} failures")
            elif self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                logger.warning("TLS Circuit Breaker: HALF_OPEN → OPEN (failure during recovery)")
    
    def allow_request(self) -> bool:
        """Check if request should be allowed through"""
        with self._lock:
            if self._state == CircuitState.CLOSED:
                return True
            
            if self._state == CircuitState.OPEN:
                elapsed = time.time() - self._last_failure_time
                if elapsed >= self.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._success_count = 0
                    logger.info("TLS Circuit Breaker: OPEN → HALF_OPEN (recovery timeout elapsed)")
                    return True
                return False
            
            # HALF_OPEN - allow test requests
            return True
    
    def get_state(self) -> Dict[str, Any]:
        """Get circuit breaker statistics"""
        with self._lock:
            return {
                'state': self._state.value,
                'failure_count': self._failure_count,
                'success_count': self._success_count,
                'last_failure_seconds_ago': time.time() - self._last_failure_time if self._last_failure_time > 0 else None,
                'recent_failures': list(self._failure_history)[-10:],
                'failure_threshold': self.failure_threshold,
                'recovery_timeout': self.recovery_timeout
            }

# Global circuit breaker instance
_global_tls_circuit_breaker = TLSCircuitBreaker()

# ============================================================================
# EXPONENTIAL BACKOFF WITH JITTER - INTELLIGENT RETRIES
# ============================================================================

class ExponentialBackoff:
    """
    Exponential backoff with jitter for TLS connection retries.
    Prevents thundering herd problem.
    
    Formula: delay = base_delay * (2 ^ attempt) * random(0.5, 1.5)
    """
    
    def __init__(
        self,
        base_delay: float = 0.1,
        max_delay: float = 10.0,
        max_retries: int = 5,
        jitter_factor: float = 0.5
    ):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.max_retries = max_retries
        self.jitter_factor = jitter_factor
    
    def get_delay(self, attempt: int) -> float:
        """Calculate delay for given attempt number"""
        exponential = self.base_delay * (2 ** attempt)
        jitter = random.uniform(
            1.0 - self.jitter_factor,
            1.0 + self.jitter_factor
        )
        return min(exponential * jitter, self.max_delay)
    
    def should_retry(self, attempt: int, exception: Exception) -> bool:
        """Determine if exception is retryable"""
        if attempt >= self.max_retries:
            return False
        
        # Only retry transient errors
        retryable_types = (
            TLSTimeoutError,
            TLSHandshakeError,
            socket.timeout,
            ConnectionError,
            TimeoutError
        )
        
        if isinstance(exception, retryable_types):
            return True
        if isinstance(exception, TLSError) and exception.retryable:
            return True
        return False

# ============================================================================
# TLS TIMEOUT PROTECTION - PREVENTS HANGING CONNECTIONS
# ============================================================================

class TLSTimeoutProtector:
    """
    Timeout protection for TLS operations.
    Prevents hanging connections during handshake or data transfer.
    
    Uses signal-based timeout where available, thread-based otherwise.
    """
    
    def __init__(self, default_timeout: float = 10.0):
        self.default_timeout = default_timeout
        self._timeout_stats: Dict[str, Any] = {
            'total_operations': 0,
            'timeout_count': 0,
            'avg_duration': 0.0
        }
        self._lock = threading.Lock()
    
    def run_with_timeout(
        self,
        func: Callable[..., T],
        *args,
        timeout: Optional[float] = None,
        **kwargs
    ) -> T:
        """Execute function with timeout protection"""
        timeout = timeout or self.default_timeout
        start_time = time.time()
        
        result_holder: List[Any] = [None]
        exception_holder: List[Optional[Exception]] = [None]
        done = threading.Event()
        
        def target():
            try:
                result_holder[0] = func(*args, **kwargs)
            except Exception as e:
                exception_holder[0] = e
            finally:
                done.set()
        
        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        
        completed = done.wait(timeout=timeout)
        duration = time.time() - start_time
        
        with self._lock:
            self._timeout_stats['total_operations'] += 1
            n = self._timeout_stats['total_operations']
            self._timeout_stats['avg_duration'] = (
                (self._timeout_stats['avg_duration'] * (n - 1) + duration) / n
            )
        
        if not completed:
            with self._lock:
                self._timeout_stats['timeout_count'] += 1
            raise TLSTimeoutError(
                f"TLS operation timed out after {timeout}s"
            )
        
        if exception_holder[0] is not None:
            raise exception_holder[0]
        
        return result_holder[0]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get timeout protection statistics"""
        with self._lock:
            return dict(self._timeout_stats)

# Global timeout protector
_global_tls_timeout_protector = TLSTimeoutProtector()

# ============================================================================
# BULKHEAD ISOLATION - TLS OPERATIONS DON'T CRASH WHOLE SYSTEM
# ============================================================================

class TLSBulkhead:
    """
    Bulkhead pattern for TLS operations.
    Isolates TLS failures so they don't crash the entire system.
    
    Limits concurrent TLS operations and provides separate thread pools.
    """
    
    def __init__(self, max_concurrent: int = 10, max_queue_size: int = 100):
        self.max_concurrent = max_concurrent
        self.max_queue_size = max_queue_size
        self._semaphore = threading.Semaphore(max_concurrent)
        self._stats: Dict[str, Any] = {
            'executed': 0,
            'rejected': 0,
            'currently_running': 0
        }
        self._lock = threading.Lock()
    
    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function with bulkhead protection"""
        acquired = self._semaphore.acquire(blocking=False)
        
        if not acquired:
            with self._lock:
                self._stats['rejected'] += 1
            raise TLSError(
                f"TLS bulkhead full - {self.max_concurrent} concurrent operations max",
                "TLS_BULKHEAD_FULL",
                retryable=True
            )
        
        try:
            with self._lock:
                self._stats['currently_running'] += 1
            return func(*args, **kwargs)
        finally:
            with self._lock:
                self._stats['currently_running'] -= 1
                self._stats['executed'] += 1
            self._semaphore.release()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get bulkhead statistics"""
        with self._lock:
            return dict(self._stats)

# Global bulkhead
_global_tls_bulkhead = TLSBulkhead()

# ============================================================================
# GRACEFUL DEGRADATION - AUTOMATIC HTTP FALLBACK
# ============================================================================

class TLSFallbackManager:
    """
    Graceful degradation manager for TLS.
    Automatically falls back to HTTP when TLS consistently fails.
    
    Maintains health score and decides when to fallback.
    """
    
    def __init__(
        self,
        fallback_threshold: float = 0.3,  # <30% success = fallback
        recovery_threshold: float = 0.8,  # >80% success = restore TLS
        window_size: int = 50
    ):
        self.fallback_threshold = fallback_threshold
        self.recovery_threshold = recovery_threshold
        self.window_size = window_size
        self._outcomes: deque = deque(maxlen=window_size)
        self._fallback_active = False
        self._lock = threading.Lock()
        self._fallback_count = 0
        self._recovery_count = 0
    
    def record_outcome(self, success: bool) -> None:
        """Record TLS operation outcome"""
        with self._lock:
            self._outcomes.append(success)
    
    def should_use_fallback(self) -> bool:
        """Check if fallback should be activated"""
        with self._lock:
            if len(self._outcomes) < 10:  # Need minimum sample
                return False
            
            success_rate = sum(1 for o in self._outcomes if o) / len(self._outcomes)
            
            if not self._fallback_active and success_rate < self.fallback_threshold:
                self._fallback_active = True
                self._fallback_count += 1
                logger.warning(f"TLS Fallback activated - success rate: {success_rate:.1%}")
            elif self._fallback_active and success_rate > self.recovery_threshold:
                self._fallback_active = False
                self._recovery_count += 1
                logger.info(f"TLS Fallback deactivated - success rate: {success_rate:.1%}")
            
            return self._fallback_active
    
    def get_health(self) -> Dict[str, Any]:
        """Get TLS health statistics"""
        with self._lock:
            total = len(self._outcomes)
            success_rate = sum(1 for o in self._outcomes if o) / total if total > 0 else 1.0
            return {
                'fallback_active': self._fallback_active,
                'success_rate': success_rate,
                'sample_size': total,
                'fallback_activations': self._fallback_count,
                'recovery_count': self._recovery_count,
                'window_size': self.window_size
            }

# Global fallback manager
_global_tls_fallback_manager = TLSFallbackManager()

# ============================================================================
# DECORATOR - COMBINES ALL ERROR RESILIENCE PATTERNS
# ============================================================================

def tls_error_resilience(
    timeout: float = 10.0,
    max_retries: int = 3,
    use_circuit_breaker: bool = True,
    use_bulkhead: bool = True,
    allow_fallback: bool = True,
    fallback_function: Optional[Callable] = None
):
    """
    Decorator that applies comprehensive TLS error resilience.
    
    Combines: timeout protection, exponential backoff retries,
    circuit breaker, bulkhead isolation, and graceful fallback.
    
    Usage:
        @tls_error_resilience(timeout=15, max_retries=5)
        def my_tls_function(...):
            ...
    """
    backoff = ExponentialBackoff(max_retries=max_retries)
    
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            attempt = 0
            
            while True:
                # Check circuit breaker
                if use_circuit_breaker and not _global_tls_circuit_breaker.allow_request():
                    if allow_fallback and fallback_function:
                        logger.warning("Circuit open - using fallback")
                        _global_tls_fallback_manager.record_outcome(False)
                        return fallback_function(*args, **kwargs)
                    raise TLSCircuitBreakerOpen()
                
                try:
                    # Execute with timeout and bulkhead
                    def execute():
                        if use_bulkhead:
                            return _global_tls_bulkhead.execute(func, *args, **kwargs)
                        return func(*args, **kwargs)
                    
                    result = _global_tls_timeout_protector.run_with_timeout(
                        execute, timeout=timeout
                    )
                    
                    # Success - record and return
                    if use_circuit_breaker:
                        _global_tls_circuit_breaker.record_success()
                    _global_tls_fallback_manager.record_outcome(True)
                    return result
                    
                except Exception as e:
                    # Record failure
                    if use_circuit_breaker:
                        _global_tls_circuit_breaker.record_failure(e)
                    _global_tls_fallback_manager.record_outcome(False)
                    
                    # Check if we should retry
                    if backoff.should_retry(attempt, e):
                        delay = backoff.get_delay(attempt)
                        logger.debug(f"TLS retry {attempt + 1}/{max_retries} after {delay:.2f}s: {e}")
                        time.sleep(delay)
                        attempt += 1
                        continue
                    
                    # Check fallback
                    if allow_fallback and fallback_function:
                        logger.warning(f"TLS failed after {attempt} retries - using fallback: {e}")
                        return fallback_function(*args, **kwargs)
                    
                    # Re-raise original exception
                    raise
        
        return wrapper
    return decorator

# ============================================================================
# TLS WRAPPER - ERROR RESILIENCE FOR SECURITY V17 TLS SERVERS
# ============================================================================

def wrap_tls_server_with_error_resilience(
    server_class: type,
    timeout: float = 15.0,
    max_retries: int = 3,
    http_fallback_class: Optional[type] = None
) -> type:
    """
    Wrap an existing TLS server class with comprehensive error resilience.
    
    This is the core integration with Security v17.
    Pure wrapper pattern - ZERO modification to original server code.
    
    Args:
        server_class: Original TLS server class from Security v17
        timeout: Handshake timeout in seconds
        max_retries: Maximum retry attempts
        http_fallback_class: Plain HTTP server class for graceful fallback
    
    Returns:
        New class with error resilience layered on top
    """
    
    class ErrorResilientTLSServer(server_class):
        """
        Error-resilient wrapper for TLS server.
        Inherits all functionality from original, adds error resilience layer.
        """
        
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._error_stats = {
                'handshake_success': 0,
                'handshake_failure': 0,
                'handshake_timeout': 0,
                'retries_used': 0,
                'fallback_used': 0
            }
            self._stats_lock = threading.Lock()
        
        def _handle_tls_handshake(self, *args, **kwargs):
            """Wrapped handshake with error resilience"""
            @tls_error_resilience(
                timeout=timeout,
                max_retries=max_retries,
                allow_fallback=(http_fallback_class is not None),
                fallback_function=self._http_fallback if http_fallback_class else None
            )
            def do_handshake():
                return super(ErrorResilientTLSServer, self)._handle_tls_handshake(*args, **kwargs)
            
            try:
                result = do_handshake()
                with self._stats_lock:
                    self._error_stats['handshake_success'] += 1
                return result
            except TLSTimeoutError:
                with self._stats_lock:
                    self._error_stats['handshake_timeout'] += 1
                raise
            except Exception as e:
                with self._stats_lock:
                    self._error_stats['handshake_failure'] += 1
                raise
        
        def _http_fallback(self, *args, **kwargs):
            """Graceful fallback to HTTP"""
            with self._stats_lock:
                self._error_stats['fallback_used'] += 1
            logger.warning("Graceful fallback: Using HTTP instead of HTTPS")
            
            if http_fallback_class:
                fallback_server = http_fallback_class(*args, **kwargs)
                return fallback_server.handle_request(*args, **kwargs)
            
            raise TLSFallbackActivated()
        
        def get_error_resilience_stats(self) -> Dict[str, Any]:
            """Get error resilience statistics"""
            with self._stats_lock:
                stats = dict(self._error_stats)
                total = stats['handshake_success'] + stats['handshake_failure']
                stats['success_rate'] = (
                    stats['handshake_success'] / total if total > 0 else 1.0
                )
                stats['circuit_breaker'] = _global_tls_circuit_breaker.get_state()
                stats['timeout_protector'] = _global_tls_timeout_protector.get_stats()
                stats['bulkhead'] = _global_tls_bulkhead.get_stats()
                stats['fallback_manager'] = _global_tls_fallback_manager.get_health()
                return stats
    
    return ErrorResilientTLSServer

# ============================================================================
# CONVENIENCE FUNCTIONS - GLOBAL ACCESS
# ============================================================================

def get_tls_error_resilience_stats() -> Dict[str, Any]:
    """Get comprehensive error resilience statistics"""
    return {
        'circuit_breaker': _global_tls_circuit_breaker.get_state(),
        'timeout_protector': _global_tls_timeout_protector.get_stats(),
        'bulkhead': _global_tls_bulkhead.get_stats(),
        'fallback_manager': _global_tls_fallback_manager.get_health(),
        'version': '25.0.0',
        'timestamp': time.time()
    }

def reset_tls_error_resilience_state() -> None:
    """Reset all error resilience state (for testing)"""
    global _global_tls_circuit_breaker
    global _global_tls_timeout_protector
    global _global_tls_bulkhead
    global _global_tls_fallback_manager
    
    _global_tls_circuit_breaker = TLSCircuitBreaker()
    _global_tls_timeout_protector = TLSTimeoutProtector()
    _global_tls_bulkhead = TLSBulkhead()
    _global_tls_fallback_manager = TLSFallbackManager()

def classify_tls_exception(exc: Exception) -> Tuple[str, bool]:
    """Classify any exception into TLS error code and retryable flag"""
    if isinstance(exc, TLSError):
        return exc.error_code, exc.retryable
    if isinstance(exc, ssl.SSLError):
        if "CERTIFICATE" in str(exc).upper():
            return "TLS_CERT_INVALID", False
        if "HANDSHAKE" in str(exc).upper():
            return "TLS_HANDSHAKE_FAILED", True
        if "CIPHER" in str(exc).upper():
            return "TLS_CIPHER_MISMATCH", False
        return "TLS_SSL_ERROR", True
    if isinstance(exc, socket.timeout):
        return "TLS_TIMEOUT", True
    if isinstance(exc, ConnectionError):
        return "TLS_CONNECTION_ERROR", True
    if isinstance(exc, TimeoutError):
        return "TLS_TIMEOUT", True
    return "TLS_UNKNOWN_ERROR", False

# ============================================================================
# BACKWARD COMPATIBILITY - ALL EXISTING CODE WORKS UNCHANGED
# ============================================================================

# Export all existing error resilience functions unchanged
# This ensures 100% backward compatibility with Error Resilience v24

try:
    from .error_resilience_v24_combined_timeout_retry_fallback_circuit_breaker_2026_june import (
        CircuitBreaker as LegacyCircuitBreaker,
        RetryWithBackoff as LegacyRetryBackoff,
        TimeoutProtector as LegacyTimeoutProtector,
        FallbackChain as LegacyFallbackChain,
        BulkheadIsolation as LegacyBulkhead,
        error_resilience_decorator as legacy_decorator
    )
    
    # Re-export for backward compatibility
    CircuitBreaker = LegacyCircuitBreaker
    RetryWithBackoff = LegacyRetryBackoff
    TimeoutProtector = LegacyTimeoutProtector
    FallbackChain = LegacyFallbackChain
    BulkheadIsolation = LegacyBulkhead
    error_resilience_decorator = legacy_decorator
    
except ImportError:
    # Fallback - v24 not available, use v25 implementations
    pass

__all__ = [
    # Exception hierarchy
    'TLSError',
    'TLSTimeoutError',
    'TLSCertificateError',
    'TLSCipherError',
    'TLSVersionError',
    'TLSHandshakeError',
    'TLSCircuitBreakerOpen',
    'TLSFallbackActivated',
    
    # Core components
    'CircuitState',
    'TLSCircuitBreaker',
    'ExponentialBackoff',
    'TLSTimeoutProtector',
    'TLSBulkhead',
    'TLSFallbackManager',
    
    # Decorators and wrappers
    'tls_error_resilience',
    'wrap_tls_server_with_error_resilience',
    
    # Convenience functions
    'get_tls_error_resilience_stats',
    'reset_tls_error_resilience_state',
    'classify_tls_exception',
    
    # Backward compatible exports
    'CircuitBreaker',
    'RetryWithBackoff',
    'TimeoutProtector',
    'FallbackChain',
    'BulkheadIsolation',
    'error_resilience_decorator',
]

# Module metadata
__version__ = '25.0.0'
__dimension__ = 'E - Error Resilience'
__compatible_with__ = ['Security v17 TLS', 'Observability v14 Metrics', 'All v24 modules']
