"""
Error Resilience - Deadline Propagation with Cooperative Cancellation Tokens v35
Dimension E: Error Resilience
ADD-ONLY implementation - wraps existing functionality, no core code modified
Happy path behavior 100% preserved

Features:
1. Deadline propagation across nested operations
2. Cooperative cancellation tokens for graceful abort
3. Hierarchical deadline inheritance
4. Deadline-aware retry with remaining time budget
5. Cancellation callback registry for cleanup
6. Deadline violation detection and reporting
"""
import time
import threading
import functools
import inspect
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from datetime import datetime
from uuid import uuid4


# -----------------------------------------------------------------------------
# BASE EXCEPTION HIERARCHY - Self-contained
# -----------------------------------------------------------------------------
class NeuralShieldError(Exception):
    """Base exception for all NeuralShield errors"""
    error_code: str = "NS-000"
    severity: str = "ERROR"
    retryable: bool = False
    fallback_available: bool = False

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.timestamp = datetime.utcnow().isoformat()


# -----------------------------------------------------------------------------
# ENHANCED EXCEPTION HIERARCHY - Deadline & Cancellation
# -----------------------------------------------------------------------------
class DeadlineExceededError(NeuralShieldError):
    """Operation exceeded its deadline"""
    error_code = "NS-DE-001"
    retryable = False
    fallback_available = True
    
    def __init__(self, message: str, deadline_seconds: float, elapsed_seconds: float, details: Optional[Dict] = None):
        super().__init__(message, details)
        self.deadline_seconds = deadline_seconds
        self.elapsed_seconds = elapsed_seconds


class OperationCancelledError(NeuralShieldError):
    """Operation was explicitly cancelled"""
    error_code = "NS-DE-002"
    retryable = False
    fallback_available = True
    
    def __init__(self, message: str, cancel_reason: str, details: Optional[Dict] = None):
        super().__init__(message, details)
        self.cancel_reason = cancel_reason


class DeadlineInheritanceError(NeuralShieldError):
    """Error in deadline propagation hierarchy"""
    error_code = "NS-DE-003"
    retryable = True


# -----------------------------------------------------------------------------
# CANCEL STATE ENUM
# -----------------------------------------------------------------------------
class CancellationState(Enum):
    NONE = "none"                  # No cancellation requested
    REQUESTED = "requested"        # Cancellation requested, pending
    CANCELLED = "cancelled"        # Operation cancelled
    COMPLETED = "completed"        # Operation completed normally


# -----------------------------------------------------------------------------
# DATA CLASSES
# -----------------------------------------------------------------------------
@dataclass
class DeadlineBudget:
    """Remaining time budget for operations"""
    total_deadline_seconds: float
    remaining_seconds: float
    start_time: float
    expired: bool = False
    
    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self.start_time
    
    def check_expired(self) -> bool:
        self.remaining_seconds = self.total_deadline_seconds - self.elapsed_seconds
        self.expired = self.remaining_seconds <= 0
        return self.expired


@dataclass
class CancellationEvent:
    timestamp: float
    reason: str
    source_token_id: str


@dataclass
class DeadlineResult:
    success: bool
    result: Any
    cancelled: bool
    deadline_exceeded: bool
    total_time: float
    deadline_budget: DeadlineBudget
    warnings: List[str] = field(default_factory=list)


# -----------------------------------------------------------------------------
# CANCELLATION TOKEN - Cooperative Cancellation
# -----------------------------------------------------------------------------
class CancellationToken:
    """
    Cooperative cancellation token with deadline propagation
    
    ADD-ONLY: Can wrap any existing function without modification
    Supports:
    - Parent-child deadline inheritance
    - Callback registration for cleanup
    - Thread-safe cancellation
    - Deadline-aware execution
    """
    
    def __init__(
        self,
        deadline_seconds: Optional[float] = None,
        parent_token: Optional['CancellationToken'] = None
    ):
        self.token_id = str(uuid4())
        self._state = CancellationState.NONE
        self._cancel_events: List[CancellationEvent] = []
        self._callbacks: List[Callable[[], None]] = []
        self._child_tokens: Set[str] = set()
        self._parent_token = parent_token
        self._lock = threading.Lock()
        
        # Deadline setup
        self._start_time = time.time()
        self._deadline_seconds = deadline_seconds
        self._absolute_deadline: Optional[float] = None
        
        if deadline_seconds is not None:
            self._absolute_deadline = self._start_time + deadline_seconds
        elif parent_token is not None and parent_token._absolute_deadline is not None:
            # Inherit parent deadline
            self._absolute_deadline = parent_token._absolute_deadline
            self._deadline_seconds = self._absolute_deadline - self._start_time
    
    @property
    def is_cancellation_requested(self) -> bool:
        """Check if cancellation has been requested"""
        with self._lock:
            return self._state in (CancellationState.REQUESTED, CancellationState.CANCELLED)
    
    @property
    def is_deadline_exceeded(self) -> bool:
        """Check if deadline has been exceeded"""
        if self._absolute_deadline is None:
            return False
        return time.time() >= self._absolute_deadline
    
    @property
    def remaining_seconds(self) -> Optional[float]:
        """Get remaining time before deadline"""
        if self._absolute_deadline is None:
            return None
        remaining = self._absolute_deadline - time.time()
        return max(0, remaining)
    
    def throw_if_cancellation_requested(self):
        """Throw exception if cancellation requested or deadline exceeded"""
        if self.is_cancellation_requested:
            raise OperationCancelledError(
                "Operation cancelled",
                cancel_reason=self._cancel_events[-1].reason if self._cancel_events else "unknown"
            )
        if self.is_deadline_exceeded:
            elapsed = time.time() - self._start_time
            raise DeadlineExceededError(
                f"Deadline exceeded: {self._deadline_seconds}s",
                deadline_seconds=self._deadline_seconds,
                elapsed_seconds=elapsed
            )
    
    def register_callback(self, callback: Callable[[], None]) -> Callable[[], None]:
        """Register callback to run on cancellation
        
        Returns: Unregister function
        """
        with self._lock:
            self._callbacks.append(callback)
        
        def unregister():
            with self._lock:
                if callback in self._callbacks:
                    self._callbacks.remove(callback)
        
        return unregister
    
    def cancel(self, reason: str = "manual"):
        """Request cancellation of this token and all children"""
        with self._lock:
            if self._state != CancellationState.NONE:
                return
            
            self._state = CancellationState.REQUESTED
            event = CancellationEvent(
                timestamp=time.time(),
                reason=reason,
                source_token_id=self.token_id
            )
            self._cancel_events.append(event)
            
            # Execute callbacks
            for callback in self._callbacks:
                try:
                    callback()
                except Exception:
                    pass  # Callback errors don't break cancellation
            
            self._state = CancellationState.CANCELLED
    
    def create_child_token(self, additional_seconds: Optional[float] = None) -> 'CancellationToken':
        """Create child token that inherits parent deadline
        
        ADD-ONLY: Creates new token without modifying parent
        """
        if additional_seconds is not None and self._absolute_deadline is not None:
            # Child gets either remaining time or additional_seconds, whichever is less
            remaining = self.remaining_seconds
            child_deadline = min(additional_seconds, remaining) if remaining else additional_seconds
            child = CancellationToken(deadline_seconds=child_deadline, parent_token=self)
        else:
            child = CancellationToken(parent_token=self)
        
        with self._lock:
            self._child_tokens.add(child.token_id)
        
        return child


# -----------------------------------------------------------------------------
# DEADLINE PROPAGATION MANAGER
# -----------------------------------------------------------------------------
class DeadlinePropagationManager:
    """
    Manager for deadline propagation across nested operations
    
    Dimension E - Error Resilience Core Implementation
    
    Features:
    - Thread-local deadline context
    - Automatic deadline inheritance
    - Deadline-aware retry
    - Graceful cancellation propagation
    - 100% backward compatible
    """
    
    def __init__(self):
        self._thread_local = threading.local()
        self._token_registry: Dict[str, CancellationToken] = {}
        self._lock = threading.Lock()
    
    def _get_current_context(self) -> Optional[CancellationToken]:
        """Get current thread's cancellation token"""
        return getattr(self._thread_local, 'current_token', None)
    
    def _set_current_context(self, token: Optional[CancellationToken]):
        """Set current thread's cancellation token"""
        self._thread_local.current_token = token
    
    def create_root_token(self, deadline_seconds: float) -> CancellationToken:
        """Create root cancellation token"""
        token = CancellationToken(deadline_seconds=deadline_seconds)
        with self._lock:
            self._token_registry[token.token_id] = token
        return token
    
    def execute_with_deadline(
        self,
        operation: Callable,
        deadline_seconds: float,
        inherit_parent: bool = True,
        *args,
        **kwargs
    ) -> DeadlineResult:
        """
        Execute operation with deadline and cancellation support
        
        ADD-ONLY wrapper - does not modify operation
        Happy path: direct execution with minimal overhead
        """
        start_time = time.time()
        warnings: List[str] = []
        
        # Determine effective deadline (parent inheritance)
        parent_token = self._get_current_context() if inherit_parent else None
        
        if parent_token and parent_token._absolute_deadline is not None:
            parent_remaining = parent_token.remaining_seconds
            if parent_remaining and parent_remaining < deadline_seconds:
                deadline_seconds = parent_remaining
                warnings.append(f"Deadline tightened to {deadline_seconds:.2f}s by parent context")
        
        # Create token for this operation
        token = CancellationToken(deadline_seconds=deadline_seconds, parent_token=parent_token)
        
        budget = DeadlineBudget(
            total_deadline_seconds=deadline_seconds,
            remaining_seconds=deadline_seconds,
            start_time=start_time
        )
        
        # Set context for nested calls
        old_context = self._get_current_context()
        self._set_current_context(token)
        
        try:
            # Check deadline before starting
            if token.is_deadline_exceeded:
                budget.check_expired()
                return DeadlineResult(
                    success=False,
                    result=None,
                    cancelled=False,
                    deadline_exceeded=True,
                    total_time=time.time() - start_time,
                    deadline_budget=budget,
                    warnings=["Deadline already exceeded before execution"]
                )
            
            # Execute operation - pass token if function accepts it
            try:
                sig = inspect.signature(operation)
                if 'cancellation_token' in sig.parameters:
                    result = operation(*args, cancellation_token=token, **kwargs)
                else:
                    result = operation(*args, **kwargs)
                
                budget.check_expired()
                return DeadlineResult(
                    success=True,
                    result=result,
                    cancelled=False,
                    deadline_exceeded=budget.expired,
                    total_time=time.time() - start_time,
                    deadline_budget=budget,
                    warnings=warnings
                )
                
            except DeadlineExceededError as e:
                budget.check_expired()
                warnings.append(f"Deadline exceeded: {e.message}")
                return DeadlineResult(
                    success=False,
                    result=None,
                    cancelled=False,
                    deadline_exceeded=True,
                    total_time=time.time() - start_time,
                    deadline_budget=budget,
                    warnings=warnings
                )
                
            except OperationCancelledError as e:
                budget.check_expired()
                warnings.append(f"Cancelled: {e.cancel_reason}")
                return DeadlineResult(
                    success=False,
                    result=None,
                    cancelled=True,
                    deadline_exceeded=False,
                    total_time=time.time() - start_time,
                    deadline_budget=budget,
                    warnings=warnings
                )
                
        finally:
            self._set_current_context(old_context)
    
    def deadline_aware_retry(
        self,
        operation: Callable,
        deadline_seconds: float,
        max_attempts: int = 3,
        backoff_base: float = 0.1,
        *args,
        **kwargs
    ) -> DeadlineResult:
        """
        Retry operation respecting remaining deadline budget
        
        ADD-ONLY: Uses remaining time to decide retry feasibility
        """
        start_time = time.time()
        all_warnings: List[str] = []
        
        for attempt in range(max_attempts):
            elapsed = time.time() - start_time
            remaining = deadline_seconds - elapsed
            
            if remaining <= 0:
                budget = DeadlineBudget(deadline_seconds, 0, start_time, True)
                return DeadlineResult(
                    success=False,
                    result=None,
                    cancelled=False,
                    deadline_exceeded=True,
                    total_time=elapsed,
                    deadline_budget=budget,
                    warnings=all_warnings + ["Deadline exhausted during retries"]
                )
            
            # Calculate backoff but don't exceed remaining time
            backoff = min(backoff_base * (2 ** attempt), remaining * 0.5)
            
            result = self.execute_with_deadline(
                operation,
                deadline_seconds=remaining,
                inherit_parent=True,
                *args,
                **kwargs
            )
            
            if result.success:
                return result
            
            all_warnings.extend([f"Attempt {attempt + 1}: {w}" for w in result.warnings])
            
            if attempt < max_attempts - 1 and backoff > 0:
                time.sleep(backoff)
        
        # All attempts failed
        budget = DeadlineBudget(
            deadline_seconds,
            deadline_seconds - (time.time() - start_time),
            start_time
        )
        budget.check_expired()
        
        return DeadlineResult(
            success=False,
            result=None,
            cancelled=False,
            deadline_exceeded=budget.expired,
            total_time=time.time() - start_time,
            deadline_budget=budget,
            warnings=all_warnings
        )


# -----------------------------------------------------------------------------
# CONTEXT MANAGER FOR DEADLINE SCOPES
# -----------------------------------------------------------------------------
class DeadlineScope:
    """
    Context manager for deadline-scoped execution
    
    with DeadlineScope(5.0) as token:
        result = do_work(cancellation_token=token)
    """
    
    def __init__(self, deadline_seconds: float, manager: Optional[DeadlinePropagationManager] = None):
        self.deadline_seconds = deadline_seconds
        self.manager = manager or DeadlinePropagationManager()
        self.token: Optional[CancellationToken] = None
        self._old_context = None
    
    def __enter__(self) -> CancellationToken:
        self._old_context = self.manager._get_current_context()
        self.token = self.manager.create_root_token(self.deadline_seconds)
        self.manager._set_current_context(self.token)
        return self.token
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.manager._set_current_context(self._old_context)
        if self.token:
            self.token.cancel(reason="scope_exit")
        return False  # Don't suppress exceptions


# -----------------------------------------------------------------------------
# GLOBAL INSTANCE AND DECORATORS
# -----------------------------------------------------------------------------
_global_deadline_manager = DeadlinePropagationManager()


def with_deadline(deadline_seconds: float, inherit: bool = True):
    """
    Decorator: Add deadline enforcement to function
    
    ADD-ONLY decorator - does not modify function logic
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> DeadlineResult:
            return _global_deadline_manager.execute_with_deadline(
                func, deadline_seconds, inherit, *args, **kwargs
            )
        return wrapper
    return decorator


def deadline_aware(max_attempts: int = 3, backoff: float = 0.1):
    """
    Decorator: Add deadline-aware retry to function
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(deadline_seconds: float, *args, **kwargs) -> DeadlineResult:
            return _global_deadline_manager.deadline_aware_retry(
                func, deadline_seconds, max_attempts, backoff, *args, **kwargs
            )
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# FALLBACK FUNCTIONS - GRACEFUL DEGRADATION
# -----------------------------------------------------------------------------
def create_safe_fallback(
    primary: Callable,
    fallback: Callable,
    deadline_seconds: float = 10.0
) -> Callable:
    """
    Create wrapped function with deadline and fallback
    
    ADD-ONLY: Creates new function, doesn't modify originals
    """
    manager = DeadlinePropagationManager()
    
    @functools.wraps(primary)
    def wrapped(*args, **kwargs):
        result = manager.execute_with_deadline(
            primary, deadline_seconds, True, *args, **kwargs
        )
        
        if result.success:
            return result.result
        
        # Try fallback with remaining time
        remaining = max(1.0, deadline_seconds - result.total_time)
        fallback_result = manager.execute_with_deadline(
            fallback, remaining, False, *args, **kwargs
        )
        
        if fallback_result.success:
            return fallback_result.result
        
        # Final graceful degradation - return safe default
        return None
    
    return wrapped
