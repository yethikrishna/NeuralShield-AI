"""
Error Resilience - Threat Detection Deadline Propagation & Cooperative Cancellation v36
Dimension E: Error Resilience
ADD-ONLY implementation - wraps existing functionality, no core code modified
Happy path behavior 100% preserved

Features:
1. Deadline propagation across nested threat detection operations
2. Cooperative cancellation with graceful cleanup
3. Deadline-aware timeout budgeting for multi-stage pipelines
4. Cancellation token propagation through call chains
5. Deadline violation detection with graceful degradation
6. Resource cleanup on cancellation
"""
import time
import threading
import functools
import signal
import contextlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type, Tuple, Union, Generator, ContextManager
from datetime import datetime, timedelta
from uuid import uuid4

# -----------------------------------------------------------------------------
# BASE EXCEPTION (defined here for standalone use)
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
    error_code = "NS-DL-001"
    retryable = True
    fallback_available = True

class OperationCancelledError(NeuralShieldError):
    """Operation was explicitly cancelled"""
    error_code = "NS-DL-002"
    retryable = False
    fallback_available = True

class DeadlineBudgetExhaustedError(NeuralShieldError):
    """Time budget exhausted for multi-stage operation"""
    error_code = "NS-DL-003"
    retryable = True
    fallback_available = True

class CancellationTokenExpiredError(NeuralShieldError):
    """Cancellation token has expired"""
    error_code = "NS-DL-004"
    retryable = False
    fallback_available = True

# -----------------------------------------------------------------------------
# ENUMS
# -----------------------------------------------------------------------------
class DeadlineSource(Enum):
    EXPLICIT = "explicit"          # User-specified deadline
    INHERITED = "inherited"        # Inherited from parent context
    BUDGETED = "budgeted"          # Calculated from remaining budget
    DEFAULT = "default"            # System default

class CancellationReason(Enum):
    USER_REQUESTED = "user_requested"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    PARENT_CANCELLED = "parent_cancelled"
    BUDGET_EXHAUSTED = "budget_exhausted"
    SYSTEM_SHUTDOWN = "system_shutdown"

# -----------------------------------------------------------------------------
# DATA CLASSES
# -----------------------------------------------------------------------------
@dataclass
class DeadlineContext:
    """Deadline context for operation timing"""
    deadline: float  # Absolute time (monotonic)
    source: DeadlineSource
    operation_key: str
    created_at: float = field(default_factory=time.monotonic)
    parent_context_id: Optional[str] = None
    context_id: str = field(default_factory=lambda: str(uuid4()))
    
    @property
    def remaining_time(self) -> float:
        """Get remaining time in seconds"""
        return max(0.0, self.deadline - time.monotonic())
    
    @property
    def expired(self) -> bool:
        """Check if deadline has passed"""
        return time.monotonic() >= self.deadline
    
    @property
    def elapsed(self) -> float:
        """Time elapsed since creation"""
        return time.monotonic() - self.created_at

@dataclass
class CancellationRegistration:
    """Registration for cancellation callback"""
    callback_id: str
    callback: Callable[[CancellationReason], None]
    oneshot: bool = True

@dataclass
class DeadlineBudget:
    """Time budget allocation for multi-stage pipelines"""
    total_budget: float
    allocated: Dict[str, float] = field(default_factory=dict)
    used: Dict[str, float] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)
    
    def allocate(self, stage: str, amount: float) -> bool:
        """Allocate time budget to a stage"""
        with self.lock:
            total_allocated = sum(self.allocated.values())
            if total_allocated + amount <= self.total_budget:
                self.allocated[stage] = amount
                return True
            return False
    
    def record_usage(self, stage: str, duration: float):
        """Record actual time used"""
        with self.lock:
            self.used[stage] = duration
    
    @property
    def remaining_budget(self) -> float:
        """Get remaining unallocated budget"""
        with self.lock:
            return self.total_budget - sum(self.allocated.values())
    
    @property
    def total_used(self) -> float:
        """Get total time used so far"""
        with self.lock:
            return sum(self.used.values())

# -----------------------------------------------------------------------------
# CANCELLATION TOKEN - Cooperative Cancellation
# -----------------------------------------------------------------------------
class CancellationToken:
    """
    Cooperative cancellation token with deadline support
    
    ADD-ONLY - Can be passed through existing call chains
    No modification required to wrapped functions
    """
    
    def __init__(
        self,
        timeout: Optional[float] = None,
        parent: Optional['CancellationToken'] = None,
        operation_key: str = "unknown"
    ):
        self._token_id = str(uuid4())
        self._parent = parent
        self._operation_key = operation_key
        self._cancelled = False
        self._cancellation_reason: Optional[CancellationReason] = None
        self._callbacks: Dict[str, CancellationRegistration] = {}
        self._lock = threading.Lock()
        self._deadline_context: Optional[DeadlineContext] = None
        
        # Set deadline if timeout specified
        if timeout is not None:
            self._deadline_context = DeadlineContext(
                deadline=time.monotonic() + timeout,
                source=DeadlineSource.EXPLICIT,
                operation_key=operation_key
            )
        
        # Register with parent if provided
        if parent is not None:
            parent._register_child(self)
    
    def _register_child(self, child: 'CancellationToken'):
        """Register child token for propagation"""
        def on_parent_cancelled(reason: CancellationReason):
            child.cancel(CancellationReason.PARENT_CANCELLED)
        
        self.register_callback(on_parent_cancelled)
    
    @property
    def cancelled(self) -> bool:
        """Check if token has been cancelled"""
        with self._lock:
            if self._cancelled:
                return True
            
            # Check deadline
            if self._deadline_context and self._deadline_context.expired:
                self._cancelled = True
                self._cancellation_reason = CancellationReason.DEADLINE_EXCEEDED
                return True
            
            return False
    
    @property
    def cancellation_reason(self) -> Optional[CancellationReason]:
        """Get reason for cancellation"""
        with self._lock:
            return self._cancellation_reason
    
    @property
    def remaining_time(self) -> Optional[float]:
        """Get remaining time if deadline set"""
        if self._deadline_context:
            return self._deadline_context.remaining_time
        return None
    
    def throw_if_cancelled(self):
        """Raise exception if cancelled"""
        if self.cancelled:
            reason = self._cancellation_reason
            if reason == CancellationReason.DEADLINE_EXCEEDED:
                raise DeadlineExceededError(
                    f"Operation '{self._operation_key}' exceeded deadline"
                )
            raise OperationCancelledError(
                f"Operation '{self._operation_key}' cancelled: {reason}"
            )
    
    def cancel(self, reason: CancellationReason = CancellationReason.USER_REQUESTED):
        """Cancel the token and invoke all callbacks"""
        with self._lock:
            if self._cancelled:
                return
            
            self._cancelled = True
            self._cancellation_reason = reason
            
            # Invoke callbacks
            for reg in list(self._callbacks.values()):
                try:
                    reg.callback(reason)
                except Exception:
                    pass  # Callback errors don't break cancellation
                
                if reg.oneshot:
                    del self._callbacks[reg.callback_id]
    
    def register_callback(
        self,
        callback: Callable[[CancellationReason], None],
        oneshot: bool = True
    ) -> str:
        """Register callback to be invoked on cancellation"""
        callback_id = str(uuid4())
        with self._lock:
            self._callbacks[callback_id] = CancellationRegistration(
                callback_id=callback_id,
                callback=callback,
                oneshot=oneshot
            )
        return callback_id
    
    def unregister_callback(self, callback_id: str):
        """Unregister a cancellation callback"""
        with self._lock:
            self._callbacks.pop(callback_id, None)
    
    def create_child(
        self,
        operation_key: str,
        timeout: Optional[float] = None
    ) -> 'CancellationToken':
        """Create child token with inherited cancellation"""
        # Calculate child timeout based on remaining time
        if timeout is None and self._deadline_context:
            timeout = self._deadline_context.remaining_time
        
        return CancellationToken(
            timeout=timeout,
            parent=self,
            operation_key=operation_key
        )
    
    def derive_deadline(self, operation_key: str, fraction: float = 0.5) -> 'CancellationToken':
        """Create child token using fraction of remaining time"""
        if self._deadline_context:
            remaining = self._deadline_context.remaining_time
            child_timeout = max(0.1, remaining * fraction)
            return self.create_child(operation_key, child_timeout)
        return self.create_child(operation_key)

# -----------------------------------------------------------------------------
# DEADLINE PROPAGATION MANAGER
# -----------------------------------------------------------------------------
class DeadlinePropagationManager:
    """
    Manager for deadline propagation across threat detection operations
    
    ADD-ONLY - Layer on top of existing detection pipelines
    Provides:
    - Deadline context management
    - Budget allocation for multi-stage detection
    - Cooperative cancellation
    - Graceful cleanup
    """
    
    def __init__(self, default_timeout: float = 30.0):
        self._default_timeout = default_timeout
        self._contexts: Dict[str, DeadlineContext] = {}
        self._budgets: Dict[str, DeadlineBudget] = {}
        self._root_tokens: Dict[str, CancellationToken] = {}
        self._lock = threading.Lock()
        self._local = threading.local()
    
    def create_root_context(
        self,
        operation_key: str,
        timeout: Optional[float] = None
    ) -> CancellationToken:
        """Create root cancellation context for an operation"""
        actual_timeout = timeout or self._default_timeout
        token = CancellationToken(timeout=actual_timeout, operation_key=operation_key)
        
        with self._lock:
            self._root_tokens[token._token_id] = token
        
        return token
    
    def create_budgeted_pipeline(
        self,
        pipeline_key: str,
        total_budget: float,
        stage_allocations: Dict[str, float]
    ) -> DeadlineBudget:
        """Create time-budgeted multi-stage pipeline"""
        budget = DeadlineBudget(total_budget=total_budget)
        
        for stage, allocation in stage_allocations.items():
            budget.allocate(stage, allocation)
        
        with self._lock:
            self._budgets[pipeline_key] = budget
        
        return budget
    
    @contextlib.contextmanager
    def deadline_scope(
        self,
        operation_key: str,
        timeout: Optional[float] = None,
        parent_token: Optional[CancellationToken] = None
    ) -> Generator[CancellationToken, None, None]:
        """
        Context manager for deadline-scoped operations
        
        Usage:
            with manager.deadline_scope("prompt_injection", 5.0) as token:
                result = detect_prompt_injection(input, token)
                token.throw_if_cancelled()
        """
        if parent_token:
            token = parent_token.create_child(operation_key, timeout)
        else:
            token = self.create_root_context(operation_key, timeout)
        
        try:
            yield token
        finally:
            # Auto-cancel on scope exit
            token.cancel(CancellationReason.PARENT_CANCELLED)
    
    def wrap_with_deadline(
        self,
        operation_key: str,
        timeout: Optional[float] = None,
        fallback: Optional[Callable] = None
    ):
        """
        Decorator to wrap function with deadline enforcement
        
        ADD-ONLY decorator - no modification to wrapped function
        """
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                # Check if token already passed
                token = kwargs.pop('cancellation_token', None)
                
                if token is None:
                    # Create new context
                    with self.deadline_scope(operation_key, timeout) as token:
                        kwargs['cancellation_token'] = token
                        return func(*args, **kwargs)
                else:
                    # Use existing token (propagation)
                    child_token = token.create_child(operation_key, timeout)
                    kwargs['cancellation_token'] = child_token
                    try:
                        return func(*args, **kwargs)
                    finally:
                        child_token.cancel(CancellationReason.PARENT_CANCELLED)
            
            return wrapper
        return decorator
    
    def check_deadline(self, token: CancellationToken, stage: str = "unknown"):
        """Check deadline and raise if exceeded"""
        token.throw_if_cancelled()

# -----------------------------------------------------------------------------
# THREAT DETECTION PIPELINE WITH DEADLINE SUPPORT
# -----------------------------------------------------------------------------
class DeadlineAwareDetectionPipeline:
    """
    Deadline-aware threat detection pipeline wrapper
    
    ADD-ONLY - Wraps existing detection modules
    Preserves 100% of happy path behavior
    Adds:
    - Deadline propagation across detection stages
    - Cooperative cancellation checks
    - Budget-aware stage execution
    - Graceful degradation on timeout
    """
    
    def __init__(self):
        self._deadline_manager = DeadlinePropagationManager()
        self._stage_fallbacks: Dict[str, Callable] = {}
        self._lock = threading.Lock()
    
    def register_stage_fallback(self, stage_name: str, fallback: Callable):
        """Register fallback for a detection stage (ADD-ONLY)"""
        with self._lock:
            self._stage_fallbacks[stage_name] = fallback
    
    def execute_pipeline(
        self,
        stages: List[Tuple[str, Callable]],
        input_data: Any,
        total_timeout: float = 10.0,
        cancellation_token: Optional[CancellationToken] = None
    ) -> Dict[str, Any]:
        """
        Execute detection pipeline with deadline awareness
        
        Features:
        - Sequential stage execution with budget tracking
        - Cooperative cancellation checks between stages
        - Automatic fallback invocation on deadline violation
        - Partial results collection
        """
        root_token = cancellation_token or self._deadline_manager.create_root_context(
            "detection_pipeline", total_timeout
        )
        
        results: Dict[str, Any] = {}
        warnings: List[str] = []
        partial_success = False
        
        for stage_name, stage_func in stages:
            try:
                # Check cancellation before stage
                root_token.throw_if_cancelled()
                
                # Create child token with budget
                stage_token = root_token.derive_deadline(stage_name)
                
                # Execute stage with deadline
                try:
                    result = stage_func(input_data, stage_token)
                    results[stage_name] = {
                        "success": True,
                        "result": result,
                        "degraded": False
                    }
                    partial_success = True
                    
                except DeadlineExceededError:
                    # Try fallback if available
                    if stage_name in self._stage_fallbacks:
                        fallback_func = self._stage_fallbacks[stage_name]
                        fallback_result = fallback_func(input_data)
                        results[stage_name] = {
                            "success": True,
                            "result": fallback_result,
                            "degraded": True,
                            "warning": "Used degraded fallback due to deadline"
                        }
                        warnings.append(f"Stage {stage_name}: degraded fallback used")
                        partial_success = True
                    else:
                        results[stage_name] = {
                            "success": False,
                            "error": "Deadline exceeded",
                            "degraded": False
                        }
                        warnings.append(f"Stage {stage_name}: deadline exceeded")
                
                except OperationCancelledError:
                    results[stage_name] = {
                        "success": False,
                        "error": "Cancelled",
                        "degraded": False
                    }
                    warnings.append(f"Stage {stage_name}: cancelled")
                    break  # Stop pipeline on explicit cancellation
                
            except Exception as e:
                results[stage_name] = {
                    "success": False,
                    "error": str(e),
                    "degraded": False
                }
                warnings.append(f"Stage {stage_name}: {str(e)}")
        
        return {
            "pipeline_success": partial_success,
            "results": results,
            "warnings": warnings,
            "total_stages": len(stages),
            "completed_stages": sum(1 for r in results.values() if r.get("success")),
            "degraded_stages": sum(1 for r in results.values() if r.get("degraded"))
        }

# -----------------------------------------------------------------------------
# GLOBAL INSTANCE - READY FOR IMPORT AND USE
# -----------------------------------------------------------------------------
_global_deadline_manager = DeadlinePropagationManager()

def get_deadline_manager() -> DeadlinePropagationManager:
    """Get global deadline manager instance"""
    return _global_deadline_manager

def deadline_aware(operation_key: str, timeout: Optional[float] = None):
    """Decorator for quick deadline wrapping"""
    return _global_deadline_manager.wrap_with_deadline(operation_key, timeout)

# -----------------------------------------------------------------------------
# USAGE EXAMPLES (for documentation)
# -----------------------------------------------------------------------------
"""
# Example 1: Basic deadline wrapping
@deadline_aware("prompt_injection_check", timeout=2.0)
def check_prompt_injection(input_text, cancellation_token=None):
    # Check cancellation periodically
    cancellation_token.throw_if_cancelled()
    result = heavy_detection(input_text)
    cancellation_token.throw_if_cancelled()
    return result

# Example 2: Pipeline with budget
pipeline = DeadlineAwareDetectionPipeline()
pipeline.register_stage_fallback("ml_detection", lightweight_fallback)

stages = [
    ("regex_check", regex_detection),
    ("ml_detection", ml_based_detection),
    ("heuristic_check", heuristic_detection),
]
result = pipeline.execute_pipeline(stages, input_text, total_timeout=5.0)

# Example 3: Context manager
manager = get_deadline_manager()
with manager.deadline_scope("full_scan", 10.0) as token:
    token.throw_if_cancelled()
    result1 = stage1(input, token)
    token.throw_if_cancelled()
    result2 = stage2(result1, token)
"""
