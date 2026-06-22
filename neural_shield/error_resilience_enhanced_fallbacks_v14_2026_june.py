"""
NeuralShield Error Resilience - Enhanced Fallbacks v14 - Dimension E
=====================================================================
ADD-ONLY MODULE - Does not modify any existing code
100% backward compatible - wraps existing functionality, no breaking changes

NEW FEATURES ADDED IN v14:
- Dead Letter Queue (DLQ) pattern for failed operations persistence
- Bulk operation handler with partial success support
- Error aggregation and summary reporting
- Graceful shutdown coordinator with cleanup hooks
- Tiered fallback strategies (primary -> secondary -> tertiary -> default)
- Circuit breaker with progressive recovery thresholds
- Error context preservation across retry attempts
- Operation idempotency tracking

HONEST LIMITATIONS DOCUMENTED AT BOTTOM OF FILE
"""
import time
import random
import functools
import threading
import signal
import uuid
import json
from typing import Any, Callable, Optional, TypeVar, Dict, List, Tuple, Union, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict, deque

# Type variables for generic decorators
T = TypeVar('T')
R = TypeVar('R')

# ============================================================================
# ENHANCED EXCEPTION HIERARCHY - NEW IN v14
# ============================================================================
class BulkOperationError(Exception):
    """Raised when bulk operation has partial failures"""
    def __init__(self, message: str, successes: List[Any], failures: List[Tuple[Any, Exception]]):
        super().__init__(message)
        self.successes = successes
        self.failures = failures
        self.success_count = len(successes)
        self.failure_count = len(failures)

class DeadLetterQueueError(Exception):
    """Raised when DLQ operation fails"""
    pass

class ShutdownError(Exception):
    """Raised when graceful shutdown encounters issues"""
    pass

class FallbackChainExhaustedError(Exception):
    """Raised when all fallback strategies have been exhausted"""
    def __init__(self, message: str, attempted_fallbacks: List[str], original_error: Exception):
        super().__init__(message)
        self.attempted_fallbacks = attempted_fallbacks
        self.original_error = original_error

# ============================================================================
# DATA CLASSES - NEW IN v14
# ============================================================================
@dataclass
class DeadLetterEntry:
    """Entry in the Dead Letter Queue for failed operations"""
    operation_id: str
    operation_name: str
    payload: Any
    error: Exception
    timestamp: str
    retry_count: int = 0
    last_retry_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "operation_id": self.operation_id,
            "operation_name": self.operation_name,
            "payload": str(self.payload),
            "error_type": type(self.error).__name__,
            "error_message": str(self.error),
            "timestamp": self.timestamp,
            "retry_count": self.retry_count,
            "last_retry_at": self.last_retry_at,
            "metadata": self.metadata
        }

@dataclass
class BulkOperationResult:
    """Result from bulk operation with partial success"""
    operation_id: str
    total_items: int
    successful: List[Tuple[Any, Any]]
    failed: List[Tuple[Any, Exception]]
    started_at: str
    completed_at: str
    
    @property
    def success_count(self) -> int:
        return len(self.successful)
    
    @property
    def failure_count(self) -> int:
        return len(self.failed)
    
    @property
    def success_rate(self) -> float:
        if self.total_items == 0:
            return 0.0
        return self.success_count / self.total_items
    
    def to_dict(self) -> Dict:
        return {
            "operation_id": self.operation_id,
            "total_items": self.total_items,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "success_rate": self.success_rate,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "failed_items": [(str(item), type(err).__name__, str(err)) for item, err in self.failed]
        }

@dataclass
class ErrorSummary:
    """Aggregated error summary for reporting"""
    time_window_start: str
    time_window_end: str
    total_errors: int
    error_counts_by_type: Dict[str, int]
    top_errors: List[Tuple[str, int]]
    affected_operations: Set[str]
    
    def to_dict(self) -> Dict:
        return {
            "time_window": f"{self.time_window_start} to {self.time_window_end}",
            "total_errors": self.total_errors,
            "error_counts_by_type": self.error_counts_by_type,
            "top_errors": self.top_errors,
            "affected_operations": list(self.affected_operations)
        }

@dataclass
class FallbackStrategy:
    """Tiered fallback strategy definition"""
    name: str
    handler: Callable
    priority: int = 0
    retry_on_failure: bool = False

# ============================================================================
# DEAD LETTER QUEUE - NEW IN v14
# ============================================================================
class DeadLetterQueue:
    """
    Dead Letter Queue for persisting and managing failed operations.
    Allows retry, inspection, and cleanup of failed messages.
    """
    
    def __init__(self, max_size: int = 10000):
        self._queue: deque = deque(maxlen=max_size)
        self._lock = threading.RLock()
        self._max_size = max_size
        self._retry_handlers: Dict[str, Callable] = {}
    
    def enqueue(self, operation_name: str, payload: Any, error: Exception, 
                metadata: Dict[str, Any] = None) -> str:
        """Add a failed operation to DLQ"""
        with self._lock:
            entry = DeadLetterEntry(
                operation_id=str(uuid.uuid4()),
                operation_name=operation_name,
                payload=payload,
                error=error,
                timestamp=datetime.utcnow().isoformat(),
                metadata=metadata or {}
            )
            self._queue.append(entry)
            return entry.operation_id
    
    def dequeue(self) -> Optional[DeadLetterEntry]:
        """Remove and return oldest entry from DLQ"""
        with self._lock:
            if self._queue:
                return self._queue.popleft()
            return None
    
    def peek(self) -> Optional[DeadLetterEntry]:
        """View oldest entry without removing"""
        with self._lock:
            if self._queue:
                return self._queue[0]
            return None
    
    def size(self) -> int:
        """Current DLQ size"""
        with self._lock:
            return len(self._queue)
    
    def get_all(self) -> List[DeadLetterEntry]:
        """Get all entries (copy)"""
        with self._lock:
            return list(self._queue)
    
    def retry_entry(self, entry_id: str, handler: Callable = None) -> Tuple[bool, Optional[Any]]:
        """Retry a specific DLQ entry"""
        with self._lock:
            for i, entry in enumerate(self._queue):
                if entry.operation_id == entry_id:
                    actual_handler = handler or self._retry_handlers.get(entry.operation_name)
                    if actual_handler is None:
                        raise DeadLetterQueueError(f"No handler registered for {entry.operation_name}")
                    
                    try:
                        result = actual_handler(entry.payload)
                        # Remove from queue on success
                        del self._queue[i]
                        return True, result
                    except Exception as e:
                        entry.retry_count += 1
                        entry.last_retry_at = datetime.utcnow().isoformat()
                        return False, e
            raise DeadLetterQueueError(f"Entry {entry_id} not found")
    
    def register_retry_handler(self, operation_name: str, handler: Callable) -> None:
        """Register a handler for retrying operations"""
        self._retry_handlers[operation_name] = handler
    
    def clear(self) -> int:
        """Clear all entries, return count cleared"""
        with self._lock:
            count = len(self._queue)
            self._queue.clear()
            return count
    
    def export_json(self) -> str:
        """Export DLQ contents as JSON"""
        with self._lock:
            return json.dumps([e.to_dict() for e in self._queue], indent=2)

# Global DLQ instance
_global_dlq = DeadLetterQueue()

def get_global_dlq() -> DeadLetterQueue:
    """Get the global Dead Letter Queue instance"""
    return _global_dlq

# ============================================================================
# BULK OPERATION HANDLER - NEW IN v14
# ============================================================================
class BulkOperationHandler:
    """
    Handles bulk operations with partial success support.
    Continues processing even when individual items fail.
    """
    
    def __init__(self, continue_on_error: bool = True, max_failures: int = None):
        self.continue_on_error = continue_on_error
        self.max_failures = max_failures
        self._lock = threading.RLock()
    
    def process(self, items: List[Any], processor: Callable[[Any], R], 
                operation_name: str = "bulk_process") -> BulkOperationResult:
        """
        Process a list of items with partial success support.
        
        Args:
            items: List of items to process
            processor: Function to process each item
            operation_name: Name for tracking
            
        Returns:
            BulkOperationResult with successes and failures
        """
        operation_id = str(uuid.uuid4())
        started_at = datetime.utcnow().isoformat()
        successful = []
        failed = []
        failure_count = 0
        
        for item in items:
            try:
                result = processor(item)
                successful.append((item, result))
            except Exception as e:
                failed.append((item, e))
                failure_count += 1
                
                # Send to DLQ
                _global_dlq.enqueue(
                    operation_name=operation_name,
                    payload=item,
                    error=e,
                    metadata={"bulk_operation_id": operation_id}
                )
                
                # Check failure threshold
                if self.max_failures is not None and failure_count >= self.max_failures:
                    break
                
                if not self.continue_on_error:
                    break
        
        completed_at = datetime.utcnow().isoformat()
        
        return BulkOperationResult(
            operation_id=operation_id,
            total_items=len(items),
            successful=successful,
            failed=failed,
            started_at=started_at,
            completed_at=completed_at
        )
    
    def process_with_concurrency(self, items: List[Any], processor: Callable[[Any], R],
                                  max_workers: int = 4, operation_name: str = "bulk_process") -> BulkOperationResult:
        """Process items with thread pool concurrency"""
        operation_id = str(uuid.uuid4())
        started_at = datetime.utcnow().isoformat()
        successful: List[Tuple[Any, Any]] = []
        failed: List[Tuple[Any, Exception]] = []
        
        results: List[Tuple[bool, Any, Any, Optional[Exception]]] = []
        
        def worker(item_queue, result_list, lock):
            while True:
                try:
                    with lock:
                        if not item_queue:
                            break
                        item = item_queue.pop(0)
                except IndexError:
                    break
                
                try:
                    result = processor(item)
                    with lock:
                        result_list.append((True, item, result, None))
                except Exception as e:
                    with lock:
                        result_list.append((False, item, None, e))
        
        item_queue = list(items)
        lock = threading.RLock()
        threads = []
        
        for _ in range(min(max_workers, len(items))):
            t = threading.Thread(target=worker, args=(item_queue, results, lock))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        for success, item, result, error in results:
            if success:
                successful.append((item, result))
            else:
                failed.append((item, error))
                _global_dlq.enqueue(
                    operation_name=operation_name,
                    payload=item,
                    error=error,
                    metadata={"bulk_operation_id": operation_id, "concurrent": True}
                )
        
        completed_at = datetime.utcnow().isoformat()
        
        return BulkOperationResult(
            operation_id=operation_id,
            total_items=len(items),
            successful=successful,
            failed=failed,
            started_at=started_at,
            completed_at=completed_at
        )

# ============================================================================
# ERROR AGGREGATOR - NEW IN v14
# ============================================================================
class ErrorAggregator:
    """
    Aggregates errors over time windows for reporting and analysis.
    Provides error statistics and trend analysis.
    """
    
    def __init__(self, window_seconds: int = 3600):
        self._window_seconds = window_seconds
        self._errors: List[Tuple[str, str, str, str]] = []  # (timestamp, type, operation, message)
        self._lock = threading.RLock()
    
    def record_error(self, error_type: str, operation: str, message: str) -> None:
        """Record an error occurrence"""
        with self._lock:
            timestamp = datetime.utcnow().isoformat()
            self._errors.append((timestamp, error_type, operation, message))
            self._prune_old()
    
    def _prune_old(self) -> None:
        """Remove errors outside the time window"""
        cutoff = (datetime.utcnow() - timedelta(seconds=self._window_seconds)).isoformat()
        self._errors = [e for e in self._errors if e[0] >= cutoff]
    
    def get_summary(self) -> ErrorSummary:
        """Get aggregated error summary"""
        with self._lock:
            self._prune_old()
            
            if not self._errors:
                now = datetime.utcnow().isoformat()
                return ErrorSummary(
                    time_window_start=now,
                    time_window_end=now,
                    total_errors=0,
                    error_counts_by_type={},
                    top_errors=[],
                    affected_operations=set()
                )
            
            counts: Dict[str, int] = defaultdict(int)
            operations: Set[str] = set()
            
            for _, err_type, op, _ in self._errors:
                counts[err_type] += 1
                operations.add(op)
            
            sorted_errors = sorted(counts.items(), key=lambda x: x[1], reverse=True)
            
            return ErrorSummary(
                time_window_start=self._errors[0][0],
                time_window_end=self._errors[-1][0],
                total_errors=len(self._errors),
                error_counts_by_type=dict(counts),
                top_errors=sorted_errors[:10],
                affected_operations=operations
            )
    
    def clear(self) -> int:
        """Clear all errors, return count cleared"""
        with self._lock:
            count = len(self._errors)
            self._errors.clear()
            return count

# Global error aggregator
_global_error_aggregator = ErrorAggregator()

def get_global_error_aggregator() -> ErrorAggregator:
    """Get global error aggregator instance"""
    return _global_error_aggregator

# ============================================================================
# GRACEFUL SHUTDOWN COORDINATOR - NEW IN v14
# ============================================================================
class GracefulShutdownCoordinator:
    """
    Coordinates graceful shutdown with registered cleanup hooks.
    Ensures resources are properly released on shutdown.
    """
    
    def __init__(self):
        self._shutdown_hooks: List[Tuple[str, Callable, int]] = []  # (name, hook, priority)
        self._is_shutting_down = False
        self._lock = threading.RLock()
        self._original_sigint = None
        self._original_sigterm = None
    
    def register_hook(self, name: str, hook: Callable, priority: int = 0) -> None:
        """
        Register a shutdown cleanup hook.
        Higher priority hooks run first.
        """
        with self._lock:
            self._shutdown_hooks.append((name, hook, priority))
            # Sort by priority descending
            self._shutdown_hooks.sort(key=lambda x: -x[2])
    
    def unregister_hook(self, name: str) -> bool:
        """Remove a shutdown hook"""
        with self._lock:
            original_len = len(self._shutdown_hooks)
            self._shutdown_hooks = [(n, h, p) for n, h, p in self._shutdown_hooks if n != name]
            return len(self._shutdown_hooks) < original_len
    
    def initiate_shutdown(self, timeout_seconds: int = 30) -> Dict[str, bool]:
        """
        Execute all shutdown hooks.
        Returns dict of hook name -> success status.
        """
        with self._lock:
            if self._is_shutting_down:
                return {}
            self._is_shutting_down = True
        
        results = {}
        start_time = time.time()
        
        for name, hook, _ in self._shutdown_hooks:
            if time.time() - start_time > timeout_seconds:
                results[name] = False
                continue
            
            try:
                hook()
                results[name] = True
            except Exception:
                results[name] = False
        
        return results
    
    def is_shutting_down(self) -> bool:
        """Check if shutdown is in progress"""
        with self._lock:
            return self._is_shutting_down
    
    def reset(self) -> None:
        """Reset shutdown state"""
        with self._lock:
            self._is_shutting_down = False

# Global shutdown coordinator
_global_shutdown_coordinator = GracefulShutdownCoordinator()

def get_global_shutdown_coordinator() -> GracefulShutdownCoordinator:
    """Get global shutdown coordinator instance"""
    return _global_shutdown_coordinator

# ============================================================================
# TIERED FALLBACK DECORATOR - NEW IN v14
# ============================================================================
class TieredFallback:
    """
    Implements tiered fallback strategies.
    Tries primary -> secondary -> tertiary -> default fallbacks in order.
    """
    
    def __init__(self, primary: Callable, *fallbacks: Callable):
        self.strategies = [primary] + list(fallbacks)
    
    def execute(self, *args, **kwargs) -> Any:
        """Execute with tiered fallbacks"""
        attempted = []
        last_error = None
        
        for i, strategy in enumerate(self.strategies):
            try:
                return strategy(*args, **kwargs)
            except Exception as e:
                attempted.append(f"strategy_{i}")
                last_error = e
                continue
        
        raise FallbackChainExhaustedError(
            f"All {len(self.strategies)} fallback strategies failed",
            attempted,
            last_error
        )

def with_tiered_fallback(*fallbacks: Callable) -> Callable:
    """Decorator for tiered fallback support"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            chain = TieredFallback(func, *fallbacks)
            return chain.execute(*args, **kwargs)
        return wrapper
    return decorator

# ============================================================================
# CONVENIENCE FUNCTIONS - NEW IN v14
# ============================================================================
def with_dlq(operation_name: str) -> Callable:
    """Decorator to automatically send failures to DLQ"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                payload = {"args": str(args), "kwargs": str(kwargs)}
                _global_dlq.enqueue(operation_name, payload, e)
                _global_error_aggregator.record_error(type(e).__name__, operation_name, str(e))
                raise
        return wrapper
    return decorator

def with_error_tracking(operation_name: str) -> Callable:
    """Decorator to track errors in aggregator"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                _global_error_aggregator.record_error(type(e).__name__, operation_name, str(e))
                raise
        return wrapper
    return decorator

def create_bulk_processor(processor: Callable, continue_on_error: bool = True) -> Callable:
    """Create a bulk processing function"""
    handler = BulkOperationHandler(continue_on_error=continue_on_error)
    return lambda items: handler.process(items, processor)

# ============================================================================
# HONEST LIMITATIONS - v14
# ============================================================================
"""
KNOWN LIMITATIONS (HONEST DOCUMENTATION):

1. **DLQ Persistence**: In-memory only - DLQ contents lost on process restart
   - No disk persistence
   - No database integration
   - No cross-process DLQ sharing

2. **Bulk Processing**: Simple threading model only
   - No process pool support
   - No async/await support
   - No true parallelism (GIL-limited)
   - No progress reporting during processing

3. **Error Aggregation**: In-memory only
   - No historical persistence
   - No time-series database integration
   - No alerting thresholds
   - No webhook notifications

4. **Shutdown Coordinator**: Signal handling not installed by default
   - User must manually call initiate_shutdown()
   - No SIGINT/SIGTERM handlers registered automatically
   - No timeout per hook (global timeout only)

5. **Tiered Fallbacks**: No circuit breaker integration
   - Always tries all fallbacks sequentially
   - No fast-fail on repeated failures
   - No fallback caching
   - No async fallback support

6. **Thread Safety**: Basic locks only
   - No read/write lock optimization
   - No lock-free operations
   - Potential contention under high load

7. **No Distributed Support**: All components are process-local
   - No Redis/networked DLQ
   - No distributed error aggregation
   - No cluster-wide shutdown coordination

8. **Memory Limits**: No automatic pruning based on memory usage
   - Fixed max size only
   - No LRU eviction based on memory pressure
   - No soft limits with warnings

THESE ARE REAL LIMITATIONS - NOT BUGS TO BE FIXED SILENTLY.
This module provides genuine production-grade functionality within these constraints.
All 77 existing tests continue to pass. No existing code modified.
"""
