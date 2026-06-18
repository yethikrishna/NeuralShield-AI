"""
NeuralShield-AI: Threat Intelligence Batch Processor
June 2026 - Production Grade Implementation
Real working feature: Batch processing engine for threat intelligence IOCs
(Indicators of Compromise) with parallel processing, progress tracking,
error handling, and statistics aggregation. Enables efficient bulk scanning
of IPs, domains, URLs, and file hashes against threat intelligence feeds.
"""
import time
import threading
import queue
from dataclasses import dataclass, field
from typing import (
    Dict, List, Optional, Any, Callable,
    Generic, TypeVar, Tuple, Union
)
from enum import Enum
from collections import defaultdict
import uuid
import hashlib
T = TypeVar('T')
class BatchStatus(Enum):
    """Status of batch processing jobs"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"
    CANCELLED = "cancelled"
class IOCType(Enum):
    """Types of Indicators of Compromise"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
@dataclass
class BatchResult(Generic[T]):
    """Result for a single item in batch processing"""
    item_id: str
    input_value: str
    ioc_type: IOCType
    success: bool
    result: Optional[T] = None
    error: Optional[str] = None
    processing_time_ms: float = 0.0
    retry_count: int = 0
    timestamp: float = field(default_factory=time.time)
@dataclass
class BatchJob:
    """Batch processing job metadata"""
    job_id: str
    total_items: int
    status: BatchStatus = BatchStatus.PENDING
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    results: List[BatchResult] = field(default_factory=list)
    errors: List[Tuple[str, str]] = field(default_factory=list)
    def get_statistics(self) -> Dict[str, Any]:
        """Get processing statistics for this job"""
        successful = sum(1 for r in self.results if r.success)
        failed = sum(1 for r in self.results if not r.success)
        
        processing_times = [r.processing_time_ms for r in self.results if r.success]
        avg_time = sum(processing_times) / len(processing_times) if processing_times else 0
        
        return {
            "job_id": self.job_id,
            "status": self.status.value,
            "total_items": self.total_items,
            "completed_items": len(self.results),
            "successful": successful,
            "failed": failed,
            "success_rate_percent": round((successful / len(self.results) * 100), 2) if self.results else 0,
            "avg_processing_time_ms": round(avg_time, 2),
            "total_processing_time_ms": round(
                ((self.completed_at or time.time()) - (self.started_at or time.time())) * 1000,
                2
            ) if self.started_at else 0
        }
class ThreatIntelligenceBatchProcessor:
    """
    Production-grade batch processor for threat intelligence IOC scanning.
    
    Features:
    - Parallel processing with configurable worker pool
    - Progress tracking with callback support
    - Automatic retry on transient failures
    - Rate limiting to avoid API throttling
    - Real-time statistics and monitoring
    - Job cancellation support
    - Thread-safe operations
    """
    def __init__(
        self,
        max_workers: int = 4,
        max_retries: int = 2,
        rate_limit_per_second: float = 10.0,
        batch_size: int = 50,
        processor_function: Optional[Callable[[str, IOCType], Any]] = None
    ):
        """
        Initialize the batch processor.
        
        Args:
            max_workers: Number of parallel worker threads
            max_retries: Maximum retry attempts per item
            rate_limit_per_second: Maximum items processed per second
            batch_size: Default batch size for processing
            processor_function: Optional default processing function
        """
        self._max_workers = max_workers
        self._max_retries = max_retries
        self._rate_limit = rate_limit_per_second
        self._batch_size = batch_size
        self._default_processor = processor_function
        
        # Thread synchronization
        self._lock = threading.RLock()
        self._task_queue: queue.Queue = queue.Queue()
        self._jobs: Dict[str, BatchJob] = {}
        
        # Rate limiting
        self._last_process_time = 0.0
        self._min_interval = 1.0 / rate_limit_per_second if rate_limit_per_second > 0 else 0
        
        # Worker management
        self._workers: List[threading.Thread] = []
        self._stop_workers = threading.Event()
        self._active_jobs = 0
        
        # Statistics
        self._total_processed = 0
        self._total_jobs_completed = 0
    def _worker_loop(self):
        """Worker thread main loop"""
        while not self._stop_workers.is_set():
            try:
                task = self._task_queue.get(timeout=0.5)
                if task is None:
                    continue
                
                job_id, item_id, value, ioc_type, processor, callback = task
                self._process_single_item(job_id, item_id, value, ioc_type, processor, callback)
                self._task_queue.task_done()
            except queue.Empty:
                continue
            except Exception:
                continue
    def _apply_rate_limit(self):
        """Apply rate limiting between processing items"""
        if self._min_interval > 0:
            with self._lock:
                elapsed = time.time() - self._last_process_time
                if elapsed < self._min_interval:
                    time.sleep(self._min_interval - elapsed)
                self._last_process_time = time.time()
    def _process_single_item(
        self,
        job_id: str,
        item_id: str,
        value: str,
        ioc_type: IOCType,
        processor: Callable[[str, IOCType], Any],
        callback: Optional[Callable[[BatchResult], None]]
    ):
        """Process a single IOC item with retry logic"""
        start_time = time.time()
        retry_count = 0
        
        while retry_count <= self._max_retries:
            try:
                self._apply_rate_limit()
                
                result = processor(value, ioc_type)
                
                processing_time = (time.time() - start_time) * 1000
                batch_result = BatchResult(
                    item_id=item_id,
                    input_value=value,
                    ioc_type=ioc_type,
                    success=True,
                    result=result,
                    processing_time_ms=processing_time,
                    retry_count=retry_count
                )
                break
            except Exception as e:
                retry_count += 1
                if retry_count > self._max_retries:
                    processing_time = (time.time() - start_time) * 1000
                    batch_result = BatchResult(
                        item_id=item_id,
                        input_value=value,
                        ioc_type=ioc_type,
                        success=False,
                        error=str(e),
                        processing_time_ms=processing_time,
                        retry_count=retry_count - 1
                    )
                    break
                time.sleep(0.1 * retry_count)  # Exponential backoff
        
        # Store result
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id].results.append(batch_result)
                if not batch_result.success:
                    self._jobs[job_id].errors.append((item_id, batch_result.error or "Unknown error"))
        
        if callback:
            try:
                callback(batch_result)
            except Exception:
                pass
        
        with self._lock:
            self._total_processed += 1
    def create_job(
        self,
        items: List[Union[str, Tuple[str, IOCType]]],
        processor_function: Optional[Callable[[str, IOCType], Any]] = None,
        progress_callback: Optional[Callable[[BatchResult], None]] = None,
        completion_callback: Optional[Callable[[BatchJob], None]] = None
    ) -> str:
        """
        Create a new batch processing job.
        
        Args:
            items: List of IOCs to process (either strings or (value, type) tuples)
            processor_function: Processing function (uses default if None)
            progress_callback: Called after each item completes
            completion_callback: Called when entire job completes
            
        Returns:
            Job ID string
        """
        processor = processor_function or self._default_processor
        if processor is None:
            raise ValueError("No processor function provided and no default set")
        
        job_id = str(uuid.uuid4())[:12]
        
        # Normalize items
        normalized_items: List[Tuple[str, IOCType]] = []
        for item in items:
            if isinstance(item, tuple):
                value, ioc_type = item
            else:
                value = item
                ioc_type = self._detect_ioc_type(value)
            normalized_items.append((value, ioc_type))
        
        job = BatchJob(
            job_id=job_id,
            total_items=len(normalized_items)
        )
        
        with self._lock:
            self._jobs[job_id] = job
            self._active_jobs += 1
        
        # Start workers if not already running
        self._ensure_workers_running()
        
        # Queue all items
        for idx, (value, ioc_type) in enumerate(normalized_items):
            item_id = hashlib.md5(f"{job_id}:{idx}:{value}".encode()).hexdigest()[:16]
            self._task_queue.put((
                job_id, item_id, value, ioc_type, processor, progress_callback
            ))
        
        return job_id
    @staticmethod
    def _detect_ioc_type(value: str) -> IOCType:
        """Auto-detect IOC type from value format"""
        value = value.strip().lower()
        
        # Simple IP detection (IPv4)
        if all(part.isdigit() and 0 <= int(part) <= 255 for part in value.split('.')) and len(value.split('.')) == 4:
            return IOCType.IP_ADDRESS
        
        # Hash detection (MD5, SHA1, SHA256)
        if len(value) in (32, 40, 64) and all(c in '0123456789abcdef' for c in value):
            return IOCType.FILE_HASH
        
        # Email detection
        if '@' in value:
            return IOCType.EMAIL
        
        # URL detection
        if value.startswith(('http://', 'https://', 'www.')):
            return IOCType.URL
        
        # Default to domain
        return IOCType.DOMAIN
    def _ensure_workers_running(self):
        """Start worker threads if they're not running"""
        with self._lock:
            if not self._workers or not all(t.is_alive() for t in self._workers):
                self._stop_workers.clear()
                self._workers = []
                for _ in range(self._max_workers):
                    worker = threading.Thread(target=self._worker_loop, daemon=True)
                    worker.start()
                    self._workers.append(worker)
    def get_job_status(self, job_id: str) -> Optional[BatchJob]:
        """Get current status of a batch job"""
        with self._lock:
            job = self._jobs.get(job_id)
            if job and job.status == BatchStatus.PENDING and job.results:
                job.status = BatchStatus.RUNNING
                if job.started_at is None:
                    job.started_at = time.time()
            
            # Check if completed
            if job and len(job.results) >= job.total_items and job.status == BatchStatus.RUNNING:
                job.status = BatchStatus.COMPLETED if not job.errors else BatchStatus.PARTIAL
                job.completed_at = time.time()
                self._active_jobs -= 1
                self._total_jobs_completed += 1
            
            return job
    def wait_for_job(self, job_id: str, timeout: Optional[float] = None) -> BatchJob:
        """
        Wait for job completion.
        
        Args:
            job_id: Job ID to wait for
            timeout: Maximum seconds to wait
            
        Returns:
            Completed BatchJob
        """
        start = time.time()
        while True:
            job = self.get_job_status(job_id)
            if job is None:
                raise ValueError(f"Job {job_id} not found")
            
            if job.status in (BatchStatus.COMPLETED, BatchStatus.PARTIAL, BatchStatus.FAILED):
                return job
            
            if timeout and (time.time() - start) > timeout:
                raise TimeoutError(f"Job {job_id} timed out")
            
            time.sleep(0.1)
    def cancel_job(self, job_id: str) -> bool:
        """Cancel a running job"""
        with self._lock:
            job = self._jobs.get(job_id)
            if job and job.status in (BatchStatus.PENDING, BatchStatus.RUNNING):
                job.status = BatchStatus.CANCELLED
                job.completed_at = time.time()
                return True
            return False
    def get_global_statistics(self) -> Dict[str, Any]:
        """Get overall processor statistics"""
        with self._lock:
            return {
                "total_items_processed": self._total_processed,
                "total_jobs_completed": self._total_jobs_completed,
                "active_jobs": self._active_jobs,
                "worker_count": len([w for w in self._workers if w.is_alive()]),
                "queue_backlog": self._task_queue.qsize(),
                "max_workers": self._max_workers,
                "rate_limit_per_second": self._rate_limit
            }
    def shutdown(self, wait: bool = True) -> None:
        """
        Shutdown the processor and all worker threads.
        
        Args:
            wait: Whether to wait for in-progress items to complete
        """
        self._stop_workers.set()
        
        if wait:
            for worker in self._workers:
                worker.join(timeout=5)
        
        with self._lock:
            self._workers.clear()
    def process_batch_sync(
        self,
        items: List[Union[str, Tuple[str, IOCType]]],
        processor_function: Callable[[str, IOCType], Any],
        progress_callback: Optional[Callable[[BatchResult], None]] = None
    ) -> BatchJob:
        """
        Process batch synchronously (block until complete).
        
        Args:
            items: List of IOCs to process
            processor_function: Processing function
            progress_callback: Optional progress callback
            
        Returns:
            Completed BatchJob
        """
        job_id = self.create_job(items, processor_function, progress_callback)
        return self.wait_for_job(job_id)
    def __enter__(self):
        """Context manager entry"""
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - auto shutdown"""
        self.shutdown(wait=True)
        return False
