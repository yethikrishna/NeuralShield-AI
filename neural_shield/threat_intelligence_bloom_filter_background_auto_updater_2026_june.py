"""
Threat Intelligence Bloom Filter Background Auto-Updater
Production-grade implementation with background thread auto-refresh

This module provides:
1. Background daemon thread for automatic bloom filter updates
2. Thread-safe signature addition with lock protection
3. Configurable refresh intervals and batch processing
4. Memory-efficient incremental updates
5. Health monitoring and metrics tracking
6. Graceful shutdown with cleanup
"""

import threading
import time
import hashlib
import math
import json
import logging
from typing import Set, List, Dict, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
import queue

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class BloomFilterMetrics:
    """Metrics for bloom filter performance monitoring"""
    total_signatures: int = 0
    false_positive_probability: float = 0.0
    update_count: int = 0
    last_update_time: Optional[datetime] = None
    background_thread_running: bool = False
    queue_size: int = 0
    errors_count: int = 0
    avg_update_duration_ms: float = 0.0


class BloomFilter:
    """
    Production-grade Bloom Filter implementation
    Memory-efficient probabilistic data structure for set membership
    """
    
    def __init__(self, expected_items: int = 100000, false_positive_rate: float = 0.001):
        """
        Initialize bloom filter with optimal parameters
        
        Args:
            expected_items: Number of expected items to store
            false_positive_rate: Desired false positive probability
        """
        self.expected_items = expected_items
        self.false_positive_rate = false_positive_rate
        
        # Calculate optimal size and hash count
        self.size = self._calculate_size(expected_items, false_positive_rate)
        self.hash_count = self._calculate_hash_count(self.size, expected_items)
        
        # Initialize bit array using bytearray for memory efficiency
        self.bit_array = bytearray((self.size + 7) // 8)
        self._lock = threading.RLock()
        
        logger.info(f"BloomFilter initialized: size={self.size} bits, hash_count={self.hash_count}")
    
    @staticmethod
    def _calculate_size(n: int, p: float) -> int:
        """Calculate optimal bit array size"""
        size = -(n * math.log(p)) / (math.log(2) ** 2)
        return max(1, int(size))
    
    @staticmethod
    def _calculate_hash_count(m: int, n: int) -> int:
        """Calculate optimal number of hash functions"""
        count = (m / n) * math.log(2)
        return max(1, int(count))
    
    def _get_hashes(self, item: str) -> List[int]:
        """Generate hash positions for an item using double hashing"""
        hashes = []
        item_bytes = item.encode('utf-8')
        
        hash1 = int(hashlib.sha256(item_bytes).hexdigest(), 16)
        hash2 = int(hashlib.blake2b(item_bytes).hexdigest(), 16)
        
        for i in range(self.hash_count):
            combined_hash = (hash1 + i * hash2) % self.size
            hashes.append(combined_hash)
        
        return hashes
    
    def add(self, item: str) -> None:
        """Add an item to the bloom filter (thread-safe)"""
        with self._lock:
            for bit_pos in self._get_hashes(item):
                byte_idx = bit_pos // 8
                bit_idx = bit_pos % 8
                self.bit_array[byte_idx] |= (1 << bit_idx)
    
    def add_batch(self, items: List[str]) -> int:
        """Add multiple items in batch (thread-safe)"""
        count = 0
        with self._lock:
            for item in items:
                for bit_pos in self._get_hashes(item):
                    byte_idx = bit_pos // 8
                    bit_idx = bit_pos % 8
                    self.bit_array[byte_idx] |= (1 << bit_idx)
                count += 1
        return count
    
    def contains(self, item: str) -> bool:
        """Check if item might be in set (thread-safe)"""
        with self._lock:
            for bit_pos in self._get_hashes(item):
                byte_idx = bit_pos // 8
                bit_idx = bit_pos % 8
                if not (self.bit_array[byte_idx] & (1 << bit_idx)):
                    return False
        return True
    
    def estimate_count(self) -> float:
        """Estimate number of items in the filter"""
        with self._lock:
            bits_set = sum(bin(byte).count('1') for byte in self.bit_array)
        
        if bits_set == 0:
            return 0.0
        
        # Estimate using formula: n = -(m/k) * ln(1 - X/m)
        X = bits_set
        m = self.size
        k = self.hash_count
        
        try:
            estimate = -(m / k) * math.log(1 - X / m)
            return max(0.0, estimate)
        except (ValueError, ZeroDivisionError):
            return 0.0
    
    def clear(self) -> None:
        """Clear all entries"""
        with self._lock:
            self.bit_array = bytearray((self.size + 7) // 8)
    
    def get_stats(self) -> Dict:
        """Get filter statistics"""
        with self._lock:
            bits_set = sum(bin(byte).count('1') for byte in self.bit_array)
        
        return {
            'size_bits': self.size,
            'size_bytes': len(self.bit_array),
            'hash_count': self.hash_count,
            'bits_set': bits_set,
            'fill_ratio': bits_set / self.size if self.size > 0 else 0,
            'estimated_count': self.estimate_count(),
            'target_fpr': self.false_positive_rate
        }


class BloomFilterBackgroundAutoUpdater:
    """
    Background auto-updater for threat intelligence bloom filters
    
    Features:
    - Daemon thread for automatic background updates
    - Thread-safe queue for signature ingestion
    - Configurable refresh intervals
    - Batch processing for efficiency
    - Health monitoring and metrics
    - Graceful shutdown support
    """
    
    def __init__(
        self,
        refresh_interval_seconds: int = 300,
        batch_size: int = 1000,
        expected_signatures: int = 100000,
        false_positive_rate: float = 0.001,
        persistence_path: Optional[str] = None
    ):
        """
        Initialize background auto-updater
        
        Args:
            refresh_interval_seconds: Interval between auto-refresh cycles
            batch_size: Maximum batch size for processing
            expected_signatures: Expected number of threat signatures
            false_positive_rate: Target false positive rate
            persistence_path: Path for state persistence
        """
        self.refresh_interval = refresh_interval_seconds
        self.batch_size = batch_size
        self.persistence_path = Path(persistence_path) if persistence_path else None
        
        # Initialize bloom filter
        self.bloom_filter = BloomFilter(
            expected_items=expected_signatures,
            false_positive_rate=false_positive_rate
        )
        
        # Thread-safe queue for new signatures
        self.signature_queue: queue.Queue[str] = queue.Queue()
        
        # Thread control
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._thread_lock = threading.Lock()
        
        # Metrics tracking
        self.metrics = BloomFilterMetrics()
        self._metrics_lock = threading.Lock()
        
        # Registered callbacks
        self._update_callbacks: List[Callable[[Dict], None]] = []
        
        logger.info("BloomFilterBackgroundAutoUpdater initialized")
    
    def add_signature(self, signature: str) -> None:
        """Add a single threat signature to the processing queue"""
        if signature and signature.strip():
            self.signature_queue.put(signature.strip())
            self._update_metrics(queue_size=self.signature_queue.qsize())
    
    def add_signatures_batch(self, signatures: List[str]) -> int:
        """Add multiple signatures to the processing queue"""
        count = 0
        for sig in signatures:
            if sig and sig.strip():
                self.signature_queue.put(sig.strip())
                count += 1
        self._update_metrics(queue_size=self.signature_queue.qsize())
        return count
    
    def check_threat(self, indicator: str) -> bool:
        """Check if an indicator matches known threat signatures"""
        if not indicator:
            return False
        return self.bloom_filter.contains(indicator.lower().strip())
    
    def start(self) -> bool:
        """Start the background update thread"""
        with self._thread_lock:
            if self._thread and self._thread.is_alive():
                logger.warning("Background thread already running")
                return False
            
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._background_worker,
                daemon=True,
                name="BloomFilterUpdater"
            )
            self._thread.start()
            self._update_metrics(background_thread_running=True)
            logger.info("Background auto-updater thread started")
            return True
    
    def stop(self, wait: bool = True, timeout: int = 10) -> bool:
        """Stop the background thread gracefully"""
        with self._thread_lock:
            if not self._thread or not self._thread.is_alive():
                self._update_metrics(background_thread_running=False)
                return True
            
            self._stop_event.set()
            
            if wait:
                self._thread.join(timeout=timeout)
            
            stopped = not self._thread.is_alive()
            self._update_metrics(background_thread_running=not stopped)
            
            if stopped:
                logger.info("Background auto-updater thread stopped gracefully")
            else:
                logger.warning("Background thread did not stop within timeout")
            
            return stopped
    
    def _background_worker(self) -> None:
        """Main background worker loop"""
        logger.info("Background worker starting main loop")
        
        while not self._stop_event.is_set():
            cycle_start = time.time()
            try:
                # Process queued signatures
                processed = self._process_queued_signatures()
                
                # Run periodic maintenance
                self._run_maintenance()
                
                # Update metrics
                duration_ms = (time.time() - cycle_start) * 1000
                self._update_metrics(
                    last_update_time=datetime.now(),
                    avg_update_duration_ms=duration_ms
                )
                
                if processed > 0:
                    logger.debug(f"Processed {processed} signatures in {duration_ms:.2f}ms")
                
            except Exception as e:
                logger.error(f"Error in background worker: {e}", exc_info=True)
                self._update_metrics(errors_count=self.metrics.errors_count + 1)
            
            # Wait for next cycle or early wakeup on stop
            self._stop_event.wait(self.refresh_interval)
        
        # Final cleanup
        self._process_queued_signatures()
        logger.info("Background worker exiting")
    
    def _process_queued_signatures(self) -> int:
        """Process queued signatures in batches"""
        processed = 0
        batch: List[str] = []
        
        while not self.signature_queue.empty() and len(batch) < self.batch_size:
            try:
                signature = self.signature_queue.get_nowait()
                batch.append(signature)
            except queue.Empty:
                break
        
        if batch:
            count = self.bloom_filter.add_batch(batch)
            processed = count
            
            with self._metrics_lock:
                self.metrics.update_count += count
                self.metrics.total_signatures = int(self.bloom_filter.estimate_count())
                self.metrics.queue_size = self.signature_queue.qsize()
            
            # Trigger callbacks
            stats = self.get_status()
            for callback in self._update_callbacks:
                try:
                    callback(stats)
                except Exception as e:
                    logger.error(f"Callback error: {e}")
        
        return processed
    
    def _run_maintenance(self) -> None:
        """Run periodic maintenance tasks"""
        # Calculate current false positive probability
        stats = self.bloom_filter.get_stats()
        fill_ratio = stats['fill_ratio']
        
        # FPR approximation: (1 - e^(-k*n/m))^k
        # Simplified monitoring based on fill ratio
        estimated_fpr = (fill_ratio) ** self.bloom_filter.hash_count
        
        with self._metrics_lock:
            self.metrics.false_positive_probability = estimated_fpr
        
        # Auto-save if persistence enabled
        if self.persistence_path:
            self._save_state()
    
    def _save_state(self) -> bool:
        """Save current state to disk"""
        if not self.persistence_path:
            return False
        
        try:
            state = {
                'metrics': {
                    'total_signatures': self.metrics.total_signatures,
                    'update_count': self.metrics.update_count,
                    'errors_count': self.metrics.errors_count,
                    'last_update_time': self.metrics.last_update_time.isoformat() 
                        if self.metrics.last_update_time else None
                },
                'bloom_filter_stats': self.bloom_filter.get_stats(),
                'saved_at': datetime.now().isoformat()
            }
            
            with open(self.persistence_path, 'w') as f:
                json.dump(state, f, indent=2)
            
            return True
        except Exception as e:
            logger.error(f"Failed to save state: {e}")
            return False
    
    def _update_metrics(self, **kwargs) -> None:
        """Update metrics thread-safely"""
        with self._metrics_lock:
            for key, value in kwargs.items():
                if hasattr(self.metrics, key):
                    setattr(self.metrics, key, value)
    
    def register_update_callback(self, callback: Callable[[Dict], None]) -> None:
        """Register callback for update notifications"""
        self._update_callbacks.append(callback)
    
    def get_status(self) -> Dict:
        """Get comprehensive status report"""
        with self._metrics_lock:
            metrics_dict = {
                'total_signatures': self.metrics.total_signatures,
                'false_positive_probability': self.metrics.false_positive_probability,
                'update_count': self.metrics.update_count,
                'last_update_time': self.metrics.last_update_time.isoformat() 
                    if self.metrics.last_update_time else None,
                'background_thread_running': self.metrics.background_thread_running,
                'queue_size': self.metrics.queue_size,
                'errors_count': self.metrics.errors_count,
                'avg_update_duration_ms': self.metrics.avg_update_duration_ms
            }
        
        return {
            'metrics': metrics_dict,
            'bloom_filter': self.bloom_filter.get_stats(),
            'is_running': self.is_running(),
            'timestamp': datetime.now().isoformat()
        }
    
    def is_running(self) -> bool:
        """Check if background thread is running"""
        with self._thread_lock:
            return self._thread is not None and self._thread.is_alive()
    
    def __enter__(self):
        """Context manager entry"""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop(wait=True)
