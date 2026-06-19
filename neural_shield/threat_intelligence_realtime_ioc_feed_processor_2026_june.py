"""
Threat Intelligence Real-Time IOC Feed Processor
Production-grade real-time IOC (Indicators of Compromise) feed processor
with bloom filter deduplication, auto-batching, and persistence.

Author: NeuralShield-AI Team
Version: 2026.06.19
"""

import hashlib
import json
import time
import threading
import os
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Callable
from datetime import datetime, timedelta
from collections import deque
import math


@dataclass
class IOCEntry:
    """Represents a single Indicator of Compromise"""
    ioc_value: str
    ioc_type: str  # ip, domain, url, hash, email
    source: str
    confidence: float  # 0.0 - 1.0
    threat_type: str
    first_seen: datetime
    last_seen: datetime
    ttl_hours: int = 72
    metadata: Dict = field(default_factory=dict)
    
    def is_expired(self) -> bool:
        """Check if IOC has expired"""
        expiry = self.last_seen + timedelta(hours=self.ttl_hours)
        return datetime.now() > expiry
    
    def get_id(self) -> str:
        """Get unique ID for IOC"""
        return hashlib.sha256(f"{self.ioc_type}:{self.ioc_value}".lower().encode()).hexdigest()[:16]


class BloomFilter:
    """
    Production-grade Bloom Filter for fast IOC existence checking
    Probabilistic data structure with configurable false positive rate
    """
    
    def __init__(self, expected_elements: int = 100000, false_positive_rate: float = 0.001):
        self.expected_elements = expected_elements
        self.false_positive_rate = false_positive_rate
        
        # Calculate optimal size and hash count
        self.size = self._calculate_size(expected_elements, false_positive_rate)
        self.hash_count = self._calculate_hash_count(self.size, expected_elements)
        self.bit_array = [0] * self.size
        
        self.elements_added = 0
        
    def _calculate_size(self, n: int, p: float) -> int:
        """Calculate optimal bit array size"""
        m = -(n * math.log(p)) / (math.log(2) ** 2)
        return int(m) + 1
    
    def _calculate_hash_count(self, m: int, n: int) -> int:
        """Calculate optimal number of hash functions"""
        k = (m / n) * math.log(2)
        return max(1, int(k))
    
    def _get_hashes(self, item: str) -> List[int]:
        """Generate multiple hash positions for the item"""
        hashes = []
        item_bytes = item.lower().encode()
        
        for i in range(self.hash_count):
            hash_val = int(hashlib.sha256(item_bytes + str(i).encode()).hexdigest(), 16)
            hashes.append(hash_val % self.size)
        
        return hashes
    
    def add(self, item: str) -> None:
        """Add an item to the bloom filter"""
        for pos in self._get_hashes(item):
            self.bit_array[pos] = 1
        self.elements_added += 1
    
    def contains(self, item: str) -> bool:
        """
        Check if item might be in the filter
        Returns:
            True: item MIGHT be in set (with false positive probability)
            False: item DEFINITELY NOT in set (100% certain)
        """
        for pos in self._get_hashes(item):
            if self.bit_array[pos] == 0:
                return False
        return True
    
    def get_false_positive_probability(self) -> float:
        """Calculate current false positive probability"""
        return (1 - math.exp(-self.hash_count * self.elements_added / self.size)) ** self.hash_count
    
    def save(self, filepath: str) -> None:
        """Save bloom filter state to disk"""
        state = {
            'size': self.size,
            'hash_count': self.hash_count,
            'expected_elements': self.expected_elements,
            'false_positive_rate': self.false_positive_rate,
            'elements_added': self.elements_added,
            'bit_array': self.bit_array
        }
        with open(filepath, 'w') as f:
            json.dump(state, f)
    
    @classmethod
    def load(cls, filepath: str) -> 'BloomFilter':
        """Load bloom filter from disk"""
        with open(filepath, 'r') as f:
            state = json.load(f)
        
        bf = cls(state['expected_elements'], state['false_positive_rate'])
        bf.size = state['size']
        bf.hash_count = state['hash_count']
        bf.elements_added = state['elements_added']
        bf.bit_array = state['bit_array']
        return bf


class RealTimeIOCFeedProcessor:
    """
    Real-Time IOC Feed Processor
    Processes incoming IOCs with deduplication, batching, and persistence
    """
    
    def __init__(self, 
                 data_dir: str = "./ioc_data",
                 bloom_filter_capacity: int = 100000,
                 batch_size: int = 100,
                 flush_interval_seconds: int = 30):
        
        self.data_dir = data_dir
        self.batch_size = batch_size
        self.flush_interval_seconds = flush_interval_seconds
        
        # Create data directory
        os.makedirs(data_dir, exist_ok=True)
        
        # Bloom filter for fast deduplication
        self.bloom_filter = BloomFilter(bloom_filter_capacity, 0.001)
        
        # IOC storage
        self.active_iocs: Dict[str, IOCEntry] = {}  # id -> IOCEntry
        self.processing_queue: deque = deque()
        
        # Statistics
        self.stats = {
            'total_received': 0,
            'total_deduplicated': 0,
            'total_processed': 0,
            'total_expired': 0,
            'batches_processed': 0,
            'last_processed_time': None
        }
        
        # Callbacks
        self.on_new_ioc_callbacks: List[Callable[[IOCEntry], None]] = []
        self.on_batch_complete_callbacks: List[Callable[[List[IOCEntry]], None]] = []
        
        # Threading
        self._lock = threading.Lock()
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None
        
        # Try to load existing state
        self._load_state()
    
    def register_new_ioc_callback(self, callback: Callable[[IOCEntry], None]) -> None:
        """Register callback for new IOC detection"""
        self.on_new_ioc_callbacks.append(callback)
    
    def register_batch_complete_callback(self, callback: Callable[[List[IOCEntry]], None]) -> None:
        """Register callback for batch completion"""
        self.on_batch_complete_callbacks.append(callback)
    
    def submit_ioc(self, 
                   ioc_value: str, 
                   ioc_type: str, 
                   source: str,
                   confidence: float = 0.5,
                   threat_type: str = "unknown",
                   metadata: Optional[Dict] = None) -> Dict:
        """
        Submit an IOC for processing
        Returns processing result
        """
        ioc_key = f"{ioc_type}:{ioc_value}".lower()
        
        with self._lock:
            self.stats['total_received'] += 1
            
            # Fast path: check bloom filter first
            if self.bloom_filter.contains(ioc_key):
                # Might be duplicate, do full check
                ioc_id = hashlib.sha256(ioc_key.encode()).hexdigest()[:16]
                if ioc_id in self.active_iocs:
                    # Update existing IOC
                    existing = self.active_iocs[ioc_id]
                    existing.last_seen = datetime.now()
                    existing.confidence = max(existing.confidence, confidence)
                    self.stats['total_deduplicated'] += 1
                    return {
                        'status': 'duplicate',
                        'ioc_id': ioc_id,
                        'message': 'IOC already known, updated timestamps'
                    }
            
            # Create new IOC entry
            now = datetime.now()
            ioc_entry = IOCEntry(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                source=source,
                confidence=min(1.0, max(0.0, confidence)),
                threat_type=threat_type,
                first_seen=now,
                last_seen=now,
                metadata=metadata or {}
            )
            
            # Add to processing queue and storage
            self.processing_queue.append(ioc_entry)
            self.active_iocs[ioc_entry.get_id()] = ioc_entry
            self.bloom_filter.add(ioc_key)
            
            # Trigger callbacks for new IOC
            for callback in self.on_new_ioc_callbacks:
                try:
                    callback(ioc_entry)
                except Exception:
                    pass  # Don't fail on callback errors
            
            return {
                'status': 'queued',
                'ioc_id': ioc_entry.get_id(),
                'message': 'IOC queued for processing'
            }
    
    def submit_batch(self, iocs: List[Dict]) -> Dict:
        """Submit a batch of IOCs"""
        results = []
        for ioc_data in iocs:
            result = self.submit_ioc(**ioc_data)
            results.append(result)
        
        return {
            'total_submitted': len(iocs),
            'results': results
        }
    
    def process_batch(self) -> int:
        """Process queued IOCs in batches"""
        processed = 0
        batch = []
        
        with self._lock:
            while self.processing_queue and processed < self.batch_size:
                ioc = self.processing_queue.popleft()
                batch.append(ioc)
                processed += 1
                self.stats['total_processed'] += 1
            
            if batch:
                self.stats['batches_processed'] += 1
                self.stats['last_processed_time'] = datetime.now().isoformat()
                
                # Persist batch
                self._persist_batch(batch)
                
                # Trigger batch callbacks
                for callback in self.on_batch_complete_callbacks:
                    try:
                        callback(batch)
                    except Exception:
                        pass
        
        return processed
    
    def cleanup_expired(self) -> int:
        """Remove expired IOCs from active set"""
        expired_count = 0
        expired_ids = []
        
        with self._lock:
            for ioc_id, ioc in self.active_iocs.items():
                if ioc.is_expired():
                    expired_ids.append(ioc_id)
            
            for ioc_id in expired_ids:
                del self.active_iocs[ioc_id]
                expired_count += 1
            
            self.stats['total_expired'] += expired_count
        
        return expired_count
    
    def check_ioc(self, ioc_value: str, ioc_type: str) -> Dict:
        """Check if an IOC is known in the threat intelligence database"""
        ioc_key = f"{ioc_type}:{ioc_value}".lower()
        
        # Fast bloom filter check first
        if not self.bloom_filter.contains(ioc_key):
            return {
                'found': False,
                'confidence': 0.0,
                'message': 'IOC not found (100% certain)'
            }
        
        # Full lookup
        ioc_id = hashlib.sha256(ioc_key.encode()).hexdigest()[:16]
        
        with self._lock:
            if ioc_id in self.active_iocs:
                ioc = self.active_iocs[ioc_id]
                return {
                    'found': True,
                    'ioc_id': ioc_id,
                    'confidence': ioc.confidence,
                    'threat_type': ioc.threat_type,
                    'source': ioc.source,
                    'first_seen': ioc.first_seen.isoformat(),
                    'last_seen': ioc.last_seen.isoformat(),
                    'expired': ioc.is_expired(),
                    'message': 'IOC found in active database'
                }
        
        return {
            'found': False,
            'confidence': 0.0,
            'message': 'IOC not in active database (may be historical)'
        }
    
    def get_statistics(self) -> Dict:
        """Get processing statistics"""
        with self._lock:
            return {
                **self.stats,
                'active_iocs_count': len(self.active_iocs),
                'queue_size': len(self.processing_queue),
                'bloom_filter_elements': self.bloom_filter.elements_added,
                'bloom_filter_false_positive_rate': self.bloom_filter.get_false_positive_probability(),
                'bloom_filter_size_bits': self.bloom_filter.size
            }
    
    def get_high_risk_iocs(self, min_confidence: float = 0.8) -> List[Dict]:
        """Get all high-risk IOCs above confidence threshold"""
        results = []
        with self._lock:
            for ioc in self.active_iocs.values():
                if ioc.confidence >= min_confidence:
                    results.append({
                        'ioc_id': ioc.get_id(),
                        'value': ioc.ioc_value,
                        'type': ioc.ioc_type,
                        'confidence': ioc.confidence,
                        'threat_type': ioc.threat_type,
                        'source': ioc.source
                    })
        return results
    
    def _persist_batch(self, batch: List[IOCEntry]) -> None:
        """Persist batch to disk"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = f"{self.data_dir}/ioc_batch_{timestamp}.json"
        
        batch_data = [
            {
                'ioc_id': ioc.get_id(),
                'ioc_value': ioc.ioc_value,
                'ioc_type': ioc.ioc_type,
                'source': ioc.source,
                'confidence': ioc.confidence,
                'threat_type': ioc.threat_type,
                'first_seen': ioc.first_seen.isoformat(),
                'last_seen': ioc.last_seen.isoformat()
            }
            for ioc in batch
        ]
        
        with open(filename, 'w') as f:
            json.dump(batch_data, f, indent=2)
    
    def _load_state(self) -> None:
        """Load saved state from disk"""
        bloom_file = f"{self.data_dir}/bloom_filter_state.json"
        if os.path.exists(bloom_file):
            try:
                self.bloom_filter = BloomFilter.load(bloom_file)
            except Exception:
                pass  # Start fresh if loading fails
    
    def save_state(self) -> None:
        """Save current state to disk"""
        bloom_file = f"{self.data_dir}/bloom_filter_state.json"
        self.bloom_filter.save(bloom_file)
    
    def start_background_worker(self) -> None:
        """Start background processing thread"""
        self._running = True
        self._worker_thread = threading.Thread(target=self._background_worker, daemon=True)
        self._worker_thread.start()
    
    def stop_background_worker(self) -> None:
        """Stop background processing thread"""
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=5)
    
    def _background_worker(self) -> None:
        """Background worker thread for periodic processing"""
        while self._running:
            self.process_batch()
            self.cleanup_expired()
            self.save_state()
            time.sleep(self.flush_interval_seconds)
    
    def __enter__(self):
        self.start_background_worker()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop_background_worker()
        self.save_state()
