"""
NeuralShield AI - Threat Intelligence Feed Aggregator with Semantic Search Cache Prefetcher v3
Production-grade implementation with adaptive caching, LRU eviction, and intelligent prefetching

Version 3 Enhancements:
- Adaptive TTL based on feed update frequency
- Background prefetching with priority queuing
- Semantic similarity-based cache warming
- Bloom filter for fast membership testing
- Memory pressure monitoring and auto-eviction
"""

import json
import time
import hashlib
import threading
import heapq
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Set
from collections import OrderedDict, defaultdict
from datetime import datetime, timedelta
import logging
import asyncio
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FeedType(Enum):
    """Types of threat intelligence feeds"""
    IOC = "ioc"
    VULNERABILITY = "vulnerability"
    MALWARE = "malware"
    PHISHING = "phishing"
    BOTNET = "botnet"
    THREAT_ACTOR = "threat_actor"


class CachePriority(Enum):
    """Cache priority levels for prefetching"""
    CRITICAL = 0  # Critical IOCs, CVEs
    HIGH = 1      # Active threats
    MEDIUM = 2    # Standard feeds
    LOW = 3       # Historical data


@dataclass(order=True)
class PrefetchTask:
    """Task for background prefetching with priority"""
    priority: int
    feed_id: str = field(compare=False)
    query: str = field(compare=False)
    timestamp: float = field(default_factory=time.time)


@dataclass
class CacheEntry:
    """Cache entry with metadata for TTL management"""
    key: str
    value: Any
    feed_type: FeedType
    created_at: float
    last_accessed: float
    access_count: int
    ttl_seconds: int
    size_bytes: int
    priority: CachePriority


class AdaptiveTTLCalculator:
    """Calculates adaptive TTL based on feed update patterns"""
    
    def __init__(self):
        self.feed_update_history: Dict[str, List[float]] = defaultdict(list)
        self.default_ttl = 300  # 5 minutes
        self.min_ttl = 60       # 1 minute minimum
        self.max_ttl = 3600     # 1 hour maximum
    
    def record_update(self, feed_id: str):
        """Record a feed update for TTL calculation"""
        now = time.time()
        self.feed_update_history[feed_id].append(now)
        # Keep only last 24 hours of history
        cutoff = now - 86400
        self.feed_update_history[feed_id] = [
            ts for ts in self.feed_update_history[feed_id] 
            if ts > cutoff
        ]
    
    def calculate_ttl(self, feed_id: str, base_priority: CachePriority) -> int:
        """Calculate adaptive TTL based on update frequency"""
        history = self.feed_update_history.get(feed_id, [])
        
        if len(history) < 2:
            return self.default_ttl
        
        # Calculate average update interval
        intervals = []
        for i in range(1, len(history)):
            intervals.append(history[i] - history[i-1])
        
        avg_interval = sum(intervals) / len(intervals)
        
        # TTL is 70% of average update interval
        calculated_ttl = int(avg_interval * 0.7)
        
        # Apply priority multiplier
        priority_multipliers = {
            CachePriority.CRITICAL: 0.5,
            CachePriority.HIGH: 0.7,
            CachePriority.MEDIUM: 1.0,
            CachePriority.LOW: 1.5
        }
        calculated_ttl = int(calculated_ttl * priority_multipliers[base_priority])
        
        # Clamp to valid range
        return max(self.min_ttl, min(self.max_ttl, calculated_ttl))


class SemanticBloomFilter:
    """Bloom filter for fast semantic membership testing"""
    
    def __init__(self, size_bits: int = 1000000, num_hashes: int = 5):
        self.size = size_bits
        self.num_hashes = num_hashes
        self.bit_array = bytearray(size_bits // 8 + 1)
    
    def _get_hashes(self, item: str) -> List[int]:
        """Generate multiple hash positions"""
        hashes = []
        for i in range(self.num_hashes):
            h = hashlib.sha256(f"{item}:{i}".encode()).hexdigest()
            hashes.append(int(h, 16) % self.size)
        return hashes
    
    def add(self, item: str):
        """Add item to bloom filter"""
        for pos in self._get_hashes(item):
            byte_idx = pos // 8
            bit_idx = pos % 8
            self.bit_array[byte_idx] |= (1 << bit_idx)
    
    def might_contain(self, item: str) -> bool:
        """Check if item might be in set (false positives possible)"""
        for pos in self._get_hashes(item):
            byte_idx = pos // 8
            bit_idx = pos % 8
            if not (self.bit_array[byte_idx] & (1 << bit_idx)):
                return False
        return True


class LRUMemoryCache:
    """LRU cache with memory pressure monitoring"""
    
    def __init__(self, max_size_mb: int = 512):
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.current_size = 0
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.lock = threading.RLock()
    
    def _estimate_size(self, value: Any) -> int:
        """Estimate size of cached value in bytes"""
        try:
            return len(json.dumps(value).encode('utf-8'))
        except:
            return 1024  # Default estimate
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        with self.lock:
            if key not in self.cache:
                return None
            
            entry = self.cache.pop(key)
            entry.last_accessed = time.time()
            entry.access_count += 1
            self.cache[key] = entry
            return entry.value
    
    def put(self, key: str, value: Any, feed_type: FeedType, 
            priority: CachePriority, ttl: int) -> bool:
        """Put value into cache with eviction if needed"""
        with self.lock:
            size_bytes = self._estimate_size(value)
            
            # Evict if needed
            while self.current_size + size_bytes > self.max_size_bytes and self.cache:
                self._evict_one()
            
            if key in self.cache:
                old_entry = self.cache.pop(key)
                self.current_size -= old_entry.size_bytes
            
            entry = CacheEntry(
                key=key,
                value=value,
                feed_type=feed_type,
                created_at=time.time(),
                last_accessed=time.time(),
                access_count=0,
                ttl_seconds=ttl,
                size_bytes=size_bytes,
                priority=priority
            )
            
            self.cache[key] = entry
            self.current_size += size_bytes
            return True
    
    def _evict_one(self):
        """Evict least recently used valid entry"""
        if not self.cache:
            return
        
        # First try to evict expired entries
        now = time.time()
        for key in list(self.cache.keys()):
            entry = self.cache[key]
            if now - entry.created_at > entry.ttl_seconds:
                self.current_size -= entry.size_bytes
                del self.cache[key]
                return
        
        # If no expired, evict LRU with lowest priority
        for key in list(self.cache.keys()):
            entry = self.cache[key]
            if entry.priority == CachePriority.LOW:
                self.current_size -= entry.size_bytes
                del self.cache[key]
                return
        
        # Finally evict pure LRU
        key, entry = self.cache.popitem(last=False)
        self.current_size -= entry.size_bytes
    
    def cleanup_expired(self):
        """Remove all expired entries"""
        with self.lock:
            now = time.time()
            expired = []
            for key, entry in self.cache.items():
                if now - entry.created_at > entry.ttl_seconds:
                    expired.append(key)
            
            for key in expired:
                entry = self.cache.pop(key)
                self.current_size -= entry.size_bytes
            
            return len(expired)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.lock:
            return {
                "total_entries": len(self.cache),
                "total_size_bytes": self.current_size,
                "max_size_bytes": self.max_size_bytes,
                "utilization_pct": (self.current_size / self.max_size_bytes) * 100
            }


class ThreatFeedAggregator:
    """Main threat intelligence feed aggregator with semantic caching"""
    
    def __init__(self, max_cache_mb: int = 512):
        self.cache = LRUMemoryCache(max_cache_mb)
        self.ttl_calculator = AdaptiveTTLCalculator()
        self.bloom_filter = SemanticBloomFilter()
        self.prefetch_queue: List[PrefetchTask] = []
        self.prefetch_lock = threading.Lock()
        self.feed_sources: Dict[str, Dict[str, Any]] = {}
        self.query_history: List[Tuple[str, float]] = []
        self.semantic_similarity_cache: Dict[str, List[str]] = {}
        self._start_background_workers()
    
    def register_feed(self, feed_id: str, feed_type: FeedType, 
                      priority: CachePriority, update_url: str):
        """Register a threat feed source"""
        self.feed_sources[feed_id] = {
            "type": feed_type,
            "priority": priority,
            "url": update_url,
            "last_updated": time.time()
        }
        logger.info(f"Registered feed: {feed_id} ({feed_type.value})")
    
    def _start_background_workers(self):
        """Start background worker threads"""
        # Prefetch worker
        def prefetch_worker():
            while True:
                try:
                    self._process_prefetch_queue()
                    time.sleep(1)
                except Exception as e:
                    logger.error(f"Prefetch worker error: {e}")
                    time.sleep(5)
        
        # Cache cleanup worker
        def cleanup_worker():
            while True:
                try:
                    expired = self.cache.cleanup_expired()
                    if expired > 0:
                        logger.debug(f"Cleaned {expired} expired cache entries")
                    time.sleep(60)
                except Exception as e:
                    logger.error(f"Cleanup worker error: {e}")
                    time.sleep(5)
        
        threading.Thread(target=prefetch_worker, daemon=True).start()
        threading.Thread(target=cleanup_worker, daemon=True).start()
    
    def _generate_cache_key(self, feed_id: str, query: str) -> str:
        """Generate unique cache key"""
        return hashlib.sha256(f"{feed_id}:{query}".encode()).hexdigest()
    
    def _process_prefetch_queue(self):
        """Process highest priority prefetch tasks"""
        with self.prefetch_lock:
            if not self.prefetch_queue:
                return
            
            task = heapq.heappop(self.prefetch_queue)
        
        # Simulate fetch and cache
        cache_key = self._generate_cache_key(task.feed_id, task.query)
        feed_info = self.feed_sources.get(task.feed_id, {})
        feed_type = feed_info.get("type", FeedType.IOC)
        priority = feed_info.get("priority", CachePriority.MEDIUM)
        
        # Prefetch simulated data
        prefetched_data = self._fetch_feed_data(task.feed_id, task.query)
        ttl = self.ttl_calculator.calculate_ttl(task.feed_id, priority)
        
        self.cache.put(cache_key, prefetched_data, feed_type, priority, ttl)
        logger.debug(f"Prefetched: {task.feed_id} - {task.query[:30]}...")
    
    def _fetch_feed_data(self, feed_id: str, query: str) -> Dict[str, Any]:
        """Simulate fetching feed data (production would call real APIs)"""
        # In production, this would call actual threat intel APIs
        return {
            "feed_id": feed_id,
            "query": query,
            "results": [
                {"ioc": f"192.168.1.{i}", "type": "ip", "confidence": 0.85 + i*0.01}
                for i in range(min(5, len(query)))
            ],
            "total_count": len(query),
            "fetched_at": datetime.utcnow().isoformat()
        }
    
    def _find_semantically_similar(self, query: str) -> List[str]:
        """Find semantically similar queries for cache warming"""
        # Simple semantic similarity based on n-gram overlap
        similar = []
        query_ngrams = set(query[i:i+3] for i in range(len(query)-2))
        
        for hist_query, _ in self.query_history[-100:]:
            hist_ngrams = set(hist_query[i:i+3] for i in range(len(hist_query)-2))
            overlap = len(query_ngrams & hist_ngrams) / len(query_ngrams | hist_ngrams)
            if overlap > 0.3:
                similar.append(hist_query)
        
        return similar[:5]
    
    def query(self, feed_id: str, query: str, enable_prefetch: bool = True) -> Dict[str, Any]:
        """Query threat feed with intelligent caching"""
        start_time = time.time()
        
        if feed_id not in self.feed_sources:
            return {"error": f"Unknown feed: {feed_id}", "success": False}
        
        cache_key = self._generate_cache_key(feed_id, query)
        
        # Check bloom filter first (fast path)
        if not self.bloom_filter.might_contain(cache_key):
            cached_result = None
        else:
            cached_result = self.cache.get(cache_key)
        
        if cached_result:
            latency = (time.time() - start_time) * 1000
            return {
                "success": True,
                "cache_hit": True,
                "data": cached_result,
                "latency_ms": round(latency, 2),
                "source": "cache"
            }
        
        # Cache miss - fetch fresh data
        result = self._fetch_feed_data(feed_id, query)
        
        # Update TTL calculator
        self.ttl_calculator.record_update(feed_id)
        
        # Cache the result
        feed_info = self.feed_sources[feed_id]
        ttl = self.ttl_calculator.calculate_ttl(feed_id, feed_info["priority"])
        self.cache.put(cache_key, result, feed_info["type"], feed_info["priority"], ttl)
        self.bloom_filter.add(cache_key)
        
        # Record query history
        self.query_history.append((query, time.time()))
        if len(self.query_history) > 1000:
            self.query_history = self.query_history[-1000:]
        
        # Prefetch similar queries
        similar_queries = []
        if enable_prefetch:
            similar_queries = self._find_semantically_similar(query)
            for sim_query in similar_queries:
                task = PrefetchTask(
                    priority=feed_info["priority"].value,
                    feed_id=feed_id,
                    query=sim_query
                )
                with self.prefetch_lock:
                    heapq.heappush(self.prefetch_queue, task)
        
        latency = (time.time() - start_time) * 1000
        
        return {
            "success": True,
            "cache_hit": False,
            "data": result,
            "latency_ms": round(latency, 2),
            "source": "fresh",
            "ttl_seconds": ttl,
            "prefetched_similar": len(similar_queries)
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        cache_stats = self.cache.get_stats()
        
        with self.prefetch_lock:
            prefetch_queue_size = len(self.prefetch_queue)
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "cache": cache_stats,
            "registered_feeds": len(self.feed_sources),
            "prefetch_queue_size": prefetch_queue_size,
            "query_history_count": len(self.query_history),
            "version": "3.0.0"
        }


# Export main class
__all__ = [
    "ThreatFeedAggregator", 
    "FeedType", 
    "CachePriority",
    "LRUMemoryCache",
    "AdaptiveTTLCalculator"
]
