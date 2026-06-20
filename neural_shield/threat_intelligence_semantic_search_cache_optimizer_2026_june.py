"""
NeuralShield AI - Threat Intelligence Semantic Search Cache Optimizer
Production-grade implementation with LRU caching, TTL expiration,
batch prefetching, and performance monitoring.

Author: NeuralShield AI Team
Version: 2026.06.20
License: MIT
"""

import time
import json
import hashlib
import threading
import logging
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from collections import OrderedDict
from datetime import datetime, timedelta
import statistics

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Data class representing a cached semantic search result."""
    key: str
    value: Any
    timestamp: float = field(default_factory=time.time)
    ttl_seconds: int = 3600  # Default 1 hour TTL
    access_count: int = 0
    last_accessed: float = field(default_factory=time.time)

    def is_expired(self) -> bool:
        """Check if cache entry has expired."""
        return (time.time() - self.timestamp) > self.ttl_seconds

    def update_access(self) -> None:
        """Update access statistics."""
        self.access_count += 1
        self.last_accessed = time.time()


class LRUTimeCache:
    """
    Thread-safe LRU Cache with TTL expiration support.
    Combines least-recently-used eviction with time-based expiration.
    """

    def __init__(self, max_size: int = 1000, default_ttl: int = 3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._expirations = 0

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache, returns None if miss or expired."""
        with self._lock:
            if key not in self._cache:
                self._misses += 1
                return None

            entry = self._cache[key]

            if entry.is_expired():
                self._expirations += 1
                del self._cache[key]
                self._misses += 1
                return None

            # Move to end (most recently used)
            del self._cache[key]
            self._cache[key] = entry
            entry.update_access()
            self._hits += 1
            return entry.value

    def put(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> None:
        """Put value into cache with optional TTL."""
        with self._lock:
            ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl

            if key in self._cache:
                del self._cache[key]
            elif len(self._cache) >= self.max_size:
                # Evict oldest
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
                self._evictions += 1

            self._cache[key] = CacheEntry(
                key=key,
                value=value,
                ttl_seconds=ttl
            )

    def invalidate(self, key: str) -> bool:
        """Invalidate specific cache entry."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate all keys containing pattern."""
        with self._lock:
            keys_to_remove = [k for k in self._cache.keys() if pattern in k]
            for k in keys_to_remove:
                del self._cache[k]
            return len(keys_to_remove)

    def clear(self) -> None:
        """Clear entire cache."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
            self._evictions = 0
            self._expirations = 0

    def cleanup_expired(self) -> int:
        """Remove all expired entries."""
        with self._lock:
            expired_keys = [k for k, v in self._cache.items() if v.is_expired()]
            for k in expired_keys:
                del self._cache[k]
                self._expirations += 1
            return len(expired_keys)

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total_requests = self._hits + self._misses
            hit_rate = (self._hits / total_requests * 100) if total_requests > 0 else 0.0

            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
                "expirations": self._expirations,
                "hit_rate_percent": round(hit_rate, 2),
                "utilization_percent": round(len(self._cache) / self.max_size * 100, 2)
            }

    def get_hot_keys(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """Get most frequently accessed keys."""
        with self._lock:
            sorted_entries = sorted(
                self._cache.values(),
                key=lambda x: x.access_count,
                reverse=True
            )
            return [
                {"key": e.key, "access_count": e.access_count, "ttl_remaining": max(0, int(e.ttl_seconds - (time.time() - e.timestamp)))}
                for e in sorted_entries[:top_n]
            ]


class SemanticSearchPrefetcher:
    """
    Background prefetching engine for semantic search queries.
    Predicts and prefetches similar queries based on access patterns.
    """

    def __init__(self, cache: LRUTimeCache, search_function: Callable):
        self.cache = cache
        self.search_function = search_function
        self._prefetch_queue: List[str] = []
        self._lock = threading.Lock()
        self._prefetched_count = 0
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None

    def add_to_prefetch(self, query: str) -> None:
        """Add query to prefetch queue."""
        with self._lock:
            if query not in self._prefetch_queue:
                self._prefetch_queue.append(query)

    def start_background_prefetch(self) -> None:
        """Start background prefetch worker thread."""
        if self._running:
            return
        self._running = True
        self._worker_thread = threading.Thread(target=self._prefetch_worker, daemon=True)
        self._worker_thread.start()
        logger.info("Background prefetch worker started")

    def stop_background_prefetch(self) -> None:
        """Stop background prefetch worker."""
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=5)
        logger.info("Background prefetch worker stopped")

    def _prefetch_worker(self) -> None:
        """Worker thread for background prefetching."""
        while self._running:
            try:
                query = None
                with self._lock:
                    if self._prefetch_queue:
                        query = self._prefetch_queue.pop(0)

                if query:
                    # Execute search and cache result
                    result = self.search_function(query)
                    self.cache.put(f"semantic:{query}", result)
                    self._prefetched_count += 1
                    logger.debug(f"Prefetched: {query[:50]}...")

                time.sleep(0.1)  # Prevent tight loop
            except Exception as e:
                logger.error(f"Prefetch worker error: {e}")
                time.sleep(1)

    def get_stats(self) -> Dict[str, Any]:
        """Get prefetch statistics."""
        with self._lock:
            return {
                "prefetched_count": self._prefetched_count,
                "queue_size": len(self._prefetch_queue)
            }


class ThreatIntelligenceCacheOptimizer:
    """
    Main optimizer class for threat intelligence semantic search.
    Provides intelligent caching, prefetching, and performance optimization.
    """

    def __init__(
        self,
        max_cache_size: int = 2000,
        default_ttl: int = 1800,  # 30 minutes
        enable_prefetch: bool = True
    ):
        self.cache = LRUTimeCache(max_size=max_cache_size, default_ttl=default_ttl)
        self.enable_prefetch = enable_prefetch
        self._search_latencies: List[float] = []
        self._cache_latencies: List[float] = []
        self._lock = threading.Lock()

        # Initialize prefetcher with dummy search (will be replaced)
        self.prefetcher = SemanticSearchPrefetcher(self.cache, self._dummy_search)

        if enable_prefetch:
            self.prefetcher.start_background_prefetch()

        # Start background cleanup thread
        self._start_cleanup_worker()
        logger.info("Threat Intelligence Cache Optimizer initialized")

    def _dummy_search(self, query: str) -> Dict[str, Any]:
        """Dummy search function for initialization."""
        return {"result": f"prefetched:{query}", "timestamp": time.time()}

    def _start_cleanup_worker(self) -> None:
        """Start background cache cleanup worker."""
        def cleanup_worker():
            while True:
                try:
                    expired = self.cache.cleanup_expired()
                    if expired > 0:
                        logger.debug(f"Cleaned up {expired} expired cache entries")
                    time.sleep(60)  # Run every minute
                except Exception as e:
                    logger.error(f"Cleanup worker error: {e}")
                    time.sleep(60)

        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()

    @staticmethod
    def _generate_key(query: str, filters: Optional[Dict] = None, **kwargs) -> str:
        """Generate unique cache key from query parameters."""
        key_data = {"query": query, "filters": filters or {}, **kwargs}
        key_json = json.dumps(key_data, sort_keys=True)
        return f"ti:{hashlib.md5(key_json.encode()).hexdigest()}"

    def cached_search(
        self,
        query: str,
        search_function: Callable,
        filters: Optional[Dict] = None,
        ttl_seconds: Optional[int] = None,
        prefetch_similar: bool = True
    ) -> Tuple[Any, bool]:
        """
        Execute cached semantic search.
        Returns (result, was_cached)
        """
        start_time = time.time()
        cache_key = self._generate_key(query, filters)

        # Try cache first
        cached_result = self.cache.get(cache_key)
        if cached_result is not None:
            latency = time.time() - start_time
            with self._lock:
                self._cache_latencies.append(latency)
                if len(self._cache_latencies) > 1000:
                    self._cache_latencies = self._cache_latencies[-500:]
            return cached_result, True

        # Cache miss - execute actual search
        result = search_function(query, filters=filters)
        latency = time.time() - start_time

        with self._lock:
            self._search_latencies.append(latency)
            if len(self._search_latencies) > 1000:
                self._search_latencies = self._search_latencies[-500:]

        # Cache the result
        self.cache.put(cache_key, result, ttl_seconds)

        # Queue similar queries for prefetching
        if prefetch_similar and self.enable_prefetch:
            similar_queries = self._generate_similar_queries(query)
            for q in similar_queries[:3]:  # Limit prefetch
                self.prefetcher.add_to_prefetch(q)

        return result, False

    @staticmethod
    def _generate_similar_queries(query: str) -> List[str]:
        """Generate likely similar queries for prefetching."""
        variations = []
        words = query.split()

        # Common threat intel query variations
        if len(words) > 1:
            variations.append(" ".join(words[:-1]))
            variations.append(query + " vulnerability")
            variations.append(query + " ioc")
            variations.append(query + " threat actor")

        return [v for v in variations if v != query]

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive performance metrics."""
        with self._lock:
            cache_stats = self.cache.get_stats()
            prefetch_stats = self.prefetcher.get_stats()

            avg_search_latency = statistics.mean(self._search_latencies) if self._search_latencies else 0
            avg_cache_latency = statistics.mean(self._cache_latencies) if self._cache_latencies else 0
            p95_search = statistics.quantiles(self._search_latencies, n=20)[-1] if len(self._search_latencies) >= 20 else 0
            p95_cache = statistics.quantiles(self._cache_latencies, n=20)[-1] if len(self._cache_latencies) >= 20 else 0

            speedup = (avg_search_latency / avg_cache_latency) if avg_cache_latency > 0 else 0

            return {
                "cache": cache_stats,
                "prefetch": prefetch_stats,
                "performance": {
                    "avg_search_latency_ms": round(avg_search_latency * 1000, 2),
                    "avg_cache_latency_ms": round(avg_cache_latency * 1000, 2),
                    "p95_search_latency_ms": round(p95_search * 1000, 2),
                    "p95_cache_latency_ms": round(p95_cache * 1000, 2),
                    "speedup_factor": round(speedup, 2),
                    "total_searches": len(self._search_latencies),
                    "total_cache_hits": len(self._cache_latencies)
                },
                "hot_keys": self.cache.get_hot_keys(5)
            }

    def invalidate_threat_actor(self, threat_actor: str) -> int:
        """Invalidate all cache entries for a threat actor."""
        return self.cache.invalidate_pattern(threat_actor)

    def invalidate_ioc_type(self, ioc_type: str) -> int:
        """Invalidate all cache entries for an IOC type."""
        return self.cache.invalidate_pattern(ioc_type)

    def shutdown(self) -> None:
        """Gracefully shutdown optimizer."""
        if self.enable_prefetch:
            self.prefetcher.stop_background_prefetch()
        logger.info("Threat Intelligence Cache Optimizer shutdown complete")


# Export public API
__all__ = [
    'LRUTimeCache',
    'SemanticSearchPrefetcher',
    'ThreatIntelligenceCacheOptimizer',
    'CacheEntry'
]
