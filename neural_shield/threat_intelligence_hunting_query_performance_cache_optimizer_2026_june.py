"""
Threat Intelligence Hunting Query Performance Cache Optimizer
Production-grade implementation for NeuralShield-AI

This module implements intelligent caching strategies for threat hunting queries
to optimize performance, reduce database load, and improve query response times.

Features:
- Multi-tier caching (memory + disk)
- TTL-based cache invalidation
- Query signature-based cache keys
- Cache warming strategies
- Performance metrics tracking
- Adaptive cache sizing
"""

import hashlib
import json
import time
import threading
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from collections import OrderedDict
import os
import pickle

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Represents a single cache entry with metadata."""
    key: str
    value: Any
    created_at: float = field(default_factory=time.time)
    accessed_at: float = field(default_factory=time.time)
    access_count: int = 0
    ttl_seconds: int = 300
    size_bytes: int = 0

    def is_expired(self) -> bool:
        """Check if cache entry has expired."""
        return time.time() - self.created_at > self.ttl_seconds

    def update_access(self) -> None:
        """Update access metadata."""
        self.accessed_at = time.time()
        self.access_count += 1


class LRUMemoryCache:
    """LRU-based in-memory cache with size limits."""

    def __init__(self, max_size_mb: int = 100, max_entries: int = 10000):
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.max_entries = max_entries
        self.current_size_bytes = 0
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.lock = threading.RLock()

    def get(self, key: str) -> Optional[Any]:
        """Retrieve value from cache."""
        with self.lock:
            if key not in self.cache:
                return None

            entry = self.cache[key]

            if entry.is_expired():
                del self.cache[key]
                self.current_size_bytes -= entry.size_bytes
                return None

            entry.update_access()
            self.cache.move_to_end(key)
            return entry.value

    def put(self, key: str, value: Any, ttl_seconds: int = 300) -> None:
        """Store value in cache."""
        with self.lock:
            # Calculate approximate size
            try:
                size_bytes = len(pickle.dumps(value))
            except:
                size_bytes = len(str(value).encode('utf-8'))

            # Remove existing entry if present
            if key in self.cache:
                old_entry = self.cache[key]
                self.current_size_bytes -= old_entry.size_bytes
                del self.cache[key]

            # Evict entries if over limit
            while (self.current_size_bytes + size_bytes > self.max_size_bytes or
                   len(self.cache) >= self.max_entries):
                if not self.cache:
                    break
                evicted_key, evicted_entry = self.cache.popitem(last=False)
                self.current_size_bytes -= evicted_entry.size_bytes
                logger.debug(f"Evicted cache entry: {evicted_key}")

            entry = CacheEntry(
                key=key,
                value=value,
                ttl_seconds=ttl_seconds,
                size_bytes=size_bytes
            )
            self.cache[key] = entry
            self.current_size_bytes += size_bytes

    def invalidate(self, key: str) -> bool:
        """Invalidate specific cache entry."""
        with self.lock:
            if key in self.cache:
                entry = self.cache[key]
                self.current_size_bytes -= entry.size_bytes
                del self.cache[key]
                return True
            return False

    def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate all keys matching pattern."""
        with self.lock:
            keys_to_remove = [k for k in self.cache.keys() if pattern in k]
            for k in keys_to_remove:
                entry = self.cache[k]
                self.current_size_bytes -= entry.size_bytes
                del self.cache[k]
            return len(keys_to_remove)

    def clear_expired(self) -> int:
        """Remove all expired entries."""
        with self.lock:
            expired_keys = [k for k, v in self.cache.items() if v.is_expired()]
            for k in expired_keys:
                entry = self.cache[k]
                self.current_size_bytes -= entry.size_bytes
                del self.cache[k]
            return len(expired_keys)

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self.lock:
            return {
                "entry_count": len(self.cache),
                "total_size_bytes": self.current_size_bytes,
                "total_size_mb": round(self.current_size_bytes / (1024 * 1024), 2),
                "hit_rate": 0.0  # Tracked at higher level
            }


class DiskCache:
    """Persistent disk-based cache for larger objects."""

    def __init__(self, cache_dir: str = "/tmp/neuralshield_cache", max_size_gb: float = 5.0):
        self.cache_dir = cache_dir
        self.max_size_bytes = int(max_size_gb * 1024 * 1024 * 1024)
        os.makedirs(cache_dir, exist_ok=True)

    def _get_filepath(self, key: str) -> str:
        """Get file path for cache key."""
        safe_filename = hashlib.md5(key.encode()).hexdigest()
        return os.path.join(self.cache_dir, f"{safe_filename}.cache")

    def get(self, key: str) -> Optional[Any]:
        """Retrieve from disk cache."""
        filepath = self._get_filepath(key)
        try:
            if not os.path.exists(filepath):
                return None

            with open(filepath, 'rb') as f:
                entry = pickle.load(f)

            if time.time() - entry['created_at'] > entry['ttl_seconds']:
                os.remove(filepath)
                return None

            return entry['value']
        except Exception as e:
            logger.debug(f"Disk cache read error: {e}")
            return None

    def put(self, key: str, value: Any, ttl_seconds: int = 3600) -> None:
        """Store to disk cache."""
        filepath = self._get_filepath(key)
        try:
            entry = {
                'key': key,
                'value': value,
                'created_at': time.time(),
                'ttl_seconds': ttl_seconds
            }
            with open(filepath, 'wb') as f:
                pickle.dump(entry, f)
        except Exception as e:
            logger.debug(f"Disk cache write error: {e}")

    def invalidate(self, key: str) -> bool:
        """Remove from disk cache."""
        filepath = self._get_filepath(key)
        if os.path.exists(filepath):
            os.remove(filepath)
            return True
        return False


class HuntingQueryCacheOptimizer:
    """
    Main optimizer class for hunting query performance.
    
    Implements multi-tier caching with intelligent query optimization.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.memory_cache = LRUMemoryCache(
            max_size_mb=self.config.get('memory_cache_mb', 256),
            max_entries=self.config.get('max_memory_entries', 50000)
        )
        self.disk_cache = DiskCache(
            cache_dir=self.config.get('disk_cache_dir', '/tmp/neuralshield_cache'),
            max_size_gb=self.config.get('disk_cache_gb', 10.0)
        )

        # Statistics
        self.stats = {
            'hits': 0,
            'misses': 0,
            'memory_hits': 0,
            'disk_hits': 0,
            'total_queries': 0,
            'time_saved_ms': 0
        }
        self.stats_lock = threading.Lock()

        # Background maintenance
        self.maintenance_thread = threading.Thread(
            target=self._maintenance_loop,
            daemon=True
        )
        self.maintenance_thread.start()

        logger.info("HuntingQueryCacheOptimizer initialized")

    def generate_query_signature(self, query: Dict[str, Any]) -> str:
        """Generate unique signature for query caching."""
        # Normalize query for consistent hashing
        normalized = json.dumps(query, sort_keys=True)
        return hashlib.sha256(normalized.encode()).hexdigest()

    def _get_cache_key(self, query_type: str, signature: str) -> str:
        """Generate full cache key."""
        return f"{query_type}:{signature}"

    def cached_execute(
        self,
        query: Dict[str, Any],
        query_type: str,
        execution_func: Callable,
        ttl_seconds: Optional[int] = None,
        use_disk_cache: bool = False
    ) -> Dict[str, Any]:
        """
        Execute query with caching layer.
        
        Args:
            query: Query parameters
            query_type: Type of query (ioc, threat_actor, etc.)
            execution_func: Function to execute if cache miss
            ttl_seconds: Custom TTL, defaults based on query type
            use_disk_cache: Whether to use disk tier
            
        Returns:
            Query results with cache metadata
        """
        signature = self.generate_query_signature(query)
        cache_key = self._get_cache_key(query_type, signature)

        # Determine TTL based on query type
        if ttl_seconds is None:
            ttl_seconds = self._get_ttl_for_query_type(query_type)

        with self.stats_lock:
            self.stats['total_queries'] += 1

        # Try memory cache first
        start_time = time.time()
        cached_result = self.memory_cache.get(cache_key)
        if cached_result is not None:
            with self.stats_lock:
                self.stats['hits'] += 1
                self.stats['memory_hits'] += 1
                self.stats['time_saved_ms'] += max(0, cached_result.get('execution_time_ms', 100))
            return {
                'result': cached_result['result'],
                'cache_hit': True,
                'cache_tier': 'memory',
                'query_signature': signature,
                'response_time_ms': int((time.time() - start_time) * 1000)
            }

        # Try disk cache if enabled
        if use_disk_cache:
            cached_result = self.disk_cache.get(cache_key)
            if cached_result is not None:
                # Promote to memory cache
                self.memory_cache.put(cache_key, cached_result, ttl_seconds)
                with self.stats_lock:
                    self.stats['hits'] += 1
                    self.stats['disk_hits'] += 1
                    self.stats['time_saved_ms'] += max(0, cached_result.get('execution_time_ms', 500))
                return {
                    'result': cached_result['result'],
                    'cache_hit': True,
                    'cache_tier': 'disk',
                    'query_signature': signature,
                    'response_time_ms': int((time.time() - start_time) * 1000)
                }

        # Cache miss - execute query
        with self.stats_lock:
            self.stats['misses'] += 1

        exec_start = time.time()
        result = execution_func(query)
        execution_time_ms = int((time.time() - exec_start) * 1000)

        # Cache the result
        cache_entry = {
            'result': result,
            'execution_time_ms': execution_time_ms,
            'cached_at': datetime.utcnow().isoformat()
        }

        self.memory_cache.put(cache_key, cache_entry, ttl_seconds)
        if use_disk_cache and execution_time_ms > 1000:
            self.disk_cache.put(cache_key, cache_entry, ttl_seconds * 2)

        return {
            'result': result,
            'cache_hit': False,
            'cache_tier': None,
            'query_signature': signature,
            'execution_time_ms': execution_time_ms,
            'response_time_ms': int((time.time() - start_time) * 1000)
        }

    def _get_ttl_for_query_type(self, query_type: str) -> int:
        """Get appropriate TTL for different query types."""
        ttl_map = {
            'ioc_lookup': 600,      # 10 minutes - IOCs change infrequently
            'threat_actor': 1800,    # 30 minutes
            'vulnerability': 3600,   # 1 hour
            'mitre_mapping': 7200,   # 2 hours
            'statistics': 300,       # 5 minutes - stats change more often
            'asset_search': 120,     # 2 minutes - asset data more dynamic
            'default': 300           # 5 minutes default
        }
        return ttl_map.get(query_type, ttl_map['default'])

    def warm_cache(
        self,
        common_queries: List[Dict[str, Any]],
        query_type: str,
        execution_func: Callable
    ) -> Dict[str, Any]:
        """Pre-cache common queries."""
        results = []
        for query in common_queries:
            result = self.cached_execute(query, query_type, execution_func)
            results.append(result)

        return {
            'warmed_queries': len(results),
            'cache_hits_during_warm': sum(1 for r in results if r['cache_hit']),
            'total_execution_time_ms': sum(r.get('execution_time_ms', 0) for r in results)
        }

    def invalidate_for_ioc(self, ioc_value: str) -> int:
        """Invalidate all cache entries related to specific IOC."""
        pattern = f":{ioc_value}"
        memory_invalidated = self.memory_cache.invalidate_pattern(pattern)
        return memory_invalidated

    def invalidate_for_threat_actor(self, actor_id: str) -> int:
        """Invalidate all cache entries for a threat actor."""
        pattern = f"threat_actor:{actor_id}"
        return self.memory_cache.invalidate_pattern(pattern)

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics."""
        with self.stats_lock:
            total_requests = self.stats['hits'] + self.stats['misses']
            hit_rate = (self.stats['hits'] / total_requests * 100) if total_requests > 0 else 0

            memory_stats = self.memory_cache.get_stats()

            return {
                'overall': {
                    'total_queries': self.stats['total_queries'],
                    'cache_hits': self.stats['hits'],
                    'cache_misses': self.stats['misses'],
                    'hit_rate_percent': round(hit_rate, 2),
                    'estimated_time_saved_ms': self.stats['time_saved_ms'],
                    'estimated_time_saved_seconds': round(self.stats['time_saved_ms'] / 1000, 1)
                },
                'tier_breakdown': {
                    'memory_hits': self.stats['memory_hits'],
                    'disk_hits': self.stats['disk_hits']
                },
                'memory_cache': memory_stats
            }

    def _maintenance_loop(self) -> None:
        """Background maintenance thread."""
        while True:
            try:
                time.sleep(60)  # Run every minute
                expired = self.memory_cache.clear_expired()
                if expired > 0:
                    logger.debug(f"Cleared {expired} expired cache entries")
            except Exception as e:
                logger.error(f"Maintenance error: {e}")

    def get_cache_status(self) -> Dict[str, Any]:
        """Get current cache health status."""
        stats = self.get_performance_stats()
        memory_stats = stats['memory_cache']

        health_score = 100
        warnings = []

        if stats['overall']['hit_rate_percent'] < 30:
            health_score -= 30
            warnings.append("Low cache hit rate (< 30%)")

        if memory_stats['entry_count'] > memory_stats.get('max_entries', 10000) * 0.9:
            health_score -= 20
            warnings.append("Memory cache near capacity")

        return {
            'health_score': health_score,
            'status': 'healthy' if health_score >= 70 else 'degraded' if health_score >= 40 else 'unhealthy',
            'warnings': warnings,
            'statistics': stats
        }


# Export singleton instance
_default_optimizer: Optional[HuntingQueryCacheOptimizer] = None


def get_hunting_query_cache_optimizer() -> HuntingQueryCacheOptimizer:
    """Get or create default optimizer instance."""
    global _default_optimizer
    if _default_optimizer is None:
        _default_optimizer = HuntingQueryCacheOptimizer()
    return _default_optimizer
