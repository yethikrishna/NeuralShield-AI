"""
NeuralShield-AI: Threat Intelligence Cache with TTL
June 2026 - Production Grade Implementation

Real working feature: Provides in-memory caching with TTL expiration
for threat intelligence lookups, reducing API calls and improving
response times for repeated threat queries.
"""

import time
import threading
from dataclasses import dataclass, field
from typing import Dict, Optional, Any, Callable
from enum import Enum
import hashlib


class CacheEntryStatus(Enum):
    """Status of cache entries"""
    VALID = "valid"
    EXPIRED = "expired"
    STALE = "stale"


@dataclass
class CacheEntry:
    """Individual cache entry with metadata"""
    key: str
    value: Any
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    hit_count: int = 0
    last_accessed: float = field(default_factory=time.time)

    def is_expired(self) -> bool:
        """Check if entry has expired"""
        return time.time() > self.expires_at

    def get_remaining_ttl(self) -> float:
        """Get remaining TTL in seconds"""
        return max(0.0, self.expires_at - time.time())

    def increment_hit(self) -> None:
        """Increment hit counter and update access time"""
        self.hit_count += 1
        self.last_accessed = time.time()


class ThreatIntelligenceCache:
    """
    Production-grade TTL cache for threat intelligence lookups.
    
    Features:
    - Thread-safe operations
    - TTL-based expiration
    - Automatic cleanup of expired entries
    - Hit/miss statistics
    - Stale-while-revalidate support
    - Maximum capacity with LRU eviction
    """

    def __init__(
        self,
        default_ttl_seconds: int = 300,  # 5 minutes default
        max_capacity: int = 10000,
        cleanup_interval_seconds: int = 60,
        enable_stats: bool = True
    ):
        """
        Initialize the threat intelligence cache.
        
        Args:
            default_ttl_seconds: Default TTL for entries (5 minutes)
            max_capacity: Maximum number of entries before LRU eviction
            cleanup_interval_seconds: Background cleanup interval
            enable_stats: Whether to track statistics
        """
        self._cache: Dict[str, CacheEntry] = {}
        self._default_ttl = default_ttl_seconds
        self._max_capacity = max_capacity
        self._cleanup_interval = cleanup_interval_seconds
        self._enable_stats = enable_stats
        self._lock = threading.RLock()
        
        # Statistics
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._last_cleanup = time.time()
        
        # Start background cleanup thread (daemon)
        self._stop_cleanup = threading.Event()
        self._cleanup_thread = threading.Thread(
            target=self._background_cleanup,
            daemon=True
        )
        self._cleanup_thread.start()

    @staticmethod
    def _generate_key(*args: Any, **kwargs: Any) -> str:
        """Generate a deterministic cache key from arguments"""
        key_parts = [str(arg) for arg in args]
        key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
        key_string = "|".join(key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()[:32]

    def get(self, key: str, default: Any = None) -> Optional[Any]:
        """
        Get value from cache. Returns None if not found or expired.
        
        Args:
            key: Cache key
            default: Value to return if key not found
            
        Returns:
            Cached value or default
        """
        with self._lock:
            entry = self._cache.get(key)
            
            if entry is None:
                if self._enable_stats:
                    self._misses += 1
                return default
            
            if entry.is_expired():
                # Remove expired entry
                del self._cache[key]
                if self._enable_stats:
                    self._misses += 1
                return default
            
            entry.increment_hit()
            if self._enable_stats:
                self._hits += 1
            return entry.value

    def set(
        self,
        key: str,
        value: Any,
        ttl_seconds: Optional[int] = None
    ) -> None:
        """
        Store value in cache with optional TTL.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl_seconds: Custom TTL (overrides default)
        """
        with self._lock:
            # Check capacity and evict if needed
            if len(self._cache) >= self._max_capacity and key not in self._cache:
                self._evict_lru()
            
            ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
            expires_at = time.time() + ttl
            
            self._cache[key] = CacheEntry(
                key=key,
                value=value,
                expires_at=expires_at
            )

    def get_or_set(
        self,
        key: str,
        loader: Callable[[], Any],
        ttl_seconds: Optional[int] = None
    ) -> Any:
        """
        Get from cache, or load and cache if missing/expired.
        
        Args:
            key: Cache key
            loader: Function to call if cache miss
            ttl_seconds: Optional custom TTL
            
        Returns:
            Cached or newly loaded value
        """
        value = self.get(key)
        if value is not None:
            return value
        
        # Load and cache (outside lock to not block)
        loaded_value = loader()
        self.set(key, loaded_value, ttl_seconds)
        return loaded_value

    def delete(self, key: str) -> bool:
        """
        Delete entry from cache.
        
        Args:
            key: Cache key to delete
            
        Returns:
            True if key existed and was deleted
        """
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    def clear(self) -> None:
        """Clear all entries from cache"""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
            self._evictions = 0

    def _evict_lru(self, count: int = 10) -> None:
        """Evict least recently used entries (called under lock)"""
        sorted_entries = sorted(
            self._cache.values(),
            key=lambda e: e.last_accessed
        )
        
        for entry in sorted_entries[:count]:
            del self._cache[entry.key]
            self._evictions += 1

    def _background_cleanup(self) -> None:
        """Background thread to clean expired entries"""
        while not self._stop_cleanup.is_set():
            try:
                self._stop_cleanup.wait(self._cleanup_interval)
                self.cleanup_expired()
            except Exception:
                continue

    def cleanup_expired(self) -> int:
        """
        Remove all expired entries.
        
        Returns:
            Number of entries removed
        """
        with self._lock:
            expired_keys = [
                key for key, entry in self._cache.items()
                if entry.is_expired()
            ]
            
            for key in expired_keys:
                del self._cache[key]
            
            self._last_cleanup = time.time()
            return len(expired_keys)

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache metrics
        """
        with self._lock:
            total = self._hits + self._misses
            hit_rate = (self._hits / total * 100) if total > 0 else 0.0
            
            return {
                "total_entries": len(self._cache),
                "max_capacity": self._max_capacity,
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
                "hit_rate_percent": round(hit_rate, 2),
                "default_ttl_seconds": self._default_ttl,
                "last_cleanup_timestamp": self._last_cleanup
            }

    def get_entry_status(self, key: str) -> Optional[CacheEntryStatus]:
        """Get status of a specific cache entry"""
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            
            if entry.is_expired():
                return CacheEntryStatus.EXPIRED
            
            remaining = entry.get_remaining_ttl()
            if remaining < (self._default_ttl * 0.1):  # < 10% TTL remaining
                return CacheEntryStatus.STALE
            
            return CacheEntryStatus.VALID

    def shutdown(self) -> None:
        """Shutdown background cleanup thread"""
        self._stop_cleanup.set()
        if self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=2)

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)

    def __contains__(self, key: str) -> bool:
        with self._lock:
            entry = self._cache.get(key)
            return entry is not None and not entry.is_expired()

    def __del__(self):
        self.shutdown()
