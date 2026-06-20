"""
Threat Intelligence IOC Context Enrichment Cache Optimizer
Production-grade implementation with LRU caching, TTL expiration,
and performance optimization for IOC (Indicator of Compromise) enrichment.

Features:
- LRU cache with configurable max size
- TTL-based automatic expiration
- Batch enrichment support
- Performance metrics tracking
- Cache hit/miss statistics
- Thread-safe operations
- Background cache cleanup
"""

import time
import threading
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
import json


class IOCType(Enum):
    """Types of Indicators of Compromise"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    CERTIFICATE = "certificate"
    REGISTRY_KEY = "registry_key"


class EnrichmentSource(Enum):
    """Enrichment data sources"""
    VIRUS_TOTAL = "virus_total"
    ABUSE_IPDB = "abuse_ipdb"
    SHODAN = "shodan"
    WHOIS = "whois"
    THREAT_FEED = "threat_feed"
    INTERNAL_CTI = "internal_cti"
    MITRE_ATTACK = "mitre_attack"


@dataclass
class CacheEntry:
    """Cache entry with enrichment data and metadata"""
    ioc_value: str
    ioc_type: IOCType
    enrichment_data: Dict[str, Any]
    sources: List[EnrichmentSource]
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    access_count: int = 0
    ttl_seconds: int = 3600  # 1 hour default

    def is_expired(self) -> bool:
        """Check if cache entry has expired"""
        return (time.time() - self.created_at) > self.ttl_seconds

    def touch(self) -> None:
        """Update access metadata"""
        self.last_accessed = time.time()
        self.access_count += 1


@dataclass
class PerformanceMetrics:
    """Performance tracking metrics"""
    total_requests: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    total_enrichment_time_ms: float = 0.0
    cache_lookups_ms: float = 0.0
    enrichment_lookups_ms: float = 0.0
    batch_operations: int = 0
    evictions: int = 0

    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate percentage"""
        if self.total_requests == 0:
            return 0.0
        return (self.cache_hits / self.total_requests) * 100

    @property
    def avg_enrichment_time_ms(self) -> float:
        """Calculate average enrichment time"""
        if self.cache_misses == 0:
            return 0.0
        return self.enrichment_lookups_ms / self.cache_misses

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary"""
        return {
            "total_requests": self.total_requests,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "hit_rate_percent": round(self.hit_rate, 2),
            "avg_enrichment_time_ms": round(self.avg_enrichment_time_ms, 2),
            "batch_operations": self.batch_operations,
            "evictions": self.evictions
        }


class ThreadSafeLRUCache:
    """Thread-safe LRU Cache implementation with TTL support"""

    def __init__(self, max_size: int = 10000, default_ttl: int = 3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()
        self.metrics = PerformanceMetrics()

    def _generate_key(self, ioc_value: str, ioc_type: IOCType) -> str:
        """Generate unique cache key"""
        key_data = f"{ioc_type.value}:{ioc_value.lower().strip()}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def get(self, ioc_value: str, ioc_type: IOCType) -> Optional[CacheEntry]:
        """Get entry from cache with thread safety"""
        start_time = time.time()
        key = self._generate_key(ioc_value, ioc_type)

        with self._lock:
            self.metrics.total_requests += 1

            if key not in self._cache:
                self.metrics.cache_misses += 1
                self.metrics.cache_lookups_ms += (time.time() - start_time) * 1000
                return None

            entry = self._cache[key]

            if entry.is_expired():
                del self._cache[key]
                self.metrics.cache_misses += 1
                self.metrics.cache_lookups_ms += (time.time() - start_time) * 1000
                return None

            entry.touch()
            self._cache.move_to_end(key)
            self.metrics.cache_hits += 1
            self.metrics.cache_lookups_ms += (time.time() - start_time) * 1000
            return entry

    def put(self, ioc_value: str, ioc_type: IOCType,
            enrichment_data: Dict[str, Any],
            sources: List[EnrichmentSource],
            ttl_seconds: Optional[int] = None) -> None:
        """Put entry into cache with thread safety"""
        key = self._generate_key(ioc_value, ioc_type)
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl

        with self._lock:
            if key in self._cache:
                del self._cache[key]
            elif len(self._cache) >= self.max_size:
                self._cache.popitem(last=False)
                self.metrics.evictions += 1

            self._cache[key] = CacheEntry(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                enrichment_data=enrichment_data,
                sources=sources,
                ttl_seconds=ttl
            )

    def batch_get(self, iocs: List[Tuple[str, IOCType]]) -> Dict[str, Optional[CacheEntry]]:
        """Batch get multiple IOCs from cache"""
        self.metrics.batch_operations += 1
        results = {}
        for ioc_value, ioc_type in iocs:
            key = f"{ioc_type.value}:{ioc_value}"
            results[key] = self.get(ioc_value, ioc_type)
        return results

    def cleanup_expired(self) -> int:
        """Remove all expired entries, return count removed"""
        with self._lock:
            expired_keys = [
                key for key, entry in self._cache.items()
                if entry.is_expired()
            ]
            for key in expired_keys:
                del self._cache[key]
            return len(expired_keys)

    def get_size(self) -> int:
        """Get current cache size"""
        with self._lock:
            return len(self._cache)

    def clear(self) -> None:
        """Clear all cache entries"""
        with self._lock:
            self._cache.clear()


class IOCContextEnrichmentCacheOptimizer:
    """
    Production-grade IOC Context Enrichment with caching optimization.
    Provides intelligent caching, batch processing, and performance metrics.
    """

    def __init__(self, cache_max_size: int = 10000,
                 cache_ttl: int = 3600,
                 enable_background_cleanup: bool = True):
        self.cache = ThreadSafeLRUCache(max_size=cache_max_size, default_ttl=cache_ttl)
        self._stop_cleanup = threading.Event()
        self._cleanup_thread: Optional[threading.Thread] = None

        if enable_background_cleanup:
            self._start_background_cleanup()

    def _start_background_cleanup(self) -> None:
        """Start background thread for periodic cache cleanup"""
        def cleanup_worker():
            while not self._stop_cleanup.is_set():
                self.cache.cleanup_expired()
                self._stop_cleanup.wait(60)  # Cleanup every minute

        self._cleanup_thread = threading.Thread(
            target=cleanup_worker,
            daemon=True,
            name="CacheCleanupThread"
        )
        self._cleanup_thread.start()

    def _simulate_enrichment_lookup(self, ioc_value: str,
                                    ioc_type: IOCType,
                                    sources: List[EnrichmentSource]) -> Dict[str, Any]:
        """
        Simulate enrichment lookup (in production this would call actual APIs).
        This demonstrates the enrichment logic pattern.
        """
        start_time = time.time()

        # Simulate network latency
        time.sleep(0.01)  # 10ms simulated API call

        enrichment = {
            "ioc_value": ioc_value,
            "ioc_type": ioc_type.value,
            "sources": [s.value for s in sources],
            "malicious_score": min(100, hash(ioc_value) % 100),
            "detections": hash(ioc_value) % 50,
            "first_seen": int(time.time()) - (hash(ioc_value) % 31536000),
            "last_seen": int(time.time()) - (hash(ioc_value) % 86400),
            "threat_actors": [f"ACTOR_{hash(ioc_value) % 10}"],
            "mitre_techniques": ["T1059", "T1027"][:(hash(ioc_value) % 2 + 1)],
            "geolocation": {
                "country": ["US", "CN", "RU", "DE", "JP"][hash(ioc_value) % 5],
                "asn": f"AS{hash(ioc_value) % 65000}"
            },
            "enriched_at": time.time()
        }

        elapsed = (time.time() - start_time) * 1000
        self.cache.metrics.enrichment_lookups_ms += elapsed
        self.cache.metrics.total_enrichment_time_ms += elapsed

        return enrichment

    def enrich_ioc(self, ioc_value: str, ioc_type: IOCType,
                   sources: Optional[List[EnrichmentSource]] = None,
                   force_refresh: bool = False) -> Tuple[Dict[str, Any], bool]:
        """
        Enrich a single IOC with caching optimization.

        Returns:
            Tuple of (enrichment_data, was_cached)
        """
        if sources is None:
            sources = [EnrichmentSource.VIRUS_TOTAL, EnrichmentSource.ABUSE_IPDB]

        # Check cache first (unless force refresh)
        if not force_refresh:
            cached = self.cache.get(ioc_value, ioc_type)
            if cached:
                return cached.enrichment_data, True

        # Cache miss - perform enrichment
        enrichment_data = self._simulate_enrichment_lookup(ioc_value, ioc_type, sources)

        # Store in cache
        self.cache.put(ioc_value, ioc_type, enrichment_data, sources)

        return enrichment_data, False

    def enrich_batch(self, iocs: List[Tuple[str, IOCType]],
                     sources: Optional[List[EnrichmentSource]] = None) -> Dict[str, Dict[str, Any]]:
        """
        Batch enrich multiple IOCs with cache optimization.
        """
        self.cache.metrics.batch_operations += 1
        results = {}
        to_enrich = []

        # First pass: check cache for all IOCs
        for ioc_value, ioc_type in iocs:
            key = f"{ioc_type.value}:{ioc_value}"
            cached = self.cache.get(ioc_value, ioc_type)
            if cached:
                results[key] = cached.enrichment_data
            else:
                to_enrich.append((ioc_value, ioc_type))

        # Second pass: enrich cache misses
        for ioc_value, ioc_type in to_enrich:
            key = f"{ioc_type.value}:{ioc_value}"
            enrichment_data, _ = self.enrich_ioc(ioc_value, ioc_type, sources)
            results[key] = enrichment_data

        return results

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics"""
        return {
            "cache": self.cache.metrics.to_dict(),
            "cache_size": self.cache.get_size(),
            "cache_max_size": self.cache.max_size,
            "cache_utilization_percent": round(
                (self.cache.get_size() / self.cache.max_size) * 100, 2
            )
        }

    def get_cache_statistics(self) -> Dict[str, Any]:
        """Get detailed cache statistics"""
        metrics = self.get_performance_metrics()
        return {
            "timestamp": time.time(),
            "performance": metrics,
            "recommendations": self._generate_recommendations(metrics)
        }

    def _generate_recommendations(self, metrics: Dict[str, Any]) -> List[str]:
        """Generate optimization recommendations based on metrics"""
        recommendations = []
        cache_metrics = metrics["cache"]

        if cache_metrics["hit_rate_percent"] < 70:
            recommendations.append(
                "Low cache hit rate detected. Consider increasing TTL or cache size."
            )

        if metrics["cache_utilization_percent"] > 90:
            recommendations.append(
                "Cache utilization high. Consider increasing max_cache_size."
            )

        if cache_metrics["avg_enrichment_time_ms"] > 100:
            recommendations.append(
                "High enrichment latency detected. Consider batch processing optimization."
            )

        if not recommendations:
            recommendations.append("Cache performance is within optimal parameters.")

        return recommendations

    def shutdown(self) -> None:
        """Shutdown cleanup thread and resources"""
        self._stop_cleanup.set()
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=5)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()
