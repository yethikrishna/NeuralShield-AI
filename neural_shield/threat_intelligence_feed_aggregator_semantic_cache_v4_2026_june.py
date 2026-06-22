"""
Threat Intelligence Feed Aggregator with Semantic Caching v4
NeuralShield-AI Feature Expansion (Dimension A)
June 22, 2026

100% ADD-ONLY IMPLEMENTATION - NO EXISTING CODE MODIFIED

This module provides:
- Multi-source threat feed aggregation
- Semantic IOC deduplication caching
- Batch processing optimization
- Feed health & quality monitoring
- Normalization & standardization
- TTL-based cache invalidation
"""

import hashlib
import time
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict
from datetime import datetime, timedelta


class FeedType(Enum):
    """Supported threat feed types."""
    ABUSE_IPDB = "abuse_ipdb"
    VIRUSTOTAL = "virustotal"
    THREATFOX = "threatfox"
    URLHAUS = "urlhaus"
    MALWAREBAZAAR = "malwarebazaar"
    EMERGINGTHREATS = "emergingthreats"
    SPAMHAUS = "spamhaus"
    SHODAN = "shodan"
    CUSTOM = "custom"


class IOCType(Enum):
    """Indicator of Compromise types."""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    JA3 = "ja3"
    JA3S = "ja3s"


class ThreatSeverity(Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class IOCEntry:
    """Single Indicator of Compromise entry."""
    value: str
    ioc_type: IOCType
    severity: ThreatSeverity
    source: FeedType
    first_seen: datetime
    last_seen: datetime
    confidence: float  # 0.0 - 1.0
    tags: List[str] = field(default_factory=list)
    description: str = ""
    ttl_hours: int = 72  # Default TTL
    
    def semantic_hash(self) -> str:
        """Generate semantic hash for deduplication."""
        normalized = self.value.strip().lower()
        hash_input = f"{normalized}:{self.ioc_type.value}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:32]
    
    def is_expired(self) -> bool:
        """Check if IOC has expired."""
        expiry = self.last_seen + timedelta(hours=self.ttl_hours)
        return datetime.utcnow() > expiry


@dataclass
class FeedStatus:
    """Feed health status."""
    feed_type: FeedType
    enabled: bool = True
    last_poll: Optional[datetime] = None
    success_count: int = 0
    failure_count: int = 0
    avg_response_ms: float = 0.0
    iocs_received: int = 0
    errors: List[str] = field(default_factory=list)
    
    @property
    def health_score(self) -> float:
        """Calculate feed health score 0.0-1.0."""
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.5  # Unknown
        return self.success_count / total
    
    @property
    def is_healthy(self) -> bool:
        """Check if feed is healthy."""
        return self.health_score >= 0.7 and self.enabled


class SemanticCache:
    """Semantic caching for IOC deduplication."""
    
    def __init__(self, max_size: int = 100000):
        self.max_size = max_size
        self._cache: Dict[str, Tuple[IOCEntry, float]] = {}  # hash -> (entry, timestamp)
        self._hits: int = 0
        self._misses: int = 0
    
    def get(self, semantic_hash: str) -> Optional[IOCEntry]:
        """Get from cache with hit tracking."""
        if semantic_hash in self._cache:
            entry, _ = self._cache[semantic_hash]
            if not entry.is_expired():
                self._hits += 1
                return entry
            else:
                del self._cache[semantic_hash]
        self._misses += 1
        return None
    
    def put(self, entry: IOCEntry) -> None:
        """Put entry in cache with LRU-style eviction."""
        semantic_hash = entry.semantic_hash()
        self._cache[semantic_hash] = (entry, time.time())
        
        # Evict if over size
        if len(self._cache) > self.max_size:
            sorted_items = sorted(self._cache.items(), key=lambda x: x[1][1])
            to_remove = len(self._cache) - self.max_size
            for key, _ in sorted_items[:to_remove]:
                del self._cache[key]
    
    def contains(self, semantic_hash: str) -> bool:
        """Check if hash exists (non-expired)."""
        return self.get(semantic_hash) is not None
    
    def cleanup_expired(self) -> int:
        """Remove expired entries, return count removed."""
        expired = [h for h, (e, _) in self._cache.items() if e.is_expired()]
        for h in expired:
            del self._cache[h]
        return len(expired)
    
    @property
    def hit_rate(self) -> float:
        """Cache hit rate."""
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0
    
    @property
    def size(self) -> int:
        return len(self._cache)
    
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "size": self.size,
            "max_size": self.max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": self.hit_rate,
            "hit_rate_pct": round(self.hit_rate * 100, 2)
        }


class FeedAggregator:
    """Threat intelligence feed aggregator."""
    
    def __init__(self, cache_size: int = 100000):
        self._cache = SemanticCache(max_size=cache_size)
        self._feed_status: Dict[FeedType, FeedStatus] = {
            ft: FeedStatus(feed_type=ft) for ft in FeedType
        }
        self._iocs_by_type: Dict[IOCType, Set[str]] = defaultdict(set)
        self._aggregated_count: int = 0
        self._deduplicated_count: int = 0
    
    def aggregate_iocs(self, iocs: List[IOCEntry]) -> Dict[str, Any]:
        """
        Aggregate and deduplicate IOCs.
        Returns aggregation statistics.
        """
        before_cache = self._cache.size
        new_iocs: List[IOCEntry] = []
        duplicates: int = 0
        
        for ioc in iocs:
            semantic_hash = ioc.semantic_hash()
            
            if self._cache.contains(semantic_hash):
                duplicates += 1
                # Update existing entry's last_seen
                existing = self._cache.get(semantic_hash)
                if existing and ioc.last_seen > existing.last_seen:
                    existing.last_seen = ioc.last_seen
                    existing.confidence = max(existing.confidence, ioc.confidence)
                    existing.tags = list(set(existing.tags + ioc.tags))
            else:
                self._cache.put(ioc)
                new_iocs.append(ioc)
                self._iocs_by_type[ioc.ioc_type].add(ioc.value)
        
        self._aggregated_count += len(iocs)
        self._deduplicated_count += len(new_iocs)
        
        # Cleanup expired
        expired = self._cache.cleanup_expired()
        
        return {
            "total_received": len(iocs),
            "new_unique": len(new_iocs),
            "duplicates_found": duplicates,
            "expired_cleaned": expired,
            "cache_before": before_cache,
            "cache_after": self._cache.size,
            "hit_rate_current": self._cache.hit_rate
        }
    
    def simulate_feed_poll(self, feed_type: FeedType, 
                          ioc_count: int = 100,
                          simulate_duplicates: bool = True) -> Dict[str, Any]:
        """
        Simulate polling a threat feed.
        Used for testing and benchmarking.
        """
        status = self._feed_status[feed_type]
        start_time = time.time()
        
        # Generate simulated IOCs
        simulated_iocs: List[IOCEntry] = []
        for i in range(ioc_count):
            # Some duplicates for testing
            if simulate_duplicates and i < ioc_count // 3:
                value = f"192.168.1.{i % 10}"
            else:
                value = f"10.0.{hash(f'{feed_type.value}{i}{time.time()}') % 255}.{i % 255}"
            
            ioc = IOCEntry(
                value=value,
                ioc_type=IOCType.IPV4,
                severity=ThreatSeverity(list(ThreatSeverity)[i % len(ThreatSeverity)]),
                source=feed_type,
                first_seen=datetime.utcnow() - timedelta(hours=i),
                last_seen=datetime.utcnow(),
                confidence=min(1.0, 0.3 + (i / ioc_count) * 0.7),
                tags=["test", "simulated", feed_type.value],
                description=f"Simulated IOC from {feed_type.value}"
            )
            simulated_iocs.append(ioc)
        
        # Aggregate
        result = self.aggregate_iocs(simulated_iocs)
        
        # Update status
        elapsed_ms = (time.time() - start_time) * 1000
        status.last_poll = datetime.utcnow()
        status.success_count += 1
        status.iocs_received += ioc_count
        status.avg_response_ms = (status.avg_response_ms * (status.success_count - 1) + elapsed_ms) / status.success_count
        
        result["feed_type"] = feed_type.value
        result["response_ms"] = round(elapsed_ms, 2)
        result["feed_health"] = status.health_score
        
        return result
    
    def get_ioc_by_value(self, value: str, ioc_type: IOCType) -> Optional[IOCEntry]:
        """Lookup IOC by value and type."""
        normalized = value.strip().lower()
        temp = IOCEntry(
            value=normalized,
            ioc_type=ioc_type,
            severity=ThreatSeverity.INFO,
            source=FeedType.CUSTOM,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            confidence=0.0
        )
        return self._cache.get(temp.semantic_hash())
    
    def batch_lookup(self, values: List[Tuple[str, IOCType]]) -> Dict[str, Optional[IOCEntry]]:
        """Batch lookup multiple IOCs."""
        results: Dict[str, Optional[IOCEntry]] = {}
        for value, ioc_type in values:
            results[value] = self.get_ioc_by_value(value, ioc_type)
        return results
    
    def get_feed_health_report(self) -> Dict[str, Any]:
        """Get comprehensive feed health report."""
        report = {
            "feeds": {},
            "overall_health": 0.0,
            "cache_stats": self._cache.stats(),
            "aggregation_totals": {
                "total_aggregated": self._aggregated_count,
                "unique_deduplicated": self._deduplicated_count,
                "deduplication_rate": round(
                    (1 - self._deduplicated_count / max(1, self._aggregated_count)) * 100, 2
                )
            }
        }
        
        healthy_count = 0
        for feed_type, status in self._feed_status.items():
            report["feeds"][feed_type.value] = {
                "enabled": status.enabled,
                "healthy": status.is_healthy,
                "health_score": round(status.health_score, 3),
                "success_count": status.success_count,
                "failure_count": status.failure_count,
                "avg_response_ms": round(status.avg_response_ms, 2),
                "iocs_received": status.iocs_received,
                "last_poll": status.last_poll.isoformat() if status.last_poll else None
            }
            if status.is_healthy:
                healthy_count += 1
        
        report["overall_health"] = round(healthy_count / len(self._feed_status), 3)
        return report
    
    def get_high_severity_iocs(self, min_confidence: float = 0.7) -> List[IOCEntry]:
        """Get all high/critical severity IOCs above confidence threshold."""
        high_severity = []
        for _, (entry, _) in self._cache._cache.items():
            if (entry.severity in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH) and
                entry.confidence >= min_confidence and
                not entry.is_expired()):
                high_severity.append(entry)
        return high_severity


# Global singleton instance
_global_aggregator: Optional[FeedAggregator] = None


def get_feed_aggregator() -> FeedAggregator:
    """Get global feed aggregator instance."""
    global _global_aggregator
    if _global_aggregator is None:
        _global_aggregator = FeedAggregator()
    return _global_aggregator


def create_ioc(value: str, ioc_type: IOCType, severity: ThreatSeverity,
              source: FeedType, confidence: float = 0.8) -> IOCEntry:
    """Helper to create IOC entry."""
    return IOCEntry(
        value=value,
        ioc_type=ioc_type,
        severity=severity,
        source=source,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        confidence=confidence
    )


def print_aggregation_report(results: Dict[str, Any]) -> None:
    """Print human-readable aggregation report."""
    print("=" * 60)
    print("THREAT INTELLIGENCE FEED AGGREGATION REPORT")
    print("=" * 60)
    print(f"Total IOCs Received:  {results.get('total_received', 0)}")
    print(f"New Unique IOCs:      {results.get('new_unique', 0)}")
    print(f"Duplicates Found:     {results.get('duplicates_found', 0)}")
    print(f"Expired Cleaned:      {results.get('expired_cleaned', 0)}")
    print(f"Cache Hit Rate:       {results.get('hit_rate_current', 0):.2%}")
    if 'response_ms' in results:
        print(f"Response Time:        {results['response_ms']}ms")
    if 'feed_health' in results:
        print(f"Feed Health Score:    {results['feed_health']:.3f}")
    print("=" * 60)
