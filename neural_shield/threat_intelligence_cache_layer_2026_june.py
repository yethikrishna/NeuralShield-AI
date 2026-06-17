"""
Threat Intelligence Cache Layer - Production Grade
NeuralShield-AI Module
Provides high-performance, memory-efficient caching layer for threat intelligence lookups
with TTL expiration, LRU eviction, and bloom filter pre-filtering.

Features:
- TTL-based automatic expiration
- LRU eviction policy for cache capacity management
- Bloom filter pre-filtering to reduce negative lookups
- Thread-safe operations
- Statistics and monitoring
- Bulk loading support
- Cache warming capabilities
"""
import time
import threading
from typing import Dict, Optional, Any, List, Tuple, Set
from dataclasses import dataclass, field
from collections import OrderedDict
from enum import Enum
import hashlib
import json

class ThreatVerdict(Enum):
    """Threat assessment verdict"""
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"

@dataclass
class CacheEntry:
    """Single cache entry with metadata"""
    ioc: str
    verdict: ThreatVerdict
    confidence: float  # 0.0 - 1.0
    threat_type: str
    source: str
    ttl_seconds: int
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    access_count: int = 0
    
    def is_expired(self) -> bool:
        """Check if entry has expired"""
        return time.time() - self.created_at > self.ttl_seconds
    
    def touch(self) -> None:
        """Update access metadata"""
        self.last_accessed = time.time()
        self.access_count += 1

@dataclass
class CacheLayerConfig:
    """Configuration for Cache Layer"""
    max_size: int = 10000
    default_ttl_seconds: int = 3600  # 1 hour
    malicious_ttl_seconds: int = 86400  # 24 hours
    suspicious_ttl_seconds: int = 14400  # 4 hours
    benign_ttl_seconds: int = 7200  # 2 hours
    enable_bloom_precheck: bool = True
    bloom_expected_elements: int = 100000
    bloom_false_positive_rate: float = 0.001
    stats_interval_seconds: int = 60

@dataclass
class CacheStatistics:
    """Cache performance statistics"""
    total_hits: int = 0
    total_misses: int = 0
    total_expirations: int = 0
    total_evictions: int = 0
    bloom_precheck_hits: int = 0
    bloom_precheck_misses: int = 0
    current_size: int = 0
    hit_rate_percent: float = 0.0
    
    def calculate_hit_rate(self) -> float:
        """Calculate current hit rate"""
        total = self.total_hits + self.total_misses
        if total == 0:
            return 0.0
        return round((self.total_hits / total) * 100, 2)

class SimpleBloomFilter:
    """Simple embedded bloom filter for pre-checking"""
    def __init__(self, expected_elements: int, false_positive_rate: float):
        import math
        self.expected_elements = expected_elements
        self.false_positive_rate = false_positive_rate
        self.size_bits = int(-(expected_elements * math.log(false_positive_rate)) / (math.log(2) ** 2))
        self.num_hashes = int((self.size_bits / expected_elements) * math.log(2))
        self.num_hashes = max(2, min(self.num_hashes, 10))
        self.size_bits = max(64, self.size_bits)
        self._bit_array = bytearray((self.size_bits + 7) // 8)
    
    def _hash(self, value: str, seed: int) -> int:
        """Generate hash position"""
        h = hashlib.sha256(f"{value}{seed}".encode()).hexdigest()
        return int(h[:16], 16) % self.size_bits
    
    def add(self, value: str) -> None:
        """Add value to filter"""
        for seed in range(self.num_hashes):
            pos = self._hash(value, seed)
            byte_idx = pos // 8
            bit_idx = pos % 8
            self._bit_array[byte_idx] |= (1 << bit_idx)
    
    def might_contain(self, value: str) -> bool:
        """Check if value might be present"""
        for seed in range(self.num_hashes):
            pos = self._hash(value, seed)
            byte_idx = pos // 8
            bit_idx = pos % 8
            if (self._bit_array[byte_idx] & (1 << bit_idx)) == 0:
                return False
        return True

class ThreatIntelligenceCacheLayer:
    """
    Production-grade Threat Intelligence Cache Layer
    
    Provides:
    1. Fast in-memory caching with TTL
    2. LRU eviction when capacity reached
    3. Bloom filter pre-check to avoid cache misses on unknown IOCs
    4. Thread-safe concurrent access
    5. Comprehensive statistics
    """
    
    def __init__(self, config: Optional[CacheLayerConfig] = None):
        self.config = config or CacheLayerConfig()
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()
        self._stats = CacheStatistics()
        self._bloom_filter: Optional[SimpleBloomFilter] = None
        
        if self.config.enable_bloom_precheck:
            self._bloom_filter = SimpleBloomFilter(
                self.config.bloom_expected_elements,
                self.config.bloom_false_positive_rate
            )
        
        self._last_stats_update = time.time()
        self._known_sources: Set[str] = set()
        self._threat_types: Set[str] = set()
    
    def _get_ttl_for_verdict(self, verdict: ThreatVerdict) -> int:
        """Get appropriate TTL based on verdict"""
        if verdict == ThreatVerdict.MALICIOUS:
            return self.config.malicious_ttl_seconds
        elif verdict == ThreatVerdict.SUSPICIOUS:
            return self.config.suspicious_ttl_seconds
        elif verdict == ThreatVerdict.BENIGN:
            return self.config.benign_ttl_seconds
        return self.config.default_ttl_seconds
    
    def _evict_if_needed(self) -> None:
        """Evict LRU entries if cache exceeds max size"""
        while len(self._cache) > self.config.max_size:
            # Remove oldest entry (LRU via OrderedDict)
            oldest_key, _ = self._cache.popitem(last=False)
            self._stats.total_evictions += 1
    
    def _clean_expired(self) -> None:
        """Remove expired entries"""
        expired_keys = []
        for key, entry in self._cache.items():
            if entry.is_expired():
                expired_keys.append(key)
        
        for key in expired_keys:
            del self._cache[key]
            self._stats.total_expirations += 1
    
    def _bloom_precheck(self, ioc: str) -> bool:
        """Run bloom filter pre-check"""
        if not self._bloom_filter:
            return True
        
        result = self._bloom_filter.might_contain(ioc)
        if result:
            self._stats.bloom_precheck_hits += 1
        else:
            self._stats.bloom_precheck_misses += 1
        return result
    
    def lookup(self, ioc: str) -> Optional[CacheEntry]:
        """
        Look up an IOC in the cache
        
        Returns:
            CacheEntry if found and not expired, None otherwise
        """
        ioc_normalized = ioc.lower().strip()
        
        with self._lock:
            # Bloom pre-check: if definitely not in dataset, return fast
            if self.config.enable_bloom_precheck and not self._bloom_precheck(ioc_normalized):
                self._stats.total_misses += 1
                return None
            
            # Check actual cache
            if ioc_normalized not in self._cache:
                self._stats.total_misses += 1
                return None
            
            entry = self._cache[ioc_normalized]
            
            # Check expiration
            if entry.is_expired():
                del self._cache[ioc_normalized]
                self._stats.total_expirations += 1
                self._stats.total_misses += 1
                return None
            
            # Update access and move to end (LRU)
            entry.touch()
            del self._cache[ioc_normalized]
            self._cache[ioc_normalized] = entry
            
            self._stats.total_hits += 1
            self._stats.current_size = len(self._cache)
            self._stats.hit_rate_percent = self._stats.calculate_hit_rate()
            
            return entry
    
    def store(self, 
              ioc: str, 
              verdict: ThreatVerdict, 
              confidence: float,
              threat_type: str,
              source: str,
              ttl_seconds: Optional[int] = None) -> bool:
        """
        Store an IOC verdict in the cache
        
        Returns:
            True if stored successfully
        """
        if not ioc:
            return False
        
        ioc_normalized = ioc.lower().strip()
        confidence = max(0.0, min(1.0, confidence))
        
        actual_ttl = ttl_seconds if ttl_seconds else self._get_ttl_for_verdict(verdict)
        
        with self._lock:
            # Remove if exists to update position
            if ioc_normalized in self._cache:
                del self._cache[ioc_normalized]
            
            entry = CacheEntry(
                ioc=ioc_normalized,
                verdict=verdict,
                confidence=confidence,
                threat_type=threat_type,
                source=source,
                ttl_seconds=actual_ttl
            )
            
            self._cache[ioc_normalized] = entry
            
            # Add to bloom filter for pre-checking
            if self._bloom_filter and verdict in (ThreatVerdict.MALICIOUS, ThreatVerdict.SUSPICIOUS):
                self._bloom_filter.add(ioc_normalized)
            
            # Track metadata
            self._known_sources.add(source)
            self._threat_types.add(threat_type)
            
            # Run maintenance
            self._evict_if_needed()
            self._clean_expired()
            
            self._stats.current_size = len(self._cache)
            
            return True
    
    def store_bulk(self, entries: List[Tuple[str, ThreatVerdict, float, str, str]]) -> int:
        """
        Bulk store multiple entries
        
        Args:
            entries: List of (ioc, verdict, confidence, threat_type, source) tuples
            
        Returns:
            Number of entries successfully stored
        """
        count = 0
        for entry in entries:
            ioc, verdict, confidence, threat_type, source = entry
            if self.store(ioc, verdict, confidence, threat_type, source):
                count += 1
        return count
    
    def batch_lookup(self, iocs: List[str]) -> Dict[str, Optional[CacheEntry]]:
        """
        Look up multiple IOCs at once
        
        Returns:
            Dictionary mapping each IOC to its cache entry (or None)
        """
        results = {}
        for ioc in iocs:
            results[ioc] = self.lookup(ioc)
        return results
    
    def get_statistics(self) -> CacheStatistics:
        """Get current cache statistics"""
        with self._lock:
            self._stats.current_size = len(self._cache)
            self._stats.hit_rate_percent = self._stats.calculate_hit_rate()
            return CacheStatistics(
                total_hits=self._stats.total_hits,
                total_misses=self._stats.total_misses,
                total_expirations=self._stats.total_expirations,
                total_evictions=self._stats.total_evictions,
                bloom_precheck_hits=self._stats.bloom_precheck_hits,
                bloom_precheck_misses=self._stats.bloom_precheck_misses,
                current_size=len(self._cache),
                hit_rate_percent=self._stats.calculate_hit_rate()
            )
    
    def get_known_sources(self) -> List[str]:
        """Get list of known threat intel sources"""
        with self._lock:
            return sorted(list(self._known_sources))
    
    def get_threat_types(self) -> List[str]:
        """Get list of known threat types"""
        with self._lock:
            return sorted(list(self._threat_types))
    
    def clear(self) -> None:
        """Clear all cache entries"""
        with self._lock:
            self._cache.clear()
            if self._bloom_filter:
                self._bloom_filter = SimpleBloomFilter(
                    self.config.bloom_expected_elements,
                    self.config.bloom_false_positive_rate
                )
            self._stats = CacheStatistics()
            self._known_sources.clear()
            self._threat_types.clear()
    
    def warm_from_list(self, malicious_iocs: List[str], source: str = "cache_warmup") -> int:
        """
        Warm cache from a list of known malicious IOCs
        
        Returns:
            Number of IOCs loaded
        """
        entries = [
            (ioc, ThreatVerdict.MALICIOUS, 0.95, "known_malicious", source)
            for ioc in malicious_iocs
        ]
        return self.store_bulk(entries)
    
    def export_cache(self, include_expired: bool = False) -> List[Dict[str, Any]]:
        """Export cache contents for persistence"""
        with self._lock:
            export_data = []
            for entry in self._cache.values():
                if not include_expired and entry.is_expired():
                    continue
                export_data.append({
                    "ioc": entry.ioc,
                    "verdict": entry.verdict.value,
                    "confidence": entry.confidence,
                    "threat_type": entry.threat_type,
                    "source": entry.source,
                    "ttl_remaining": max(0, int(entry.ttl_seconds - (time.time() - entry.created_at))),
                    "access_count": entry.access_count
                })
            return export_data
    
    def get_size_info(self) -> Dict[str, Any]:
        """Get detailed size information"""
        stats = self.get_statistics()
        return {
            "current_entries": stats.current_size,
            "max_capacity": self.config.max_size,
            "capacity_percent": round((stats.current_size / self.config.max_size) * 100, 2),
            "hit_rate_percent": stats.hit_rate_percent,
            "total_lookups": stats.total_hits + stats.total_misses,
            "bloom_enabled": self.config.enable_bloom_precheck
        }
