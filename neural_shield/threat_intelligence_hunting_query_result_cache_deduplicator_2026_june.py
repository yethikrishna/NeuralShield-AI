"""
Threat Intelligence Hunting Query Result Cache & Result Set Deduplicator - Production Grade
NeuralShield-AI Module
Provides intelligent caching of threat hunting query results with sophisticated
deduplication across result sets, preventing duplicate alerts and reducing
redundant processing of overlapping query results.

Features:
- Query result caching with content-based fingerprinting
- Cross-query result set deduplication
- Set theory operations for result comparison
- Incremental result delta detection
- Result similarity scoring
- Duplicate alert suppression
- Result aging and TTL management
- Thread-safe concurrent operations
- Comprehensive statistics and monitoring
- Bloom filter for fast membership testing
"""
import time
import threading
import hashlib
import json
from typing import Dict, Optional, Any, List, Tuple, Set, Callable, Iterable
from dataclasses import dataclass, field
from collections import OrderedDict
from enum import Enum
from functools import lru_cache


class ResultMatchType(Enum):
    """Type of result match found"""
    EXACT_DUPLICATE = "exact_duplicate"
    PARTIAL_OVERLAP = "partial_overlap"
    SUBSET = "subset"
    SUPERSET = "superset"
    NEW_ONLY = "new_only"
    NO_OVERLAP = "no_overlap"


@dataclass
class CachedQueryResult:
    """Single cached query result with metadata"""
    query_id: str
    query_text: str
    result_fingerprint: str
    result_items: Set[str]
    result_count: int
    execution_time: float
    ttl_seconds: int
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    access_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_expired(self) -> bool:
        """Check if result has expired"""
        return time.time() - self.created_at > self.ttl_seconds
    
    def touch(self) -> None:
        """Update access metadata"""
        self.last_accessed = time.time()
        self.access_count += 1
    
    def calculate_jaccard_similarity(self, other_items: Set[str]) -> float:
        """Calculate Jaccard similarity with another result set"""
        if not self.result_items or not other_items:
            return 0.0
        intersection = len(self.result_items & other_items)
        union = len(self.result_items | other_items)
        return intersection / union if union > 0 else 0.0


@dataclass
class DeduplicationResult:
    """Result of deduplication analysis"""
    match_type: ResultMatchType
    similarity_score: float  # 0.0 - 1.0
    duplicate_count: int
    new_item_count: int
    overlapping_items: Set[str]
    new_items: Set[str]
    matched_query_ids: List[str]
    should_suppress_alert: bool
    suppression_reason: str = ""


@dataclass
class ResultCacheConfig:
    """Configuration for Result Cache & Deduplicator"""
    max_cached_results: int = 5000
    default_ttl_seconds: int = 3600  # 1 hour
    max_result_items_per_cache: int = 10000
    enable_bloom_filter: bool = True
    bloom_expected_items: int = 100000
    bloom_false_positive_rate: float = 0.001
    deduplication_similarity_threshold: float = 0.8
    auto_suppress_duplicates: bool = True
    min_items_for_deduplication: int = 1
    enable_incremental_detection: bool = True
    stats_interval_seconds: int = 60
    max_fingerprint_cache_size: int = 10000


@dataclass
class CacheStatistics:
    """Cache performance statistics"""
    total_queries_cached: int = 0
    total_cache_hits: int = 0
    total_cache_misses: int = 0
    total_duplicates_detected: int = 0
    total_alerts_suppressed: int = 0
    total_items_deduplicated: int = 0
    average_similarity_score: float = 0.0
    current_cache_size: int = 0
    cache_hit_rate_percent: float = 0.0
    deduplication_rate_percent: float = 0.0
    
    def calculate_hit_rate(self) -> float:
        """Calculate cache hit rate"""
        total = self.total_cache_hits + self.total_cache_misses
        if total == 0:
            return 0.0
        return round((self.total_cache_hits / total) * 100, 2)


class ResultFingerprintGenerator:
    """Generates content-based fingerprints for result sets"""
    
    @staticmethod
    def generate_item_fingerprint(item: str) -> str:
        """Generate fingerprint for single result item"""
        return hashlib.sha256(item.encode('utf-8')).hexdigest()[:32]
    
    @staticmethod
    def generate_set_fingerprint(items: Iterable[str]) -> str:
        """Generate consistent fingerprint for a set of items"""
        sorted_items = sorted(items)
        content = "|".join(sorted_items)
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
    
    @staticmethod
    def generate_query_fingerprint(query_text: str) -> str:
        """Generate fingerprint for query text"""
        normalized = " ".join(query_text.lower().split())
        return hashlib.md5(normalized.encode('utf-8')).hexdigest()


class SimpleBloomFilter:
    """Simple bloom filter for fast membership testing"""
    
    def __init__(self, expected_elements: int, false_positive_rate: float):
        import math
        self.expected_elements = expected_elements
        self.false_positive_rate = false_positive_rate
        self.size_bits = int(-(expected_elements * math.log(false_positive_rate)) / (math.log(2) ** 2))
        self.num_hashes = int((self.size_bits / expected_elements) * math.log(2))
        self.num_hashes = max(2, min(self.num_hashes, 8))
        self.size_bits = max(64, self.size_bits)
        self._bit_array = bytearray((self.size_bits + 7) // 8)
    
    def _hash(self, value: str, seed: int) -> int:
        h = hashlib.sha256(f"{value}{seed}".encode()).hexdigest()
        return int(h[:16], 16) % self.size_bits
    
    def add(self, value: str) -> None:
        for seed in range(self.num_hashes):
            pos = self._hash(value, seed)
            self._bit_array[pos // 8] |= (1 << (pos % 8))
    
    def might_contain(self, value: str) -> bool:
        for seed in range(self.num_hashes):
            pos = self._hash(value, seed)
            if (self._bit_array[pos // 8] & (1 << (pos % 8))) == 0:
                return False
        return True
    
    def add_many(self, values: Iterable[str]) -> None:
        for v in values:
            self.add(v)


class ThreatIntelligenceHuntingQueryResultCacheDeduplicator:
    """
    Production-grade Hunting Query Result Cache & Deduplicator
    
    Provides:
    1. Caching of hunting query results to avoid reprocessing
    2. Cross-query deduplication to prevent duplicate alerts
    3. Set theory analysis for result overlap detection
    4. Intelligent alert suppression
    5. Incremental result processing
    """
    
    def __init__(self, config: Optional[ResultCacheConfig] = None):
        self.config = config or ResultCacheConfig()
        
        # Result cache
        self._result_cache: OrderedDict[str, CachedQueryResult] = OrderedDict()
        self._fingerprint_index: Dict[str, List[str]] = {}  # fingerprint -> query_ids
        
        # Global item tracking for deduplication
        self._all_seen_items: Set[str] = set()
        self._bloom_filter: Optional[SimpleBloomFilter] = None
        
        if self.config.enable_bloom_filter:
            self._bloom_filter = SimpleBloomFilter(
                self.config.bloom_expected_items,
                self.config.bloom_false_positive_rate
            )
        
        # Statistics and locking
        self._stats = CacheStatistics()
        self._lock = threading.RLock()
    
    def _evict_if_needed(self) -> None:
        """Evict LRU entries when cache exceeds max size"""
        while len(self._result_cache) > self.config.max_cached_results:
            oldest_key, oldest_result = self._result_cache.popitem(last=False)
            
            # Remove from fingerprint index
            fp = oldest_result.result_fingerprint
            if fp in self._fingerprint_index:
                if oldest_key in self._fingerprint_index[fp]:
                    self._fingerprint_index[fp].remove(oldest_key)
                if not self._fingerprint_index[fp]:
                    del self._fingerprint_index[fp]
    
    def _clean_expired(self) -> None:
        """Remove expired cache entries"""
        expired_keys = []
        for key, result in self._result_cache.items():
            if result.is_expired():
                expired_keys.append(key)
        
        for key in expired_keys:
            result = self._result_cache[key]
            del self._result_cache[key]
            
            fp = result.result_fingerprint
            if fp in self._fingerprint_index and key in self._fingerprint_index[fp]:
                self._fingerprint_index[fp].remove(key)
                if not self._fingerprint_index[fp]:
                    del self._fingerprint_index[fp]
    
    def cache_query_result(self,
                           query_id: str,
                           query_text: str,
                           result_items: List[str],
                           ttl_seconds: Optional[int] = None,
                           metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Cache a query result set
        
        Returns:
            Result fingerprint
        """
        result_set = set(result_items)
        fingerprint = ResultFingerprintGenerator.generate_set_fingerprint(result_set)
        actual_ttl = ttl_seconds or self.config.default_ttl_seconds
        
        with self._lock:
            # Create cached result
            cached = CachedQueryResult(
                query_id=query_id,
                query_text=query_text,
                result_fingerprint=fingerprint,
                result_items=result_set,
                result_count=len(result_set),
                execution_time=time.time(),
                ttl_seconds=actual_ttl,
                metadata=metadata or {}
            )
            
            # Remove existing if present (to update LRU position)
            if query_id in self._result_cache:
                old_result = self._result_cache[query_id]
                old_fp = old_result.result_fingerprint
                if old_fp in self._fingerprint_index and query_id in self._fingerprint_index[old_fp]:
                    self._fingerprint_index[old_fp].remove(query_id)
                del self._result_cache[query_id]
            
            # Store in cache
            self._result_cache[query_id] = cached
            
            # Index by fingerprint
            if fingerprint not in self._fingerprint_index:
                self._fingerprint_index[fingerprint] = []
            self._fingerprint_index[fingerprint].append(query_id)
            
            # Update global item tracking
            self._all_seen_items.update(result_set)
            if self._bloom_filter:
                self._bloom_filter.add_many(result_set)
            
            # Maintenance
            self._evict_if_needed()
            self._clean_expired()
            
            self._stats.total_queries_cached += 1
            self._stats.current_cache_size = len(self._result_cache)
            
            return fingerprint
    
    def lookup_cached_result(self, query_id: str) -> Optional[CachedQueryResult]:
        """Look up a cached query result"""
        with self._lock:
            if query_id not in self._result_cache:
                self._stats.total_cache_misses += 1
                return None
            
            result = self._result_cache[query_id]
            
            if result.is_expired():
                del self._result_cache[query_id]
                self._stats.total_cache_misses += 1
                return None
            
            # Update LRU position
            result.touch()
            del self._result_cache[query_id]
            self._result_cache[query_id] = result
            
            self._stats.total_cache_hits += 1
            self._stats.cache_hit_rate_percent = self._stats.calculate_hit_rate()
            
            return result
    
    def deduplicate_results(self,
                            new_result_items: List[str],
                            query_id: Optional[str] = None) -> DeduplicationResult:
        """
        Deduplicate a new result set against all cached results
        
        Returns comprehensive deduplication analysis
        """
        new_set = set(new_result_items)
        
        with self._lock:
            # Fast pre-check with bloom filter
            bloom_hits = 0
            if self._bloom_filter:
                for item in new_set:
                    if self._bloom_filter.might_contain(item):
                        bloom_hits += 1
            
            # Find exact and similar cached results
            overlapping: Set[str] = set()
            matched_queries: List[str] = []
            max_similarity = 0.0
            
            for cached_result in self._result_cache.values():
                if cached_result.is_expired():
                    continue
                
                similarity = cached_result.calculate_jaccard_similarity(new_set)
                max_similarity = max(max_similarity, similarity)
                
                if similarity > 0:
                    common = cached_result.result_items & new_set
                    overlapping.update(common)
                    if cached_result.query_id not in matched_queries:
                        matched_queries.append(cached_result.query_id)
            
            # Calculate new items
            new_items = new_set - overlapping
            
            # Determine match type
            if len(overlapping) == len(new_set) and len(new_set) > 0:
                match_type = ResultMatchType.EXACT_DUPLICATE
                should_suppress = self.config.auto_suppress_duplicates
                reason = "All results are exact duplicates of previous queries"
            elif len(new_items) == 0:
                match_type = ResultMatchType.SUBSET
                should_suppress = self.config.auto_suppress_duplicates
                reason = "Results are complete subset of previous results"
            elif len(overlapping) == 0:
                match_type = ResultMatchType.NO_OVERLAP
                should_suppress = False
                reason = "No overlapping results found"
            elif len(overlapping) > 0 and similarity >= self.config.deduplication_similarity_threshold:
                match_type = ResultMatchType.PARTIAL_OVERLAP
                should_suppress = len(new_items) == 0
                reason = f"Partial overlap: {len(overlapping)} duplicates, {len(new_items)} new"
            else:
                match_type = ResultMatchType.NEW_ONLY
                should_suppress = False
                reason = "Mostly new results with minimal overlap"
            
            # Update statistics
            self._stats.total_duplicates_detected += len(overlapping)
            self._stats.total_items_deduplicated += len(overlapping)
            if should_suppress:
                self._stats.total_alerts_suppressed += 1
            
            total = self._stats.total_duplicates_detected + len(new_items)
            if total > 0:
                self._stats.deduplication_rate_percent = round(
                    (self._stats.total_duplicates_detected / total) * 100, 2
                )
            
            return DeduplicationResult(
                match_type=match_type,
                similarity_score=round(max_similarity, 4),
                duplicate_count=len(overlapping),
                new_item_count=len(new_items),
                overlapping_items=overlapping,
                new_items=new_items,
                matched_query_ids=matched_queries[:10],  # Limit for performance
                should_suppress_alert=should_suppress,
                suppression_reason=reason
            )
    
    def get_incremental_delta(self, query_id: str, new_result_items: List[str]) -> Dict[str, Any]:
        """
        Get incremental delta between cached results and new results
        
        Returns:
            Dictionary with added, removed, and unchanged items
        """
        cached = self.lookup_cached_result(query_id)
        
        if cached is None:
            return {
                "status": "no_cache",
                "added": new_result_items,
                "removed": [],
                "unchanged": [],
                "delta_summary": f"First time seeing {len(new_result_items)} results"
            }
        
        old_set = cached.result_items
        new_set = set(new_result_items)
        
        added = new_set - old_set
        removed = old_set - new_set
        unchanged = old_set & new_set
        
        return {
            "status": "delta_computed",
            "added": sorted(list(added)),
            "removed": sorted(list(removed)),
            "unchanged": sorted(list(unchanged)),
            "added_count": len(added),
            "removed_count": len(removed),
            "unchanged_count": len(unchanged),
            "delta_summary": f"+{len(added)} new, -{len(removed)} removed, {len(unchanged)} unchanged"
        }
    
    def find_similar_queries(self, result_items: List[str], 
                             min_similarity: float = 0.5) -> List[Dict[str, Any]]:
        """Find queries with similar result sets"""
        search_set = set(result_items)
        matches = []
        
        with self._lock:
            for cached in self._result_cache.values():
                if cached.is_expired():
                    continue
                
                similarity = cached.calculate_jaccard_similarity(search_set)
                if similarity >= min_similarity:
                    matches.append({
                        "query_id": cached.query_id,
                        "similarity": round(similarity, 4),
                        "result_count": cached.result_count,
                        "age_seconds": int(time.time() - cached.created_at)
                    })
        
        return sorted(matches, key=lambda x: x["similarity"], reverse=True)
    
    def get_statistics(self) -> CacheStatistics:
        """Get current cache statistics"""
        with self._lock:
            return CacheStatistics(
                total_queries_cached=self._stats.total_queries_cached,
                total_cache_hits=self._stats.total_cache_hits,
                total_cache_misses=self._stats.total_cache_misses,
                total_duplicates_detected=self._stats.total_duplicates_detected,
                total_alerts_suppressed=self._stats.total_alerts_suppressed,
                total_items_deduplicated=self._stats.total_items_deduplicated,
                average_similarity_score=self._stats.average_similarity_score,
                current_cache_size=len(self._result_cache),
                cache_hit_rate_percent=self._stats.calculate_hit_rate(),
                deduplication_rate_percent=self._stats.deduplication_rate_percent
            )
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive performance metrics"""
        stats = self.get_statistics()
        return {
            "cache_hit_rate_percent": stats.cache_hit_rate_percent,
            "deduplication_rate_percent": stats.deduplication_rate_percent,
            "total_results_cached": stats.total_queries_cached,
            "total_duplicates_eliminated": stats.total_duplicates_detected,
            "alerts_suppressed": stats.total_alerts_suppressed,
            "cache_utilization_percent": round(
                (stats.current_cache_size / self.config.max_cached_results) * 100, 2
            ),
            "unique_items_tracked": len(self._all_seen_items)
        }
    
    def clear(self) -> None:
        """Clear all cached data"""
        with self._lock:
            self._result_cache.clear()
            self._fingerprint_index.clear()
            self._all_seen_items.clear()
            if self._bloom_filter:
                self._bloom_filter = SimpleBloomFilter(
                    self.config.bloom_expected_items,
                    self.config.bloom_false_positive_rate
                )
            self._stats = CacheStatistics()
    
    def export_cache_summary(self) -> List[Dict[str, Any]]:
        """Export summary of cached queries"""
        with self._lock:
            return [
                {
                    "query_id": r.query_id,
                    "result_count": r.result_count,
                    "fingerprint": r.result_fingerprint[:16],
                    "age_seconds": int(time.time() - r.created_at),
                    "access_count": r.access_count
                }
                for r in list(self._result_cache.values())[-100:]
            ]
