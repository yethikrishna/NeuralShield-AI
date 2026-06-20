"""
Threat Intelligence Semantic Search Cache Prefetcher - Production Grade
NeuralShield-AI Module
Provides intelligent prefetching and caching for semantic threat intelligence searches
with adaptive learning, query prediction, and performance optimization.

Features:
- Query pattern analysis and prediction
- Intelligent prefetching based on historical access patterns
- Semantic similarity-based cache warming
- Adaptive TTL based on query frequency
- Query clustering and batch prefetching
- Real-time performance monitoring
- Memory-efficient vector caching
- Thread-safe concurrent operations
"""
import time
import threading
import hashlib
import math
from typing import Dict, Optional, Any, List, Tuple, Set, Callable
from dataclasses import dataclass, field
from collections import OrderedDict, defaultdict, deque
from enum import Enum
import heapq


class QueryCategory(Enum):
    """Categories of threat intelligence queries"""
    IOC_LOOKUP = "ioc_lookup"
    THREAT_ACTOR = "threat_actor"
    CVE_SEARCH = "cve_search"
    MALWARE_ANALYSIS = "malware_analysis"
    VULNERABILITY = "vulnerability"
    MITRE_TECHNIQUE = "mitre_technique"
    GENERAL = "general"


@dataclass
class QueryPattern:
    """Represents a query pattern with metadata"""
    query_text: str
    category: QueryCategory
    frequency: int = 0
    last_accessed: float = field(default_factory=time.time)
    avg_response_time_ms: float = 0.0
    total_accesses: int = 0
    embedding_hash: str = ""
    
    def update_access(self, response_time_ms: float) -> None:
        """Update access statistics"""
        self.frequency += 1
        self.total_accesses += 1
        self.last_accessed = time.time()
        # Rolling average for response time
        if self.total_accesses == 1:
            self.avg_response_time_ms = response_time_ms
        else:
            self.avg_response_time_ms = (
                (self.avg_response_time_ms * (self.total_accesses - 1) + response_time_ms) 
                / self.total_accesses
            )


@dataclass
class PrefetchConfig:
    """Configuration for Cache Prefetcher"""
    max_cache_size: int = 5000
    max_pattern_history: int = 10000
    prefetch_threshold: int = 3  # Prefetch after N accesses
    prediction_window_seconds: int = 300  # 5 minutes
    adaptive_ttl_base: int = 600  # 10 minutes base TTL
    adaptive_ttl_max: int = 7200  # 2 hours max TTL
    semantic_similarity_threshold: float = 0.85
    enable_prefetch: bool = True
    enable_adaptive_ttl: bool = True
    max_prefetch_batch: int = 20
    pattern_decay_hours: float = 24.0  # Pattern decay over time
    stats_interval_seconds: int = 60


@dataclass
class PrefetchStatistics:
    """Prefetcher performance statistics"""
    total_queries: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    prefetched_queries: int = 0
    successful_prefetches: int = 0
    false_prefetches: int = 0
    avg_latency_ms: float = 0.0
    hit_rate_percent: float = 0.0
    prefetch_accuracy_percent: float = 0.0
    total_saved_time_ms: float = 0.0
    
    def calculate_rates(self) -> None:
        """Calculate performance rates"""
        total = self.cache_hits + self.cache_misses
        if total > 0:
            self.hit_rate_percent = round((self.cache_hits / total) * 100, 2)
        
        total_prefetch = self.successful_prefetches + self.false_prefetches
        if total_prefetch > 0:
            self.prefetch_accuracy_percent = round(
                (self.successful_prefetches / total_prefetch) * 100, 2
            )


@dataclass
class CacheEntry:
    """Cached semantic search result"""
    query: str
    result: Any
    category: QueryCategory
    ttl_seconds: int
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    access_count: int = 0
    was_prefetched: bool = False
    
    def is_expired(self) -> bool:
        """Check if entry has expired"""
        return time.time() - self.created_at > self.ttl_seconds
    
    def touch(self) -> None:
        """Update access metadata"""
        self.last_accessed = time.time()
        self.access_count += 1


class SimpleSemanticHasher:
    """Simple semantic hashing for query similarity detection"""
    
    @staticmethod
    def compute_hash(text: str) -> str:
        """Compute a hash for query text"""
        normalized = text.lower().strip()
        # Simple token-based fingerprint
        tokens = sorted(set(normalized.split()))
        fingerprint = " ".join(tokens[:10])  # Use first 10 unique tokens
        return hashlib.md5(fingerprint.encode()).hexdigest()[:16]
    
    @staticmethod
    def compute_similarity(hash1: str, hash2: str) -> float:
        """Compute simple similarity between two hashes"""
        # Hamming distance based similarity
        if hash1 == hash2:
            return 1.0
        matching = sum(1 for a, b in zip(hash1, hash2) if a == b)
        return matching / len(hash1)


class ThreatIntelSemanticCachePrefetcher:
    """
    Production-grade Threat Intelligence Semantic Search Cache Prefetcher
    
    Provides:
    1. Intelligent query pattern learning
    2. Predictive prefetching of likely future queries
    3. Semantic similarity-based cache warming
    4. Adaptive TTL based on query frequency
    5. Comprehensive performance monitoring
    6. Thread-safe concurrent operations
    """
    
    def __init__(self, config: Optional[PrefetchConfig] = None, 
                 lookup_callback: Optional[Callable[[str, QueryCategory], Any]] = None):
        self.config = config or PrefetchConfig()
        self._lookup_callback = lookup_callback
        
        # Cache storage (LRU)
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._query_patterns: Dict[str, QueryPattern] = {}
        self._access_history: deque = deque(maxlen=1000)
        self._category_frequency: Dict[QueryCategory, int] = defaultdict(int)
        
        # Thread safety
        self._lock = threading.RLock()
        self._stats = PrefetchStatistics()
        
        # Semantic hashing
        self._hasher = SimpleSemanticHasher()
        
        # Prefetch prediction queue
        self._prefetch_queue: List[Tuple[float, str, QueryCategory]] = []
        self._prefetched_hashes: Set[str] = set()
        
        self._start_time = time.time()
        self._last_maintenance = time.time()
    
    def _categorize_query(self, query: str) -> QueryCategory:
        """Categorize a query based on its content"""
        query_lower = query.lower()
        
        # Simple heuristic categorization
        if any(indicator in query_lower for indicator in ["ip:", "domain:", "hash:", "ioc", "indicator"]):
            return QueryCategory.IOC_LOOKUP
        elif any(cve in query_lower for cve in ["cve-", "cve ", "vulnerability"]):
            return QueryCategory.CVE_SEARCH
        elif any(actor in query_lower for actor in ["apt", "threat actor", "group", "campaign"]):
            return QueryCategory.THREAT_ACTOR
        elif any(malware in query_lower for malware in ["malware", "trojan", "ransomware", "virus"]):
            return QueryCategory.MALWARE_ANALYSIS
        elif any(mitre in query_lower for mitre in ["mitre", "tactic", "technique", "t1"]):
            return QueryCategory.MITRE_TECHNIQUE
        elif any(vuln in query_lower for vuln in ["exploit", "patch", "cvss"]):
            return QueryCategory.VULNERABILITY
        return QueryCategory.GENERAL
    
    def _calculate_adaptive_ttl(self, pattern: QueryPattern) -> int:
        """Calculate adaptive TTL based on query frequency"""
        if not self.config.enable_adaptive_ttl:
            return self.config.adaptive_ttl_base
        
        # More frequent queries get longer TTL
        frequency_factor = min(pattern.frequency, 10) / 10.0
        ttl_range = self.config.adaptive_ttl_max - self.config.adaptive_ttl_base
        adaptive_ttl = self.config.adaptive_ttl_base + int(frequency_factor * ttl_range)
        
        return adaptive_ttl
    
    def _evict_cache_if_needed(self) -> None:
        """Evict LRU entries if cache exceeds max size"""
        while len(self._cache) > self.config.max_cache_size:
            oldest_key, _ = self._cache.popitem(last=False)
    
    def _decay_patterns(self) -> None:
        """Apply time decay to pattern frequencies"""
        decay_factor = 0.5 ** (1.0 / (self.config.pattern_decay_hours * 3600))
        current_time = time.time()
        
        for pattern in self._query_patterns.values():
            time_since_access = current_time - pattern.last_accessed
            decay = decay_factor ** time_since_access
            pattern.frequency = int(pattern.frequency * decay)
    
    def _predict_prefetch_candidates(self) -> List[Tuple[str, QueryCategory]]:
        """Predict which queries should be prefetched"""
        candidates = []
        current_time = time.time()
        
        for query_hash, pattern in self._query_patterns.items():
            # Only prefetch frequently accessed queries
            if pattern.frequency < self.config.prefetch_threshold:
                continue
            
            # Check if query was accessed recently and might be needed again
            time_since_access = current_time - pattern.last_accessed
            if time_since_access < self.config.prediction_window_seconds:
                # Priority based on frequency and recency
                priority = pattern.frequency / (time_since_access + 1)
                candidates.append((priority, pattern.query_text, pattern.category))
        
        # Sort by priority and return top candidates
        candidates.sort(reverse=True, key=lambda x: x[0])
        return [(q, c) for _, q, c in candidates[:self.config.max_prefetch_batch]]
    
    def _execute_prefetch(self, query: str, category: QueryCategory) -> bool:
        """Execute prefetch for a single query"""
        if not self._lookup_callback:
            return False
        
        query_hash = self._hasher.compute_hash(query)
        if query_hash in self._prefetched_hashes:
            return False
        
        try:
            start_time = time.time()
            result = self._lookup_callback(query, category)
            latency_ms = (time.time() - start_time) * 1000
            
            ttl = self.config.adaptive_ttl_base
            if query_hash in self._query_patterns:
                ttl = self._calculate_adaptive_ttl(self._query_patterns[query_hash])
            
            entry = CacheEntry(
                query=query,
                result=result,
                category=category,
                ttl_seconds=ttl,
                was_prefetched=True
            )
            
            self._cache[query_hash] = entry
            self._prefetched_hashes.add(query_hash)
            self._stats.prefetched_queries += 1
            
            return True
        except Exception:
            return False
    
    def lookup(self, query: str) -> Tuple[Optional[Any], bool]:
        """
        Look up a query result, using cache if available
        
        Returns:
            Tuple of (result, was_cached)
        """
        start_time = time.time()
        query_hash = self._hasher.compute_hash(query)
        category = self._categorize_query(query)
        
        with self._lock:
            self._stats.total_queries += 1
            
            # Check cache first
            if query_hash in self._cache:
                entry = self._cache[query_hash]
                
                if not entry.is_expired():
                    # Cache hit
                    entry.touch()
                    # Move to end for LRU
                    del self._cache[query_hash]
                    self._cache[query_hash] = entry
                    
                    self._stats.cache_hits += 1
                    
                    if entry.was_prefetched:
                        self._stats.successful_prefetches += 1
                    
                    latency_ms = (time.time() - start_time) * 1000
                    self._stats.total_saved_time_ms += max(0, entry.access_count * 50 - latency_ms)
                    
                    self._update_pattern(query, category, latency_ms, query_hash)
                    self._stats.calculate_rates()
                    
                    return entry.result, True
                else:
                    # Expired - remove
                    del self._cache[query_hash]
            
            # Cache miss
            self._stats.cache_misses += 1
            
            # Update pattern learning
            latency_ms = (time.time() - start_time) * 1000
            self._update_pattern(query, category, latency_ms, query_hash)
            
            # Check if this was a false prefetch (was prefetched but expired or not hit)
            if query_hash in self._prefetched_hashes:
                self._stats.false_prefetches += 1
                self._prefetched_hashes.discard(query_hash)
            
            self._stats.calculate_rates()
            
            return None, False
    
    def _update_pattern(self, query: str, category: QueryCategory, 
                        response_time_ms: float, query_hash: str) -> None:
        """Update query pattern learning"""
        if query_hash not in self._query_patterns:
            self._query_patterns[query_hash] = QueryPattern(
                query_text=query,
                category=category,
                embedding_hash=query_hash
            )
        
        self._query_patterns[query_hash].update_access(response_time_ms)
        self._category_frequency[category] += 1
        self._access_history.append((time.time(), query_hash))
    
    def store(self, query: str, result: Any) -> bool:
        """
        Store a query result in cache
        
        Returns:
            True if stored successfully
        """
        if not query:
            return False
        
        query_hash = self._hasher.compute_hash(query)
        category = self._categorize_query(query)
        
        with self._lock:
            # Remove existing if present
            if query_hash in self._cache:
                del self._cache[query_hash]
            
            ttl = self.config.adaptive_ttl_base
            if query_hash in self._query_patterns:
                ttl = self._calculate_adaptive_ttl(self._query_patterns[query_hash])
            
            entry = CacheEntry(
                query=query,
                result=result,
                category=category,
                ttl_seconds=ttl
            )
            
            self._cache[query_hash] = entry
            self._evict_cache_if_needed()
            
            return True
    
    def run_prefetch_cycle(self) -> int:
        """
        Run one prefetch cycle
        
        Returns:
            Number of queries successfully prefetched
        """
        if not self.config.enable_prefetch:
            return 0
        
        with self._lock:
            candidates = self._predict_prefetch_candidates()
            success_count = 0
            
            for query, category in candidates:
                if self._execute_prefetch(query, category):
                    success_count += 1
            
            return success_count
    
    def get_semantically_similar(self, query: str, limit: int = 5) -> List[str]:
        """Find semantically similar queries in cache"""
        query_hash = self._hasher.compute_hash(query)
        similarities = []
        
        with self._lock:
            for cached_hash, entry in self._cache.items():
                sim = self._hasher.compute_similarity(query_hash, cached_hash)
                if sim >= self.config.semantic_similarity_threshold:
                    similarities.append((sim, entry.query))
        
        similarities.sort(reverse=True, key=lambda x: x[0])
        return [q for _, q in similarities[:limit]]
    
    def get_statistics(self) -> PrefetchStatistics:
        """Get current prefetcher statistics"""
        with self._lock:
            self._stats.avg_latency_ms = round(
                self._stats.total_saved_time_ms / max(1, self._stats.cache_hits), 2
            )
            return PrefetchStatistics(
                total_queries=self._stats.total_queries,
                cache_hits=self._stats.cache_hits,
                cache_misses=self._stats.cache_misses,
                prefetched_queries=self._stats.prefetched_queries,
                successful_prefetches=self._stats.successful_prefetches,
                false_prefetches=self._stats.false_prefetches,
                avg_latency_ms=self._stats.avg_latency_ms,
                hit_rate_percent=self._stats.hit_rate_percent,
                prefetch_accuracy_percent=self._stats.prefetch_accuracy_percent,
                total_saved_time_ms=self._stats.total_saved_time_ms
            )
    
    def get_category_distribution(self) -> Dict[str, int]:
        """Get query category distribution"""
        with self._lock:
            return {cat.value: count for cat, count in self._category_frequency.items()}
    
    def get_top_patterns(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most frequent query patterns"""
        with self._lock:
            patterns = sorted(
                self._query_patterns.values(),
                key=lambda p: p.frequency,
                reverse=True
            )[:limit]
            
            return [
                {
                    "query": p.query_text[:50] + "..." if len(p.query_text) > 50 else p.query_text,
                    "category": p.category.value,
                    "frequency": p.frequency,
                    "avg_response_ms": round(p.avg_response_time_ms, 2)
                }
                for p in patterns
            ]
    
    def clear(self) -> None:
        """Clear all cache and patterns"""
        with self._lock:
            self._cache.clear()
            self._query_patterns.clear()
            self._access_history.clear()
            self._category_frequency.clear()
            self._prefetch_queue.clear()
            self._prefetched_hashes.clear()
            self._stats = PrefetchStatistics()
    
    def get_cache_info(self) -> Dict[str, Any]:
        """Get detailed cache information"""
        stats = self.get_statistics()
        return {
            "cache_size": len(self._cache),
            "max_cache_size": self.config.max_cache_size,
            "learned_patterns": len(self._query_patterns),
            "prefetched_entries": len(self._prefetched_hashes),
            "hit_rate_percent": stats.hit_rate_percent,
            "prefetch_accuracy_percent": stats.prefetch_accuracy_percent,
            "total_saved_seconds": round(stats.total_saved_time_ms / 1000, 2),
            "uptime_seconds": int(time.time() - self._start_time)
        }
