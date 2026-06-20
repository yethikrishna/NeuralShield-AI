"""
NeuralShield AI - Threat Intelligence Semantic Search Cache Prefetcher Enhanced
Production-grade implementation with intelligent prefetching, adaptive learning,
and performance optimization capabilities.

This module enhances the semantic search cache prefetcher with:
1. Adaptive prefetching based on query patterns
2. Intelligent cache warming strategies
3. Query similarity-based prefetch queue prioritization
4. Performance metrics and adaptive tuning
5. Memory-aware cache eviction policies
"""

import hashlib
import heapq
import json
import logging
import threading
import time
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, Future

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PrefetchPriority(Enum):
    """Priority levels for prefetch operations."""
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3


class CacheWarmingStrategy(Enum):
    """Cache warming strategies."""
    RECENT_QUERIES = "recent_queries"
    POPULAR_QUERIES = "popular_queries"
    TIME_BASED = "time_based"
    PATTERN_BASED = "pattern_based"
    ADAPTIVE = "adaptive"


@dataclass(order=True)
class PrefetchTask:
    """Represents a prefetch task with priority."""
    priority: int
    query: str = field(compare=False)
    query_vector: List[float] = field(compare=False, default_factory=list)
    created_at: float = field(compare=False, default_factory=time.time)
    retry_count: int = field(compare=False, default=0)
    metadata: Dict[str, Any] = field(compare=False, default_factory=dict)


@dataclass
class CacheEntry:
    """Represents a cached search result."""
    query: str
    query_hash: str
    results: List[Dict[str, Any]]
    vector: List[float]
    created_at: float
    last_accessed: float
    access_count: int = 0
    ttl_seconds: int = 3600
    size_bytes: int = 0

    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        return time.time() - self.created_at > self.ttl_seconds

    def update_access(self) -> None:
        """Update access statistics."""
        self.last_accessed = time.time()
        self.access_count += 1


class AdaptiveLRUCache:
    """Adaptive LRU cache with memory awareness and TTL support."""

    def __init__(
        self,
        max_size_bytes: int = 100 * 1024 * 1024,  # 100MB
        max_entries: int = 10000,
        ttl_default: int = 3600
    ):
        self.max_size_bytes = max_size_bytes
        self.max_entries = max_entries
        self.ttl_default = ttl_default
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.current_size_bytes = 0
        self.hit_count = 0
        self.miss_count = 0
        self.eviction_count = 0
        self._lock = threading.RLock()

    def _compute_hash(self, query: str) -> str:
        """Compute hash for query."""
        return hashlib.sha256(query.encode('utf-8')).hexdigest()

    def get(self, query: str) -> Optional[List[Dict[str, Any]]]:
        """Get cached results for query."""
        query_hash = self._compute_hash(query)
        with self._lock:
            if query_hash in self.cache:
                entry = self.cache[query_hash]
                if entry.is_expired():
                    self._evict_entry(query_hash)
                    self.miss_count += 1
                    return None
                entry.update_access()
                self.cache.move_to_end(query_hash)
                self.hit_count += 1
                return entry.results
            self.miss_count += 1
            return None

    def put(
        self,
        query: str,
        results: List[Dict[str, Any]],
        vector: Optional[List[float]] = None,
        ttl_seconds: Optional[int] = None
    ) -> None:
        """Put results into cache."""
        query_hash = self._compute_hash(query)
        entry_size = len(json.dumps(results).encode('utf-8'))
        
        with self._lock:
            # Remove existing if present
            if query_hash in self.cache:
                old_entry = self.cache[query_hash]
                self.current_size_bytes -= old_entry.size_bytes
            
            # Evict if needed
            while (
                self.current_size_bytes + entry_size > self.max_size_bytes
                or len(self.cache) >= self.max_entries
            ):
                if not self.cache:
                    break
                self._evict_lru()
            
            entry = CacheEntry(
                query=query,
                query_hash=query_hash,
                results=results,
                vector=vector or [],
                created_at=time.time(),
                last_accessed=time.time(),
                ttl_seconds=ttl_seconds or self.ttl_default,
                size_bytes=entry_size
            )
            self.cache[query_hash] = entry
            self.current_size_bytes += entry_size

    def _evict_entry(self, query_hash: str) -> None:
        """Evict specific entry."""
        if query_hash in self.cache:
            entry = self.cache.pop(query_hash)
            self.current_size_bytes -= entry.size_bytes
            self.eviction_count += 1

    def _evict_lru(self) -> None:
        """Evict least recently used entry."""
        if self.cache:
            oldest_key = next(iter(self.cache))
            self._evict_entry(oldest_key)

    def get_hit_rate(self) -> float:
        """Get cache hit rate."""
        total = self.hit_count + self.miss_count
        return self.hit_count / total if total > 0 else 0.0

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "hit_count": self.hit_count,
            "miss_count": self.miss_count,
            "hit_rate": self.get_hit_rate(),
            "eviction_count": self.eviction_count,
            "entry_count": len(self.cache),
            "size_bytes": self.current_size_bytes,
            "max_size_bytes": self.max_size_bytes
        }

    def cleanup_expired(self) -> int:
        """Clean up expired entries."""
        expired = []
        with self._lock:
            for query_hash, entry in list(self.cache.items()):
                if entry.is_expired():
                    expired.append(query_hash)
            for h in expired:
                self._evict_entry(h)
        return len(expired)


class QueryPatternLearner:
    """Learns query patterns to predict future queries."""

    def __init__(self, pattern_window_size: int = 1000):
        self.pattern_window_size = pattern_window_size
        self.query_history: deque = deque(maxlen=pattern_window_size)
        self.query_transitions: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self.query_frequencies: Dict[str, int] = defaultdict(int)
        self.time_patterns: Dict[int, List[str]] = defaultdict(list)
        self._lock = threading.Lock()

    def record_query(self, query: str) -> None:
        """Record a query for pattern learning."""
        with self._lock:
            # Update frequencies
            self.query_frequencies[query] += 1
            
            # Update transitions
            if self.query_history:
                prev_query = self.query_history[-1]
                self.query_transitions[prev_query][query] += 1
            
            self.query_history.append(query)
            
            # Record time pattern (hour of day)
            hour = datetime.now().hour
            self.time_patterns[hour].append(query)

    def predict_next_queries(
        self,
        current_query: str,
        top_k: int = 5
    ) -> List[Tuple[str, float]]:
        """Predict likely next queries based on patterns."""
        predictions: Dict[str, float] = {}
        
        with self._lock:
            # Transition-based predictions
            if current_query in self.query_transitions:
                transitions = self.query_transitions[current_query]
                total = sum(transitions.values())
                for next_q, count in transitions.items():
                    predictions[next_q] = count / total
            
            # Popular queries as fallback
            sorted_freq = sorted(
                self.query_frequencies.items(),
                key=lambda x: x[1],
                reverse=True
            )
            for q, freq in sorted_freq[:top_k]:
                if q not in predictions:
                    predictions[q] = freq / len(self.query_history) if self.query_history else 0
        
        return sorted(predictions.items(), key=lambda x: x[1], reverse=True)[:top_k]

    def get_popular_queries(self, top_k: int = 10) -> List[Tuple[str, int]]:
        """Get most frequent queries."""
        with self._lock:
            return sorted(
                self.query_frequencies.items(),
                key=lambda x: x[1],
                reverse=True
            )[:top_k]


class SemanticSimilarityCalculator:
    """Calculates semantic similarity between queries."""

    @staticmethod
    def cosine_similarity(v1: List[float], v2: List[float]) -> float:
        """Calculate cosine similarity between two vectors."""
        if not v1 or not v2 or len(v1) != len(v2):
            return 0.0
        
        dot_product = sum(a * b for a, b in zip(v1, v2))
        norm1 = sum(a * a for a in v1) ** 0.5
        norm2 = sum(b * b for b in v2) ** 0.5
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)

    @staticmethod
    def jaccard_similarity(s1: str, s2: str) -> float:
        """Calculate Jaccard similarity between query strings."""
        set1 = set(s1.lower().split())
        set2 = set(s2.lower().split())
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        return intersection / union if union > 0 else 0.0

    @staticmethod
    def hybrid_similarity(
        query1: str,
        query2: str,
        vec1: Optional[List[float]] = None,
        vec2: Optional[List[float]] = None
    ) -> float:
        """Calculate hybrid similarity combining string and vector."""
        jaccard = SemanticSimilarityCalculator.jaccard_similarity(query1, query2)
        
        if vec1 and vec2:
            cosine = SemanticSimilarityCalculator.cosine_similarity(vec1, vec2)
            return 0.6 * cosine + 0.4 * jaccard
        
        return jaccard


class EnhancedSemanticSearchCachePrefetcher:
    """
    Enhanced semantic search cache prefetcher with intelligent prefetching,
    adaptive learning, and performance optimization.
    """

    def __init__(
        self,
        cache_max_size_bytes: int = 100 * 1024 * 1024,
        prefetch_workers: int = 4,
        prefetch_queue_size: int = 1000,
        similarity_threshold: float = 0.7,
        auto_warm_enabled: bool = True
    ):
        self.cache = AdaptiveLRUCache(max_size_bytes=cache_max_size_bytes)
        self.pattern_learner = QueryPatternLearner()
        self.similarity_calc = SemanticSimilarityCalculator()
        
        self.prefetch_queue: List[PrefetchTask] = []
        self.prefetch_queue_size = prefetch_queue_size
        self.similarity_threshold = similarity_threshold
        self.auto_warm_enabled = auto_warm_enabled
        
        self.executor = ThreadPoolExecutor(max_workers=prefetch_workers)
        self.prefetching_enabled = True
        self.active_prefetches: Set[str] = set()
        
        self.search_callback: Optional[Callable[[str], Tuple[List[Dict], List[float]]]] = None
        self._lock = threading.Lock()
        self._prefetch_lock = threading.Lock()
        
        # Statistics
        self.prefetch_attempts = 0
        self.prefetch_hits = 0
        self.prefetch_misses = 0
        
        # Start background threads
        self._start_background_tasks()
        logger.info("Enhanced Semantic Search Cache Prefetcher initialized")

    def _start_background_tasks(self) -> None:
        """Start background maintenance tasks."""
        def maintenance_loop():
            while True:
                try:
                    # Clean expired cache entries
                    expired = self.cache.cleanup_expired()
                    if expired > 0:
                        logger.debug(f"Cleaned {expired} expired cache entries")
                    
                    # Process prefetch queue
                    self._process_prefetch_queue()
                    
                    time.sleep(30)
                except Exception as e:
                    logger.error(f"Maintenance task error: {e}")
                    time.sleep(60)

        threading.Thread(target=maintenance_loop, daemon=True).start()

    def register_search_callback(
        self,
        callback: Callable[[str], Tuple[List[Dict[str, Any]], List[float]]]
    ) -> None:
        """Register callback for actual search execution."""
        self.search_callback = callback

    def search(self, query: str) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Perform search with cache lookup and trigger prefetching.
        
        Returns:
            Tuple of (results, was_cached)
        """
        # Check cache first
        cached = self.cache.get(query)
        if cached is not None:
            self.pattern_learner.record_query(query)
            self._trigger_prefetching(query)
            return cached, True

        # Execute actual search
        if self.search_callback:
            results, vector = self.search_callback(query)
            self.cache.put(query, results, vector)
            self.pattern_learner.record_query(query)
            self._trigger_prefetching(query)
            return results, False
        
        return [], False

    def _trigger_prefetching(self, current_query: str) -> None:
        """Trigger prefetching based on current query."""
        if not self.prefetching_enabled:
            return

        # Get predicted next queries
        predictions = self.pattern_learner.predict_next_queries(current_query)
        
        for predicted_query, confidence in predictions:
            if confidence > 0.1:  # Only prefetch if confidence is meaningful
                priority = PrefetchPriority.HIGH if confidence > 0.5 else PrefetchPriority.MEDIUM
                self._queue_prefetch(predicted_query, priority, {
                    "source": "prediction",
                    "confidence": confidence
                })

        # Prefetch similar queries from popular set
        popular = self.pattern_learner.get_popular_queries(20)
        for popular_query, _ in popular:
            if popular_query != current_query:
                sim = self.similarity_calc.jaccard_similarity(current_query, popular_query)
                if sim > self.similarity_threshold:
                    self._queue_prefetch(popular_query, PrefetchPriority.MEDIUM, {
                        "source": "similarity",
                        "similarity": sim
                    })

    def _queue_prefetch(
        self,
        query: str,
        priority: PrefetchPriority,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Queue a prefetch task."""
        with self._prefetch_lock:
            # Check if already queued or active
            query_in_queue = any(t.query == query for t in self.prefetch_queue)
            if query_in_queue or query in self.active_prefetches:
                return
            
            # Check if already cached
            if self.cache.get(query) is not None:
                return
            
            task = PrefetchTask(
                priority=priority.value,
                query=query,
                metadata=metadata or {}
            )
            
            if len(self.prefetch_queue) < self.prefetch_queue_size:
                heapq.heappush(self.prefetch_queue, task)
            else:
                # Only add if higher priority than lowest in queue
                if task < self.prefetch_queue[-1]:
                    heapq.heapreplace(self.prefetch_queue, task)

    def _process_prefetch_queue(self) -> None:
        """Process queued prefetch tasks."""
        if not self.search_callback:
            return

        with self._prefetch_lock:
            batch_size = min(5, len(self.prefetch_queue))
            tasks_to_process = []
            
            for _ in range(batch_size):
                if self.prefetch_queue:
                    task = heapq.heappop(self.prefetch_queue)
                    tasks_to_process.append(task)

        for task in tasks_to_process:
            self._execute_prefetch(task)

    def _execute_prefetch(self, task: PrefetchTask) -> None:
        """Execute a single prefetch task."""
        if task.query in self.active_prefetches:
            return

        with self._lock:
            self.active_prefetches.add(task.query)
        
        try:
            self.prefetch_attempts += 1
            
            # Double-check cache
            if self.cache.get(task.query) is not None:
                self.prefetch_hits += 1
                return
            
            # Execute search
            if self.search_callback:
                results, vector = self.search_callback(task.query)
                self.cache.put(task.query, results, vector)
                self.prefetch_misses += 1
                
        except Exception as e:
            logger.debug(f"Prefetch error for '{task.query}': {e}")
        finally:
            with self._lock:
                self.active_prefetches.discard(task.query)

    def warm_cache(
        self,
        strategy: CacheWarmingStrategy = CacheWarmingStrategy.ADAPTIVE,
        count: int = 50
    ) -> int:
        """
        Warm cache using specified strategy.
        
        Returns:
            Number of queries warmed
        """
        queries_to_warm: List[str] = []
        
        if strategy in [CacheWarmingStrategy.POPULAR_QUERIES, CacheWarmingStrategy.ADAPTIVE]:
            popular = self.pattern_learner.get_popular_queries(count)
            queries_to_warm.extend([q for q, _ in popular])
        
        if strategy in [CacheWarmingStrategy.RECENT_QUERIES, CacheWarmingStrategy.ADAPTIVE]:
            with self.pattern_learner._lock:
                recent = list(self.pattern_learner.query_history)[-count:]
                queries_to_warm.extend(recent)
        
        # Deduplicate
        queries_to_warm = list(set(queries_to_warm))[:count]
        
        warmed = 0
        for query in queries_to_warm:
            if self.cache.get(query) is None:
                self._queue_prefetch(query, PrefetchPriority.CRITICAL, {"source": "warmup"})
                warmed += 1
        
        logger.info(f"Cache warming queued {warmed} queries with {strategy.value} strategy")
        return warmed

    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics."""
        return {
            "cache": self.cache.get_stats(),
            "prefetching": {
                "attempts": self.prefetch_attempts,
                "hits": self.prefetch_hits,
                "misses": self.prefetch_misses,
                "queue_size": len(self.prefetch_queue),
                "active_prefetches": len(self.active_prefetches)
            },
            "patterns": {
                "learned_queries": len(self.pattern_learner.query_frequencies),
                "history_size": len(self.pattern_learner.query_history)
            }
        }

    def shutdown(self) -> None:
        """Shutdown prefetcher gracefully."""
        self.prefetching_enabled = False
        self.executor.shutdown(wait=False)
        logger.info("Enhanced Semantic Search Cache Prefetcher shutdown complete")
