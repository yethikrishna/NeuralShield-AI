"""
NeuralShield AI - Threat Intelligence Semantic Cache
Dimension A: Feature Expansion v25
Session 127 | June 24, 2026

ADD-ONLY MODULE - No existing code modified
OPT-IN ONLY - Disabled by default, no side effects

Purpose: Semantic caching layer for threat intelligence to avoid redundant
processing of semantically identical threats. Uses perceptual hashing of
input content to detect near-duplicate threat vectors.

Stability: EXPERIMENTAL
Backward Compatible: YES
Dependencies: Python stdlib only
"""

import hashlib
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from datetime import datetime, timedelta


class CacheStrategy(Enum):
    """Cache eviction strategy enumeration."""
    LRU = "least_recently_used"
    LFU = "least_frequently_used"
    FIFO = "first_in_first_out"
    TTL = "time_to_live_only"


class ThreatCategory(Enum):
    """Threat category classification for cache partitioning."""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    HALLUCINATION = "hallucination"
    TOXICITY = "toxicity"
    ADVERSARIAL = "adversarial"
    BACKDOOR = "backdoor"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class CacheEntry:
    """Immutable cache entry for threat detection results."""
    semantic_hash: str
    threat_category: ThreatCategory
    detection_result: Dict[str, Any]
    confidence_score: float
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    access_count: int = 0
    ttl_seconds: int = 3600  # 1 hour default

    def is_expired(self) -> bool:
        """Check if this entry has expired."""
        return time.time() - self.created_at > self.ttl_seconds

    def with_updated_access(self) -> 'CacheEntry':
        """Create new entry with updated access metadata (immutable pattern)."""
        return CacheEntry(
            semantic_hash=self.semantic_hash,
            threat_category=self.threat_category,
            detection_result=self.detection_result,
            confidence_score=self.confidence_score,
            created_at=self.created_at,
            last_accessed=time.time(),
            access_count=self.access_count + 1,
            ttl_seconds=self.ttl_seconds
        )


class SemanticHasher:
    """
    Perceptual/semantic hashing for input content.
    Creates consistent hashes for semantically similar inputs.
    """

    @staticmethod
    def compute_sha256(content: str) -> str:
        """Compute SHA-256 hash for exact matching."""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    @staticmethod
    def compute_semantic_hash(content: str, granularity: int = 8) -> str:
        """
        Compute semantic hash using normalized content.
        Normalizes whitespace, case, and common variations.
        """
        # Normalization pipeline
        normalized = content.lower()
        normalized = ' '.join(normalized.split())  # Normalize whitespace
        normalized = normalized.strip()
        
        # Simple perceptual hash - character frequency based
        char_freq = [0] * 26
        for c in normalized:
            if 'a' <= c <= 'z':
                char_freq[ord(c) - ord('a')] += 1
        
        # Create hash from frequency pattern
        base_hash = hashlib.md5(bytes(char_freq)).hexdigest()[:16]
        content_hash = hashlib.sha256(normalized.encode('utf-8')).hexdigest()[:granularity]
        
        return f"{base_hash}:{content_hash}"

    @staticmethod
    def compute_multi_hash(content: str) -> Dict[str, str]:
        """Compute multiple hash types for layered matching."""
        return {
            'exact': SemanticHasher.compute_sha256(content),
            'semantic': SemanticHasher.compute_semantic_hash(content),
            'coarse': SemanticHasher.compute_semantic_hash(content, granularity=4)
        }

    @staticmethod
    def hash_similarity(hash1: str, hash2: str) -> float:
        """Compute similarity score between two hashes (0.0-1.0)."""
        if hash1 == hash2:
            return 1.0
        
        min_len = min(len(hash1), len(hash2))
        matches = sum(1 for i in range(min_len) if hash1[i] == hash2[i])
        
        return matches / min_len


class ThreatIntelligenceSemanticCache:
    """
    Semantic caching layer for threat intelligence detection.
    
    Features:
    - Multi-level hashing (exact, semantic, coarse)
    - Multiple eviction strategies (LRU, LFU, FIFO, TTL)
    - Per-category cache partitioning
    - Thread-safe operations
    - Hit/miss statistics
    - Optional callback on cache hit
    - TTL-based expiration
    - OPT-IN ONLY - must be explicitly enabled
    """

    def __init__(
        self,
        max_size: int = 10000,
        strategy: CacheStrategy = CacheStrategy.LRU,
        default_ttl: int = 3600,
        similarity_threshold: float = 0.9,
        enabled: bool = False
    ):
        self._enabled = enabled
        self._max_size = max_size
        self._strategy = strategy
        self._default_ttl = default_ttl
        self._similarity_threshold = similarity_threshold
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Cache storage - partitioned by threat category
        self._caches: Dict[ThreatCategory, Dict[str, CacheEntry]] = {
            category: {} for category in ThreatCategory
        }
        
        # Statistics
        self._stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'expirations': 0,
            'semantic_hits': 0
        }
        
        # Callbacks
        self._on_cache_hit: Optional[Callable[[str, CacheEntry], None]] = None
        self._on_cache_miss: Optional[Callable[[str], None]] = None

    def enable(self) -> None:
        """Enable the cache (OPT-IN)."""
        with self._lock:
            self._enabled = True

    def disable(self) -> None:
        """Disable the cache - no side effects when disabled."""
        with self._lock:
            self._enabled = False

    def is_enabled(self) -> bool:
        """Check if cache is enabled."""
        return self._enabled

    def set_on_cache_hit(self, callback: Callable[[str, CacheEntry], None]) -> None:
        """Set callback for cache hit events."""
        self._on_cache_hit = callback

    def set_on_cache_miss(self, callback: Callable[[str], None]) -> None:
        """Set callback for cache miss events."""
        self._on_cache_miss = callback

    def _evict_if_needed(self, category: ThreatCategory) -> None:
        """Evict entries according to strategy if cache is full."""
        cache = self._caches[category]
        
        if len(cache) < self._max_size:
            return

        # First pass: remove expired entries
        expired = [k for k, v in cache.items() if v.is_expired()]
        for key in expired:
            del cache[key]
            self._stats['expirations'] += 1

        if len(cache) < self._max_size:
            return

        # Second pass: evict according to strategy
        entries = list(cache.items())
        
        if self._strategy == CacheStrategy.LRU:
            entries.sort(key=lambda x: x[1].last_accessed)
        elif self._strategy == CacheStrategy.LFU:
            entries.sort(key=lambda x: x[1].access_count)
        elif self._strategy == CacheStrategy.FIFO:
            entries.sort(key=lambda x: x[1].created_at)
        # TTL strategy already handled in first pass

        if entries:
            key_to_remove, _ = entries[0]
            del cache[key_to_remove]
            self._stats['evictions'] += 1

    def put(
        self,
        content: str,
        threat_category: ThreatCategory,
        detection_result: Dict[str, Any],
        confidence_score: float,
        ttl_seconds: Optional[int] = None
    ) -> str:
        """
        Store threat detection result in cache.
        Returns the computed semantic hash.
        """
        if not self._enabled:
            return ""

        with self._lock:
            hashes = SemanticHasher.compute_multi_hash(content)
            semantic_hash = hashes['semantic']
            
            entry = CacheEntry(
                semantic_hash=semantic_hash,
                threat_category=threat_category,
                detection_result=detection_result,
                confidence_score=confidence_score,
                ttl_seconds=ttl_seconds or self._default_ttl
            )
            
            self._evict_if_needed(threat_category)
            self._caches[threat_category][semantic_hash] = entry
            
            return semantic_hash

    def get(
        self,
        content: str,
        threat_category: Optional[ThreatCategory] = None
    ) -> Optional[CacheEntry]:
        """
        Retrieve cached detection result.
        Returns None if not found or disabled.
        """
        if not self._enabled:
            return None

        with self._lock:
            hashes = SemanticHasher.compute_multi_hash(content)
            target_hash = hashes['semantic']
            
            categories = [threat_category] if threat_category else list(ThreatCategory)
            
            for category in categories:
                cache = self._caches[category]
                
                # Exact match first
                if target_hash in cache:
                    entry = cache[target_hash]
                    if entry.is_expired():
                        del cache[target_hash]
                        self._stats['expirations'] += 1
                        continue
                    
                    # Update access (immutable pattern)
                    cache[target_hash] = entry.with_updated_access()
                    self._stats['hits'] += 1
                    
                    if self._on_cache_hit:
                        self._on_cache_hit(content, entry)
                    
                    return entry
                
                # Semantic similarity match
                for key, entry in cache.items():
                    if not entry.is_expired():
                        similarity = SemanticHasher.hash_similarity(target_hash, key)
                        if similarity >= self._similarity_threshold:
                            self._stats['hits'] += 1
                            self._stats['semantic_hits'] += 1
                            return entry

            self._stats['misses'] += 1
            if self._on_cache_miss:
                self._on_cache_miss(content)
            
            return None

    def get_or_compute(
        self,
        content: str,
        threat_category: ThreatCategory,
        compute_fn: Callable[[], Tuple[Dict[str, Any], float]],
        ttl_seconds: Optional[int] = None
    ) -> Tuple[Dict[str, Any], float, bool]:
        """
        Get from cache or compute and store result.
        Returns (result, confidence, was_cached)
        """
        cached = self.get(content, threat_category)
        if cached:
            return cached.detection_result, cached.confidence_score, True
        
        detection_result, confidence = compute_fn()
        self.put(content, threat_category, detection_result, confidence, ttl_seconds)
        
        return detection_result, confidence, False

    def get_statistics(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total = self._stats['hits'] + self._stats['misses']
            hit_rate = self._stats['hits'] / total if total > 0 else 0.0
            
            sizes = {cat.name: len(cache) for cat, cache in self._caches.items()}
            
            return {
                'enabled': self._enabled,
                'max_size': self._max_size,
                'strategy': self._strategy.value,
                'similarity_threshold': self._similarity_threshold,
                'hits': self._stats['hits'],
                'misses': self._stats['misses'],
                'semantic_hits': self._stats['semantic_hits'],
                'evictions': self._stats['evictions'],
                'expirations': self._stats['expirations'],
                'hit_rate': hit_rate,
                'total_entries': sum(sizes.values()),
                'entries_by_category': sizes
            }

    def clear(self, category: Optional[ThreatCategory] = None) -> int:
        """Clear cache entries, returns count cleared."""
        with self._lock:
            if category:
                count = len(self._caches[category])
                self._caches[category].clear()
                return count
            else:
                total = 0
                for cat in self._caches:
                    total += len(self._caches[cat])
                    self._caches[cat].clear()
                return total

    def cleanup_expired(self) -> int:
        """Remove all expired entries, returns count removed."""
        with self._lock:
            removed = 0
            for category in ThreatCategory:
                cache = self._caches[category]
                expired = [k for k, v in cache.items() if v.is_expired()]
                for key in expired:
                    del cache[key]
                    removed += 1
                self._stats['expirations'] += removed
            return removed


# Default singleton instance (OPT-IN - disabled by default)
default_cache = ThreatIntelligenceSemanticCache(
    max_size=10000,
    strategy=CacheStrategy.LRU,
    default_ttl=3600,
    similarity_threshold=0.9,
    enabled=False
)
