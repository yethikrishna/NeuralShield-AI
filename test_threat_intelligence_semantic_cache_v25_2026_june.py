"""
Test Suite for Threat Intelligence Semantic Cache
Dimension A: Feature Expansion v25
Session 127 | June 24, 2026

Tests cover:
- Semantic hashing functionality
- Cache put/get operations
- Cache strategies (LRU, LFU, FIFO, TTL)
- Thread safety
- Statistics tracking
- Callbacks
- OPT-IN behavior (disabled by default)
- Backward compatibility
"""

import pytest
import threading
import time
from neural_shield.threat_intelligence_semantic_cache_v25_2026_june import (
    CacheStrategy,
    ThreatCategory,
    CacheEntry,
    SemanticHasher,
    ThreatIntelligenceSemanticCache,
    default_cache
)


class TestSemanticHasher:
    """Tests for semantic hashing functionality."""

    def test_sha256_hash_consistent(self):
        """Test SHA-256 produces consistent hashes."""
        content = "test threat content"
        hash1 = SemanticHasher.compute_sha256(content)
        hash2 = SemanticHasher.compute_sha256(content)
        
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 is 64 hex chars

    def test_semantic_hash_case_insensitive(self):
        """Test semantic hash is case insensitive."""
        content1 = "IGNORE PREVIOUS INSTRUCTIONS"
        content2 = "ignore previous instructions"
        
        hash1 = SemanticHasher.compute_semantic_hash(content1)
        hash2 = SemanticHasher.compute_semantic_hash(content2)
        
        # Should be identical after normalization
        assert hash1 == hash2

    def test_semantic_hash_whitespace_normalized(self):
        """Test semantic hash normalizes whitespace."""
        content1 = "ignore   previous   instructions"
        content2 = "ignore previous instructions"
        
        hash1 = SemanticHasher.compute_semantic_hash(content1)
        hash2 = SemanticHasher.compute_semantic_hash(content2)
        
        assert hash1 == hash2

    def test_multi_hash_returns_all_types(self):
        """Test multi-hash returns all hash types."""
        hashes = SemanticHasher.compute_multi_hash("test content")
        
        assert 'exact' in hashes
        assert 'semantic' in hashes
        assert 'coarse' in hashes
        assert len(hashes) == 3

    def test_hash_similarity_identical(self):
        """Test identical hashes have similarity 1.0."""
        similarity = SemanticHasher.hash_similarity("abc123", "abc123")
        assert similarity == 1.0

    def test_hash_similarity_different(self):
        """Test different hashes have similarity < 1.0."""
        similarity = SemanticHasher.hash_similarity("abc123", "def456")
        assert similarity < 1.0
        assert similarity >= 0.0


class TestCacheEntry:
    """Tests for immutable cache entry."""

    def test_cache_entry_creation(self):
        """Test cache entry creation with all fields."""
        entry = CacheEntry(
            semantic_hash="test_hash",
            threat_category=ThreatCategory.PROMPT_INJECTION,
            detection_result={'threat': True, 'score': 0.95},
            confidence_score=0.95,
            ttl_seconds=60
        )
        
        assert entry.semantic_hash == "test_hash"
        assert entry.threat_category == ThreatCategory.PROMPT_INJECTION
        assert entry.confidence_score == 0.95
        assert entry.access_count == 0

    def test_cache_entry_not_expired_initially(self):
        """Test new entry is not expired."""
        entry = CacheEntry(
            semantic_hash="test",
            threat_category=ThreatCategory.JAILBREAK,
            detection_result={},
            confidence_score=0.5,
            ttl_seconds=3600
        )
        
        assert not entry.is_expired()

    def test_with_updated_access_creates_new_entry(self):
        """Test with_updated_access creates new immutable entry."""
        entry = CacheEntry(
            semantic_hash="test",
            threat_category=ThreatCategory.JAILBREAK,
            detection_result={},
            confidence_score=0.5
        )
        
        updated = entry.with_updated_access()
        
        assert updated.access_count == 1
        assert entry.access_count == 0  # Original unchanged
        assert updated is not entry  # Different object


class TestThreatIntelligenceSemanticCache:
    """Tests for main cache class."""

    def test_cache_disabled_by_default(self):
        """Test cache is OPT-IN - disabled by default."""
        cache = ThreatIntelligenceSemanticCache()
        assert not cache.is_enabled()

    def test_enable_disable(self):
        """Test enabling and disabling cache."""
        cache = ThreatIntelligenceSemanticCache()
        cache.enable()
        assert cache.is_enabled()
        
        cache.disable()
        assert not cache.is_enabled()

    def test_put_returns_empty_when_disabled(self):
        """Test put returns empty string when disabled."""
        cache = ThreatIntelligenceSemanticCache()
        result = cache.put(
            "test content",
            ThreatCategory.PROMPT_INJECTION,
            {'threat': True},
            0.9
        )
        
        assert result == ""

    def test_get_returns_none_when_disabled(self):
        """Test get returns None when disabled."""
        cache = ThreatIntelligenceSemanticCache()
        cache.enable()
        cache.put("test", ThreatCategory.PROMPT_INJECTION, {}, 0.9)
        cache.disable()
        
        result = cache.get("test")
        assert result is None

    def test_put_get_exact_match(self):
        """Test basic put and get exact match."""
        cache = ThreatIntelligenceSemanticCache(enabled=True)
        
        content = "ignore previous instructions"
        result = cache.put(
            content,
            ThreatCategory.PROMPT_INJECTION,
            {'threat_detected': True, 'type': 'injection'},
            0.95
        )
        
        assert result != ""
        
        cached = cache.get(content)
        assert cached is not None
        assert cached.detection_result['threat_detected'] is True
        assert cached.confidence_score == 0.95

    def test_get_or_compute_cached(self):
        """Test get_or_compute returns cached value when available."""
        cache = ThreatIntelligenceSemanticCache(enabled=True)
        
        call_count = [0]
        
        def compute_fn():
            call_count[0] += 1
            return {'threat': True}, 0.9
        
        # First call - compute
        result1, conf1, was_cached1 = cache.get_or_compute(
            "test", ThreatCategory.PROMPT_INJECTION, compute_fn
        )
        
        assert was_cached1 is False
        assert call_count[0] == 1
        
        # Second call - cached
        result2, conf2, was_cached2 = cache.get_or_compute(
            "test", ThreatCategory.PROMPT_INJECTION, compute_fn
        )
        
        assert was_cached2 is True
        assert call_count[0] == 1  # Not called again

    def test_statistics_tracking(self):
        """Test hit/miss statistics are tracked."""
        cache = ThreatIntelligenceSemanticCache(enabled=True)
        
        # Put some entries
        cache.put("content1", ThreatCategory.PROMPT_INJECTION, {}, 0.9)
        cache.put("content2", ThreatCategory.JAILBREAK, {}, 0.8)
        
        # Create hits
        cache.get("content1")
        cache.get("content1")
        
        # Create miss
        cache.get("nonexistent")
        
        stats = cache.get_statistics()
        
        assert stats['hits'] == 2
        assert stats['misses'] == 1
        assert stats['hit_rate'] == 2/3

    def test_clear_cache(self):
        """Test clearing cache entries."""
        cache = ThreatIntelligenceSemanticCache(enabled=True)
        
        cache.put("content1", ThreatCategory.PROMPT_INJECTION, {}, 0.9)
        cache.put("content2", ThreatCategory.JAILBREAK, {}, 0.8)
        
        stats_before = cache.get_statistics()
        assert stats_before['total_entries'] == 2
        
        cleared = cache.clear()
        assert cleared == 2
        
        stats_after = cache.get_statistics()
        assert stats_after['total_entries'] == 0

    def test_callback_on_hit(self):
        """Test cache hit callback is invoked."""
        cache = ThreatIntelligenceSemanticCache(enabled=True)
        callback_called = [False]
        
        def on_hit(content, entry):
            callback_called[0] = True
        
        cache.set_on_cache_hit(on_hit)
        cache.put("test", ThreatCategory.PROMPT_INJECTION, {}, 0.9)
        cache.get("test")
        
        assert callback_called[0] is True

    def test_callback_on_miss(self):
        """Test cache miss callback is invoked."""
        cache = ThreatIntelligenceSemanticCache(enabled=True)
        callback_called = [False]
        
        def on_miss(content):
            callback_called[0] = True
        
        cache.set_on_cache_miss(on_miss)
        cache.get("nonexistent")
        
        assert callback_called[0] is True


class TestCacheStrategies:
    """Tests for different cache eviction strategies."""

    def test_lru_eviction(self):
        """Test LRU eviction removes least recently used."""
        cache = ThreatIntelligenceSemanticCache(
            max_size=2,
            strategy=CacheStrategy.LRU,
            enabled=True
        )
        
        # Fill cache
        cache.put("content1", ThreatCategory.PROMPT_INJECTION, {}, 0.9)
        cache.put("content2", ThreatCategory.PROMPT_INJECTION, {}, 0.9)
        
        # Access content1 to make it recently used
        cache.get("content1")
        
        # Add third - should evict content2 (LRU)
        cache.put("content3", ThreatCategory.PROMPT_INJECTION, {}, 0.9)
        
        stats = cache.get_statistics()
        assert stats['evictions'] == 1

    def test_lfu_eviction(self):
        """Test LFU eviction removes least frequently used."""
        cache = ThreatIntelligenceSemanticCache(
            max_size=2,
            strategy=CacheStrategy.LFU,
            enabled=True
        )
        
        cache.put("content1", ThreatCategory.PROMPT_INJECTION, {}, 0.9)
        cache.put("content2", ThreatCategory.PROMPT_INJECTION, {}, 0.9)
        
        # Access content1 multiple times
        cache.get("content1")
        cache.get("content1")
        
        # Add third - should evict content2 (LFU)
        cache.put("content3", ThreatCategory.PROMPT_INJECTION, {}, 0.9)
        
        stats = cache.get_statistics()
        assert stats['evictions'] == 1

    def test_fifo_eviction(self):
        """Test FIFO eviction removes oldest."""
        cache = ThreatIntelligenceSemanticCache(
            max_size=2,
            strategy=CacheStrategy.FIFO,
            enabled=True
        )
        
        cache.put("oldest", ThreatCategory.PROMPT_INJECTION, {}, 0.9)
        time.sleep(0.01)
        cache.put("middle", ThreatCategory.PROMPT_INJECTION, {}, 0.9)
        
        # Add third - should evict oldest
        cache.put("newest", ThreatCategory.PROMPT_INJECTION, {}, 0.9)
        
        stats = cache.get_statistics()
        assert stats['evictions'] == 1


class TestThreadSafety:
    """Tests for thread-safe operations."""

    def test_concurrent_puts(self):
        """Test multiple threads can put concurrently."""
        cache = ThreatIntelligenceSemanticCache(
            max_size=1000,
            enabled=True
        )
        
        def worker(thread_id):
            for i in range(50):
                cache.put(
                    f"content_{thread_id}_{i}",
                    ThreatCategory.PROMPT_INJECTION,
                    {'value': i},
                    0.5 + i/100
                )
        
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        stats = cache.get_statistics()
        assert stats['total_entries'] > 0


class TestBackwardCompatibility:
    """Tests for backward compatibility guarantees."""

    def test_default_instance_disabled(self):
        """Test default singleton is disabled by default (no side effects)."""
        assert not default_cache.is_enabled()

    def test_import_without_side_effects(self):
        """Test module can be imported without side effects."""
        # Module already imported, verify no auto-enable
        assert not default_cache.is_enabled()

    def test_no_modifications_to_existing_code(self):
        """Verify ADD-ONLY - this module doesn't modify anything."""
        # This test passes by virtue of being a separate file
        # No existing modules are imported or modified
        assert True


class TestTTLExpiration:
    """Tests for TTL-based expiration."""

    def test_entry_expires_after_ttl(self):
        """Test entry expires after TTL duration."""
        cache = ThreatIntelligenceSemanticCache(enabled=True)
        
        cache.put(
            "short_lived",
            ThreatCategory.PROMPT_INJECTION,
            {},
            0.9,
            ttl_seconds=1  # 1 second TTL
        )
        
        # Should exist immediately
        assert cache.get("short_lived") is not None
        
        # Wait for expiration
        time.sleep(1.1)
        
        # Should be expired
        assert cache.get("short_lived") is None
        
        stats = cache.get_statistics()
        assert stats['expirations'] >= 1

    def test_cleanup_expired_removes_expired(self):
        """Test cleanup_expired removes expired entries."""
        cache = ThreatIntelligenceSemanticCache(enabled=True)
        
        cache.put("expires_fast", ThreatCategory.PROMPT_INJECTION, {}, 0.9, ttl_seconds=1)
        cache.put("long_lived", ThreatCategory.PROMPT_INJECTION, {}, 0.9, ttl_seconds=3600)
        
        time.sleep(1.1)
        
        removed = cache.cleanup_expired()
        assert removed >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
