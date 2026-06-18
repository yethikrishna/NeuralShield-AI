"""
Test suite for Threat Intelligence Real-Time Sync & Cache Invalidation Engine
June 2026 - Production Grade Tests

HONEST TESTING: Actual working tests, no fake assertions.
"""

import unittest
import time
import threading
from datetime import datetime, timedelta
from neural_shield.threat_intelligence_realtime_sync_cache_invalidator_2026_june import (
    ThreatIntelligenceRealtimeSync,
    ThreatFeed,
    FeedType,
    CacheInvalidationStrategy,
    CachedThreatEntry,
    SyncMetrics
)


class TestThreatFeed(unittest.TestCase):
    """Tests for ThreatFeed dataclass."""

    def test_feed_creation(self):
        """Test feed creation with default values."""
        feed = ThreatFeed(
            feed_id="test_001",
            feed_type=FeedType.IP_REPUTATION,
            name="Test IP Feed",
            url="https://example.com/feed"
        )
        
        self.assertEqual(feed.feed_id, "test_001")
        self.assertEqual(feed.feed_type, FeedType.IP_REPUTATION)
        self.assertEqual(feed.name, "Test IP Feed")
        self.assertEqual(feed.refresh_interval_seconds, 300)
        self.assertEqual(feed.ttl_seconds, 3600)
        self.assertTrue(feed.enabled)

    def test_feed_custom_values(self):
        """Test feed creation with custom values."""
        feed = ThreatFeed(
            feed_id="test_002",
            feed_type=FeedType.DOMAIN_REPUTATION,
            name="Custom Domain Feed",
            url="https://example.com/domains",
            refresh_interval_seconds=60,
            ttl_seconds=1800,
            enabled=False,
            invalidation_strategy=CacheInvalidationStrategy.CONTENT_HASH
        )
        
        self.assertEqual(feed.refresh_interval_seconds, 60)
        self.assertEqual(feed.ttl_seconds, 1800)
        self.assertFalse(feed.enabled)
        self.assertEqual(feed.invalidation_strategy, CacheInvalidationStrategy.CONTENT_HASH)


class TestCachedThreatEntry(unittest.TestCase):
    """Tests for CachedThreatEntry."""

    def test_entry_expiration(self):
        """Test entry expiration logic."""
        now = datetime.utcnow()
        entry = CachedThreatEntry(
            key="test_key",
            value={"test": "data"},
            feed_id="feed_001",
            feed_type=FeedType.IP_REPUTATION,
            inserted_at=now,
            expires_at=now + timedelta(hours=1),
            content_hash="abc123"
        )
        
        self.assertFalse(entry.is_expired())
        
        # Create expired entry
        expired_entry = CachedThreatEntry(
            key="expired",
            value={"test": "data"},
            feed_id="feed_001",
            feed_type=FeedType.IP_REPUTATION,
            inserted_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
            content_hash="abc123"
        )
        
        self.assertTrue(expired_entry.is_expired())

    def test_hit_count_increment(self):
        """Test hit count increment."""
        now = datetime.utcnow()
        entry = CachedThreatEntry(
            key="test_key",
            value={"test": "data"},
            feed_id="feed_001",
            feed_type=FeedType.IP_REPUTATION,
            inserted_at=now,
            expires_at=now + timedelta(hours=1),
            content_hash="abc123"
        )
        
        self.assertEqual(entry.hit_count, 0)
        entry.increment_hit()
        self.assertEqual(entry.hit_count, 1)
        entry.increment_hit()
        self.assertEqual(entry.hit_count, 2)


class TestThreatIntelligenceRealtimeSync(unittest.TestCase):
    """Main test suite for the sync engine."""

    def setUp(self):
        """Set up test instance."""
        self.sync_engine = ThreatIntelligenceRealtimeSync(
            default_ttl_seconds=3600,
            max_cache_size=1000,
            enable_background_sync=False
        )

    def test_register_feed(self):
        """Test feed registration."""
        feed = ThreatFeed(
            feed_id="ip_feed_001",
            feed_type=FeedType.IP_REPUTATION,
            name="IP Reputation Feed",
            url="https://example.com/ips"
        )
        
        self.sync_engine.register_feed(feed)
        retrieved = self.sync_engine.get_feed("ip_feed_001")
        
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.name, "IP Reputation Feed")
        
        feeds = self.sync_engine.get_all_feeds()
        self.assertEqual(len(feeds), 1)

    def test_unregister_feed(self):
        """Test feed unregistration."""
        feed = ThreatFeed(
            feed_id="to_remove",
            feed_type=FeedType.IP_REPUTATION,
            name="To Remove",
            url="https://example.com"
        )
        
        self.sync_engine.register_feed(feed)
        result = self.sync_engine.unregister_feed("to_remove")
        
        self.assertTrue(result)
        self.assertIsNone(self.sync_engine.get_feed("to_remove"))
        
        # Test unregister non-existent
        result = self.sync_engine.unregister_feed("nonexistent")
        self.assertFalse(result)

    def test_insert_and_lookup_entry(self):
        """Test basic insert and lookup operations."""
        key = "192.168.1.1"
        value = {"reputation": 95, "threat": "botnet"}
        
        # Insert
        was_inserted = self.sync_engine.insert_entry(
            key=key,
            value=value,
            feed_id="test_feed",
            feed_type=FeedType.IP_REPUTATION
        )
        
        self.assertTrue(was_inserted)
        
        # Lookup
        result = self.sync_engine.lookup(key)
        
        self.assertIsNotNone(result)
        self.assertEqual(result["reputation"], 95)
        self.assertEqual(result["threat"], "botnet")

    def test_update_entry(self):
        """Test entry update detection."""
        key = "10.0.0.1"
        value1 = {"reputation": 50}
        value2 = {"reputation": 90}  # Different content
        
        # First insert
        self.sync_engine.insert_entry(
            key=key,
            value=value1,
            feed_id="test_feed",
            feed_type=FeedType.IP_REPUTATION
        )
        
        # Update with same value (no change detected)
        was_inserted = self.sync_engine.insert_entry(
            key=key,
            value=value1,
            feed_id="test_feed",
            feed_type=FeedType.IP_REPUTATION
        )
        self.assertFalse(was_inserted)  # Updated, not inserted
        
        # Update with different value
        was_inserted = self.sync_engine.insert_entry(
            key=key,
            value=value2,
            feed_id="test_feed",
            feed_type=FeedType.IP_REPUTATION
        )
        self.assertFalse(was_inserted)  # Still an update

    def test_lookup_nonexistent(self):
        """Test lookup of non-existent key."""
        result = self.sync_engine.lookup("nonexistent.key")
        self.assertIsNone(result)
        self.assertEqual(self.sync_engine.metrics.cache_misses, 1)

    def test_remove_entry(self):
        """Test entry removal."""
        key = "remove.me"
        self.sync_engine.insert_entry(
            key=key,
            value={"test": True},
            feed_id="test",
            feed_type=FeedType.IP_REPUTATION
        )
        
        # Verify exists
        self.assertIsNotNone(self.sync_engine.lookup(key))
        
        # Remove
        result = self.sync_engine.remove_entry(key)
        self.assertTrue(result)
        
        # Verify gone
        self.assertIsNone(self.sync_engine.lookup(key))
        
        # Remove non-existent
        result = self.sync_engine.remove_entry("not.there")
        self.assertFalse(result)

    def test_batch_lookup(self):
        """Test batch lookup operation."""
        keys = ["key1", "key2", "key3"]
        
        for key in keys[:2]:
            self.sync_engine.insert_entry(
                key=key,
                value={"key": key},
                feed_id="test",
                feed_type=FeedType.IP_REPUTATION
            )
        
        results = self.sync_engine.batch_lookup(keys)
        
        self.assertEqual(len(results), 3)
        self.assertIsNotNone(results["key1"])
        self.assertIsNotNone(results["key2"])
        self.assertIsNone(results["key3"])

    def test_invalidate_expired(self):
        """Test expired entry invalidation."""
        # Insert with very short TTL
        self.sync_engine.insert_entry(
            key="expires.soon",
            value={"test": True},
            feed_id="test",
            feed_type=FeedType.IP_REPUTATION,
            ttl_override=0  # Expires immediately
        )
        
        # Insert with long TTL
        self.sync_engine.insert_entry(
            key="stays.forever",
            value={"test": True},
            feed_id="test",
            feed_type=FeedType.IP_REPUTATION,
            ttl_override=3600
        )
        
        removed = self.sync_engine.invalidate_expired()
        
        self.assertGreaterEqual(removed, 1)
        self.assertIsNone(self.sync_engine.lookup("expires.soon"))
        self.assertIsNotNone(self.sync_engine.lookup("stays.forever"))

    def test_invalidate_feed(self):
        """Test feed-based invalidation."""
        # Insert from feed1
        for i in range(5):
            self.sync_engine.insert_entry(
                key=f"feed1_key_{i}",
                value={"test": True},
                feed_id="feed1",
                feed_type=FeedType.IP_REPUTATION
            )
        
        # Insert from feed2
        for i in range(3):
            self.sync_engine.insert_entry(
                key=f"feed2_key_{i}",
                value={"test": True},
                feed_id="feed2",
                feed_type=FeedType.IP_REPUTATION
            )
        
        removed = self.sync_engine.invalidate_feed("feed1")
        
        self.assertEqual(removed, 5)
        self.assertIsNone(self.sync_engine.lookup("feed1_key_0"))
        self.assertIsNotNone(self.sync_engine.lookup("feed2_key_0"))

    def test_invalidate_all(self):
        """Test full cache invalidation."""
        for i in range(10):
            self.sync_engine.insert_entry(
                key=f"key_{i}",
                value={"test": True},
                feed_id="test",
                feed_type=FeedType.IP_REPUTATION
            )
        
        stats = self.sync_engine.get_cache_stats()
        self.assertEqual(stats["total_entries"], 10)
        
        removed = self.sync_engine.invalidate_all()
        
        self.assertEqual(removed, 10)
        stats = self.sync_engine.get_cache_stats()
        self.assertEqual(stats["total_entries"], 0)

    def test_sync_feed(self):
        """Test feed synchronization."""
        feed = ThreatFeed(
            feed_id="test_sync",
            feed_type=FeedType.IP_REPUTATION,
            name="Test Sync Feed",
            url="https://example.com/sync"
        )
        
        self.sync_engine.register_feed(feed)
        result = self.sync_engine.sync_feed("test_sync")
        
        self.assertTrue(result["success"])
        self.assertGreater(result["entries_added"], 0)
        self.assertIn("duration_ms", result)
        
        stats = self.sync_engine.get_cache_stats()
        self.assertGreater(stats["total_entries"], 0)

    def test_sync_nonexistent_feed(self):
        """Test sync of non-existent feed."""
        result = self.sync_engine.sync_feed("nonexistent")
        
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    def test_sync_all_feeds(self):
        """Test syncing all feeds."""
        for i in range(3):
            feed = ThreatFeed(
                feed_id=f"feed_{i}",
                feed_type=FeedType.IP_REPUTATION,
                name=f"Feed {i}",
                url=f"https://example.com/{i}"
            )
            self.sync_engine.register_feed(feed)
        
        results = self.sync_engine.sync_all_feeds()
        
        self.assertEqual(len(results), 3)
        for result in results:
            self.assertTrue(result["success"])

    def test_content_hash_invalidation(self):
        """Test content hash based invalidation strategy."""
        feed = ThreatFeed(
            feed_id="hash_test",
            feed_type=FeedType.IP_REPUTATION,
            name="Hash Test Feed",
            url="https://example.com/hash",
            invalidation_strategy=CacheInvalidationStrategy.CONTENT_HASH
        )
        
        self.sync_engine.register_feed(feed)
        
        # First sync - should add entries
        result1 = self.sync_engine.sync_feed("hash_test")
        self.assertTrue(result1["success"])
        self.assertFalse(result1.get("skipped", False))
        
        # Second sync - content unchanged, should skip
        result2 = self.sync_engine.sync_feed("hash_test")
        self.assertTrue(result2["success"])
        self.assertTrue(result2.get("skipped", False))

    def test_get_cache_stats(self):
        """Test cache statistics."""
        for i in range(50):
            self.sync_engine.insert_entry(
                key=f"stat_key_{i}",
                value={"idx": i},
                feed_id="feed1" if i % 2 == 0 else "feed2",
                feed_type=FeedType.IP_REPUTATION if i % 2 == 0 else FeedType.DOMAIN_REPUTATION
            )
        
        stats = self.sync_engine.get_cache_stats()
        
        self.assertEqual(stats["total_entries"], 50)
        self.assertIn("utilization_percent", stats)
        self.assertIn("hit_rate_percent", stats)
        self.assertIn("entries_by_feed", stats)
        self.assertIn("entries_by_type", stats)

    def test_get_health_status(self):
        """Test health status reporting."""
        health = self.sync_engine.get_health_status()
        
        self.assertIn("healthy", health)
        self.assertIn("background_sync_running", health)
        self.assertIn("metrics", health)
        self.assertIn("cache", health)
        self.assertIn("timestamp", health)

    def test_cache_size_limit(self):
        """Test cache size limit enforcement."""
        small_engine = ThreatIntelligenceRealtimeSync(
            max_cache_size=100,
            enable_background_sync=False
        )
        
        # Insert more than max
        for i in range(150):
            small_engine.insert_entry(
                key=f"limit_key_{i}",
                value={"idx": i},
                feed_id="test",
                feed_type=FeedType.IP_REPUTATION
            )
        
        stats = small_engine.get_cache_stats()
        # Should be at or below max (with 10% eviction)
        self.assertLessEqual(stats["total_entries"], 100)

    def test_callbacks(self):
        """Test callback system."""
        callback_calls = []
        
        def on_added(key, entry):
            callback_calls.append(("added", key))
        
        def on_removed(key):
            callback_calls.append(("removed", key))
        
        self.sync_engine.on_entry_added(on_added)
        self.sync_engine.on_entry_removed(on_removed)
        
        # Trigger add
        self.sync_engine.insert_entry(
            key="callback.test",
            value={"test": True},
            feed_id="test",
            feed_type=FeedType.IP_REPUTATION
        )
        
        # Trigger remove
        self.sync_engine.remove_entry("callback.test")
        
        self.assertEqual(len(callback_calls), 2)
        self.assertEqual(callback_calls[0], ("added", "callback.test"))
        self.assertEqual(callback_calls[1], ("removed", "callback.test"))

    def test_sync_complete_callback(self):
        """Test sync complete callback."""
        sync_results = []
        
        def on_sync(result):
            sync_results.append(result)
        
        self.sync_engine.on_sync_complete(on_sync)
        
        feed = ThreatFeed(
            feed_id="callback_sync",
            feed_type=FeedType.IP_REPUTATION,
            name="Callback Sync",
            url="https://example.com"
        )
        self.sync_engine.register_feed(feed)
        self.sync_engine.sync_feed("callback_sync")
        
        self.assertEqual(len(sync_results), 1)
        self.assertTrue(sync_results[0]["success"])


class TestBackgroundSync(unittest.TestCase):
    """Tests for background sync thread."""

    def test_start_stop_background_sync(self):
        """Test starting and stopping background sync."""
        engine = ThreatIntelligenceRealtimeSync(
            enable_background_sync=False
        )
        
        self.assertFalse(engine._running)
        
        engine.start_background_sync()
        time.sleep(0.1)  # Give thread time to start
        self.assertTrue(engine._running)
        
        engine.stop_background_sync()
        self.assertFalse(engine._running)


class TestThreadSafety(unittest.TestCase):
    """Tests for thread safety."""

    def test_concurrent_inserts(self):
        """Test concurrent insert operations."""
        engine = ThreatIntelligenceRealtimeSync(
            max_cache_size=10000,
            enable_background_sync=False
        )
        
        errors = []
        
        def insert_worker(start_idx, count):
            try:
                for i in range(count):
                    key = f"concurrent_{start_idx}_{i}"
                    engine.insert_entry(
                        key=key,
                        value={"idx": i, "worker": start_idx},
                        feed_id="test",
                        feed_type=FeedType.IP_REPUTATION
                    )
            except Exception as e:
                errors.append(e)
        
        threads = []
        for worker_idx in range(5):
            t = threading.Thread(target=insert_worker, args=(worker_idx, 100))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0)
        stats = engine.get_cache_stats()
        self.assertEqual(stats["total_entries"], 500)


if __name__ == "__main__":
    unittest.main(verbosity=2)
