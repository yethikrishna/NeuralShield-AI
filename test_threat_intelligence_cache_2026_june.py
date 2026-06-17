"""
Test suite for Threat Intelligence Cache
June 2026 - Production Grade Tests

Verifies all cache functionality works correctly.
"""

import unittest
import time
import threading
from neural_shield.threat_intelligence_cache_2026_june import (
    ThreatIntelligenceCache,
    CacheEntryStatus,
    CacheEntry
)


class TestThreatIntelligenceCache(unittest.TestCase):
    """Test suite for ThreatIntelligenceCache"""

    def setUp(self):
        """Set up test cache with short TTL for testing"""
        self.cache = ThreatIntelligenceCache(
            default_ttl_seconds=2,
            max_capacity=100,
            cleanup_interval_seconds=1
        )

    def tearDown(self):
        """Clean up after tests"""
        self.cache.shutdown()

    def test_basic_set_get(self):
        """Test basic set and get operations"""
        # Set value
        self.cache.set("threat:ip:192.168.1.1", {"risk": "high", "score": 0.95})
        
        # Get value
        result = self.cache.get("threat:ip:192.168.1.1")
        
        # Verify
        self.assertIsNotNone(result)
        self.assertEqual(result["risk"], "high")
        self.assertEqual(result["score"], 0.95)

    def test_get_missing_key(self):
        """Test get with non-existent key returns None"""
        result = self.cache.get("nonexistent:key")
        self.assertIsNone(result)

    def test_get_with_default(self):
        """Test get with default value"""
        result = self.cache.get("nonexistent:key", default={"risk": "unknown"})
        self.assertEqual(result["risk"], "unknown")

    def test_ttl_expiration(self):
        """Test TTL expiration works correctly"""
        # Set with very short TTL
        self.cache.set("expiring:key", "test_value", ttl_seconds=1)
        
        # Should exist immediately
        self.assertIsNotNone(self.cache.get("expiring:key"))
        
        # Wait for expiration
        time.sleep(1.2)
        
        # Should be gone
        result = self.cache.get("expiring:key")
        self.assertIsNone(result)

    def test_delete(self):
        """Test delete operation"""
        self.cache.set("to:delete", "value")
        self.assertIn("to:delete", self.cache)
        
        result = self.cache.delete("to:delete")
        self.assertTrue(result)
        self.assertNotIn("to:delete", self.cache)

    def test_delete_nonexistent(self):
        """Test delete on non-existent key"""
        result = self.cache.delete("does:not:exist")
        self.assertFalse(result)

    def test_clear(self):
        """Test clear all entries"""
        for i in range(10):
            self.cache.set(f"key:{i}", f"value:{i}")
        
        self.assertEqual(len(self.cache), 10)
        self.cache.clear()
        self.assertEqual(len(self.cache), 0)

    def test_get_or_set(self):
        """Test get_or_set with loader function"""
        call_count = [0]
        
        def loader():
            call_count[0] += 1
            return {"loaded": True, "count": call_count[0]}
        
        # First call - should load
        result1 = self.cache.get_or_set("loader:test", loader)
        self.assertEqual(result1["count"], 1)
        
        # Second call - should use cache
        result2 = self.cache.get_or_set("loader:test", loader)
        self.assertEqual(result2["count"], 1)  # Still 1, loader not called
        self.assertEqual(call_count[0], 1)

    def test_len(self):
        """Test __len__ method"""
        self.assertEqual(len(self.cache), 0)
        
        for i in range(5):
            self.cache.set(f"len:test:{i}", i)
        
        self.assertEqual(len(self.cache), 5)

    def test_contains(self):
        """Test __contains__ method"""
        self.cache.set("contains:test", "value")
        
        self.assertTrue("contains:test" in self.cache)
        self.assertFalse("not:contains" in self.cache)

    def test_cache_stats(self):
        """Test statistics tracking"""
        # Some hits and misses
        self.cache.set("stats:test", "value")
        self.cache.get("stats:test")  # Hit
        self.cache.get("stats:test")  # Hit
        self.cache.get("stats:missing")  # Miss
        
        stats = self.cache.get_stats()
        
        self.assertEqual(stats["hits"], 2)
        self.assertEqual(stats["misses"], 1)
        self.assertEqual(stats["total_entries"], 1)
        self.assertGreater(stats["hit_rate_percent"], 0)

    def test_entry_status(self):
        """Test entry status detection"""
        # Valid entry
        self.cache.set("status:valid", "value", ttl_seconds=10)
        self.assertEqual(
            self.cache.get_entry_status("status:valid"),
            CacheEntryStatus.VALID
        )
        
        # Missing entry
        self.assertIsNone(self.cache.get_entry_status("status:missing"))

    def test_lru_eviction(self):
        """Test LRU eviction when capacity exceeded"""
        small_cache = ThreatIntelligenceCache(
            default_ttl_seconds=60,
            max_capacity=5
        )
        
        try:
            # Fill cache
            for i in range(5):
                small_cache.set(f"lru:{i}", f"value:{i}")
            
            self.assertEqual(len(small_cache), 5)
            
            # Access first few to make them "recent"
            small_cache.get("lru:0")
            small_cache.get("lru:1")
            
            # Add one more - should trigger eviction
            small_cache.set("lru:new", "new_value")
            
            # Should still be at capacity
            self.assertEqual(len(small_cache), 5)
            
            # Recently accessed should still exist
            self.assertIsNotNone(small_cache.get("lru:0"))
            self.assertIsNotNone(small_cache.get("lru:1"))
        finally:
            small_cache.shutdown()

    def test_generate_key_deterministic(self):
        """Test key generation is deterministic"""
        key1 = ThreatIntelligenceCache._generate_key("ip", "192.168.1.1", port=80)
        key2 = ThreatIntelligenceCache._generate_key("ip", "192.168.1.1", port=80)
        
        self.assertEqual(key1, key2)

    def test_thread_safety(self):
        """Test thread safety with concurrent access"""
        threads = []
        errors = []
        
        def worker(thread_id):
            try:
                for i in range(50):
                    key = f"thread:{thread_id}:{i}"
                    self.cache.set(key, f"value:{thread_id}:{i}")
                    result = self.cache.get(key)
                    assert result == f"value:{thread_id}:{i}"
            except Exception as e:
                errors.append(e)
        
        for t in range(5):
            thread = threading.Thread(target=worker, args=(t,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        self.assertEqual(len(errors), 0, f"Thread safety errors: {errors}")

    def test_cleanup_expired(self):
        """Test manual cleanup of expired entries"""
        # Add some expiring entries
        self.cache.set("cleanup:1", "v1", ttl_seconds=1)
        self.cache.set("cleanup:2", "v2", ttl_seconds=3600)  # Long TTL
        
        time.sleep(1.2)
        
        removed = self.cache.cleanup_expired()
        self.assertEqual(removed, 1)
        self.assertEqual(len(self.cache), 1)


if __name__ == "__main__":
    print("Running Threat Intelligence Cache Tests...")
    unittest.main(verbosity=2)
