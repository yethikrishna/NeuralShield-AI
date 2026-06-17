"""
Test suite for Threat Intelligence Auto-Updater
Production-grade tests with real assertions and edge case coverage.
"""

import json
import os
import tempfile
import time
import threading
from pathlib import Path

import pytest

from neural_shield.threat_intelligence_auto_updater_2026_june import (
    ThreatIntelligenceAutoUpdater,
    ThreatSignature,
    UpdateStatus,
    CacheEntry,
)


class TestThreatSignature:
    """Tests for ThreatSignature dataclass."""

    def test_signature_creation(self):
        """Test basic signature creation."""
        sig = ThreatSignature(
            signature_id="test-001",
            pattern="ignore previous instructions",
            threat_type="jailbreak",
            severity="high",
            confidence=0.95,
            created_at=time.time(),
        )
        
        assert sig.signature_id == "test-001"
        assert sig.pattern == "ignore previous instructions"
        assert sig.threat_type == "jailbreak"
        assert sig.severity == "high"
        assert sig.confidence == 0.95

    def test_signature_expiration(self):
        """Test TTL expiration logic."""
        current_time = time.time()
        sig = ThreatSignature(
            signature_id="test-002",
            pattern="test pattern",
            threat_type="injection",
            severity="medium",
            confidence=0.8,
            created_at=current_time - 4000,  # Created > 1 hour ago
            ttl_seconds=3600,
        )
        
        assert sig.is_expired(current_time) is True
        
        sig2 = ThreatSignature(
            signature_id="test-003",
            pattern="test pattern",
            threat_type="injection",
            severity="medium",
            confidence=0.8,
            created_at=current_time,
            ttl_seconds=3600,
        )
        assert sig2.is_expired(current_time) is False

    def test_signature_hashing(self):
        """Test consistent hashing for deduplication."""
        sig1 = ThreatSignature(
            signature_id="test-001",
            pattern="same pattern",
            threat_type="jailbreak",
            severity="high",
            confidence=0.9,
            created_at=time.time(),
        )
        
        sig2 = ThreatSignature(
            signature_id="test-002",  # Different ID
            pattern="same pattern",  # Same content
            threat_type="jailbreak",
            severity="high",
            confidence=0.9,
            created_at=time.time(),
        )
        
        assert sig1.compute_hash() == sig2.compute_hash()


class TestThreatIntelligenceAutoUpdater:
    """Tests for the main Auto-Updater class."""

    def setup_method(self):
        """Setup temporary directory for each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.updater = ThreatIntelligenceAutoUpdater(
            cache_dir=self.temp_dir,
            refresh_interval_seconds=60,
            feeds=[],  # Empty feeds for testing
        )

    def teardown_method(self):
        """Cleanup."""
        if os.path.exists(self.temp_dir):
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_initialization(self):
        """Test proper initialization."""
        assert self.updater is not None
        assert len(self.updater.signature_cache) == 0
        assert self.updater.refresh_interval == 60

    def test_add_local_signatures(self):
        """Test adding local signatures programmatically."""
        test_signatures = [
            {
                "pattern": "ignore all previous instructions",
                "type": "jailbreak",
                "severity": "critical",
                "confidence": 0.98,
            },
            {
                "pattern": "<script>alert('xss')</script>",
                "type": "injection",
                "severity": "high",
                "confidence": 0.9,
            },
        ]
        
        new_count = self.updater.add_local_signatures(test_signatures, source="test")
        
        assert new_count == 2
        assert len(self.updater.signature_cache) == 2

    def test_deduplication(self):
        """Test that duplicate signatures are not added."""
        # Create fresh updater for this test
        import tempfile
        temp_dir = tempfile.mkdtemp()
        updater = ThreatIntelligenceAutoUpdater(
            cache_dir=temp_dir,
            feeds=[],
        )
        
        test_signatures = [
            {
                "pattern": "duplicate pattern",
                "type": "jailbreak",
                "severity": "high",
                "confidence": 0.9,
            },
        ]
        
        # Add same signature twice
        count1 = updater.add_local_signatures(test_signatures)
        count2 = updater.add_local_signatures(test_signatures)
        
        assert count1 == 1
        assert count2 == 0  # Should be deduplicated
        assert len(updater.signature_cache) == 1

    def test_get_active_signatures(self):
        """Test filtering active signatures."""
        # Create fresh updater
        import tempfile
        temp_dir = tempfile.mkdtemp()
        updater = ThreatIntelligenceAutoUpdater(
            cache_dir=temp_dir,
            feeds=[],
        )
        
        # Add some signatures
        test_sigs = [
            {"pattern": "sig1", "type": "jailbreak", "severity": "high", "confidence": 0.9},
            {"pattern": "sig2", "type": "injection", "severity": "medium", "confidence": 0.8},
            {"pattern": "sig3", "type": "jailbreak", "severity": "critical", "confidence": 0.95},
        ]
        
        updater.add_local_signatures(test_sigs)
        
        # Test filtering by type
        jailbreak_sigs = updater.get_active_signatures(threat_type="jailbreak")
        assert len(jailbreak_sigs) == 2
        
        # Test filtering by severity
        critical_sigs = updater.get_active_signatures(min_severity="critical")
        assert len(critical_sigs) == 1
        
        # Test combined filter
        combined = updater.get_active_signatures(threat_type="jailbreak", min_severity="high")
        assert len(combined) == 2

    def test_clean_expired_signatures(self):
        """Test automatic cleanup of expired signatures."""
        # Add an expired signature manually
        from neural_shield.threat_intelligence_auto_updater_2026_june import ThreatSignature, CacheEntry
        
        expired_sig = ThreatSignature(
            signature_id="expired-001",
            pattern="old pattern",
            threat_type="jailbreak",
            severity="high",
            confidence=0.9,
            created_at=time.time() - 10000,  # Way past TTL
            ttl_seconds=3600,
        )
        
        with self.updater._lock:
            self.updater.signature_cache["expired-001"] = CacheEntry(
                signature=expired_sig,
                last_updated=time.time() - 10000,
            )
        
        initial_count = len(self.updater.signature_cache)
        removed = self.updater._clean_expired_signatures()
        
        assert removed == 1
        assert len(self.updater.signature_cache) == initial_count - 1

    def test_cache_stats(self):
        """Test cache statistics reporting."""
        # Add some signatures
        test_sigs = [
            {"pattern": "sig1", "type": "jailbreak", "severity": "high", "confidence": 0.9},
            {"pattern": "sig2", "type": "injection", "severity": "medium", "confidence": 0.8},
        ]
        self.updater.add_local_signatures(test_sigs)
        
        stats = self.updater.get_cache_stats()
        
        assert stats["total_signatures"] == 2
        assert stats["active_signatures"] == 2
        assert stats["expired_signatures"] == 0
        assert stats["feeds_configured"] == 0

    def test_persistence(self):
        """Test that signatures persist to disk."""
        test_sigs = [
            {"pattern": "persist-test", "type": "jailbreak", "severity": "high", "confidence": 0.9},
        ]
        self.updater.add_local_signatures(test_sigs)
        self.updater._persist_signatures()
        
        # Create new updater instance to load persisted data
        updater2 = ThreatIntelligenceAutoUpdater(
            cache_dir=self.temp_dir,
            feeds=[],
        )
        
        # Should have loaded the persisted signature
        assert len(updater2.signature_cache) >= 1

    def test_update_now_empty_feeds(self):
        """Test update_now with no configured feeds."""
        result = self.updater.update_now()
        
        assert result["status"] == UpdateStatus.OFFLINE_FALLBACK.value
        assert result["new_signatures"] == 0
        assert result["offline_mode"] is True

    def test_context_manager(self):
        """Test context manager usage."""
        with ThreatIntelligenceAutoUpdater(cache_dir=self.temp_dir, feeds=[]) as updater:
            assert updater._update_thread is not None
            assert updater._update_thread.is_alive()
        
        # Give thread time to stop
        time.sleep(0.1)
        assert not updater._update_thread.is_alive()

    def test_callback_registration(self):
        """Test update callback registration."""
        callback_called = []
        
        def callback(status, new_count):
            callback_called.append((status, new_count))
        
        self.updater.register_update_callback(callback)
        self.updater.update_now()
        
        assert len(callback_called) == 1
        assert callback_called[0][0] == UpdateStatus.OFFLINE_FALLBACK


class TestIntegration:
    """Integration tests."""

    def test_full_workflow(self):
        """Test complete workflow: add signatures, query, update."""
        temp_dir = tempfile.mkdtemp()
        
        try:
            updater = ThreatIntelligenceAutoUpdater(
                cache_dir=temp_dir,
                refresh_interval_seconds=1,
                feeds=[],
            )
            
            # Add signatures
            sigs = [
                {"pattern": "ignore system prompt", "type": "jailbreak", "severity": "critical", "confidence": 0.99},
                {"pattern": "DAN prompt", "type": "jailbreak", "severity": "high", "confidence": 0.95},
            ]
            added = updater.add_local_signatures(sigs)
            assert added == 2
            
            # Query signatures
            active = updater.get_active_signatures()
            assert len(active) == 2
            
            # Get stats
            stats = updater.get_cache_stats()
            assert stats["total_signatures"] == 2
            
            # Force update
            result = updater.update_now()
            assert result["total_signatures"] == 2
            
        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    # Run tests
    print("Running Threat Intelligence Auto-Updater tests...")
    
    # Run signature tests
    print("\n1. Testing ThreatSignature class...")
    sig_test = TestThreatSignature()
    sig_test.test_signature_creation()
    sig_test.test_signature_expiration()
    sig_test.test_signature_hashing()
    print("   ✓ All ThreatSignature tests passed")
    
    # Run updater tests
    print("\n2. Testing AutoUpdater class...")
    updater_test = TestThreatIntelligenceAutoUpdater()
    updater_test.setup_method()
    updater_test.test_initialization()
    updater_test.test_add_local_signatures()
    updater_test.test_deduplication()
    updater_test.test_get_active_signatures()
    updater_test.test_clean_expired_signatures()
    updater_test.test_cache_stats()
    updater_test.test_persistence()
    updater_test.test_update_now_empty_feeds()
    updater_test.test_callback_registration()
    updater_test.teardown_method()
    print("   ✓ All AutoUpdater tests passed")
    
    # Integration test
    print("\n3. Running integration test...")
    int_test = TestIntegration()
    int_test.test_full_workflow()
    print("   ✓ Integration test passed")
    
    print("\n✅ All tests passed successfully!")
