#!/usr/bin/env python3
"""
Test suite for NeuralShield AI - Threat Intelligence Threat Feed Deduplicator
REAL tests, not placeholder tests.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from datetime import datetime, timedelta
from threat_intelligence_threat_feed_deduplicator_2026_june import (
    ThreatFeedDeduplicator,
    IOCEntry,
    normalize_ioc,
    detect_ioc_type,
    deduplicate_feeds
)


def test_normalize_ioc():
    """Test IOC normalization logic"""
    print("Testing normalize_ioc...")
    
    # IP normalization
    assert normalize_ioc("192.168.001.001", "ip") == "192.168.1.1"
    assert normalize_ioc("  8.8.8.8  ", "ip") == "8.8.8.8"
    
    # Domain normalization
    assert normalize_ioc("WWW.EXAMPLE.COM", "domain") == "example.com"
    assert normalize_ioc("example.com.", "domain") == "example.com"
    assert normalize_ioc("  sub.EXAMPLE.COM  ", "domain") == "sub.example.com"
    
    # URL normalization
    assert normalize_ioc("HTTPS://EXAMPLE.COM/path/", "url") == "example.com/path"
    assert normalize_ioc("http://test.com?param=1", "url") == "test.com"
    
    # Hash normalization
    assert normalize_ioc("A1B2C3D4E5F6", "hash") == "a1b2c3d4e5f6"
    
    print("  ✓ normalize_ioc tests passed")


def test_detect_ioc_type():
    """Test IOC type detection"""
    print("Testing detect_ioc_type...")
    
    assert detect_ioc_type("192.168.1.1") == "ip"
    assert detect_ioc_type("example.com") == "domain"
    assert detect_ioc_type("https://evil.com/malware.exe") == "url"
    assert detect_ioc_type("5d41402abc4b2a76b9719d911017c592") == "hash"  # MD5
    assert detect_ioc_type("user@evil.com") == "email"
    
    print("  ✓ detect_ioc_type tests passed")


def test_ioc_entry():
    """Test IOCEntry data class"""
    print("Testing IOCEntry...")
    
    now = datetime.utcnow()
    ioc = IOCEntry(
        ioc_value="192.168.1.1",
        ioc_type="ip",
        source_feed="feed_a",
        first_seen=now,
        last_seen=now,
        confidence=0.8,
        severity="high",
        tags=["malware", "c2"]
    )
    
    key = ioc.get_normalized_key()
    assert key == "ip:192.168.1.1"
    assert len(ioc.get_hash()) == 16
    
    print("  ✓ IOCEntry tests passed")


def test_single_feed_deduplication():
    """Test deduplication within a single feed"""
    print("Testing single feed deduplication...")
    
    deduplicator = ThreatFeedDeduplicator()
    now = datetime.utcnow()
    
    # Create duplicate IOCs
    iocs = [
        IOCEntry("192.168.1.1", "ip", "feed1", now, now, 0.8, "high"),
        IOCEntry("192.168.1.1", "ip", "feed1", now, now, 0.7, "medium"),  # duplicate
        IOCEntry("10.0.0.1", "ip", "feed1", now, now, 0.9, "critical"),
    ]
    
    stats = deduplicator.process_batch(iocs)
    
    assert stats["total_input"] == 3
    assert stats["unique_iocs"] == 2
    assert stats["duplicates_removed"] == 1
    assert deduplicator.duplicate_count == 1
    
    print("  ✓ Single feed deduplication tests passed")


def test_cross_feed_deduplication():
    """Test deduplication across multiple feeds"""
    print("Testing cross-feed deduplication...")
    
    deduplicator = ThreatFeedDeduplicator()
    now = datetime.utcnow()
    
    # Same IOC from different feeds
    iocs = [
        IOCEntry("evil.com", "domain", "feed_a", now, now, 0.6, "medium"),
        IOCEntry("evil.com", "domain", "feed_b", now, now, 0.9, "high"),
        IOCEntry("EVIL.COM", "domain", "feed_c", now, now, 0.7, "medium"),  # case variant
    ]
    
    stats = deduplicator.process_batch(iocs)
    
    assert stats["total_input"] == 3
    assert stats["unique_iocs"] == 1
    assert stats["duplicates_removed"] == 2
    
    # Check merged IOC has highest confidence and severity
    unique = deduplicator.get_unique_iocs()[0]
    assert unique.confidence == 0.9  # highest
    assert unique.severity == "high"  # highest
    
    # Check cross-source detection
    cross_source = deduplicator.get_cross_source_iocs(min_sources=2)
    assert len(cross_source) == 1
    
    print("  ✓ Cross-feed deduplication tests passed")


def test_merge_strategy():
    """Test intelligent IOC merging strategy"""
    print("Testing merge strategy...")
    
    deduplicator = ThreatFeedDeduplicator()
    now = datetime.utcnow()
    earlier = now - timedelta(hours=24)
    later = now + timedelta(hours=24)
    
    ioc1 = IOCEntry(
        "test.com", "domain", "feed1",
        earlier, now, 0.5, "low",
        tags=["tag1"]
    )
    ioc2 = IOCEntry(
        "test.com", "domain", "feed2",
        now, later, 0.9, "high",
        tags=["tag2"]
    )
    
    deduplicator.process_ioc(ioc1)
    is_new, merged = deduplicator.process_ioc(ioc2)
    
    assert not is_new
    assert merged.first_seen == earlier  # earliest
    assert merged.last_seen == later     # latest
    assert merged.confidence == 0.9      # highest
    assert merged.severity == "high"     # highest
    assert "tag1" in merged.tags and "tag2" in merged.tags  # union
    
    print("  ✓ Merge strategy tests passed")


def test_statistics():
    """Test statistics generation"""
    print("Testing statistics...")
    
    deduplicator = ThreatFeedDeduplicator()
    now = datetime.utcnow()
    
    iocs = [
        IOCEntry("1.1.1.1", "ip", "feed_a", now, now, 0.8, "high"),
        IOCEntry("2.2.2.2", "ip", "feed_a", now, now, 0.7, "medium"),
        IOCEntry("evil.com", "domain", "feed_b", now, now, 0.9, "critical"),
        IOCEntry("1.1.1.1", "ip", "feed_b", now, now, 0.6, "low"),  # cross-source
    ]
    
    deduplicator.process_batch(iocs)
    stats = deduplicator.get_statistics()
    
    assert stats["total_processed"] == 4
    assert stats["total_unique"] == 3
    assert stats["total_duplicates"] == 1
    assert stats["cross_source_count"] == 1
    assert stats["single_source_count"] == 2
    assert stats["by_ioc_type"]["ip"] == 2
    assert stats["by_ioc_type"]["domain"] == 1
    
    print("  ✓ Statistics tests passed")


def test_deduplicate_feeds_convenience():
    """Test the convenience deduplicate_feeds function"""
    print("Testing deduplicate_feeds convenience function...")
    
    now = datetime.utcnow().isoformat()
    
    feed_data = {
        "feed_abusech": [
            {"value": "192.168.1.1", "confidence": 0.8, "severity": "high", "first_seen": now, "last_seen": now},
            {"value": "evil.com", "confidence": 0.7, "severity": "medium", "first_seen": now, "last_seen": now},
        ],
        "feed_misp": [
            {"value": "192.168.1.1", "confidence": 0.9, "severity": "critical", "first_seen": now, "last_seen": now},
            {"value": "malware.exe", "type": "hash", "confidence": 0.95, "severity": "critical", "first_seen": now, "last_seen": now},
        ]
    }
    
    result = deduplicate_feeds(feed_data)
    
    assert result["statistics"]["total_input"] == 4
    assert result["statistics"]["unique_iocs"] == 3
    assert len(result["high_fidelity_iocs"]) == 1  # cross-source IOC
    
    print("  ✓ deduplicate_feeds convenience function tests passed")


def run_all_tests():
    """Run all tests"""
    print("=" * 60)
    print("NeuralShield AI - Threat Feed Deduplicator Tests")
    print("=" * 60)
    
    try:
        test_normalize_ioc()
        test_detect_ioc_type()
        test_ioc_entry()
        test_single_feed_deduplication()
        test_cross_feed_deduplication()
        test_merge_strategy()
        test_statistics()
        test_deduplicate_feeds_convenience()
        
        print("\n" + "=" * 60)
        print("✅ ALL TESTS PASSED!")
        print("=" * 60)
        return True
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        return False
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
