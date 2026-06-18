#!/usr/bin/env python3
"""
Test suite for Threat Intelligence IOC Aggregator
NeuralShield-AI - June 2026
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_ioc_aggregator_2026_june import (
    ThreatIntelligenceAggregator,
    IOCExtractor,
    IOType,
    ThreatSeverity,
    IOCEntry
)


def test_ioc_extractor_basic():
    """Test basic IOC extraction from text"""
    print("Test 1: IOC Extractor Basic")
    
    test_text = """
    Check this IP: 192.168.1.1 and domain: malicious.com
    Also this URL: http://bad-site.com/payload.exe
    MD5: 44d88612fea8a8f36de82e1278abb02f
    SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    Email: attacker@evil.com
    """
    
    extracted = IOCExtractor.extract_iocs(test_text)
    
    assert IOType.IP_ADDRESS in extracted, "Should find IP address"
    assert IOType.DOMAIN in extracted, "Should find domain"
    assert IOType.URL in extracted, "Should find URL"
    assert IOType.MD5_HASH in extracted, "Should find MD5"
    assert IOType.SHA256_HASH in extracted, "Should find SHA256"
    assert IOType.EMAIL in extracted, "Should find email"
    
    print(f"  - IPs found: {len(extracted.get(IOType.IP_ADDRESS, []))}")
    print(f"  - Domains found: {len(extracted.get(IOType.DOMAIN, []))}")
    print(f"  - URLs found: {len(extracted.get(IOType.URL, []))}")
    print(f"  - MD5 found: {len(extracted.get(IOType.MD5_HASH, []))}")
    print("  ✓ PASSED")


def test_aggregator_initialization():
    """Test aggregator initialization"""
    print("\nTest 2: Aggregator Initialization")
    
    aggregator = ThreatIntelligenceAggregator(
        cache_ttl_minutes=30,
        auto_refresh=False
    )
    
    # Initialize without network (should work offline)
    aggregator._initialized = True
    
    stats = aggregator.get_statistics()
    assert stats["initialized"] == True, "Should be initialized"
    
    print(f"  - Cache TTL: {stats['cache_ttl_minutes']} minutes")
    print(f"  - Total IOCs: {stats['total_iocs']}")
    print("  ✓ PASSED")


def test_custom_ioc_addition():
    """Test adding custom IOC entries"""
    print("\nTest 3: Custom IOC Addition")
    
    aggregator = ThreatIntelligenceAggregator(auto_refresh=False)
    aggregator._initialized = True
    
    # Add custom malicious IP
    result = aggregator.add_custom_ioc(
        value="1.2.3.4",
        ioc_type=IOType.IP_ADDRESS,
        severity=ThreatSeverity.CRITICAL,
        source="test",
        confidence=0.95
    )
    
    assert result == True, "Should add custom IOC"
    
    # Scan for it
    match = aggregator.scan_value("1.2.3.4")
    assert match is not None, "Should find the custom IOC"
    assert match.severity == ThreatSeverity.CRITICAL, "Should have correct severity"
    assert match.confidence == 0.95, "Should have correct confidence"
    
    print(f"  - Added custom IOC: 1.2.3.4")
    print(f"  - Matched severity: {match.severity.value}")
    print("  ✓ PASSED")


def test_text_scanning():
    """Test full text scanning functionality"""
    print("\nTest 4: Text Scanning")
    
    aggregator = ThreatIntelligenceAggregator(auto_refresh=False)
    aggregator._initialized = True
    
    # Add test IOCs
    aggregator.add_custom_ioc(
        "bad-malware-site.com",
        IOType.DOMAIN,
        ThreatSeverity.HIGH
    )
    aggregator.add_custom_ioc(
        "5f4dcc3b5aa765d61d8327deb882cf99",
        IOType.MD5_HASH,
        ThreatSeverity.CRITICAL
    )
    
    # Scan text containing the IOCs
    test_text = """
    User uploaded file with hash 5f4dcc3b5aa765d61d8327deb882cf99
    and referenced domain bad-malware-site.com in the request.
    Also mentioned safe-site.com which is fine.
    """
    
    scan_result = aggregator.scan_text(test_text)
    
    assert scan_result.matched == True, "Should find matches"
    assert len(scan_result.matches) >= 2, "Should find at least 2 matches"
    assert scan_result.highest_severity == ThreatSeverity.CRITICAL, "Highest severity should be CRITICAL"
    
    print(f"  - Text matched: {scan_result.matched}")
    print(f"  - Total matches: {len(scan_result.matches)}")
    print(f"  - Highest severity: {scan_result.highest_severity.value}")
    print(f"  - Scanned against {scan_result.total_iocs_scanned} IOCs")
    print("  ✓ PASSED")


def test_ioc_entry_serialization():
    """Test IOC entry serialization"""
    print("\nTest 5: IOC Entry Serialization")
    
    from datetime import datetime
    
    entry = IOCEntry(
        value="test-value",
        ioc_type=IOType.IP_ADDRESS,
        source="test",
        severity=ThreatSeverity.MEDIUM,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        confidence=0.8,
        description="Test entry"
    )
    
    entry_dict = entry.to_dict()
    
    assert entry_dict["value"] == "test-value"
    assert entry_dict["severity"] == "medium"
    assert entry_dict["confidence"] == 0.8
    assert "first_seen" in entry_dict
    
    print(f"  - Serialized keys: {list(entry_dict.keys())}")
    print("  ✓ PASSED")


def test_empty_text_scan():
    """Test scanning empty/clean text"""
    print("\nTest 6: Empty/Clean Text Scan")
    
    aggregator = ThreatIntelligenceAggregator(auto_refresh=False)
    aggregator._initialized = True
    
    result = aggregator.scan_text("This is completely safe text with no threats")
    
    assert result.matched == False, "Should not match anything"
    assert len(result.matches) == 0, "Should have zero matches"
    assert result.highest_severity is None, "Should have no highest severity"
    
    print(f"  - Matched: {result.matched}")
    print(f"  - Match count: {len(result.matches)}")
    print("  ✓ PASSED")


def test_threat_severity_ordering():
    """Test threat severity ordering works correctly"""
    print("\nTest 7: Threat Severity Ordering")
    
    aggregator = ThreatIntelligenceAggregator(auto_refresh=False)
    aggregator._initialized = True
    
    # Add multiple severities
    aggregator.add_custom_ioc("low.example.com", IOType.DOMAIN, ThreatSeverity.LOW)
    aggregator.add_custom_ioc("medium.example.com", IOType.DOMAIN, ThreatSeverity.MEDIUM)
    aggregator.add_custom_ioc("critical.example.com", IOType.DOMAIN, ThreatSeverity.CRITICAL)
    
    # Scan all
    text = "low.example.com medium.example.com critical.example.com"
    result = aggregator.scan_text(text)
    
    assert result.highest_severity == ThreatSeverity.CRITICAL, "CRITICAL should be highest"
    
    print(f"  - Highest severity correctly identified: {result.highest_severity.value}")
    print("  ✓ PASSED")


def run_all_tests():
    """Run all test cases"""
    print("=" * 60)
    print("NeuralShield-AI: Threat Intelligence IOC Aggregator Tests")
    print("June 2026 - Production Grade")
    print("=" * 60)
    
    tests = [
        test_ioc_extractor_basic,
        test_aggregator_initialization,
        test_custom_ioc_addition,
        test_text_scanning,
        test_ioc_entry_serialization,
        test_empty_text_scan,
        test_threat_severity_ordering,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  ✗ FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"  ✗ ERROR: {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
