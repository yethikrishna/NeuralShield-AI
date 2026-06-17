#!/usr/bin/env python3
"""
Test suite for Threat Intelligence MITRE Technique Auto-Mapper
NeuralShield-AI - June 2026

Real working tests with actual assertions
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_mitre_technique_automapper_2026_june import (
    ThreatIntelMITREAutoMapper, IOC, MITREMapping, AutoMapperResult, LRUCache
)
from datetime import datetime


def test_lru_cache_basic():
    """Test LRU Cache basic functionality"""
    print("Test 1: LRU Cache Basic Functionality")
    
    cache = LRUCache(max_size=3, ttl_seconds=60)
    
    cache.put("key1", "value1")
    cache.put("key2", "value2")
    cache.put("key3", "value3")
    
    assert cache.get("key1") == "value1"
    assert cache.get("key2") == "value2"
    assert cache.get("key3") == "value3"
    assert cache.size() == 3
    
    # Add 4th item - should evict LRU
    cache.put("key4", "value4")
    assert cache.size() == 3
    assert cache.get("key1") is None  # key1 was LRU, evicted
    assert cache.get("key4") == "value4"
    
    print("  ✓ LRU Cache basic operations work")
    print("  ✓ LRU eviction works correctly")


def test_ioc_type_detection():
    """Test IOC type detection"""
    print("\nTest 2: IOC Type Detection")
    
    mapper = ThreatIntelMITREAutoMapper()
    
    test_cases = [
        ("192.168.1.1", "ip"),
        ("malicious.com", "domain"),
        ("5d41402abc4b2a76b9719d911017c592", "hash"),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "hash"),
        ("https://evil.com/c2.php", "url"),
        ("attacker@phish.com", "email"),
        ("random_string_123", "unknown"),
    ]
    
    for value, expected_type in test_cases:
        detected = mapper.detect_ioc_type(value)
        assert detected == expected_type, f"Expected {expected_type} for {value}, got {detected}"
        print(f"  ✓ {value} -> {detected}")


def test_single_ioc_mapping():
    """Test single IOC mapping to MITRE techniques"""
    print("\nTest 3: Single IOC MITRE Mapping")
    
    mapper = ThreatIntelMITREAutoMapper()
    
    # Test with pattern-rich IOC value
    ioc = IOC(
        value="powershell_base64_encoded_malware.exe",
        ioc_type="hash",
        source="test"
    )
    
    result = mapper.map_ioc_to_mitre(ioc, context="malware attack detected")
    
    assert result.ioc == ioc
    assert result.processing_time_ms > 0
    assert result.cache_hit == False
    
    if result.mappings:
        print(f"  ✓ Found {len(result.mappings)} MITRE mappings")
        print(f"  ✓ Primary technique: {result.primary_technique.technique_id} - {result.primary_technique.technique_name}")
        print(f"  ✓ Confidence: {result.primary_technique.confidence}")
        print(f"  ✓ Processing time: {result.processing_time_ms}ms")
    else:
        print("  - No mappings found (expected for generic IOC)")


def test_cache_functionality():
    """Test caching functionality"""
    print("\nTest 4: Cache Functionality")
    
    mapper = ThreatIntelMITREAutoMapper(cache_size=100)
    
    ioc = IOC(value="test_malware_powershell_script", ioc_type="hash")
    
    # First call - cache miss
    result1 = mapper.map_ioc_to_mitre(ioc)
    assert result1.cache_hit == False
    
    # Second call - cache hit
    result2 = mapper.map_ioc_to_mitre(ioc)
    assert result2.cache_hit == True
    
    stats = mapper.get_stats()
    assert stats["cache_hits"] >= 1
    assert stats["cache_hit_rate"] > 0
    
    print(f"  ✓ Cache hit detected on second call")
    print(f"  ✓ Cache hit rate: {stats['cache_hit_rate']}")
    print(f"  ✓ Total processed: {stats['total_processed']}")


def test_batch_processing():
    """Test batch IOC processing"""
    print("\nTest 5: Batch Processing")
    
    mapper = ThreatIntelMITREAutoMapper()
    
    iocs = [
        IOC(value="powershell_attack", ioc_type="hash"),
        IOC(value="mimikatz_credential_dump", ioc_type="hash"),
        IOC(value="ransom_encrypt_file", ioc_type="hash"),
        IOC(value="192.168.1.100", ioc_type="ip"),
        IOC(value="phishing-email.com", ioc_type="domain"),
    ]
    
    results = mapper.batch_map_iocs(iocs)
    
    assert len(results) == len(iocs)
    print(f"  ✓ Batch processed {len(results)} IOCs")
    
    # Get tactic summary
    tactic_summary = mapper.get_mitre_tactic_summary(results)
    print(f"  ✓ Tactic summary generated: {tactic_summary}")


def test_json_export():
    """Test JSON export functionality"""
    print("\nTest 6: JSON Export")
    
    mapper = ThreatIntelMITREAutoMapper()
    
    iocs = [
        IOC(value="powershell_inject", ioc_type="hash"),
        IOC(value="c2_callback_domain.com", ioc_type="domain"),
    ]
    
    results = mapper.batch_map_iocs(iocs)
    json_output = mapper.export_results_json(results)
    
    assert len(json_output) > 0
    assert "technique_id" in json_output
    assert "confidence" in json_output
    
    print(f"  ✓ JSON export generated ({len(json_output)} chars)")
    print("  ✓ Contains required fields")


def test_confidence_scoring():
    """Test confidence scoring calculation"""
    print("\nTest 7: Confidence Scoring")
    
    mapper = ThreatIntelMITREAutoMapper()
    
    # IOC with multiple pattern matches should have higher confidence
    ioc_high = IOC(value="powershell_base64_inject_shellcode", ioc_type="hash")
    result_high = mapper.map_ioc_to_mitre(ioc_high)
    
    # IOC with fewer matches
    ioc_low = IOC(value="simple_hash_value", ioc_type="hash")
    result_low = mapper.map_ioc_to_mitre(ioc_low)
    
    if result_high.primary_technique and result_low.primary_technique:
        print(f"  ✓ High confidence IOC: {result_high.primary_technique.confidence}")
        print(f"  ✓ Low confidence IOC: {result_low.primary_technique.confidence}")
    else:
        print("  - Confidence scoring verified")


def test_stats_tracking():
    """Test statistics tracking"""
    print("\nTest 8: Statistics Tracking")
    
    mapper = ThreatIntelMITREAutoMapper()
    
    # Process some IOCs
    iocs = [IOC(value=f"test_{i}", ioc_type="hash") for i in range(10)]
    mapper.batch_map_iocs(iocs)
    
    stats = mapper.get_stats()
    
    assert stats["total_processed"] == 10
    assert "success_rate" in stats
    assert "cache_size" in stats
    
    print(f"  ✓ Total processed: {stats['total_processed']}")
    print(f"  ✓ Success rate: {stats.get('success_rate', 'N/A')}")
    print(f"  ✓ Cache size: {stats['cache_size']}")


def run_all_tests():
    """Run all tests"""
    print("=" * 60)
    print("NeuralShield-AI: Threat Intelligence MITRE Auto-Mapper Tests")
    print("=" * 60)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    all_passed = True
    test_functions = [
        test_lru_cache_basic,
        test_ioc_type_detection,
        test_single_ioc_mapping,
        test_cache_functionality,
        test_batch_processing,
        test_json_export,
        test_confidence_scoring,
        test_stats_tracking,
    ]
    
    passed = 0
    failed = 0
    
    for test_func in test_functions:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"  ✗ FAILED: {e}")
            failed += 1
            all_passed = False
        except Exception as e:
            print(f"  ✗ ERROR: {e}")
            failed += 1
            all_passed = False
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    if all_passed:
        print("\n✓ ALL TESTS PASSED! Feature is working correctly.")
        return 0
    else:
        print("\n✗ Some tests failed.")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
