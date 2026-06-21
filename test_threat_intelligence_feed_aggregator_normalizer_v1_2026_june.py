#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Feed Aggregator & Normalizer
NeuralShield-AI - June 21, 2026
"""

import json
import sys
from datetime import datetime
from neural_shield.threat_intelligence_feed_aggregator_normalizer_v1_2026_june import (
    ThreatFeedAggregator,
    create_threat_feed_aggregator,
    verify_threat_feed_aggregator,
    RawIndicator,
    FeedSource,
    IOCTYPE,
    ThreatSeverity,
)


def test_basic_functionality():
    """Test basic aggregator functionality"""
    print("=== Test 1: Basic Functionality ===")
    
    aggregator = create_threat_feed_aggregator()
    
    # Test IOC validation
    assert aggregator.validate_ioc(IOCTYPE.IPV4, "8.8.8.8") == True
    assert aggregator.validate_ioc(IOCTYPE.IPV4, "invalid-ip") == False
    assert aggregator.validate_ioc(IOCTYPE.MD5, "d41d8cd98f00b204e9800998ecf8427e") == True
    assert aggregator.validate_ioc(IOCTYPE.SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == True
    assert aggregator.validate_ioc(IOCTYPE.URL, "https://example.com/path") == True
    
    print("✓ IOC validation works correctly")
    
    # Test IOC type detection
    assert aggregator.detect_ioc_type("192.168.1.1") == IOCTYPE.IPV4
    assert aggregator.detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == IOCTYPE.MD5
    assert aggregator.detect_ioc_type("https://malicious.com") == IOCTYPE.URL
    assert aggregator.detect_ioc_type("CVE-2026-1234") == IOCTYPE.CVE
    
    print("✓ IOC type auto-detection works correctly")
    
    # Test ID generation (deterministic)
    id1 = aggregator.generate_ioc_id(IOCTYPE.IPV4, "192.168.1.1")
    id2 = aggregator.generate_ioc_id(IOCTYPE.IPV4, "192.168.1.1")
    assert id1 == id2
    
    print("✓ IOC ID generation is deterministic")
    print("✓ Basic functionality test PASSED\n")


def test_deduplication():
    """Test cross-source deduplication"""
    print("=== Test 2: Deduplication ===")
    
    aggregator = create_threat_feed_aggregator()
    
    # Same IP from two different sources
    indicators = [
        RawIndicator(
            source=FeedSource.ABUSEIPDB,
            raw_data={"ioc_value": "10.0.0.1", "ioc_type": "ipv4"}
        ),
        RawIndicator(
            source=FeedSource.THREATFOX,
            raw_data={"ioc_value": "10.0.0.1", "ioc_type": "ipv4"}
        ),
        RawIndicator(
            source=FeedSource.VIRUSTOTAL,
            raw_data={"ioc_value": "10.0.0.1", "ioc_type": "ipv4"}
        ),
    ]
    
    result = aggregator.aggregate_feeds(indicators)
    
    # Should only have 1 unique indicator despite 3 inputs
    assert result.total_unique_indicators == 1
    assert result.total_duplicates_removed == 2
    
    # The indicator should show all 3 sources and higher confidence
    normalized = result.normalized_indicators[0]
    assert len(normalized.sources) == 3
    assert normalized.correlation_count == 3
    assert normalized.confidence_score > 0.85  # Higher due to corroboration
    
    print(f"✓ Processed {result.total_indicators_fetched} indicators")
    print(f"✓ Found {result.total_unique_indicators} unique, removed {result.total_duplicates_removed} duplicates")
    print(f"✓ Corroborated indicator confidence: {normalized.confidence_score}")
    print("✓ Deduplication test PASSED\n")


def test_confidence_scoring():
    """Test confidence scoring algorithm"""
    print("=== Test 3: Confidence Scoring ===")
    
    aggregator = create_threat_feed_aggregator()
    
    # Single source - VirusTotal (high reputation)
    conf1 = aggregator.calculate_confidence_score(
        [FeedSource.VIRUSTOTAL],
        corroboration_count=1,
        age_days=0
    )
    
    # Single source - URLHaus (lower reputation)
    conf2 = aggregator.calculate_confidence_score(
        [FeedSource.URLHAUS],
        corroboration_count=1,
        age_days=0
    )
    
    # Multiple sources (corroboration bonus)
    conf3 = aggregator.calculate_confidence_score(
        [FeedSource.VIRUSTOTAL, FeedSource.ABUSEIPDB, FeedSource.THREATFOX],
        corroboration_count=3,
        age_days=0
    )
    
    # Aged indicator (time decay)
    conf4 = aggregator.calculate_confidence_score(
        [FeedSource.VIRUSTOTAL],
        corroboration_count=1,
        age_days=30
    )
    
    assert conf1 > conf2  # VT > URLHaus
    assert conf3 > conf1  # Multiple sources > single VT
    assert conf4 < conf1  # Aged < fresh
    
    print(f"✓ VirusTotal confidence: {conf1}")
    print(f"✓ URLHaus confidence: {conf2}")
    print(f"✓ 3-source corroborated confidence: {conf3}")
    print(f"✓ 30-day aged VT confidence: {conf4}")
    print("✓ Confidence scoring hierarchy correct")
    print("✓ Confidence scoring test PASSED\n")


def test_stix2_export():
    """Test STIX 2.1 export functionality"""
    print("=== Test 4: STIX 2.1 Export ===")
    
    aggregator = create_threat_feed_aggregator()
    
    indicators = [
        RawIndicator(
            source=FeedSource.VIRUSTOTAL,
            raw_data={"ioc_value": "d41d8cd98f00b204e9800998ecf8427e", "ioc_type": "md5"}
        ),
        RawIndicator(
            source=FeedSource.ABUSEIPDB,
            raw_data={"ioc_value": "192.168.1.100", "ioc_type": "ipv4"}
        ),
    ]
    
    result = aggregator.aggregate_feeds(indicators)
    stix_bundle = aggregator.export_to_stix2(result.normalized_indicators)
    
    assert stix_bundle["type"] == "bundle"
    assert stix_bundle["spec_version"] == "2.1"
    assert len(stix_bundle["objects"]) == 2
    
    for obj in stix_bundle["objects"]:
        assert obj["type"] == "indicator"
        assert "pattern" in obj
        assert "confidence" in obj
        assert "labels" in obj
    
    print(f"✓ STIX 2.1 bundle created with {len(stix_bundle['objects'])} objects")
    print(f"✓ Spec version: {stix_bundle['spec_version']}")
    print("✓ STIX 2.1 export test PASSED\n")


def test_high_confidence_filtering():
    """Test high confidence indicator filtering"""
    print("=== Test 5: High Confidence Filtering ===")
    
    aggregator = create_threat_feed_aggregator()
    
    indicators = [
        # High reputation sources
        RawIndicator(
            source=FeedSource.VIRUSTOTAL,
            raw_data={"ioc_value": "d41d8cd98f00b204e9800998ecf8427e", "ioc_type": "md5"}
        ),
        RawIndicator(
            source=FeedSource.MITRE_ATTACK,
            raw_data={"ioc_value": "CVE-2026-9999", "ioc_type": "cve"}
        ),
        # Lower reputation source
        RawIndicator(
            source=FeedSource.URLHAUS,
            raw_data={"ioc_value": "https://low-rep-example.com/bad.exe", "ioc_type": "url"}
        ),
    ]
    
    result = aggregator.aggregate_feeds(indicators)
    
    # Filter for high confidence only
    high_conf = aggregator.get_high_confidence_indicators(
        min_confidence=0.8,
        min_severity=ThreatSeverity.HIGH
    )
    
    print(f"✓ Total indicators: {len(result.normalized_indicators)}")
    print(f"✓ High confidence indicators (>=0.8, HIGH+): {len(high_conf)}")
    
    for ind in high_conf:
        print(f"  - {ind.ioc_type.value}: {ind.ioc_value[:32]}... (conf: {ind.confidence_score}, sev: {ind.severity.value})")
    
    print("✓ High confidence filtering test PASSED\n")


def test_feed_quality_reporting():
    """Test feed quality metrics and reporting"""
    print("=== Test 6: Feed Quality Reporting ===")
    
    aggregator = create_threat_feed_aggregator()
    
    # Mix of valid and invalid indicators
    indicators = [
        RawIndicator(
            source=FeedSource.ABUSEIPDB,
            raw_data={"ioc_value": "1.2.3.4", "ioc_type": "ipv4"}
        ),
        RawIndicator(
            source=FeedSource.ABUSEIPDB,
            raw_data={"ioc_value": "invalid-ip-here", "ioc_type": "ipv4"}
        ),
        RawIndicator(
            source=FeedSource.ABUSEIPDB,
            raw_data={"ioc_value": "5.6.7.8", "ioc_type": "ipv4"}
        ),
    ]
    
    result = aggregator.aggregate_feeds(indicators)
    report = aggregator.get_feed_quality_report()
    
    abuseipdb_stats = report["feed_sources"]["abuseipdb"]
    assert abuseipdb_stats["processed"] == 3
    assert abuseipdb_stats["invalid"] == 1
    # Use approximate comparison due to floating point rounding
    assert abs(abuseipdb_stats["quality_rate"] - 0.667) < 0.01  # ~2/3
    
    print(f"✓ Processed: {abuseipdb_stats['processed']}")
    print(f"✓ Invalid: {abuseipdb_stats['invalid']}")
    print(f"✓ Quality rate: {abuseipdb_stats['quality_rate']:.1%}")
    print(f"✓ Average confidence across all: {report['average_confidence']}")
    print("✓ Feed quality reporting test PASSED\n")


def run_full_verification():
    """Run the complete built-in verification"""
    print("=== Test 7: Full Built-in Verification ===")
    
    result = verify_threat_feed_aggregator()
    
    print(f"Run ID: {result['aggregation_run']['run_id']}")
    print(f"Total fetched: {result['aggregation_run']['total_fetched']}")
    print(f"Unique indicators: {result['aggregation_run']['unique_indicators']}")
    print(f"Duplicates removed: {result['aggregation_run']['duplicates_removed']}")
    print(f"Processing time: {result['aggregation_run']['processing_time_ms']}ms")
    print(f"High confidence count: {result['high_confidence_count']}")
    print(f"STIX2 export valid: {result['stix2_export_valid']}")
    print(f"Verification passed: {result['verification_passed']}")
    
    assert result["verification_passed"] == True
    print("✓ Full built-in verification PASSED\n")


def main():
    """Run all tests"""
    print("=" * 60)
    print("NeuralShield-AI: Threat Feed Aggregator Test Suite")
    print("=" * 60 + "\n")
    
    try:
        test_basic_functionality()
        test_deduplication()
        test_confidence_scoring()
        test_stix2_export()
        test_high_confidence_filtering()
        test_feed_quality_reporting()
        run_full_verification()
        
        print("=" * 60)
        print("ALL TESTS PASSED ✓")
        print("=" * 60)
        
        # Save test results
        test_results = {
            "test_timestamp": datetime.utcnow().isoformat() + "Z",
            "module": "threat_intelligence_feed_aggregator_normalizer_v1_2026_june",
            "all_tests_passed": True,
            "tests_executed": 7
        }
        
        with open("test_results_feed_aggregator_normalizer_v1_2026_june.json", "w") as f:
            json.dump(test_results, f, indent=2)
        
        print("\nTest results saved to test_results_feed_aggregator_normalizer_v1_2026_june.json")
        return 0
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ TEST ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
