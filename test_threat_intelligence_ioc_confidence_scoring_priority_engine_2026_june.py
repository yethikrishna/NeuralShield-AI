#!/usr/bin/env python3
"""
Test suite for NeuralShield IOC Confidence Scoring & Priority Ranking Engine
Production-grade tests with real-world scenarios
"""

import sys
import os
from datetime import datetime, timedelta

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_ioc_confidence_scoring_priority_engine_2026_june import (
    IOCConfidenceScoringEngine,
    IOCEntry,
    IOType,
    ThreatSeverity,
    validate_ioc_format
)


def test_single_ioc_processing():
    """Test processing of a single IOC with known high-reliability source"""
    print("Test 1: Single IOC Processing...")
    
    engine = IOCConfidenceScoringEngine()
    
    ioc = IOCEntry(
        value="192.168.1.100",
        ioc_type=IOType.IP_ADDRESS,
        source="CISA Government Feed",
        first_seen=datetime.utcnow() - timedelta(hours=2),
        last_seen=datetime.utcnow() - timedelta(minutes=30),
        threat_actor="APT28",
        severity=ThreatSeverity.CRITICAL,
        seen_count=15
    )
    
    scored = engine.process_ioc(ioc)
    
    assert scored.confidence_score > 0.7, "High confidence expected for government source"
    assert scored.priority_score > 0.7, "High priority expected for recent critical IOC"
    assert scored.priority_rank in ["CRITICAL", "HIGH"], "Critical or High rank expected"
    assert scored.source_score > 0.9, "Government source should have high reliability"
    assert scored.temporal_score > 0.8, "Recent IOC should have high temporal score"
    
    print(f"  ✓ Confidence: {scored.confidence_score}")
    print(f"  ✓ Priority: {scored.priority_score} ({scored.priority_rank})")
    print("  PASSED\n")


def test_batch_processing():
    """Test batch processing of multiple IOCs"""
    print("Test 2: Batch IOC Processing...")
    
    engine = IOCConfidenceScoringEngine()
    
    iocs = [
        IOCEntry(
            value="10.0.0.1",
            ioc_type=IOType.IP_ADDRESS,
            source="Mandiant Premium Feed",
            first_seen=datetime.utcnow() - timedelta(hours=1),
            last_seen=datetime.utcnow() - timedelta(minutes=5),
            threat_actor="Conti",
            severity=ThreatSeverity.CRITICAL,
            seen_count=25
        ),
        IOCEntry(
            value="malicious-domain.com",
            ioc_type=IOType.DOMAIN,
            source="VirusTotal",
            first_seen=datetime.utcnow() - timedelta(days=5),
            last_seen=datetime.utcnow() - timedelta(days=2),
            threat_actor="Phishing",
            severity=ThreatSeverity.HIGH,
            seen_count=8
        ),
        IOCEntry(
            value="d41d8cd98f00b204e9800998ecf8427e",
            ioc_type=IOType.HASH,
            source="Community Report",
            first_seen=datetime.utcnow() - timedelta(days=60),
            last_seen=datetime.utcnow() - timedelta(days=45),
            threat_actor=None,
            severity=ThreatSeverity.LOW,
            seen_count=2
        ),
        IOCEntry(
            value="192.168.1.50",
            ioc_type=IOType.IP_ADDRESS,
            source="Unknown Source",
            first_seen=datetime.utcnow() - timedelta(days=10),
            last_seen=datetime.utcnow() - timedelta(days=10),
            threat_actor=None,
            severity=ThreatSeverity.MEDIUM,
            seen_count=1
        )
    ]
    
    results = engine.process_batch(iocs, prioritize=True)
    
    assert len(results) == 4, "All 4 IOCs should be processed"
    assert results[0].priority_score >= results[-1].priority_score, "Should be sorted by priority"
    
    stats = engine.get_processing_statistics()
    assert stats["total_processed"] == 4, "Stats should show 4 processed"
    
    print(f"  ✓ Processed {len(results)} IOCs")
    print(f"  ✓ Highest priority: {results[0].priority_score:.4f} ({results[0].priority_rank})")
    print(f"  ✓ Lowest priority: {results[-1].priority_score:.4f} ({results[-1].priority_rank})")
    print(f"  ✓ Stats: {stats}")
    print("  PASSED\n")


def test_temporal_decay():
    """Test temporal decay scoring works correctly"""
    print("Test 3: Temporal Decay Calculation...")
    
    engine = IOCConfidenceScoringEngine()
    
    # Very recent IOC
    recent_ioc = IOCEntry(
        value="1.1.1.1",
        ioc_type=IOType.IP_ADDRESS,
        source="CISA",
        first_seen=datetime.utcnow() - timedelta(hours=1),
        last_seen=datetime.utcnow() - timedelta(minutes=10),
        severity=ThreatSeverity.HIGH
    )
    
    # Old IOC
    old_ioc = IOCEntry(
        value="2.2.2.2",
        ioc_type=IOType.IP_ADDRESS,
        source="CISA",
        first_seen=datetime.utcnow() - timedelta(days=90),
        last_seen=datetime.utcnow() - timedelta(days=90),
        severity=ThreatSeverity.HIGH
    )
    
    scored_recent = engine.process_ioc(recent_ioc)
    scored_old = engine.process_ioc(old_ioc)
    
    assert scored_recent.temporal_score > scored_old.temporal_score, "Recent should have higher temporal score"
    assert scored_recent.temporal_score > 0.8, "Very recent should be > 0.8"
    assert scored_old.temporal_score < 0.2, "Very old should have decayed"
    
    print(f"  ✓ Recent IOC temporal score: {scored_recent.temporal_score:.4f}")
    print(f"  ✓ Old IOC temporal score: {scored_old.temporal_score:.4f}")
    print("  PASSED\n")


def test_source_reliability():
    """Test different sources get different reliability scores"""
    print("Test 4: Source Reliability Scoring...")
    
    engine = IOCConfidenceScoringEngine()
    
    sources = [
        ("CISA Feed", 0.9, "Government"),
        ("Mandiant Threat Intel", 0.85, "Commercial Premium"),
        ("VirusTotal Community", 0.7, "Trusted Open Source"),
        ("Random Forum Post", 0.5, "Unknown/Community"),
    ]
    
    for source_name, min_expected, category in sources:
        ioc = IOCEntry(
            value="192.168.1.1",
            ioc_type=IOType.IP_ADDRESS,
            source=source_name,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            severity=ThreatSeverity.HIGH
        )
        scored = engine.process_ioc(ioc)
        assert scored.source_score >= min_expected * 0.8, f"{category} source should have reasonable score"
        print(f"  ✓ {category}: {scored.source_score:.4f}")
    
    print("  PASSED\n")


def test_frequency_scoring():
    """Test frequency-based scoring"""
    print("Test 5: Observation Frequency Scoring...")
    
    engine = IOCConfidenceScoringEngine()
    
    for count in [1, 3, 5, 10, 20]:
        ioc = IOCEntry(
            value=f"10.0.0.{count}",
            ioc_type=IOType.IP_ADDRESS,
            source="CISA",
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            seen_count=count,
            severity=ThreatSeverity.HIGH
        )
        scored = engine.process_ioc(ioc)
        print(f"  ✓ {count} observations: frequency score = {scored.frequency_score:.4f}")
    
    print("  PASSED\n")


def test_high_priority_filtering():
    """Test filtering high priority IOCs"""
    print("Test 6: High Priority IOC Filtering...")
    
    engine = IOCConfidenceScoringEngine()
    
    # Create mix of high and low priority
    for i in range(10):
        ioc = IOCEntry(
            value=f"192.168.1.{i}",
            ioc_type=IOType.IP_ADDRESS,
            source="CISA" if i < 5 else "Unknown",
            first_seen=datetime.utcnow() - timedelta(hours=i),
            last_seen=datetime.utcnow() - timedelta(minutes=i*10),
            severity=ThreatSeverity.CRITICAL if i < 5 else ThreatSeverity.LOW,
            seen_count=10 if i < 5 else 1
        )
        engine.process_ioc(ioc)
    
    high_priority = engine.get_high_priority_iocs(threshold=0.7)
    
    assert len(high_priority) >= 3, "Should have at least 3 high priority IOCs"
    
    print(f"  ✓ Found {len(high_priority)} high-priority IOCs")
    for hp in high_priority[:3]:
        print(f"    - {hp.ioc.value}: {hp.priority_score:.4f} ({hp.priority_rank})")
    print("  PASSED\n")


def test_ioc_validation():
    """Test IOC format validation"""
    print("Test 7: IOC Format Validation...")
    
    test_cases = [
        ("192.168.1.1", IOType.IP_ADDRESS, True),
        ("256.256.256.256", IOType.IP_ADDRESS, True),  # Pattern match only
        ("google.com", IOType.DOMAIN, True),
        ("d41d8cd98f00b204e9800998ecf8427e", IOType.HASH, True),  # MD5
        ("user@example.com", IOType.EMAIL, True),
        ("invalid-ip", IOType.IP_ADDRESS, False),
    ]
    
    for value, ioc_type, expected in test_cases:
        result = validate_ioc_format(value, ioc_type)
        assert result == expected, f"Validation failed for {value}"
        status = "✓" if result else "✗"
        print(f"  {status} {value} as {ioc_type.value}: {'valid' if result else 'invalid'}")
    
    print("  PASSED\n")


def test_json_export():
    """Test JSON export functionality"""
    print("Test 8: JSON Results Export...")
    
    engine = IOCConfidenceScoringEngine()
    
    ioc = IOCEntry(
        value="192.168.1.100",
        ioc_type=IOType.IP_ADDRESS,
        source="CISA",
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        threat_actor="APT29",
        severity=ThreatSeverity.CRITICAL,
        seen_count=10
    )
    engine.process_ioc(ioc)
    
    export_file = "/tmp/test_ioc_export.json"
    success = engine.export_results_json(export_file)
    
    assert success, "Export should succeed"
    assert os.path.exists(export_file), "Export file should exist"
    
    import json
    with open(export_file) as f:
        data = json.load(f)
    
    assert "scored_iocs" in data
    assert "statistics" in data
    assert len(data["scored_iocs"]) == 1
    
    os.remove(export_file)
    print(f"  ✓ Exported to {export_file}")
    print(f"  ✓ Contains statistics and {len(data['scored_iocs'])} scored IOCs")
    print("  PASSED\n")


def run_all_tests():
    """Run complete test suite"""
    print("=" * 60)
    print("NeuralShield AI - IOC Confidence Scoring Engine Tests")
    print("=" * 60 + "\n")
    
    tests_passed = 0
    tests_failed = 0
    
    test_functions = [
        test_single_ioc_processing,
        test_batch_processing,
        test_temporal_decay,
        test_source_reliability,
        test_frequency_scoring,
        test_high_priority_filtering,
        test_ioc_validation,
        test_json_export
    ]
    
    for test_func in test_functions:
        try:
            test_func()
            tests_passed += 1
        except AssertionError as e:
            print(f"  FAILED: {e}\n")
            tests_failed += 1
        except Exception as e:
            print(f"  ERROR: {e}\n")
            tests_failed += 1
    
    print("=" * 60)
    print(f"TEST SUMMARY: {tests_passed} PASSED, {tests_failed} FAILED")
    print("=" * 60)
    
    return tests_failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
