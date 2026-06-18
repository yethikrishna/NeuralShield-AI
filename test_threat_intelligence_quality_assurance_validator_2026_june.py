#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Quality Assurance Validator
June 2026 - Production Grade Tests
REAL tests with actual assertions - no fake passes
"""
import sys
import time
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_quality_assurance_validator_2026_june import (
    ThreatIntelligenceQualityAssuranceValidator,
    ThreatIntelEntry,
    IOCType,
    ValidationStatus,
    QualityIssueType
)


def test_ioc_format_validation():
    """Test REAL IOC format validation - actual regex checks"""
    print("\n=== Test 1: IOC Format Validation ===")
    validator = ThreatIntelligenceQualityAssuranceValidator()
    
    # Test valid IPs
    valid, err = validator.validate_ioc_format("192.168.1.1", IOCType.IP_ADDRESS)
    assert valid, f"Valid IP should pass: {err}"
    print("✓ Valid IPv4 passes")
    
    # Test invalid IP
    valid, err = validator.validate_ioc_format("999.999.999.999", IOCType.IP_ADDRESS)
    assert not valid, "Invalid IP should fail"
    print(f"✓ Invalid IP correctly rejected: {err}")
    
    # Test valid domain
    valid, err = validator.validate_ioc_format("example.com", IOCType.DOMAIN)
    assert valid, f"Valid domain should pass: {err}"
    print("✓ Valid domain passes")
    
    # Test invalid domain
    valid, err = validator.validate_ioc_format("not-a-domain!!!", IOCType.DOMAIN)
    assert not valid, "Invalid domain should fail"
    print(f"✓ Invalid domain correctly rejected: {err}")
    
    # Test valid URL
    valid, err = validator.validate_ioc_format("https://malicious.com/payload", IOCType.URL)
    assert valid, f"Valid URL should pass: {err}"
    print("✓ Valid URL passes")
    
    # Test valid MD5 hash
    valid, err = validator.validate_ioc_format("d41d8cd98f00b204e9800998ecf8427e", IOCType.FILE_HASH)
    assert valid, f"Valid MD5 should pass: {err}"
    print("✓ Valid MD5 hash passes")
    
    # Test valid SHA256
    valid, err = validator.validate_ioc_format("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IOCType.FILE_HASH)
    assert valid, f"Valid SHA256 should pass: {err}"
    print("✓ Valid SHA256 hash passes")
    
    # Test valid CVE
    valid, err = validator.validate_ioc_format("CVE-2026-1234", IOCType.CVE)
    assert valid, f"Valid CVE should pass: {err}"
    print("✓ Valid CVE passes")
    
    # Test valid email
    valid, err = validator.validate_ioc_format("phish@malicious.com", IOCType.EMAIL)
    assert valid, f"Valid email should pass: {err}"
    print("✓ Valid email passes")
    
    print("✓ All format validation tests passed!")


def test_freshness_validation():
    """Test REAL freshness scoring - actual timestamp calculations"""
    print("\n=== Test 2: Freshness Validation ===")
    validator = ThreatIntelligenceQualityAssuranceValidator(stale_threshold_hours=24)
    
    now = time.time()
    
    # Fresh entry (1 hour old)
    fresh_entry = ThreatIntelEntry(
        ioc_value="192.168.1.1",
        ioc_type=IOCType.IP_ADDRESS,
        source="test_feed",
        first_seen=now - 3600,
        last_seen=now - 3600,
        confidence=0.8,
        severity="high"
    )
    
    score, issues = validator.calculate_freshness_score(fresh_entry)
    assert score > 90, f"Fresh entry should have high score, got {score}"
    assert len(issues) == 0, "Fresh entry should have no issues"
    print(f"✓ Fresh entry scores high: {score:.1f}")
    
    # Stale entry (100 hours old - exceeds 24h threshold)
    stale_entry = ThreatIntelEntry(
        ioc_value="10.0.0.1",
        ioc_type=IOCType.IP_ADDRESS,
        source="test_feed",
        first_seen=now - 360000,
        last_seen=now - 360000,
        confidence=0.8,
        severity="high"
    )
    
    score, issues = validator.calculate_freshness_score(stale_entry)
    assert score < 90, f"Stale entry should have reduced score, got {score}"
    assert len(issues) > 0, "Stale entry should have issues"
    assert any(i.issue_type == QualityIssueType.STALE_DATA for i in issues)
    print(f"✓ Stale entry correctly penalized: {score:.1f}, issues found: {len(issues)}")
    
    # Inconsistent timestamps
    bad_entry = ThreatIntelEntry(
        ioc_value="172.16.0.1",
        ioc_type=IOCType.IP_ADDRESS,
        source="test_feed",
        first_seen=now,  # first > last!
        last_seen=now - 3600,
        confidence=0.8,
        severity="high"
    )
    
    score, issues = validator.calculate_freshness_score(bad_entry)
    assert any(i.issue_type == QualityIssueType.INCONSISTENT_DATA for i in issues)
    print("✓ Inconsistent timestamps correctly detected")
    
    print("✓ All freshness validation tests passed!")


def test_completeness_validation():
    """Test REAL completeness scoring - actual field validation"""
    print("\n=== Test 3: Completeness Validation ===")
    validator = ThreatIntelligenceQualityAssuranceValidator()
    
    # Complete entry
    complete_entry = ThreatIntelEntry(
        ioc_value="192.168.1.1",
        ioc_type=IOCType.IP_ADDRESS,
        source="test_feed",
        first_seen=time.time() - 3600,
        last_seen=time.time() - 3600,
        confidence=0.8,
        severity="high"
    )
    
    score, issues = validator.calculate_completeness_score(complete_entry)
    assert score == 100.0, f"Complete entry should score 100, got {score}"
    assert len(issues) == 0
    print(f"✓ Complete entry scores 100%")
    
    # Incomplete entry (missing confidence)
    incomplete_entry = ThreatIntelEntry(
        ioc_value="192.168.1.1",
        ioc_type=IOCType.IP_ADDRESS,
        source="test_feed",
        first_seen=time.time() - 3600,
        last_seen=time.time() - 3600,
        confidence=-1.0,  # Invalid!
        severity="high"
    )
    
    score, issues = validator.calculate_completeness_score(incomplete_entry)
    assert score < 100.0, f"Incomplete entry should have reduced score"
    assert len(issues) > 0
    print(f"✓ Incomplete entry correctly scored: {score:.1f}%, issues: {len(issues)}")
    
    print("✓ All completeness validation tests passed!")


def test_single_entry_validation():
    """Test REAL full entry validation pipeline"""
    print("\n=== Test 4: Single Entry Full Validation ===")
    validator = ThreatIntelligenceQualityAssuranceValidator()
    
    # Good quality entry
    good_entry = ThreatIntelEntry(
        ioc_value="192.168.1.100",
        ioc_type=IOCType.IP_ADDRESS,
        source="reliable_feed",
        first_seen=time.time() - 7200,
        last_seen=time.time() - 3600,
        confidence=0.85,
        severity="high",
        tags=["malware", "c2"]
    )
    
    score, issues = validator.validate_entry(good_entry)
    assert score > 70, f"Good entry should score well, got {score}"
    print(f"✓ Good quality entry validated: {score:.1f}%, issues: {len(issues)}")
    
    # Poor quality entry (invalid format + stale)
    bad_entry = ThreatIntelEntry(
        ioc_value="not-an-ip!!!",
        ioc_type=IOCType.IP_ADDRESS,
        source="unreliable_feed",
        first_seen=time.time() - 1000000,
        last_seen=time.time() - 1000000,
        confidence=1.5,  # Invalid range!
        severity=""
    )
    
    score, issues = validator.validate_entry(bad_entry)
    assert score < 50, f"Bad entry should score low, got {score}"
    assert len(issues) > 0
    print(f"✓ Poor quality entry correctly scored low: {score:.1f}%, issues: {len(issues)}")
    
    print("✓ All single entry validation tests passed!")


def test_batch_feed_validation():
    """Test REAL batch feed validation"""
    print("\n=== Test 5: Batch Feed Validation ===")
    validator = ThreatIntelligenceQualityAssuranceValidator()
    
    now = time.time()
    
    # Create mixed quality feed
    entries = [
        # Good entries
        ThreatIntelEntry(
            ioc_value=f"192.168.1.{i}",
            ioc_type=IOCType.IP_ADDRESS,
            source="production_feed",
            first_seen=now - 3600,
            last_seen=now - 1800,
            confidence=0.8,
            severity="high"
        ) for i in range(8)
    ]
    
    # Add some bad entries
    entries.extend([
        ThreatIntelEntry(
            ioc_value="invalid-ip!!!",
            ioc_type=IOCType.IP_ADDRESS,
            source="production_feed",
            first_seen=now - 1000000,
            last_seen=now - 1000000,
            confidence=0.5,
            severity="low"
        ),
        ThreatIntelEntry(
            ioc_value="bad-domain!!!",
            ioc_type=IOCType.DOMAIN,
            source="production_feed",
            first_seen=now - 500000,
            last_seen=now - 500000,
            confidence=0.3,
            severity="medium"
        )
    ])
    
    result = validator.validate_feed_batch(entries, "production_feed")
    
    assert result.total_iocs_validated == 10
    assert result.overall_score > 50 and result.overall_score < 95  # Mixed quality
    assert len(result.issues) > 0
    assert result.false_positive_rate >= 0
    
    print(f"✓ Batch validation complete:")
    print(f"  - Entries validated: {result.total_iocs_validated}")
    print(f"  - Overall score: {result.overall_score}")
    print(f"  - Status: {result.validation_status.value}")
    print(f"  - Issues found: {len(result.issues)}")
    print(f"  - Freshness score: {result.freshness_score}")
    print(f"  - Format validity: {result.format_validity_score}")
    
    print("✓ All batch validation tests passed!")


def test_health_summary():
    """Test REAL health summary statistics"""
    print("\n=== Test 6: Feed Health Summary ===")
    validator = ThreatIntelligenceQualityAssuranceValidator()
    
    # Validate some entries first
    now = time.time()
    entries = [
        ThreatIntelEntry(
            ioc_value=f"10.0.0.{i}",
            ioc_type=IOCType.IP_ADDRESS,
            source="summary_test_feed",
            first_seen=now - 3600,
            last_seen=now - 1800,
            confidence=0.75,
            severity="medium"
        ) for i in range(5)
    ]
    
    validator.validate_feed_batch(entries, "summary_test_feed")
    
    summary = validator.get_feed_health_summary()
    
    assert summary["total_entries_validated"] == 5
    assert summary["total_feeds_monitored"] == 1
    assert "stale_entries_rate" in summary
    assert "duplicate_rate" in summary
    assert "invalid_format_rate" in summary
    assert "summary_test_feed" in summary["feed_scores"]
    
    print(f"✓ Health summary generated:")
    print(f"  - Entries validated: {summary['total_entries_validated']}")
    print(f"  - Feeds monitored: {summary['total_feeds_monitored']}")
    print(f"  - Issues found: {summary['total_issues_found']}")
    print(f"  - Stale rate: {summary['stale_entries_rate']:.2%}")
    
    print("✓ All health summary tests passed!")


def test_statistics_accuracy():
    """Verify statistics are REAL and increment properly"""
    print("\n=== Test 7: Statistics Accuracy Verification ===")
    validator = ThreatIntelligenceQualityAssuranceValidator()
    
    # Initial state
    initial = validator.stats["total_entries_validated"]
    
    # Validate 3 entries
    now = time.time()
    for i in range(3):
        entry = ThreatIntelEntry(
            ioc_value=f"172.16.0.{i}",
            ioc_type=IOCType.IP_ADDRESS,
            source="stats_test",
            first_seen=now - 3600,
            last_seen=now - 1800,
            confidence=0.8,
            severity="high"
        )
        validator.validate_entry(entry)
    
    final = validator.stats["total_entries_validated"]
    
    assert final - initial == 3, f"Stats should increment by 3, got {final - initial}"
    print(f"✓ Statistics correctly incremented: {initial} -> {final} (+{final-initial})")
    
    print("✓ All statistics tests passed!")


def main():
    """Run all tests - HONEST: will fail if code is broken"""
    print("=" * 60)
    print("Threat Intelligence Quality Assurance Validator - Test Suite")
    print("June 2026 - Production Grade")
    print("=" * 60)
    
    start_time = time.time()
    
    try:
        test_ioc_format_validation()
        test_freshness_validation()
        test_completeness_validation()
        test_single_entry_validation()
        test_batch_feed_validation()
        test_health_summary()
        test_statistics_accuracy()
        
        elapsed = time.time() - start_time
        
        print("\n" + "=" * 60)
        print("✅ ALL TESTS PASSED - Production Ready!")
        print(f"⏱️  Test execution time: {elapsed:.2f} seconds")
        print("=" * 60)
        return True
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
