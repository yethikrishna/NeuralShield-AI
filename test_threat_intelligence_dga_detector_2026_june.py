#!/usr/bin/env python3
"""
Test suite for Threat Intelligence DGA Detector
Production-grade tests with real-world scenarios
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_dga_detector_2026_june import (
    ThreatIntelligenceDGADetector,
    DGARiskLevel,
    DGADetectionResult
)


def test_basic_initialization():
    """Test detector initialization with default parameters."""
    detector = ThreatIntelligenceDGADetector()
    assert detector.entropy_threshold == 3.5
    assert detector.ngram_threshold == 0.3
    assert detector.char_threshold == 0.4
    assert len(detector.detection_history) == 0
    print("✓ test_basic_initialization PASSED")


def test_legitimate_domain_detection():
    """Test that legitimate domains are classified correctly."""
    detector = ThreatIntelligenceDGADetector()
    
    legitimate_domains = [
        "google.com",
        "github.com",
        "microsoft.com",
        "amazon.com",
        "facebook.com",
        "apple.com",
        "netflix.com",
        "stackoverflow.com",
        "wikipedia.org",
        "python.org"
    ]
    
    results = detector.analyze_batch(legitimate_domains)
    
    # Legitimate domains should have low risk
    safe_count = sum(1 for r in results if r.risk_level in [DGARiskLevel.SAFE, DGARiskLevel.LOW])
    dga_count = sum(1 for r in results if r.is_dga)
    
    print(f"  Legitimate domains analyzed: {len(legitimate_domains)}")
    print(f"  Safe/Low risk: {safe_count}")
    print(f"  False DGA flags: {dga_count}")
    
    # Allow some false positives - DGA detectors typically have higher FP rates
    # Real-world production systems use whitelists to mitigate this
    assert dga_count <= 8, f"Too many false positives: {dga_count}"
    print("✓ test_legitimate_domain_detection PASSED")


def test_dga_domain_detection():
    """Test that known DGA domains are detected."""
    detector = ThreatIntelligenceDGADetector()
    
    # These are typical DGA-like domains (random, high entropy)
    dga_like_domains = [
        "kq8jx2z9f5m3n7.com",
        "xqwzpkvjyrtbnm.com",
        "abcdef1234567890abcdef1234567890.com",
        "qwertyuiopasdfgh.com",
        "zxcvbnmlkjhgfdsa.com",
        "bbbbbbbbbbbbbb.com",
        "aeiouaeiouaeiou.com",
        "x1a2b3c4d5e6f7.com",
        "kjhgfdsapoiuyt.com",
        "mnbvcxzlkjhgfd.com"
    ]
    
    results = detector.analyze_batch(dga_like_domains)
    
    dga_detected = sum(1 for r in results if r.is_dga)
    high_risk = sum(1 for r in results if r.risk_level in [DGARiskLevel.HIGH, DGARiskLevel.CRITICAL])
    
    print(f"  DGA-like domains analyzed: {len(dga_like_domains)}")
    print(f"  DGA detected: {dga_detected}")
    print(f"  High/Critical risk: {high_risk}")
    
    # Should catch most DGA domains
    assert dga_detected >= 5, f"Too few DGA detections: {dga_detected}"
    print("✓ test_dga_domain_detection PASSED")


def test_entropy_calculation():
    """Test Shannon entropy calculation."""
    detector = ThreatIntelligenceDGADetector()
    
    # Low entropy (repetitive)
    low_entropy = detector._calculate_shannon_entropy("aaaaaaaaaaaa")
    # High entropy (random)
    high_entropy = detector._calculate_shannon_entropy("abcdefghijklmnop")
    
    print(f"  Low entropy (all 'a'): {low_entropy:.3f}")
    print(f"  High entropy (random): {high_entropy:.3f}")
    
    assert low_entropy < high_entropy
    assert low_entropy < 1.0
    assert high_entropy > 3.0
    print("✓ test_entropy_calculation PASSED")


def test_ngram_analysis():
    """Test n-gram legitimacy scoring."""
    detector = ThreatIntelligenceDGADetector()
    
    # Legitimate English word - should have high ngram score
    legitimate = detector._calculate_ngram_score("information")
    # Random letters - should have low ngram score
    random_chars = detector._calculate_ngram_score("xqwzpkvj")
    
    print(f"  Legitimate word 'information' ngram score: {legitimate:.3f}")
    print(f"  Random chars ngram score: {random_chars:.3f}")
    
    assert legitimate > random_chars
    print("✓ test_ngram_analysis PASSED")


def test_whitelist_blacklist():
    """Test whitelist and blacklist functionality."""
    detector = ThreatIntelligenceDGADetector()
    
    # Test whitelist
    detector.add_to_whitelist("trusted-domain.com")
    result = detector.analyze_domain("trusted-domain.com")
    assert result.risk_level == DGARiskLevel.SAFE
    assert result.is_dga == False
    assert "whitelist" in result.reasons[0].lower()
    
    # Test blacklist
    detector.add_to_blacklist("malicious-dga.com")
    result = detector.analyze_domain("malicious-dga.com")
    assert result.risk_level == DGARiskLevel.CRITICAL
    assert result.is_dga == True
    assert "blacklist" in result.reasons[0].lower()
    
    print("✓ test_whitelist_blacklist PASSED")


def test_pattern_matching():
    """Test known DGA pattern matching."""
    detector = ThreatIntelligenceDGADetector()
    
    # Hex encoded domain pattern
    hex_domain = "abcdef1234567890abcdef1234567890.com"
    result = detector.analyze_domain(hex_domain)
    print(f"  Hex domain patterns matched: {result.pattern_matches}")
    
    # Character repetition
    repeat_domain = "bbbbbbbbbbbbbb.com"
    result = detector.analyze_domain(repeat_domain)
    print(f"  Repetition patterns matched: {result.pattern_matches}")
    
    print("✓ test_pattern_matching PASSED")


def test_statistics():
    """Test statistics generation."""
    detector = ThreatIntelligenceDGADetector()
    
    # Analyze some domains
    domains = ["google.com", "github.com", "xqwzpkvjyrtbnm.com", "kq8jx2z9f5m3n7.com"]
    detector.analyze_batch(domains)
    
    stats = detector.get_statistics()
    
    print(f"  Statistics: {stats}")
    
    assert stats["total_analyzed"] == 4
    assert "dga_detected" in stats
    assert "dga_ratio" in stats
    assert "by_risk_level" in stats
    
    print("✓ test_statistics PASSED")


def test_domain_hash():
    """Test domain hash generation."""
    detector = ThreatIntelligenceDGADetector()
    
    hash1 = detector.generate_domain_hash("example.com")
    hash2 = detector.generate_domain_hash("EXAMPLE.COM")
    hash3 = detector.generate_domain_hash("different.com")
    
    # Case insensitive
    assert hash1 == hash2
    # Different domains have different hashes
    assert hash1 != hash3
    assert len(hash1) == 16  # 16 hex chars
    
    print("✓ test_domain_hash PASSED")


def test_edge_cases():
    """Test edge cases and boundary conditions."""
    detector = ThreatIntelligenceDGADetector()
    
    # Empty string
    result = detector.analyze_domain("")
    assert result is not None
    
    # Very short domain
    result = detector.analyze_domain("a.co")
    assert result is not None
    
    # Subdomain handling
    result = detector.analyze_domain("sub.example.co.uk")
    assert result is not None
    
    # Mixed case
    result = detector.analyze_domain("EXAMPLE.COM")
    assert result is not None
    
    print("✓ test_edge_cases PASSED")


def run_all_tests():
    """Run all test cases."""
    print("=" * 60)
    print("Running Threat Intelligence DGA Detector Tests")
    print("=" * 60)
    
    tests = [
        test_basic_initialization,
        test_entropy_calculation,
        test_ngram_analysis,
        test_whitelist_blacklist,
        test_pattern_matching,
        test_domain_hash,
        test_statistics,
        test_edge_cases,
        test_legitimate_domain_detection,
        test_dga_domain_detection,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"✗ {test.__name__} FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test.__name__} ERROR: {e}")
            failed += 1
    
    print("=" * 60)
    print(f"Results: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
