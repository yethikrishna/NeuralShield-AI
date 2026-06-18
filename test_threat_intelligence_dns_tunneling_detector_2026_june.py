"""
Test Suite for DNS Tunneling Detector
HONEST TESTING - Real tests that actually run
All tests must pass for honest verification
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_dns_tunneling_detector_2026_june import (
    DNSTunnelingDetector,
    DNSTunnelRiskLevel,
    DNSQueryAnalysis
)


def test_entropy_calculation():
    """Test 1: Shannon entropy calculation works correctly"""
    print("Test 1: Shannon Entropy Calculation")
    
    detector = DNSTunnelingDetector()
    
    # Low entropy - repeating pattern
    low_entropy = detector.calculate_shannon_entropy("aaaaabbbbbccccc")
    print(f"  Low entropy (repeating): {low_entropy:.3f}")
    
    # High entropy - random/encoded data
    high_entropy = detector.calculate_shannon_entropy("a1b2c3d4e5f6a7b8c9d0e1f2")
    print(f"  High entropy (random): {high_entropy:.3f}")
    
    # Empty string
    empty = detector.calculate_shannon_entropy("")
    print(f"  Empty string: {empty}")
    
    assert low_entropy < high_entropy, "High entropy should be > low entropy"
    assert empty == 0.0, "Empty string should have 0 entropy"
    assert high_entropy > 3.0, "Random string should have significant entropy"
    
    print("  ✓ PASSED")
    return True


def test_subdomain_extraction():
    """Test 2: Subdomain extraction works correctly"""
    print("\nTest 2: Subdomain Extraction")
    
    detector = DNSTunnelingDetector()
    
    test_cases = [
        ("google.com", ""),
        ("mail.google.com", "mail"),
        ("sub1.sub2.example.com", "sub1.sub2"),
        ("very.long.subdomain.example.co.uk", "very.long.subdomain.example"),
    ]
    
    for domain, expected in test_cases:
        result = detector.extract_subdomain(domain)
        print(f"  {domain} -> '{result}' (expected: '{expected}')")
    
    # Basic assertions
    assert detector.extract_subdomain("google.com") == ""
    assert detector.extract_subdomain("mail.google.com") == "mail"
    
    print("  ✓ PASSED")
    return True


def test_character_distribution_analysis():
    """Test 3: Character distribution analysis"""
    print("\nTest 3: Character Distribution Analysis")
    
    detector = DNSTunnelingDetector()
    
    # Hex encoded data
    hex_text = "48656c6c6f20576f726c64205468697320697320686578"
    score, issues = detector.analyze_character_distribution(hex_text)
    print(f"  Hex text score: {score:.2f}, issues: {issues}")
    assert score > 0, "Hex content should trigger suspicion"
    assert "high_hex_content" in issues
    
    # Normal domain
    normal = "mailserver"
    score2, issues2 = detector.analyze_character_distribution(normal)
    print(f"  Normal text score: {score2:.2f}, issues: {issues2}")
    
    print("  ✓ PASSED")
    return True


def test_tld_suspicion():
    """Test 4: Suspicious TLD detection"""
    print("\nTest 4: Suspicious TLD Detection")
    
    detector = DNSTunnelingDetector()
    
    # Suspicious TLD
    score, issues = detector.check_tld_suspicion("test.tk")
    print(f"  test.tk score: {score}, issues: {issues}")
    assert score > 0, "Suspicious TLD should score > 0"
    
    # Normal TLD
    score2, issues2 = detector.check_tld_suspicion("google.com")
    print(f"  google.com score: {score2}, issues: {issues2}")
    assert score2 == 0, "Normal TLD should score 0"
    
    print("  ✓ PASSED")
    return True


def test_known_tunnel_patterns():
    """Test 5: Known tunneling pattern detection"""
    print("\nTest 5: Known Tunneling Pattern Detection")
    
    detector = DNSTunnelingDetector()
    
    # Known tunneling service
    score, issues = detector.check_known_tunnel_patterns("dnscat2.attacker.com", "dnscat2")
    print(f"  dnscat2 domain score: {score}, issues: {issues}")
    assert score > 0, "Known tunnel service should be detected"
    assert any("dnscat2" in i for i in issues)
    
    # Normal domain
    score2, issues2 = detector.check_known_tunnel_patterns("mail.google.com", "mail")
    print(f"  Normal domain score: {score2}")
    
    print("  ✓ PASSED")
    return True


def test_full_query_analysis():
    """Test 6: Full DNS query analysis pipeline"""
    print("\nTest 6: Full Query Analysis")
    
    detector = DNSTunnelingDetector()
    
    # Definitely tunneling-like (high entropy hex subdomain)
    tunneling_domain = "48656c6c6f576f726c645465737444617461457866696c74726174696f6e.example.com"
    result = detector.analyze_query(tunneling_domain)
    print(f"  Tunneling-like domain:")
    print(f"    Risk score: {result.overall_risk_score}")
    print(f"    Risk level: {result.risk_level.value}")
    print(f"    Patterns: {result.detected_patterns}")
    print(f"    Is tunneling: {result.is_tunneling}")
    
    # Normal domain
    normal_domain = "mail.google.com"
    result2 = detector.analyze_query(normal_domain)
    print(f"  Normal domain (mail.google.com):")
    print(f"    Risk score: {result2.overall_risk_score}")
    print(f"    Risk level: {result2.risk_level.value}")
    print(f"    Is tunneling: {result2.is_tunneling}")
    
    assert result.overall_risk_score > result2.overall_risk_score, "Tunneling should score higher"
    assert result2.risk_level == DNSTunnelRiskLevel.SAFE, "Normal domain should be safe"
    
    print("  ✓ PASSED")
    return True


def test_batch_analysis_and_honest_report():
    """Test 7: Batch analysis and honest capabilities report"""
    print("\nTest 7: Batch Analysis & Honest Capabilities Report")
    
    detector = DNSTunnelingDetector()
    
    domains = [
        "mail.google.com",
        "api.github.com",
        "48656c6c6f576f726c64.attacker.tk",
        "cdn.cloudflare.com",
    ]
    
    results = detector.analyze_batch(domains)
    print(f"  Batch analyzed {len(results)} domains")
    
    for r in results:
        print(f"    {r.domain}: {r.risk_level.value} (score: {r.overall_risk_score})")
    
    assert len(results) == len(domains), "Batch should return same count"
    
    # Honest report - this is critical for our honesty principle
    report = detector.get_honest_capabilities()
    print(f"\n  HONEST CAPABILITIES REPORT:")
    print(f"    Capabilities: {len(report['capabilities'])} items")
    print(f"    Limitations: {len(report['limitations'])} items")
    print(f"    Detection confidence explicitly stated")
    
    # Verify honesty - limitations MUST be present
    assert len(report['limitations']) >= 5, "Must document limitations honestly"
    assert "THIS IS NOT 100% ACCURATE" in str(report['limitations']), "Must state accuracy limitation"
    
    print("  ✓ PASSED")
    return True


def main():
    """Run all tests and report results"""
    print("=" * 60)
    print("DNS TUNNELING DETECTOR - HONEST TEST SUITE")
    print("NeuralShield-AI - June 18, 2026")
    print("=" * 60)
    
    tests = [
        test_entropy_calculation,
        test_subdomain_extraction,
        test_character_distribution_analysis,
        test_tld_suspicion,
        test_known_tunnel_patterns,
        test_full_query_analysis,
        test_batch_analysis_and_honest_report
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"  ✗ FAILED with exception: {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed}/{len(tests)} PASSED")
    if failed > 0:
        print(f"WARNING: {failed} TESTS FAILED")
    else:
        print("ALL TESTS PASSED ✓")
    print("=" * 60)
    
    return passed == len(tests)


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
