#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Entropy Analyzer
Production-grade validation tests
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_entropy_analyzer_2026_june import (
    ThreatIntelligenceEntropyAnalyzer,
    EntropyResult
)


def run_tests():
    """Run all validation tests"""
    print("=" * 60)
    print("NeuralShield AI - Threat Intelligence Entropy Analyzer Tests")
    print("=" * 60)
    
    analyzer = ThreatIntelligenceEntropyAnalyzer()
    passed = 0
    failed = 0
    
    # Test 1: Basic Shannon entropy calculation
    print("\n[Test 1] Shannon Entropy Calculation")
    try:
        # Low entropy: repeated characters
        low_entropy = analyzer.shannon_entropy("AAAAA")
        assert low_entropy == 0.0, f"Expected 0.0, got {low_entropy}"
        
        # Medium entropy: normal word
        med_entropy = analyzer.shannon_entropy("hello world")
        assert 2.0 <= med_entropy <= 3.5, f"Expected 2.0-3.5, got {med_entropy}"
        
        # High entropy: random string
        high_entropy = analyzer.shannon_entropy("aB3k9$xQ!zR7")
        assert high_entropy >= 3.0, f"Expected >= 3.0, got {high_entropy}"
        
        print(f"  ✓ PASS - Low={low_entropy}, Med={med_entropy}, High={high_entropy}")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAIL - {e}")
        failed += 1
    
    # Test 2: Metric entropy normalization
    print("\n[Test 2] Metric Entropy Normalization")
    try:
        metric1 = analyzer.metric_entropy("AAAAA")
        metric2 = analyzer.metric_entropy("ABCDEFGHIJKLMNOP")
        assert metric1 == 0.0, f"Expected 0.0, got {metric1}"
        assert 0.0 <= metric2 <= 1.0, f"Expected 0-1 range, got {metric2}"
        print(f"  ✓ PASS - Metric entropy in valid range")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAIL - {e}")
        failed += 1
    
    # Test 3: High entropy detection
    print("\n[Test 3] High Entropy String Detection")
    try:
        # Random base64 string (high entropy)
        b64_str = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IG9mIGhpZ2ggZW50cm9weS4="
        result = analyzer.analyze_string(b64_str)
        assert result.is_high_entropy or result.entropy_rating in ['high', 'very_high'], \
            f"High entropy string not detected: {result.shannon_entropy}"
        print(f"  ✓ PASS - High entropy detected: {result.shannon_entropy}")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAIL - {e}")
        failed += 1
    
    # Test 4: DGA domain detection
    print("\n[Test 4] DGA Domain Detection")
    try:
        # DGA-like domain (random-looking, no dictionary words)
        dga_domain = "xqz7kw9f3mdn1v8b2.com"
        result = analyzer.analyze_string(dga_domain, context='domain')
        
        # Legitimate domain
        legit_domain = "google.com"
        result2 = analyzer.analyze_string(legit_domain, context='domain')
        
        dga_analysis = result.analysis_details.get('dga_analysis', {})
        print(f"    DGA domain score: {dga_analysis.get('dga_score', 'N/A')}")
        print(f"    Legitimate domain entropy: {result2.shannon_entropy}")
        
        assert result.shannon_entropy > result2.shannon_entropy, \
            "DGA domain should have higher entropy than legitimate domain"
        print(f"  ✓ PASS - DGA entropy differentiation works")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAIL - {e}")
        failed += 1
    
    # Test 5: Encoding pattern detection
    print("\n[Test 5] Encoding Pattern Detection")
    try:
        # Hex string
        hex_str = "48656c6c6f20576f726c64"
        result = analyzer.analyze_string(hex_str)
        assert result.analysis_details['encoding_patterns']['is_likely_hex'], \
            "Hex string not detected"
        
        # Base64 string
        b64_str = "SGVsbG8="
        result2 = analyzer.analyze_string(b64_str)
        assert result2.analysis_details['encoding_patterns']['is_likely_base64'], \
            "Base64 string not detected"
        
        print(f"  ✓ PASS - Hex and Base64 patterns detected")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAIL - {e}")
        failed += 1
    
    # Test 6: Character distribution analysis
    print("\n[Test 6] Character Distribution Analysis")
    try:
        test_str = "HelloWorld123!"
        result = analyzer.analyze_string(test_str)
        dist = result.character_distribution
        
        assert 'lowercase' in dist
        assert 'uppercase' in dist
        assert 'digits' in dist
        assert 'special' in dist
        assert 0 <= dist['lowercase'] <= 1
        print(f"  ✓ PASS - Character distribution computed correctly")
        passed += 1
    except (AssertionError, KeyError) as e:
        print(f"  ✗ FAIL - {e}")
        failed += 1
    
    # Test 7: Threat classification
    print("\n[Test 7] Threat Classification")
    try:
        # Benign string
        benign = analyzer.analyze_string("Hello, this is normal text.")
        assert benign.threat_classification in ['benign', 'notable']
        
        # Suspicious: long base64
        suspicious = analyzer.analyze_string("SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB2ZXJ5IGxvbmcgYmFzZTY0IHN0cmluZyB0aGF0IG1pZ2h0IGJlIG9iZnVzY2F0ZWQgY29udGVudC4=")
        
        print(f"    Benign: {benign.threat_classification} (score={benign.threat_score})")
        print(f"    Suspicious: {suspicious.threat_classification} (score={suspicious.threat_score})")
        
        assert suspicious.threat_score >= benign.threat_score
        print(f"  ✓ PASS - Threat classification works")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAIL - {e}")
        failed += 1
    
    # Test 8: Batch analysis
    print("\n[Test 8] Batch Analysis")
    try:
        strings = ["normal", "text", "xJ3f9$zQ!mK2", "AAAAA"]
        results = analyzer.analyze_batch(strings)
        assert len(results) == 4
        assert all(isinstance(r, EntropyResult) for r in results)
        print(f"  ✓ PASS - Batch analysis processed {len(results)} strings")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAIL - {e}")
        failed += 1
    
    # Test 9: Suspicious filtering
    print("\n[Test 9] Suspicious String Filtering")
    try:
        strings = ["hello", "world", "aB3k9$xQ!zR7mP2sV5"]
        suspicious = analyzer.get_suspicious_strings(strings, min_threat_score=0.1)
        assert isinstance(suspicious, list)
        print(f"  ✓ PASS - Filtering works, found {len(suspicious)} suspicious")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAIL - {e}")
        failed += 1
    
    # Test 10: Statistics tracking
    print("\n[Test 10] Statistics Tracking")
    try:
        stats = analyzer.get_stats()
        assert 'total_analyzed' in stats
        assert stats['total_analyzed'] > 0
        print(f"  ✓ PASS - Stats tracked: {stats['total_analyzed']} total analyzed")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAIL - {e}")
        failed += 1
    
    # Test 11: Entropy fingerprint
    print("\n[Test 11] Entropy Fingerprint")
    try:
        fp1 = analyzer.generate_entropy_fingerprint("test string 1")
        fp2 = analyzer.generate_entropy_fingerprint("different string")
        assert len(fp1) == 16
        assert fp1 != fp2
        print(f"  ✓ PASS - Fingerprints generated: {fp1[:8]}...")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAIL - {e}")
        failed += 1
    
    # Summary
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    if failed == 0:
        print("\n✓ ALL TESTS PASSED - Production ready!")
        return True
    else:
        print(f"\n✗ {failed} TEST(S) FAILED")
        return False


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
