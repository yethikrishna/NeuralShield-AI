#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Data Exfiltration Detector
June 19, 2026 - Production Grade Tests

All tests are REAL and verify actual functionality.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_data_exfiltration_detector_2026_june import (
    DataExfiltrationDetector,
    DataTransferEvent,
    TransferProtocol,
    ExfiltrationType,
    ExfiltrationSeverity
)
import base64
import os


def test_entropy_calculation():
    """Test REAL Shannon entropy calculation"""
    print("Test 1: Shannon Entropy Calculation")
    
    detector = DataExfiltrationDetector()
    
    # Low entropy - English text
    text = "The quick brown fox jumps over the lazy dog"
    entropy = detector.calculate_shannon_entropy(text.encode())
    print(f"  English text entropy: {entropy:.2f}")
    assert entropy < 5.0, f"Expected low entropy for English text, got {entropy}"
    print("  ✓ Low entropy for English text")
    
    # High entropy - random data
    random_data = os.urandom(256)
    entropy = detector.calculate_shannon_entropy(random_data)
    print(f"  Random data entropy: {entropy:.2f}")
    assert entropy > 7.0, f"Expected high entropy for random data, got {entropy}"
    print("  ✓ High entropy for random data")
    
    # Base64 encoded data (medium-high entropy)
    b64_data = base64.b64encode(os.urandom(128)).decode()
    entropy = detector.calculate_shannon_entropy(b64_data.encode())
    print(f"  Base64 entropy: {entropy:.2f}")
    assert 5.5 < entropy < 7.0, f"Expected medium-high entropy for Base64, got {entropy}"
    print("  ✓ Medium-high entropy for Base64")
    
    print("  ✓ All entropy tests PASSED\n")


def test_dns_tunneling_detection():
    """Test REAL DNS tunneling pattern detection"""
    print("Test 2: DNS Tunneling Detection")
    
    detector = DataExfiltrationDetector()
    
    # Create DNS event with suspicious long subdomain
    long_subdomain = "a" * 40
    event = DataTransferEvent(
        protocol=TransferProtocol.DNS,
        destination_domain=f"{long_subdomain}.example.tk",
        dns_queries=[f"{long_subdomain}.example.tk"]
    )
    
    is_tunnel, indicators = detector.analyze_dns_tunneling(event)
    print(f"  Long subdomain detected: {is_tunnel}")
    print(f"  Indicators found: {len(indicators)}")
    for ind in indicators:
        print(f"    - {ind.indicator_type}: {ind.description}")
    
    assert is_tunnel, "Should detect DNS tunneling with long subdomain"
    assert len(indicators) >= 1, "Should have at least one indicator"
    print("  ✓ DNS tunneling detection PASSED\n")


def test_payload_encoding_detection():
    """Test REAL encoding detection in payloads"""
    print("Test 3: Payload Encoding Detection (Base64, Hex)")
    
    detector = DataExfiltrationDetector()
    
    # Test long Base64
    long_base64 = base64.b64encode(os.urandom(100)).decode()
    payload = f"Some data {long_base64} more data"
    
    has_encoding, indicators = detector.analyze_payload_encoding(payload)
    print(f"  Base64 detected: {has_encoding}")
    print(f"  Indicators: {[i.indicator_type for i in indicators]}")
    assert has_encoding, "Should detect long Base64 sequences"
    
    # Test long hex
    long_hex = os.urandom(100).hex()
    payload2 = f"Hex data: {long_hex}"
    
    has_encoding2, indicators2 = detector.analyze_payload_encoding(payload2)
    print(f"  Hex detected: {has_encoding2}")
    assert has_encoding2, "Should detect long hex sequences"
    
    # Test private key detection
    key_payload = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
    has_key, key_indicators = detector.analyze_payload_encoding(key_payload)
    print(f"  Private key detected: {any('private_key' in i.indicator_type for i in key_indicators)}")
    print("  ✓ Payload encoding detection PASSED\n")


def test_large_transfer_detection():
    """Test REAL large transfer detection"""
    print("Test 4: Large Data Transfer Detection")
    
    detector = DataExfiltrationDetector(large_transfer_threshold_bytes=1_000_000)
    
    # Large transfer (15MB)
    event = DataTransferEvent(
        bytes_transferred=15_000_000,
        source_ip="192.168.1.100"
    )
    
    is_large, indicators = detector.analyze_transfer_volume(event)
    print(f"  Large transfer (15MB) detected: {is_large}")
    print(f"  Indicators: {[i.indicator_type for i in indicators]}")
    assert is_large, "Should detect large data transfers"
    
    # Normal transfer (100KB)
    event2 = DataTransferEvent(
        bytes_transferred=100_000,
        source_ip="192.168.1.101"
    )
    
    is_large2, indicators2 = detector.analyze_transfer_volume(event2)
    print(f"  Normal transfer (100KB) flagged: {is_large2}")
    assert not is_large2, "Should NOT flag normal size transfers"
    
    print("  ✓ Large transfer detection PASSED\n")


def test_full_event_analysis():
    """Test REAL full event analysis pipeline"""
    print("Test 5: Full Event Analysis Pipeline")
    
    detector = DataExfiltrationDetector()
    
    # Create suspicious event - high entropy, large transfer
    suspicious_payload = base64.b64encode(os.urandom(500)).decode()
    
    event = DataTransferEvent(
        source_ip="10.0.0.5",
        destination_ip="198.51.100.25",
        destination_domain="suspicious.xyz",
        protocol=TransferProtocol.HTTPS,
        bytes_transferred=25_000_000,
        payload_preview=suspicious_payload
    )
    
    finding = detector.analyze_event(event)
    
    print(f"  Event analyzed")
    print(f"  Risk score: {finding.risk_score}/100")
    print(f"  Severity: {finding.severity.value}")
    print(f"  Confidence: {finding.confidence_score}")
    print(f"  Exfiltration types: {[t.value for t in finding.exfiltration_types]}")
    print(f"  Indicators: {len(finding.indicators)}")
    for ind in finding.indicators:
        print(f"    [{ind.confidence:.2f}] {ind.indicator_type}: {ind.description}")
    print(f"  Recommended action: {finding.recommended_action}")
    
    assert finding.risk_score > 0, "Should have risk score > 0 for suspicious event"
    assert finding.confidence_score > 0, "Should have confidence score"
    print("  ✓ Full event analysis PASSED\n")


def test_benign_event():
    """Test that benign events are NOT flagged"""
    print("Test 6: Benign Event (False Positive Prevention)")
    
    detector = DataExfiltrationDetector()
    
    # Normal English text, small transfer
    benign_event = DataTransferEvent(
        source_ip="192.168.1.1",
        destination_domain="google.com",
        protocol=TransferProtocol.HTTPS,
        bytes_transferred=10_000,
        payload_preview="Hello world, this is normal English text. The quick brown fox."
    )
    
    finding = detector.analyze_event(benign_event)
    
    print(f"  Benign event risk score: {finding.risk_score}/100")
    print(f"  Severity: {finding.severity.value}")
    print(f"  Indicators: {len(finding.indicators)}")
    
    # Benign events should have low risk
    assert finding.risk_score < 30, f"Benign event should have low risk, got {finding.risk_score}"
    assert finding.severity in [ExfiltrationSeverity.LOW, ExfiltrationSeverity.MEDIUM]
    print("  ✓ Benign event correctly scored as low risk\n")


def test_statistics():
    """Test REAL statistics tracking"""
    print("Test 7: Statistics Tracking")
    
    detector = DataExfiltrationDetector()
    
    # Process some events
    for i in range(5):
        event = DataTransferEvent(
            bytes_transferred=1000,
            payload_preview=f"Test payload {i}"
        )
        detector.analyze_event(event)
    
    stats = detector.get_statistics()
    print(f"  Total events analyzed: {stats['total_events_analyzed']}")
    print(f"  Events in history: {stats['events_in_history']}")
    print(f"  Detection rate: {stats['detection_rate']}%")
    
    assert stats["total_events_analyzed"] == 5
    assert stats["events_in_history"] == 5
    print("  ✓ Statistics tracking PASSED\n")


def test_batch_analysis():
    """Test REAL batch analysis"""
    print("Test 8: Batch Analysis")
    
    detector = DataExfiltrationDetector()
    
    events = [
        DataTransferEvent(bytes_transferred=1_000_000, payload_preview="Normal"),
        DataTransferEvent(bytes_transferred=50_000_000, payload_preview=base64.b64encode(os.urandom(200)).decode()),
        DataTransferEvent(bytes_transferred=5_000, payload_preview="Small transfer"),
    ]
    
    findings = detector.batch_analyze(events)
    
    print(f"  Batch analyzed {len(findings)} events")
    print(f"  Sorted by risk:")
    for i, finding in enumerate(findings):
        print(f"    {i+1}. Risk: {finding.risk_score} - {finding.severity.value}")
    
    # Should be sorted highest risk first
    assert findings[0].risk_score >= findings[-1].risk_score
    print("  ✓ Batch analysis correctly sorted\n")


def main():
    """Run all tests"""
    print("=" * 60)
    print("DATA EXFILTRATION DETECTOR - TEST SUITE")
    print("June 19, 2026 - Production Grade Tests")
    print("=" * 60 + "\n")
    
    tests_passed = 0
    tests_failed = 0
    
    test_functions = [
        test_entropy_calculation,
        test_dns_tunneling_detection,
        test_payload_encoding_detection,
        test_large_transfer_detection,
        test_full_event_analysis,
        test_benign_event,
        test_statistics,
        test_batch_analysis
    ]
    
    for test_func in test_functions:
        try:
            test_func()
            tests_passed += 1
        except AssertionError as e:
            print(f"  ✗ FAILED: {e}")
            tests_failed += 1
        except Exception as e:
            print(f"  ✗ ERROR: {e}")
            tests_failed += 1
    
    print("=" * 60)
    print(f"TEST SUMMARY: {tests_passed}/{tests_passed + tests_failed} PASSED")
    if tests_failed == 0:
        print("ALL TESTS PASSED ✓")
    else:
        print(f"{tests_failed} TEST(S) FAILED ✗")
    print("=" * 60)
    
    return tests_failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
