#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Signature Auto-Generation Engine
Production-grade tests with real validation
June 2026
"""

import sys
import os
import json
import time

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_signature_auto_generator_engine_2026_june import (
    SignatureAutoGeneratorEngine,
    PatternExtractor,
    YARAGenerator,
    SNORTGenerator,
    ThreatPattern
)


def test_pattern_extractor():
    """Test pattern extraction functionality"""
    print("=== Testing Pattern Extractor ===")
    
    extractor = PatternExtractor()
    
    # Test string pattern extraction
    test_content = """
    malicious_payload malicious_payload malicious_payload
    Connect to C2 server at 192.168.1.100
    Download from evil-domain.com and malware-site.net
    malicious_payload malicious_payload
    """
    
    string_patterns = extractor.extract_string_patterns(test_content)
    print(f"  Extracted {len(string_patterns)} string patterns")
    
    # Test regex pattern extraction
    regex_patterns = extractor.extract_regex_patterns(test_content)
    print(f"  Extracted {len(regex_patterns)} regex patterns")
    
    # Test byte pattern extraction
    byte_content = b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90TESTTESTTEST"
    byte_patterns = extractor.extract_byte_patterns(byte_content)
    print(f"  Extracted {len(byte_patterns)} byte patterns")
    
    return len(string_patterns) > 0 or len(regex_patterns) > 0


def test_yara_generator():
    """Test YARA rule generation"""
    print("\n=== Testing YARA Generator ===")
    
    yara_gen = YARAGenerator()
    
    # Create test patterns
    patterns = [
        ThreatPattern(
            pattern_id="test1",
            pattern_type="string",
            content="malicious_payload",
            confidence=0.9,
            threat_type="payload",
            source="test",
            severity="high"
        ),
        ThreatPattern(
            pattern_id="test2",
            pattern_type="regex",
            content="192.168.1.100",
            confidence=0.85,
            threat_type="c2",
            source="test",
            severity="critical"
        )
    ]
    
    signature = yara_gen.generate_rule(
        patterns,
        rule_name="Test_Malware_Detection",
        description="Auto-generated test rule for malware detection"
    )
    
    print(f"  Generated YARA rule ID: {signature.signature_id}")
    print(f"  Confidence score: {signature.confidence_score:.2f}")
    print(f"  False positive risk: {signature.false_positive_risk}")
    print(f"  Patterns used: {len(signature.patterns_used)}")
    print("\n  Rule content preview:")
    print("  " + signature.rule_content[:200].replace("\n", "\n  ") + "...")
    
    # Validate YARA syntax
    assert "rule " in signature.rule_content
    assert "meta:" in signature.rule_content
    assert "strings:" in signature.rule_content
    assert "condition:" in signature.rule_content
    
    return True


def test_snort_generator():
    """Test SNORT rule generation"""
    print("\n=== Testing SNORT Generator ===")
    
    snort_gen = SNORTGenerator()
    
    patterns = [
        ThreatPattern(
            pattern_id="test1",
            pattern_type="string",
            content="malicious_payload",
            confidence=0.9,
            threat_type="payload",
            source="test",
            severity="high"
        )
    ]
    
    signature = snort_gen.generate_rule(
        patterns,
        rule_name="NeuralShield Malicious Payload Detected"
    )
    
    print(f"  Generated SNORT rule ID: {signature.signature_id}")
    print(f"  Confidence score: {signature.confidence_score:.2f}")
    
    # Validate SNORT syntax
    assert "alert " in signature.rule_content
    assert "msg:" in signature.rule_content
    assert "content:" in signature.rule_content
    assert "sid:" in signature.rule_content
    
    return True


def test_signature_engine_basic():
    """Test main signature generation engine with basic sample"""
    print("\n=== Testing Signature Auto-Generation Engine ===")
    
    engine = SignatureAutoGeneratorEngine()
    
    # Simulated malware payload sample
    threat_sample = """
    BEGIN MALWARE PAYLOAD
    X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
    C2 Server: command-control.bad-domain.com
    Callback IP: 10.0.0.254
    Payload hash: abcdef1234567890abcdef1234567890
    Encryption: AES-256-CBC
    Registry: HKCU\\Software\\Malicious\\Payload
    File: malicious_executable.exe
    malicious_executable.exe malicious_executable.exe
    END MALWARE PAYLOAD
    """
    
    result = engine.process_threat_sample(
        threat_sample,
        sample_type='text',
        threat_name='Test_Malware_Sample'
    )
    
    print(f"  Processing successful: {result['success']}")
    print(f"  Patterns extracted: {result['patterns_extracted']}")
    print(f"  High confidence patterns: {result['high_confidence_patterns']}")
    print(f"  Signatures generated: {result['signatures_generated']}")
    print(f"  Processing time: {result['processing_time']:.4f}s")
    
    for sig in result['signatures']:
        print(f"    - {sig.signature_type.upper()} rule: {sig.signature_id} (conf: {sig.confidence_score:.2f})")
    
    assert result['success'] == True
    assert result['signatures_generated'] > 0
    
    return True


def test_batch_processing():
    """Test batch processing of multiple threat samples"""
    print("\n=== Testing Batch Processing ===")
    
    engine = SignatureAutoGeneratorEngine()
    
    samples = [
        {
            'content': 'Ransomware payload: encrypt_all_files encrypt_all_files payment@bitcoin.com',
            'type': 'text',
            'name': 'Ransomware_Sample_1'
        },
        {
            'content': 'Phishing credential harvester login-form fake-bank.com',
            'type': 'text',
            'name': 'Phishing_Sample_1'
        },
        {
            'content': 'Backdoor reverse_shell connect_back 172.16.0.10',
            'type': 'text',
            'name': 'Backdoor_Sample_1'
        }
    ]
    
    result = engine.batch_process_samples(samples)
    
    print(f"  Batch size: {result['batch_size']}")
    print(f"  Total signatures generated: {result['total_signatures']}")
    print(f"  Total patterns extracted: {result['total_patterns']}")
    
    assert result['total_signatures'] > 0
    
    return True


def test_signature_export():
    """Test signature export functionality"""
    print("\n=== Testing Signature Export ===")
    
    engine = SignatureAutoGeneratorEngine()
    
    # Process a sample first
    engine.process_threat_sample(
        "test_malware test_malware test_malware bad-domain.com",
        threat_name="Export_Test"
    )
    
    # Test JSON export
    json_export = engine.export_signatures('json')
    print(f"  JSON export length: {len(json_export)} chars")
    assert len(json_export) > 0
    
    # Parse and validate JSON
    parsed = json.loads(json_export)
    print(f"  Exported {len(parsed)} signatures in JSON")
    
    # Test raw export
    raw_export = engine.export_signatures('raw')
    print(f"  Raw export length: {len(raw_export)} chars")
    assert len(raw_export) > 0
    
    return True


def test_engine_statistics():
    """Test engine statistics tracking"""
    print("\n=== Testing Engine Statistics ===")
    
    engine = SignatureAutoGeneratorEngine()
    
    # Process multiple samples
    for i in range(5):
        engine.process_threat_sample(
            f"pattern_{i} pattern_{i} pattern_{i} domain{i}.com",
            threat_name=f"Stat_Test_{i}"
        )
    
    stats = engine.get_statistics()
    print(f"  Total samples processed: {stats.get('total_samples_processed', 0)}")
    print(f"  Total signatures generated: {stats.get('total_signatures_generated', 0)}")
    print(f"  Total patterns detected: {stats.get('total_patterns_detected', 0)}")
    print(f"  YARA rules: {stats.get('yara_rules', 0)}")
    print(f"  SNORT rules: {stats.get('snort_rules', 0)}")
    print(f"  Average confidence: {stats.get('avg_confidence', 0):.3f}")
    
    assert stats['total_samples_processed'] == 5
    assert stats['total_signatures_generated'] > 0
    
    return True


def run_all_tests():
    """Run all tests and save results"""
    print("=" * 60)
    print("Threat Intelligence Signature Auto-Generation Engine Tests")
    print("=" * 60)
    print(f"Test started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    tests = [
        ("Pattern Extractor", test_pattern_extractor),
        ("YARA Generator", test_yara_generator),
        ("SNORT Generator", test_snort_generator),
        ("Basic Engine Functionality", test_signature_engine_basic),
        ("Batch Processing", test_batch_processing),
        ("Signature Export", test_signature_export),
        ("Engine Statistics", test_engine_statistics),
    ]
    
    results = {}
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            if result:
                results[test_name] = "PASSED"
                passed += 1
            else:
                results[test_name] = "FAILED"
                failed += 1
        except Exception as e:
            results[test_name] = f"ERROR: {str(e)}"
            failed += 1
            print(f"  EXCEPTION: {e}")
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    for test_name, result in results.items():
        status = "✓" if result == "PASSED" else "✗"
        print(f"  {status} {test_name}: {result}")
    
    print(f"\n  Total: {passed} PASSED, {failed} FAILED")
    print(f"  Success rate: {passed/(passed+failed)*100:.1f}%")
    
    # Save results
    result_data = {
        "test_timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
        "module": "threat_intelligence_signature_auto_generator_engine",
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": passed/(passed+failed)*100,
        "results": results
    }
    
    with open("test_results_signature_auto_generator_engine.json", "w") as f:
        json.dump(result_data, f, indent=2)
    
    print(f"\n  Results saved to test_results_signature_auto_generator_engine.json")
    print("=" * 60)
    
    return passed == len(tests)


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
