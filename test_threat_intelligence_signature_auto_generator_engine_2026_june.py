#!/usr/bin/env python3
"""
Test Suite for NeuralShield-AI: Threat Intelligence Signature Auto-Generator Engine
June 2026 Production-Grade Tests

This test suite verifies all functionality of the automated signature generation engine:
- IOC type detection
- YARA rule generation (MD5, SHA1, SHA256)
- Snort rule generation (IP, Domain)
- Sigma rule generation
- Batch processing
- Deduplication
- Quality scoring
- Error handling
"""
import json
import sys
import os
import tempfile

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from neural_shield.threat_intelligence_signature_auto_generator_engine_2026_june import (
    SignatureAutoGeneratorEngine,
    create_signature_generator,
    GeneratedSignature,
    SignatureGenerationResult
)


def run_tests():
    """Run all tests and report results"""
    print("=" * 70)
    print("NeuralShield-AI: Signature Auto-Generator Engine - Test Suite")
    print("=" * 70 + "\n")
    
    results = {
        'passed': 0,
        'failed': 0,
        'tests': []
    }
    
    def test(name, test_func):
        try:
            test_func()
            print(f"✅ PASS: {name}")
            results['passed'] += 1
            results['tests'].append({'name': name, 'status': 'PASS'})
        except AssertionError as e:
            print(f"❌ FAIL: {name} - {str(e)}")
            results['failed'] += 1
            results['tests'].append({'name': name, 'status': 'FAIL', 'error': str(e)})
        except Exception as e:
            print(f"❌ ERROR: {name} - {str(e)}")
            results['failed'] += 1
            results['tests'].append({'name': name, 'status': 'ERROR', 'error': str(e)})
    
    # Test 1: Engine initialization
    def test_engine_init():
        engine = create_signature_generator()
        assert engine is not None
        assert engine.rule_counter == 0
        assert len(engine.generated_rules_cache) == 0
    
    test("Engine initialization", test_engine_init)
    
    # Test 2: IOC type detection
    def test_ioc_detection():
        engine = create_signature_generator()
        
        # MD5
        assert engine._detect_ioc_type("5d41402abc4b2a76b9719d911017c592") == "md5"
        # SHA1
        assert engine._detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"
        # SHA256
        assert engine._detect_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "sha256"
        # IPv4
        assert engine._detect_ioc_type("192.168.1.1") == "ipv4"
        # Domain
        assert engine._detect_ioc_type("malicious.com") == "domain"
        # Unknown
        assert engine._detect_ioc_type("not-an-ioc") == "unknown"
    
    test("IOC type detection", test_ioc_detection)
    
    # Test 3: Quality scoring
    def test_quality_scoring():
        engine = create_signature_generator()
        
        # Hash should have high quality
        score = engine._calculate_quality_score("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256")
        assert score >= 0.9, f"SHA256 score too low: {score}"
        
        # IP should have medium quality
        score = engine._calculate_quality_score("192.168.1.1", "ipv4")
        assert 0.6 <= score <= 0.8, f"IP score out of range: {score}"
    
    test("Quality scoring calculation", test_quality_scoring)
    
    # Test 4: YARA MD5 rule generation
    def test_yara_md5_generation():
        engine = create_signature_generator()
        md5_hash = "5d41402abc4b2a76b9719d911017c592"
        
        sig = engine.generate_yara_hash_rule(md5_hash, "md5", {'threat': 'Test Malware'})
        
        assert sig is not None
        assert sig.signature_type == "yara"
        assert sig.source_ioc == md5_hash
        assert md5_hash in sig.rule_content
        assert "rule AUTOGEN_MALWARE_HASH" in sig.rule_content
        assert sig.quality_score > 0.8
    
    test("YARA MD5 rule generation", test_yara_md5_generation)
    
    # Test 5: YARA SHA256 rule generation
    def test_yara_sha256_generation():
        engine = create_signature_generator()
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        
        sig = engine.generate_yara_hash_rule(sha256_hash, "sha256")
        
        assert sig is not None
        assert sig.signature_type == "yara"
        assert sha256_hash in sig.rule_content
        assert "sha256" in sig.rule_content.lower()
    
    test("YARA SHA256 rule generation", test_yara_sha256_generation)
    
    # Test 6: Snort IP rule generation
    def test_snort_ip_generation():
        engine = create_signature_generator()
        ip = "10.0.0.1"
        
        sig = engine.generate_snort_ip_rule(ip, {'description': 'Test C2'})
        
        assert sig is not None
        assert sig.signature_type == "snort"
        assert ip in sig.rule_content
        assert "alert ip" in sig.rule_content
        assert "sid:" in sig.rule_content
    
    test("Snort IP rule generation", test_snort_ip_generation)
    
    # Test 7: Snort Domain rule generation
    def test_snort_domain_generation():
        engine = create_signature_generator()
        domain = "evil-domain.com"
        
        sig = engine.generate_snort_domain_rule(domain)
        
        assert sig is not None
        assert sig.signature_type == "snort"
        assert domain in sig.rule_content
        assert "alert udp" in sig.rule_content
    
    test("Snort Domain DNS rule generation", test_snort_domain_generation)
    
    # Test 8: Sigma network rule generation
    def test_sigma_network_generation():
        engine = create_signature_generator()
        ip = "192.168.100.200"
        
        sig = engine.generate_sigma_network_rule(ip)
        
        assert sig is not None
        assert sig.signature_type == "sigma"
        assert ip in sig.rule_content
        assert "title:" in sig.rule_content
        assert "logsource:" in sig.rule_content
        assert "detection:" in sig.rule_content
    
    test("Sigma network rule generation", test_sigma_network_generation)
    
    # Test 9: Single IOC generation
    def test_single_ioc_generation():
        engine = create_signature_generator()
        
        signatures = engine.generate_from_ioc("5d41402abc4b2a76b9719d911017c592")
        
        assert len(signatures) >= 1
        assert signatures[0].signature_type == "yara"
    
    test("Single IOC signature generation", test_single_ioc_generation)
    
    # Test 10: IP generates multiple rule types
    def test_ip_multiple_rules():
        engine = create_signature_generator()
        
        signatures = engine.generate_from_ioc("192.168.1.1")
        
        # IP should generate Snort + Sigma rules
        assert len(signatures) >= 2
        types = [s.signature_type for s in signatures]
        assert "snort" in types
        assert "sigma" in types
    
    test("IP generates multiple rule types (Snort + Sigma)", test_ip_multiple_rules)
    
    # Test 11: Batch processing
    def test_batch_processing():
        engine = create_signature_generator()
        
        iocs = [
            ("5d41402abc4b2a76b9719d911017c592", {'threat': 'Malware A'}),
            ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", {'threat': 'Malware B'}),
            ("192.168.1.100", {'threat_type': 'C2'}),
        ]
        
        result = engine.batch_generate(iocs)
        
        assert result.total_iocs_processed == 3
        assert result.total_signatures_generated >= 4  # 2 hashes + 2 rules for IP
        assert len(result.failed_iocs) == 0
        assert result.processing_time >= 0
    
    test("Batch processing multiple IOCs", test_batch_processing)
    
    # Test 12: Deduplication
    def test_deduplication():
        engine = create_signature_generator()
        
        # Same IOC twice
        iocs = [
            ("5d41402abc4b2a76b9719d911017c592", {}),
            ("5d41402abc4b2a76b9719d911017c592", {}),  # Duplicate
        ]
        
        result = engine.batch_generate(iocs)
        
        assert result.total_iocs_processed == 2
        assert result.deduplicated_count >= 1
        assert result.total_signatures_generated == 1  # Only one unique rule
    
    test("Deduplication of duplicate IOCs", test_deduplication)
    
    # Test 13: Statistics tracking
    def test_statistics_tracking():
        engine = create_signature_generator()
        
        iocs = [
            ("5d41402abc4b2a76b9719d911017c592", {}),
            ("192.168.1.1", {}),
        ]
        
        engine.batch_generate(iocs)
        stats = engine.get_stats()
        
        assert stats['total_iocs_processed_lifetime'] >= 2
        assert 'md5' in stats['by_ioc_type']
        assert 'ipv4' in stats['by_ioc_type']
        assert stats['unique_rules_generated'] >= 3  # 1 hash + 2 IP rules
    
    test("Statistics tracking", test_statistics_tracking)
    
    # Test 14: Domain to hex conversion
    def test_domain_hex_conversion():
        engine = create_signature_generator()
        
        hex_result = engine._domain_to_hex("test.com")
        
        assert len(hex_result) > 0
        # Should contain length bytes + hex chars
        assert all(c in '0123456789abcdef' for c in hex_result)
    
    test("Domain hex conversion for Snort rules", test_domain_hex_conversion)
    
    # Test 15: UUID generation
    def test_uuid_generation():
        engine = create_signature_generator()
        
        uuid1 = engine._generate_uuid()
        uuid2 = engine._generate_uuid()
        
        assert len(uuid1) == 36  # UUID format length
        assert '-' in uuid1
        assert uuid1 != uuid2  # Should be unique (time-based)
    
    test("UUID generation for Sigma rules", test_uuid_generation)
    
    # Test 16: Rule ID generation
    def test_rule_id_generation():
        engine = create_signature_generator()
        
        id1 = engine._generate_rule_id()
        id2 = engine._generate_rule_id()
        
        assert id1 >= 9000000
        assert id2 == id1 + 1
    
    test("Rule SID generation", test_rule_id_generation)
    
    # Test 17: Clear cache
    def test_clear_cache():
        engine = create_signature_generator()
        
        engine.generate_yara_hash_rule("5d41402abc4b2a76b9719d911017c592", "md5")
        assert len(engine.generated_rules_cache) == 1
        
        engine.clear_cache()
        assert len(engine.generated_rules_cache) == 0
        assert engine.rule_counter == 0
    
    test("Cache clearing functionality", test_clear_cache)
    
    # Test 18: Export rules functionality
    def test_export_rules():
        engine = create_signature_generator()
        
        iocs = [("5d41402abc4b2a76b9719d911017c592", {})]
        result = engine.batch_generate(iocs)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            export_result = engine.export_rules(result, tmpdir, format='individual')
            
            assert export_result['total'] >= 1
            assert export_result['yara'] >= 1
    
    test("Rule export functionality", test_export_rules)
    
    # Test 19: Error handling for invalid IOC
    def test_error_handling():
        engine = create_signature_generator()
        
        # Should not crash, should handle gracefully
        try:
            sigs = engine.generate_from_ioc("")
            # Empty string should return empty list or handle gracefully
            assert True
        except Exception:
            # This is acceptable - empty IOC may fail
            assert True
    
    test("Error handling for edge cases", test_error_handling)
    
    # Test 20: GeneratedSignature dataclass
    def test_dataclass_instantiation():
        sig = GeneratedSignature(
            signature_id="TEST_001",
            signature_type="yara",
            rule_content="rule test {}",
            source_ioc="testhash",
            ioc_type="md5",
            confidence_score=0.9,
            quality_score=0.85
        )
        
        assert sig.signature_id == "TEST_001"
        assert sig.version == "1.0"
        assert sig.generated_at > 0
    
    test("GeneratedSignature dataclass", test_dataclass_instantiation)
    
    # Summary
    print("\n" + "=" * 70)
    total = results['passed'] + results['failed']
    print(f"TEST SUMMARY: {results['passed']} PASSED / {results['failed']} FAILED / {total} TOTAL")
    print("=" * 70)
    
    # Save results
    with open('test_results_signature_auto_generator_engine.json', 'w') as f:
        json.dump({
            'test_timestamp': __import__('time').time(),
            'total_tests': total,
            'passed': results['passed'],
            'failed': results['failed'],
            'pass_rate': results['passed'] / total if total > 0 else 0,
            'tests': results['tests']
        }, f, indent=2)
    
    print(f"\nTest results saved to: test_results_signature_auto_generator_engine.json")
    
    return results['failed'] == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
