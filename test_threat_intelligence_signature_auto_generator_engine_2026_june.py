"""
Test Suite for Threat Intelligence Signature Auto-Generator Engine
NeuralShield-AI - June 2026
Production-grade testing with real assertions and validation.
"""
import json
import sys
import os

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_signature_auto_generator_2026_june import (
    ThreatSignatureGenerator,
    SignatureMetadata,
    GeneratedSignature
)

def run_tests():
    """Run all tests and return results."""
    results = {
        'total_tests': 0,
        'passed': 0,
        'failed': 0,
        'test_details': []
    }
    
    def test(name, test_func):
        results['total_tests'] += 1
        try:
            test_func()
            results['passed'] += 1
            results['test_details'].append({'name': name, 'status': 'PASSED'})
            print(f"✅ {name}")
        except Exception as e:
            results['failed'] += 1
            results['test_details'].append({'name': name, 'status': 'FAILED', 'error': str(e)})
            print(f"❌ {name}: {str(e)}")
    
    print("=" * 60)
    print("Threat Intelligence Signature Auto-Generator - Test Suite")
    print("=" * 60 + "\n")
    
    # Test 1: Generator initialization
    def test_init():
        gen = ThreatSignatureGenerator()
        assert gen.enable_optimization == True
        assert gen._lock is not None
        assert isinstance(gen._generated_signatures, dict)
    
    test("Generator initialization", test_init)
    
    # Test 2: Signature ID generation
    def test_signature_id():
        gen = ThreatSignatureGenerator()
        sig_id = gen._generate_signature_id("TEST")
        assert sig_id.startswith("TEST-SIG-")
        assert len(sig_id) > 20
        # Verify uniqueness
        sig_id2 = gen._generate_signature_id("TEST")
        assert sig_id != sig_id2
    
    test("Signature ID generation and uniqueness", test_signature_id)
    
    # Test 3: Pattern extraction from text
    def test_pattern_extraction():
        gen = ThreatSignatureGenerator()
        text = "Malware sample with DEADBEEFCAFE pattern and malicious.exe"
        patterns = gen._extract_patterns_from_text(text)
        assert len(patterns) > 0
        assert "DEADBEEFCAFE" in patterns or "malicious.exe" in patterns
    
    test("Pattern extraction from threat text", test_pattern_extraction)
    
    # Test 4: Pattern quality scoring
    def test_pattern_quality():
        gen = ThreatSignatureGenerator()
        # Hex pattern should score high
        score1 = gen._calculate_pattern_quality("DEADBEEFCAFE1234")
        assert score1 > 0.5
        # Short pattern should score lower
        score2 = gen._calculate_pattern_quality("abc")
        assert score2 < score1
    
    test("Pattern quality scoring algorithm", test_pattern_quality)
    
    # Test 5: False positive risk assessment
    def test_fp_risk():
        gen = ThreatSignatureGenerator()
        risk1 = gen._assess_false_positive_risk(["DEADBEEF", "MALWARE_SIG"])
        assert risk1 == "low"
        risk2 = gen._assess_false_positive_risk(["http", "www", "html", "json"])
        assert risk2 == "high"
    
    test("False positive risk assessment", test_fp_risk)
    
    # Test 6: YARA rule generation
    def test_yara_generation():
        gen = ThreatSignatureGenerator()
        sig = gen.generate_yara_rule(
            rule_name="Test_Malware_Detection",
            threat_description="Detects test malware with malicious patterns",
            patterns=["malicious_payload", "evil_function"],
            hex_patterns=["DEADBEEFCAFE"],
            threat_category="trojan"
        )
        assert isinstance(sig, GeneratedSignature)
        assert sig.metadata.signature_type == "yara"
        assert sig.metadata.threat_category == "trojan"
        assert "rule Test_Malware_Detection" in sig.content
        assert "$str0" in sig.content
        assert "$hex0" in sig.content
        assert "condition:" in sig.content
    
    test("YARA rule generation with strings and hex patterns", test_yara_generation)
    
    # Test 7: YARA auto-pattern extraction
    def test_yara_auto_extract():
        gen = ThreatSignatureGenerator()
        sig = gen.generate_yara_rule(
            rule_name="Auto_Extract_Test",
            threat_description="Ransomware encrypts files with AES-256 and demands bitcoin ransom",
            patterns=None  # Force auto-extraction
        )
        assert len(sig.patterns) > 0
        assert sig.metadata.confidence_score > 0
    
    test("YARA automatic pattern extraction from description", test_yara_auto_extract)
    
    # Test 8: Snort rule generation
    def test_snort_generation():
        gen = ThreatSignatureGenerator()
        sig = gen.generate_snort_rule(
            action="alert",
            protocol="tcp",
            msg="NeuralShield: Malicious C2 Traffic Detected",
            content_patterns=["malicious-c2", "evil_payload"],
            priority=1,
            classtype="trojan-activity"
        )
        assert isinstance(sig, GeneratedSignature)
        assert sig.metadata.signature_type == "snort"
        assert "alert tcp" in sig.content
        assert 'msg:"NeuralShield' in sig.content
        assert 'content:"malicious-c2"' in sig.content
        assert "sid:" in sig.content
    
    test("Snort IDS rule generation", test_snort_generation)
    
    # Test 9: Suricata HTTP rule generation
    def test_suricata_http():
        gen = ThreatSignatureGenerator()
        sig = gen.generate_suricata_http_rule(
            msg="NeuralShield: Malicious HTTP Request",
            uri_patterns=["/malicious/api", "/evil/endpoint"],
            user_agent_patterns=["MaliciousBot"]
        )
        assert isinstance(sig, GeneratedSignature)
        assert sig.metadata.signature_type == "suricata"
        assert "http_uri" in sig.content
        assert "http_user_agent" in sig.content
    
    test("Suricata HTTP inspection rule generation", test_suricata_http)
    
    # Test 10: Batch IOC signature generation
    def test_batch_ioc():
        gen = ThreatSignatureGenerator()
        iocs = {
            "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
            "domain": ["malicious-c2.com", "phishing-site.net"],
            "ip": ["192.168.1.100"]
        }
        signatures = gen.batch_generate_from_iocs(iocs, output_format="all")
        assert len(signatures) > 0
        # Verify mix of signature types
        types = set(s.metadata.signature_type for s in signatures)
        assert "yara" in types
    
    test("Batch IOC signature generation (YARA + Snort)", test_batch_ioc)
    
    # Test 11: Statistics tracking
    def test_statistics():
        gen = ThreatSignatureGenerator()
        # Generate some signatures
        gen.generate_yara_rule("Test1", "Description 1", patterns=["a"])
        gen.generate_yara_rule("Test2", "Description 2", patterns=["b"])
        gen.generate_snort_rule(content_patterns=["c"])
        
        stats = gen.get_signature_statistics()
        assert stats["total_generated"] == 3
        assert "yara" in stats["by_type"]
        assert "snort" in stats["by_type"]
        assert stats["by_type"]["yara"] == 2
        assert stats["average_confidence"] > 0
    
    test("Generation statistics tracking", test_statistics)
    
    # Test 12: Thread safety (basic)
    def test_thread_safety():
        import threading
        gen = ThreatSignatureGenerator()
        
        def worker(n):
            for i in range(5):
                gen.generate_yara_rule(f"Thread{n}_Rule{i}", f"Test {i}", patterns=[f"pattern_{n}_{i}"])
        
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        stats = gen.get_signature_statistics()
        assert stats["total_generated"] == 15  # 3 threads × 5 rules each
    
    test("Thread-safe concurrent generation", test_thread_safety)
    
    # Test 13: Export functionality
    def test_export():
        import tempfile
        gen = ThreatSignatureGenerator()
        gen.generate_yara_rule("ExportTest", "Test export", patterns=["test_pattern"])
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.rules') as f:
            filepath = f.name
        
        try:
            result = gen.export_all_signatures(filepath)
            assert result == True
            # Verify file was written
            with open(filepath, 'r') as f:
                content = f.read()
            assert "Signature ID" in content
            assert "YARA-SIG" in content
        finally:
            os.unlink(filepath)
    
    test("Signature export to file", test_export)
    
    # Test 14: Metadata validation
    def test_metadata():
        gen = ThreatSignatureGenerator()
        sig = gen.generate_yara_rule(
            "MetaTest", "Test", patterns=["a"], reference="https://threatintel.example.com"
        )
        assert sig.metadata.signature_id != ""
        assert sig.metadata.created_at > 0
        assert sig.metadata.pattern_count > 0
        assert sig.metadata.false_positive_risk in ["low", "medium", "high"]
        assert len(sig.metadata.references) >= 0
    
    test("Signature metadata completeness", test_metadata)
    
    # Test 15: Validation scoring
    def test_validation_score():
        gen = ThreatSignatureGenerator()
        # High-quality hex pattern
        sig1 = gen.generate_yara_rule("HighQual", "Test", hex_patterns=["DEADBEEFCAFE1234567890ABCDEF"])
        # Lower-quality generic pattern
        sig2 = gen.generate_yara_rule("LowQual", "Test", patterns=["http"])
        assert sig1.validation_score > sig2.validation_score
    
    test("Validation score differentiation by pattern quality", test_validation_score)
    
    # Summary
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {results['passed']}/{results['total_tests']} PASSED")
    if results['failed'] > 0:
        print(f"WARNING: {results['failed']} TEST(S) FAILED")
        for detail in results['test_details']:
            if detail['status'] == 'FAILED':
                print(f"  - {detail['name']}: {detail.get('error', 'Unknown error')}")
    print("=" * 60)
    
    # Save results
    with open('test_results_signature_auto_generator_engine.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    return results

if __name__ == "__main__":
    results = run_tests()
    sys.exit(0 if results['failed'] == 0 else 1)
