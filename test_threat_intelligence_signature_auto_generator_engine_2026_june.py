#!/usr/bin/env python3
"""
Test for Threat Intelligence Signature Auto-Generator Engine
REAL tests with actual assertions
"""
import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_signature_auto_generator_engine_2026_june import (
    SignatureAutoGeneratorEngine,
    RuleType,
    ThreatSeverity,
    GeneratedRule
)


def test_string_extraction():
    """Test that string extraction actually works"""
    print("TEST: String Extraction")
    
    engine = SignatureAutoGeneratorEngine()
    
    test_content = """
    This is a malicious payload with unique strings:
    MALWARE_EXEC_2026_START
    malicious_function_call()
    EVIL_PAYLOAD_v2.0
    backdoor_connect_to_c2()
    secret_encryption_key_12345
    """
    
    strings = engine.extract_significant_strings(test_content)
    
    print(f"  Extracted {len(strings)} strings")
    assert len(strings) > 0, "Should extract at least some strings"
    print("  ✓ String extraction works")
    return True


def test_yara_rule_generation():
    """Test that YARA rules are actually generated with valid syntax"""
    print("\nTEST: YARA Rule Generation")
    
    engine = SignatureAutoGeneratorEngine()
    
    strings = [
        "MALWARE_EXEC_2026",
        "malicious_payload_v2",
        "backdoor_connection"
    ]
    
    rule = engine.generate_yara_rule(
        sample_name="test_malware",
        threat_category="trojan",
        strings=strings,
        severity=ThreatSeverity.HIGH
    )
    
    print(f"  Generated rule: {rule.rule_name}")
    print(f"  Rule ID: {rule.rule_id}")
    print(f"  Confidence: {rule.confidence}")
    
    # Verify basic syntax
    assert "rule " in rule.rule_content, "Should have rule declaration"
    assert "meta:" in rule.rule_content, "Should have meta section"
    assert "strings:" in rule.rule_content, "Should have strings section"
    assert "condition:" in rule.rule_content, "Should have condition section"
    assert "MALWARE_EXEC" in rule.rule_content, "Should contain patterns"
    
    print("  ✓ YARA rule generated with valid syntax")
    return True


def test_snort_rule_generation():
    """Test that Snort rules are actually generated with valid syntax"""
    print("\nTEST: Snort Rule Generation")
    
    engine = SignatureAutoGeneratorEngine()
    
    patterns = [
        "MALWARE_SIGNATURE",
        "C2_CONNECT",
        "exploit_code"
    ]
    
    rule = engine.generate_snort_rule(
        sample_name="test_exploit",
        threat_category="exploit",
        patterns=patterns,
        severity=ThreatSeverity.CRITICAL
    )
    
    print(f"  Generated rule: {rule.rule_name}")
    print(f"  Rule ID: {rule.rule_id}")
    
    # Verify basic Snort syntax
    assert rule.rule_content.startswith("alert "), "Should start with action"
    assert "msg:" in rule.rule_content, "Should have message"
    assert "content:" in rule.rule_content, "Should have content matches"
    assert "sid:" in rule.rule_content, "Should have SID"
    assert "rev:" in rule.rule_content, "Should have revision"
    
    print("  ✓ Snort rule generated with valid syntax")
    return True


def test_end_to_end_rule_generation():
    """Test full end-to-end pipeline"""
    print("\nTEST: End-to-End Rule Generation Pipeline")
    
    engine = SignatureAutoGeneratorEngine()
    
    sample_content = """
    PROMPT_INJECTION_ATTACK_V2
    IGNORE_PREVIOUS_INSTRUCTIONS
    SYSTEM_PROMPT_OVERRIDE
    ACT_AS_ADMINISTRATOR
    BYPASS_ALL_SECURITY_CHECKS
    """
    
    rules = engine.generate_rules_from_sample(
        sample_content=sample_content,
        sample_name="prompt_injection_attack",
        threat_category="prompt_injection",
        severity=ThreatSeverity.HIGH
    )
    
    print(f"  Generated {len(rules)} rules from sample")
    
    assert len(rules) >= 2, "Should generate at least YARA and Snort"
    
    yara_rules = [r for r in rules if r.rule_type == RuleType.YARA]
    snort_rules = [r for r in rules if r.rule_type == RuleType.SNORT]
    
    assert len(yara_rules) == 1, "Should have 1 YARA rule"
    assert len(snort_rules) == 1, "Should have 1 Snort rule"
    
    print(f"  ✓ YARA rules: {len(yara_rules)}")
    print(f"  ✓ Snort rules: {len(snort_rules)}")
    return True


def test_batch_generation():
    """Test batch rule generation"""
    print("\nTEST: Batch Rule Generation")
    
    engine = SignatureAutoGeneratorEngine()
    
    samples = [
        {
            "content": "MALWARE_A_PAYLOAD execute_malware() C2_SERVER_1",
            "name": "malware_a",
            "category": "trojan",
            "severity": ThreatSeverity.HIGH
        },
        {
            "content": "RANSOMWARE_ENCRYPT encrypt_all_files() BTC_ADDRESS",
            "name": "ransomware_x",
            "category": "ransomware",
            "severity": ThreatSeverity.CRITICAL
        },
        {
            "content": "PHISHING_ATTACK fake_login_page steal_credentials()",
            "name": "phishing_kit",
            "category": "phishing",
            "severity": ThreatSeverity.MEDIUM
        }
    ]
    
    rules = engine.batch_generate_rules(samples)
    
    print(f"  Generated {len(rules)} rules from {len(samples)} samples")
    assert len(rules) >= len(samples), "Should generate rules for each sample"
    
    stats = engine.get_statistics()
    print(f"  Total rules: {stats['total_rules_generated']}")
    print(f"  YARA: {stats['yara_rules']}, Snort: {stats['snort_rules']}")
    print(f"  Avg confidence: {stats['average_confidence']}")
    
    print("  ✓ Batch generation works")
    return True


def test_statistics_and_limitations():
    """Test that statistics include honest limitations"""
    print("\nTEST: Statistics and Honest Limitations")
    
    engine = SignatureAutoGeneratorEngine()
    
    stats = engine.get_statistics()
    
    assert "honest_limitations" in stats, "Should include honest limitations"
    assert len(stats["honest_limitations"]) > 0, "Should have actual limitations"
    assert "recommended_next_steps" in stats, "Should include recommendations"
    
    print("  Limitations documented:")
    for limitation in stats["honest_limitations"]:
        print(f"    - {limitation}")
    
    print("  ✓ Honest limitations are properly documented")
    return True


def run_all_tests():
    """Run all tests and save results"""
    print("=" * 60)
    print("NeuralShield AI - Signature Auto-Generator Engine Tests")
    print("=" * 60)
    
    tests = [
        test_string_extraction,
        test_yara_rule_generation,
        test_snort_rule_generation,
        test_end_to_end_rule_generation,
        test_batch_generation,
        test_statistics_and_limitations
    ]
    
    results = {}
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            result = test()
            if result:
                passed += 1
                results[test.__name__] = "PASSED"
            else:
                failed += 1
                results[test.__name__] = "FAILED"
        except Exception as e:
            failed += 1
            results[test.__name__] = f"ERROR: {str(e)}"
            print(f"  ✗ ERROR: {e}")
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed}/{passed + failed} PASSED")
    print("=" * 60)
    
    # Save results
    results_data = {
        "test_timestamp": __import__("time").time(),
        "tests_passed": passed,
        "tests_failed": failed,
        "total_tests": passed + failed,
        "results": results
    }
    
    with open("test_results_signature_auto_generator_engine.json", "w") as f:
        json.dump(results_data, f, indent=2)
    
    print(f"\nResults saved to test_results_signature_auto_generator_engine.json")
    
    return passed == len(tests)


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
