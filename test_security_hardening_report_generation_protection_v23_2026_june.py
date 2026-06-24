"""
Test Suite for Security Hardening v23 - Report Generation Protection
NeuralShield-AI | June 24, 2026
Session 127 - Dimension B: Security Hardening v23
"""

import unittest
import secrets
from neural_shield.security_hardening_threat_report_protection_v23_2026_june import (
    SecurityLevelV23,
    ValidationSeverityV23,
    SecureMemoryProtectionV23,
    AdaptiveRateLimiterV23,
    AdaptiveRateLimitConfigV23,
    TemplateInjectionProtectorV23,
    MitreTechniqueValidatorV23,
    ReportIntegritySealerV23,
    secure_threat_report_v23,
    get_security_hardening_v23_info,
)


class TestSecureMemoryProtectionV23(unittest.TestCase):
    def test_bytearray_zeroization(self):
        data = bytearray(b'sensitive threat data')
        original = bytes(data)
        SecureMemoryProtectionV23.secure_zeroize(data)
        self.assertNotEqual(bytes(data), original)
    
    def test_constant_time_compare(self):
        self.assertTrue(SecureMemoryProtectionV23.constant_time_compare(b'abc', b'abc'))
        self.assertFalse(SecureMemoryProtectionV23.constant_time_compare(b'abc', b'abd'))


class TestAdaptiveRateLimiterV23(unittest.TestCase):
    def test_basic_rate_limit(self):
        limiter = AdaptiveRateLimiterV23(AdaptiveRateLimitConfigV23(base_max_per_hour=3))
        for i in range(3):
            allowed, _ = limiter.check_and_record("client1")
            self.assertTrue(allowed)
        allowed, _ = limiter.check_and_record("client1")
        self.assertFalse(allowed)


class TestTemplateInjectionProtectorV23(unittest.TestCase):
    def test_clean_content(self):
        result = TemplateInjectionProtectorV23.scan_for_template_injection("Normal content")
        self.assertTrue(result.valid)
    
    def test_jinja2_injection(self):
        result = TemplateInjectionProtectorV23.scan_for_template_injection("{{ 7*7 }}")
        self.assertFalse(result.valid)
    
    def test_xss_detection(self):
        result = TemplateInjectionProtectorV23.scan_for_xss("<script>alert(1)</script>")
        self.assertFalse(result.valid)


class TestMitreTechniqueValidatorV23(unittest.TestCase):
    def test_valid_technique(self):
        result = MitreTechniqueValidatorV23.validate_technique_id("T1055")
        self.assertTrue(result.valid)
    
    def test_invalid_technique(self):
        result = MitreTechniqueValidatorV23.validate_technique_id("INVALID")
        self.assertFalse(result.valid)


class TestReportIntegritySealerV23(unittest.TestCase):
    def test_seal_report(self):
        sealer = ReportIntegritySealerV23()
        seal = sealer.seal_report("Test content", "report-001")
        self.assertIn("signature", seal)
        self.assertIn("report_id", seal)


class TestSecureThreatReportDecoratorV23(unittest.TestCase):
    def test_decorator_wraps_function(self):
        @secure_threat_report_v23(client_id="test")
        def test_func(report_data=None):
            return {"content": "test report", "report_id": "test-1"}
        
        result = test_func(report_data={"test": "data"})
        self.assertIn("content", result)
        self.assertIn("integrity_seal", result)


class TestVersionInformationV23(unittest.TestCase):
    def test_version_info(self):
        info = get_security_hardening_v23_info()
        self.assertEqual(info["version"], "v23")
        self.assertEqual(info["dimension"], "B - Security Hardening")
        self.assertEqual(info["session"], "127")
        self.assertIn("100% ADD-ONLY", info["implementation_note"])


if __name__ == '__main__':
    unittest.main(verbosity=2)
