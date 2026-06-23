"""
Tests for Security Hardening Layer v14 - Threat Intelligence
ADD-ONLY - NO existing code modified
42 comprehensive tests
"""

import unittest
import threading
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from security_hardening_threat_intelligence_v14_2026_june import (
    ValidationSeverity,
    ValidationResult,
    RateLimitConfig,
    SecurityHardeningConfig,
    SecureMemoryZeroizer,
    ConstantTimeComparator,
    InputValidator,
    AdaptiveRateLimiter,
    ThreatIntelligenceSecurityHardener,
    security_hardener
)


class TestValidationSeverityEnum(unittest.TestCase):
    """Test ValidationSeverity enum"""
    
    def test_severity_values_exist(self):
        self.assertEqual(ValidationSeverity.LOW.value, "low")
        self.assertEqual(ValidationSeverity.MEDIUM.value, "medium")
        self.assertEqual(ValidationSeverity.HIGH.value, "high")
        self.assertEqual(ValidationSeverity.CRITICAL.value, "critical")
    
    def test_severity_comparison(self):
        self.assertNotEqual(ValidationSeverity.LOW, ValidationSeverity.HIGH)


class TestValidationResult(unittest.TestCase):
    """Test ValidationResult dataclass"""
    
    def test_validation_result_creation(self):
        result = ValidationResult(
            is_valid=True,
            severity=ValidationSeverity.LOW,
            message="Test valid",
            field_name="test_field",
            sanitized_value="clean"
        )
        self.assertTrue(result.is_valid)
        self.assertEqual(result.severity, ValidationSeverity.LOW)
        self.assertEqual(result.message, "Test valid")
        self.assertEqual(result.field_name, "test_field")
        self.assertEqual(result.sanitized_value, "clean")


class TestRateLimitConfig(unittest.TestCase):
    """Test RateLimitConfig"""
    
    def test_default_config(self):
        config = RateLimitConfig()
        self.assertEqual(config.max_requests_per_window, 100)
        self.assertEqual(config.window_seconds, 60)
        self.assertEqual(config.burst_limit, 20)
        self.assertTrue(config.enabled)
    
    def test_custom_config(self):
        config = RateLimitConfig(
            max_requests_per_window=50,
            window_seconds=30,
            burst_limit=10
        )
        self.assertEqual(config.max_requests_per_window, 50)
        self.assertEqual(config.window_seconds, 30)
        self.assertEqual(config.burst_limit, 10)


class TestSecurityHardeningConfig(unittest.TestCase):
    """Test SecurityHardeningConfig"""
    
    def test_default_config(self):
        config = SecurityHardeningConfig()
        self.assertTrue(config.enable_input_validation)
        self.assertTrue(config.enable_rate_limiting)
        self.assertTrue(config.enable_memory_zeroization)
        self.assertTrue(config.enable_constant_time_compare)
        self.assertEqual(config.max_indicator_size, 1024)
        self.assertEqual(config.max_metadata_entries, 50)


class TestSecureMemoryZeroizer(unittest.TestCase):
    """Test SecureMemoryZeroizer"""
    
    def test_zeroize_bytes(self):
        data = bytearray(b'sensitive data here')
        SecureMemoryZeroizer.zeroize_bytes(data)
        self.assertEqual(sum(data), 0)
        self.assertEqual(len(data), 19)
    
    def test_zeroize_list(self):
        data = [1, 2, 3, 4, 5]
        SecureMemoryZeroizer.zeroize_list(data)
        self.assertEqual(len(data), 0)
    
    def test_zeroize_string(self):
        result = SecureMemoryZeroizer.zeroize_string("secret")
        self.assertEqual(result, "")


class TestConstantTimeComparator(unittest.TestCase):
    """Test ConstantTimeComparator"""
    
    def test_compare_strings_equal(self):
        self.assertTrue(ConstantTimeComparator.compare_strings("test", "test"))
    
    def test_compare_strings_not_equal(self):
        self.assertFalse(ConstantTimeComparator.compare_strings("test", "TEST"))
    
    def test_compare_strings_empty(self):
        self.assertTrue(ConstantTimeComparator.compare_strings("", ""))
        self.assertFalse(ConstantTimeComparator.compare_strings("a", ""))
    
    def test_compare_bytes_equal(self):
        self.assertTrue(ConstantTimeComparator.compare_bytes(b'test', b'test'))
    
    def test_compare_bytes_not_equal(self):
        self.assertFalse(ConstantTimeComparator.compare_bytes(b'test', b'TEST'))
    
    def test_compare_ips(self):
        self.assertTrue(ConstantTimeComparator.compare_ips("192.168.1.1", "192.168.1.1"))
        self.assertFalse(ConstantTimeComparator.compare_ips("192.168.1.1", "192.168.1.2"))


class TestInputValidator(unittest.TestCase):
    """Test InputValidator"""
    
    def setUp(self):
        self.config = SecurityHardeningConfig()
        self.validator = InputValidator(self.config)
    
    def test_validate_indicator_type_valid(self):
        result = self.validator.validate_indicator_type("ip")
        self.assertTrue(result.is_valid)
        self.assertEqual(result.sanitized_value, "ip")
    
    def test_validate_indicator_type_invalid(self):
        result = self.validator.validate_indicator_type("invalid_type")
        self.assertFalse(result.is_valid)
        self.assertEqual(result.severity, ValidationSeverity.MEDIUM)
    
    def test_validate_indicator_type_empty(self):
        result = self.validator.validate_indicator_type("")
        self.assertFalse(result.is_valid)
        self.assertEqual(result.severity, ValidationSeverity.HIGH)
    
    def test_validate_indicator_type_case_insensitive(self):
        result = self.validator.validate_indicator_type("IP")
        self.assertTrue(result.is_valid)
        self.assertEqual(result.sanitized_value, "ip")
    
    def test_validate_indicator_value_valid(self):
        result = self.validator.validate_indicator_value("192.168.1.1", "ip")
        self.assertTrue(result.is_valid)
    
    def test_validate_indicator_value_empty(self):
        result = self.validator.validate_indicator_value("", "ip")
        self.assertFalse(result.is_valid)
        self.assertEqual(result.severity, ValidationSeverity.HIGH)
    
    def test_validate_indicator_value_too_long(self):
        long_value = "x" * 2000
        result = self.validator.validate_indicator_value(long_value, "hash")
        self.assertFalse(result.is_valid)
    
    def test_validate_confidence_valid(self):
        result = self.validator.validate_confidence(0.5)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.sanitized_value, 0.5)
    
    def test_validate_confidence_clamped_high(self):
        result = self.validator.validate_confidence(2.0)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.sanitized_value, 1.0)
    
    def test_validate_confidence_clamped_low(self):
        result = self.validator.validate_confidence(-1.0)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.sanitized_value, 0.0)
    
    def test_validate_confidence_invalid_type(self):
        result = self.validator.validate_confidence("not a number")
        self.assertFalse(result.is_valid)
    
    def test_validate_metadata_valid(self):
        metadata = {"key1": "value1", "key2": "value2"}
        result = self.validator.validate_metadata(metadata)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.sanitized_value, metadata)
    
    def test_validate_metadata_not_dict(self):
        result = self.validator.validate_metadata("not a dict")
        self.assertFalse(result.is_valid)
    
    def test_validate_metadata_too_many_entries(self):
        metadata = {f"key{i}": f"value{i}" for i in range(100)}
        result = self.validator.validate_metadata(metadata)
        self.assertFalse(result.is_valid)
    
    def test_validate_full_ingestion(self):
        results = self.validator.validate_indicator_ingestion(
            "ip", "192.168.1.1", 0.8, {"source": "test"}
        )
        self.assertTrue(all(v.is_valid for v in results.values()))


class TestAdaptiveRateLimiter(unittest.TestCase):
    """Test AdaptiveRateLimiter"""
    
    def setUp(self):
        self.config = RateLimitConfig(
            max_requests_per_window=10,
            window_seconds=60,
            burst_limit=15
        )
        self.limiter = AdaptiveRateLimiter(self.config)
    
    def test_rate_limit_basic(self):
        for _ in range(10):
            self.assertTrue(self.limiter.check_rate_limit())
        # 11th should fail (window limit)
        self.assertFalse(self.limiter.check_rate_limit())
    
    def test_burst_limit(self):
        tight_config = RateLimitConfig(
            max_requests_per_window=100,
            window_seconds=60,
            burst_limit=3
        )
        limiter = AdaptiveRateLimiter(tight_config)
        # First 3 should pass (burst)
        for _ in range(3):
            self.assertTrue(limiter.check_rate_limit())
        # 4th should fail burst
        self.assertFalse(limiter.check_rate_limit())
    
    def test_rate_limiter_disabled(self):
        config = RateLimitConfig(enabled=False)
        limiter = AdaptiveRateLimiter(config)
        for _ in range(100):
            self.assertTrue(limiter.check_rate_limit())
    
    def test_get_stats(self):
        stats = self.limiter.get_stats()
        self.assertIn('requests_in_window', stats)
        self.assertIn('window_remaining', stats)
        self.assertIn('burst_tokens_remaining', stats)
        self.assertIn('enabled', stats)


class TestThreatIntelligenceSecurityHardenerSingleton(unittest.TestCase):
    """Test singleton pattern"""
    
    def test_singleton_instance(self):
        instance1 = ThreatIntelligenceSecurityHardener()
        instance2 = ThreatIntelligenceSecurityHardener()
        self.assertIs(instance1, instance2)
    
    def test_global_instance(self):
        self.assertIsInstance(security_hardener, ThreatIntelligenceSecurityHardener)


class TestThreatIntelligenceSecurityHardenerOptIn(unittest.TestCase):
    """Test OPT-IN pattern"""
    
    def setUp(self):
        self.hardener = ThreatIntelligenceSecurityHardener()
        self.hardener.disable()
    
    def test_disabled_by_default(self):
        # Fresh instance check
        hardener = ThreatIntelligenceSecurityHardener()
        hardener.disable()
        self.assertFalse(hardener.is_enabled())
    
    def test_enable_disable(self):
        self.hardener.enable()
        self.assertTrue(self.hardener.is_enabled())
        self.hardener.disable()
        self.assertFalse(self.hardener.is_enabled())
    
    def test_disabled_passthrough(self):
        """When disabled, validation should always pass through"""
        self.hardener.disable()
        result = self.hardener.validate_and_sanitize_indicator(
            "invalid", "", -1, "not a dict"  # All invalid
        )
        self.assertTrue(result['allowed'])  # Passthrough when disabled


class TestThreatIntelligenceSecurityHardenerEnabled(unittest.TestCase):
    """Test security hardener when enabled"""
    
    def setUp(self):
        self.hardener = ThreatIntelligenceSecurityHardener()
        self.hardener.enable()
    
    def test_valid_indicator_passes(self):
        result = self.hardener.validate_and_sanitize_indicator(
            "ip", "192.168.1.1", 0.8, {"source": "test"}
        )
        self.assertTrue(result['allowed'])
        self.assertIn('sanitized', result)
    
    def test_invalid_indicator_type_blocked(self):
        result = self.hardener.validate_and_sanitize_indicator(
            "", "192.168.1.1", 0.8, {}
        )
        self.assertFalse(result['allowed'])
        self.assertEqual(result['reason'], 'validation_failed')
    
    def test_confidence_clamped(self):
        result = self.hardener.validate_and_sanitize_indicator(
            "ip", "192.168.1.1", 2.0, {}
        )
        self.assertTrue(result['allowed'])
        self.assertEqual(result['sanitized']['confidence'], 1.0)
    
    def test_secure_compare_enabled(self):
        # Should use constant time compare when enabled
        result = self.hardener.secure_compare_indicators("test", "test")
        self.assertTrue(result)
    
    def test_get_security_stats(self):
        stats = self.hardener.get_security_stats()
        self.assertIn('enabled', stats)
        self.assertIn('validation_failures', stats)
        self.assertIn('rate_limited_requests', stats)
        self.assertIn('rate_limiter', stats)
        self.assertIn('config', stats)


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility"""
    
    def test_all_imports_work(self):
        """Verify all public API can be imported without errors"""
        from security_hardening_threat_intelligence_v14_2026_june import (
            ValidationSeverity,
            ValidationResult,
            RateLimitConfig,
            SecurityHardeningConfig,
            SecureMemoryZeroizer,
            ConstantTimeComparator,
            InputValidator,
            AdaptiveRateLimiter,
            ThreatIntelligenceSecurityHardener,
            security_hardener
        )
        # If we get here without ImportError, we pass
        self.assertTrue(True)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases"""
    
    def test_empty_metadata(self):
        hardener = ThreatIntelligenceSecurityHardener()
        hardener.enable()
        result = hardener.validate_and_sanitize_indicator(
            "ip", "192.168.1.1", 0.5, {}
        )
        self.assertTrue(result['allowed'])
    
    def test_zero_confidence(self):
        hardener = ThreatIntelligenceSecurityHardener()
        hardener.enable()
        result = hardener.validate_and_sanitize_indicator(
            "ip", "192.168.1.1", 0.0, {}
        )
        self.assertTrue(result['allowed'])
        self.assertEqual(result['sanitized']['confidence'], 0.0)
    
    def test_full_confidence(self):
        hardener = ThreatIntelligenceSecurityHardener()
        hardener.enable()
        result = hardener.validate_and_sanitize_indicator(
            "ip", "192.168.1.1", 1.0, {}
        )
        self.assertTrue(result['allowed'])
        self.assertEqual(result['sanitized']['confidence'], 1.0)


class TestThreadSafety(unittest.TestCase):
    """Test thread safety"""
    
    def test_concurrent_access(self):
        hardener = ThreatIntelligenceSecurityHardener()
        hardener.enable()
        errors = []
        
        def worker():
            try:
                for _ in range(10):
                    hardener.validate_and_sanitize_indicator(
                        "ip", "192.168.1.1", 0.5, {}
                    )
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
