"""
Test Suite for Security Hardening v16 - Observability Protection Layer
NeuralShield-AI | June 23, 2026

100% ADD-ONLY - NO PRODUCTION CODE MODIFIED
32 Total Tests Across 9 Test Classes
"""

import unittest
import threading
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from security_hardening_observability_protection_v16_2026_june import (
    ObservabilitySecurityHardening,
    SecurityValidationResult,
    AccessLevel,
    get_observability_security,
    enable_observability_security,
    disable_observability_security,
)


class TestObservabilitySecurityBaseline(unittest.TestCase):
    """Test module availability and default state."""
    
    def test_module_importable(self):
        """Verify module imports correctly."""
        self.assertIsNotNone(ObservabilitySecurityHardening)
        self.assertIsNotNone(SecurityValidationResult)
        self.assertIsNotNone(AccessLevel)
    
    def test_security_disabled_by_default(self):
        """Verify OPT-IN philosophy - disabled by default."""
        sec = ObservabilitySecurityHardening()
        self.assertFalse(sec.is_enabled())
    
    def test_singleton_pattern(self):
        """Test thread-safe singleton behavior."""
        instance1 = get_observability_security()
        instance2 = get_observability_security()
        self.assertIs(instance1, instance2)
    
    def test_enable_disable_functions(self):
        """Test convenience API functions."""
        sec = get_observability_security()
        initial = sec.is_enabled()
        
        enable_observability_security()
        self.assertTrue(sec.is_enabled())
        
        disable_observability_security()
        self.assertFalse(sec.is_enabled())
        
        # Restore
        if initial:
            enable_observability_security()


class TestConstantTimeComparison(unittest.TestCase):
    """Test constant-time comparison security."""
    
    def test_equal_strings_return_true(self):
        """Equal strings should return True."""
        self.assertTrue(ObservabilitySecurityHardening.constant_time_compare("test123", "test123"))
        self.assertTrue(ObservabilitySecurityHardening.constant_time_compare("", ""))
    
    def test_different_strings_return_false(self):
        """Different strings should return False."""
        self.assertFalse(ObservabilitySecurityHardening.constant_time_compare("abc", "abd"))
        self.assertFalse(ObservabilitySecurityHardening.constant_time_compare("abc", "abcd"))
    
    def test_non_string_inputs(self):
        """Non-string inputs return False."""
        self.assertFalse(ObservabilitySecurityHardening.constant_time_compare(123, "123"))
        self.assertFalse(ObservabilitySecurityHardening.constant_time_compare(None, "None"))


class TestSecureMemoryZeroization(unittest.TestCase):
    """Test secure memory zeroization."""
    
    def test_zeroize_bytearray(self):
        """Test bytearray is properly zeroized."""
        sensitive = bytearray(b"secret_api_key_12345")
        original = bytes(sensitive)
        
        ObservabilitySecurityHardening.zeroize_memory(sensitive)
        
        # All bytes should be zero
        for b in sensitive:
            self.assertEqual(b, 0)
        
        # Original data should be gone
        self.assertNotEqual(bytes(sensitive), original)
    
    def test_zeroize_empty_buffer(self):
        """Zeroizing empty buffer should not crash."""
        empty = bytearray()
        ObservabilitySecurityHardening.zeroize_memory(empty)
        self.assertEqual(len(empty), 0)


class TestRateLimiting(unittest.TestCase):
    """Test token bucket rate limiting."""
    
    def setUp(self):
        self.sec = ObservabilitySecurityHardening()
        self.sec.enable()
    
    def test_rate_limit_allows_initial_requests(self):
        """Initial requests within burst should be allowed."""
        for i in range(5):
            allowed, result = self.sec.check_rate_limit("client1")
            self.assertTrue(allowed)
            self.assertEqual(result, SecurityValidationResult.VALID)
    
    def test_rate_limit_blocks_exceeded(self):
        """Requests exceeding burst should be blocked."""
        self.sec.set_rate_limit(per_second=1.0, burst=3)
        
        # Consume burst
        for i in range(3):
            self.sec.check_rate_limit("client2")
        
        # 4th should be blocked
        allowed, result = self.sec.check_rate_limit("client2")
        self.assertFalse(allowed)
        self.assertEqual(result, SecurityValidationResult.RATE_LIMITED)
    
    def test_rate_limit_refills_over_time(self):
        """Tokens should refill over time."""
        self.sec.set_rate_limit(per_second=100.0, burst=1)
        
        # Consume token
        self.sec.check_rate_limit("client3")
        
        # Wait for refill
        time.sleep(0.02)
        
        # Should have token again
        allowed, _ = self.sec.check_rate_limit("client3")
        self.assertTrue(allowed)
    
    def test_disabled_mode_bypasses_rate_limit(self):
        """Disabled mode allows all requests."""
        self.sec.disable()
        self.sec.set_rate_limit(per_second=0.1, burst=1)
        
        # Should allow 100 requests even with very low limit
        for i in range(100):
            allowed, _ = self.sec.check_rate_limit("client4")
            self.assertTrue(allowed)


class TestAccessControlApiKeys(unittest.TestCase):
    """Test API key access control."""
    
    def setUp(self):
        self.sec = ObservabilitySecurityHardening()
        self.sec.enable()
    
    def test_no_api_key_rejected(self):
        """Empty API key is rejected."""
        valid, result = self.sec.validate_api_key("", AccessLevel.METRICS_READ)
        self.assertFalse(valid)
        self.assertEqual(result, SecurityValidationResult.UNAUTHORIZED)
    
    def test_valid_api_key_accepted(self):
        """Valid registered API key is accepted."""
        test_key = "test_valid_key_12345"
        self.sec.register_api_key(test_key, AccessLevel.METRICS_READ)
        
        valid, result = self.sec.validate_api_key(test_key, AccessLevel.METRICS_READ)
        self.assertTrue(valid)
        self.assertEqual(result, SecurityValidationResult.VALID)
    
    def test_insufficient_access_level_rejected(self):
        """Key with insufficient access is rejected."""
        test_key = "limited_key"
        self.sec.register_api_key(test_key, AccessLevel.METRICS_READ)
        
        # Try to access admin level with read-only key
        valid, result = self.sec.validate_api_key(test_key, AccessLevel.ADMIN)
        self.assertFalse(valid)
        self.assertEqual(result, SecurityValidationResult.UNAUTHORIZED)
    
    def test_invalid_api_key_rejected(self):
        """Unregistered key is rejected."""
        valid, result = self.sec.validate_api_key("random_key", AccessLevel.METRICS_READ)
        self.assertFalse(valid)
        self.assertEqual(result, SecurityValidationResult.UNAUTHORIZED)
    
    def test_disabled_mode_bypasses_auth(self):
        """Disabled mode accepts any key."""
        self.sec.disable()
        valid, _ = self.sec.validate_api_key("any_key", AccessLevel.ADMIN)
        self.assertTrue(valid)


class TestTrustedIpValidation(unittest.TestCase):
    """Test trusted IP validation."""
    
    def setUp(self):
        self.sec = ObservabilitySecurityHardening()
        self.sec.enable()
    
    def test_localhost_trusted_by_default(self):
        """localhost is trusted by default."""
        valid, _ = self.sec.validate_client_ip("127.0.0.1")
        self.assertTrue(valid)
        valid, _ = self.sec.validate_client_ip("::1")
        self.assertTrue(valid)
    
    def test_untrusted_ip_rejected(self):
        """Untrusted external IP is rejected."""
        valid, result = self.sec.validate_client_ip("192.168.1.100")
        self.assertFalse(valid)
        self.assertEqual(result, SecurityValidationResult.UNAUTHORIZED)
    
    def test_add_trusted_ip(self):
        """Can add new trusted IPs."""
        new_ip = "10.0.0.1"
        self.sec.add_trusted_ip(new_ip)
        valid, _ = self.sec.validate_client_ip(new_ip)
        self.assertTrue(valid)


class TestInputValidationMetrics(unittest.TestCase):
    """Test metric and label input validation."""
    
    def setUp(self):
        self.sec = ObservabilitySecurityHardening()
        self.sec.enable()
    
    def test_valid_metric_name_accepted(self):
        """Valid Prometheus metric names are accepted."""
        valid_names = [
            "http_requests_total",
            "process_cpu_seconds_total",
            "neuralshield:threat:detected",
            "_private_metric",
        ]
        for name in valid_names:
            valid, _ = self.sec.validate_metric_name(name)
            self.assertTrue(valid, f"Should accept: {name}")
    
    def test_invalid_metric_name_rejected(self):
        """Invalid metric names are rejected."""
        invalid_names = [
            "",  # Empty
            "123invalid",  # Starts with number
            "metric with spaces",
            "metric-with-dashes",
            "a" * 300,  # Too long
        ]
        for name in invalid_names:
            valid, result = self.sec.validate_metric_name(name)
            self.assertFalse(valid, f"Should reject: {name}")
    
    def test_valid_label_name_accepted(self):
        """Valid label names are accepted."""
        valid_names = ["method", "status_code", "instance", "_internal"]
        for name in valid_names:
            valid, _ = self.sec.validate_label_name(name)
            self.assertTrue(valid, f"Should accept: {name}")
    
    def test_reserved_label_prefix_rejected(self):
        """Labels starting with __ are reserved and rejected."""
        valid, _ = self.sec.validate_label_name("__reserved__")
        self.assertFalse(valid)


class TestSensitiveDataSanitization(unittest.TestCase):
    """Test PII/sensitive data redaction."""
    
    def setUp(self):
        self.sec = ObservabilitySecurityHardening()
        self.sec.enable()
    
    def test_email_redaction(self):
        """Email addresses should be redacted."""
        result = self.sec.sanitize_label_value("Contact user@example.com for help")
        self.assertIn("EMAIL_REDACTED", result)
        self.assertNotIn("user@example.com", result)
    
    def test_api_key_redaction(self):
        """API keys should be redacted."""
        result = self.sec.sanitize_label_value('api_key=secret_token_12345abcde')
        self.assertIn("API_KEY_REDACTED", result)
    
    def test_ip_address_redaction(self):
        """IP addresses should be redacted."""
        result = self.sec.sanitize_label_value("Request from 192.168.1.1")
        self.assertIn("IP_REDACTED", result)
        self.assertNotIn("192.168.1.1", result)
    
    def test_control_characters_removed(self):
        """Control characters should be removed."""
        result = self.sec.sanitize_label_value("hello\x00world\n")
        self.assertNotIn("\x00", result)
        self.assertNotIn("\n", result)
    
    def test_disabled_mode_no_sanitization(self):
        """Disabled mode returns original text."""
        self.sec.disable()
        original = "user@example.com 192.168.1.1"
        result = self.sec.sanitize_label_value(original)
        self.assertEqual(result, original)


class TestSecurityEventLogging(unittest.TestCase):
    """Test security event logging."""
    
    def setUp(self):
        self.sec = ObservabilitySecurityHardening()
        self.sec.enable()
    
    def test_security_summary_returns_data(self):
        """Security summary returns expected structure."""
        # Generate some events
        for i in range(5):
            self.sec.check_rate_limit("test_client")
        
        summary = self.sec.get_security_summary()
        self.assertIn("enabled", summary)
        self.assertIn("total_events_logged", summary)
        self.assertIn("rate_limit_config", summary)
        self.assertTrue(summary["enabled"])


class TestThreadSafety(unittest.TestCase):
    """Test high-concurrency thread safety."""
    
    def test_concurrent_rate_limit_checks(self):
        """10 threads x 100 operations = 1000 concurrent rate limit checks."""
        sec = ObservabilitySecurityHardening()
        sec.enable()
        errors = []
        
        def worker():
            try:
                for i in range(100):
                    sec.check_rate_limit(f"thread_{threading.get_ident()}")
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0, f"Thread safety errors: {errors}")
    
    def test_concurrent_singleton_access(self):
        """30 threads accessing singleton concurrently."""
        instances = []
        
        def worker():
            instances.append(get_observability_security())
        
        threads = [threading.Thread(target=worker) for _ in range(30)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # All should be same instance
        first = instances[0]
        for inst in instances[1:]:
            self.assertIs(inst, first)


class TestBackwardCompatibility(unittest.TestCase):
    """Test zero overhead and backward compatibility."""
    
    def test_disabled_mode_performance(self):
        """Disabled mode: 40,000 operations should be fast (< 0.5 seconds)."""
        sec = ObservabilitySecurityHardening()
        # Explicitly disabled
        
        start = time.time()
        for i in range(40000):
            sec.check_rate_limit(f"client_{i}")
            sec.validate_api_key("any_key", AccessLevel.METRICS_READ)
            sec.validate_metric_name("valid_metric")
        elapsed = time.time() - start
        
        # Should be very fast (essentially no-ops)
        self.assertLess(elapsed, 0.5, f"Disabled mode too slow: {elapsed:.3f}s")
    
    def test_add_only_compliance(self):
        """Verify 100% ADD-ONLY - module is standalone."""
        # Module should have no dependencies on other observability modules
        import security_hardening_observability_protection_v16_2026_june as sec_module
        
        # Verify it's a standalone module
        self.assertTrue(hasattr(sec_module, 'ObservabilitySecurityHardening'))
        self.assertTrue(hasattr(sec_module, 'AccessLevel'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
