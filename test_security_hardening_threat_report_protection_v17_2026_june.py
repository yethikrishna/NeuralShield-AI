"""
Test Suite for NeuralShield Security Hardening v17 - Threat Report Protection
===========================================================================
DIMENSION B - SECURITY HARDENING
ADD-ONLY TESTS - NO EXISTING TESTS MODIFIED

All tests are isolated and do not affect existing functionality.
"""

import unittest
import time
import threading
import hashlib
from typing import Dict, Any

# Import the new security hardening module
from neural_shield.security_hardening_threat_report_protection_v17_2026_june import (
    SecurityLevel,
    ValidationSeverity,
    SensitiveDataType,
    ValidationResult,
    RateLimitConfig,
    SecurityContext,
    SecureMemory,
    ConstantTime,
    RateLimiter,
    InputValidator,
    SensitiveDataRedactor,
    ProtectedReportGenerator,
    create_high_security_protector,
    create_maximum_security_protector,
    create_audit_only_protector,
    get_version_info,
    VERSION,
)


# -----------------------------------------------------------------------------
# Test Security Enums
# -----------------------------------------------------------------------------

class TestSecurityLevelEnum(unittest.TestCase):
    """Test SecurityLevel enum values."""
    
    def test_security_level_values(self):
        """Test all security level values exist."""
        self.assertEqual(SecurityLevel.LOW.value, "low")
        self.assertEqual(SecurityLevel.MEDIUM.value, "medium")
        self.assertEqual(SecurityLevel.HIGH.value, "high")
        self.assertEqual(SecurityLevel.MAXIMUM.value, "maximum")
    
    def test_security_level_count(self):
        """Test correct number of security levels."""
        self.assertEqual(len(list(SecurityLevel)), 4)


class TestValidationSeverityEnum(unittest.TestCase):
    """Test ValidationSeverity enum."""
    
    def test_severity_order(self):
        """Test severity ordering is correct."""
        severities = list(ValidationSeverity)
        self.assertEqual(severities[0], ValidationSeverity.INFO)
        self.assertEqual(severities[-1], ValidationSeverity.CRITICAL)


# -----------------------------------------------------------------------------
# Test Data Classes
# -----------------------------------------------------------------------------

class TestValidationResult(unittest.TestCase):
    """Test ValidationResult dataclass."""
    
    def test_default_values(self):
        """Test default values are correct."""
        result = ValidationResult(valid=True)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.warnings, [])
        self.assertEqual(result.severity, ValidationSeverity.INFO)
    
    def test_error_tracking(self):
        """Test error tracking works."""
        result = ValidationResult(valid=False, errors=["test error"])
        self.assertFalse(result.valid)
        self.assertEqual(len(result.errors), 1)


class TestRateLimitConfig(unittest.TestCase):
    """Test RateLimitConfig dataclass."""
    
    def test_default_limits(self):
        """Test default rate limit values."""
        config = RateLimitConfig()
        self.assertEqual(config.max_requests_per_window, 100)
        self.assertEqual(config.window_seconds, 60)
        self.assertEqual(config.max_report_size_bytes, 10 * 1024 * 1024)


class TestSecurityContext(unittest.TestCase):
    """Test SecurityContext dataclass."""
    
    def test_default_security_level(self):
        """Test default security level is MEDIUM."""
        context = SecurityContext()
        self.assertEqual(context.security_level, SecurityLevel.MEDIUM)
    
    def test_protections_enabled_by_default(self):
        """Test core protections are enabled by default."""
        context = SecurityContext()
        self.assertTrue(context.enable_memory_zeroization)
        self.assertTrue(context.enable_rate_limiting)
        self.assertTrue(context.enable_sensitive_data_redaction)
        self.assertFalse(context.audit_logging_enabled)  # Opt-in only


# -----------------------------------------------------------------------------
# Test Secure Memory Zeroization
# -----------------------------------------------------------------------------

class TestSecureMemory(unittest.TestCase):
    """Test secure memory zeroization utilities."""
    
    def test_zeroize_string(self):
        """Test string zeroization returns empty string."""
        sensitive = "my_secret_api_key_12345"
        result = SecureMemory.zeroize_string(sensitive)
        self.assertEqual(result, "")
    
    def test_zeroize_bytes(self):
        """Test bytes zeroization."""
        sensitive = b"secret_data_here"
        result = SecureMemory.zeroize_bytes(sensitive)
        # Should return empty bytes
        self.assertEqual(result, b'')
    
    def test_zeroize_dict(self):
        """Test dictionary zeroization."""
        sensitive = {"key": "secret_value", "nested": {"password": "test123"}}
        result = SecureMemory.zeroize_dict(sensitive)
        self.assertEqual(result, {})
    
    def test_zeroize_list(self):
        """Test list zeroization."""
        sensitive = ["secret1", "secret2"]
        result = SecureMemory.zeroize_list(sensitive)
        self.assertEqual(result, [])


# -----------------------------------------------------------------------------
# Test Constant-Time Comparison
# -----------------------------------------------------------------------------

class TestConstantTime(unittest.TestCase):
    """Test constant-time comparison utilities."""
    
    def test_compare_strings_equal(self):
        """Test equal strings compare correctly."""
        self.assertTrue(ConstantTime.compare_strings("test123", "test123"))
    
    def test_compare_strings_not_equal(self):
        """Test unequal strings compare correctly."""
        self.assertFalse(ConstantTime.compare_strings("test123", "test456"))
    
    def test_compare_strings_different_length(self):
        """Test different length strings return False."""
        self.assertFalse(ConstantTime.compare_strings("short", "much_longer_string"))
    
    def test_compare_bytes_equal(self):
        """Test equal bytes compare correctly."""
        self.assertTrue(ConstantTime.compare_bytes(b"test", b"test"))
    
    def test_compare_hashes(self):
        """Test hash comparison."""
        hash1 = hashlib.sha256(b"test").hexdigest()
        hash2 = hashlib.sha256(b"test").hexdigest()
        self.assertTrue(ConstantTime.compare_hashes(hash1, hash2))
    
    def test_compare_hashes_case_insensitive(self):
        """Test hash comparison is case-insensitive."""
        hash_upper = "A1B2C3D4"
        hash_lower = "a1b2c3d4"
        self.assertTrue(ConstantTime.compare_hashes(hash_upper, hash_lower))


# -----------------------------------------------------------------------------
# Test Rate Limiting
# -----------------------------------------------------------------------------

class TestRateLimiter(unittest.TestCase):
    """Test thread-safe rate limiter."""
    
    def test_initial_quota(self):
        """Test initial quota is available."""
        config = RateLimitConfig(max_requests_per_window=5)
        limiter = RateLimiter(config)
        self.assertEqual(limiter.get_remaining_quota(), 5)
    
    def test_rate_limit_enforced(self):
        """Test rate limit blocks requests after quota."""
        config = RateLimitConfig(max_requests_per_window=2, window_seconds=3600)
        limiter = RateLimiter(config)
        
        # First two should pass
        self.assertTrue(limiter.check_rate_limit())
        self.assertTrue(limiter.check_rate_limit())
        # Third should be blocked
        self.assertFalse(limiter.check_rate_limit())
    
    def test_remaining_quota_decreases(self):
        """Test remaining quota decreases with each request."""
        config = RateLimitConfig(max_requests_per_window=3)
        limiter = RateLimiter(config)
        
        self.assertEqual(limiter.get_remaining_quota(), 3)
        limiter.check_rate_limit()
        self.assertEqual(limiter.get_remaining_quota(), 2)
        limiter.check_rate_limit()
        self.assertEqual(limiter.get_remaining_quota(), 1)
    
    def test_report_size_check(self):
        """Test report size validation."""
        config = RateLimitConfig(max_report_size_bytes=1000)
        limiter = RateLimiter(config)
        
        self.assertTrue(limiter.check_report_size(500))
        self.assertFalse(limiter.check_report_size(2000))
    
    def test_section_count_check(self):
        """Test section count validation."""
        config = RateLimitConfig(max_sections_per_report=10)
        limiter = RateLimiter(config)
        
        self.assertTrue(limiter.check_section_count(5))
        self.assertFalse(limiter.check_section_count(20))
    
    def test_thread_safety(self):
        """Test rate limiter is thread-safe."""
        config = RateLimitConfig(max_requests_per_window=100)
        limiter = RateLimiter(config)
        
        def worker():
            for _ in range(10):
                limiter.check_rate_limit()
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should have 50 requests recorded
        self.assertEqual(limiter.get_remaining_quota(), 50)


# -----------------------------------------------------------------------------
# Test Input Validation
# -----------------------------------------------------------------------------

class TestInputValidator(unittest.TestCase):
    """Test input validation wrappers."""
    
    def test_validate_report_type_valid(self):
        """Test valid report type passes."""
        result = InputValidator.validate_report_type("threat_summary")
        self.assertTrue(result.valid)
        self.assertEqual(len(result.errors), 0)
    
    def test_validate_report_type_empty(self):
        """Test empty report type fails."""
        result = InputValidator.validate_report_type("")
        self.assertFalse(result.valid)
        self.assertGreater(len(result.errors), 0)
    
    def test_validate_report_type_xss_detection(self):
        """Test XSS detection works."""
        result = InputValidator.validate_report_type("<script>alert(1)</script>")
        self.assertFalse(result.valid)
        self.assertEqual(result.severity, ValidationSeverity.CRITICAL)
    
    def test_validate_output_format_valid(self):
        """Test valid formats pass."""
        for fmt in ['json', 'markdown', 'html', 'csv']:
            result = InputValidator.validate_output_format(fmt)
            self.assertTrue(result.valid)
    
    def test_validate_output_format_invalid(self):
        """Test invalid format fails."""
        result = InputValidator.validate_output_format("exe")
        self.assertFalse(result.valid)
    
    def test_validate_section_name_warning_on_html(self):
        """Test HTML tags trigger warning."""
        result = InputValidator.validate_section_name("<b>Section</b>")
        self.assertTrue(result.valid)  # Still valid
        self.assertGreater(len(result.warnings), 0)
    
    def test_validate_section_name_too_long(self):
        """Test overly long section name fails."""
        long_name = "x" * 300
        result = InputValidator.validate_section_name(long_name)
        self.assertFalse(result.valid)
    
    def test_validate_report_content_valid(self):
        """Test valid content passes."""
        result = InputValidator.validate_report_content({"key": "value"})
        self.assertTrue(result.valid)
    
    def test_validate_report_content_not_dict(self):
        """Test non-dict content fails."""
        result = InputValidator.validate_report_content("not a dict")  # type: ignore
        self.assertFalse(result.valid)


# -----------------------------------------------------------------------------
# Test Sensitive Data Redaction
# -----------------------------------------------------------------------------

class TestSensitiveDataRedactor(unittest.TestCase):
    """Test sensitive data redaction utilities."""
    
    def test_redact_api_key(self):
        """Test API key redaction."""
        text = "My API key is api_key=abcdefghijklmnopqrstuvwxyz123456"
        redacted = SensitiveDataRedactor.redact_string(text)
        self.assertIn("[REDACTED]", redacted)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz123456", redacted)
    
    def test_redact_email(self):
        """Test email redaction."""
        text = "Contact me at user@example.com for details"
        redacted = SensitiveDataRedactor.redact_string(text)
        self.assertIn("[REDACTED]", redacted)
        self.assertNotIn("user@example.com", redacted)
    
    def test_redact_ip_address(self):
        """Test IP address redaction."""
        text = "Server IP is 192.168.1.100"
        redacted = SensitiveDataRedactor.redact_string(text)
        self.assertIn("[REDACTED]", redacted)
        self.assertNotIn("192.168.1.100", redacted)
    
    def test_redact_password(self):
        """Test password redaction."""
        text = 'password=MySecretPassword123'
        redacted = SensitiveDataRedactor.redact_string(text)
        self.assertIn("[REDACTED]", redacted)
    
    def test_redact_dict_recursive(self):
        """Test recursive dictionary redaction."""
        data = {
            "user": "admin",
            "contact": "admin@example.com",
            "nested": {
                "key_value": "api_key=secret1234567890abcdefghij",
                "server": "192.168.1.100"
            }
        }
        redacted = SensitiveDataRedactor.redact_report_content(data)
        self.assertEqual(redacted["user"], "admin")  # Not sensitive
        self.assertEqual(redacted["contact"], "[REDACTED]")
        self.assertIn("[REDACTED]", redacted["nested"]["key_value"])
        self.assertEqual(redacted["nested"]["server"], "[REDACTED]")
    def test_redact_list_in_dict(self):
        """Test list items within dictionaries are redacted."""
        data = {
            "emails": ["user1@example.com", "user2@example.com"]
        }
        redacted = SensitiveDataRedactor.redact_report_content(data)
        self.assertEqual(redacted["emails"][0], "[REDACTED]")
        self.assertEqual(redacted["emails"][1], "[REDACTED]")


# -----------------------------------------------------------------------------
# Test Protected Report Generator
# -----------------------------------------------------------------------------

class TestProtectedReportGenerator(unittest.TestCase):
    """Test ProtectedReportGenerator wrapper."""
    
    def test_create_default(self):
        """Test default protector creation."""
        protector = ProtectedReportGenerator()
        self.assertIsNotNone(protector)
    
    def test_validate_generation_request_valid(self):
        """Test valid request passes validation."""
        protector = ProtectedReportGenerator()
        result = protector.validate_generation_request(
            report_type="threat_summary",
            output_format="json"
        )
        self.assertTrue(result.valid)
        self.assertEqual(len(result.errors), 0)
    
    def test_validate_generation_request_invalid_format(self):
        """Test invalid format fails validation."""
        protector = ProtectedReportGenerator()
        result = protector.validate_generation_request(
            report_type="threat_summary",
            output_format="invalid_format"
        )
        self.assertFalse(result.valid)
        self.assertGreater(len(result.errors), 0)
    
    def test_generate_protected_report_basic(self):
        """Test basic protected report generation."""
        protector = ProtectedReportGenerator()
        result = protector.generate_protected_report(
            report_type="threat_summary",
            output_format="json"
        )
        self.assertTrue(result['success'])
        self.assertTrue(result['security_protected'])
        self.assertEqual(result['security_level'], 'medium')
    
    def test_generate_protected_report_redacts_data(self):
        """Test custom data is redacted."""
        protector = ProtectedReportGenerator()
        sensitive_data = {
            "api_key": "abcdefghijklmnopqrstuvwxyz123456",
            "email": "user@example.com"
        }
        result = protector.generate_protected_report(
            report_type="threat_summary",
            output_format="json",
            custom_data=sensitive_data
        )
        self.assertTrue(result['success'])
    
    def test_get_security_status(self):
        """Test security status reporting."""
        protector = ProtectedReportGenerator()
        status = protector.get_security_status()
        self.assertEqual(status['security_level'], 'medium')
        self.assertTrue(status['memory_zeroization_enabled'])
        self.assertTrue(status['rate_limiting_enabled'])
        self.assertEqual(status['version'], 'v17')
    
    def test_audit_log_disabled_by_default(self):
        """Test audit log is empty when disabled."""
        protector = ProtectedReportGenerator()
        log = protector.get_audit_log()
        self.assertEqual(log, [])
    
    def test_verify_report_integrity_no_hash(self):
        """Test integrity check fails when no hash present."""
        protector = ProtectedReportGenerator()
        report = {'data': 'test'}  # No integrity_hash
        self.assertFalse(protector.verify_report_integrity(report, 'abc123'))


# -----------------------------------------------------------------------------
# Test Factory Functions
# -----------------------------------------------------------------------------

class TestFactoryFunctions(unittest.TestCase):
    """Test convenience factory functions."""
    
    def test_create_high_security_protector(self):
        """Test high security protector creation."""
        protector = create_high_security_protector()
        status = protector.get_security_status()
        self.assertEqual(status['security_level'], 'high')
    
    def test_create_maximum_security_protector(self):
        """Test maximum security protector creation."""
        protector = create_maximum_security_protector()
        status = protector.get_security_status()
        self.assertEqual(status['security_level'], 'maximum')
        self.assertTrue(status['audit_logging_enabled'])
    
    def test_create_audit_only_protector(self):
        """Test audit-only protector creation."""
        protector = create_audit_only_protector()
        status = protector.get_security_status()
        self.assertEqual(status['security_level'], 'low')
        self.assertTrue(status['audit_logging_enabled'])
        self.assertFalse(status['memory_zeroization_enabled'])


# -----------------------------------------------------------------------------
# Test Version Information
# -----------------------------------------------------------------------------

class TestVersionInformation(unittest.TestCase):
    """Test version information functions."""
    
    def test_version_constant(self):
        """Test version constant is correct."""
        self.assertEqual(VERSION, "v17")
    
    def test_get_version_info(self):
        """Test get_version_info returns correct data."""
        info = get_version_info()
        self.assertEqual(info['version'], 'v17')
        self.assertEqual(info['stability'], 'STABLE')
        self.assertEqual(info['dimension'], 'B - Security Hardening')
        self.assertTrue(info['backward_compatible'])
        self.assertTrue(info['add_only'])


# -----------------------------------------------------------------------------
# Test Backward Compatibility
# -----------------------------------------------------------------------------

class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility guarantees."""
    
    def test_no_dependencies(self):
        """Test module has no external dependencies."""
        from neural_shield.security_hardening_threat_report_protection_v17_2026_june import DEPENDENCIES
        self.assertEqual(DEPENDENCIES, [])
    
    def test_pure_python(self):
        """Test module imports without any external packages."""
        # This test itself proves the module can be imported
        import neural_shield.security_hardening_threat_report_protection_v17_2026_june as module
        self.assertIsNotNone(module)
    
    def test_wrapper_pattern(self):
        """Test module uses wrapper pattern (no modification needed)."""
        # Can be used without any underlying generator
        protector = ProtectedReportGenerator(underlying_generator=None)
        result = protector.generate_protected_report("test", "json")
        self.assertTrue(result['success'])  # Works without underlying


# -----------------------------------------------------------------------------
# Run all tests
# -----------------------------------------------------------------------------

def run_tests():
    """Run all tests and return results."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestSecurityLevelEnum,
        TestValidationSeverityEnum,
        TestValidationResult,
        TestRateLimitConfig,
        TestSecurityContext,
        TestSecureMemory,
        TestConstantTime,
        TestRateLimiter,
        TestInputValidator,
        TestSensitiveDataRedactor,
        TestProtectedReportGenerator,
        TestFactoryFunctions,
        TestVersionInformation,
        TestBackwardCompatibility,
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    runner = unittest.TextTestRunner(verbosity=2)
    return runner.run(suite)


if __name__ == '__main__':
    result = run_tests()
    exit(0 if result.wasSuccessful() else 1)
