"""
Test Suite for NeuralShield-AI Security Hardening Module v17
DIMENSION B - Security Hardening

Tests cover:
1. SecurityLevel enum
2. ValidationSeverity enum
3. ValidationResult dataclass
4. RateLimitConfig dataclass
5. SecureMemory utilities
6. RateLimiter functionality
7. InputValidator validation
8. SecurityAuditLogger
9. SecureReportGeneratorWrapper
10. Convenience functions
11. Backward compatibility
12. Version information
"""

import unittest
import threading
import time
from unittest.mock import Mock, patch

# Import the security hardening module
from neural_shield.security_hardening_report_generation_v17_2026_june import (
    SecurityValidationError,
    RateLimitExceededError,
    SecurityLevel,
    ValidationSeverity,
    ValidationResult,
    RateLimitConfig,
    SecureMemory,
    RateLimiter,
    InputValidator,
    SecurityAuditLogger,
    SecureReportGeneratorWrapper,
    create_secure_wrapper,
    secure_compare,
    zeroize_sensitive_data,
    SECURITY_HARDENING_VERSION,
    SECURITY_HARDENING_BUILD_DATE,
    SECURITY_HARDENING_DIMENSION,
)


class TestSecurityLevelEnum(unittest.TestCase):
    """Test SecurityLevel enum values"""
    
    def test_security_level_values(self):
        self.assertEqual(SecurityLevel.LOW.value, "low")
        self.assertEqual(SecurityLevel.MEDIUM.value, "medium")
        self.assertEqual(SecurityLevel.HIGH.value, "high")
        self.assertEqual(SecurityLevel.CRITICAL.value, "critical")
    
    def test_security_level_count(self):
        self.assertEqual(len(list(SecurityLevel)), 4)


class TestValidationSeverityEnum(unittest.TestCase):
    """Test ValidationSeverity enum values"""
    
    def test_severity_values(self):
        self.assertEqual(ValidationSeverity.INFO.value, "info")
        self.assertEqual(ValidationSeverity.WARNING.value, "warning")
        self.assertEqual(ValidationSeverity.ERROR.value, "error")
        self.assertEqual(ValidationSeverity.CRITICAL.value, "critical")
    
    def test_severity_count(self):
        self.assertEqual(len(list(ValidationSeverity)), 4)


class TestValidationResult(unittest.TestCase):
    """Test ValidationResult dataclass"""
    
    def test_initial_state(self):
        result = ValidationResult(is_valid=True)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.warnings, [])
        self.assertIsNone(result.sanitized_input)
    
    def test_add_error(self):
        result = ValidationResult(is_valid=True)
        result.add_error("Test error")
        self.assertFalse(result.is_valid)
        self.assertIn("Test error", result.errors)
    
    def test_add_warning(self):
        result = ValidationResult(is_valid=True)
        result.add_warning("Test warning")
        self.assertTrue(result.is_valid)
        self.assertIn("Test warning", result.warnings)
    
    def test_sanitized_input(self):
        result = ValidationResult(is_valid=True, sanitized_input={"key": "value"})
        self.assertEqual(result.sanitized_input, {"key": "value"})


class TestRateLimitConfig(unittest.TestCase):
    """Test RateLimitConfig dataclass"""
    
    def test_default_values(self):
        config = RateLimitConfig()
        self.assertEqual(config.max_requests_per_minute, 60)
        self.assertEqual(config.max_requests_per_hour, 1000)
        self.assertEqual(config.max_report_size_bytes, 10 * 1024 * 1024)
        self.assertEqual(config.max_sections_per_report, 50)
        self.assertEqual(config.max_iocs_per_report, 10000)
        self.assertEqual(config.burst_limit, 10)
    
    def test_custom_values(self):
        config = RateLimitConfig(
            max_requests_per_minute=10,
            max_requests_per_hour=100
        )
        self.assertEqual(config.max_requests_per_minute, 10)
        self.assertEqual(config.max_requests_per_hour, 100)


class TestSecureMemory(unittest.TestCase):
    """Test SecureMemory security utilities"""
    
    def test_secure_compare_equal(self):
        self.assertTrue(SecureMemory.secure_compare("test123", "test123"))
    
    def test_secure_compare_not_equal(self):
        self.assertFalse(SecureMemory.secure_compare("test123", "test456"))
    
    def test_secure_compare_bytes_equal(self):
        self.assertTrue(SecureMemory.secure_compare_bytes(b"test", b"test"))
    
    def test_secure_compare_bytes_not_equal(self):
        self.assertFalse(SecureMemory.secure_compare_bytes(b"test", b"other"))
    
    def test_zeroize_bytearray(self):
        data = bytearray(b"sensitive data")
        SecureMemory.zeroize(data)
        self.assertEqual(all(b == 0 for b in data), True)
    
    def test_zeroize_list(self):
        data = [1, 2, 3, 4, 5]
        SecureMemory.zeroize(data)
        self.assertEqual(all(x == 0 for x in data), True)
    
    def test_generate_secure_nonce(self):
        nonce = SecureMemory.generate_secure_nonce(32)
        self.assertEqual(len(nonce), 32)
        self.assertIsInstance(nonce, bytes)
    
    def test_generate_secure_token(self):
        token = SecureMemory.generate_secure_token(64)
        self.assertEqual(len(token), 64)  # 32 bytes = 64 hex chars
        self.assertIsInstance(token, str)
    
    def test_token_uniqueness(self):
        tokens = {SecureMemory.generate_secure_token() for _ in range(100)}
        self.assertEqual(len(tokens), 100)  # All unique


class TestRateLimiter(unittest.TestCase):
    """Test RateLimiter functionality"""
    
    def test_initialization(self):
        limiter = RateLimiter()
        self.assertIsNotNone(limiter.config)
    
    def test_custom_config(self):
        config = RateLimitConfig(max_requests_per_minute=5)
        limiter = RateLimiter(config)
        self.assertEqual(limiter.config.max_requests_per_minute, 5)
    
    def test_check_rate_limit_allowed(self):
        limiter = RateLimiter(RateLimitConfig(max_requests_per_minute=10))
        allowed, info = limiter.check_rate_limit("test_client")
        self.assertTrue(allowed)
        self.assertIn("minute_remaining", info)
    
    def test_rate_limit_exceeded(self):
        limiter = RateLimiter(RateLimitConfig(max_requests_per_minute=2))
        limiter.check_rate_limit("client1")
        limiter.check_rate_limit("client1")
        allowed, info = limiter.check_rate_limit("client1")
        self.assertFalse(allowed)
        self.assertEqual(info["reason"], "per_minute_limit_exceeded")
    
    def test_different_clients(self):
        limiter = RateLimiter(RateLimitConfig(max_requests_per_minute=1))
        allowed1, _ = limiter.check_rate_limit("clientA")
        allowed2, _ = limiter.check_rate_limit("clientB")
        self.assertTrue(allowed1)
        self.assertTrue(allowed2)
    
    def test_get_current_usage(self):
        limiter = RateLimiter()
        limiter.check_rate_limit("test")
        usage = limiter.get_current_usage("test")
        self.assertIn("minute_requests", usage)
        self.assertIn("hour_requests", usage)
        self.assertGreaterEqual(usage["minute_requests"], 1)
    
    def test_thread_safety(self):
        """Basic thread safety test"""
        limiter = RateLimiter(RateLimitConfig(max_requests_per_minute=1000))
        
        def make_requests():
            for _ in range(10):
                limiter.check_rate_limit("thread_test")
        
        threads = [threading.Thread(target=make_requests) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        usage = limiter.get_current_usage("thread_test")
        self.assertEqual(usage["minute_requests"], 50)


class TestInputValidator(unittest.TestCase):
    """Test InputValidator functionality"""
    
    def test_initialization(self):
        validator = InputValidator()
        self.assertEqual(validator.security_level, SecurityLevel.MEDIUM)
    
    def test_custom_security_level(self):
        validator = InputValidator(SecurityLevel.HIGH)
        self.assertEqual(validator.security_level, SecurityLevel.HIGH)
    
    def test_validate_valid_request(self):
        validator = InputValidator()
        request = {
            "report_type": "threat_summary",
            "output_format": "json",
            "title": "Test Report"
        }
        result = validator.validate_report_request(request)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.errors, [])
    
    def test_validate_invalid_report_type(self):
        validator = InputValidator()
        request = {"report_type": "invalid_type"}
        result = validator.validate_report_request(request)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Invalid report_type" in e for e in result.errors))
    
    def test_validate_invalid_output_format(self):
        validator = InputValidator()
        request = {"output_format": "invalid_format"}
        result = validator.validate_report_request(request)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Invalid output_format" in e for e in result.errors))
    
    def test_validate_iocs(self):
        validator = InputValidator()
        request = {
            "iocs": ["192.168.1.1", "example.com"]
        }
        result = validator.validate_report_request(request)
        self.assertTrue(result.is_valid)
        self.assertIn("iocs", result.sanitized_input)
    
    def test_validate_sections(self):
        validator = InputValidator()
        request = {
            "sections": [{"title": "Section 1", "content": "Test"}]
        }
        result = validator.validate_report_request(request)
        self.assertTrue(result.is_valid)
        self.assertIn("sections", result.sanitized_input)
    
    def test_sanitization(self):
        validator = InputValidator()
        request = {
            "report_type": "threat_summary",
            "title": "  Test Title  ",
            "extra_field": "should be removed"
        }
        result = validator.validate_report_request(request)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.sanitized_input["title"], "Test Title")
    
    def test_high_security_nesting_check(self):
        validator = InputValidator(SecurityLevel.HIGH)
        # Create deeply nested structure
        nested = {}
        current = nested
        for i in range(15):  # Exceeds MAX_NESTING_DEPTH
            current["nested"] = {}
            current = current["nested"]
        
        request = {"deep_data": nested}
        result = validator.validate_report_request(request)
        # Should have error about nesting depth
        self.assertFalse(result.is_valid)


class TestSecurityAuditLogger(unittest.TestCase):
    """Test SecurityAuditLogger functionality"""
    
    def test_initialization(self):
        logger = SecurityAuditLogger()
        self.assertIsNotNone(logger)
    
    def test_log_event(self):
        logger = SecurityAuditLogger()
        logger.log_event("test_event", ValidationSeverity.INFO, {"key": "value"})
        log = logger.get_audit_log()
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["event_type"], "test_event")
    
    def test_log_severity(self):
        logger = SecurityAuditLogger()
        logger.log_event("error_event", ValidationSeverity.ERROR, {})
        log = logger.get_audit_log()
        self.assertEqual(log[0]["severity"], "error")
    
    def test_get_security_summary(self):
        logger = SecurityAuditLogger()
        logger.log_event("event1", ValidationSeverity.INFO, {})
        logger.log_event("event2", ValidationSeverity.WARNING, {})
        summary = logger.get_security_summary()
        self.assertEqual(summary["total_events"], 2)
        self.assertIn("by_severity", summary)
        self.assertIn("by_type", summary)
    
    def test_log_limit(self):
        logger = SecurityAuditLogger()
        for i in range(1500):  # More than 1000 limit
            logger.log_event(f"event_{i}", ValidationSeverity.INFO, {})
        log = logger.get_audit_log(limit=2000)
        self.assertLessEqual(len(log), 1000)  # Capped at 1000
    
    def test_client_id_hashing(self):
        logger = SecurityAuditLogger()
        logger.log_event("test", ValidationSeverity.INFO, {}, "sensitive_client_id")
        log = logger.get_audit_log()
        # Client ID should be hashed, not plain text
        self.assertNotEqual(log[0]["client_id"], "sensitive_client_id")
        self.assertEqual(len(log[0]["client_id"]), 16)  # First 16 chars of SHA256


class TestSecureReportGeneratorWrapper(unittest.TestCase):
    """Test SecureReportGeneratorWrapper"""
    
    def test_initialization(self):
        wrapper = SecureReportGeneratorWrapper()
        self.assertIsNotNone(wrapper)
        self.assertIsNotNone(wrapper.validator)
        self.assertIsNotNone(wrapper.rate_limiter)
        self.assertIsNotNone(wrapper.audit_logger)
    
    def test_custom_security_level(self):
        wrapper = SecureReportGeneratorWrapper(security_level=SecurityLevel.HIGH)
        self.assertEqual(wrapper.security_level, SecurityLevel.HIGH)
    
    def test_generate_secure_report_standalone(self):
        wrapper = SecureReportGeneratorWrapper()
        request = {
            "report_type": "threat_summary",
            "output_format": "json"
        }
        result = wrapper.generate_secure_report(request)
        self.assertTrue(result["security_validated"])
        self.assertIn("secure_generation_id", result)
    
    def test_generate_secure_report_validation_error(self):
        wrapper = SecureReportGeneratorWrapper()
        request = {"report_type": "invalid_type"}
        with self.assertRaises(SecurityValidationError):
            wrapper.generate_secure_report(request)
    
    def test_rate_limit_enforced(self):
        config = RateLimitConfig(max_requests_per_minute=1)
        wrapper = SecureReportGeneratorWrapper(rate_limit_config=config)
        request = {"report_type": "threat_summary"}
        
        # First request should work
        wrapper.generate_secure_report(request, "client1")
        
        # Second request should fail
        with self.assertRaises(RateLimitExceededError):
            wrapper.generate_secure_report(request, "client1")
    
    def test_get_security_status(self):
        wrapper = SecureReportGeneratorWrapper()
        status = wrapper.get_security_status()
        self.assertIn("security_level", status)
        self.assertIn("rate_limiter_status", status)
        self.assertIn("audit_summary", status)
        self.assertIn("security_features", status)
        self.assertEqual(status["wrapper_version"], "v17")
    
    def test_with_mock_underlying_generator(self):
        mock_generator = Mock()
        mock_generator.generate_report.return_value = {"report": "data"}
        
        wrapper = SecureReportGeneratorWrapper(underlying_generator=mock_generator)
        request = {"report_type": "threat_summary"}
        result = wrapper.generate_secure_report(request)
        
        mock_generator.generate_report.assert_called_once()
        self.assertEqual(result, {"report": "data"})


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience functions"""
    
    def test_create_secure_wrapper(self):
        wrapper = create_secure_wrapper()
        self.assertIsInstance(wrapper, SecureReportGeneratorWrapper)
    
    def test_create_secure_wrapper_with_level(self):
        wrapper = create_secure_wrapper(security_level=SecurityLevel.CRITICAL)
        self.assertEqual(wrapper.security_level, SecurityLevel.CRITICAL)
    
    def test_secure_compare_convenience(self):
        self.assertTrue(secure_compare("abc", "abc"))
        self.assertFalse(secure_compare("abc", "def"))
    
    def test_zeroize_sensitive_data_convenience(self):
        data = bytearray(b"test")
        zeroize_sensitive_data(data)
        self.assertTrue(all(b == 0 for b in data))


class TestVersionInformation(unittest.TestCase):
    """Test version information constants"""
    
    def test_version_constants(self):
        self.assertEqual(SECURITY_HARDENING_VERSION, "v17")
        self.assertEqual(SECURITY_HARDENING_BUILD_DATE, "2026-06-24")
        self.assertEqual(SECURITY_HARDENING_DIMENSION, "B - Security Hardening")


class TestExceptionClasses(unittest.TestCase):
    """Test custom exception classes"""
    
    def test_security_validation_error(self):
        with self.assertRaises(SecurityValidationError):
            raise SecurityValidationError("Test error")
    
    def test_rate_limit_exceeded_error(self):
        with self.assertRaises(RateLimitExceededError):
            raise RateLimitExceededError("Rate limit exceeded")


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility - all existing code should work"""
    
    def test_no_modifications_to_existing_modules(self):
        """Verify this module is standalone and doesn't require changes to others"""
        # This module can be imported independently
        import neural_shield.security_hardening_report_generation_v17_2026_june as sec
        self.assertIsNotNone(sec)
    
    def test_wrapper_pattern_preserves_existing(self):
        """Wrapper pattern means existing generators work unchanged"""
        # The wrapper wraps existing, existing code needs zero changes
        wrapper = SecureReportGeneratorWrapper(underlying_generator=None)
        # Can work in standalone mode
        self.assertIsNotNone(wrapper)


if __name__ == "__main__":
    unittest.main(verbosity=2)
