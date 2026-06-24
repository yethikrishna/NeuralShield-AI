"""
Tests for Security Hardening v17 - Report Generation Protection Module
NeuralShield-AI

Covers all security features:
- Input validation and sanitization
- Rate limiting and DoS protection
- Secure memory handling
- Constant-time comparison
- Security context isolation
"""

import unittest
import threading
import time
from typing import Any

# Import security module
from neural_shield.security_hardening_report_generation_protection_v17_2026_june import (
    SecurityLevel,
    ValidationSeverity,
    ValidationResult,
    RateLimitConfig,
    SecurityContext,
    SecureMemory,
    InputValidator,
    RateLimiter,
    ReportGenerationSecurityProtector,
    get_default_protector,
    secure_generate_report,
    constant_time_compare,
    secure_zeroize,
    VERSION,
    VERSION_INFO,
    get_version,
    get_version_info
)


class TestSecurityLevelEnum(unittest.TestCase):
    """Test SecurityLevel enumeration."""
    
    def test_security_level_values(self):
        """Test all security levels have correct values."""
        self.assertEqual(SecurityLevel.LOW.value, "low")
        self.assertEqual(SecurityLevel.MEDIUM.value, "medium")
        self.assertEqual(SecurityLevel.HIGH.value, "high")
        self.assertEqual(SecurityLevel.MAXIMUM.value, "maximum")
    
    def test_security_level_count(self):
        """Test correct number of security levels."""
        self.assertEqual(len(list(SecurityLevel)), 4)


class TestValidationSeverityEnum(unittest.TestCase):
    """Test ValidationSeverity enumeration."""
    
    def test_severity_values(self):
        """Test all severity levels have correct values."""
        self.assertEqual(ValidationSeverity.INFO.value, "info")
        self.assertEqual(ValidationSeverity.WARNING.value, "warning")
        self.assertEqual(ValidationSeverity.ERROR.value, "error")
        self.assertEqual(ValidationSeverity.CRITICAL.value, "critical")
    
    def test_severity_count(self):
        """Test correct number of severity levels."""
        self.assertEqual(len(list(ValidationSeverity)), 4)


class TestValidationResult(unittest.TestCase):
    """Test ValidationResult dataclass."""
    
    def test_validation_result_creation(self):
        """Test creating validation result with all fields."""
        result = ValidationResult(
            valid=True,
            severity=ValidationSeverity.INFO,
            message="Test message",
            field="test_field",
            sanitized_value="clean_value"
        )
        self.assertTrue(result.valid)
        self.assertEqual(result.severity, ValidationSeverity.INFO)
        self.assertEqual(result.message, "Test message")
        self.assertEqual(result.field, "test_field")
        self.assertEqual(result.sanitized_value, "clean_value")
    
    def test_validation_result_defaults(self):
        """Test default values work correctly."""
        result = ValidationResult(valid=False)
        self.assertFalse(result.valid)
        self.assertEqual(result.severity, ValidationSeverity.INFO)
        self.assertEqual(result.message, "")
        self.assertEqual(result.field, "")
        self.assertIsNone(result.sanitized_value)


class TestRateLimitConfig(unittest.TestCase):
    """Test RateLimitConfig dataclass."""
    
    def test_default_config(self):
        """Test default rate limit configuration."""
        config = RateLimitConfig()
        self.assertEqual(config.max_requests_per_window, 100)
        self.assertEqual(config.window_seconds, 60)
        self.assertEqual(config.max_report_size_bytes, 10 * 1024 * 1024)
        self.assertEqual(config.max_sections_per_report, 50)
        self.assertEqual(config.max_iocs_per_report, 10000)
    
    def test_custom_config(self):
        """Test custom rate limit configuration."""
        config = RateLimitConfig(
            max_requests_per_window=50,
            window_seconds=30,
            max_report_size_bytes=5 * 1024 * 1024
        )
        self.assertEqual(config.max_requests_per_window, 50)
        self.assertEqual(config.window_seconds, 30)
        self.assertEqual(config.max_report_size_bytes, 5 * 1024 * 1024)


class TestSecurityContext(unittest.TestCase):
    """Test SecurityContext isolation."""
    
    def test_context_creation(self):
        """Test security context creation with defaults."""
        context = SecurityContext()
        self.assertIsNotNone(context.context_id)
        self.assertEqual(len(context.context_id), 32)  # 16 bytes hex
        self.assertEqual(context.security_level, SecurityLevel.MEDIUM)
        self.assertEqual(context.request_count, 0)
        self.assertEqual(context.validation_failures, [])
    
    def test_context_custom_level(self):
        """Test security context with custom security level."""
        context = SecurityContext(security_level=SecurityLevel.HIGH)
        self.assertEqual(context.security_level, SecurityLevel.HIGH)
    
    def test_increment_request_threadsafe(self):
        """Test request counter is thread-safe."""
        context = SecurityContext()
        
        def increment_many(n: int):
            for _ in range(n):
                context.increment_request()
        
        threads = [threading.Thread(target=increment_many, args=(100,)) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(context.request_count, 1000)
    
    def test_add_validation_failure(self):
        """Test adding validation failures to context."""
        context = SecurityContext()
        failure = ValidationResult(valid=False, severity=ValidationSeverity.ERROR)
        context.add_validation_failure(failure)
        self.assertEqual(len(context.validation_failures), 1)
        self.assertEqual(context.validation_failures[0], failure)


class TestSecureMemory(unittest.TestCase):
    """Test SecureMemory utilities."""
    
    def test_zeroize_bytes(self):
        """Test secure bytearray zeroization."""
        data = bytearray(b'sensitive data here')
        original = bytes(data)
        SecureMemory.zeroize_bytes(data)
        self.assertEqual(data, bytearray(len(original)))
        self.assertEqual(all(b == 0 for b in data), True)
    
    def test_zeroize_string(self):
        """Test string zeroization returns zeros."""
        s = "secret"
        result = SecureMemory.zeroize_string(s)
        self.assertEqual(len(result), len(s))
        self.assertEqual(result, '\x00' * len(s))
    
    def test_constant_time_compare_equal(self):
        """Test constant-time compare with equal bytes."""
        a = b'test data'
        b = b'test data'
        self.assertTrue(SecureMemory.constant_time_compare(a, b))
    
    def test_constant_time_compare_different(self):
        """Test constant-time compare with different bytes."""
        a = b'test data'
        b = b'test different'
        self.assertFalse(SecureMemory.constant_time_compare(a, b))
    
    def test_constant_time_compare_different_length(self):
        """Test constant-time compare with different lengths."""
        a = b'short'
        b = b'much longer data'
        self.assertFalse(SecureMemory.constant_time_compare(a, b))
    
    def test_constant_time_str_compare_equal(self):
        """Test constant-time string compare with equal strings."""
        self.assertTrue(SecureMemory.constant_time_str_compare("test", "test"))
    
    def test_constant_time_str_compare_different(self):
        """Test constant-time string compare with different strings."""
        self.assertFalse(SecureMemory.constant_time_str_compare("test", "TEST"))
        self.assertFalse(SecureMemory.constant_time_str_compare("test", "different"))
    
    def test_secure_hash_generates_output(self):
        """Test secure hash generates bytes output."""
        data = b'test data'
        result = SecureMemory.secure_hash(data)
        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 64)  # SHA-512 output


class TestInputValidator(unittest.TestCase):
    """Test InputValidator class."""
    
    def test_validate_report_type_valid(self):
        """Test valid report types pass validation."""
        valid_types = [
            'threat_summary', 'ioc_analysis', 'mitre_coverage',
            'false_positive_reduction', 'comprehensive_security',
            'executive_summary'
        ]
        for report_type in valid_types:
            result = InputValidator.validate_report_type(report_type)
            self.assertTrue(result.valid, f"Failed for {report_type}")
            self.assertEqual(result.sanitized_value, report_type)
    
    def test_validate_report_type_case_insensitive(self):
        """Test report type validation is case-insensitive."""
        result = InputValidator.validate_report_type('THREAT_SUMMARY')
        self.assertTrue(result.valid)
        self.assertEqual(result.sanitized_value, 'threat_summary')
    
    def test_validate_report_type_invalid(self):
        """Test invalid report types are rejected."""
        result = InputValidator.validate_report_type('invalid_type')
        self.assertFalse(result.valid)
        self.assertEqual(result.severity, ValidationSeverity.ERROR)
        self.assertEqual(result.field, 'report_type')
    
    def test_validate_output_format_valid(self):
        """Test valid output formats pass validation."""
        for fmt in ['json', 'markdown', 'html', 'csv']:
            result = InputValidator.validate_output_format(fmt)
            self.assertTrue(result.valid, f"Failed for {fmt}")
    
    def test_validate_output_format_invalid(self):
        """Test invalid output formats are rejected."""
        result = InputValidator.validate_output_format('exe')
        self.assertFalse(result.valid)
        self.assertEqual(result.severity, ValidationSeverity.ERROR)
    
    def test_validate_string_length_valid(self):
        """Test strings within length limits pass."""
        result = InputValidator.validate_string_length("short string", 'report_title')
        self.assertTrue(result.valid)
        self.assertEqual(result.sanitized_value, "short string")
    
    def test_validate_string_length_too_long(self):
        """Test strings exceeding limits are truncated."""
        long_string = "x" * 1000
        result = InputValidator.validate_string_length(long_string, 'report_title')
        self.assertFalse(result.valid)
        self.assertEqual(result.severity, ValidationSeverity.WARNING)
        self.assertEqual(len(result.sanitized_value), 200)  # MAX_FIELD_LENGTHS['report_title']
    
    def test_sanitize_html_content(self):
        """Test dangerous HTML patterns are sanitized."""
        dangerous = '<script>alert("xss")</script>'
        sanitized = InputValidator.sanitize_html_content(dangerous)
        self.assertNotIn('<script', sanitized)
        self.assertIn('&lt;script', sanitized)
    
    def test_sanitize_javascript_urls(self):
        """Test javascript: URLs are blocked."""
        dangerous = 'javascript:alert(1)'
        sanitized = InputValidator.sanitize_html_content(dangerous)
        self.assertIn('javascript_blocked:', sanitized)
    
    def test_validate_ioc_value_valid(self):
        """Test valid IOC values pass validation."""
        result = InputValidator.validate_ioc_value('192.168.1.1')
        self.assertTrue(result.valid)
        self.assertEqual(result.sanitized_value, '192.168.1.1')
    
    def test_validate_ioc_value_empty(self):
        """Test empty IOC values are rejected."""
        result = InputValidator.validate_ioc_value('')
        self.assertFalse(result.valid)
        self.assertEqual(result.severity, ValidationSeverity.ERROR)
    
    def test_validate_filename_path_traversal_blocked(self):
        """Test path traversal attempts are blocked."""
        result = InputValidator.validate_filename('../../../etc/passwd')
        self.assertFalse(result.valid)
        self.assertEqual(result.severity, ValidationSeverity.CRITICAL)
    
    def test_validate_filename_sanitized(self):
        """Test filenames are sanitized of dangerous characters."""
        result = InputValidator.validate_filename('my report!.txt')
        self.assertTrue(result.valid)
        self.assertEqual(result.sanitized_value, 'my report.txt')
    
    def test_validate_numeric_range_valid(self):
        """Test numbers within range pass validation."""
        result = InputValidator.validate_numeric_range(50, 'test', 0, 100)
        self.assertTrue(result.valid)
        self.assertEqual(result.sanitized_value, 50)
    
    def test_validate_numeric_range_out_of_bounds(self):
        """Test numbers outside range are rejected."""
        result = InputValidator.validate_numeric_range(150, 'test', 0, 100)
        self.assertFalse(result.valid)
        self.assertEqual(result.severity, ValidationSeverity.ERROR)


class TestRateLimiter(unittest.TestCase):
    """Test RateLimiter class."""
    
    def test_rate_limit_allows_initial_requests(self):
        """Test initial requests are allowed."""
        limiter = RateLimiter(RateLimitConfig(max_requests_per_window=5))
        for i in range(5):
            allowed, info = limiter.check_rate_limit()
            self.assertTrue(allowed, f"Request {i+1} should be allowed")
    
    def test_rate_limit_blocks_excess_requests(self):
        """Test requests exceeding limit are blocked."""
        limiter = RateLimiter(RateLimitConfig(max_requests_per_window=3))
        # Allow 3
        for _ in range(3):
            limiter.check_rate_limit()
        # Block 4th
        allowed, info = limiter.check_rate_limit()
        self.assertFalse(allowed)
        self.assertEqual(info['reason'], 'global_rate_limit_exceeded')
    
    def test_per_client_rate_limiting(self):
        """Test per-client rate limiting works."""
        limiter = RateLimiter(RateLimitConfig(max_requests_per_window=100))
        client_id = "test_client"
        
        # Client should be limited to 10% of global = 10
        for i in range(10):
            allowed, _ = limiter.check_rate_limit(client_id)
            self.assertTrue(allowed, f"Client request {i+1} should be allowed")
        
        # 11th request from same client should be blocked
        allowed, info = limiter.check_rate_limit(client_id)
        self.assertFalse(allowed)
        self.assertEqual(info['reason'], 'client_rate_limit_exceeded')
    
    def test_report_size_check_valid(self):
        """Test reports within size limit pass."""
        limiter = RateLimiter()
        allowed, info = limiter.check_report_size(1024)
        self.assertTrue(allowed)
    
    def test_report_size_check_exceeded(self):
        """Test oversized reports are blocked."""
        limiter = RateLimiter()
        allowed, info = limiter.check_report_size(100 * 1024 * 1024)  # 100MB
        self.assertFalse(allowed)
        self.assertEqual(info['reason'], 'report_size_exceeded')
    
    def test_section_count_check_valid(self):
        """Test valid section counts pass."""
        limiter = RateLimiter()
        allowed, info = limiter.check_section_count(10)
        self.assertTrue(allowed)
    
    def test_section_count_check_exceeded(self):
        """Test excessive section counts are blocked."""
        limiter = RateLimiter()
        allowed, info = limiter.check_section_count(1000)
        self.assertFalse(allowed)
        self.assertEqual(info['reason'], 'section_count_exceeded')
    
    def test_rate_limiter_thread_safety(self):
        """Test rate limiter is thread-safe."""
        limiter = RateLimiter(RateLimitConfig(max_requests_per_window=1000))
        
        def make_requests(n: int):
            for _ in range(n):
                limiter.check_rate_limit()
        
        threads = [threading.Thread(target=make_requests, args=(100,)) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        allowed, info = limiter.check_rate_limit()
        self.assertEqual(info['current_count'], 1000)


class TestReportGenerationSecurityProtector(unittest.TestCase):
    """Test main ReportGenerationSecurityProtector class."""
    
    def setUp(self):
        """Set up test protector."""
        self.protector = ReportGenerationSecurityProtector(
            security_level=SecurityLevel.MEDIUM
        )
    
    def test_create_security_context(self):
        """Test creating security context."""
        context = self.protector.create_security_context()
        self.assertIsNotNone(context.context_id)
        self.assertEqual(context.security_level, SecurityLevel.MEDIUM)
        self.assertIn(context.context_id, self.protector.active_contexts)
    
    def test_release_context(self):
        """Test releasing security context."""
        context = self.protector.create_security_context()
        context_id = context.context_id
        self.protector.release_context(context_id)
        self.assertNotIn(context_id, self.protector.active_contexts)
    
    def test_secure_report_generation_success(self):
        """Test successful secure report generation."""
        def mock_generator(report_type: str) -> str:
            return f"Generated report for {report_type}"
        
        success, result, metadata = self.protector.secure_report_generation(
            mock_generator,
            report_type='threat_summary'
        )
        
        self.assertTrue(success)
        self.assertEqual(result, "Generated report for threat_summary")
        self.assertTrue(metadata['success'])
        self.assertIn('context_id', metadata)
        self.assertIn('execution_time', metadata)
    
    def test_secure_report_generation_validation_block(self):
        """Test validation failure blocks generation."""
        def mock_generator(report_type: str) -> str:
            return f"Generated report for {report_type}"
        
        success, result, metadata = self.protector.secure_report_generation(
            mock_generator,
            report_type='invalid_type'
        )
        
        self.assertFalse(success)
        self.assertIsNone(result)
        self.assertEqual(metadata['blocked_reason'], 'validation_failure')
        self.assertFalse(metadata['validation_passed'])
    
    def test_secure_report_generation_path_traversal_block(self):
        """Test path traversal in filename is blocked."""
        def mock_generator(filename: str) -> str:
            return f"Report saved to {filename}"
        
        success, result, metadata = self.protector.secure_report_generation(
            mock_generator,
            filename='../../../etc/passwd'
        )
        
        self.assertFalse(success)
        self.assertIsNone(result)
        self.assertEqual(metadata['blocked_reason'], 'validation_failure')
    
    def test_secure_report_generation_low_security_allows_warnings(self):
        """Test LOW security level allows through validation warnings."""
        protector = ReportGenerationSecurityProtector(security_level=SecurityLevel.LOW)
        
        def mock_generator(report_type: str) -> str:
            return f"Generated report for {report_type}"
        
        # Invalid report type, but LOW security should not block
        success, result, metadata = protector.secure_report_generation(
            mock_generator,
            report_type='invalid_type'
        )
        
        # LOW security doesn't block on validation errors
        self.assertTrue(success)
        self.assertIsNotNone(result)
    
    def test_secure_report_generation_exception_handling(self):
        """Test exceptions in wrapped function are handled."""
        def failing_generator() -> str:
            raise ValueError("Generator failed")
        
        success, result, metadata = self.protector.secure_report_generation(failing_generator)
        
        self.assertFalse(success)
        self.assertIsNone(result)
        self.assertIn('error', metadata)
        self.assertEqual(metadata['error'], "Generator failed")
    
    def test_get_security_stats(self):
        """Test getting security statistics."""
        # Create some contexts
        for _ in range(3):
            self.protector.create_security_context()
        
        stats = self.protector.get_security_stats()
        self.assertEqual(stats['active_contexts'], 3)
        self.assertEqual(stats['security_level'], 'medium')
        self.assertIn('rate_limit_config', stats)


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience wrapper functions."""
    
    def test_get_default_protector(self):
        """Test default protector singleton."""
        p1 = get_default_protector()
        p2 = get_default_protector()
        self.assertIs(p1, p2)
    
    def test_secure_generate_report_wrapper(self):
        """Test convenience secure_generate_report function."""
        def mock_func(report_type: str) -> str:
            return f"Report: {report_type}"
        
        success, result, metadata = secure_generate_report(
            mock_func,
            report_type='threat_summary',
            security_level=SecurityLevel.HIGH
        )
        
        self.assertTrue(success)
        self.assertEqual(result, "Report: threat_summary")
        self.assertEqual(metadata['security_level'], 'high')
    
    def test_constant_time_compare_convenience(self):
        """Test constant_time_compare convenience function."""
        self.assertTrue(constant_time_compare("test", "test"))
        self.assertFalse(constant_time_compare("test", "different"))
    
    def test_secure_zeroize_convenience(self):
        """Test secure_zeroize convenience function."""
        data = bytearray(b'secret')
        secure_zeroize(data)
        self.assertEqual(data, bytearray(6))


class TestVersionInformation(unittest.TestCase):
    """Test module version information."""
    
    def test_version_format(self):
        """Test version string format."""
        self.assertEqual(VERSION, "1.7.0")
    
    def test_version_info_structure(self):
        """Test version info structure."""
        info = get_version_info()
        self.assertEqual(info['major'], 1)
        self.assertEqual(info['minor'], 7)
        self.assertEqual(info['patch'], 0)
        self.assertEqual(info['dimension'], 'B')
        self.assertEqual(info['dimension_version'], 17)
        self.assertEqual(info['release_date'], '2026-06-24')
    
    def test_get_version_function(self):
        """Test get_version returns correct string."""
        self.assertEqual(get_version(), "1.7.0")
    
    def test_get_version_info_returns_copy(self):
        """Test get_version_info returns a copy (not reference)."""
        info1 = get_version_info()
        info2 = get_version_info()
        info1['test'] = 'modified'
        self.assertNotIn('test', info2)


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility - no breaking changes."""
    
    def test_module_imports_without_errors(self):
        """Test module can be imported without errors."""
        import neural_shield.security_hardening_report_generation_protection_v17_2026_june as module
        self.assertIsNotNone(module)
    
    def test_all_public_apis_exist(self):
        """Test all expected public APIs are available."""
        import neural_shield.security_hardening_report_generation_protection_v17_2026_june as module
        
        # Classes
        self.assertTrue(hasattr(module, 'SecurityLevel'))
        self.assertTrue(hasattr(module, 'SecureMemory'))
        self.assertTrue(hasattr(module, 'InputValidator'))
        self.assertTrue(hasattr(module, 'RateLimiter'))
        self.assertTrue(hasattr(module, 'ReportGenerationSecurityProtector'))
        
        # Functions
        self.assertTrue(hasattr(module, 'get_default_protector'))
        self.assertTrue(hasattr(module, 'secure_generate_report'))
        self.assertTrue(hasattr(module, 'get_version'))
        self.assertTrue(hasattr(module, 'get_version_info'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
