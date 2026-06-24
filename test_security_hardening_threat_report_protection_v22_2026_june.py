"""
Tests for Security Hardening v22 - Threat Report Generation Protection Module
NeuralShield-AI

Covers all security features:
- Input validation and sanitization for threat reports
- IOC validation (IP, domain, URL, hash, email)
- MITRE ATT&CK technique validation
- Rate limiting and DoS protection
- Secure memory handling and zeroization
- Constant-time comparison
- HMAC report sealing and tamper detection
- Security context isolation
- Thread safety
- Backward compatibility
"""
import unittest
import threading
import time
from typing import Any

# Import security module
from neural_shield.security_hardening_threat_report_protection_v22_2026_june import (
    ReportSecurityLevel,
    IOCType,
    ValidationSeverity,
    SecurityEventType,
    ValidationResult,
    SecurityEvent,
    ReportRateLimitConfig,
    ProtectedReportContext,
    SecureMemoryV22,
    IOCValidator,
    ReportContentSanitizer,
    ReportRateLimiter,
    ReportSealer,
    ProtectedThreatReportGenerator,
    create_protected_generator,
    validate_ioc_list,
    __version__,
    __compatibility__,
)

# ============================================================================
# ENUMERATION TESTS
# ============================================================================

class TestReportSecurityLevelEnum(unittest.TestCase):
    """Test security level enumeration."""
    
    def test_security_level_count(self):
        """Test correct number of security levels."""
        self.assertEqual(len(ReportSecurityLevel), 4)
    
    def test_security_level_values(self):
        """Test all security level values exist."""
        levels = {level.value for level in ReportSecurityLevel}
        self.assertIn("basic", levels)
        self.assertIn("standard", levels)
        self.assertIn("enhanced", levels)
        self.assertIn("maximum", levels)

class TestIOCTypeEnum(unittest.TestCase):
    """Test IOC type enumeration."""
    
    def test_ioc_type_values(self):
        """Test all IOC type values."""
        types = {t.value for t in IOCType}
        self.assertIn("ipv4", types)
        self.assertIn("ipv6", types)
        self.assertIn("domain", types)
        self.assertIn("url", types)
        self.assertIn("md5", types)
        self.assertIn("sha1", types)
        self.assertIn("sha256", types)
        self.assertIn("sha512", types)
        self.assertIn("email", types)
        self.assertIn("unknown", types)

class TestValidationSeverityEnum(unittest.TestCase):
    """Test validation severity enumeration."""
    
    def test_severity_order(self):
        """Test severity levels are properly ordered."""
        severities = [s.value for s in ValidationSeverity]
        self.assertIn("info", severities)
        self.assertIn("warning", severities)
        self.assertIn("error", severities)
        self.assertIn("critical", severities)

class TestSecurityEventTypeEnum(unittest.TestCase):
    """Test security event type enumeration."""
    
    def test_event_types_exist(self):
        """Test key event types exist."""
        events = {e.value for e in SecurityEventType}
        self.assertIn("report_created", events)
        self.assertIn("report_signed", events)
        self.assertIn("validation_failed", events)
        self.assertIn("rate_limit_exceeded", events)
        self.assertIn("tamper_detected", events)

# ============================================================================
# DATA CLASS TESTS
# ============================================================================

class TestValidationResult(unittest.TestCase):
    """Test ValidationResult data class."""
    
    def test_validation_result_creation(self):
        """Test basic validation result creation."""
        result = ValidationResult(valid=True, message="Test passed")
        self.assertTrue(result.valid)
        self.assertEqual(result.message, "Test passed")
        self.assertGreater(result.check_timestamp, 0)
    
    def test_validation_result_defaults(self):
        """Test default values are properly set."""
        result = ValidationResult(valid=False)
        self.assertEqual(result.severity, ValidationSeverity.INFO)
        self.assertEqual(result.field, "")
        self.assertIsNone(result.sanitized_value)

class TestProtectedReportContext(unittest.TestCase):
    """Test ProtectedReportContext data class."""
    
    def test_context_creation(self):
        """Test context creation with defaults."""
        context = ProtectedReportContext()
        self.assertGreater(len(context.context_id), 0)
        self.assertEqual(context.security_level, ReportSecurityLevel.STANDARD)
        self.assertGreater(context.created_at, 0)
        self.assertGreater(context.expires_at, context.created_at)
        self.assertEqual(context.report_count, 0)
    
    def test_context_expiry(self):
        """Test context expiry check."""
        context = ProtectedReportContext()
        self.assertFalse(context.is_expired())
    
    def test_context_increment_report(self):
        """Test thread-safe report counter increment."""
        context = ProtectedReportContext()
        context.increment_report_count()
        context.increment_report_count()
        self.assertEqual(context.report_count, 2)

# ============================================================================
# SECURE MEMORY TESTS
# ============================================================================

class TestSecureMemoryV22(unittest.TestCase):
    """Test secure memory utilities."""
    
    def test_constant_time_compare_equal(self):
        """Test constant-time comparison for equal values."""
        a = b"test_data_123"
        b = b"test_data_123"
        self.assertTrue(SecureMemoryV22.constant_time_compare(a, b))
    
    def test_constant_time_compare_not_equal(self):
        """Test constant-time comparison for different values."""
        a = b"test_data_123"
        b = b"test_data_456"
        self.assertFalse(SecureMemoryV22.constant_time_compare(a, b))
    
    def test_constant_time_str_compare(self):
        """Test constant-time string comparison."""
        self.assertTrue(SecureMemoryV22.constant_time_str_compare("abc123", "abc123"))
        self.assertFalse(SecureMemoryV22.constant_time_str_compare("abc123", "abc456"))
    
    def test_zeroize_bytearray(self):
        """Test bytearray zeroization."""
        data = bytearray(b"sensitive_data_here")
        SecureMemoryV22.zeroize_bytearray(data)
        self.assertEqual(sum(data), 0)
    
    def test_zeroize_threat_data(self):
        """Test threat dictionary data zeroization."""
        threat_data = {
            "iocs": ["192.168.1.1", "malicious.com"],
            "raw_threat_data": "sensitive_raw_data"
        }
        SecureMemoryV22.zeroize_threat_data(threat_data)
        # Should not raise exceptions

# ============================================================================
# IOC VALIDATOR TESTS
# ============================================================================

class TestIOCValidator(unittest.TestCase):
    """Test IOC validation functionality."""
    
    def test_detect_ioc_type_ipv4(self):
        """Test IPv4 address detection."""
        self.assertEqual(IOCValidator.detect_ioc_type("192.168.1.1"), IOCType.IPV4)
    
    def test_detect_ioc_type_ipv6(self):
        """Test IPv6 address detection."""
        self.assertEqual(IOCValidator.detect_ioc_type("2001:db8::1"), IOCType.IPV6)
    
    def test_detect_ioc_type_domain(self):
        """Test domain name detection."""
        self.assertEqual(IOCValidator.detect_ioc_type("example.com"), IOCType.DOMAIN)
    
    def test_detect_ioc_type_email(self):
        """Test email address detection."""
        self.assertEqual(IOCValidator.detect_ioc_type("user@example.com"), IOCType.EMAIL)
    
    def test_detect_ioc_type_url(self):
        """Test URL detection."""
        self.assertEqual(IOCValidator.detect_ioc_type("https://example.com/path"), IOCType.URL)
    
    def test_detect_ioc_type_hashes(self):
        """Test hash type detection."""
        self.assertEqual(IOCValidator.detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e"), IOCType.MD5)
        self.assertEqual(IOCValidator.detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709"), IOCType.SHA1)
    
    def test_validate_ioc_valid(self):
        """Test valid IOC validation."""
        result = IOCValidator.validate_ioc("192.168.1.1")
        self.assertTrue(result.valid)
    
    def test_validate_ioc_empty(self):
        """Test empty IOC validation."""
        result = IOCValidator.validate_ioc("")
        self.assertFalse(result.valid)
        self.assertEqual(result.severity, ValidationSeverity.ERROR)
    
    def test_validate_mitre_technique_valid(self):
        """Test valid MITRE technique ID."""
        result = IOCValidator.validate_mitre_technique("T1059")
        self.assertTrue(result.valid)
    
    def test_validate_mitre_technique_invalid(self):
        """Test invalid MITRE technique ID."""
        result = IOCValidator.validate_mitre_technique("INVALID")
        self.assertFalse(result.valid)
    
    def test_validate_severity_valid(self):
        """Test valid severity level."""
        result = IOCValidator.validate_severity("critical")
        self.assertTrue(result.valid)
    
    def test_validate_severity_invalid(self):
        """Test invalid severity level."""
        result = IOCValidator.validate_severity("EXTREME")
        self.assertFalse(result.valid)
        self.assertEqual(result.sanitized_value, "unknown")
    
    def test_validate_false_positive_rate_valid(self):
        """Test valid false positive rate."""
        result = IOCValidator.validate_false_positive_rate(0.5)
        self.assertTrue(result.valid)
    
    def test_validate_false_positive_rate_clamped(self):
        """Test out-of-range false positive rate clamping."""
        result = IOCValidator.validate_false_positive_rate(2.5)
        self.assertFalse(result.valid)
        self.assertEqual(result.sanitized_value, 1.0)

# ============================================================================
# CONTENT SANITIZER TESTS
# ============================================================================

class TestReportContentSanitizer(unittest.TestCase):
    """Test report content sanitization."""
    
    def test_sanitize_xss_script(self):
        """Test XSS script tag sanitization."""
        content = '<script>alert("xss")</script>'
        sanitized = ReportContentSanitizer.sanitize_report_content(content)
        self.assertNotIn('<script', sanitized.lower())
    
    def test_sanitize_javascript_uri(self):
        """Test javascript: URI sanitization."""
        content = 'Click <a href="javascript:alert(1)">here</a>'
        sanitized = ReportContentSanitizer.sanitize_report_content(content)
        self.assertNotIn('javascript:', sanitized.lower())
    
    def test_sanitize_template_injection(self):
        """Test template injection sanitization."""
        content = '{{ malicious_code() }}'
        sanitized = ReportContentSanitizer.sanitize_report_content(content)
        self.assertIn('[template_blocked]', sanitized)
    
    def test_sanitize_filename(self):
        """Test filename path traversal sanitization."""
        filename = '../../etc/passwd'
        sanitized = ReportContentSanitizer.sanitize_filename(filename)
        self.assertNotIn('..', sanitized)
        self.assertNotIn('/', sanitized)
    
    def test_sanitize_recommendation(self):
        """Test recommendation text sanitization."""
        rec = 'Run <script>evil</script> command'
        sanitized = ReportContentSanitizer.sanitize_recommendation(rec)
        self.assertNotIn('<script', sanitized.lower())

# ============================================================================
# RATE LIMITER TESTS
# ============================================================================

class TestReportRateLimiter(unittest.TestCase):
    """Test report rate limiting functionality."""
    
    def test_rate_limit_initial_allowed(self):
        """Test initial requests are allowed."""
        limiter = ReportRateLimiter(ReportRateLimitConfig(max_reports_per_hour=5))
        allowed, meta = limiter.check_rate_limit("client1")
        self.assertTrue(allowed)
        self.assertEqual(meta["current_count"], 0)
    
    def test_rate_limit_exceeded(self):
        """Test rate limit enforcement."""
        config = ReportRateLimitConfig(max_reports_per_hour=2, window_seconds=3600)
        limiter = ReportRateLimiter(config)
        
        # First two allowed
        limiter.check_rate_limit("client1")
        limiter.check_rate_limit("client1")
        
        # Third should be blocked
        allowed, _ = limiter.check_rate_limit("client1")
        self.assertFalse(allowed)
    
    def test_rate_limit_per_client(self):
        """Test rate limits are per-client."""
        config = ReportRateLimitConfig(max_reports_per_hour=1)
        limiter = ReportRateLimiter(config)
        
        # Client 1 uses quota
        limiter.check_rate_limit("client1")
        allowed1, _ = limiter.check_rate_limit("client1")
        
        # Client 2 still has quota
        allowed2, _ = limiter.check_rate_limit("client2")
        
        self.assertFalse(allowed1)
        self.assertTrue(allowed2)
    
    def test_check_ioc_count(self):
        """Test IOC count limit check."""
        limiter = ReportRateLimiter(ReportRateLimitConfig(max_iocs_per_report=100))
        self.assertTrue(limiter.check_ioc_count(50))
        self.assertFalse(limiter.check_ioc_count(200))
    
    def test_check_report_size(self):
        """Test report size limit check."""
        limiter = ReportRateLimiter()
        self.assertTrue(limiter.check_report_size(1000))
        self.assertFalse(limiter.check_report_size(100 * 1024 * 1024))

# ============================================================================
# REPORT SEALER TESTS
# ============================================================================

class TestReportSealer(unittest.TestCase):
    """Test report sealing and tamper detection."""
    
    def test_seal_report(self):
        """Test report sealing creates signature."""
        sealer = ReportSealer()
        result = sealer.seal_report("report content", "report_123")
        self.assertEqual(result["report_id"], "report_123")
        self.assertIn("signature", result)
        self.assertTrue(result["sealed"])
    
    def test_verify_report_valid(self):
        """Test valid report verification."""
        sealer = ReportSealer()
        content = "original report content"
        seal = sealer.seal_report(content, "report_123")
        
        valid, msg = sealer.verify_report(content, seal)
        self.assertTrue(valid)
    
    def test_verify_report_tampered(self):
        """Test tampered report detection."""
        sealer = ReportSealer()
        content = "original report content"
        seal = sealer.seal_report(content, "report_123")
        
        tampered = "tampered report content"
        valid, msg = sealer.verify_report(tampered, seal)
        self.assertFalse(valid)
        self.assertIn("tampering", msg.lower())

# ============================================================================
# PROTECTED GENERATOR TESTS
# ============================================================================

class TestProtectedThreatReportGenerator(unittest.TestCase):
    """Test main protected report generator wrapper."""
    
    def test_generator_creation(self):
        """Test generator creation with different security levels."""
        gen = ProtectedThreatReportGenerator(security_level=ReportSecurityLevel.MAXIMUM)
        self.assertEqual(gen.security_level, ReportSecurityLevel.MAXIMUM)
        self.assertTrue(gen._initialized)
    
    def test_validate_report_inputs_valid(self):
        """Test valid report inputs validation."""
        gen = ProtectedThreatReportGenerator()
        results = gen.validate_report_inputs(
            report_type="threat_summary",
            output_format="json"
        )
        self.assertEqual(len(results), 0)
    
    def test_validate_report_inputs_invalid_type(self):
        """Test invalid report type validation."""
        gen = ProtectedThreatReportGenerator()
        results = gen.validate_report_inputs(
            report_type="invalid_type",
            output_format="json"
        )
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].valid)
    
    def test_generate_protected_report_mock(self):
        """Test protected report generation with mock generator."""
        gen = ProtectedThreatReportGenerator()
        
        def mock_generator(**kwargs):
            return {"report": "generated", "type": kwargs.get("report_type")}
        
        result = gen.generate_protected_report(
            mock_generator,
            report_type="threat_summary",
            output_format="json"
        )
        
        self.assertTrue(result["success"])
        self.assertTrue(result["security_protected"])
        self.assertIn("original_result", result)
    
    def test_get_security_audit_log(self):
        """Test security audit log retrieval."""
        gen = ProtectedThreatReportGenerator()
        
        def mock_generator(**kwargs):
            return {"test": "data"}
        
        gen.generate_protected_report(mock_generator, "threat_summary", "json")
        log = gen.get_security_audit_log()
        
        self.assertGreater(len(log), 0)
        self.assertIn("event_type", log[0])
    
    def test_secure_dispose(self):
        """Test secure context disposal."""
        gen = ProtectedThreatReportGenerator(security_level=ReportSecurityLevel.MAXIMUM)
        gen.secure_dispose()
        # Should not raise exceptions

# ============================================================================
# CONVENIENCE FUNCTION TESTS
# ============================================================================

class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience wrapper functions."""
    
    def test_create_protected_generator_default(self):
        """Test default generator creation."""
        gen = create_protected_generator()
        self.assertIsInstance(gen, ProtectedThreatReportGenerator)
    
    def test_create_protected_generator(self):
        """Test generator creation with level parameter."""
        gen = create_protected_generator("maximum")
        self.assertEqual(gen.security_level, ReportSecurityLevel.MAXIMUM)
    
    def test_validate_ioc_list(self):
        """Test bulk IOC list validation."""
        iocs = ["192.168.1.1", "example.com", "invalid_ioc_!@#$"]
        result = validate_ioc_list(iocs)
        self.assertEqual(result["total"], 3)
        self.assertGreaterEqual(result["valid"], 2)

# ============================================================================
# THREAD SAFETY TESTS
# ============================================================================

class TestThreadSafety(unittest.TestCase):
    """Test thread safety of security components."""
    
    def test_context_thread_safety(self):
        """Test ProtectedReportContext is thread-safe."""
        context = ProtectedReportContext()
        num_threads = 10
        increments_per_thread = 100
        
        def worker():
            for _ in range(increments_per_thread):
                context.increment_report_count()
        
        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(context.report_count, num_threads * increments_per_thread)

# ============================================================================
# BACKWARD COMPATIBILITY TESTS
# ============================================================================

class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility guarantees."""
    
    def test_module_version_info(self):
        """Test version metadata exists."""
        self.assertEqual(__version__, "22.0.0")
        self.assertIn("100% backward compatible", __compatibility__)
    
    def test_compatibility_statement(self):
        """Test compatibility statement is present."""
        self.assertIn("ADD-ONLY", __compatibility__)

# ============================================================================
# TEST RUNNER
# ============================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
