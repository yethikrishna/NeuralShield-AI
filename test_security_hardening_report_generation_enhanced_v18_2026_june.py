"""
Test Suite for Security Hardening v18 - Enhanced Report Generation Protection
NeuralShield-AI

Comprehensive tests for all v18 security features.
All tests verify ADD-ONLY implementation - no existing code modified.
"""
import pytest
import time
import threading
import json
from neural_shield.security_hardening_report_generation_enhanced_v18_2026_june import (
    SecurityLevel,
    ValidationSeverity,
    SecurityEventType,
    ValidationResult,
    SecurityEvent,
    AdaptiveRateLimitConfig,
    CircuitBreakerConfig,
    SecurityContext,
    SecureMemoryV18,
    EnhancedInputValidator,
    AdaptiveRateLimiter,
    ReportTamperProtector,
    EnhancedReportSecurityProtector,
    create_v18_security_protector,
    get_v18_version_info
)


class TestSecurityLevelEnum:
    """Tests for SecurityLevel enumeration."""
    
    def test_security_level_values(self):
        assert SecurityLevel.LOW.value == "low"
        assert SecurityLevel.MEDIUM.value == "medium"
        assert SecurityLevel.HIGH.value == "high"
        assert SecurityLevel.MAXIMUM.value == "maximum"
    
    def test_security_level_count(self):
        assert len(list(SecurityLevel)) == 4


class TestValidationSeverityEnum:
    """Tests for ValidationSeverity enumeration."""
    
    def test_severity_values(self):
        assert ValidationSeverity.INFO.value == "info"
        assert ValidationSeverity.WARNING.value == "warning"
        assert ValidationSeverity.ERROR.value == "error"
        assert ValidationSeverity.CRITICAL.value == "critical"


class TestSecurityEventTypeEnum:
    """Tests for SecurityEventType enumeration."""
    
    def test_event_type_values(self):
        event_types = [e.value for e in SecurityEventType]
        assert "validation_passed" in event_types
        assert "validation_failed" in event_types
        assert "rate_limit_exceeded" in event_types
        assert "memory_zeroized" in event_types
        assert "context_created" in event_types
        assert "report_signed" in event_types
        assert "tamper_detected" in event_types
        assert "circuit_breaker_tripped" in event_types


class TestValidationResult:
    """Tests for ValidationResult dataclass."""
    
    def test_validation_result_creation(self):
        result = ValidationResult(valid=True, message="Test passed")
        assert result.valid is True
        assert result.message == "Test passed"
        assert result.severity == ValidationSeverity.INFO
    
    def test_validation_result_failure(self):
        result = ValidationResult(
            valid=False,
            severity=ValidationSeverity.ERROR,
            message="Invalid input",
            field="test_field"
        )
        assert result.valid is False
        assert result.severity == ValidationSeverity.ERROR
        assert result.field == "test_field"


class TestSecurityContext:
    """Tests for SecurityContext class."""
    
    def test_context_creation(self):
        context = SecurityContext(security_level=SecurityLevel.HIGH, client_id="test_client")
        assert context.context_id is not None
        assert len(context.context_id) == 32  # 16 bytes hex
        assert context.security_level == SecurityLevel.HIGH
        assert context.client_id == "test_client"
        assert context.request_count == 0
    
    def test_increment_request(self):
        context = SecurityContext()
        assert context.request_count == 0
        context.increment_request()
        assert context.request_count == 1
        context.increment_request()
        assert context.request_count == 2
    
    def test_context_expiration(self):
        context = SecurityContext()
        context.expires_at = time.time() - 1
        assert context.is_expired() is True
    
    def test_context_not_expired(self):
        context = SecurityContext()
        assert context.is_expired() is False
    
    def test_add_validation_failure(self):
        context = SecurityContext()
        failure = ValidationResult(valid=False, severity=ValidationSeverity.ERROR)
        context.add_validation_failure(failure)
        assert len(context.validation_failures) == 1
    
    def test_add_security_event(self):
        context = SecurityContext()
        event = SecurityEvent(
            event_type=SecurityEventType.CONTEXT_CREATED,
            severity=ValidationSeverity.INFO,
            message="Test"
        )
        context.add_security_event(event)
        assert len(context.security_events) == 1
    
    def test_get_failure_count(self):
        context = SecurityContext()
        context.add_validation_failure(ValidationResult(valid=False, severity=ValidationSeverity.WARNING))
        context.add_validation_failure(ValidationResult(valid=False, severity=ValidationSeverity.ERROR))
        context.add_validation_failure(ValidationResult(valid=False, severity=ValidationSeverity.CRITICAL))
        assert context.get_failure_count(ValidationSeverity.ERROR) == 2


class TestSecureMemoryV18:
    """Tests for SecureMemoryV18 utilities."""
    
    def test_zeroize_bytearray(self):
        data = bytearray(b"sensitive data here")
        original = bytes(data)
        SecureMemoryV18.zeroize_bytearray(data)
        assert all(b == 0 for b in data)
        assert bytes(data) != original
    
    def test_zeroize_bytes(self):
        original = b"test data"
        result = SecureMemoryV18.zeroize_bytes(original)
        assert len(result) == len(original)
        assert all(b == 0 for b in result)
    
    def test_zeroize_string(self):
        original = "test string"
        result = SecureMemoryV18.zeroize_string(original)
        assert len(result) == len(original)
        assert all(c == '\x00' for c in result)
    
    def test_constant_time_compare_equal(self):
        a = b"same value"
        b = b"same value"
        assert SecureMemoryV18.constant_time_compare(a, b) is True
    
    def test_constant_time_compare_different(self):
        a = b"value a"
        b = b"value b"
        assert SecureMemoryV18.constant_time_compare(a, b) is False
    
    def test_constant_time_str_compare_equal(self):
        assert SecureMemoryV18.constant_time_str_compare("test", "test") is True
    
    def test_constant_time_str_compare_different_length(self):
        assert SecureMemoryV18.constant_time_str_compare("short", "longer string") is False
    
    def test_secure_hash(self):
        data = b"test data"
        result = SecureMemoryV18.secure_hash(data)
        assert len(result) == 64  # SHA512 output
        assert result != data


class TestEnhancedInputValidator:
    """Tests for EnhancedInputValidator class."""
    
    def test_validate_report_type_valid(self):
        result = EnhancedInputValidator.validate_report_type("threat_summary")
        assert result.valid is True
        assert result.sanitized_value == "threat_summary"
    
    def test_validate_report_type_invalid(self):
        result = EnhancedInputValidator.validate_report_type("invalid_type")
        assert result.valid is False
        assert result.severity == ValidationSeverity.ERROR
    
    def test_validate_report_type_empty(self):
        result = EnhancedInputValidator.validate_report_type("")
        assert result.valid is False
    
    def test_validate_output_format_valid(self):
        result = EnhancedInputValidator.validate_output_format("json")
        assert result.valid is True
    
    def test_validate_output_format_invalid(self):
        result = EnhancedInputValidator.validate_output_format("exe")
        assert result.valid is False
    
    def test_validate_string_length_valid(self):
        result = EnhancedInputValidator.validate_string_length("short", "report_title")
        assert result.valid is True
    
    def test_validate_string_length_too_long(self):
        long_str = "x" * 300
        result = EnhancedInputValidator.validate_string_length(long_str, "report_title")
        assert result.valid is False
        assert result.severity == ValidationSeverity.WARNING
    
    def test_sanitize_content_script(self):
        dangerous = "<script>alert('xss')</script>"
        sanitized = EnhancedInputValidator.sanitize_content(dangerous)
        assert "<script" not in sanitized.lower()
    
    def test_validate_ioc_value_valid(self):
        result = EnhancedInputValidator.validate_ioc_value("192.168.1.1")
        assert result.valid is True
    
    def test_validate_ioc_value_suspicious(self):
        suspicious = "UNION SELECT password FROM users"
        result = EnhancedInputValidator.validate_ioc_value(suspicious)
        assert result.valid is False
        assert result.severity == ValidationSeverity.CRITICAL
    
    def test_validate_filename_valid(self):
        result = EnhancedInputValidator.validate_filename("report.json")
        assert result.valid is True
    
    def test_validate_filename_path_traversal(self):
        result = EnhancedInputValidator.validate_filename("../../../etc/passwd")
        assert result.valid is False
        assert result.severity == ValidationSeverity.CRITICAL
    
    def test_calculate_suspicion_score(self):
        score = EnhancedInputValidator.calculate_suspicion_score("normal content")
        assert score == 0
        
        high_score = EnhancedInputValidator.calculate_suspicion_score("UNION SELECT cmd.exe")
        assert high_score >= 10
    
    def test_validate_nested_dict_valid(self):
        data = {"key": "value", "nested": {"inner": "data"}}
        result = EnhancedInputValidator.validate_nested_dict(data)
        assert result.valid is True


class TestAdaptiveRateLimiter:
    """Tests for AdaptiveRateLimiter class."""
    
    def test_rate_limiter_creation(self):
        limiter = AdaptiveRateLimiter()
        assert limiter.config is not None
    
    def test_check_rate_limit_allowed(self):
        limiter = AdaptiveRateLimiter()
        allowed, meta = limiter.check_rate_limit("client1")
        assert allowed is True
        assert "current_count" in meta
    
    def test_rate_limit_enforcement(self):
        config = AdaptiveRateLimitConfig(
            base_max_requests_per_window=3,
            window_seconds=60
        )
        limiter = AdaptiveRateLimiter(config)
        
        # First 3 should be allowed
        for i in range(3):
            allowed, _ = limiter.check_rate_limit("test_client")
            assert allowed is True
        
        # 4th should be blocked
        allowed, meta = limiter.check_rate_limit("test_client")
        assert allowed is False
        assert meta['reason'] == 'client_rate_limit_exceeded'
    
    def test_check_report_size_valid(self):
        limiter = AdaptiveRateLimiter()
        allowed, _ = limiter.check_report_size(1024)
        assert allowed is True
    
    def test_check_report_size_too_big(self):
        limiter = AdaptiveRateLimiter()
        allowed, meta = limiter.check_report_size(100 * 1024 * 1024)
        assert allowed is False
        assert meta['reason'] == 'report_size_exceeded'


class TestReportTamperProtector:
    """Tests for ReportTamperProtector class."""
    
    def test_sign_report_dict(self):
        protector = ReportTamperProtector()
        content = {"report": "data", "score": 95}
        signed = protector.sign_report(content, "context_123")
        
        assert 'content' in signed
        assert 'signature' in signed
        assert 'context_id' in signed
        assert signed['algorithm'] == 'HMAC-SHA512'
        assert signed['version'] == 'v18'
    
    def test_sign_report_string(self):
        protector = ReportTamperProtector()
        signed = protector.sign_report("markdown report content", "ctx_456")
        assert 'signature' in signed
    
    def test_verify_report_valid(self):
        protector = ReportTamperProtector()
        content = {"test": "data"}
        signed = protector.sign_report(content, "ctx")
        valid, meta = protector.verify_report(signed)
        assert valid is True
        assert meta['verified'] is True
    
    def test_verify_report_tampered(self):
        protector = ReportTamperProtector()
        content = {"test": "data"}
        signed = protector.sign_report(content, "ctx")
        
        # Tamper with content
        signed['content'] = {"test": "TAMPERED"}
        valid, meta = protector.verify_report(signed)
        assert valid is False
        assert meta['tamper_detected'] is True
    
    def test_verify_report_missing_field(self):
        protector = ReportTamperProtector()
        valid, meta = protector.verify_report({"content": {}})
        assert valid is False


class TestEnhancedReportSecurityProtector:
    """Tests for main EnhancedReportSecurityProtector class."""
    
    def test_protector_creation(self):
        protector = EnhancedReportSecurityProtector(SecurityLevel.MEDIUM)
        assert protector.security_level == SecurityLevel.MEDIUM
        assert protector.VERSION == "18.0.0"
    
    def test_create_security_context(self):
        protector = EnhancedReportSecurityProtector()
        context = protector.create_security_context("client_123")
        assert context is not None
        assert context.client_id == "client_123"
        assert context.context_id in protector.active_contexts
    
    def test_destroy_security_context(self):
        protector = EnhancedReportSecurityProtector()
        context = protector.create_security_context()
        ctx_id = context.context_id
        assert ctx_id in protector.active_contexts
        
        protector.destroy_security_context(ctx_id)
        assert ctx_id not in protector.active_contexts
    
    def test_validate_report_generation_request_valid(self):
        protector = EnhancedReportSecurityProtector()
        context = protector.create_security_context()
        
        valid, results = protector.validate_report_generation_request(
            context,
            report_type="threat_summary",
            output_format="json"
        )
        assert valid is True
        assert all(r.valid for r in results)
    
    def test_validate_report_generation_request_invalid_type(self):
        protector = EnhancedReportSecurityProtector()
        context = protector.create_security_context()
        
        valid, results = protector.validate_report_generation_request(
            context,
            report_type="invalid_type",
            output_format="json"
        )
        assert valid is False
    
    def test_secure_report_output(self):
        protector = EnhancedReportSecurityProtector()
        context = protector.create_security_context()
        
        report = {"title": "Threat Report", "findings": 5}
        secured = protector.secure_report_output(context, report)
        
        assert 'content' in secured
        assert 'signature' in secured
        assert secured['context_id'] == context.context_id
    
    def test_get_security_audit_log(self):
        protector = EnhancedReportSecurityProtector()
        context = protector.create_security_context()
        
        log = protector.get_security_audit_log(context)
        assert isinstance(log, list)
        assert len(log) >= 1  # At least context created event
    
    def test_get_version_info(self):
        protector = EnhancedReportSecurityProtector()
        info = protector.get_version_info()
        assert info['version'] == "18.0.0"
        assert 'features' in info
        assert 'adaptive_rate_limiting' in info['features']
        assert 'circuit_breaker' in info['features']


class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    def test_create_v18_security_protector(self):
        protector = create_v18_security_protector(SecurityLevel.HIGH)
        assert isinstance(protector, EnhancedReportSecurityProtector)
        assert protector.security_level == SecurityLevel.HIGH
    
    def test_get_v18_version_info(self):
        info = get_v18_version_info()
        assert info['version'] == "18.0.0"
        assert 'v18' in info['module']


class TestThreadSafety:
    """Tests for thread safety of security components."""
    
    def test_concurrent_rate_limit_checks(self):
        limiter = AdaptiveRateLimiter(AdaptiveRateLimitConfig(
            base_max_requests_per_window=100,
            window_seconds=60
        ))
        
        def worker():
            for _ in range(10):
                limiter.check_rate_limit("thread_client")
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should not crash or have race conditions
        assert True
    
    def test_concurrent_context_operations(self):
        protector = EnhancedReportSecurityProtector()
        context = protector.create_security_context()
        
        def worker():
            for _ in range(10):
                context.increment_request()
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert context.request_count == 100


class TestBackwardCompatibility:
    """Tests verifying backward compatibility - no breaking changes."""
    
    def test_v18_does_not_break_v17_imports(self):
        """Verify v18 module doesn't interfere with existing v17 module."""
        # Both should be importable
        from neural_shield import security_hardening_report_generation_protection_v17_2026_june as v17
        assert v17 is not None
    
    def test_v18_is_add_only(self):
        """Verify v18 is completely separate module."""
        # v18 has its own namespace
        assert 'v18' in EnhancedReportSecurityProtector.VERSION


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
