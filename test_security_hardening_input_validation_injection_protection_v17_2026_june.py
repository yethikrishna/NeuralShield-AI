"""
Tests for NeuralShield Security Hardening v17 - Input Validation & Injection Protection
DIMENSION B: Security Hardening
All tests must pass - backward compatibility verified.
"""
import pytest
import os
import tempfile
from pathlib import Path

from neural_shield.security_hardening_input_validation_injection_protection_v17_2026_june import (
    PathTraversalProtector,
    InjectionProtector,
    InputValidator,
    HeaderInjectionProtector,
    ReDosProtector,
    is_safe_path,
    sanitize_path,
    safe_path_join,
    sanitize_sql,
    detect_sql_injection,
    sanitize_command_arg,
    sanitize_xss,
    validate_string,
    validate_int,
    validate_email,
    is_safe_header,
    sanitize_header,
)


class TestPathTraversalProtector:
    """Test path traversal attack prevention."""
    
    def test_is_safe_path_normal(self):
        """Test normal safe paths are accepted."""
        protector = PathTraversalProtector()
        assert protector.is_safe_path("file.txt", strict=False) is True
        assert protector.is_safe_path("subdir/file.txt", strict=False) is True
        assert protector.is_safe_path("/tmp/valid/path.txt", strict=False) is True
    
    def test_is_safe_path_detects_traversal(self):
        """Test path traversal attempts are detected."""
        protector = PathTraversalProtector()
        assert protector.is_safe_path("../etc/passwd", strict=False) is False
        assert protector.is_safe_path("..\\..\\windows\\system32", strict=False) is False
        assert protector.is_safe_path("/etc/../../../etc/passwd", strict=False) is False
    
    def test_is_safe_path_url_encoded(self):
        """Test URL-encoded traversal attempts are detected."""
        protector = PathTraversalProtector()
        assert protector.is_safe_path("%2e%2e%2fetc%2fpasswd", strict=False) is False
        assert protector.is_safe_path("..%2f..%2fetc", strict=False) is False
    
    def test_sanitize_path(self):
        """Test path sanitization."""
        protector = PathTraversalProtector()
        assert protector.sanitize_path("../file.txt") == ""
        assert protector.sanitize_path("safe_file.txt") == "safe_file.txt"
    
    def test_safe_path_join(self):
        """Test safe path joining."""
        protector = PathTraversalProtector()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = protector.safe_join(tmpdir, "subdir", "file.txt")
            assert result is not None
            assert tmpdir in result
            
            # Traversal attempt should fail
            result = protector.safe_join(tmpdir, "..", "etc", "passwd")
            assert result is None
    
    def test_convenience_functions(self):
        """Test public convenience functions."""
        assert is_safe_path("safe.txt", strict=False) is True
        assert is_safe_path("../unsafe", strict=False) is False
        assert sanitize_path("safe.txt") == "safe.txt"
        assert safe_path_join("/tmp", "file.txt") is not None


class TestInjectionProtector:
    """Test SQL, command, XSS injection protection."""
    
    def test_sanitize_sql_input(self):
        """Test SQL input sanitization."""
        protector = InjectionProtector()
        # Single quotes are escaped
        assert protector.sanitize_sql_input("O'Brien") == "O''Brien"
        # Comment markers removed
        assert '-- comment' not in protector.sanitize_sql_input("value -- comment")
        # Semicolons removed
        assert ';' not in protector.sanitize_sql_input("value; DROP TABLE")
    
    def test_detect_sql_injection(self):
        """Test SQL injection detection."""
        protector = InjectionProtector()
        # Obvious SQL injection
        suspicious, score = protector.detect_sql_injection("' OR 1=1 --")
        assert suspicious is True
        assert score > 0.3
        
        # Normal input (no SQL patterns)
        suspicious, score = protector.detect_sql_injection("simple_text_value")
        assert suspicious is False
    
    def test_sanitize_command_arg(self):
        """Test command argument sanitization."""
        protector = InjectionProtector()
        result = protector.sanitize_command_arg("file; rm -rf /")
        assert ';' not in result
        assert '|' not in protector.sanitize_command_arg("file | cat /etc/passwd")
    
    def test_detect_command_injection(self):
        """Test command injection detection."""
        protector = InjectionProtector()
        suspicious, score = protector.detect_command_injection("file; rm -rf /")
        assert suspicious is True
    
    def test_sanitize_xss(self):
        """Test XSS sanitization."""
        protector = InjectionProtector()
        result = protector.sanitize_xss('<script>alert("xss")</script>')
        assert '<script>' not in result
        assert '&lt;' in result  # HTML escaped
    
    def test_sanitize_html_content(self):
        """Test HTML content sanitization."""
        protector = InjectionProtector()
        result = protector.sanitize_html_content('<script>bad</script><b>good</b>')
        assert '<script>' not in result
        assert '<b>good</b>' in result


class TestInputValidator:
    """Test type-safe input validation."""
    
    def test_validate_string(self):
        """Test string validation."""
        validator = InputValidator()
        
        # Length validation
        valid, val = validator.validate_string("test", min_len=2, max_len=10)
        assert valid is True
        
        valid, val = validator.validate_string("a", min_len=2)
        assert valid is False
    
    def test_validate_int(self):
        """Test integer validation."""
        validator = InputValidator()
        
        valid, val = validator.validate_int("42", min_val=0, max_val=100)
        assert valid is True
        assert val == 42
        
        valid, val = validator.validate_int("150", max_val=100)
        assert valid is False
    
    def test_validate_float(self):
        """Test float validation."""
        validator = InputValidator()
        
        valid, val = validator.validate_float("3.14")
        assert valid is True
        assert val == 3.14
    
    def test_validate_email(self):
        """Test email validation."""
        validator = InputValidator()
        assert validator.validate_email("user@example.com") is True
        assert validator.validate_email("invalid-email") is False
    
    def test_validate_url(self):
        """Test URL validation."""
        validator = InputValidator()
        assert validator.validate_url("https://example.com") is True
        assert validator.validate_url("not-a-url") is False
    
    def test_validate_uuid(self):
        """Test UUID validation."""
        validator = InputValidator()
        assert validator.validate_uuid("550e8400-e29b-41d4-a716-446655440000") is True
        assert validator.validate_uuid("not-a-uuid") is False
    
    def test_validate_list(self):
        """Test list validation."""
        validator = InputValidator()
        
        valid, val = validator.validate_list([1, 2, 3], min_items=1, max_items=5)
        assert valid is True
        
        valid, val = validator.validate_list("not a list")
        assert valid is False
    
    def test_convenience_functions(self):
        """Test validation convenience functions."""
        valid, val = validate_string("test", max_len=100)
        assert valid is True
        
        valid, val = validate_int("42")
        assert valid is True
        assert val == 42
        
        assert validate_email("user@example.com") is True


class TestHeaderInjectionProtector:
    """Test HTTP header injection prevention."""
    
    def test_is_safe_header_value(self):
        """Test safe header detection."""
        protector = HeaderInjectionProtector()
        assert protector.is_safe_header_value("normal value") is True
        assert protector.is_safe_header_value("value\r\nSet-Cookie: hacked=1") is False
    
    def test_sanitize_header_value(self):
        """Test header sanitization."""
        protector = HeaderInjectionProtector()
        result = protector.sanitize_header_value("value\r\nSet-Cookie: hacked=1")
        assert '\r' not in result
        assert '\n' not in result
    
    def test_convenience_functions(self):
        """Test header convenience functions."""
        assert is_safe_header("safe") is True
        assert is_safe_header("unsafe\r\n") is False
        assert sanitize_header("test\r\n") == "test"


class TestReDosProtector:
    """Test Regular Expression DoS protection."""
    
    def test_safe_match_basic(self):
        """Test basic safe regex matching."""
        protector = ReDosProtector()
        match = protector.safe_match(r'^[a-z]+$', 'hello')
        assert match is not None
    
    def test_safe_match_no_match(self):
        """Test non-matching patterns."""
        protector = ReDosProtector()
        match = protector.safe_match(r'^[0-9]+$', 'hello')
        assert match is None
    
    def test_is_dangerous_pattern(self):
        """Test dangerous pattern detection."""
        protector = ReDosProtector()
        # Nested quantifiers are dangerous
        assert protector._is_dangerous_pattern('(a+)+') is True


class TestBackwardCompatibility:
    """Verify backward compatibility - no breaking changes."""
    
    def test_all_imports_work(self):
        """All classes and functions import correctly."""
        # Just verify no import errors
        assert PathTraversalProtector is not None
        assert InjectionProtector is not None
        assert InputValidator is not None
        assert HeaderInjectionProtector is not None
        assert ReDosProtector is not None
    
    def test_no_exceptions_on_empty_input(self):
        """Empty input handling doesn't crash."""
        assert is_safe_path(None, strict=False) is False
        assert sanitize_path(None) == ''
        assert sanitize_sql(None) == ''
        assert sanitize_xss(None) == ''


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
