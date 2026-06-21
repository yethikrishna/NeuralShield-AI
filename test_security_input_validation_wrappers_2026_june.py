#!/usr/bin/env python3
"""
Tests for Security Input Validation Wrappers
DIMENSION B: Security Hardening

All tests are isolated - no existing code dependencies.
"""

import unittest
import threading
from typing import Any

# Import the new module
from neural_shield.security_input_validation_wrappers_2026_june import (
    InputValidator,
    InputSanitizer,
    ValidationContext,
    ValidationResult,
    ValidationError,
    ValidationSeverity,
    ValidationErrorCode,
    validate_input,
    sanitize_input,
    get_validator,
    get_sanitizer,
)


class TestInputSanitizer(unittest.TestCase):
    """Test input sanitization functions."""
    
    def setUp(self):
        self.sanitizer = InputSanitizer()
    
    def test_sanitize_string_basic(self):
        """Test basic string sanitization."""
        result = self.sanitizer.sanitize_string("hello world")
        self.assertEqual(result, "hello world")
    
    def test_sanitize_string_control_chars(self):
        """Test control character stripping."""
        # Null byte and other control chars should be stripped
        test_input = "hello\x00world\x01\x02"
        result = self.sanitizer.sanitize_string(test_input)
        self.assertEqual(result, "helloworld")
    
    def test_sanitize_string_preserve_newlines(self):
        """Test newline preservation option."""
        test_input = "hello\nworld\r\n"
        result = self.sanitizer.sanitize_string(test_input, allow_newlines=True)
        self.assertEqual(result, "hello\nworld\r\n")
    
    def test_sanitize_string_max_length(self):
        """Test max length enforcement."""
        test_input = "a" * 1000
        result = self.sanitizer.sanitize_string(test_input, max_length=100)
        self.assertEqual(len(result), 100)
    
    def test_sanitize_filename_basic(self):
        """Test basic filename sanitization."""
        result = self.sanitizer.sanitize_filename("test.txt")
        self.assertEqual(result, "test.txt")
    
    def test_sanitize_filename_path_traversal(self):
        """Test path traversal prevention."""
        result = self.sanitizer.sanitize_filename("../../../etc/passwd")
        self.assertNotIn("/", result)
        self.assertNotIn("..", result)
    
    def test_sanitize_filename_unsafe_chars(self):
        """Test unsafe character removal."""
        result = self.sanitizer.sanitize_filename('file<name>:".txt')
        self.assertNotIn("<", result)
        self.assertNotIn(">", result)
        self.assertNotIn(":", result)
        self.assertNotIn('"', result)
    
    def test_sanitize_filename_leading_dots(self):
        """Test leading dot removal."""
        result = self.sanitizer.sanitize_filename("...hidden_file")
        self.assertFalse(result.startswith("."))
        self.assertEqual(result, "hidden_file")
    
    def test_sanitize_json_input_valid(self):
        """Test valid JSON parsing."""
        result = self.sanitizer.sanitize_json_input('{"key": "value"}')
        self.assertEqual(result, {"key": "value"})
    
    def test_sanitize_json_input_invalid(self):
        """Test invalid JSON handling."""
        result = self.sanitizer.sanitize_json_input('not json')
        self.assertIsNone(result)
    
    def test_sanitize_json_input_depth_limit(self):
        """Test JSON depth limit enforcement."""
        deep_json = '{"a":' * 20 + '{}' + '}' * 20
        result = self.sanitizer.sanitize_json_input(deep_json, max_depth=10)
        self.assertIsNone(result)


class TestInputValidator(unittest.TestCase):
    """Test input validation functions."""
    
    def setUp(self):
        self.validator = InputValidator()
    
    def test_validate_type_valid(self):
        """Test valid type validation."""
        result = self.validator.validate_type("test", str)
        self.assertTrue(result.passed)
    
    def test_validate_type_invalid(self):
        """Test invalid type validation."""
        result = self.validator.validate_type(123, str)
        self.assertFalse(result.passed)
        self.assertEqual(result.error_code, ValidationErrorCode.TYPE_MISMATCH)
    
    def test_validate_type_tuple(self):
        """Test type validation with tuple of types."""
        result = self.validator.validate_type(123, (int, float))
        self.assertTrue(result.passed)
        result = self.validator.validate_type(1.5, (int, float))
        self.assertTrue(result.passed)
    
    def test_validate_range_valid(self):
        """Test valid range validation."""
        result = self.validator.validate_range(5, min_val=0, max_val=10)
        self.assertTrue(result.passed)
    
    def test_validate_range_too_low(self):
        """Test range below minimum."""
        result = self.validator.validate_range(-1, min_val=0)
        self.assertFalse(result.passed)
        self.assertEqual(result.error_code, ValidationErrorCode.VALUE_OUT_OF_RANGE)
    
    def test_validate_range_too_high(self):
        """Test range above maximum."""
        result = self.validator.validate_range(11, max_val=10)
        self.assertFalse(result.passed)
        self.assertEqual(result.error_code, ValidationErrorCode.VALUE_OUT_OF_RANGE)
    
    def test_validate_length_valid(self):
        """Test valid length validation."""
        result = self.validator.validate_length("test", min_len=1, max_len=10)
        self.assertTrue(result.passed)
    
    def test_validate_length_too_short(self):
        """Test length below minimum."""
        result = self.validator.validate_length("", min_len=1)
        self.assertFalse(result.passed)
        self.assertEqual(result.error_code, ValidationErrorCode.LENGTH_VIOLATION)
    
    def test_validate_length_too_long(self):
        """Test length above maximum."""
        result = self.validator.validate_length("a" * 100, max_len=10)
        self.assertFalse(result.passed)
        self.assertEqual(result.error_code, ValidationErrorCode.LENGTH_VIOLATION)
    
    def test_validate_pattern_valid(self):
        """Test valid pattern matching."""
        result = self.validator.validate_pattern("user123", r'^[a-z0-9]+$')
        self.assertTrue(result.passed)
    
    def test_validate_pattern_invalid(self):
        """Test invalid pattern matching."""
        result = self.validator.validate_pattern("USER!!!", r'^[a-z0-9]+$')
        self.assertFalse(result.passed)
        self.assertEqual(result.error_code, ValidationErrorCode.PATTERN_MISMATCH)
    
    def test_validate_allowed_values(self):
        """Test allowed values validation."""
        result = self.validator.validate_allowed_values("admin", {"user", "admin", "guest"})
        self.assertTrue(result.passed)
        
        result = self.validator.validate_allowed_values("root", {"user", "admin"})
        self.assertFalse(result.passed)
        self.assertEqual(result.error_code, ValidationErrorCode.FORBIDDEN_VALUE)
    
    def test_validate_forbidden_values(self):
        """Test forbidden values validation."""
        result = self.validator.validate_forbidden_values("user", {"root", "admin"})
        self.assertTrue(result.passed)
        
        result = self.validator.validate_forbidden_values("root", {"root", "admin"})
        self.assertFalse(result.passed)
        self.assertEqual(result.error_code, ValidationErrorCode.FORBIDDEN_VALUE)
    
    def test_validate_not_empty(self):
        """Test not empty validation."""
        result = self.validator.validate_not_empty("value")
        self.assertTrue(result.passed)
        
        result = self.validator.validate_not_empty("")
        self.assertFalse(result.passed)
        
        result = self.validator.validate_not_empty(None)
        self.assertFalse(result.passed)
        
        result = self.validator.validate_not_empty([])
        self.assertFalse(result.passed)


class TestValidateInputDecorator(unittest.TestCase):
    """Test @validate_input decorator."""
    
    def test_validate_input_type_check(self):
        """Test type checking via decorator."""
        @validate_input(value={'type': str})
        def test_func(value: str) -> str:
            return value
        
        # Valid call
        result = test_func("hello")
        self.assertEqual(result, "hello")
        
        # Invalid call should raise
        with self.assertRaises(ValidationError):
            test_func(123)  # type: ignore
    
    def test_validate_input_range(self):
        """Test range checking via decorator."""
        @validate_input(temp={'type': (int, float), 'min': 0, 'max': 2})
        def test_func(temp: float) -> float:
            return temp
        
        test_func(1.0)  # Valid
        
        with self.assertRaises(ValidationError):
            test_func(3.0)  # Too high
        
        with self.assertRaises(ValidationError):
            test_func(-1.0)  # Too low
    
    def test_validate_input_length(self):
        """Test length checking via decorator."""
        @validate_input(prompt={'type': str, 'max_len': 100})
        def test_func(prompt: str) -> str:
            return prompt
        
        test_func("short")  # Valid
        
        with self.assertRaises(ValidationError):
            test_func("a" * 200)  # Too long
    
    def test_validate_input_pattern(self):
        """Test pattern matching via decorator."""
        @validate_input(user_id={'pattern': r'^[a-zA-Z0-9_-]{1,64}$'})
        def test_func(user_id: str) -> str:
            return user_id
        
        test_func("user_123-test")  # Valid
        
        with self.assertRaises(ValidationError):
            test_func("user!@#$")  # Invalid chars
    
    def test_validate_input_not_empty(self):
        """Test not empty checking via decorator."""
        @validate_input(prompt={'type': str, 'not_empty': True})
        def test_func(prompt: str) -> str:
            return prompt
        
        test_func("has content")  # Valid
        
        with self.assertRaises(ValidationError):
            test_func("")  # Empty
    
    def test_validate_input_allowed(self):
        """Test allowed values via decorator."""
        @validate_input(role={'allowed': ['user', 'admin', 'guest']})
        def test_func(role: str) -> str:
            return role
        
        test_func("admin")  # Valid
        
        with self.assertRaises(ValidationError):
            test_func("root")  # Not allowed
    
    def test_validate_input_multiple_rules(self):
        """Test multiple validation rules combined."""
        @validate_input(
            prompt={'type': str, 'not_empty': True, 'max_len': 1000},
            temperature={'type': (int, float), 'min': 0, 'max': 2},
            user_id={'pattern': r'^[a-z0-9_]{1,32}$'}
        )
        def test_func(prompt: str, temperature: float, user_id: str) -> dict:
            return {'prompt': prompt, 'temp': temperature, 'user': user_id}
        
        # Valid call
        result = test_func("test prompt", 0.7, "test_user")
        self.assertEqual(result['prompt'], "test prompt")
        
        # Invalid temperature
        with self.assertRaises(ValidationError):
            test_func("test", 5.0, "test_user")
        
        # Invalid user_id
        with self.assertRaises(ValidationError):
            test_func("test", 0.7, "INVALID-ID!!!")


class TestSanitizeInputDecorator(unittest.TestCase):
    """Test @sanitize_input decorator."""
    
    def test_sanitize_string_decorator(self):
        """Test string sanitization via decorator."""
        @sanitize_input(text={'max_length': 10, 'strip_control': True})
        def test_func(text: str) -> str:
            return text
        
        # Control chars stripped
        result = test_func("hello\x00world")
        self.assertNotIn("\x00", result)
        
        # Length enforced
        result = test_func("a" * 100)
        self.assertEqual(len(result), 10)
    
    def test_sanitize_filename_decorator(self):
        """Test filename sanitization via decorator."""
        @sanitize_input(filename={'sanitize_filename': True})
        def test_func(filename: str) -> str:
            return filename
        
        result = test_func("../../../etc/passwd")
        self.assertNotIn("/", result)
        self.assertNotIn("..", result)


class TestGlobalInstances(unittest.TestCase):
    """Test global shared instances."""
    
    def test_get_validator(self):
        """Test getting shared validator."""
        v1 = get_validator()
        v2 = get_validator()
        self.assertIs(v1, v2)
        self.assertIsInstance(v1, InputValidator)
    
    def test_get_sanitizer(self):
        """Test getting shared sanitizer."""
        s1 = get_sanitizer()
        s2 = get_sanitizer()
        self.assertIs(s1, s2)
        self.assertIsInstance(s1, InputSanitizer)


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of shared instances."""
    
    def test_concurrent_validator_access(self):
        """Test concurrent access to shared validator."""
        errors = []
        
        def worker():
            try:
                validator = get_validator()
                for _ in range(100):
                    validator.validate_type("test", str)
                    validator.validate_range(5, 0, 10)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0)


class TestValidationContext(unittest.TestCase):
    """Test validation context."""
    
    def test_context_defaults(self):
        """Test default context values."""
        ctx = ValidationContext()
        self.assertFalse(ctx.strict_mode)
        self.assertTrue(ctx.fail_fast)
        self.assertFalse(ctx.auto_sanitize)
        self.assertFalse(ctx.log_violations)
    
    def test_context_custom(self):
        """Test custom context configuration."""
        ctx = ValidationContext(
            strict_mode=True,
            fail_fast=False,
            auto_sanitize=True,
            log_violations=True
        )
        self.assertTrue(ctx.strict_mode)
        self.assertFalse(ctx.fail_fast)
        self.assertTrue(ctx.auto_sanitize)
        self.assertTrue(ctx.log_violations)


if __name__ == '__main__':
    unittest.main(verbosity=2)
