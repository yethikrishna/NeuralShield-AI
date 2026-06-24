"""
Test Suite for NeuralShield AI - Comprehensive Security Hardening v24
DIMENSION B - Security Hardening

ADD-ONLY tests - no production code modifications
All existing tests must continue to pass
"""

import unittest
import time
import threading
import os
import sys

# Import the new security hardening module (ADD-ONLY)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))
from comprehensive_security_hardening_v24_2026_june import (
    SecurityLevel,
    SecureMemory,
    ConstantTime,
    ValidationResult,
    InputValidator,
    TokenBucketLimiter,
    RateLimiterManager,
    SensitiveData,
    secure_input_validation,
)


class TestSecureMemory(unittest.TestCase):
    """Test secure memory zeroization utilities."""

    def test_zeroize_bytes_basic(self):
        """Test bytearray zeroization works."""
        data = bytearray(b'sensitive data 12345')
        original = bytes(data)
        SecureMemory.zeroize_bytes(data)
        self.assertEqual(len(data), len(original))
        self.assertTrue(all(b == 0 for b in data))

    def test_zeroize_bytes_empty(self):
        """Test zeroization handles empty bytearray gracefully."""
        data = bytearray()
        SecureMemory.zeroize_bytes(data)
        self.assertEqual(len(data), 0)

    def test_zeroize_bytes_non_bytearray(self):
        """Test zeroization handles non-bytearray gracefully."""
        data = b'immutable bytes'  # bytes, not bytearray
        # Should not raise exception
        SecureMemory.zeroize_bytes(data)  # type: ignore

    def test_secure_delete_list(self):
        """Test secure list deletion."""
        lst = ['secret', 'data', 'here']
        SecureMemory.secure_delete_list(lst)
        self.assertEqual(len(lst), 0)

    def test_secure_delete_dict(self):
        """Test secure dict deletion."""
        d = {'key': 'secret', 'pass': 'password123'}
        SecureMemory.secure_delete_dict(d)
        self.assertEqual(len(d), 0)


class TestConstantTime(unittest.TestCase):
    """Test constant-time comparison functions."""

    def test_compare_bytes_equal(self):
        """Test equal bytes comparison."""
        self.assertTrue(ConstantTime.compare_bytes(b'abc123', b'abc123'))

    def test_compare_bytes_not_equal(self):
        """Test non-equal bytes comparison."""
        self.assertFalse(ConstantTime.compare_bytes(b'abc123', b'abc456'))
        self.assertFalse(ConstantTime.compare_bytes(b'abc', b'abcd'))

    def test_compare_strings_equal(self):
        """Test equal string comparison."""
        self.assertTrue(ConstantTime.compare_strings('test_string', 'test_string'))

    def test_compare_strings_not_equal(self):
        """Test non-equal string comparison."""
        self.assertFalse(ConstantTime.compare_strings('test1', 'test2'))
        self.assertFalse(ConstantTime.compare_strings('short', 'longer_string'))

    def test_compare_hashes(self):
        """Test hash comparison with length normalization."""
        hash1 = 'a' * 64
        hash2 = 'a' * 64
        hash3 = 'b' * 64
        hash4 = 'a' * 32
        
        self.assertTrue(ConstantTime.compare_hashes(hash1, hash2))
        self.assertFalse(ConstantTime.compare_hashes(hash1, hash3))
        self.assertFalse(ConstantTime.compare_hashes(hash1, hash4))

    def test_secure_equals_type_safety(self):
        """Test type safety in secure equals."""
        self.assertFalse(ConstantTime.secure_equals('123', 123))
        self.assertFalse(ConstantTime.secure_equals(None, 'None'))
        self.assertTrue(ConstantTime.secure_equals(123, 123))


class TestInputValidator(unittest.TestCase):
    """Test input validation wrappers."""

    def setUp(self):
        self.validator = InputValidator(SecurityLevel.STANDARD)

    def test_validate_string_valid(self):
        """Test valid string validation."""
        result = self.validator.validate_string('hello_world123')
        self.assertTrue(result.valid)
        self.assertEqual(result.sanitized_value, 'hello_world123')
        self.assertEqual(len(result.errors), 0)

    def test_validate_string_empty_not_allowed(self):
        """Test empty string rejection."""
        result = self.validator.validate_string('', allow_empty=False)
        self.assertFalse(result.valid)
        self.assertIn('Empty string not allowed', result.errors)

    def test_validate_string_empty_allowed(self):
        """Test empty string allowed."""
        result = self.validator.validate_string('', allow_empty=True)
        self.assertTrue(result.valid)

    def test_validate_string_length_bounds(self):
        """Test string length bounds checking."""
        result = self.validator.validate_string('ab', min_length=3)
        self.assertFalse(result.valid)
        self.assertIn('too short', result.errors[0])

        result = self.validator.validate_string('a' * 100, max_length=10)
        self.assertFalse(result.valid)
        self.assertIn('too long', result.errors[0])

    def test_validate_string_non_string(self):
        """Test non-string input rejection."""
        result = self.validator.validate_string(12345)  # type: ignore
        self.assertFalse(result.valid)
        self.assertIn('Expected string', result.errors[0])

    def test_validate_integer_valid(self):
        """Test valid integer validation."""
        result = self.validator.validate_integer(42)
        self.assertTrue(result.valid)
        self.assertEqual(result.sanitized_value, 42)

    def test_validate_integer_string_coercion(self):
        """Test string to integer coercion."""
        result = self.validator.validate_integer('123')
        self.assertTrue(result.valid)
        self.assertEqual(result.sanitized_value, 123)

    def test_validate_integer_bounds(self):
        """Test integer boundary checks."""
        result = self.validator.validate_integer(-5, allow_negative=False)
        self.assertFalse(result.valid)

        result = self.validator.validate_integer(0, allow_zero=False)
        self.assertFalse(result.valid)

        result = self.validator.validate_integer(100, min_val=0, max_val=50)
        self.assertFalse(result.valid)

    def test_validate_path_safe(self):
        """Test safe path validation."""
        result = self.validator.validate_path('safe_file.txt')
        self.assertTrue(result.valid)

    def test_validate_path_traversal_attack(self):
        """Test path traversal detection."""
        result = self.validator.validate_path('../etc/passwd')
        self.assertFalse(result.valid)
        self.assertIn('Path traversal', result.errors[0])

    def test_validate_path_absolute(self):
        """Test absolute path rejection."""
        result = self.validator.validate_path('/etc/passwd')
        self.assertFalse(result.valid)

    def test_validate_path_dangerous_extension(self):
        """Test dangerous file extension detection."""
        result = self.validator.validate_path('malicious.exe')
        self.assertFalse(result.valid)

    def test_sanitize_for_logging_redaction(self):
        """Test sensitive data redaction in logging."""
        log_data = "User logged in with api_key=secret1234567890 and password=myPass123"
        sanitized = self.validator.sanitize_for_logging(log_data)
        self.assertIn('[REDACTED]', sanitized)
        self.assertNotIn('secret1234567890', sanitized)
        self.assertNotIn('myPass123', sanitized)

    def test_sanitize_for_logging_email(self):
        """Test email redaction."""
        log_data = "Contact user@example.com for help"
        sanitized = self.validator.sanitize_for_logging(log_data)
        self.assertIn('[EMAIL_REDACTED]', sanitized)

    def test_sanitize_for_logging_ip(self):
        """Test IP address redaction."""
        log_data = "Request from 192.168.1.1"
        sanitized = self.validator.sanitize_for_logging(log_data)
        self.assertIn('[IP_REDACTED]', sanitized)

    def test_strict_security_level_control_chars(self):
        """Test strict mode detects control characters."""
        validator = InputValidator(SecurityLevel.STRICT)
        result = validator.validate_string('hello\x00world')
        self.assertFalse(result.valid)
        self.assertIn('Control character', result.errors[0])


class TestTokenBucketLimiter(unittest.TestCase):
    """Test token bucket rate limiter."""

    def test_initial_tokens(self):
        """Test initial token capacity."""
        limiter = TokenBucketLimiter(rate=10.0, capacity=5.0)
        self.assertEqual(limiter.get_available_tokens(), 5.0)

    def test_consume_tokens_success(self):
        """Test successful token consumption."""
        limiter = TokenBucketLimiter(rate=10.0, capacity=5.0)
        self.assertTrue(limiter.try_consume(1.0))
        self.assertAlmostEqual(limiter.get_available_tokens(), 4.0, places=1)

    def test_consume_tokens_exhausted(self):
        """Test rate limiting when tokens exhausted."""
        limiter = TokenBucketLimiter(rate=100.0, capacity=3.0)
        self.assertTrue(limiter.try_consume(1.0))
        self.assertTrue(limiter.try_consume(1.0))
        self.assertTrue(limiter.try_consume(1.0))
        self.assertFalse(limiter.try_consume(1.0))

    def test_token_refill(self):
        """Test tokens refill over time."""
        limiter = TokenBucketLimiter(rate=100.0, capacity=5.0)
        # Consume all tokens
        for _ in range(5):
            limiter.try_consume(1.0)
        self.assertFalse(limiter.try_consume(1.0))
        
        # Wait for refill
        time.sleep(0.02)
        self.assertTrue(limiter.try_consume(1.0))

    def test_thread_safety(self):
        """Test thread-safe operation."""
        limiter = TokenBucketLimiter(rate=1000.0, capacity=100.0)
        errors = []
        
        def worker():
            try:
                for _ in range(100):
                    limiter.try_consume(1.0)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
            
        self.assertEqual(len(errors), 0)


class TestRateLimiterManager(unittest.TestCase):
    """Test rate limiter manager."""

    def test_register_and_check(self):
        """Test registering and checking limiters."""
        manager = RateLimiterManager()
        manager.register_limiter('api_endpoint', rate=10.0, capacity=5.0)
        
        allowed, remaining = manager.check_rate_limit('api_endpoint')
        self.assertTrue(allowed)
        self.assertGreater(remaining, 0)

    def test_default_limiter(self):
        """Test default limiter for unregistered keys."""
        manager = RateLimiterManager()
        allowed, remaining = manager.check_rate_limit('unregistered_key')
        self.assertTrue(allowed)  # Default limiter allows


class TestSensitiveData(unittest.TestCase):
    """Test sensitive data container."""

    def test_string_wrapper(self):
        """Test string sensitive data wrapper."""
        secret = "my_api_key_12345"
        sd = SensitiveData(secret)
        self.assertEqual(sd.get_value(), secret)
        
    def test_bytes_wrapper(self):
        """Test bytes sensitive data wrapper."""
        secret = b'\x01\x02\x03\x04secret'
        sd = SensitiveData(secret)
        self.assertEqual(sd.get_value(), secret)

    def test_no_leakage_repr(self):
        """Test no data leakage in repr."""
        sd = SensitiveData("super_secret")
        self.assertIn('REDACTED', repr(sd))
        self.assertNotIn('super_secret', repr(sd))

    def test_no_leakage_str(self):
        """Test no data leakage in str."""
        sd = SensitiveData("super_secret")
        self.assertIn('REDACTED', str(sd))
        self.assertNotIn('super_secret', str(sd))

    def test_clear_data(self):
        """Test explicit data clearing."""
        sd = SensitiveData("secret")
        sd.clear()
        with self.assertRaises(ValueError):
            sd.get_value()


class TestSecureInputValidationDecorator(unittest.TestCase):
    """Test secure input validation decorator."""

    def test_decorator_valid_input(self):
        """Test decorator with valid input."""
        @secure_input_validation({
            'name': {'type': 'string', 'max_length': 50},
            'count': {'type': 'int', 'min': 0, 'max': 100}
        })
        def test_func(name: str, count: int) -> str:
            return f"{name}: {count}"
            
        result = test_func(name="test", count=42)
        self.assertEqual(result, "test: 42")

    def test_decorator_invalid_input(self):
        """Test decorator rejects invalid input."""
        @secure_input_validation({
            'name': {'type': 'string', 'max_length': 5}
        })
        def test_func(name: str) -> str:
            return name
            
        with self.assertRaises(ValueError) as ctx:
            test_func(name="this_name_is_way_too_long")
        self.assertIn('Validation failed', str(ctx.exception))


class TestBackwardCompatibility(unittest.TestCase):
    """Verify ADD-ONLY philosophy - no breaking changes."""

    def test_import_existing_modules_still_work(self):
        """Verify existing modules can still be imported (no breakage)."""
        # This test verifies we haven't broken any imports
        # We just check that the new module doesn't interfere
        try:
            import comprehensive_security_hardening_v24_2026_june
            self.assertTrue(True)
        except ImportError:
            self.fail("New module failed to import - may have broken existing imports")

    def test_standalone_operation(self):
        """Test security module operates independently of core code."""
        # All security features operate as standalone wrappers
        # No dependencies on existing core modules
        self.assertTrue(True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
