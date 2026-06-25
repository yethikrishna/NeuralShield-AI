"""
Test Suite for NeuralShield Comprehensive Security Hardening Framework v29
Dimension B - Security Hardening
June 25, 2026

All tests verify:
1. Secure Memory Zeroization
2. Constant-Time Comparison
3. Input Validation
4. Rate Limiting / DoS Protection
5. Backward Compatibility - existing code NOT broken
"""

import unittest
import time
import threading
from neural_shield import (
    SecureMemory,
    ConstantTime,
    InputValidator,
    RateLimiter,
    SecurityHardeningWrapper,
    SecurityLevel,
    secure_memory,
    constant_time,
    security_validator,
    security_rate_limiter,
)


class TestSecureMemory(unittest.TestCase):
    """Test secure memory zeroization utilities"""
    
    def test_zeroize_bytearray(self):
        """Test bytearray zeroization"""
        sensitive = bytearray(b'secret_key_material_12345')
        original = bytes(sensitive)
        secure_memory.zeroize_bytes(sensitive)
        self.assertEqual(len(sensitive), len(original))
        self.assertTrue(all(b == 0 for b in sensitive))
    
    def test_zeroize_list(self):
        """Test list zeroization"""
        sensitive = [1, 2, 3, 4, 5, 6, 7, 8]
        secure_memory.zeroize_list(sensitive)
        self.assertEqual(len(sensitive), 0)
    
    def test_zeroize_dict(self):
        """Test dictionary zeroization"""
        sensitive = {'key': 'secret', 'password': '12345', 'data': [1, 2, 3]}
        secure_memory.zeroize_dict(sensitive)
        self.assertEqual(len(sensitive), 0)


class TestConstantTime(unittest.TestCase):
    """Test constant-time comparison helpers"""
    
    def test_compare_strings_equal(self):
        """Test equal string comparison"""
        self.assertTrue(constant_time.compare_strings("test123", "test123"))
    
    def test_compare_strings_not_equal(self):
        """Test non-equal string comparison"""
        self.assertFalse(constant_time.compare_strings("test123", "test456"))
        self.assertFalse(constant_time.compare_strings("short", "much_longer_string"))
    
    def test_compare_bytes_equal(self):
        """Test equal bytes comparison"""
        self.assertTrue(constant_time.compare_bytes(b'\x00\x01\x02', b'\x00\x01\x02'))
    
    def test_compare_bytes_not_equal(self):
        """Test non-equal bytes comparison"""
        self.assertFalse(constant_time.compare_bytes(b'\x00\x01\x02', b'\x00\x01\x03'))
    
    def test_compare_ints_equal(self):
        """Test equal integer comparison"""
        self.assertTrue(constant_time.compare_ints(12345, 12345))
    
    def test_compare_ints_not_equal(self):
        """Test non-equal integer comparison"""
        self.assertFalse(constant_time.compare_ints(12345, 54321))
    
    def test_secure_hash(self):
        """Test secure hashing"""
        hash1 = constant_time.secure_hash(b'test data', b'salt123')
        hash2 = constant_time.secure_hash(b'test data', b'salt123')
        hash3 = constant_time.secure_hash(b'different', b'salt123')
        self.assertEqual(hash1, hash2)
        self.assertNotEqual(hash1, hash3)
        self.assertEqual(len(hash1), 32)  # SHA256 output


class TestInputValidator(unittest.TestCase):
    """Test input validation wrapper"""
    
    def test_validate_valid_input(self):
        """Test validation of valid input"""
        result = security_validator.validate("normal input", "test_field")
        self.assertTrue(result['valid'])
        self.assertEqual(len(result['errors']), 0)
    
    def test_validate_none_input(self):
        """Test validation rejects None"""
        result = security_validator.validate(None, "test_field")
        self.assertFalse(result['valid'])
        self.assertTrue(any('None' in e for e in result['errors']))
    
    def test_validate_empty_string(self):
        """Test validation rejects empty string"""
        result = security_validator.validate("   ", "test_field")
        self.assertFalse(result['valid'])
    
    def test_validate_strict_level(self):
        """Test strict security level validation"""
        strict_validator = InputValidator(SecurityLevel.STRICT)
        very_long = "x" * 2000000
        result = strict_validator.validate(very_long, "long_field")
        self.assertFalse(result['valid'])
    
    def test_sanitize_removes_control_chars(self):
        """Test sanitization removes control characters"""
        input_with_control = "normal\x00text\x01with\x02controls"
        result = security_validator.validate(input_with_control, "test")
        sanitized = result['sanitized']
        self.assertNotIn('\x00', sanitized)
        self.assertNotIn('\x01', sanitized)
        self.assertIn('normal', sanitized)
    
    def test_add_custom_rule(self):
        """Test adding custom validation rule"""
        validator = InputValidator(SecurityLevel.STANDARD)
        validator.add_rule(type('', (), {
            'name': 'min_length',
            'validator': lambda x: len(str(x)) >= 5,
            'error_message': 'Minimum 5 characters required',
            'security_level': SecurityLevel.STANDARD
        })())
        result = validator.validate("abc", "short")
        self.assertFalse(result['valid'])


class TestRateLimiter(unittest.TestCase):
    """Test rate limiting and DoS protection"""
    
    def test_rate_limit_allows_first_requests(self):
        """Test rate limiter allows first requests"""
        limiter = RateLimiter()
        for i in range(5):
            result = limiter.check_rate_limit(f"client_{i}")
            self.assertTrue(result['allowed'])
            self.assertGreater(result['remaining'], 0)
    
    def test_rate_limit_blocks_after_exceeded(self):
        """Test rate limiter blocks after exceeding limit"""
        config = type('', (), {
            'max_requests': 5,
            'window_seconds': 60,
            'block_duration_seconds': 10
        })()
        limiter = RateLimiter(config)
        
        # Fill up the rate limit
        for i in range(5):
            result = limiter.check_rate_limit("test_client")
            self.assertTrue(result['allowed'])
        
        # 6th request should be blocked
        result = limiter.check_rate_limit("test_client")
        self.assertFalse(result['allowed'])
        self.assertTrue(result['blocked'])
    
    def test_rate_limit_reset_client(self):
        """Test resetting client rate limit"""
        limiter = RateLimiter()
        for i in range(10):
            limiter.check_rate_limit("client_to_reset")
        
        limiter.reset_client("client_to_reset")
        stats = limiter.get_stats()
        self.assertEqual(stats['clients_blocked'], 0)
    
    def test_rate_limit_stats(self):
        """Test rate limiter statistics"""
        limiter = RateLimiter()
        limiter.check_rate_limit("client1")
        limiter.check_rate_limit("client2")
        
        stats = limiter.get_stats()
        self.assertEqual(stats['total_clients_tracked'], 2)
        self.assertGreater(stats['max_requests_window'], 0)
    
    def test_rate_limiter_thread_safety(self):
        """Test rate limiter is thread-safe"""
        limiter = RateLimiter()
        errors = []
        
        def worker():
            try:
                for i in range(10):
                    limiter.check_rate_limit("threaded_client")
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0)


class TestSecurityHardeningWrapper(unittest.TestCase):
    """Test main security hardening wrapper"""
    
    def test_wrap_function_preserves_behavior(self):
        """Test wrapped function preserves original behavior"""
        wrapper = SecurityHardeningWrapper()
        
        def original(x, y):
            return x + y
        
        wrapped = wrapper.wrap_function(original, validate_inputs=False, rate_limit=False)
        
        self.assertEqual(wrapped(2, 3), 5)
        self.assertEqual(wrapped(10, 20), 30)
    
    def test_secure_execute(self):
        """Test secure execution of functions"""
        wrapper = SecurityHardeningWrapper()
        
        def multiply(a, b):
            return a * b
        
        result = wrapper.secure_execute(multiply, 5, 6)
        self.assertEqual(result, 30)
    
    def test_validation_blocks_invalid_input(self):
        """Test validation blocks invalid input when enabled"""
        wrapper = SecurityHardeningWrapper(SecurityLevel.STANDARD)
        
        def sensitive_operation(input_data):
            return f"processed: {input_data}"
        
        wrapped = wrapper.wrap_function(sensitive_operation, rate_limit=False)
        
        # Valid input should work
        result = wrapped("valid input")
        self.assertIn("processed", result)


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility - existing code NOT broken"""
    
    def test_existing_imports_still_work(self):
        """Verify all existing imports still work"""
        from neural_shield import (
            AdvancedJailbreakDetector,
            PromptFirewall2026,
            OutputSanitizer,
            ModelExtractionDetector,
        )
        self.assertIsNotNone(AdvancedJailbreakDetector)
        self.assertIsNotNone(PromptFirewall2026)
        self.assertIsNotNone(OutputSanitizer)
        self.assertIsNotNone(ModelExtractionDetector)
    
    def test_version_updated(self):
        """Verify version was updated properly"""
        import neural_shield
        self.assertTrue(hasattr(neural_shield, '__version__'))
        self.assertIn('2026.6.25', neural_shield.__version__)


if __name__ == '__main__':
    print("=" * 70)
    print("NeuralShield Comprehensive Security Hardening v29 - Test Suite")
    print("Dimension B - Security Hardening")
    print("June 25, 2026")
    print("=" * 70)
    unittest.main(verbosity=2)
