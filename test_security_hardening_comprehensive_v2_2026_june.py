"""
Test Suite for Security Hardening Comprehensive Module v2
Dimension B: Security Hardening - ADD-ONLY implementation

All tests verify the security hardening utilities work correctly.
No existing production code is modified or tested - only new features.
"""

import unittest
import time
import threading
import sys
import os

# Add neural_shield to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from security_hardening_comprehensive_v2_2026_june import (
    SecurityLevel,
    SecurityConfig,
    SecureMemory,
    ConstantTime,
    InputValidationResult,
    InputValidationWrapper,
    RateLimiter,
    CircuitBreakerState,
    CircuitBreaker,
    SecurityAuditor,
    secure_compare,
    secure_zeroize,
    validate_and_sanitize,
    check_rate_limit,
)


class TestSecureMemory(unittest.TestCase):
    """Test secure memory zeroization utilities."""
    
    def test_bytearray_zeroization(self):
        """Test that bytearrays are properly zeroized."""
        data = bytearray(b'sensitive data 12345')
        original = bytes(data)
        
        SecureMemory.secure_zeroize(data)
        
        # After zeroization, all bytes should be 0
        self.assertEqual(len(data), len(original))
        self.assertTrue(all(b == 0 for b in data))
    
    def test_multi_pass_wipe(self):
        """Test multi-pass bytearray wiping."""
        data = bytearray(b'secret key material here')
        original_hash = hash(bytes(data))
        
        SecureMemory.secure_wipe_bytearray(data, passes=5)
        
        # Data should be wiped
        self.assertNotEqual(hash(bytes(data)), original_hash)
        # Should be all zeros after final pass
        self.assertTrue(all(b == 0 for b in data))
    
    def test_list_zeroization(self):
        """Test list zeroization."""
        data = ['secret', 'data', 'here']
        
        SecureMemory.secure_zeroize(data)
        
        self.assertEqual(len(data), 0)
    
    def test_dict_zeroization(self):
        """Test dictionary zeroization."""
        data = {'key': 'secret', 'value': 'data'}
        
        SecureMemory.secure_zeroize(data)
        
        self.assertEqual(len(data), 0)
    
    def test_create_sensitive_buffer(self):
        """Test creating sensitive buffer."""
        buffer = SecureMemory.create_sensitive_buffer(32)
        
        self.assertEqual(len(buffer), 32)
        self.assertIsInstance(buffer, bytearray)
        self.assertTrue(all(b == 0 for b in buffer))
    
    def test_copy_to_sensitive(self):
        """Test copying to mutable bytearray."""
        source = b'immutable secret'
        mutable = SecureMemory.copy_to_sensitive(source)
        
        self.assertEqual(bytes(mutable), source)
        self.assertIsInstance(mutable, bytearray)
        
        # Can modify it
        mutable[0] = 0
        self.assertNotEqual(bytes(mutable), source)


class TestConstantTime(unittest.TestCase):
    """Test constant-time comparison utilities."""
    
    def test_compare_equal_same(self):
        """Test constant-time compare with equal values."""
        a = b'test data 123'
        b = b'test data 123'
        
        self.assertTrue(ConstantTime.compare_equal(a, b))
    
    def test_compare_equal_different(self):
        """Test constant-time compare with different values."""
        a = b'test data 123'
        b = b'test data 456'
        
        self.assertFalse(ConstantTime.compare_equal(a, b))
    
    def test_compare_strings_same(self):
        """Test constant-time string comparison."""
        a = "hello world"
        b = "hello world"
        
        self.assertTrue(ConstantTime.compare_strings_constant_time(a, b))
    
    def test_compare_strings_different_length(self):
        """Test constant-time string comparison with different lengths."""
        a = "short"
        b = "much longer string"
        
        self.assertFalse(ConstantTime.compare_strings_constant_time(a, b))
    
    def test_compare_strings_different_content(self):
        """Test constant-time string comparison with different content."""
        a = "hello world"
        b = "hello there"
        
        self.assertFalse(ConstantTime.compare_strings_constant_time(a, b))
    
    def test_mac_verification(self):
        """Test constant-time MAC verification."""
        key = b'secret key 12345'
        data = b'message to authenticate'
        
        import hmac
        import hashlib
        expected = hmac.new(key, data, 'sha256').digest()
        
        self.assertTrue(
            ConstantTime.verify_mac_constant_time(key, data, expected, 'sha256')
        )
    
    def test_mac_verification_wrong(self):
        """Test constant-time MAC verification with wrong MAC."""
        key = b'secret key 12345'
        data = b'message to authenticate'
        wrong_mac = b'0' * 32
        
        self.assertFalse(
            ConstantTime.verify_mac_constant_time(key, data, wrong_mac, 'sha256')
        )
    
    def test_constant_time_pad(self):
        """Test constant-time padding."""
        data = b'test'
        padded = ConstantTime.length_constant_time_pad(data, 16)
        
        self.assertEqual(len(padded), 16)
        self.assertTrue(padded.startswith(data))
    
    def test_convenience_secure_compare(self):
        """Test convenience secure_compare function."""
        self.assertTrue(secure_compare(b'abc', b'abc'))
        self.assertFalse(secure_compare(b'abc', b'def'))


class TestInputValidationWrapper(unittest.TestCase):
    """Test input validation and sanitization."""
    
    def setUp(self):
        self.validator = InputValidationWrapper()
    
    def test_valid_input(self):
        """Test validation of normal input."""
        result = self.validator.validate_input("Hello, this is normal text.")
        
        self.assertEqual(result.status, InputValidationResult.VALID)
        self.assertEqual(len(result.issues_found), 0)
    
    def test_xss_detection(self):
        """Test XSS pattern detection."""
        result = self.validator.validate_input('<script>alert("xss")</script>')
        
        self.assertEqual(result.status, InputValidationResult.SUSPICIOUS)
        self.assertGreater(len(result.issues_found), 0)
    
    def test_sql_injection_detection(self):
        """Test SQL injection pattern detection."""
        result = self.validator.validate_input("' OR 1=1 --")
        
        self.assertEqual(result.status, InputValidationResult.SUSPICIOUS)
    
    def test_path_traversal_detection(self):
        """Test path traversal detection."""
        result = self.validator.validate_input("../../../etc/passwd")
        
        self.assertEqual(result.status, InputValidationResult.SUSPICIOUS)
    
    def test_sanitize_removes_scripts(self):
        """Test sanitization removes script tags."""
        input_str = 'Hello <script>bad()</script> World'
        sanitized = self.validator.sanitize_input(input_str)
        
        self.assertNotIn('<script>', sanitized)
        self.assertIn('[SANITIZED]', sanitized)
    
    def test_sanitize_removes_control_chars(self):
        """Test sanitization removes control characters."""
        input_str = 'Normal\x00text\x01with\x02controls'
        sanitized = self.validator.sanitize_input(input_str)
        
        # No null bytes should remain
        self.assertNotIn('\x00', sanitized)
    
    def test_validate_and_sanitize_convenience(self):
        """Test validate_and_sanitize convenience function."""
        # Safe input
        is_safe, output = validate_and_sanitize("Normal text")
        self.assertTrue(is_safe)
        self.assertEqual(output, "Normal text")
        
        # Unsafe input
        is_safe, output = validate_and_sanitize("<script>evil</script>")
        self.assertFalse(is_safe)
        self.assertIn('[SANITIZED]', output)
    
    def test_secure_decorator(self):
        """Test the secure decorator wraps functions."""
        @self.validator.secure_decorator
        def test_func(text):
            return f"processed: {text}"
        
        # Should work normally
        result = test_func("test input")
        self.assertEqual(result, "processed: test input")


class TestRateLimiter(unittest.TestCase):
    """Test rate limiter for DoS protection."""
    
    def test_initial_tokens(self):
        """Test rate limiter starts with full burst."""
        limiter = RateLimiter(max_rate=10, burst_size=10)
        
        self.assertEqual(limiter.get_current_tokens(), 10)
    
    def test_try_acquire_success(self):
        """Test successful token acquisition."""
        limiter = RateLimiter(max_rate=100, burst_size=10)
        
        for _ in range(10):
            self.assertTrue(limiter.try_acquire())
        
        # 11th should fail
        self.assertFalse(limiter.try_acquire())
    
    def test_token_refill(self):
        """Test tokens refill over time."""
        limiter = RateLimiter(max_rate=100, per_seconds=1.0, burst_size=10)
        
        # Use all tokens
        for _ in range(10):
            limiter.try_acquire()
        
        self.assertFalse(limiter.try_acquire())
        
        # Wait for refill
        time.sleep(0.1)
        
        # Should have some tokens back
        tokens = limiter.get_current_tokens()
        self.assertGreater(tokens, 0)
    
    def test_wait_for_token(self):
        """Test waiting for tokens."""
        limiter = RateLimiter(max_rate=100, burst_size=1)
        
        # Use the token
        self.assertTrue(limiter.try_acquire())
        
        # Wait for another
        success = limiter.wait_for_token(timeout=0.5)
        self.assertTrue(success)
    
    def test_check_rate_limit_convenience(self):
        """Test check_rate_limit convenience function."""
        # Should work (global limiter)
        result = check_rate_limit()
        self.assertIsInstance(result, bool)


class TestCircuitBreaker(unittest.TestCase):
    """Test circuit breaker pattern."""
    
    def test_initial_state_closed(self):
        """Test circuit breaker starts closed."""
        breaker = CircuitBreaker(failure_threshold=5)
        
        self.assertEqual(breaker.get_state(), CircuitBreakerState.CLOSED)
    
    def test_can_execute_when_closed(self):
        """Test execution allowed when closed."""
        breaker = CircuitBreaker()
        
        self.assertTrue(breaker.can_execute())
    
    def test_transitions_to_open_after_failures(self):
        """Test circuit breaker opens after threshold failures."""
        breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)
        
        # Record 3 failures
        for _ in range(3):
            breaker.record_failure()
        
        self.assertEqual(breaker.get_state(), CircuitBreakerState.OPEN)
        self.assertFalse(breaker.can_execute())
    
    def test_success_resets_failure_count(self):
        """Test success resets failure counter."""
        breaker = CircuitBreaker(failure_threshold=5)
        
        # Record 2 failures
        breaker.record_failure()
        breaker.record_failure()
        
        # Success should reset
        breaker.record_success()
        
        # 4 more failures should NOT trigger open yet
        for _ in range(4):
            breaker.record_failure()
        
        self.assertEqual(breaker.get_state(), CircuitBreakerState.CLOSED)
    
    def test_half_open_recovery(self):
        """Test half-open state recovery."""
        breaker = CircuitBreaker(
            failure_threshold=2,
            recovery_timeout=0.1,
            half_open_max_calls=2
        )
        
        # Trigger open
        breaker.record_failure()
        breaker.record_failure()
        self.assertEqual(breaker.get_state(), CircuitBreakerState.OPEN)
        
        # Wait for timeout
        time.sleep(0.15)
        
        # Should be half-open now
        self.assertEqual(breaker.get_state(), CircuitBreakerState.HALF_OPEN)
        
        # Should allow limited calls
        self.assertTrue(breaker.can_execute())
        self.assertTrue(breaker.can_execute())
        
        # Success should close it
        breaker.record_success()
        self.assertEqual(breaker.get_state(), CircuitBreakerState.CLOSED)
    
    def test_half_open_failure_goes_back_to_open(self):
        """Test failure in half-open goes back to open."""
        breaker = CircuitBreaker(
            failure_threshold=2,
            recovery_timeout=0.1,
            half_open_max_calls=1
        )
        
        # Trigger open
        breaker.record_failure()
        breaker.record_failure()
        
        # Wait for half-open
        time.sleep(0.15)
        
        # Must call can_execute first to enter half-open state properly
        self.assertTrue(breaker.can_execute())
        
        # Failure in half-open
        breaker.record_failure()
        
        self.assertEqual(breaker.get_state(), CircuitBreakerState.OPEN)


class TestSecurityAuditor(unittest.TestCase):
    """Test security event auditing."""
    
    def test_log_event(self):
        """Test logging security events."""
        auditor = SecurityAuditor(max_events=100)
        
        auditor.log_security_event(
            event_type='validation_failure',
            severity='warning',
            details={'input': 'test', 'issues': ['xss']},
            source='test'
        )
        
        stats = auditor.get_event_statistics()
        self.assertEqual(stats['total_events_logged'], 1)
        self.assertEqual(stats['event_type_counts']['validation_failure'], 1)
    
    def test_get_recent_events(self):
        """Test retrieving recent events."""
        auditor = SecurityAuditor()
        
        for i in range(5):
            auditor.log_security_event(
                event_type=f'event_{i}',
                severity='info',
                details={'index': i}
            )
        
        events = auditor.get_recent_events(limit=3)
        self.assertEqual(len(events), 3)
        # Most recent first
        self.assertEqual(events[0]['event_type'], 'event_4')
    
    def test_filter_by_event_type(self):
        """Test filtering events by type."""
        auditor = SecurityAuditor()
        
        auditor.log_security_event('type_a', 'info', {})
        auditor.log_security_event('type_b', 'info', {})
        auditor.log_security_event('type_a', 'warning', {})
        
        events = auditor.get_recent_events(event_type='type_a')
        self.assertEqual(len(events), 2)
    
    def test_buffer_capacity(self):
        """Test event buffer capacity limit."""
        auditor = SecurityAuditor(max_events=10)
        
        for i in range(20):
            auditor.log_security_event(f'event_{i}', 'info', {})
        
        stats = auditor.get_event_statistics()
        # Should only keep last 10
        self.assertEqual(stats['total_events_logged'], 10)


class TestSecurityConfig(unittest.TestCase):
    """Test security configuration."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = SecurityConfig()
        
        self.assertEqual(config.security_level, SecurityLevel.STANDARD)
        self.assertTrue(config.enable_zeroization)
        self.assertTrue(config.enable_constant_time)
        self.assertEqual(config.zeroization_passes, 3)
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = SecurityConfig(
            security_level=SecurityLevel.MAXIMUM,
            max_requests_per_second=50,
            circuit_breaker_threshold=10
        )
        
        self.assertEqual(config.security_level, SecurityLevel.MAXIMUM)
        self.assertEqual(config.max_requests_per_second, 50)
        self.assertEqual(config.circuit_breaker_threshold, 10)


class TestConvenienceFunctions(unittest.TestCase):
    """Test global convenience functions."""
    
    def test_secure_zeroize_convenience(self):
        """Test secure_zeroize convenience function."""
        data = bytearray(b'test')
        secure_zeroize(data)
        self.assertTrue(all(b == 0 for b in data))


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of security utilities."""
    
    def test_rate_limiter_thread_safety(self):
        """Test rate limiter works with multiple threads."""
        limiter = RateLimiter(max_rate=1000, burst_size=100)
        results = []
        
        def worker():
            for _ in range(10):
                results.append(limiter.try_acquire())
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # All should have succeeded
        self.assertEqual(len(results), 50)
        self.assertTrue(all(results))
    
    def test_auditor_thread_safety(self):
        """Test auditor works with multiple threads."""
        auditor = SecurityAuditor()
        
        def worker():
            for i in range(10):
                auditor.log_security_event('test', 'info', {'thread': 'worker'})
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        stats = auditor.get_event_statistics()
        self.assertEqual(stats['total_events_logged'], 50)


if __name__ == '__main__':
    unittest.main(verbosity=2)
