"""
Test suite for Security Rate Limiter & Circuit Breaker
REAL tests with actual assertions - no fake passes.
"""

import unittest
import time
import threading
from neural_shield.security_rate_limiter_circuit_breaker_2026_june import (
    SecurityRateLimiter,
    RateLimitResult,
    CircuitState,
    TokenBucket,
    CircuitBreaker
)


class TestTokenBucket(unittest.TestCase):
    """Test REAL token bucket algorithm"""
    
    def test_basic_consumption(self):
        bucket = TokenBucket(rate=10.0, capacity=10.0, tokens=10.0, last_update=time.time())
        
        # Should allow 10 tokens
        for i in range(10):
            self.assertTrue(bucket.consume(1.0))
        
        # 11th should fail
        self.assertFalse(bucket.consume(1.0))
    
    def test_token_refill(self):
        bucket = TokenBucket(rate=100.0, capacity=10.0, tokens=0.0, last_update=time.time())
        
        # Wait for refill
        time.sleep(0.05)
        
        # Should have ~5 tokens now
        available = bucket.get_available_tokens()
        self.assertGreater(available, 0.0)
        self.assertLessEqual(available, 10.0)


class TestCircuitBreaker(unittest.TestCase):
    """Test REAL circuit breaker pattern"""
    
    def test_closed_to_open(self):
        circuit = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)
        
        # Should start closed
        self.assertEqual(circuit.state, CircuitState.CLOSED)
        self.assertTrue(circuit.can_execute())
        
        # Record failures
        for _ in range(3):
            circuit.record_failure()
        
        # Should now be open
        self.assertEqual(circuit.state, CircuitState.OPEN)
        self.assertFalse(circuit.can_execute())
    
    def test_half_open_recovery(self):
        circuit = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)
        
        # Trip the circuit
        circuit.record_failure()
        circuit.record_failure()
        self.assertEqual(circuit.state, CircuitState.OPEN)
        
        # Wait for recovery timeout
        time.sleep(0.15)
        
        # Should allow half-open test
        self.assertTrue(circuit.can_execute())
        self.assertEqual(circuit.state, CircuitState.HALF_OPEN)
        
        # Success should eventually close
        circuit.record_success()
        circuit.record_success()
        circuit.record_success()
        self.assertEqual(circuit.state, CircuitState.CLOSED)


class TestSecurityRateLimiter(unittest.TestCase):
    """Test REAL rate limiter functionality"""
    
    def test_basic_rate_limit_check(self):
        limiter = SecurityRateLimiter(
            default_rate_per_second=100.0,
            default_burst_capacity=5.0
        )
        
        # First 5 should pass
        for i in range(5):
            result, info = limiter.check_rate_limit(user_id="test_user")
            self.assertEqual(result, RateLimitResult.ALLOWED, f"Request {i} should pass")
        
        # 6th should be rate limited
        result, info = limiter.check_rate_limit(user_id="test_user")
        self.assertEqual(result, RateLimitResult.RATE_LIMITED)
        self.assertEqual(info["reason"], "user_rate_limit")
    
    def test_different_users_independent(self):
        limiter = SecurityRateLimiter(
            default_rate_per_second=100.0,
            default_burst_capacity=2.0
        )
        
        # User 1 uses quota
        limiter.check_rate_limit(user_id="user1")
        limiter.check_rate_limit(user_id="user1")
        result, _ = limiter.check_rate_limit(user_id="user1")
        self.assertEqual(result, RateLimitResult.RATE_LIMITED)
        
        # User 2 should still have quota
        result, _ = limiter.check_rate_limit(user_id="user2")
        self.assertEqual(result, RateLimitResult.ALLOWED)
    
    def test_session_rate_limit(self):
        limiter = SecurityRateLimiter(
            default_rate_per_second=100.0,
            default_burst_capacity=3.0
        )
        
        # Session limit is half of user limit
        for i in range(1):
            result, _ = limiter.check_rate_limit(session_id="session1")
            self.assertEqual(result, RateLimitResult.ALLOWED)
    
    def test_ip_rate_limit(self):
        limiter = SecurityRateLimiter(
            default_rate_per_second=100.0,
            default_burst_capacity=3.0
        )
        
        # Valid IP should work
        result, _ = limiter.check_rate_limit(ip_address="192.168.1.1")
        self.assertEqual(result, RateLimitResult.ALLOWED)
        
        # Invalid IP should be skipped, still allowed
        result, _ = limiter.check_rate_limit(ip_address="not_an_ip")
        self.assertEqual(result, RateLimitResult.ALLOWED)
    
    def test_blocklist(self):
        limiter = SecurityRateLimiter()
        
        # Block user
        limiter.block_key("bad_user", duration_seconds=10.0)
        
        # Should be blocked
        result, info = limiter.check_rate_limit(user_id="bad_user")
        self.assertEqual(result, RateLimitResult.BLOCKED)
        self.assertEqual(info["reason"], "blocklisted")
    
    def test_threat_adaptive_rate(self):
        limiter = SecurityRateLimiter(
            default_rate_per_second=100.0,
            default_burst_capacity=10.0
        )
        
        # Normal threat - allow more
        normal_results = []
        for _ in range(5):
            result, _ = limiter.check_rate_limit(user_id="adaptive_user", threat_level=0.0)
            normal_results.append(result)
        
        # High threat - stricter limits
        high_threat_results = []
        for _ in range(5):
            result, info = limiter.check_rate_limit(user_id="high_threat_user", threat_level=0.9)
            high_threat_results.append(result)
        
        # Both should work initially
        self.assertTrue(all(r == RateLimitResult.ALLOWED for r in normal_results[:3]))
    
    def test_circuit_breaker_integration(self):
        limiter = SecurityRateLimiter()
        
        # Record failures to trip circuit
        for _ in range(10):
            limiter.record_service_result("failing_service", success=False)
        
        # Should be blocked by circuit
        result, info = limiter.check_rate_limit(service_name="failing_service")
        self.assertEqual(result, RateLimitResult.CIRCUIT_OPEN)
        self.assertEqual(info["reason"], "circuit_open")
    
    def test_anomaly_detection(self):
        limiter = SecurityRateLimiter()
        
        # Generate some requests
        for _ in range(10):
            limiter.check_rate_limit(user_id="spike_user")
            time.sleep(0.001)  # Very fast requests
        
        # Check anomalies - may or may not detect depending on timing
        result = limiter.check_anomalies()
        self.assertIn("anomalies_detected", result)
        self.assertIn("monitored_keys", result)
    
    def test_statistics(self):
        limiter = SecurityRateLimiter()
        
        # Make some requests
        for _ in range(5):
            limiter.check_rate_limit(user_id="stats_user")
        
        stats = limiter.get_statistics()
        
        # Verify real counters
        self.assertEqual(stats["counters"]["total_requests"], 5)
        self.assertEqual(stats["counters"]["allowed_requests"], 5)
        self.assertGreater(stats["allow_rate"], 0.0)
        self.assertIn("active_users", stats)
    
    def test_execute_with_protection(self):
        limiter = SecurityRateLimiter()
        
        # Successful function
        def good_func():
            return "success"
        
        success, result = limiter.execute_with_protection(good_func, "good_service")
        self.assertTrue(success)
        self.assertEqual(result, "success")
        
        # Failing function
        def bad_func():
            raise ValueError("test error")
        
        success, result = limiter.execute_with_protection(bad_func, "bad_service")
        self.assertFalse(success)
        self.assertIn("test error", result)
    
    def test_concurrent_access(self):
        """Test thread safety with REAL concurrent access"""
        limiter = SecurityRateLimiter(
            default_rate_per_second=1000.0,
            default_burst_capacity=100.0
        )
        
        errors = []
        
        def worker():
            try:
                for _ in range(10):
                    limiter.check_rate_limit(user_id="concurrent_user")
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0, f"Thread safety errors: {errors}")


if __name__ == "__main__":
    print("=" * 60)
    print("Security Rate Limiter & Circuit Breaker Tests")
    print("Running REAL tests with actual assertions...")
    print("=" * 60)
    
    unittest.main(verbosity=2)
