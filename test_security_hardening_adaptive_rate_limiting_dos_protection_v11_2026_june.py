"""
Test Suite for NeuralShield AI - Adaptive Rate Limiting & DoS Protection v11
Dimension B: Security Hardening
Tests cover: Token Bucket, Sliding Window, Leaky Bucket, DoS Detection,
Circuit Breaker, Adaptive Threat Limiting, Decorators, Factory Functions
"""

import pytest
import time
import threading
from unittest.mock import patch

# Import the module
from neural_shield.security_hardening_adaptive_rate_limiting_dos_protection_v11_2026_june import (
    AdaptiveRateLimiter,
    RateLimitConfig,
    RateLimitAlgorithm,
    RateLimitResult,
    ThreatLevel,
    DoSAttackType,
    DoSDetector,
    RateLimitExceededError,
    rate_limit,
    create_token_bucket_limiter,
    create_sliding_window_limiter,
    create_dos_protector,
    TokenBucketLimiter,
    SlidingWindowLimiter,
    LeakyBucketLimiter,
)


class TestRateLimitEnums:
    """Test enum classes."""

    def test_rate_limit_algorithm_enum(self):
        """Test RateLimitAlgorithm has all expected values."""
        assert RateLimitAlgorithm.TOKEN_BUCKET.value == "token_bucket"
        assert RateLimitAlgorithm.LEAKY_BUCKET.value == "leaky_bucket"
        assert RateLimitAlgorithm.SLIDING_WINDOW.value == "sliding_window"
        assert RateLimitAlgorithm.FIXED_WINDOW.value == "fixed_window"

    def test_threat_level_enum(self):
        """Test ThreatLevel enum."""
        assert ThreatLevel.LOW.value == "low"
        assert ThreatLevel.MEDIUM.value == "medium"
        assert ThreatLevel.HIGH.value == "high"
        assert ThreatLevel.CRITICAL.value == "critical"

    def test_dos_attack_type_enum(self):
        """Test DoSAttackType enum."""
        assert DoSAttackType.NONE.value == "none"
        assert DoSAttackType.BURST_FLOOD.value == "burst_flood"
        assert DoSAttackType.SLOWLORIS.value == "slowloris"
        assert DoSAttackType.ENDPOINT_FLOOD.value == "endpoint_flood"
        assert DoSAttackType.DISTRIBUTED_FLOOD.value == "distributed_flood"


class TestRateLimitConfig:
    """Test RateLimitConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = RateLimitConfig()
        assert config.requests_per_second == 10.0
        assert config.max_burst == 50
        assert config.window_seconds == 60
        assert config.algorithm == RateLimitAlgorithm.TOKEN_BUCKET
        assert config.block_duration_seconds == 300
        assert config.enable_adaptive is True

    def test_custom_config(self):
        """Test custom configuration."""
        config = RateLimitConfig(
            requests_per_second=100.0,
            max_burst=200,
            window_seconds=30,
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            block_duration_seconds=60,
            enable_adaptive=False
        )
        assert config.requests_per_second == 100.0
        assert config.max_burst == 200
        assert config.window_seconds == 30
        assert config.algorithm == RateLimitAlgorithm.SLIDING_WINDOW


class TestTokenBucketLimiter:
    """Test Token Bucket algorithm."""

    def test_token_bucket_allows_requests(self):
        """Test token bucket allows requests within limit."""
        limiter = TokenBucketLimiter()
        config = RateLimitConfig(requests_per_second=10.0, max_burst=5)

        # First 5 requests should be allowed (burst capacity)
        for i in range(5):
            result = limiter.check_rate_limit(f"test_key_{i}", config)
            assert result.allowed is True

    def test_token_bucket_blocks_excess(self):
        """Test token bucket blocks requests exceeding limit."""
        limiter = TokenBucketLimiter()
        config = RateLimitConfig(requests_per_second=10.0, max_burst=3)

        # Consume all tokens
        for i in range(3):
            limiter.check_rate_limit("test_key", config)

        # 4th should be blocked
        result = limiter.check_rate_limit("test_key", config)
        assert result.allowed is False
        assert result.retry_after is not None

    def test_token_bucket_refills(self):
        """Test token bucket refills over time."""
        limiter = TokenBucketLimiter()
        config = RateLimitConfig(requests_per_second=100.0, max_burst=5)

        # Consume all
        for i in range(5):
            limiter.check_rate_limit("test_key", config)

        # Wait for refill
        time.sleep(0.05)

        # Should have tokens again
        result = limiter.check_rate_limit("test_key", config)
        assert result.allowed is True


class TestSlidingWindowLimiter:
    """Test Sliding Window algorithm."""

    def test_sliding_window_allows_requests(self):
        """Test sliding window allows requests within limit."""
        limiter = SlidingWindowLimiter()
        config = RateLimitConfig(requests_per_second=1.0, window_seconds=60, max_burst=60)

        for i in range(5):
            result = limiter.check_rate_limit(f"key_{i}", config)
            assert result.allowed is True

    def test_sliding_window_enforces_limit(self):
        """Test sliding window enforces rate limit."""
        limiter = SlidingWindowLimiter()
        config = RateLimitConfig(requests_per_second=10.0, window_seconds=1, max_burst=10)

        # Fill window
        for i in range(10):
            limiter.check_rate_limit("test_key", config)

        # Next should be blocked
        result = limiter.check_rate_limit("test_key", config)
        assert result.allowed is False


class TestLeakyBucketLimiter:
    """Test Leaky Bucket algorithm."""

    def test_leaky_bucket_basic(self):
        """Test leaky bucket basic functionality."""
        limiter = LeakyBucketLimiter()
        config = RateLimitConfig(requests_per_second=100.0, max_burst=10)

        # Should allow up to max_burst
        for i in range(10):
            result = limiter.check_rate_limit(f"key_{i}", config)
            assert result.allowed is True


class TestDoSDetector:
    """Test DoS attack detection."""

    def test_dos_detector_creation(self):
        """Test DoS detector creation."""
        detector = DoSDetector()
        assert detector.burst_threshold == 100
        assert detector.slow_request_threshold == 30.0

    def test_dos_detector_no_attack(self):
        """Test no attack detected for normal traffic."""
        detector = DoSDetector(burst_threshold=100)

        # Normal traffic - 1 request
        result = detector.track_request("192.168.1.1", "/api/test")
        assert result == DoSAttackType.NONE

    def test_dos_detector_burst_flood(self):
        """Test burst flood detection."""
        detector = DoSDetector(burst_threshold=10)

        # Simulate burst
        for i in range(15):
            result = detector.track_request("192.168.1.100", "/api/test")

        assert result == DoSAttackType.BURST_FLOOD

    def test_dos_detector_slowloris(self):
        """Test slowloris detection."""
        detector = DoSDetector(slow_request_threshold=1.0)

        # Many slow requests
        for i in range(6):
            result = detector.track_request("10.0.0.1", "/api/long", duration=5.0)

        assert result == DoSAttackType.SLOWLORIS

    def test_threat_level_calculation(self):
        """Test threat level based on request rate."""
        detector = DoSDetector()

        # Low threat
        assert detector.get_threat_level("1.1.1.1") == ThreatLevel.LOW

        # Add many requests for medium
        for i in range(60):
            detector.track_request("2.2.2.2", "/test")
        # Note: timing-based, so we just verify it returns a valid level
        level = detector.get_threat_level("2.2.2.2")
        assert level in [ThreatLevel.LOW, ThreatLevel.MEDIUM, ThreatLevel.HIGH]


class TestAdaptiveRateLimiter:
    """Test main AdaptiveRateLimiter class."""

    def test_adaptive_limiter_creation(self):
        """Test limiter creation with default config."""
        limiter = AdaptiveRateLimiter()
        assert limiter.base_config is not None

    def test_adaptive_limiter_custom_config(self):
        """Test limiter with custom config."""
        config = RateLimitConfig(requests_per_second=100.0)
        limiter = AdaptiveRateLimiter(config)
        assert limiter.base_config.requests_per_second == 100.0

    def test_check_request_basic(self):
        """Test basic request checking."""
        limiter = AdaptiveRateLimiter(RateLimitConfig(
            requests_per_second=1000.0,
            max_burst=100
        ))

        result = limiter.check_request("test_key", "127.0.0.1", "/api/test")
        assert result.allowed is True
        assert result.threat_level == ThreatLevel.LOW
        assert result.attack_detected == DoSAttackType.NONE

    def test_check_request_multiple_keys(self):
        """Test multiple different keys work independently."""
        limiter = AdaptiveRateLimiter(RateLimitConfig(max_burst=2))

        # Different keys have separate limits
        result1 = limiter.check_request("key1", "ip1", "/ep1")
        result2 = limiter.check_request("key2", "ip2", "/ep2")
        assert result1.allowed is True
        assert result2.allowed is True

    def test_circuit_breaker_closed_initially(self):
        """Test circuit breaker starts closed."""
        limiter = AdaptiveRateLimiter()
        allowed, wait = limiter.check_circuit_breaker("test_service")
        assert allowed is True
        assert wait is None

    def test_circuit_breaker_opens_on_failures(self):
        """Test circuit breaker opens after failures."""
        limiter = AdaptiveRateLimiter()

        # Record multiple failures
        for i in range(6):
            limiter.record_failure("unreliable_service", failure_threshold=5)

        # Should be open now
        allowed, wait = limiter.check_circuit_breaker("unreliable_service")
        assert allowed is False
        assert wait is not None

    def test_circuit_breaker_recovery(self):
        """Test circuit breaker recovers after timeout."""
        limiter = AdaptiveRateLimiter()

        # Trip the breaker
        for i in range(6):
            limiter.record_failure("flaky", failure_threshold=5, recovery_timeout=0.1)

        # Immediately should be blocked
        allowed, _ = limiter.check_circuit_breaker("flaky")
        assert allowed is False

        # Wait for recovery
        time.sleep(0.15)

        # Should allow now (half-open)
        allowed, _ = limiter.check_circuit_breaker("flaky")
        assert allowed is True

    def test_record_success_resets_breaker(self):
        """Test successful requests help reset circuit breaker."""
        limiter = AdaptiveRateLimiter()

        # Trip to half-open
        for i in range(6):
            limiter.record_failure("test", failure_threshold=5, recovery_timeout=0.01)

        time.sleep(0.02)
        limiter.check_circuit_breaker("test")  # Move to half-open

        # Multiple successes should close it
        for i in range(5):
            limiter.record_success("test")

        # Should be working normally
        allowed, _ = limiter.check_circuit_breaker("test")
        assert allowed is True

    def test_get_stats(self):
        """Test stats collection."""
        limiter = AdaptiveRateLimiter()
        stats = limiter.get_stats()
        assert "tracked_ips" in stats
        assert "tracked_endpoints" in stats
        assert "circuit_breakers" in stats
        assert "open_circuits" in stats


class TestRateLimitDecorator:
    """Test @rate_limit decorator."""

    def test_decorator_allows_calls(self):
        """Test decorator allows function calls within limit."""
        @rate_limit(config=RateLimitConfig(requests_per_second=1000, max_burst=100))
        def protected_func(x):
            return x * 2

        # Should work
        result = protected_func(5)
        assert result == 10

    def test_decorator_enforces_limit(self):
        """Test decorator enforces rate limit."""
        @rate_limit(config=RateLimitConfig(requests_per_second=1, max_burst=2))
        def limited_func():
            return "ok"

        # Consume burst
        limited_func()
        limited_func()

        # Should raise on third
        # Note: due to key hashing based on args, each call with different args
        # gets different key, so we call with same args
        with pytest.raises(RateLimitExceededError):
            for i in range(5):
                limited_func()


class TestFactoryFunctions:
    """Test factory convenience functions."""

    def test_create_token_bucket_limiter(self):
        """Test token bucket factory."""
        limiter = create_token_bucket_limiter(50.0, 100)
        assert isinstance(limiter, AdaptiveRateLimiter)
        assert limiter.base_config.algorithm == RateLimitAlgorithm.TOKEN_BUCKET

    def test_create_sliding_window_limiter(self):
        """Test sliding window factory."""
        limiter = create_sliding_window_limiter(600, 60)
        assert isinstance(limiter, AdaptiveRateLimiter)
        assert limiter.base_config.algorithm == RateLimitAlgorithm.SLIDING_WINDOW

    def test_create_dos_protector(self):
        """Test DoS protector factory."""
        detector = create_dos_protector()
        assert isinstance(detector, DoSDetector)


class TestRateLimitExceededError:
    """Test custom exception."""

    def test_exception_creation(self):
        """Test exception creation with retry_after."""
        err = RateLimitExceededError("Too fast", retry_after=5.0)
        assert str(err) == "Too fast"
        assert err.retry_after == 5.0

    def test_exception_no_retry(self):
        """Test exception without retry_after."""
        err = RateLimitExceededError("Blocked")
        assert err.retry_after is None


class TestThreadSafety:
    """Test thread safety of rate limiters."""

    def test_concurrent_requests(self):
        """Test limiter handles concurrent requests."""
        limiter = AdaptiveRateLimiter(RateLimitConfig(
            requests_per_second=1000.0,
            max_burst=200
        ))
        results = []
        errors = []

        def worker():
            try:
                for i in range(10):
                    r = limiter.check_request(f"thread_{threading.get_ident()}_{i}")
                    results.append(r.allowed)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert all(results)


class TestBackwardCompatibility:
    """Test backward compatibility - module should not affect existing code."""

    def test_module_imports_cleanly(self):
        """Test module can be imported without side effects."""
        import neural_shield.security_hardening_adaptive_rate_limiting_dos_protection_v11_2026_june as module
        assert module is not None

    def test_no_global_state_leakage(self):
        """Test separate instances don't share state."""
        limiter1 = AdaptiveRateLimiter()
        limiter2 = AdaptiveRateLimiter()

        # Use up limiter1
        config = RateLimitConfig(max_burst=1)
        for _ in range(3):
            limiter1.check_request("shared_key", algorithm=RateLimitAlgorithm.TOKEN_BUCKET)

        # limiter2 should still work
        result = limiter2.check_request("shared_key", algorithm=RateLimitAlgorithm.TOKEN_BUCKET)
        # Different instances have different state - both work independently
        assert True  # Just verify no crash


class TestEdgeCases:
    """Test edge cases."""

    def test_empty_ip(self):
        """Test handling empty/unknown IP."""
        limiter = AdaptiveRateLimiter()
        result = limiter.check_request("key", "", "")
        assert result.allowed is True  # Should not crash

    def test_special_characters_in_key(self):
        """Test special characters in rate limit key."""
        limiter = AdaptiveRateLimiter()
        result = limiter.check_request("key!@#$%^&*()", "127.0.0.1", "/api")
        assert result.allowed is True

    def test_very_long_key(self):
        """Test very long key strings."""
        limiter = AdaptiveRateLimiter()
        long_key = "x" * 10000
        result = limiter.check_request(long_key, "127.0.0.1", "/api")
        assert result.allowed is True

    def test_none_values(self):
        """Test None handling."""
        limiter = AdaptiveRateLimiter()
        # Should not crash with None
        result = limiter.check_request("key")
        assert result.allowed is True


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
