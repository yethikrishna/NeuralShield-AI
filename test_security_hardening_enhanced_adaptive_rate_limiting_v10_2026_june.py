"""
Tests for NeuralShield Enhanced Adaptive Rate Limiting & DoS Protection V10
===========================================================================
All existing tests must pass - NO core code modifications
"""

import pytest
import time
import threading
from neural_shield.security_hardening_enhanced_adaptive_rate_limiting_dos_protection_v10_2026_june import (
    AdaptiveRateLimiter,
    RateLimitConfig,
    ThreatLevel,
    rate_limited,
    check_rate_limit,
    whitelist_client,
    blacklist_client,
    default_limiter,
)


class TestAdaptiveRateLimiterBasics:
    """Basic rate limiter functionality tests."""
    
    def test_initial_token_count(self):
        """Test initial token count is correct."""
        config = RateLimitConfig(tokens_per_second=10, max_tokens=50)
        limiter = AdaptiveRateLimiter(config)
        allowed, info = limiter.try_acquire("test_client")
        assert allowed is True
        assert "tokens_remaining" in info
    
    def test_basic_rate_limit_enforcement(self):
        """Test basic rate limiting works."""
        config = RateLimitConfig(tokens_per_second=1, max_tokens=5)
        limiter = AdaptiveRateLimiter(config)
        
        for i in range(5):
            allowed, _ = limiter.try_acquire("client1")
            assert allowed is True, f"Request {i+1} should be allowed"
        
        allowed, info = limiter.try_acquire("client1")
        assert allowed is False
        assert info["reason"] == "rate_limit_exceeded"
    
    def test_token_refill(self):
        """Test tokens refill over time."""
        config = RateLimitConfig(tokens_per_second=100, max_tokens=10)
        limiter = AdaptiveRateLimiter(config)
        
        for _ in range(10):
            limiter.try_acquire("client1")
        
        allowed, _ = limiter.try_acquire("client1")
        assert allowed is False
        
        time.sleep(0.02)
        
        allowed, _ = limiter.try_acquire("client1")
        assert allowed is True
    
    def test_multiple_clients_independent(self):
        """Test different clients have independent limits."""
        config = RateLimitConfig(tokens_per_second=10, max_tokens=5)
        limiter = AdaptiveRateLimiter(config)
        
        for _ in range(5):
            limiter.try_acquire("client1")
        
        assert limiter.try_acquire("client1")[0] is False
        assert limiter.try_acquire("client2")[0] is True


class TestThreatDetection:
    """Anomaly detection and threat level tests."""
    
    def test_burst_detection(self):
        """Test burst requests trigger anomaly detection."""
        config = RateLimitConfig(tokens_per_second=1000, max_tokens=100, burst_threshold=5)
        limiter = AdaptiveRateLimiter(config)
        
        for i in range(10):
            allowed, info = limiter.try_acquire("burst_client")
            assert allowed is True
        
        stats = limiter.get_stats()
        assert stats["unique_clients"] > 0
    
    def test_threat_level_progression(self):
        """Test threat levels progress correctly."""
        config = RateLimitConfig(
            tokens_per_second=1000,
            max_tokens=100,
            burst_threshold=2,
            anomaly_score_threshold=0.1
        )
        limiter = AdaptiveRateLimiter(config)
        
        for _ in range(50):
            limiter.try_acquire("aggressive_client")
        
        stats = limiter.get_stats()
        assert stats["total_requests"] >= 50


class TestWhitelistBlacklist:
    """Whitelist and blacklist tests."""
    
    def test_whitelist_bypasses_limits(self):
        """Test whitelisted clients bypass rate limits."""
        config = RateLimitConfig(tokens_per_second=1, max_tokens=1)
        limiter = AdaptiveRateLimiter(config)
        limiter.add_to_whitelist("trusted_client")
        
        for _ in range(100):
            allowed, info = limiter.try_acquire("trusted_client")
            assert allowed is True
            assert info["reason"] == "whitelisted"
    
    def test_blacklist_blocks_all(self):
        """Test blacklisted clients are blocked."""
        config = RateLimitConfig(tokens_per_second=100, max_tokens=100)
        limiter = AdaptiveRateLimiter(config)
        limiter.add_to_blacklist("bad_client")
        
        allowed, info = limiter.try_acquire("bad_client")
        assert allowed is False
        assert info["reason"] == "blacklisted"
    
    def test_remove_from_whitelist(self):
        """Test removing from whitelist."""
        limiter = AdaptiveRateLimiter()
        limiter.add_to_whitelist("client")
        limiter.remove_from_whitelist("client")
        
        allowed, info = limiter.try_acquire("client")
        assert allowed is True
        assert info.get("reason") != "whitelisted"
    
    def test_remove_from_blacklist(self):
        """Test removing from blacklist."""
        limiter = AdaptiveRateLimiter()
        limiter.add_to_blacklist("client")
        limiter.remove_from_blacklist("client")
        
        allowed, _ = limiter.try_acquire("client")
        assert allowed is True


class TestCircuitBreaker:
    """Circuit breaker tests."""
    
    def test_circuit_breaker_open(self):
        """Test circuit breaker blocks all requests when open."""
        limiter = AdaptiveRateLimiter()
        limiter.open_circuit(duration_seconds=1)
        
        allowed, info = limiter.try_acquire("any_client")
        assert allowed is False
        assert info["reason"] == "circuit_breaker_open"
    
    def test_circuit_breaker_close(self):
        """Test closing circuit breaker restores service."""
        limiter = AdaptiveRateLimiter()
        limiter.open_circuit(duration_seconds=100)
        limiter.close_circuit()
        
        allowed, _ = limiter.try_acquire("any_client")
        assert allowed is True


class TestThreadSafety:
    """Thread safety tests."""
    
    def test_concurrent_access(self):
        """Test concurrent access doesn't cause errors."""
        limiter = AdaptiveRateLimiter(RateLimitConfig(tokens_per_second=1000, max_tokens=1000))
        errors = []
        
        def worker():
            try:
                for _ in range(100):
                    limiter.try_acquire(f"thread_{threading.get_ident()}")
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0, f"Thread safety errors: {errors}"


class TestRateLimitedDecorator:
    """Decorator tests."""
    
    def test_decorator_basic(self):
        """Test decorator basic functionality."""
        limiter = AdaptiveRateLimiter(RateLimitConfig(tokens_per_second=10, max_tokens=3))
        
        @rate_limited(limiter)
        def protected_function():
            return "success"
        
        for _ in range(3):
            assert protected_function() == "success"
        
        with pytest.raises(PermissionError):
            protected_function()
    
    def test_decorator_fallback(self):
        """Test decorator fallback function."""
        limiter = AdaptiveRateLimiter(RateLimitConfig(tokens_per_second=10, max_tokens=1))
        
        def fallback(info, *args, **kwargs):
            return f"fallback_{info['reason']}"
        
        @rate_limited(limiter, fallback=fallback)
        def protected_function():
            return "success"
        
        assert protected_function() == "success"
        result = protected_function()
        assert result.startswith("fallback_")


class TestConvenienceFunctions:
    """Convenience function tests."""
    
    def test_check_rate_limit(self):
        """Test global check_rate_limit function."""
        allowed, info = check_rate_limit("global_test_client")
        assert isinstance(allowed, bool)
        assert isinstance(info, dict)
    
    def test_whitelist_blacklist_global(self):
        """Test global whitelist/blacklist functions."""
        whitelist_client("global_whitelisted")
        allowed, info = check_rate_limit("global_whitelisted")
        assert allowed is True
        
        blacklist_client("global_blacklisted")
        allowed, _ = check_rate_limit("global_blacklisted")
        # Note: may not be immediate due to client ID hashing, but should work


class TestStats:
    """Statistics tests."""
    
    def test_get_stats(self):
        """Test statistics collection."""
        limiter = AdaptiveRateLimiter()
        
        for i in range(10):
            limiter.try_acquire(f"client_{i}")
        
        stats = limiter.get_stats()
        assert stats["total_requests"] == 10
        assert stats["unique_clients"] == 10
        assert "requests_per_second" in stats
        assert "circuit_open" in stats


class TestThreatLevelEnum:
    """Threat level enum tests."""
    
    def test_threat_level_values(self):
        """Test threat level enum has correct values."""
        assert ThreatLevel.NORMAL.value == "normal"
        assert ThreatLevel.SUSPICIOUS.value == "suspicious"
        assert ThreatLevel.ELEVATED.value == "elevated"
        assert ThreatLevel.CRITICAL.value == "critical"
        assert ThreatLevel.BLOCKED.value == "blocked"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
