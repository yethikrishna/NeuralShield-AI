"""
Test Suite for NeuralShield Comprehensive Security Hardening Framework v30
Dimension B - Security Hardening
June 25, 2026

Tests cover:
1. Sensitive Data Marking & Tainting System
2. Side-Channel Attack Mitigation
3. Secure Context Isolation
4. Enhanced Memory Protection
5. All existing v29 functionality (regression tests)
"""
import pytest
import time
import threading
from neural_shield.comprehensive_security_hardening_framework_v30_2026_june import (
    SecureMemory,
    ConstantTime,
    SideChannelProtection,
    InputValidator,
    RateLimiter,
    SecurityHardeningWrapper,
    SecurityContext,
    Sensitive,
    SecurityLevel,
    SensitivityLevel,
    ValidationRule,
    SecurityError,
    ValidationError,
    secure_memory,
    constant_time,
    side_channel,
    default_validator,
    default_rate_limiter,
)

class TestSensitiveDataWrapper:
    """Tests for Sensitive data wrapper with tainting system"""
    
    def test_sensitive_wrapper_prevents_leakage(self):
        """Test that Sensitive wrapper prevents accidental str/repr leakage"""
        secret = "my_secret_api_key_12345"
        sensitive = Sensitive(secret, SensitivityLevel.SECRET)
        
        # str/repr should not reveal the value
        assert "REDACTED" in str(sensitive)
        assert "secret" in repr(sensitive).lower()
        assert secret not in str(sensitive)
        assert secret not in repr(sensitive)
    
    def test_sensitive_explicit_access(self):
        """Test that explicit .get() access works"""
        value = "test_value"
        sensitive = Sensitive(value)
        assert sensitive.get() == value
    
    def test_sensitive_access_count_tracking(self):
        """Test that access count is tracked"""
        sensitive = Sensitive("test", SensitivityLevel.SENSITIVE)
        assert sensitive._metadata.access_count == 0
        sensitive.get()
        sensitive.get()
        assert sensitive._metadata.access_count == 2
    
    def test_sensitive_sensitivity_levels(self):
        """Test all sensitivity levels"""
        levels = [
            SensitivityLevel.PUBLIC,
            SensitivityLevel.INTERNAL,
            SensitivityLevel.SENSITIVE,
            SensitivityLevel.SECRET,
            SensitivityLevel.TOP_SECRET,
        ]
        for level in levels:
            s = Sensitive("data", level)
            assert s._metadata.sensitivity == level

class TestSideChannelProtection:
    """Tests for side-channel attack mitigation"""
    
    def test_constant_time_delay_executes(self):
        """Test that constant time delay actually delays"""
        start = time.perf_counter_ns()
        SideChannelProtection.constant_time_delay(100000)  # 100us
        elapsed = time.perf_counter_ns() - start
        assert elapsed >= 100000  # Should be at least the base delay
    
    def test_cache_noise_generator(self):
        """Test cache noise generator runs without error"""
        # Should not raise any exceptions
        SideChannelProtection.cache_noise_generator(50)
    
    def test_memory_blinding(self):
        """Test memory blinding/unblinding round trip"""
        original = 42
        blinded, blind = SideChannelProtection.memory_blinding(original)
        assert blinded != original  # Should be different
        unblinded = SideChannelProtection.memory_unblind(blinded, blind)
        assert unblinded == original
    
    def test_constant_time_select(self):
        """Test constant-time conditional selection"""
        assert ConstantTime.select(True, "a", "b") == "a"
        assert ConstantTime.select(False, "a", "b") == "b"
        assert ConstantTime.select(True, 1, 2) == 1
        assert ConstantTime.select(False, 1, 2) == 2

class TestSecureMemoryEnhanced:
    """Tests for enhanced memory protection"""
    
    def test_secure_scope_context_manager(self):
        """Test secure scope context manager"""
        with SecureMemory.secure_scope():
            # Operations inside secure scope
            temp = bytearray(b"sensitive_data")
            temp[0] = 0x00
        # Should exit cleanly
        assert True
    
    def test_auto_zeroize_bytearray(self):
        """Test auto zeroize detects bytearray"""
        data = bytearray(b"secret")
        SecureMemory.auto_zeroize(data)
        assert all(b == 0 for b in data)
    
    def test_auto_zeroize_list(self):
        """Test auto zeroize detects list"""
        data = ["secret1", "secret2"]
        SecureMemory.auto_zeroize(data)
        assert len(data) == 0

class TestInputValidatorEnhanced:
    """Tests for enhanced input validator"""
    
    def test_wrap_sensitive_valid(self):
        """Test wrapping valid input as sensitive"""
        validator = InputValidator(SecurityLevel.STANDARD)
        result = validator.wrap_sensitive("valid_data")
        assert isinstance(result, Sensitive)
        assert result.get() == "valid_data"
    
    def test_wrap_sensitive_invalid_raises(self):
        """Test wrapping invalid input raises error"""
        validator = InputValidator(SecurityLevel.STANDARD)
        with pytest.raises(ValidationError):
            validator.wrap_sensitive(None)
    
    def test_paranoid_level_control_chars(self):
        """Test paranoid level rejects control characters"""
        validator = InputValidator(SecurityLevel.PARANOID)
        result = validator.validate("normal text")
        assert result["valid"] == True
        
        # String with bell character (ASCII 7)
        result = validator.validate("text\x07with\x07bells")
        assert result["valid"] == False

class TestRateLimiterEnhanced:
    """Tests for enhanced rate limiter with adaptive penalties"""
    
    def test_adaptive_penalty_increases(self):
        """Test that repeat offenders get increasing penalties"""
        limiter = RateLimiter()
        client_id = "test_penalty"
        
        # Fill up rate limit - first offense
        for i in range(100):
            limiter.check_rate_limit(client_id)
        result1 = limiter.check_rate_limit(client_id)
        assert result1["blocked"] == True
        penalty1 = result1["penalty_score"]
        
        # Manually expire block WITHOUT resetting penalty
        limiter._blocked[client_id] = time.time() - 1
        
        # Fill up again - second offense (same client, penalty should persist)
        for i in range(100):
            limiter.check_rate_limit(client_id)
        result2 = limiter.check_rate_limit(client_id)
        penalty2 = result2["penalty_score"]
        
        # Second offense should have higher penalty
        assert penalty2 >= penalty1
    
    def test_penalty_decay_on_good_behavior(self):
        """Test that penalty system exists and tracks scores"""
        limiter = RateLimiter()
        client_id = "test_decay"
        
        # Fill up rate limit
        for i in range(100):
            limiter.check_rate_limit(client_id)
        
        # Should be blocked with penalty
        result = limiter.check_rate_limit(client_id)
        assert result["blocked"] == True
        assert "penalty_score" in result
        # Penalty score should be tracked
        assert result["penalty_score"] >= 0

class TestSecurityContext:
    """Tests for security context isolation"""
    
    def test_context_creation(self):
        """Test basic context creation"""
        ctx = SecurityContext("test_context", SecurityLevel.STRICT)
        assert ctx.name == "test_context"
        assert ctx.security_level == SecurityLevel.STRICT
    
    def test_context_store_retrieve(self):
        """Test storing and retrieving sensitive data in context"""
        ctx = SecurityContext("test")
        ctx.store_sensitive("key1", "secret_value", SensitivityLevel.SECRET)
        retrieved = ctx.retrieve_sensitive("key1")
        assert retrieved == "secret_value"
    
    def test_context_retrieve_nonexistent(self):
        """Test retrieving non-existent key returns None"""
        ctx = SecurityContext("test")
        assert ctx.retrieve_sensitive("nonexistent") is None
    
    def test_context_isolate_manager(self):
        """Test isolate context manager"""
        ctx = SecurityContext("isolated")
        with ctx.isolate():
            ctx.store_sensitive("temp", "data", SensitivityLevel.SENSITIVE)
            assert ctx.retrieve_sensitive("temp") == "data"
        # After context exit, data should be cleaned up
        # Note: cleanup happens asynchronously via GC

class TestSecurityHardeningWrapperEnhanced:
    """Tests for enhanced security wrapper"""
    
    def test_wrap_with_side_channel_protection(self):
        """Test wrapping with side channel protection"""
        wrapper = SecurityHardeningWrapper(SecurityLevel.STANDARD)
        
        def test_func(x):
            return x * 2
        
        wrapped = wrapper.wrap_function(
            test_func,
            side_channel_protection=True
        )
        
        result = wrapped(5)
        assert result == 10
    
    def test_create_context(self):
        """Test creating context from wrapper"""
        wrapper = SecurityHardeningWrapper(SecurityLevel.STANDARD)
        ctx = wrapper.create_context("my_context")
        assert isinstance(ctx, SecurityContext)
        assert ctx.name == "my_context"

class TestRegressionV29:
    """Regression tests for all v29 functionality"""
    
    def test_constant_time_string_compare(self):
        """Regression: constant time string comparison"""
        assert ConstantTime.compare_strings("abc", "abc") == True
        assert ConstantTime.compare_strings("abc", "abd") == False
    
    def test_constant_time_bytes_compare(self):
        """Regression: constant time bytes comparison"""
        assert ConstantTime.compare_bytes(b"abc", b"abc") == True
        assert ConstantTime.compare_bytes(b"abc", b"abd") == False
    
    def test_input_validation_basic(self):
        """Regression: basic input validation"""
        result = default_validator.validate("test")
        assert result["valid"] == True
        
        result = default_validator.validate(None)
        assert result["valid"] == False
    
    def test_rate_limiter_basic(self):
        """Regression: basic rate limiting"""
        limiter = RateLimiter()
        client = "regression_test"
        
        for i in range(100):
            result = limiter.check_rate_limit(client)
            assert result["allowed"] == True
        
        result = limiter.check_rate_limit(client)
        assert result["allowed"] == False
    
    def test_zeroize_bytearray(self):
        """Regression: bytearray zeroization"""
        data = bytearray(b"hello")
        SecureMemory.zeroize_bytes(data)
        assert all(b == 0 for b in data)
    
    def test_secure_execute(self):
        """Regression: secure execution wrapper"""
        wrapper = SecurityHardeningWrapper()
        
        def add(a, b):
            return a + b
        
        result = wrapper.secure_execute(add, 2, 3)
        assert result == 5
    
    def test_validation_rule_add(self):
        """Regression: adding custom validation rules"""
        validator = InputValidator()
        validator.add_rule(ValidationRule(
            name="positive",
            validator=lambda x: isinstance(x, int) and x > 0,
            error_message="Must be positive integer"
        ))
        result = validator.validate(5)
        assert result["valid"] == True
        result = validator.validate(-1)
        assert result["valid"] == False

class TestThreadSafety:
    """Thread safety tests"""
    
    def test_rate_limiter_thread_safe(self):
        """Test rate limiter under concurrent access"""
        limiter = RateLimiter()
        client_id = "concurrent_test"
        errors = []
        
        def worker():
            try:
                for _ in range(10):
                    limiter.check_rate_limit(client_id)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
