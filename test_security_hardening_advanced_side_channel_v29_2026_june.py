"""
Tests for NeuralShield AI - Advanced Side-Channel Protection v29
Dimension B: Security Hardening
"""

import pytest
import threading
import time
from neural_shield.security_hardening_advanced_side_channel_protection_v29_2026_june import (
    constant_time_bytes_equal,
    constant_time_str_equal,
    constant_time_int_equal,
    constant_time_choose,
    SecureMemory,
    SecureMemoryError,
    secure_gc_suspend,
    constant_time_execution,
    EntropyValidator,
    TimingAttackProtector,
    CacheAttackMitigation,
    secure_wipe_object,
    __version__,
    __dimension__,
)


class TestModuleMetadata:
    """Test module metadata correctness."""
    
    def test_version_correct(self):
        assert __version__ == "29.0.0"
    
    def test_dimension_correct(self):
        assert __dimension__ == "B - Security Hardening"


class TestConstantTimeComparison:
    """Test constant-time comparison functions."""
    
    def test_bytes_equal_identical(self):
        a = b"test_data_12345"
        assert constant_time_bytes_equal(a, a) is True
    
    def test_bytes_equal_different(self):
        a = b"test_data_12345"
        b = b"test_data_12346"
        assert constant_time_bytes_equal(a, b) is False
    
    def test_bytes_equal_different_length(self):
        a = b"short"
        b = b"much_longer"
        assert constant_time_bytes_equal(a, b) is False
    
    def test_bytes_equal_empty(self):
        assert constant_time_bytes_equal(b"", b"") is True
    
    def test_str_equal_identical(self):
        assert constant_time_str_equal("hello world", "hello world") is True
    
    def test_str_equal_different(self):
        assert constant_time_str_equal("hello", "world") is False
    
    def test_str_equal_unicode(self):
        assert constant_time_str_equal("你好世界", "你好世界") is True
        assert constant_time_str_equal("你好世界", "你好") is False
    
    def test_int_equal_identical(self):
        assert constant_time_int_equal(42, 42) is True
    
    def test_int_equal_different(self):
        assert constant_time_int_equal(42, 43) is False
    
    def test_int_equal_zero(self):
        assert constant_time_int_equal(0, 0) is True
        assert constant_time_int_equal(0, 1) is False
    
    def test_int_equal_large_numbers(self):
        assert constant_time_int_equal(2**64, 2**64) is True
        assert constant_time_int_equal(2**64, 2**64 + 1) is False


class TestConstantTimeChoose:
    """Test branchless selection."""
    
    def test_choose_int_true(self):
        result = constant_time_choose(True, 100, 200)
        assert result == 100
    
    def test_choose_int_false(self):
        result = constant_time_choose(False, 100, 200)
        assert result == 200
    
    def test_choose_bytes_true(self):
        result = constant_time_choose(True, b"aaa", b"bbb")
        assert result == b"aaa"
    
    def test_choose_bytes_false(self):
        result = constant_time_choose(False, b"aaa", b"bbb")
        assert result == b"bbb"
    
    def test_choose_bytes_different_length(self):
        # Should handle padding
        result = constant_time_choose(True, b"a", b"bbbb")
        assert len(result) == 4  # Max length


class TestSecureMemory:
    """Test secure memory container."""
    
    def test_create_and_get(self):
        with SecureMemory(b"secret_data") as mem:
            data = mem.get()
            assert data == b"secret_data"
    
    def test_create_from_string(self):
        with SecureMemory("secret_string") as mem:
            data = mem.get()
            assert data == b"secret_string"
    
    def test_wipe_clears_data(self):
        mem = SecureMemory(b"secret")
        mem.wipe()
        with pytest.raises(SecureMemoryError):
            mem.get()
    
    def test_context_manager_auto_wipe(self):
        mem = None
        with SecureMemory(b"test") as m:
            mem = m
            assert mem.get() == b"test"
        # After context exit, should be wiped
        with pytest.raises(SecureMemoryError):
            mem.get()
    
    def test_double_wipe_safe(self):
        mem = SecureMemory(b"test")
        mem.wipe()
        mem.wipe()  # Should not raise
    
    def test_wiped_flag(self):
        mem = SecureMemory(b"test")
        assert mem._wiped is False
        mem.wipe()
        assert mem._wiped is True


class TestGCControl:
    """Test garbage collection suspension."""
    
    def test_gc_suspend_context(self):
        import gc
        gc.enable()
        with secure_gc_suspend():
            assert not gc.isenabled()
        assert gc.isenabled()
    
    def test_gc_suspend_nested(self):
        import gc
        gc.enable()
        with secure_gc_suspend():
            with secure_gc_suspend():
                assert not gc.isenabled()
            assert not gc.isenabled()  # Still suspended by outer
        assert gc.isenabled()


class TestConstantTimeExecution:
    """Test constant-time execution environment."""
    
    def test_execution_context(self):
        # Should not raise
        with constant_time_execution():
            x = sum(range(100))
        assert x == 4950
    
    def test_execution_preserves_result(self):
        def sensitive_operation():
            return hashlib.sha256(b"test").digest()
        
        with constant_time_execution():
            result = sensitive_operation()
        
        expected = hashlib.sha256(b"test").digest()
        assert result == expected


class TestEntropyValidator:
    """Test entropy validation functions."""
    
    def test_monobit_perfect(self):
        # Alternating bits should have good score
        data = bytes([0xAA, 0x55] * 16)  # 10101010, 01010101
        score = EntropyValidator.monobit_test(data)
        assert score > 0.9
    
    def test_monobit_all_zeros(self):
        data = b'\x00' * 32
        score = EntropyValidator.monobit_test(data)
        assert score < 0.1  # Very bad
    
    def test_runs_test_random(self):
        import secrets
        data = secrets.token_bytes(64)
        score = EntropyValidator.runs_test(data)
        assert score > 0.5  # Random should be decent
    
    def test_validate_good_entropy(self):
        import secrets
        data = secrets.token_bytes(32)
        assert EntropyValidator.validate_entropy(data) is True
    
    def test_validate_bad_entropy(self):
        data = b'\x00' * 32
        assert EntropyValidator.validate_entropy(data) is False
    
    def test_validate_too_short(self):
        data = b'short'
        assert EntropyValidator.validate_entropy(data) is False


class TestTimingAttackProtector:
    """Test timing attack protection decorators."""
    
    def test_protected_operation_decorator(self):
        @TimingAttackProtector.protected_operation
        def sensitive_func(x):
            return x * 2
        
        result = sensitive_func(21)
        assert result == 42
    
    def test_no_early_exit_decorator(self):
        @TimingAttackProtector.no_early_exit
        def check_value(x):
            return x > 10
        
        assert check_value(5) is False
        assert check_value(15) is True


class TestCacheAttackMitigation:
    """Test cache attack mitigation functions."""
    
    def test_blind_lookup_correct(self):
        table = [10, 20, 30, 40, 50]
        result = CacheAttackMitigation.blind_lookup(table, 2)
        assert result == 30
    
    def test_blind_lookup_first(self):
        table = ['a', 'b', 'c']
        result = CacheAttackMitigation.blind_lookup(table, 0)
        assert result == 'a'
    
    def test_blind_lookup_last(self):
        table = ['a', 'b', 'c']
        result = CacheAttackMitigation.blind_lookup(table, 2)
        assert result == 'c'
    
    def test_blind_lookup_empty(self):
        with pytest.raises(IndexError):
            CacheAttackMitigation.blind_lookup([], 0)
    
    def test_constant_time_find_found(self):
        items = ['x', 'y', 'z', 'target', 'w']
        idx = CacheAttackMitigation.constant_time_index_find(items, 'target')
        assert idx == 3
    
    def test_constant_time_find_not_found(self):
        items = ['a', 'b', 'c']
        idx = CacheAttackMitigation.constant_time_index_find(items, 'missing')
        assert idx == -1


class TestSecureWipe:
    """Test object wiping functions."""
    
    def test_wipe_bytearray(self):
        data = bytearray(b'secret')
        secure_wipe_object(data)
        assert all(b == 0 for b in data)
    
    def test_wipe_int_list(self):
        data = [1, 2, 3, 4, 5]
        secure_wipe_object(data)
        assert all(x == 0 for x in data)
    
    def test_wipe_empty_bytearray(self):
        data = bytearray()
        secure_wipe_object(data)  # Should not raise
        assert len(data) == 0


class TestThreadSafety:
    """Test thread safety of security primitives."""
    
    def test_concurrent_secure_memory(self):
        errors = []
        
        def worker():
            try:
                for _ in range(10):
                    with SecureMemory(b"test") as mem:
                        _ = mem.get()
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
    
    def test_concurrent_entropy_validation(self):
        import secrets
        results = []
        
        def worker():
            for _ in range(10):
                data = secrets.token_bytes(32)
                results.append(EntropyValidator.validate_entropy(data))
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert all(results)


import hashlib
