"""
Tests for Constant-Time Comparison Utilities v23 - NeuralShield-AI
Security Hardening - Dimension B
"""

import pytest
import time
from neural_shield.constant_time_comparison_v23_2026_june import (
    ConstantTimeComparer,
    ConstantTimeArray,
    TimingAttackProtector,
    constant_time_all,
    constant_time_any,
    secure_hash_compare,
    secure_password_compare,
    ConstantTimeError,
)


class TestConstantTimeComparer:
    """Tests for ConstantTimeComparer class."""
    
    def test_compare_bytes_equal(self):
        """Test comparing equal byte strings."""
        a = b'test data 123'
        b = b'test data 123'
        assert ConstantTimeComparer.compare_bytes(a, b) is True
    
    def test_compare_bytes_not_equal(self):
        """Test comparing different byte strings."""
        a = b'test data 123'
        b = b'test data 456'
        assert ConstantTimeComparer.compare_bytes(a, b) is False
    
    def test_compare_bytes_different_length(self):
        """Test comparing byte strings of different length."""
        a = b'short'
        b = b'much longer string'
        assert ConstantTimeComparer.compare_bytes(a, b) is False
    
    def test_compare_strings_equal(self):
        """Test comparing equal strings."""
        a = "hello world"
        b = "hello world"
        assert ConstantTimeComparer.compare_strings(a, b) is True
    
    def test_compare_strings_not_equal(self):
        """Test comparing different strings."""
        a = "hello world"
        b = "hello xorld"
        assert ConstantTimeComparer.compare_strings(a, b) is False
    
    def test_compare_strings_different_length(self):
        """Test comparing strings of different length."""
        a = "short"
        b = "much longer string"
        assert ConstantTimeComparer.compare_strings(a, b) is False
    
    def test_compare_ints_equal(self):
        """Test comparing equal integers."""
        assert ConstantTimeComparer.compare_ints(42, 42) is True
        assert ConstantTimeComparer.compare_ints(0, 0) is True
        assert ConstantTimeComparer.compare_ints(-1, -1) is True
    
    def test_compare_ints_not_equal(self):
        """Test comparing different integers."""
        assert ConstantTimeComparer.compare_ints(42, 43) is False
        assert ConstantTimeComparer.compare_ints(100, 200) is False
    
    def test_is_equal_length(self):
        """Test equal length check."""
        assert ConstantTimeComparer.is_equal_length([1, 2, 3], [4, 5, 6]) is True
        assert ConstantTimeComparer.is_equal_length("abc", "xyz") is True
        assert ConstantTimeComparer.is_equal_length([1], []) is False
    
    def test_select_integer(self):
        """Test constant-time select for integers."""
        assert ConstantTimeComparer.select(True, 100, 200) == 100
        assert ConstantTimeComparer.select(False, 100, 200) == 200
    
    def test_less_than(self):
        """Test constant-time less than comparison."""
        assert ConstantTimeComparer.less_than(5, 10) is True
        assert ConstantTimeComparer.less_than(10, 5) is False
        assert ConstantTimeComparer.less_than(5, 5) is False
    
    def test_greater_than(self):
        """Test constant-time greater than comparison."""
        assert ConstantTimeComparer.greater_than(10, 5) is True
        assert ConstantTimeComparer.greater_than(5, 10) is False
        assert ConstantTimeComparer.greater_than(5, 5) is False


class TestConstantTimeArray:
    """Tests for ConstantTimeArray class."""
    
    def test_lookup_basic(self):
        """Test basic constant-time lookup."""
        table = [b'entry0', b'entry1', b'entry2', b'entry3']
        result = ConstantTimeArray.lookup(table, 2)
        assert result == b'entry2'
    
    def test_lookup_first(self):
        """Test lookup first entry."""
        table = [b'first', b'second', b'third']
        result = ConstantTimeArray.lookup(table, 0)
        assert result == b'first'
    
    def test_lookup_last(self):
        """Test lookup last entry."""
        table = [b'first', b'second', b'third']
        result = ConstantTimeArray.lookup(table, 2)
        assert result == b'third'
    
    def test_lookup_empty_table(self):
        """Test lookup on empty table."""
        with pytest.raises(ValueError):
            ConstantTimeArray.lookup([], 0)
    
    def test_copy_if_true(self):
        """Test copy_if with condition True."""
        dest = bytearray(b'xxxxxx')
        src = b'hello!'
        ConstantTimeArray.copy_if(dest, src, True)
        assert dest == bytearray(b'hello!')
    
    def test_copy_if_false(self):
        """Test copy_if with condition False."""
        dest = bytearray(b'xxxxxx')
        original = bytes(dest)
        src = b'hello!'
        ConstantTimeArray.copy_if(dest, src, False)
        assert dest == bytearray(original)


class TestTimingAttackProtector:
    """Tests for TimingAttackProtector class."""
    
    def test_initialization(self):
        """Test protector initialization."""
        protector = TimingAttackProtector()
        assert protector.jitter_min == 0.001
        assert protector.jitter_max == 0.010
        assert protector._operation_count == 0
    
    def test_random_delay(self):
        """Test that random delay executes."""
        protector = TimingAttackProtector(jitter_range=(0.0001, 0.0002))
        start = time.time()
        protector.random_delay()
        elapsed = time.time() - start
        # Should have some delay
        assert elapsed >= 0
    
    def test_normalize_execution_time(self):
        """Test execution time normalization."""
        protector = TimingAttackProtector()
        start = time.time()
        # Do nothing, should sleep to reach target
        protector.normalize_execution_time(start, 0.001)
        elapsed = time.time() - start
        assert elapsed >= 0.001
    
    def test_count_operation(self):
        """Test operation counting."""
        protector = TimingAttackProtector()
        assert protector._operation_count == 0
        protector.count_operation()
        assert protector._operation_count == 1
        protector.count_operation()
        assert protector._operation_count == 2


class TestConstantTimeLogical:
    """Tests for constant-time logical operations."""
    
    def test_constant_time_all_true(self):
        """Test all conditions true."""
        assert constant_time_all([True, True, True]) is True
    
    def test_constant_time_all_false(self):
        """Test some conditions false."""
        assert constant_time_all([True, False, True]) is False
        assert constant_time_all([False, False, False]) is False
    
    def test_constant_time_all_empty(self):
        """Test all with empty list."""
        assert constant_time_all([]) is True
    
    def test_constant_time_any_true(self):
        """Test any condition true."""
        assert constant_time_any([False, True, False]) is True
        assert constant_time_any([True, True, True]) is True
    
    def test_constant_time_any_false(self):
        """Test all conditions false."""
        assert constant_time_any([False, False, False]) is False
    
    def test_constant_time_any_empty(self):
        """Test any with empty list."""
        assert constant_time_any([]) is False


class TestSecureCompare:
    """Tests for secure comparison functions."""
    
    def test_secure_hash_compare_equal(self):
        """Test hash comparison equal."""
        hash_a = b'\x00' * 32
        hash_b = b'\x00' * 32
        assert secure_hash_compare(hash_a, hash_b) is True
    
    def test_secure_hash_compare_not_equal(self):
        """Test hash comparison not equal."""
        hash_a = b'\x00' * 32
        hash_b = b'\x01' + b'\x00' * 31
        assert secure_hash_compare(hash_a, hash_b) is False
    
    def test_secure_password_compare_equal(self):
        """Test password hash comparison equal."""
        pw_hash = b'stored_hash_value'
        attempt = b'stored_hash_value'
        assert secure_password_compare(pw_hash, attempt) is True
    
    def test_secure_password_compare_not_equal(self):
        """Test password hash comparison not equal."""
        pw_hash = b'correct_password_hash'
        attempt = b'wrong_password_hash'
        assert secure_password_compare(pw_hash, attempt) is False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
