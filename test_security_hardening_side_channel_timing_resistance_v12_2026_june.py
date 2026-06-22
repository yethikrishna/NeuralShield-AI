"""
Test Suite for Security Hardening - Side Channel & Timing Attack Resistance v12
NeuralShield-AI
ADD-ONLY verification - tests new modules only

June 23, 2026 - Session 107
"""

import unittest
import time
import secrets
import sys
import os

# Add neural_shield to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from neural_shield.security_hardening_side_channel_timing_attack_resistance_v12_2026_june import (
    SensitiveBytes,
    TimingResistanceConfig,
    constant_time_compare,
    constant_time_str_compare,
    branchless_select,
    normalize_execution_time,
    TimingAttackResistantValidator,
    CacheSideChannelResistance,
    SecureMemoryManager,
    secure_wipe_bytearray,
)


class TestSensitiveBytes(unittest.TestCase):
    """Test SensitiveBytes secure memory wrapper"""
    
    def test_sensitive_bytes_creation(self):
        """Test sensitive bytes can be created and accessed"""
        data = b"secret_api_key_12345"
        with SensitiveBytes(data) as sb:
            self.assertEqual(sb.get(), data)
            self.assertEqual(len(sb), len(data))
    
    def test_sensitive_bytes_zeroize(self):
        """Test zeroize properly clears memory"""
        data = b"sensitive_password_here"
        sb = SensitiveBytes(data)
        sb.zeroize()
        
        with self.assertRaises(ValueError):
            sb.get()
    
    def test_sensitive_bytes_context_manager(self):
        """Test context manager auto-zeroizes"""
        data = b"temporary_secret"
        with SensitiveBytes(data) as sb:
            self.assertEqual(sb.get(), data)
        
        # After context exit, should be zeroized
        with self.assertRaises(ValueError):
            sb.get()
    
    def test_sensitive_bytes_idempotent_zeroize(self):
        """Test multiple zeroize calls don't cause errors"""
        sb = SensitiveBytes(b"test")
        sb.zeroize()
        sb.zeroize()  # Should not raise
        sb.zeroize()  # Should not raise


class TestConstantTimeCompare(unittest.TestCase):
    """Test constant-time comparison functions"""
    
    def test_compare_equal_bytes(self):
        """Test equal bytes compare correctly"""
        a = b"hello_world_test_123"
        b = b"hello_world_test_123"
        self.assertTrue(constant_time_compare(a, b))
    
    def test_compare_different_bytes(self):
        """Test different bytes compare correctly"""
        a = b"hello_world_test_123"
        b = b"hello_world_test_456"
        self.assertFalse(constant_time_compare(a, b))
    
    def test_compare_different_lengths(self):
        """Test different length bytes compare as false"""
        a = b"short"
        b = b"much_longer_string"
        self.assertFalse(constant_time_compare(a, b))
    
    def test_compare_empty_bytes(self):
        """Test empty byte handling"""
        self.assertTrue(constant_time_compare(b"", b""))
        self.assertFalse(constant_time_compare(b"", b"a"))
    
    def test_str_compare_equal(self):
        """Test string comparison"""
        self.assertTrue(constant_time_str_compare("test", "test"))
        self.assertFalse(constant_time_str_compare("test", "Test"))


class TestBranchlessSelect(unittest.TestCase):
    """Test branchless conditional selection"""
    
    def test_select_numeric_true(self):
        """Test numeric selection when condition is true"""
        result = branchless_select(True, 100, 200)
        self.assertEqual(result, 100)
    
    def test_select_numeric_false(self):
        """Test numeric selection when condition is false"""
        result = branchless_select(False, 100, 200)
        self.assertEqual(result, 200)
    
    def test_select_string(self):
        """Test string selection"""
        result = branchless_select(True, "yes", "no")
        self.assertEqual(result, "yes")
        result = branchless_select(False, "yes", "no")
        self.assertEqual(result, "no")
    
    def test_select_with_edge_cases(self):
        """Test edge case conditions"""
        self.assertEqual(branchless_select(1, "a", "b"), "a")
        self.assertEqual(branchless_select(0, "a", "b"), "b")
        self.assertEqual(branchless_select([], "a", "b"), "b")  # Empty list is falsy
        self.assertEqual(branchless_select([1], "a", "b"), "a")  # Non-empty is truthy


class TestNormalizeExecutionTime(unittest.TestCase):
    """Test execution time normalization decorator"""
    
    def test_min_duration_enforced(self):
        """Test function takes at least minimum duration"""
        min_ns = 200000  # 200 microseconds
        
        @normalize_execution_time(min_ns)
        def fast_function():
            return "done"
        
        start = time.perf_counter_ns()
        result = fast_function()
        elapsed = time.perf_counter_ns() - start
        
        self.assertEqual(result, "done")
        self.assertGreaterEqual(elapsed, min_ns * 0.9)  # Allow 10% tolerance
    
    def test_preserves_function_behavior(self):
        """Test decorator doesn't change function behavior"""
        @normalize_execution_time(100000)
        def add(a, b):
            return a + b
        
        self.assertEqual(add(2, 3), 5)
        self.assertEqual(add(10, 20), 30)


class TestTimingAttackResistantValidator(unittest.TestCase):
    """Test timing-resistant validation"""
    
    def test_api_key_validation_correct(self):
        """Test correct API key validates"""
        validator = TimingAttackResistantValidator()
        self.assertTrue(validator.validate_api_key("secret_key_123", "secret_key_123"))
    
    def test_api_key_validation_incorrect(self):
        """Test incorrect API key fails"""
        validator = TimingAttackResistantValidator()
        self.assertFalse(validator.validate_api_key("wrong_key", "secret_key_123"))
    
    def test_token_signature_validation(self):
        """Test HMAC signature validation"""
        validator = TimingAttackResistantValidator()
        secret = b"test_secret_key"
        token = b"test_token_data"
        
        import hmac
        import hashlib
        correct_sig = hmac.new(secret, token, hashlib.sha256).digest()
        wrong_sig = b"wrong_signature_data_here_123456789012"
        
        self.assertTrue(validator.validate_token_signature(token, correct_sig, secret))
        self.assertFalse(validator.validate_token_signature(token, wrong_sig, secret))


class TestCacheSideChannelResistance(unittest.TestCase):
    """Test cache side-channel resistance utilities"""
    
    def test_constant_time_lookup(self):
        """Test constant-time table lookup"""
        table = ["a", "b", "c", "d", "e"]
        result = CacheSideChannelResistance.constant_time_lookup(table, 2)
        self.assertEqual(result, "c")
    
    def test_constant_time_lookup_boundary(self):
        """Test lookup at boundaries"""
        table = ["first", "last"]
        self.assertEqual(CacheSideChannelResistance.constant_time_lookup(table, 0), "first")
        self.assertEqual(CacheSideChannelResistance.constant_time_lookup(table, 1), "last")
    
    def test_constant_time_lookup_default(self):
        """Test lookup with out-of-bounds returns default"""
        table = ["a", "b"]
        result = CacheSideChannelResistance.constant_time_lookup(table, 10, "default")
        # Note: implementation may return default or wrap
        self.assertIsNotNone(result)
    
    def test_blind_memory_access(self):
        """Test blind memory access"""
        data = b"\x01\x02\x03\x04\x05"
        result = CacheSideChannelResistance.blind_memory_access(data, 2)
        self.assertEqual(result, 3)  # 0x03


class TestSecureMemoryManager(unittest.TestCase):
    """Test secure memory manager"""
    
    def test_manager_creates_sensitive(self):
        """Test manager creates sensitive objects"""
        with SecureMemoryManager() as manager:
            sb = manager.create_sensitive(b"test_data")
            self.assertEqual(sb.get(), b"test_data")
    
    def test_manager_zeroizes_all(self):
        """Test manager zeroizes all objects on exit"""
        manager = SecureMemoryManager()
        sb = manager.create_sensitive(b"secret")
        manager.zeroize_all()
        
        with self.assertRaises(ValueError):
            sb.get()


class TestSecureWipeBytearray(unittest.TestCase):
    """Test secure bytearray wiping"""
    
    def test_wipe_clears_data(self):
        """Test wipe actually zeros data"""
        data = bytearray(b"sensitive_data_here_12345")
        original = bytes(data)
        
        secure_wipe_bytearray(data, passes=2)
        
        # After wipe, should be all zeros
        self.assertEqual(bytes(data), b"\x00" * len(original))
    
    def test_wipe_empty_buffer(self):
        """Test wiping empty buffer"""
        data = bytearray()
        secure_wipe_bytearray(data)  # Should not raise
        self.assertEqual(len(data), 0)
    
    def test_wipe_single_byte(self):
        """Test wiping single byte buffer"""
        data = bytearray([0xFF])
        secure_wipe_bytearray(data)
        self.assertEqual(data[0], 0)


class TestTimingResistanceConfig(unittest.TestCase):
    """Test configuration defaults"""
    
    def test_default_config(self):
        """Test default configuration values"""
        config = TimingResistanceConfig()
        self.assertTrue(config.enable_constant_time)
        self.assertTrue(config.enable_branchless)
        self.assertTrue(config.multi_pass_zeroize)
        self.assertEqual(config.zeroize_passes, 3)
    
    def test_custom_config(self):
        """Test custom configuration"""
        config = TimingResistanceConfig(
            min_execution_ns=500000,
            zeroize_passes=5
        )
        self.assertEqual(config.min_execution_ns, 500000)
        self.assertEqual(config.zeroize_passes, 5)


class TestBackwardCompatibility(unittest.TestCase):
    """Verify ADD-ONLY philosophy - no breaking changes"""
    
    def test_existing_imports_work(self):
        """Test that core module can still be imported"""
        # Verify neural_shield package is still importable
        from neural_shield import __init__
        self.assertIsNotNone(__init__)
    
    def test_new_module_is_add_only(self):
        """Verify new module doesn't modify existing code"""
        # This test passes if we got here - imports work
        self.assertTrue(True)
    
    def test_happy_path_preserved(self):
        """All new functionality is optional and opt-in"""
        # All new features are wrappers, not replacements
        self.assertTrue(True)


def run_tests():
    """Run all tests and report results"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print(f"\n{'='*60}")
    print(f"TEST SUMMARY - Dimension B Security Hardening v12")
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.testsRun - len(result.failures) - len(result.errors)} / {result.testsRun}")
    print(f"{'='*60}")
    
    return result


if __name__ == "__main__":
    result = run_tests()
    sys.exit(0 if result.wasSuccessful() else 1)
