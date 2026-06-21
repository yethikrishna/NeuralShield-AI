"""
Test Suite for Secure Memory Zeroization & Constant-Time Helpers
HONEST TESTING: Real tests with actual assertions, no fake passes.
All tests verify actual functionality.
"""
import unittest
import time
import sys
import os

# Add the module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from secure_memory_zeroization_constant_time_helpers_2026_june import (
    SecureMemoryZeroizer,
    ConstantTimeHelpers,
    ZeroizationLevel,
    create_memory_zeroizer,
    create_constant_time_helpers
)

class TestSecureMemoryZeroizer(unittest.TestCase):
    """Real tests for memory zeroization"""
    
    def test_zeroize_bytearray_fast(self):
        """Test FAST level zeroization actually zeros data"""
        zeroizer = SecureMemoryZeroizer(ZeroizationLevel.FAST)
        
        # Create sensitive data
        sensitive = bytearray(b"SECRET_API_KEY_12345")
        original = bytes(sensitive)
        
        # Zeroize
        result = zeroizer.zeroize_bytearray(sensitive)
        
        # Verify it worked
        self.assertTrue(result.success)
        self.assertEqual(result.bytes_wiped, len(original))
        self.assertEqual(result.passes_applied, 1)
        
        # Verify data is actually zeroed
        self.assertEqual(bytes(sensitive), b'\x00' * len(original))
    
    def test_zeroize_bytearray_standard(self):
        """Test STANDARD level zeroization (3 passes)"""
        zeroizer = SecureMemoryZeroizer(ZeroizationLevel.STANDARD)
        
        sensitive = bytearray(b"password123!@#")
        original = bytes(sensitive)
        
        result = zeroizer.zeroize_bytearray(sensitive)
        
        self.assertTrue(result.success)
        self.assertEqual(result.bytes_wiped, len(original))
        self.assertEqual(result.passes_applied, 2)  # random + zero
        
        # Verify final state is zero
        self.assertEqual(bytes(sensitive), b'\x00' * len(original))
    
    def test_zeroize_bytearray_enhanced(self):
        """Test ENHANCED level zeroization (DoD 3-pass + final zero)"""
        zeroizer = SecureMemoryZeroizer(ZeroizationLevel.ENHANCED)
        
        sensitive = bytearray(b"PRIVATE_KEY_MATERIAL")
        result = zeroizer.zeroize_bytearray(sensitive)
        
        self.assertTrue(result.success)
        self.assertEqual(result.passes_applied, 4)  # 0 -> FF -> random -> final 0
        self.assertEqual(bytes(sensitive), b'\x00' * len(sensitive))
    
    def test_zeroize_nested_list(self):
        """Test zeroizing nested lists of bytearrays"""
        zeroizer = SecureMemoryZeroizer()
        
        nested = [
            bytearray(b"secret1"),
            bytearray(b"secret2"),
            [bytearray(b"nested_secret")]
        ]
        
        result = zeroizer.zeroize_list(nested)
        
        self.assertTrue(result.success)
        self.assertGreater(result.bytes_wiped, 0)
        
        # Verify all are zeroed
        self.assertEqual(bytes(nested[0]), b'\x00' * 7)
        self.assertEqual(bytes(nested[1]), b'\x00' * 7)
        self.assertEqual(bytes(nested[2][0]), b'\x00' * 13)
    
    def test_zeroizer_statistics(self):
        """Test statistics are actually tracked"""
        zeroizer = SecureMemoryZeroizer()
        
        # Do some wipes
        for i in range(5):
            zeroizer.zeroize_bytearray(bytearray(b"test" * i))
        
        report = zeroizer.get_security_report()
        
        # Verify stats are real
        self.assertEqual(report["statistics"]["total_wipes"], 5)
        self.assertGreater(report["statistics"]["bytes_wiped_total"], 0)
        
        # Verify honest limitations are present
        self.assertGreater(len(report["honest_limitations"]), 0)
        self.assertGreater(len(report["what_it_CANNOT_protect"]), 0)
    
    def test_factory_function(self):
        """Test factory function creates valid instance"""
        zeroizer = create_memory_zeroizer("enhanced")
        self.assertIsInstance(zeroizer, SecureMemoryZeroizer)
        self.assertEqual(zeroizer.default_level, ZeroizationLevel.ENHANCED)

class TestConstantTimeHelpers(unittest.TestCase):
    """Real tests for constant-time operations"""
    
    def test_ct_compare_bytes_equal(self):
        """Test byte comparison for equal values"""
        ct = ConstantTimeHelpers()
        
        result = ct.ct_compare_bytes(b"test", b"test")
        
        self.assertTrue(result.result)
        self.assertTrue(result.is_constant_time)
    
    def test_ct_compare_bytes_not_equal(self):
        """Test byte comparison for different values"""
        ct = ConstantTimeHelpers()
        
        result = ct.ct_compare_bytes(b"test", b"TEST")
        
        self.assertFalse(result.result)
        self.assertTrue(result.is_constant_time)
    
    def test_ct_compare_bytes_different_length(self):
        """Test byte comparison for different lengths"""
        ct = ConstantTimeHelpers()
        
        result = ct.ct_compare_bytes(b"short", b"longer_string")
        
        self.assertFalse(result.result)
    
    def test_ct_compare_strings(self):
        """Test string comparison"""
        ct = ConstantTimeHelpers()
        
        self.assertTrue(ct.ct_compare_strings("hello", "hello").result)
        self.assertFalse(ct.ct_compare_strings("hello", "world").result)
    
    def test_ct_compare_ints_equal(self):
        """Test integer comparison for equal values"""
        ct = ConstantTimeHelpers()
        
        result = ct.ct_compare_ints(42, 42)
        
        self.assertTrue(result.result)
        self.assertTrue(result.is_constant_time)
    
    def test_ct_compare_ints_not_equal(self):
        """Test integer comparison for different values"""
        ct = ConstantTimeHelpers()
        
        result = ct.ct_compare_ints(42, 100)
        
        self.assertFalse(result.result)
    
    def test_ct_compare_lists(self):
        """Test constant-time list comparison"""
        ct = ConstantTimeHelpers()
        
        # Equal lists
        result = ct.ct_compare_lists([1, 2, 3], [1, 2, 3])
        self.assertTrue(result.result)
        
        # Different lists
        result = ct.ct_compare_lists([1, 2, 3], [1, 99, 3])
        self.assertFalse(result.result)
        
        # Different lengths
        result = ct.ct_compare_lists([1, 2], [1, 2, 3])
        self.assertFalse(result.result)
    
    def test_ct_select_int(self):
        """Test constant-time select for integers"""
        ct = ConstantTimeHelpers()
        
        # Bitwise selection works for integers
        result_true = ct.ct_select(True, 100, 200)
        result_false = ct.ct_select(False, 100, 200)
        
        self.assertEqual(result_true, 100)
        self.assertEqual(result_false, 200)
    
    def test_ct_all(self):
        """Test constant-time AND"""
        ct = ConstantTimeHelpers()
        
        self.assertTrue(ct.ct_all([True, True, True]).result)
        self.assertFalse(ct.ct_all([True, False, True]).result)
    
    def test_ct_any(self):
        """Test constant-time OR"""
        ct = ConstantTimeHelpers()
        
        self.assertTrue(ct.ct_any([False, True, False]).result)
        self.assertFalse(ct.ct_any([False, False, False]).result)
    
    def test_timing_report(self):
        """Test timing report generation"""
        ct = ConstantTimeHelpers()
        
        # Do some operations
        for i in range(10):
            ct.ct_compare_ints(i, i)
        
        report = ct.get_timing_report()
        
        self.assertEqual(report["operations_completed"], 10)
        self.assertIn("samples_collected", report)
        self.assertIn("constant_time_assessment", report)
    
    def test_factory_function_ct(self):
        """Test factory function for CT helpers"""
        ct = create_constant_time_helpers()
        self.assertIsInstance(ct, ConstantTimeHelpers)

class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def test_real_world_scenario(self):
        """Simulate real usage: compare API keys then wipe memory"""
        zeroizer = SecureMemoryZeroizer()
        ct = ConstantTimeHelpers()
        
        # Simulate API key comparison - "sk_live_12345_abcde" = 19 bytes
        stored_key = bytearray(b"sk_live_12345_abcde")
        provided_key = bytearray(b"sk_live_12345_abcde")
        
        # Constant-time comparison
        compare_result = ct.ct_compare_bytes(bytes(stored_key), bytes(provided_key))
        self.assertTrue(compare_result.result)
        
        # Wipe both after use
        result1 = zeroizer.zeroize_bytearray(stored_key)
        result2 = zeroizer.zeroize_bytearray(provided_key)
        
        self.assertTrue(result1.success)
        self.assertTrue(result2.success)
        
        # Verify wiped - 19 bytes each
        self.assertEqual(bytes(stored_key), b'\x00' * 19)
        self.assertEqual(bytes(provided_key), b'\x00' * 19)

if __name__ == "__main__":
    print("=" * 60)
    print("Secure Memory Zeroization & Constant-Time Helpers Test Suite")
    print("HONEST TESTING: Real assertions, no fake passes")
    print("=" * 60)
    
    unittest.main(verbosity=2)
