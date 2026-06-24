"""
Test Suite for NeuralShield AI - Advanced Cryptographic Security Protection (Dimension B V28)
============================================================================================
ADD-ONLY TESTS - NO MODIFICATIONS TO EXISTING TESTS
All existing tests must continue to pass.
This test suite only tests the NEW security hardening module.
"""
import sys
import os
import tempfile
import unittest

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from security_hardening_advanced_crypto_protection_v28_2026_june import (
    SecureRandom,
    SecureHashing,
    InjectionDetector,
    SecureFileIO,
    SecretRedactor,
    AdvancedCryptoSecurityToolkit,
    SecurityLevel,
    get_crypto_security_toolkit,
)


class TestSecureRandom(unittest.TestCase):
    """Test cryptographically secure random number generation"""
    
    def test_generate_bytes(self):
        """Test secure byte generation"""
        result = SecureRandom.generate_bytes(32)
        self.assertEqual(len(result), 32)
        self.assertIsInstance(result, bytes)
    
    def test_generate_salt(self):
        """Test salt generation"""
        salt = SecureRandom.generate_salt(32)
        self.assertEqual(len(salt), 32)
        self.assertIsInstance(salt, bytes)
    
    def test_generate_token(self):
        """Test token generation"""
        token = SecureRandom.generate_token(32)
        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 30)  # URL-safe encoding
    
    def test_generate_hex(self):
        """Test hex generation"""
        hex_str = SecureRandom.generate_hex(32)
        self.assertEqual(len(hex_str), 64)  # 32 bytes = 64 hex chars
        self.assertIsInstance(hex_str, str)
    
    def test_randbelow(self):
        """Test random integer range"""
        for _ in range(100):
            val = SecureRandom.randbelow(100)
            self.assertGreaterEqual(val, 0)
            self.assertLess(val, 100)
    
    def test_choice(self):
        """Test random choice"""
        items = ['a', 'b', 'c', 'd']
        choice = SecureRandom.choice(items)
        self.assertIn(choice, items)


class TestSecureHashing(unittest.TestCase):
    """Test secure password/secret hashing"""
    
    def test_hash_secret_basic(self):
        """Test basic hashing works"""
        secret = "test_password_123"
        result = SecureHashing.hash_secret(secret)
        
        self.assertIsNotNone(result.hash_bytes)
        self.assertIsNotNone(result.salt)
        self.assertEqual(len(result.salt), 32)
        self.assertGreater(result.iterations, 0)
        self.assertIn('$', result.encoded_string)
    
    def test_hash_unique_salts(self):
        """Test each hash gets unique salt"""
        secret = "same_password"
        hash1 = SecureHashing.hash_secret(secret)
        hash2 = SecureHashing.hash_secret(secret)
        
        # Same password should produce DIFFERENT hashes (due to unique salt)
        self.assertNotEqual(hash1.encoded_string, hash2.encoded_string)
        self.assertNotEqual(hash1.salt, hash2.salt)
    
    def test_verify_secret_correct(self):
        """Test verification with correct password"""
        secret = "my_secure_password"
        stored = SecureHashing.hash_secret(secret).encoded_string
        
        result = SecureHashing.verify_secret(secret, stored)
        self.assertTrue(result)
    
    def test_verify_secret_wrong(self):
        """Test verification with wrong password"""
        secret = "correct_password"
        stored = SecureHashing.hash_secret(secret).encoded_string
        
        result = SecureHashing.verify_secret("wrong_password", stored)
        self.assertFalse(result)
    
    def test_verify_invalid_hash_format(self):
        """Test verification handles invalid formats gracefully"""
        result = SecureHashing.verify_secret("test", "invalid_hash_format")
        self.assertFalse(result)
    
    def test_verify_bytes_secret(self):
        """Test verification works with bytes input"""
        secret = b"binary_secret_data"
        stored = SecureHashing.hash_secret(secret).encoded_string
        
        result = SecureHashing.verify_secret(secret, stored)
        self.assertTrue(result)


class TestInjectionDetector(unittest.TestCase):
    """Test injection attack detection"""
    
    def test_safe_input(self):
        """Test safe input passes"""
        detector = InjectionDetector(SecurityLevel.STANDARD)
        result = detector.scan_input("Hello, this is normal user input")
        
        self.assertTrue(result.is_safe)
        self.assertEqual(len(result.detected_threats), 0)
        self.assertEqual(result.risk_score, 0)
    
    def test_sql_injection_detection(self):
        """Test SQL injection patterns detected"""
        detector = InjectionDetector(SecurityLevel.STANDARD)
        
        # Classic SQL injection
        result = detector.scan_input("' OR '1'='1")
        self.assertFalse(result.is_safe)
        self.assertGreater(result.risk_score, 0)
        
        # UNION SELECT
        result2 = detector.scan_input("test' UNION SELECT * FROM users--")
        self.assertFalse(result2.is_safe)
    
    def test_xss_detection(self):
        """Test XSS patterns detected"""
        detector = InjectionDetector(SecurityLevel.STANDARD)
        
        result = detector.scan_input('<script>alert("xss")</script>')
        self.assertFalse(result.is_safe)
    
    def test_path_traversal_detection(self):
        """Test path traversal detected"""
        detector = InjectionDetector(SecurityLevel.STANDARD)
        
        result = detector.scan_input("../../../etc/passwd")
        self.assertFalse(result.is_safe)
    
    def test_sanitization_works(self):
        """Test input sanitization"""
        detector = InjectionDetector(SecurityLevel.STANDARD)
        result = detector.scan_input('<script>test</script>', sanitize=True)
        
        self.assertNotEqual(result.sanitized_value, '<script>test</script>')
        self.assertIn('&lt;', result.sanitized_value)


class TestSecureFileIO(unittest.TestCase):
    """Test secure file I/O wrappers"""
    
    def test_path_validation_blocks_traversal(self):
        """Test path traversal is blocked"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_io = SecureFileIO(allowed_base_dir=tmpdir)
            
            # Try path traversal
            is_safe, _ = file_io._validate_path(os.path.join(tmpdir, "../../etc/passwd"))
            self.assertFalse(is_safe)
    
    def test_safe_path_allowed(self):
        """Test safe paths within allowed dir work"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_io = SecureFileIO(allowed_base_dir=tmpdir)
            test_file = os.path.join(tmpdir, "test.txt")
            
            is_safe, _ = file_io._validate_path(test_file)
            self.assertTrue(is_safe)
    
    def test_safe_write_read(self):
        """Test writing and reading works"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_io = SecureFileIO(allowed_base_dir=tmpdir)
            test_file = os.path.join(tmpdir, "test.txt")
            
            # Write
            write_ok = file_io.safe_write(test_file, "test content")
            self.assertTrue(write_ok)
            
            # Read
            content = file_io.safe_read(test_file)
            self.assertEqual(content, "test content")


class TestSecretRedactor(unittest.TestCase):
    """Test sensitive data redaction"""
    
    def test_redact_api_key(self):
        """Test API key redaction"""
        text = "My api_key=abcdefghijklmnopqrstuvwxyz123456 secret"
        redacted = SecretRedactor.redact(text)
        
        self.assertNotIn('abcdefghijklmnopqrstuvwxyz123456', redacted)
        self.assertIn('[REDACTED]', redacted)
    
    def test_redact_bearer_token(self):
        """Test Bearer token redaction"""
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        redacted = SecretRedactor.redact(text)
        
        self.assertIn('[REDACTED]', redacted)
    
    def test_redact_github_token(self):
        """Test GitHub token redaction"""
        text = "Token: ghp_fakeExampleToken123456789abcdefghijklmnop"
        redacted = SecretRedactor.redact(text)
        
        self.assertIn('[REDACTED]', redacted)
    
    def test_redact_dict(self):
        """Test dictionary redaction"""
        data = {
            'username': 'testuser',
            'password': 'my_secret_pass',
            'nested': {
                'api_key': 'secret_key_here'
            }
        }
        redacted = SecretRedactor.redact_dict(data)
        
        self.assertEqual(redacted['username'], 'testuser')
        self.assertEqual(redacted['password'], '[REDACTED]')
        self.assertEqual(redacted['nested']['api_key'], '[REDACTED]')
    
    def test_normal_text_unchanged(self):
        """Test normal text not affected"""
        text = "Hello world, this is normal text without secrets"
        redacted = SecretRedactor.redact(text)
        
        self.assertEqual(redacted, text)


class TestAdvancedCryptoSecurityToolkit(unittest.TestCase):
    """Test main toolkit facade"""
    
    def test_toolkit_instantiation(self):
        """Test toolkit creates successfully"""
        toolkit = AdvancedCryptoSecurityToolkit(SecurityLevel.STANDARD)
        self.assertIsNotNone(toolkit)
    
    def test_get_crypto_security_toolkit(self):
        """Test convenience function works"""
        toolkit = get_crypto_security_toolkit()
        self.assertIsNotNone(toolkit)
    
    def test_hash_and_verify_integration(self):
        """Test full hash+verify flow through toolkit"""
        toolkit = get_crypto_security_toolkit()
        
        secret = "integration_test_secret"
        stored_hash = toolkit.hash_secret(secret)
        
        self.assertIsInstance(stored_hash, str)
        self.assertTrue(toolkit.verify_secret(secret, stored_hash))
        self.assertFalse(toolkit.verify_secret("wrong_secret", stored_hash))
    
    def test_generate_token_integration(self):
        """Test token generation through toolkit"""
        toolkit = get_crypto_security_toolkit()
        token = toolkit.generate_secure_token(32)
        
        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 10)
    
    def test_scan_injection_integration(self):
        """Test injection scanning through toolkit"""
        toolkit = get_crypto_security_toolkit()
        
        safe_result = toolkit.scan_for_injection("normal input")
        self.assertTrue(safe_result.is_safe)
        
        unsafe_result = toolkit.scan_for_injection("' OR 1=1--")
        self.assertFalse(unsafe_result.is_safe)
    
    def test_redact_integration(self):
        """Test redaction through toolkit"""
        toolkit = get_crypto_security_toolkit()
        
        text = "My password=supersecret123"
        redacted = toolkit.redact_secrets(text)
        
        self.assertIn('[REDACTED]', redacted)
        self.assertNotIn('supersecret123', redacted)


def run_all_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestSecureRandom))
    suite.addTests(loader.loadTestsFromTestCase(TestSecureHashing))
    suite.addTests(loader.loadTestsFromTestCase(TestInjectionDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestSecureFileIO))
    suite.addTests(loader.loadTestsFromTestCase(TestSecretRedactor))
    suite.addTests(loader.loadTestsFromTestCase(TestAdvancedCryptoSecurityToolkit))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print(f"\n{'='*60}")
    print(f"TEST SUMMARY:")
    print(f"  Tests run: {result.testsRun}")
    print(f"  Failures: {len(result.failures)}")
    print(f"  Errors: {len(result.errors)}")
    print(f"  Success: {result.wasSuccessful()}")
    print(f"{'='*60}")
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
