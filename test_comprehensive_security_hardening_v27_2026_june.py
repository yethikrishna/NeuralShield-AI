"""
Test Suite for NeuralShield Enhanced Security Protection Layer (Dimension B - Security Hardening)
=================================================================================================
ADD-ONLY TESTS - NO modifications to production source code.
Tests all new security hardening features:
  - Path traversal protection
  - SQL/NoSQL injection protection
  - Secure random generation
  - XSS protection
  - File content validation
  - Security headers

All existing tests must continue to pass.
"""
import os
import sys
import unittest
import tempfile
import threading
from typing import Optional

# Add neural_shield to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from security_hardening_enhanced_protection_layer_v27_2026_june import (
    ProtectionLevel,
    SecurityCheckResult,
    PathTraversalProtector,
    SQLInjectionProtector,
    SecureRandomGenerator,
    XSSProtector,
    FileContentValidator,
    SecurityHeaderManager,
    EnhancedSecurityLayer,
    get_enhanced_security_layer,
)


class TestProtectionLevel(unittest.TestCase):
    """Test ProtectionLevel enum"""
    
    def test_protection_level_values(self):
        self.assertEqual(ProtectionLevel.BASIC, 1)
        self.assertEqual(ProtectionLevel.STANDARD, 2)
        self.assertEqual(ProtectionLevel.STRICT, 3)
        self.assertEqual(ProtectionLevel.PARANOID, 4)
    
    def test_protection_level_ordering(self):
        self.assertLess(ProtectionLevel.BASIC, ProtectionLevel.STANDARD)
        self.assertLess(ProtectionLevel.STANDARD, ProtectionLevel.STRICT)
        self.assertLess(ProtectionLevel.STRICT, ProtectionLevel.PARANOID)


class TestSecurityCheckResult(unittest.TestCase):
    """Test SecurityCheckResult dataclass"""
    
    def test_default_values(self):
        result = SecurityCheckResult(is_safe=True)
        self.assertTrue(result.is_safe)
        self.assertEqual(result.threats_detected, [])
        self.assertIsNone(result.sanitized_value)
        self.assertEqual(result.warnings, [])
        self.assertEqual(result.confidence_score, 1.0)
    
    def test_custom_values(self):
        result = SecurityCheckResult(
            is_safe=False,
            threats_detected=["test threat"],
            sanitized_value="clean",
            warnings=["test warning"],
            confidence_score=0.8
        )
        self.assertFalse(result.is_safe)
        self.assertEqual(result.threats_detected, ["test threat"])
        self.assertEqual(result.sanitized_value, "clean")
        self.assertEqual(result.warnings, ["test warning"])
        self.assertEqual(result.confidence_score, 0.8)


class TestPathTraversalProtector(unittest.TestCase):
    """Test path traversal protection"""
    
    def setUp(self):
        self.protector = PathTraversalProtector(base_directory=tempfile.gettempdir())
    
    def test_safe_path(self):
        result = self.protector.is_safe_path("safe_file.txt")
        self.assertTrue(result.is_safe)
        self.assertEqual(result.threats_detected, [])
    
    def test_path_traversal_attack(self):
        attacks = [
            "../etc/passwd",
            "..\\..\\windows\\system32",
            "subdir/../../../etc/passwd",
            "%2e%2e/%2e%2e/etc/passwd",
        ]
        for attack in attacks:
            result = self.protector.is_safe_path(attack)
            self.assertFalse(result.is_safe, f"Should detect attack: {attack}")
            self.assertGreater(len(result.threats_detected), 0)
    
    def test_absolute_path_rejected(self):
        result = self.protector.is_safe_path("/etc/passwd", allow_absolute=False)
        self.assertFalse(result.is_safe)
    
    def test_absolute_path_allowed(self):
        result = self.protector.is_safe_path("/etc/passwd", allow_absolute=True)
        # May still fail due to other checks, but should not fail on absolute path alone
        self.assertNotIn("Absolute path not allowed", result.threats_detected)
    
    def test_safe_join(self):
        is_safe, path = self.protector.safe_join("subdir", "file.txt")
        self.assertTrue(is_safe)
        self.assertIsNotNone(path)
    
    def test_unsafe_join(self):
        is_safe, path = self.protector.safe_join("../../../etc", "passwd")
        self.assertFalse(is_safe)
        self.assertIsNone(path)


class TestSQLInjectionProtector(unittest.TestCase):
    """Test SQL injection protection"""
    
    def setUp(self):
        self.protector = SQLInjectionProtector()
    
    def test_safe_input(self):
        result = self.protector.check_sql_injection("normal user input")
        self.assertTrue(result.is_safe)
        self.assertEqual(result.threats_detected, [])
    
    def test_sql_injection_detection(self):
        attacks = [
            "' OR '1'='1",
            "admin' --",
            "UNION SELECT username, password FROM users--",
            "1; DROP TABLE users--",
            "1' WAITFOR DELAY '0:0:5'--",
        ]
        for attack in attacks:
            result = self.protector.check_sql_injection(attack)
            self.assertFalse(result.is_safe, f"Should detect SQL injection: {attack}")
            self.assertGreater(len(result.threats_detected), 0)
    
    def test_nosql_injection_detection(self):
        attacks = [
            '{"$gt": ""}',
            '{"$where": "this.password.match(/^a/)"}',
        ]
        for attack in attacks:
            result = self.protector.check_nosql_injection(attack)
            self.assertFalse(result.is_safe, f"Should detect NoSQL injection: {attack}")
            self.assertGreater(len(result.threats_detected), 0)
    
    def test_sanitize_sql_input(self):
        dangerous = "'; DROP TABLE users--"
        sanitized = self.protector.sanitize_sql_input(dangerous)
        self.assertNotIn(";", sanitized)
        self.assertNotIn("--", sanitized)


class TestSecureRandomGenerator(unittest.TestCase):
    """Test secure random generation"""
    
    def test_generate_token(self):
        token1 = SecureRandomGenerator.generate_token(32)
        token2 = SecureRandomGenerator.generate_token(32)
        self.assertIsInstance(token1, str)
        self.assertNotEqual(token1, token2)
        self.assertGreater(len(token1), 0)
    
    def test_generate_hex(self):
        hex_str = SecureRandomGenerator.generate_hex(16)
        self.assertIsInstance(hex_str, str)
        self.assertEqual(len(hex_str), 32)  # 16 bytes = 32 hex chars
    
    def test_random_bytes(self):
        bytes_val = SecureRandomGenerator.random_bytes(32)
        self.assertIsInstance(bytes_val, bytes)
        self.assertEqual(len(bytes_val), 32)
    
    def test_random_int(self):
        for _ in range(100):
            val = SecureRandomGenerator.random_int(0, 100)
            self.assertGreaterEqual(val, 0)
            self.assertLessEqual(val, 100)
    
    def test_choice(self):
        options = ['a', 'b', 'c', 'd']
        chosen = SecureRandomGenerator.choice(options)
        self.assertIn(chosen, options)
    
    def test_compare_digest(self):
        self.assertTrue(SecureRandomGenerator.compare_digest("test", "test"))
        self.assertFalse(SecureRandomGenerator.compare_digest("test", "TEST"))
        self.assertTrue(SecureRandomGenerator.compare_digest(b"bytes", b"bytes"))


class TestXSSProtector(unittest.TestCase):
    """Test XSS protection"""
    
    def setUp(self):
        self.protector = XSSProtector()
    
    def test_encode_html(self):
        dangerous = '<script>alert("xss")</script>'
        encoded = self.protector.encode_html(dangerous)
        self.assertNotIn('<script>', encoded)
        self.assertIn('&lt;script&gt;', encoded)
    
    def test_encode_attribute(self):
        dangerous = '" onclick="alert(1)"'
        encoded = self.protector.encode_attribute(dangerous)
        self.assertNotIn('"', encoded)
    
    def test_encode_javascript(self):
        dangerous = '</script><script>alert(1)</script>'
        encoded = self.protector.encode_javascript(dangerous)
        self.assertNotIn('</script>', encoded)
    
    def test_dangerous_html_detection(self):
        dangerous = '<script>alert("xss")</script>'
        result = self.protector.sanitize_html_content(dangerous)
        self.assertFalse(result.is_safe)
        self.assertGreater(len(result.threats_detected), 0)


class TestFileContentValidator(unittest.TestCase):
    """Test file content validation"""
    
    def setUp(self):
        self.validator = FileContentValidator(max_file_size=1000)
    
    def test_valid_image_content(self):
        # Valid PNG header
        png_content = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100
        result = self.validator.validate_file_content(png_content)
        self.assertTrue(result.is_safe)
    
    def test_file_too_large(self):
        large_content = b'\x00' * 2000
        result = self.validator.validate_file_content(large_content)
        self.assertFalse(result.is_safe)
        self.assertIn("File too large", result.threats_detected[0])
    
    def test_executable_detection(self):
        elf_content = b'\x7fELF' + b'\x00' * 100
        self.assertTrue(self.validator.is_executable_content(elf_content))
        
        pe_content = b'MZ' + b'\x00' * 100
        self.assertTrue(self.validator.is_executable_content(pe_content))
        
        script_content = b'#!/bin/bash\n'
        self.assertTrue(self.validator.is_executable_content(script_content))
    
    def test_allowed_mime_types(self):
        validator = FileContentValidator(allowed_mime_types=['image/png'])
        png_content = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100
        result = validator.validate_file_content(png_content)
        self.assertTrue(result.is_safe)


class TestSecurityHeaderManager(unittest.TestCase):
    """Test security header utilities"""
    
    def test_get_secure_headers(self):
        headers = SecurityHeaderManager.get_secure_headers()
        self.assertIsInstance(headers, dict)
        self.assertIn('X-Content-Type-Options', headers)
        self.assertIn('X-Frame-Options', headers)
        self.assertIn('X-XSS-Protection', headers)
        self.assertIn('Content-Security-Policy', headers)
    
    def test_sanitize_header_value(self):
        dangerous = "value\r\nSet-Cookie: injected=1"
        sanitized = SecurityHeaderManager.sanitize_header_value(dangerous)
        self.assertNotIn('\r', sanitized)
        self.assertNotIn('\n', sanitized)


class TestEnhancedSecurityLayer(unittest.TestCase):
    """Test main EnhancedSecurityLayer facade"""
    
    def setUp(self):
        self.security = EnhancedSecurityLayer()
    
    def test_get_instance(self):
        self.assertIsNotNone(self.security)
        self.assertIsNotNone(self.security.path_protector)
        self.assertIsNotNone(self.security.sql_protector)
        self.assertIsNotNone(self.security.random)
        self.assertIsNotNone(self.security.xss_protector)
        self.assertIsNotNone(self.security.file_validator)
        self.assertIsNotNone(self.security.headers)
    
    def test_validate_file_upload(self):
        png_content = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100
        result = self.security.validate_file_upload(png_content, "test.png")
        self.assertTrue(result.is_safe)
    
    def test_validate_file_upload_traversal(self):
        png_content = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100
        result = self.security.validate_file_upload(png_content, "../../etc/passwd")
        self.assertFalse(result.is_safe)
    
    def test_safe_database_input(self):
        safe_result = self.security.safe_database_input("normal input")
        self.assertTrue(safe_result.is_safe)
        
        unsafe_result = self.security.safe_database_input("' OR '1'='1")
        self.assertFalse(unsafe_result.is_safe)
    
    def test_safe_file_operation(self):
        is_safe, path = self.security.safe_file_operation("safe_file.txt")
        self.assertTrue(is_safe)
        self.assertIsNotNone(path)
    
    def test_generate_csrf_token(self):
        token1 = self.security.generate_csrf_token()
        token2 = self.security.generate_csrf_token()
        self.assertIsInstance(token1, str)
        self.assertNotEqual(token1, token2)
    
    def test_encode_for_context(self):
        content = '<script>alert(1)</script>'
        html_encoded = self.security.encode_for_context(content, 'html')
        self.assertNotIn('<script>', html_encoded)
        
        js_encoded = self.security.encode_for_context(content, 'javascript')
        self.assertNotIn('<script>', js_encoded)


class TestGetEnhancedSecurityLayer(unittest.TestCase):
    """Test factory function"""
    
    def test_get_default(self):
        security = get_enhanced_security_layer()
        self.assertIsInstance(security, EnhancedSecurityLayer)
    
    def test_get_with_custom_level(self):
        security = get_enhanced_security_layer(protection_level=ProtectionLevel.STRICT)
        self.assertIsInstance(security, EnhancedSecurityLayer)
        self.assertEqual(security.protection_level, ProtectionLevel.STRICT)
    
    def test_get_with_base_directory(self):
        security = get_enhanced_security_layer(base_directory=tempfile.gettempdir())
        self.assertIsInstance(security, EnhancedSecurityLayer)


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of security components"""
    
    def test_concurrent_path_validation(self):
        protector = PathTraversalProtector()
        errors = []
        
        def worker():
            try:
                for _ in range(100):
                    protector.is_safe_path("test_file.txt")
                    protector.is_safe_path("../../../etc/passwd")
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(errors, [])
    
    def test_concurrent_random_generation(self):
        results = set()
        errors = []
        
        def worker():
            try:
                for _ in range(50):
                    results.add(SecureRandomGenerator.generate_token(8))
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(errors, [])
        self.assertGreater(len(results), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
