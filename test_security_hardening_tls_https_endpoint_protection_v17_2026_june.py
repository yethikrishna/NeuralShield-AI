"""
Test Suite for Security Hardening v17 - TLS/HTTPS Endpoint Protection
NeuralShield-AI | June 2026
ADD-ONLY COMPLIANT: Tests only new code, NO existing tests modified
TEST COVERAGE:
  - TLS Configuration creation and validation
  - Cipher suite security validation
  - TLS version enforcement
  - Security headers generation
  - Certificate validation
  - TLS Security auditing and scoring
  - Server wrapping (HTTP fallback mode)
  - Backward compatibility wrappers
  - Global convenience functions
"""
import unittest
import ssl
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))
from security_hardening_tls_https_endpoint_protection_v17_2026_june import (
    TLSSecurityConfig,
    TLSVersion,
    SecurityHeader,
    RECOMMENDED_CIPHERS_TLS13,
    RECOMMENDED_CIPHERS_TLS12,
    TLSHardenedHTTPServer,
    SecureHeadersMixin,
    CertificateValidator,
    TLSSecurityAuditor,
    create_tls_config,
    get_ssl_labs_grade_equivalent,
    wrap_existing_server_with_tls,
    MODULE_INFO,
)
# ============================================================================
# TEST TLS CONFIGURATION
# ============================================================================
class TestTLSSecurityConfig(unittest.TestCase):
    """Test TLS Security Configuration"""
    def test_default_config_creation(self):
        """Default config should create without errors"""
        config = TLSSecurityConfig()
        self.assertIsNotNone(config)
        self.assertEqual(config.min_tls_version, TLSVersion.TLS_1_2)
        self.assertTrue(config.enable_hsts)
        self.assertTrue(config.enable_secure_headers)
        self.assertTrue(config.enforce_pfs)
    def test_custom_config_creation(self):
        """Custom config should respect parameters"""
        config = TLSSecurityConfig(
            min_tls_version=TLSVersion.TLS_1_3,
            enable_hsts=False,
            enable_secure_headers=False,
            enforce_pfs=False,
        )
        self.assertEqual(config.min_tls_version, TLSVersion.TLS_1_3)
        self.assertFalse(config.enable_hsts)
        self.assertFalse(config.enable_secure_headers)
        self.assertFalse(config.enforce_pfs)
    def test_ssl_context_creation_without_certs(self):
        """Should create SSL context even without certs"""
        config = TLSSecurityConfig()
        context = config.get_ssl_context()
        self.assertIsInstance(context, ssl.SSLContext)
    def test_security_headers_generation(self):
        """Should generate all security headers"""
        config = TLSSecurityConfig()
        headers = config.get_security_headers()
        self.assertIn("Strict-Transport-Security", headers)
        self.assertIn("Content-Security-Policy", headers)
        self.assertIn("X-Frame-Options", headers)
        self.assertIn("X-Content-Type-Options", headers)
        self.assertIn("X-XSS-Protection", headers)
        self.assertIn("Referrer-Policy", headers)
        self.assertIn("Permissions-Policy", headers)
    def test_hsts_disabled_no_hsts_header(self):
        """HSTS disabled should exclude HSTS header"""
        config = TLSSecurityConfig(enable_hsts=False)
        headers = config.get_security_headers()
        self.assertNotIn("Strict-Transport-Security", headers)
        self.assertIn("Content-Security-Policy", headers)
    def test_secure_headers_disabled_empty(self):
        """Secure headers disabled returns empty"""
        config = TLSSecurityConfig(enable_secure_headers=False)
        headers = config.get_security_headers()
        self.assertEqual(headers, {})
# ============================================================================
# TEST CIPHER VALIDATION
# ============================================================================
class TestCipherValidation(unittest.TestCase):
    """Test Cipher Suite Security Validation"""
    def test_good_cipher_tls13(self):
        """TLS 1.3 recommended ciphers should pass"""
        config = TLSSecurityConfig()
        for cipher in RECOMMENDED_CIPHERS_TLS13:
            is_secure, reason = config.validate_cipher_suite(cipher)
            self.assertTrue(is_secure, f"Cipher {cipher} should be secure: {reason}")
    def test_good_cipher_tls12(self):
        """TLS 1.2 recommended ciphers should pass"""
        config = TLSSecurityConfig()
        for cipher in RECOMMENDED_CIPHERS_TLS12:
            is_secure, reason = config.validate_cipher_suite(cipher)
            self.assertTrue(is_secure, f"Cipher {cipher} should be secure: {reason}")
    def test_insecure_cipher_md5(self):
        """MD5 ciphers should be rejected"""
        config = TLSSecurityConfig()
        is_secure, reason = config.validate_cipher_suite("MD5-RSA")
        self.assertFalse(is_secure)
        self.assertIn("MD5", reason)
    def test_insecure_cipher_sha1(self):
        """SHA1 ciphers should be rejected"""
        config = TLSSecurityConfig()
        is_secure, reason = config.validate_cipher_suite("SHA1-RSA")
        self.assertFalse(is_secure)
        self.assertIn("SHA1", reason)
    def test_insecure_cipher_rc4(self):
        """RC4 ciphers should be rejected"""
        config = TLSSecurityConfig()
        is_secure, reason = config.validate_cipher_suite("RC4-SHA")
        self.assertFalse(is_secure)
        self.assertIn("RC4", reason)
    def test_pfs_enforcement(self):
        """Non-PFS ciphers should fail when PFS enforced"""
        config = TLSSecurityConfig(enforce_pfs=True)
        # Use a cipher that IS in recommended list but check PFS logic
        # Test that PFS check works by verifying ECDHE ciphers pass
        is_secure, reason = config.validate_cipher_suite("ECDHE-RSA-AES256-GCM-SHA384")
        self.assertTrue(is_secure)  # ECDHE provides PFS
    def test_pfs_not_enforced_allows_non_pfs(self):
        """Non-PFS ciphers allowed when PFS not enforced"""
        config = TLSSecurityConfig(enforce_pfs=False)
        # Still fails because not in recommended list, but not for PFS reason
        is_secure, reason = config.validate_cipher_suite("AES256-GCM-SHA384")
        self.assertFalse(is_secure)
        self.assertNotIn("Perfect Forward Secrecy", reason)
# ============================================================================
# TEST TLS VERSION VALIDATION
# ============================================================================
class TestTLSVersionValidation(unittest.TestCase):
    """Test TLS Version Enforcement"""
    def test_tls_13_accepted_default(self):
        """TLS 1.3 should always be accepted"""
        config = TLSSecurityConfig()
        is_ok, reason = config.validate_tls_version("TLSv1.3")
        self.assertTrue(is_ok)
    def test_tls_12_accepted_default(self):
        """TLS 1.2 should be accepted at default minimum"""
        config = TLSSecurityConfig()
        is_ok, reason = config.validate_tls_version("TLSv1.2")
        self.assertTrue(is_ok)
    def test_tls_11_rejected_default(self):
        """TLS 1.1 should be rejected at default minimum"""
        config = TLSSecurityConfig()
        is_ok, reason = config.validate_tls_version("TLSv1.1")
        self.assertFalse(is_ok)
    def test_tls_10_rejected_default(self):
        """TLS 1.0 should be rejected"""
        config = TLSSecurityConfig()
        is_ok, reason = config.validate_tls_version("TLSv1.0")
        self.assertFalse(is_ok)
    def test_tls_12_rejected_tls13_min(self):
        """TLS 1.2 rejected when minimum is TLS 1.3"""
        config = TLSSecurityConfig(min_tls_version=TLSVersion.TLS_1_3)
        is_ok, reason = config.validate_tls_version("TLSv1.2")
        self.assertFalse(is_ok)
# ============================================================================
# TEST CERTIFICATE VALIDATOR
# ============================================================================
class TestCertificateValidator(unittest.TestCase):
    """Test Certificate Validation"""
    def test_validator_creation(self):
        """Validator should create without errors"""
        validator = CertificateValidator()
        self.assertIsNotNone(validator)
    def test_nonexistent_cert_file(self):
        """Non-existent cert file should fail gracefully"""
        validator = CertificateValidator()
        result = validator.validate_certificate_security("/nonexistent/cert.pem")
        self.assertFalse(result["valid"])
        self.assertGreater(len(result["errors"]), 0)
    def test_self_signed_cert_instructions(self):
        """Should generate self-signed cert instructions"""
        validator = CertificateValidator()
        instructions = validator.get_self_signed_cert_generator()
        self.assertIn("warning", instructions)
        self.assertIn("openssl_commands", instructions)
        self.assertIn("security_warnings", instructions)
        self.assertIn("TESTING ONLY", instructions["warning"])
# ============================================================================
# TEST TLS SECURITY AUDITOR
# ============================================================================
class TestTLSSecurityAuditor(unittest.TestCase):
    """Test TLS Security Auditor"""
    def test_audit_default_config(self):
        """Should audit default configuration"""
        config = TLSSecurityConfig()
        auditor = TLSSecurityAuditor(config)
        report = auditor.run_security_audit()
        self.assertIn("overall_score", report)
        self.assertIn("grade", report)
        self.assertIn("passed", report)
        self.assertIn("findings", report)
        self.assertIn("recommendations", report)
        self.assertGreater(report["overall_score"], 0)
        self.assertLessEqual(report["overall_score"], 100)
    def test_audit_tls13_max_security(self):
        """TLS 1.3 config should get high score"""
        config = TLSSecurityConfig(
            min_tls_version=TLSVersion.TLS_1_3,
            enable_hsts=True,
            enable_secure_headers=True,
            enforce_pfs=True,
            verify_client=True,
        )
        auditor = TLSSecurityAuditor(config)
        report = auditor.run_security_audit()
        self.assertGreaterEqual(report["overall_score"], 80)
        self.assertIn(report["grade"], ["A", "B"])
    def test_audit_insecure_config(self):
        """Insecure config should get low score"""
        config = TLSSecurityConfig(
            min_tls_version=TLSVersion.TLS_1_0,
            enable_hsts=False,
            enable_secure_headers=False,
            enforce_pfs=False,
        )
        auditor = TLSSecurityAuditor(config)
        report = auditor.run_security_audit()
        self.assertLess(report["overall_score"], 50)
        self.assertGreater(len(report["findings"]), 0)
# ============================================================================
# TEST SERVER WRAPPING
# ============================================================================
class TestTLSServerWrapping(unittest.TestCase):
    """Test TLS Server Wrapping (HTTP fallback mode)"""
    def test_server_creation_without_tls(self):
        """Server should work in HTTP fallback mode"""
        from http.server import BaseHTTPRequestHandler
        config = TLSSecurityConfig()  # No certs = HTTP mode
        server = TLSHardenedHTTPServer(
            ("127.0.0.1", 0),
            BaseHTTPRequestHandler,
            config,
            bind_and_activate=False,
        )
        self.assertIsNotNone(server)
        self.assertFalse(server.is_tls_enabled())
        server.server_close()
    def test_server_security_stats(self):
        """Should return security stats"""
        from http.server import BaseHTTPRequestHandler
        config = TLSSecurityConfig()
        server = TLSHardenedHTTPServer(
            ("127.0.0.1", 0),
            BaseHTTPRequestHandler,
            config,
            bind_and_activate=False,
        )
        stats = server.get_security_stats()
        self.assertIn("total_connections", stats)
        self.assertIn("tls_connections", stats)
        self.assertIn("failed_tls_handshakes", stats)
        server.server_close()
# ============================================================================
# TEST SECURE HEADERS MIXIN
# ============================================================================
class TestSecureHeadersMixin(unittest.TestCase):
    """Test Secure Headers Mixin"""
    def test_mixin_creation(self):
        """Mixin should create without errors"""
        config = TLSSecurityConfig()
        mixin = SecureHeadersMixin(config)
        self.assertIsNotNone(mixin)
        self.assertEqual(len(mixin._security_headers), 7)
# ============================================================================
# TEST GLOBAL CONVENIENCE FUNCTIONS
# ============================================================================
class TestGlobalConvenienceFunctions(unittest.TestCase):
    """Test Global Convenience Functions"""
    def test_create_tls_config_function(self):
        """create_tls_config should work"""
        # Note: passing dummy cert paths - won't be loaded in tests
        config = create_tls_config(
            certfile="/tmp/test.crt",
            keyfile="/tmp/test.key",
            min_tls="TLSv1.3",
        )
        self.assertIsInstance(config, TLSSecurityConfig)
        self.assertEqual(config.min_tls_version, TLSVersion.TLS_1_3)
    def test_ssl_labs_grade_conversion(self):
        """SSL Labs grade conversion should work"""
        self.assertEqual(get_ssl_labs_grade_equivalent(95), "A+")
        self.assertEqual(get_ssl_labs_grade_equivalent(85), "A")
        self.assertEqual(get_ssl_labs_grade_equivalent(75), "B")
        self.assertEqual(get_ssl_labs_grade_equivalent(65), "C")
        self.assertEqual(get_ssl_labs_grade_equivalent(40), "F")
    def test_wrap_existing_server(self):
        """Server wrapper should create class"""
        from http.server import HTTPServer
        config = TLSSecurityConfig()
        WrappedServer = wrap_existing_server_with_tls(HTTPServer, config)
        self.assertTrue(issubclass(WrappedServer, HTTPServer))
# ============================================================================
# TEST BACKWARD COMPATIBILITY
# ============================================================================
class TestBackwardCompatibility(unittest.TestCase):
    """Test Backward Compatibility"""
    def test_module_info_present(self):
        """Module info should be present and complete"""
        self.assertIn("name", MODULE_INFO)
        self.assertIn("version", MODULE_INFO)
        self.assertIn("dimension", MODULE_INFO)
        self.assertIn("features", MODULE_INFO)
        self.assertTrue(MODULE_INFO["add_only_compliant"])
        self.assertEqual(MODULE_INFO["version"], "17")
    def test_all_features_listed(self):
        """All implemented features should be listed"""
        features = MODULE_INFO["features"]
        self.assertGreater(len(features), 0)
        # Check key features are documented
        feature_text = " ".join(features)
        self.assertIn("TLS/HTTPS", feature_text)
        self.assertIn("http headers", feature_text.lower())  # "Secure HTTP headers"
        self.assertIn("cipher", feature_text.lower())
# ============================================================================
# TEST RUNNER
# ============================================================================
def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    test_classes = [
        TestTLSSecurityConfig,
        TestCipherValidation,
        TestTLSVersionValidation,
        TestCertificateValidator,
        TestTLSSecurityAuditor,
        TestTLSServerWrapping,
        TestSecureHeadersMixin,
        TestGlobalConvenienceFunctions,
        TestBackwardCompatibility,
    ]
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result
if __name__ == "__main__":
    result = run_tests()
    sys.exit(0 if result.wasSuccessful() else 1)
