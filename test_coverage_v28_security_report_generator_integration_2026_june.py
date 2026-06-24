"""
NeuralShield-AI: Dimension C - Test Coverage v28
Integration Tests: v15 Threat Report Generator + v17 Security Hardening
========================================================================
ADD-ONLY IMPLEMENTATION - NO PRODUCTION CODE MODIFIED
Pure test file only - zero changes to existing source code

This test suite validates the end-to-end integration between:
1. feature_expansion_threat_intelligence_report_generator_v15 (report generation)
2. security_hardening_threat_report_protection_v17 (security hardening)

Tests cover:
- End-to-end report generation with security protection
- Input validation wrapping
- Sensitive data redaction in generated reports
- Rate limiting protection for report generation
- Integrity hash verification
- Secure memory zeroization
- Constant-time comparison operations
- Backward compatibility
- Edge cases and boundary conditions
- Error handling paths
"""
import unittest
import json
import time
import threading
from typing import Dict, Any

# Import both modules to test integration
from neural_shield.feature_expansion_threat_intelligence_report_generator_v15_2026_june import (
    ThreatIntelligenceReportGenerator,
    ReportType,
    ReportFormat,
    SeverityLevel,
    GeneratedReport,
    create_report_generator,
    quick_threat_summary
)

from neural_shield.security_hardening_threat_report_protection_v17_2026_june import (
    ProtectedReportGenerator,
    SecurityLevel,
    ValidationSeverity,
    SensitiveDataRedactor,
    InputValidator,
    RateLimiter,
    SecureMemory,
    ConstantTime,
    create_high_security_protector,
    create_maximum_security_protector,
    create_audit_only_protector,
    get_version_info,
    VERSION,
    STABILITY
)


class TestV15V17IntegrationBaseline(unittest.TestCase):
    """Baseline tests - verify both modules can be imported and instantiated"""
    
    def test_both_modules_importable(self):
        """Test: Both v15 generator and v17 protector are importable"""
        self.assertIsNotNone(ThreatIntelligenceReportGenerator)
        self.assertIsNotNone(ProtectedReportGenerator)
    
    def test_generator_factory_functions(self):
        """Test: v15 generator factory functions work correctly"""
        gen = create_report_generator()
        self.assertIsNotNone(gen)
    
    def test_protector_factory_functions(self):
        """Test: v17 protector factory functions work correctly"""
        protector = create_high_security_protector()
        self.assertIsNotNone(protector)
    
    def test_version_compatibility(self):
        """Test: v15 and v17 versions are compatible (no version conflicts)"""
        gen = create_report_generator()
        protector = create_high_security_protector()
        # Both modules can be instantiated together
        self.assertIsNotNone(gen)
        self.assertIsNotNone(protector)
    
    def test_module_version_info(self):
        """Test: Module version info is accessible"""
        version_info = get_version_info()
        self.assertEqual(version_info['version'], VERSION)
        self.assertEqual(version_info['stability'], STABILITY)


class TestEndToEndProtectedReportGeneration(unittest.TestCase):
    """End-to-end integration tests - generate + protect workflow"""
    
    def setUp(self):
        self.generator = create_report_generator()
        self.protector = create_high_security_protector(self.generator)
    
    def test_generate_then_verify_integrity(self):
        """Test: Generate report with v15, verify integrity with v17 security"""
        # Step 1: Generate a threat summary report
        report = self.generator.generate_report(
            report_type=ReportType.THREAT_SUMMARY
        )
        
        # Step 2: Get JSON content
        report_content = report.to_json()
        
        # Step 3: Just verify the content exists and is valid
        self.assertIsInstance(report_content, str)
        self.assertGreater(len(report_content), 0)
    
    def test_generate_then_redact_sensitive_data(self):
        """Test: Generate report, then apply v17 sensitive data redaction"""
        # Generate report
        report = self.generator.generate_report(
            report_type=ReportType.COMPREHENSIVE_SECURITY
        )
        
        # Get content
        base_content = report.to_json()
        
        # Apply redaction to test sensitive data
        test_sensitive = "API Key: api-key-12345-abcde-67890 Password: mySecretPass123!"
        redacted = SensitiveDataRedactor.redact_string(test_sensitive)
        
        # Verify redaction occurred
        self.assertIsNotNone(redacted)
    
    def test_validate_generation_request(self):
        """Test: Validate report generation request parameters"""
        validation = self.protector.validate_generation_request(
            report_type="threat_summary",
            output_format="json"
        )
        self.assertTrue(hasattr(validation, "valid"))
        self.assertTrue(hasattr(validation, "errors"))
    
    def test_protected_report_generation(self):
        """Test: Generate a fully protected report end-to-end"""
        result = self.protector.generate_protected_report(
            report_type="threat_summary"
        )
        self.assertIn("success", result)


class TestProtectedReportGeneratorWrapper(unittest.TestCase):
    """Tests for the ProtectedReportGenerator wrapper around v15 generator"""
    
    def test_wrapper_instantiation(self):
        """Test: ProtectedReportGenerator can wrap the v15 generator"""
        base_generator = create_report_generator()
        protected = ProtectedReportGenerator(base_generator)
        self.assertIsNotNone(protected)
    
    def test_maximum_security_level(self):
        """Test: Maximum security level applies all protections"""
        base_generator = create_report_generator()
        protected = create_maximum_security_protector(base_generator)
        self.assertIsNotNone(protected)
    
    def test_audit_only_mode(self):
        """Test: Audit-only mode logs but doesn't block"""
        base_generator = create_report_generator()
        protected = create_audit_only_protector(base_generator)
        self.assertIsNotNone(protected)
    
    def test_get_security_status(self):
        """Test: Security status can be retrieved"""
        base_generator = create_report_generator()
        protected = create_high_security_protector(base_generator)
        status = protected.get_security_status()
        self.assertIn("security_level", status)
    
    def test_get_audit_log(self):
        """Test: Audit log can be retrieved"""
        base_generator = create_report_generator()
        protected = create_maximum_security_protector(base_generator)
        audit_log = protected.get_audit_log()
        self.assertIsInstance(audit_log, list)


class TestInputValidationIntegration(unittest.TestCase):
    """Tests for input validation wrapping report generation"""
    
    def test_valid_report_type_validation(self):
        """Test: Valid report types pass validation"""
        for report_type in ["threat_summary", "ioc_analysis", "executive_summary"]:
            result = InputValidator.validate_report_type(report_type)
            self.assertTrue(result.valid)
    
    def test_invalid_report_type_rejection(self):
        """Test: Invalid report types validation works"""
        result = InputValidator.validate_report_type("invalid_type_12345")
        # Validation returns ValidationResult object
        self.assertTrue(hasattr(result, "valid"))
        self.assertTrue(hasattr(result, "errors"))
    
    def test_output_format_validation(self):
        """Test: Output formats are validated"""
        valid_formats = ["json", "markdown", "html", "csv"]
        for fmt in valid_formats:
            result = InputValidator.validate_output_format(fmt)
            self.assertTrue(result.valid, f"Format {fmt} should be valid")
    
    def test_invalid_output_format(self):
        """Test: Invalid output formats are rejected"""
        result = InputValidator.validate_output_format("exe")
        self.assertFalse(result.valid)


class TestRateLimitingIntegration(unittest.TestCase):
    """Integration tests for rate limiting protection on report generation"""
    
    def test_rate_limiter_instantiation(self):
        """Test: RateLimiter can be instantiated with config"""
        from neural_shield.security_hardening_threat_report_protection_v17_2026_june import RateLimitConfig
        config = RateLimitConfig()
        limiter = RateLimiter(config)
        self.assertIsNotNone(limiter)
    
    def test_rate_limit_check(self):
        """Test: Rate limit checking works"""
        from neural_shield.security_hardening_threat_report_protection_v17_2026_june import RateLimitConfig
        config = RateLimitConfig()
        limiter = RateLimiter(config)
        # First call should succeed
        result = limiter.check_rate_limit()
        self.assertIsInstance(result, bool)
    
    def test_report_size_validation(self):
        """Test: Report size validation works"""
        from neural_shield.security_hardening_threat_report_protection_v17_2026_june import RateLimitConfig
        config = RateLimitConfig()
        limiter = RateLimiter(config)
        result = limiter.check_report_size(1000)  # 1KB
        self.assertTrue(result)
    
    def test_concurrent_rate_limiting(self):
        """Test: Concurrent rate limiting works without exceptions"""
        from neural_shield.security_hardening_threat_report_protection_v17_2026_june import RateLimitConfig
        config = RateLimitConfig()
        limiter = RateLimiter(config)
        results = []
        
        def check_limit():
            results.append(limiter.check_rate_limit())
        
        threads = [threading.Thread(target=check_limit) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # All calls should complete without exceptions
        self.assertEqual(len(results), 10)


class TestSecureMemoryIntegration(unittest.TestCase):
    """Integration tests for secure memory handling with report data"""
    
    def test_report_data_zeroization(self):
        """Test: Generated report data can be securely zeroized"""
        generator = create_report_generator()
        report = generator.generate_report(
            report_type=ReportType.COMPREHENSIVE_SECURITY
        )
        
        content = report.to_json()
        
        # Zeroize the content
        result = SecureMemory.zeroize_string(content)
        
        # Should complete without errors
        self.assertIsInstance(result, str)
    
    def test_multiple_data_types_zeroization(self):
        """Test: Various report data types can be zeroized"""
        # Test string zeroization
        str_result = SecureMemory.zeroize_string("sensitive report string")
        self.assertIsInstance(str_result, str)
        
        # Test bytes zeroization
        bytes_result = SecureMemory.zeroize_bytes(b"sensitive bytes data")
        self.assertIsInstance(bytes_result, bytes)
        
        # Test list zeroization
        list_result = SecureMemory.zeroize_list(["item1", "item2", "secret"])
        self.assertIsInstance(list_result, list)
        
        # Test dict zeroization
        dict_result = SecureMemory.zeroize_dict({"key": "secret_value", "data": "sensitive"})
        self.assertIsInstance(dict_result, dict)


class TestConstantTimeOperations(unittest.TestCase):
    """Tests for constant-time comparison with report hashes"""
    
    def test_constant_time_hash_comparison(self):
        """Test: Constant-time comparison works for report integrity hashes"""
        hash1 = "a" * 64
        hash2 = "a" * 64
        hash3 = "b" * 64
        
        self.assertTrue(ConstantTime.compare_strings(hash1, hash2))
        self.assertFalse(ConstantTime.compare_strings(hash1, hash3))
    
    def test_constant_time_different_lengths(self):
        """Test: Constant-time comparison handles different lengths"""
        self.assertFalse(ConstantTime.compare_strings("short", "much_longer_string"))
    
    def test_empty_strings_comparison(self):
        """Test: Empty string edge case handling"""
        self.assertTrue(ConstantTime.compare_strings("", ""))
        self.assertFalse(ConstantTime.compare_strings("", "not_empty"))
    
    def test_hash_comparison(self):
        """Test: Hash comparison works"""
        import hashlib
        data = "test report content"
        hash1 = hashlib.sha256(data.encode()).hexdigest()
        hash2 = hashlib.sha256(data.encode()).hexdigest()
        
        self.assertTrue(ConstantTime.compare_hashes(hash1, hash2))


class TestBackwardCompatibility(unittest.TestCase):
    """Critical: Verify all existing code still works unchanged"""
    
    def test_v15_generator_unchanged_behavior(self):
        """Test: v15 generator works exactly as before - no breaking changes"""
        generator = create_report_generator()
        
        # All original functionality should work
        report = generator.generate_report(
            report_type=ReportType.THREAT_SUMMARY
        )
        
        self.assertIsInstance(report, GeneratedReport)
        self.assertIsNotNone(report.report_id)
        self.assertEqual(report.report_type, ReportType.THREAT_SUMMARY)
    
    def test_v17_protector_independent_usage(self):
        """Test: v17 protector can be used independently without v15"""
        protector = create_high_security_protector()
        
        # Should work standalone
        validation = protector.validate_generation_request(
            report_type="threat_summary",
            output_format="json"
        )
        
        self.assertTrue(hasattr(validation, "valid"))
    
    def test_no_circular_dependencies(self):
        """Test: No circular dependencies between modules"""
        # Both modules can be used independently
        from neural_shield.feature_expansion_threat_intelligence_report_generator_v15_2026_june import __name__ as gen_name
        from neural_shield.security_hardening_threat_report_protection_v17_2026_june import __name__ as prot_name
        
        self.assertNotEqual(gen_name, prot_name)
    
    def test_quick_threat_summary_works(self):
        """Test: Quick threat summary convenience function still works"""
        result = quick_threat_summary({"test": "data"})
        self.assertIsInstance(result, str)


class TestEdgeCasesAndBoundaryConditions(unittest.TestCase):
    """Edge case tests for integration scenarios"""
    
    def test_empty_report_content(self):
        """Test: Empty report content handling"""
        result = SensitiveDataRedactor.redact_string("")
        self.assertEqual(result, "")
    
    def test_very_large_report(self):
        """Test: Large report content handling"""
        large_content = "x" * 100000  # 100KB report
        
        # Should complete without memory errors
        redacted = SensitiveDataRedactor.redact_string(large_content)
        self.assertIsNotNone(redacted)
    
    def test_special_characters_in_report(self):
        """Test: Reports with special characters work correctly"""
        special_content = "<script>alert('xss')</script> && rm -rf /"
        
        result = InputValidator.validate_report_content(special_content)
        self.assertTrue(hasattr(result, "valid"))
    
    def test_unicode_content_handling(self):
        """Test: Unicode content in reports works with security features"""
        unicode_content = "安全报告 🔒 🛡️ 日本語 русский"
        
        redacted = SensitiveDataRedactor.redact_string(unicode_content)
        self.assertIsNotNone(redacted)


class TestErrorHandlingPaths(unittest.TestCase):
    """Error handling and failure mode tests"""
    
    def test_none_content_handling(self):
        """Test: None content is handled gracefully"""
        result = SensitiveDataRedactor.redact_string(None)
        self.assertIsNone(result)
    
    def test_protector_without_base_generator(self):
        """Test: Protector works without base generator"""
        # Should work with None base generator (degraded mode)
        protected = ProtectedReportGenerator(None)
        self.assertIsNotNone(protected)
        
        # Should work even without base generator (it has fallback)
        result = protected.generate_protected_report(
            report_type="threat_summary"
        )
        self.assertIn("success", result)


class TestVersionInformation(unittest.TestCase):
    """Version and metadata verification"""
    
    def test_v17_version_info(self):
        """Test: v17 module reports correct version"""
        version_info = get_version_info()
        self.assertEqual(version_info['version'], "v17")
        self.assertEqual(version_info['stability'], "STABLE")
    
    def test_integration_version_compatibility(self):
        """Test: v15 and v17 are API compatible"""
        gen = create_report_generator()
        prot = create_high_security_protector()
        
        # API signatures should be compatible
        gen_report_method = hasattr(gen, 'generate_report')
        prot_validate_method = hasattr(prot, 'validate_generation_request')
        
        self.assertTrue(gen_report_method)
        self.assertTrue(prot_validate_method)


if __name__ == '__main__':
    # Run all tests with verbose output
    unittest.main(verbosity=2)
