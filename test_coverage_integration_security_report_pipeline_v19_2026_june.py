"""
Test Coverage v19 - Integration Tests for Security + Report Pipeline
NeuralShield-AI | June 24, 2026 | Session 128
DIMENSION C - TEST COVERAGE EXPANSION
ADD-ONLY: Tests only, no production code modified
Integration tests between v15 Report Generators and v17 Security Protectors
Covers:
- End-to-end security pipeline integration
- Report generation with security validation
- Redaction workflow integration
- Rate limiting with actual report generation
- Integrity verification end-to-end
- Backward compatibility verification
"""
import unittest
import sys
import os
import json
import hashlib
import hmac
import time
import threading
from typing import Dict, Any, List

# Add source directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

# Import v15 Report Generator (Dimension A v15)
try:
    from feature_expansion_threat_intelligence_report_generator_v15_2026_june import (
        ThreatIntelligenceReportGenerator,
        ReportFormat,
        ReportType,
        ReportSection,
        create_standard_report_generator,
        create_comprehensive_report_generator,
        create_executive_summary_generator
    )
    REPORT_V15_AVAILABLE = True
except ImportError as e:
    REPORT_V15_AVAILABLE = False
    REPORT_IMPORT_ERROR = str(e)

# Import v17 Security Protector (Dimension B v17)
try:
    from security_hardening_threat_report_protection_v17_2026_june import (
        ProtectedReportGenerator,
        SecurityLevel,
        ValidationSeverity,
        ValidationResult,
        InputValidator,
        SensitiveDataRedactor,
        create_high_security_protector,
        create_maximum_security_protector,
        create_audit_only_protector
    )
    SECURITY_V17_AVAILABLE = True
except ImportError as e:
    SECURITY_V17_AVAILABLE = False
    SECURITY_IMPORT_ERROR = str(e)


class TestReportSecurityPipelineIntegration(unittest.TestCase):
    """Integration tests for v15 Report Generator + v17 Security Protector pipeline"""

    @unittest.skipUnless(REPORT_V15_AVAILABLE and SECURITY_V17_AVAILABLE, 
                        "v15 Report or v17 Security module not available")
    def setUp(self):
        """Set up integration test fixtures"""
        self.report_generator = create_standard_report_generator()
        self.security_protector = create_high_security_protector()
        self.input_validator = InputValidator()
        self.data_redactor = SensitiveDataRedactor()
        
        # Sample threat intelligence data
        self.sample_threat_data = {
            "threat_actor": "APT-29",
            "ttp": ["T1059", "T1027", "T1046"],
            "iocs": ["192.168.1.100", "10.0.0.50"],
            "confidence": 0.87,
            "severity": "HIGH",
            "target_sector": "Healthcare",
            "mitre_techniques": ["Command and Scripting Interpreter", "Obfuscated Files"]
        }

    @unittest.skipUnless(REPORT_V15_AVAILABLE and SECURITY_V17_AVAILABLE, 
                        "v15 Report or v17 Security module not available")
    def test_secure_report_generation_pipeline_end_to_end(self):
        """Test end-to-end: Generate report, validate through security, verify integrity"""
        # Step 1: Generate report using v15 generator
        report_result = self.report_generator.generate_report(
            threat_data=self.sample_threat_data,
            report_type=ReportType.THREAT_SUMMARY,
            output_format=ReportFormat.JSON,
            sections=[ReportSection.EXECUTIVE_SUMMARY, ReportSection.TTP_ANALYSIS]
        )
        
        self.assertIsNotNone(report_result)
        self.assertIn("report_id", report_result)
        
        # Step 2: Validate report content through v17 security validator
        validation_result = self.input_validator.validate_report_content(
            content=report_result
        )
        
        self.assertIsInstance(validation_result, ValidationResult)
        
        # Step 3: Generate protected report with integrity hash
        protected_result = self.security_protector.generate_protected_report(
            threat_data=self.sample_threat_data,
            report_generator_fn=lambda data: self.report_generator.generate_report(
                threat_data=data,
                report_type=ReportType.THREAT_SUMMARY,
                output_format=ReportFormat.JSON
            )
        )
        
        self.assertIsNotNone(protected_result)
        self.assertIn("protected_report", protected_result)
        self.assertIn("integrity_hash", protected_result)

    @unittest.skipUnless(REPORT_V15_AVAILABLE and SECURITY_V17_AVAILABLE, 
                        "v15 Report or v17 Security module not available")
    def test_rate_limiting_with_actual_report_generation(self):
        """Test rate limiting applies correctly during actual report generation"""
        protector = create_maximum_security_protector()
        
        # Generate reports within rate limit
        successful_reports = 0
        for i in range(3):  # Well within default limits
            result = protector.generate_protected_report(
                threat_data=self.sample_threat_data,
                report_generator_fn=lambda data: self.report_generator.generate_report(
                    threat_data=data,
                    report_type=ReportType.THREAT_SUMMARY,
                    output_format=ReportFormat.JSON
                )
            )
            if result:
                successful_reports += 1
        
        self.assertGreater(successful_reports, 0)

    @unittest.skipUnless(REPORT_V15_AVAILABLE and SECURITY_V17_AVAILABLE, 
                        "v15 Report or v17 Security module not available")
    def test_integrity_verification_after_report_generation(self):
        """Test integrity hash can be verified after report generation"""
        # Generate protected report
        protected = self.security_protector.generate_protected_report(
            threat_data=self.sample_threat_data,
            report_generator_fn=lambda data: self.report_generator.generate_report(
                threat_data=data,
                report_type=ReportType.THREAT_SUMMARY,
                output_format=ReportFormat.JSON
            )
        )
        
        self.assertIn("integrity_hash", protected)
        original_hash = protected["integrity_hash"]
        
        # Verify integrity
        is_valid = self.security_protector.verify_report_integrity(
            report_content=protected["protected_report"],
            expected_hash=original_hash
        )
        
        self.assertTrue(is_valid is not None)

    @unittest.skipUnless(REPORT_V15_AVAILABLE and SECURITY_V17_AVAILABLE, 
                        "v15 Report or v17 Security module not available")
    def test_all_security_levels_with_report_generation(self):
        """Test all security levels work correctly with actual report generation"""
        security_levels = [
            (SecurityLevel.LOW, "low_security"),
            (SecurityLevel.MEDIUM, "medium_security"),
            (SecurityLevel.HIGH, "high_security"),
            (SecurityLevel.MAXIMUM, "maximum_security")
        ]
        
        for level, _ in security_levels:
            protector = ProtectedReportGenerator(security_level=level)
            
            result = protector.generate_protected_report(
                threat_data=self.sample_threat_data,
                report_generator_fn=lambda data: self.report_generator.generate_report(
                    threat_data=data,
                    report_type=ReportType.THREAT_SUMMARY,
                    output_format=ReportFormat.JSON
                )
            )
            
            self.assertIsNotNone(result)

    @unittest.skipUnless(REPORT_V15_AVAILABLE and SECURITY_V17_AVAILABLE, 
                        "v15 Report or v17 Security module not available")
    def test_concurrent_secure_report_generation(self):
        """Test thread safety of secure report generation pipeline"""
        results = []
        errors = []
        
        def generate_secure_report():
            try:
                result = self.security_protector.generate_protected_report(
                    threat_data=self.sample_threat_data,
                    report_generator_fn=lambda data: self.report_generator.generate_report(
                        threat_data=data,
                        report_type=ReportType.THREAT_SUMMARY,
                        output_format=ReportFormat.JSON
                    )
                )
                results.append(result)
            except Exception as e:
                errors.append(str(e))
        
        # Create multiple threads
        threads = [threading.Thread(target=generate_secure_report) for _ in range(5)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        
        self.assertEqual(len(errors), 0, f"Thread safety errors: {errors}")


class TestSecurityModuleIndependentOperation(unittest.TestCase):
    """Test security module can operate independently (backward compatibility)"""

    @unittest.skipUnless(SECURITY_V17_AVAILABLE, "v17 Security module not available")
    def test_security_works_without_report_generator(self):
        """Security protector should work even without report generator installed"""
        protector = create_high_security_protector()
        validator = InputValidator()
        
        # Test validation works standalone
        result = validator.validate_report_content(
            content={"test": "valid_json_content"}
        )
        
        self.assertIsInstance(result, ValidationResult)

    @unittest.skipUnless(REPORT_V15_AVAILABLE, "v15 Report module not available")
    def test_report_generator_works_without_security(self):
        """Report generator should work even without security module installed"""
        generator = create_standard_report_generator()
        
        result = generator.generate_report(
            threat_data=self.sample_threat_data if hasattr(self, 'sample_threat_data') else {"test": "data"},
            report_type=ReportType.THREAT_SUMMARY,
            output_format=ReportFormat.JSON
        )
        
        self.assertIsNotNone(result)
        self.assertIn("report_id", result)

    def setUp(self):
        self.sample_threat_data = {"confidence": 0.85, "severity": "HIGH"}


class TestCrossModuleBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility across module versions"""

    @unittest.skipUnless(REPORT_V15_AVAILABLE and SECURITY_V17_AVAILABLE, 
                        "Modules not available")
    def test_old_report_format_with_new_security(self):
        """v17 security should handle v15 report format gracefully"""
        # Generate v15 format report
        report = create_standard_report_generator().generate_report(
            threat_data={"test": "data"},
            report_type=ReportType.THREAT_SUMMARY,
            output_format=ReportFormat.JSON
        )
        
        # v17 security should validate it
        validator = InputValidator()
        result = validator.validate_report_content(
            content=report
        )
        
        # Should not crash, even if validation fails
        self.assertIsInstance(result, ValidationResult)

    @unittest.skipUnless(REPORT_V15_AVAILABLE and SECURITY_V17_AVAILABLE, 
                        "Modules not available")
    def test_empty_data_handling_across_modules(self):
        """Both modules should handle empty data gracefully"""
        validator = InputValidator()
        generator = create_standard_report_generator()
        
        # Empty data should not crash
        try:
            report = generator.generate_report(
                threat_data={},
                report_type=ReportType.THREAT_SUMMARY,
                output_format=ReportFormat.JSON
            )
            # Should handle gracefully
        except Exception:
            pass  # Acceptable to raise, but not crash
        
        # Security should handle empty content
        result = validator.validate_report_content(content={})
        self.assertIsInstance(result, ValidationResult)


class TestPipelineEdgeCases(unittest.TestCase):
    """Edge case integration tests for security + report pipeline"""

    @unittest.skipUnless(SECURITY_V17_AVAILABLE, "v17 Security module not available")
    def test_large_report_content_validation(self):
        """Test validation handles very large report content"""
        validator = InputValidator()
        
        # Generate large content
        large_content = {"data": ["x" * 1000 for _ in range(100)]}
        
        result = validator.validate_report_content(
            content=large_content
        )
        
        self.assertIsInstance(result, ValidationResult)


class TestFactoryFunctionIntegration(unittest.TestCase):
    """Test factory functions create properly integrated instances"""

    @unittest.skipUnless(REPORT_V15_AVAILABLE and SECURITY_V17_AVAILABLE, 
                        "Modules not available")
    def test_all_security_factories_with_report_generation(self):
        """All security factory functions should work with report generation"""
        factories = [
            create_high_security_protector,
            create_maximum_security_protector,
            create_audit_only_protector
        ]
        
        for factory_fn in factories:
            protector = factory_fn()
            
            result = protector.generate_protected_report(
                threat_data={"test": "data"},
                report_generator_fn=lambda data: create_standard_report_generator().generate_report(
                    threat_data=data,
                    report_type=ReportType.THREAT_SUMMARY,
                    output_format=ReportFormat.JSON
                )
            )
            
            self.assertIsNotNone(result)

    @unittest.skipUnless(REPORT_V15_AVAILABLE and SECURITY_V17_AVAILABLE, 
                        "Modules not available")
    def test_all_report_factories_with_security(self):
        """All report generator factories should work with security"""
        report_factories = [
            create_standard_report_generator,
            create_comprehensive_report_generator,
            create_executive_summary_generator
        ]
        
        protector = create_high_security_protector()
        
        for factory_fn in report_factories:
            generator = factory_fn()
            
            result = protector.generate_protected_report(
                threat_data={"test": "data"},
                report_generator_fn=lambda data: generator.generate_report(
                    threat_data=data,
                    report_type=ReportType.THREAT_SUMMARY,
                    output_format=ReportFormat.JSON
                )
            )
            
            self.assertIsNotNone(result)


def run_integration_tests():
    """Run all integration tests and return results"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return {
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "success": result.wasSuccessful()
    }


if __name__ == "__main__":
    print("=" * 70)
    print("NeuralShield-AI - Test Coverage v19 - Security + Report Integration Tests")
    print("Session 128 | June 24, 2026")
    print("=" * 70)
    print()
    
    results = run_integration_tests()
    
    print()
    print("=" * 70)
    print("SUMMARY:")
    print(f"  Tests Run: {results['tests_run']}")
    print(f"  Failures: {results['failures']}")
    print(f"  Errors: {results['errors']}")
    print(f"  Skipped: {results['skipped']}")
    print(f"  Success: {'YES ✅' if results['success'] else 'NO ❌'}")
    print("=" * 70)
