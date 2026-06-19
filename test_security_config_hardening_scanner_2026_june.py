#!/usr/bin/env python3
"""
Test Suite for Security Configuration Hardening Scanner
NeuralShield-AI - June 2026

Production-grade tests with actual working logic.
"""

import sys
import os
import json
import unittest
from unittest.mock import patch, mock_open

# Add the module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from security_config_hardening_scanner_2026_june import (
    SecurityConfigHardeningScanner,
    SeverityLevel,
    ComplianceStandard,
    ConfigurationFinding,
    ScanResult
)


class TestSecurityConfigHardeningScanner(unittest.TestCase):
    """Test cases for Security Configuration Hardening Scanner."""

    def setUp(self):
        """Set up test fixtures."""
        self.scanner = SecurityConfigHardeningScanner()

    def test_scanner_initialization(self):
        """Test scanner initialization."""
        self.assertIsNotNone(self.scanner)
        self.assertIsNotNone(self.scanner.security_checks)
        self.assertGreater(len(self.scanner.security_checks), 0)
        print("✓ Scanner initialization test passed")

    def test_scan_with_secure_config(self):
        """Test scanning a properly secured configuration."""
        secure_config = {
            "pam_password": "minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 pam_faillock",
            "ssh_config": "ClientAliveInterval 900",
            "tls_config": "TLSv1.2 TLSv1.3",
            "cookie_config": "Secure HttpOnly SameSite=Strict",
            "security_headers": "Strict-Transport-Security Content-Security-Policy X-Frame-Options X-Content-Type-Options",
            "file_permissions": {"/etc/shadow": "000", "/etc/ssh/ssh_host_rsa_key": "600"},
            "log_retention_days": "90",
            "rate_limit": "100/minute",
            "cors": "https://trusted-domain.com",
            "auditd": "enabled"
        }
        
        result = self.scanner.scan(secure_config)
        
        self.assertIsInstance(result, ScanResult)
        self.assertEqual(result.total_checks, 13)
        self.assertGreater(result.compliance_score, 50)
        print(f"✓ Secure config scan test passed. Score: {result.compliance_score}%")

    def test_scan_with_insecure_config(self):
        """Test scanning an insecure configuration."""
        insecure_config = {
            "pam_password": "minlen=6",  # Too short, no complexity
            "ssh_config": "ClientAliveInterval 3600",  # Too long
            "tls_config": "SSLv3 TLSv1.0",  # Insecure protocols
            "cookie_config": "",  # No security flags
            "security_headers": "",  # No security headers
            "file_permissions": {"/etc/shadow": "644", "/etc/ssh/ssh_host_rsa_key": "755"},
            "log_retention_days": "7",  # Too short
            # No rate limiting
            "cors": "Access-Control-Allow-Origin: *",  # Wildcard
        }
        
        result = self.scanner.scan(insecure_config)
        
        self.assertIsInstance(result, ScanResult)
        self.assertGreater(result.failed_checks, 0)
        print(f"✓ Insecure config scan test passed. Failed checks: {result.failed_checks}")

    def test_password_length_check(self):
        """Test password length validation."""
        # Test fail case
        fail_config = {"pam_password": "minlen=6"}
        finding = self.scanner._check_password_length(fail_config)
        self.assertEqual(finding.status, "FAIL")
        self.assertEqual(finding.severity, SeverityLevel.HIGH)
        
        # Test pass case
        pass_config = {"pam_password": "minlen=14"}
        finding = self.scanner._check_password_length(pass_config)
        self.assertEqual(finding.status, "PASS")
        print("✓ Password length check tests passed")

    def test_password_complexity_check(self):
        """Test password complexity validation."""
        # Test fail case
        fail_config = {"pam_password": "minlen=12"}
        finding = self.scanner._check_password_complexity(fail_config)
        self.assertEqual(finding.status, "FAIL")
        
        # Test pass case
        pass_config = {"pam_password": "minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1"}
        finding = self.scanner._check_password_complexity(pass_config)
        self.assertEqual(finding.status, "PASS")
        print("✓ Password complexity check tests passed")

    def test_tls_version_check(self):
        """Test TLS version validation."""
        # Test fail case
        fail_config = {"tls_config": "SSLv3 enabled"}
        finding = self.scanner._check_tls_version(fail_config)
        self.assertEqual(finding.status, "FAIL")
        self.assertEqual(finding.severity, SeverityLevel.CRITICAL)
        
        # Test pass case
        pass_config = {"tls_config": "TLS 1.2 and 1.3 only"}
        finding = self.scanner._check_tls_version(pass_config)
        self.assertEqual(finding.status, "PASS")
        print("✓ TLS version check tests passed")

    def test_secure_cookies_check(self):
        """Test secure cookies validation."""
        # Test fail case
        fail_config = {"cookie_config": "no flags here"}
        finding = self.scanner._check_secure_cookies(fail_config)
        self.assertEqual(finding.status, "FAIL")
        
        # Test pass case
        pass_config = {"cookie_config": "Secure HttpOnly SameSite=Strict"}
        finding = self.scanner._check_secure_cookies(pass_config)
        self.assertEqual(finding.status, "PASS")
        print("✓ Secure cookies check tests passed")

    def test_cors_configuration_check(self):
        """Test CORS configuration validation."""
        # Test fail case
        fail_config = {"cors": "Access-Control-Allow-Origin: *"}
        finding = self.scanner._check_cors_configuration(fail_config)
        self.assertEqual(finding.status, "FAIL")
        
        # Test pass case
        pass_config = {"cors": "Access-Control-Allow-Origin: https://example.com"}
        finding = self.scanner._check_cors_configuration(pass_config)
        self.assertEqual(finding.status, "PASS")
        print("✓ CORS configuration check tests passed")

    def test_api_rate_limiting_check(self):
        """Test API rate limiting validation."""
        # Test fail case
        fail_config = {}
        finding = self.scanner._check_api_rate_limiting(fail_config)
        self.assertEqual(finding.status, "FAIL")
        
        # Test pass case
        pass_config = {"rate_limit": "enabled"}
        finding = self.scanner._check_api_rate_limiting(pass_config)
        self.assertEqual(finding.status, "PASS")
        print("✓ API rate limiting check tests passed")

    def test_generate_json_report(self):
        """Test JSON report generation."""
        test_config = {"pam_password": "minlen=12"}
        result = self.scanner.scan(test_config)
        report = self.scanner.generate_report(result, format="json")
        
        report_data = json.loads(report)
        self.assertIn("scan_id", report_data)
        self.assertIn("summary", report_data)
        self.assertIn("findings", report_data)
        print("✓ JSON report generation test passed")

    def test_generate_markdown_report(self):
        """Test Markdown report generation."""
        test_config = {"pam_password": "minlen=12"}
        result = self.scanner.scan(test_config)
        report = self.scanner.generate_report(result, format="markdown")
        
        self.assertIn("# Security Configuration Hardening Scan Report", report)
        self.assertIn("Compliance Score", report)
        self.assertIn("Findings", report)
        print("✓ Markdown report generation test passed")

    def test_remediation_prioritization(self):
        """Test remediation prioritization."""
        insecure_config = {
            "pam_password": "minlen=6",
            "tls_config": "SSLv3",
        }
        result = self.scanner.scan(insecure_config)
        remediation_list = self.scanner.get_remediation_prioritization(result)
        
        self.assertIsInstance(remediation_list, list)
        if remediation_list:
            # Critical items should come first
            priorities = [item["priority"] for item in remediation_list]
            self.assertEqual(priorities, sorted(priorities))
        print("✓ Remediation prioritization test passed")

    def test_scan_id_generation(self):
        """Test scan ID generation."""
        scan_id = self.scanner._generate_scan_id()
        self.assertEqual(len(scan_id), 16)
        self.assertIsInstance(scan_id, str)
        print("✓ Scan ID generation test passed")

    def test_severity_level_enum(self):
        """Test severity level enum."""
        self.assertEqual(SeverityLevel.CRITICAL.value, "CRITICAL")
        self.assertEqual(SeverityLevel.HIGH.value, "HIGH")
        self.assertEqual(SeverityLevel.MEDIUM.value, "MEDIUM")
        self.assertEqual(SeverityLevel.LOW.value, "LOW")
        print("✓ Severity level enum test passed")

    def test_compliance_standard_enum(self):
        """Test compliance standard enum."""
        self.assertIn("CIS Benchmark", [s.value for s in ComplianceStandard])
        self.assertIn("NIST SP 800-53", [s.value for s in ComplianceStandard])
        self.assertIn("OWASP Top 10", [s.value for s in ComplianceStandard])
        print("✓ Compliance standard enum test passed")

    def test_full_integration_scan(self):
        """Full integration test with comprehensive configuration."""
        comprehensive_config = {
            "pam_password": "minlen=14 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 pam_faillock",
            "ssh_config": "ClientAliveInterval 600",
            "tls_config": "TLSv1.2 TLSv1.3",
            "cookie_config": "Secure HttpOnly SameSite=Strict",
            "security_headers": "Strict-Transport-Security Content-Security-Policy X-Frame-Options X-Content-Type-Options",
            "file_permissions": {"/etc/shadow": "000", "/etc/ssh/ssh_host_rsa_key": "600"},
            "log_retention_days": "180",
            "rate_limit": "1000/hour per client",
            "cors": "https://app.example.com https://admin.example.com",
            "auditd": "enabled",
        }
        
        result = self.scanner.scan(comprehensive_config)
        
        print(f"\n=== Full Integration Scan Results ===")
        print(f"Scan ID: {result.scan_id}")
        print(f"Timestamp: {result.timestamp}")
        print(f"Total Checks: {result.total_checks}")
        print(f"Passed: {result.passed_checks}")
        print(f"Failed: {result.failed_checks}")
        print(f"Compliance Score: {result.compliance_score}%")
        print(f"Scan Duration: {result.scan_duration_seconds}s")
        
        self.assertGreater(result.compliance_score, 70)
        print("✓ Full integration scan test passed")


def run_tests():
    """Run all tests and generate results."""
    print("=" * 60)
    print("Security Configuration Hardening Scanner - Test Suite")
    print("NeuralShield-AI - June 2026")
    print("=" * 60)
    print()
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestSecurityConfigHardeningScanner)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    # Save test results
    test_results = {
        "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "success": result.wasSuccessful()
    }
    
    with open("test_results_security_config_hardening_scanner.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"Results saved to test_results_security_config_hardening_scanner.json")
    print(f"Overall: {'PASSED' if result.wasSuccessful() else 'FAILED'}")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
