"""
NeuralShield-AI: LLM Agent Tool Call Security Validator
June 2026 Production Release

Validates and sanitizes tool calls made by LLM agents to prevent:
- Command injection attacks
- Privilege escalation attempts
- Path traversal attacks
- Shell metacharacter injection
- Malicious parameter manipulation

Production-grade security enforcement for agentic AI systems.
"""

import re
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse


class ToolCallAttackType(Enum):
    """Types of tool call attacks detected"""
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SHELL_METACHARACTER = "shell_metacharacter"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MALICIOUS_PARAMETER = "malicious_parameter"
    UNSAFE_URL = "unsafe_url"
    CODE_EXECUTION = "code_execution"
    ENVIRONMENT_LEAK = "environment_leak"


class ValidationRiskLevel(Enum):
    """Risk levels for validation results"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


@dataclass
class ToolCallFinding:
    """Individual finding from tool call validation"""
    attack_type: ToolCallAttackType
    risk_level: ValidationRiskLevel
    parameter: str
    value: str
    description: str
    confidence: float  # 0.0 - 1.0


@dataclass
class ToolCallValidationResult:
    """Complete validation result for a tool call"""
    tool_name: str
    is_safe: bool
    overall_risk: ValidationRiskLevel
    findings: List[ToolCallFinding] = field(default_factory=list)
    sanitized_parameters: Dict[str, Any] = field(default_factory=dict)
    blocked_parameters: List[str] = field(default_factory=list)
    validation_timestamp: float = 0.0

    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def get_critical_findings(self) -> List[ToolCallFinding]:
        return [f for f in self.findings if f.risk_level == ValidationRiskLevel.CRITICAL]

    def get_high_risk_findings(self) -> List[ToolCallFinding]:
        return [f for f in self.findings if f.risk_level == ValidationRiskLevel.HIGH]


class AgentToolCallValidator:
    """
    Production-grade LLM Agent Tool Call Security Validator
    
    Validates all parameters passed to agent tools before execution.
    Implements defense-in-depth with multiple validation layers.
    """

    # Dangerous shell metacharacters that can cause command injection
    DANGEROUS_METACHARS = r'[;&|`$()<>\\\'\"\n\r\t*?~\[\]{}#!]'
    
    # Command injection patterns
    COMMAND_INJECTION_PATTERNS = [
        r'(?:^|\s)(?:rm|sudo|chmod|chown|mkfs|dd|shred)\s',
        r';\s*(?:rm|sudo|sh|bash|zsh|ksh|python|perl|ruby|nc|curl|wget)\s',
        r'\|\s*(?:rm|sudo|sh|bash|cat|echo)\s',
        r'`.*?`',
        r'\$\(.*?\)',
        r'\$\{.*?\}',
        r'(?:^|\s)>\s*/dev/',
        r'(?:^|\s)>\s*/etc/',
        r'(?:^|\s)>\s*/proc/',
    ]
    
    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r'\.\./',
        r'\.\.\\',
        r'%2e%2e%2f',
        r'%2e%2e/',
        r'/%2e%2e/',
        r'\.\.$',
        r'/etc/',
        r'/proc/',
        r'/dev/',
        r'/root/',
        r'/home/[^/]+/',
    ]
    
    # Privilege escalation patterns
    PRIVILEGE_ESCALATION_PATTERNS = [
        r'(?:^|\s)sudo\s',
        r'(?:^|\s)su\s',
        r'(?:^|\s)pkexec\s',
        r'(?:^|\s)doas\s',
        r'--privileged',
        r'--root',
        r'uid=0',
        r'euid=0',
    ]
    
    # Dangerous Python code execution patterns
    CODE_EXEC_PATTERNS = [
        r'__import__\s*\(',
        r'exec\s*\(',
        r'eval\s*\(',
        r'subprocess\s*\.',
        r'os\.system\s*\(',
        r'os\.popen\s*\(',
        r'builtins\.open\s*\(',
        r'globals\(\)',
        r'locals\(\)',
        r'getattr\s*\(',
    ]
    
    # Environment variable leak patterns
    ENV_LEAK_PATTERNS = [
        r'\$[A-Z_]+',
        r'\$\{[A-Z_]+\}',
        r'os\.environ',
        r'os\.getenv',
    ]
    
    # Safe URL schemes
    SAFE_URL_SCHEMES = {'http', 'https', 'ftp', 'ftps'}
    
    # Blocked IP ranges (private, loopback, link-local)
    BLOCKED_IP_RANGES = [
        (r'^127\.', 'loopback'),
        (r'^10\.', 'private'),
        (r'^192\.168\.', 'private'),
        (r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', 'private'),
        (r'^169\.254\.', 'link-local'),
        (r'^localhost$', 'loopback'),
        (r'^0\.0\.0\.0$', 'wildcard'),
    ]

    def __init__(self, strict_mode: bool = True):
        """
        Initialize the Tool Call Validator
        
        Args:
            strict_mode: If True, blocks on medium risk and above
        """
        self.strict_mode = strict_mode
        self.compiled_command_patterns = [re.compile(p, re.IGNORECASE) for p in self.COMMAND_INJECTION_PATTERNS]
        self.compiled_path_patterns = [re.compile(p, re.IGNORECASE) for p in self.PATH_TRAVERSAL_PATTERNS]
        self.compiled_priv_patterns = [re.compile(p, re.IGNORECASE) for p in self.PRIVILEGE_ESCALATION_PATTERNS]
        self.compiled_code_patterns = [re.compile(p, re.IGNORECASE) for p in self.CODE_EXEC_PATTERNS]
        self.compiled_env_patterns = [re.compile(p, re.IGNORECASE) for p in self.ENV_LEAK_PATTERNS]
        self.metachar_pattern = re.compile(self.DANGEROUS_METACHARS)

    def validate_tool_call(self, tool_name: str, parameters: Dict[str, Any]) -> ToolCallValidationResult:
        """
        Validate a complete tool call with all parameters
        
        Args:
            tool_name: Name of the tool being called
            parameters: Dictionary of parameter names to values
            
        Returns:
            ToolCallValidationResult with findings and sanitized parameters
        """
        import time
        findings: List[ToolCallFinding] = []
        sanitized: Dict[str, Any] = {}
        blocked: List[str] = []

        for param_name, param_value in parameters.items():
            if isinstance(param_value, str):
                param_findings = self._validate_string_parameter(param_name, param_value)
                findings.extend(param_findings)
                
                # Sanitize the parameter
                sanitized_value = self._sanitize_parameter(param_value)
                sanitized[param_name] = sanitized_value
                
                # Check if should block
                if self._should_block_parameter(param_findings):
                    blocked.append(param_name)
            else:
                # Non-string parameters pass through
                sanitized[param_name] = param_value

        # Determine overall risk
        overall_risk = self._calculate_overall_risk(findings)
        is_safe = len(blocked) == 0 and overall_risk in [ValidationRiskLevel.SAFE, ValidationRiskLevel.LOW]
        
        if not self.strict_mode:
            is_safe = overall_risk in [ValidationRiskLevel.SAFE, ValidationRiskLevel.LOW, ValidationRiskLevel.MEDIUM]

        return ToolCallValidationResult(
            tool_name=tool_name,
            is_safe=is_safe,
            overall_risk=overall_risk,
            findings=findings,
            sanitized_parameters=sanitized,
            blocked_parameters=blocked,
            validation_timestamp=time.time()
        )

    def _validate_string_parameter(self, param_name: str, value: str) -> List[ToolCallFinding]:
        """Validate a single string parameter"""
        findings: List[ToolCallFinding] = []

        # Check for shell metacharacters
        if self.metachar_pattern.search(value):
            findings.append(ToolCallFinding(
                attack_type=ToolCallAttackType.SHELL_METACHARACTER,
                risk_level=ValidationRiskLevel.HIGH,
                parameter=param_name,
                value=value,
                description="Parameter contains dangerous shell metacharacters",
                confidence=0.95
            ))

        # Check for command injection
        for pattern in self.compiled_command_patterns:
            if pattern.search(value):
                findings.append(ToolCallFinding(
                    attack_type=ToolCallAttackType.COMMAND_INJECTION,
                    risk_level=ValidationRiskLevel.CRITICAL,
                    parameter=param_name,
                    value=value,
                    description=f"Command injection pattern detected: {pattern.pattern[:50]}",
                    confidence=0.98
                ))
                break  # One command injection finding is enough

        # Check for path traversal
        for pattern in self.compiled_path_patterns:
            if pattern.search(value):
                findings.append(ToolCallFinding(
                    attack_type=ToolCallAttackType.PATH_TRAVERSAL,
                    risk_level=ValidationRiskLevel.HIGH,
                    parameter=param_name,
                    value=value,
                    description=f"Path traversal pattern detected: {pattern.pattern[:50]}",
                    confidence=0.90
                ))
                break

        # Check for privilege escalation
        for pattern in self.compiled_priv_patterns:
            if pattern.search(value):
                findings.append(ToolCallFinding(
                    attack_type=ToolCallAttackType.PRIVILEGE_ESCALATION,
                    risk_level=ValidationRiskLevel.CRITICAL,
                    parameter=param_name,
                    value=value,
                    description=f"Privilege escalation attempt detected: {pattern.pattern[:50]}",
                    confidence=0.97
                ))
                break

        # Check for code execution
        for pattern in self.compiled_code_patterns:
            if pattern.search(value):
                findings.append(ToolCallFinding(
                    attack_type=ToolCallAttackType.CODE_EXECUTION,
                    risk_level=ValidationRiskLevel.CRITICAL,
                    parameter=param_name,
                    value=value,
                    description=f"Code execution pattern detected: {pattern.pattern[:50]}",
                    confidence=0.96
                ))
                break

        # Check for environment leak
        for pattern in self.compiled_env_patterns:
            if pattern.search(value):
                findings.append(ToolCallFinding(
                    attack_type=ToolCallAttackType.ENVIRONMENT_LEAK,
                    risk_level=ValidationRiskLevel.MEDIUM,
                    parameter=param_name,
                    value=value,
                    description="Environment variable access detected",
                    confidence=0.85
                ))
                break

        # Check for unsafe URLs
        url_findings = self._validate_url_safety(param_name, value)
        findings.extend(url_findings)

        return findings

    def _validate_url_safety(self, param_name: str, value: str) -> List[ToolCallFinding]:
        """Validate URL safety - prevent SSRF attacks"""
        findings: List[ToolCallFinding] = []
        
        # Check if value looks like a URL
        if not (value.startswith('http://') or value.startswith('https://')):
            return findings

        try:
            parsed = urlparse(value)
            hostname = parsed.hostname or ''
            
            # Check scheme
            if parsed.scheme not in self.SAFE_URL_SCHEMES:
                findings.append(ToolCallFinding(
                    attack_type=ToolCallAttackType.UNSAFE_URL,
                    risk_level=ValidationRiskLevel.HIGH,
                    parameter=param_name,
                    value=value,
                    description=f"Unsafe URL scheme: {parsed.scheme}",
                    confidence=0.90
                ))
            
            # Check for blocked IP ranges
            for pattern, reason in self.BLOCKED_IP_RANGES:
                if re.match(pattern, hostname):
                    findings.append(ToolCallFinding(
                        attack_type=ToolCallAttackType.UNSAFE_URL,
                        risk_level=ValidationRiskLevel.CRITICAL,
                        parameter=param_name,
                        value=value,
                        description=f"SSRF attempt - blocked {reason} address: {hostname}",
                        confidence=0.95
                    ))
                    break
                    
        except Exception:
            pass

        return findings

    def _sanitize_parameter(self, value: str) -> str:
        """Sanitize a parameter value by removing dangerous characters"""
        # Remove shell metacharacters
        sanitized = self.metachar_pattern.sub('', value)
        
        # Remove path traversal attempts
        sanitized = sanitized.replace('../', '').replace('..\\', '')
        
        # Trim whitespace
        sanitized = sanitized.strip()
        
        return sanitized

    def _should_block_parameter(self, findings: List[ToolCallFinding]) -> bool:
        """Determine if a parameter should be blocked based on findings"""
        for finding in findings:
            if finding.risk_level in [ValidationRiskLevel.CRITICAL, ValidationRiskLevel.HIGH]:
                return True
            if self.strict_mode and finding.risk_level == ValidationRiskLevel.MEDIUM:
                return True
        return False

    def _calculate_overall_risk(self, findings: List[ToolCallFinding]) -> ValidationRiskLevel:
        """Calculate overall risk level from all findings"""
        if not findings:
            return ValidationRiskLevel.SAFE
            
        risk_order = {
            ValidationRiskLevel.CRITICAL: 4,
            ValidationRiskLevel.HIGH: 3,
            ValidationRiskLevel.MEDIUM: 2,
            ValidationRiskLevel.LOW: 1,
            ValidationRiskLevel.SAFE: 0
        }
        
        max_risk = max(findings, key=lambda f: risk_order[f.risk_level])
        return max_risk.risk_level

    def get_security_report(self, result: ToolCallValidationResult) -> str:
        """Generate a human-readable security report"""
        report = [f"=== Tool Call Security Report: {result.tool_name} ==="]
        report.append(f"Status: {'SAFE' if result.is_safe else 'BLOCKED'}")
        report.append(f"Overall Risk: {result.overall_risk.value.upper()}")
        report.append(f"Total Findings: {len(result.findings)}")
        
        if result.findings:
            report.append("\nFindings:")
            for finding in result.findings:
                report.append(f"  [{finding.risk_level.value.upper()}] {finding.attack_type.value}")
                report.append(f"    Parameter: {finding.parameter}")
                report.append(f"    Description: {finding.description}")
                report.append(f"    Confidence: {finding.confidence:.1%}")
        
        if result.blocked_parameters:
            report.append(f"\nBlocked Parameters: {', '.join(result.blocked_parameters)}")
            
        return '\n'.join(report)
