"""
Security Configuration Hardening Scanner
NeuralShield-AI - June 2026

Production-grade security configuration scanner that:
1. Scans system and application configurations for security best practices
2. Identifies misconfigurations and security vulnerabilities
3. Provides actionable remediation recommendations
4. Generates compliance reports
5. Supports CIS benchmarks and industry standards
"""

import os
import re
import json
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SeverityLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ComplianceStandard(Enum):
    CIS = "CIS Benchmark"
    NIST = "NIST SP 800-53"
    OWASP = "OWASP Top 10"
    HIPAA = "HIPAA"
    GDPR = "GDPR"
    PCI = "PCI DSS"


@dataclass
class ConfigurationFinding:
    check_id: str
    title: str
    severity: SeverityLevel
    status: str  # PASS, FAIL, WARNING, SKIPPED
    description: str
    current_value: Optional[str] = None
    recommended_value: Optional[str] = None
    remediation: Optional[str] = None
    compliance_standards: List[ComplianceStandard] = field(default_factory=list)
    evidence: Optional[str] = None


@dataclass
class ScanResult:
    scan_id: str
    timestamp: str
    total_checks: int
    passed_checks: int
    failed_checks: int
    findings: List[ConfigurationFinding]
    compliance_score: float
    scan_duration_seconds: float


class SecurityConfigHardeningScanner:
    """
    Production-grade security configuration hardening scanner.
    Scans configurations against security best practices and compliance standards.
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.findings: List[ConfigurationFinding] = []
        self.scan_start_time: Optional[datetime] = None
        self._initialize_security_checks()

    def _initialize_security_checks(self):
        """Initialize all security configuration checks."""
        self.security_checks = [
            # Authentication & Password Policies
            {
                "id": "AUTH-001",
                "title": "Password Minimum Length Check",
                "severity": SeverityLevel.HIGH,
                "description": "Passwords should be at least 12 characters long",
                "check_fn": self._check_password_length,
                "compliance": [ComplianceStandard.CIS, ComplianceStandard.NIST]
            },
            {
                "id": "AUTH-002",
                "title": "Password Complexity Requirements",
                "severity": SeverityLevel.HIGH,
                "description": "Passwords should require mixed case, numbers, and special characters",
                "check_fn": self._check_password_complexity,
                "compliance": [ComplianceStandard.CIS, ComplianceStandard.NIST]
            },
            {
                "id": "AUTH-003",
                "title": "Account Lockout Policy",
                "severity": SeverityLevel.MEDIUM,
                "description": "Account lockout should be enabled after failed attempts",
                "check_fn": self._check_account_lockout,
                "compliance": [ComplianceStandard.CIS]
            },
            {
                "id": "AUTH-004",
                "title": "Session Timeout Configuration",
                "severity": SeverityLevel.MEDIUM,
                "description": "Idle sessions should timeout after 15 minutes or less",
                "check_fn": self._check_session_timeout,
                "compliance": [ComplianceStandard.CIS, ComplianceStandard.HIPAA]
            },
            
            # Network Security
            {
                "id": "NET-001",
                "title": "TLS Version Check",
                "severity": SeverityLevel.CRITICAL,
                "description": "Only TLS 1.2+ should be enabled, SSL and old TLS versions disabled",
                "check_fn": self._check_tls_version,
                "compliance": [ComplianceStandard.CIS, ComplianceStandard.NIST, ComplianceStandard.PCI]
            },
            {
                "id": "NET-002",
                "title": "Secure Cookies Configuration",
                "severity": SeverityLevel.HIGH,
                "description": "Cookies should have Secure, HttpOnly, and SameSite flags",
                "check_fn": self._check_secure_cookies,
                "compliance": [ComplianceStandard.OWASP, ComplianceStandard.GDPR]
            },
            {
                "id": "NET-003",
                "title": "Security Headers Presence",
                "severity": SeverityLevel.HIGH,
                "description": "Security headers (HSTS, CSP, X-Frame-Options, etc.) should be configured",
                "check_fn": self._check_security_headers,
                "compliance": [ComplianceStandard.OWASP]
            },
            
            # File System Security
            {
                "id": "FS-001",
                "title": "File Permission Check",
                "severity": SeverityLevel.HIGH,
                "description": "Sensitive files should not be world-readable",
                "check_fn": self._check_file_permissions,
                "compliance": [ComplianceStandard.CIS, ComplianceStandard.NIST]
            },
            {
                "id": "FS-002",
                "title": "Default Credentials Check",
                "severity": SeverityLevel.CRITICAL,
                "description": "Default credentials should be changed",
                "check_fn": self._check_default_credentials,
                "compliance": [ComplianceStandard.OWASP, ComplianceStandard.CIS]
            },
            
            # Logging & Auditing
            {
                "id": "LOG-001",
                "title": "Audit Logging Enabled",
                "severity": SeverityLevel.MEDIUM,
                "description": "Security audit logging should be enabled",
                "check_fn": self._check_audit_logging,
                "compliance": [ComplianceStandard.CIS, ComplianceStandard.HIPAA, ComplianceStandard.GDPR]
            },
            {
                "id": "LOG-002",
                "title": "Log Retention Policy",
                "severity": SeverityLevel.LOW,
                "description": "Logs should be retained for at least 90 days",
                "check_fn": self._check_log_retention,
                "compliance": [ComplianceStandard.NIST, ComplianceStandard.HIPAA]
            },
            
            # API Security
            {
                "id": "API-001",
                "title": "API Rate Limiting",
                "severity": SeverityLevel.HIGH,
                "description": "API rate limiting should be configured",
                "check_fn": self._check_api_rate_limiting,
                "compliance": [ComplianceStandard.OWASP]
            },
            {
                "id": "API-002",
                "title": "CORS Configuration",
                "severity": SeverityLevel.MEDIUM,
                "description": "CORS should not allow wildcard origins",
                "check_fn": self._check_cors_configuration,
                "compliance": [ComplianceStandard.OWASP]
            },
        ]

    def scan(self, target_config: Dict[str, Any] = None) -> ScanResult:
        """
        Run full security configuration scan.
        
        Args:
            target_config: Optional dictionary of configuration values to scan
            
        Returns:
            ScanResult with all findings and compliance score
        """
        self.scan_start_time = datetime.utcnow()
        self.findings = []
        
        logger.info(f"Starting security configuration scan at {self.scan_start_time}")
        
        # Use provided config or scan system
        if target_config:
            self._scan_configuration(target_config)
        else:
            self._scan_system_configuration()
        
        scan_end_time = datetime.utcnow()
        duration = (scan_end_time - self.scan_start_time).total_seconds()
        
        passed = sum(1 for f in self.findings if f.status == "PASS")
        failed = sum(1 for f in self.findings if f.status in ["FAIL", "WARNING"])
        total = len(self.findings)
        compliance_score = (passed / total * 100) if total > 0 else 0.0
        
        result = ScanResult(
            scan_id=self._generate_scan_id(),
            timestamp=scan_end_time.isoformat(),
            total_checks=total,
            passed_checks=passed,
            failed_checks=failed,
            findings=self.findings,
            compliance_score=round(compliance_score, 2),
            scan_duration_seconds=round(duration, 3)
        )
        
        logger.info(f"Scan complete. Compliance Score: {compliance_score:.1f}%")
        logger.info(f"Passed: {passed}/{total}, Failed: {failed}")
        
        return result

    def _scan_configuration(self, config: Dict[str, Any]):
        """Scan provided configuration dictionary."""
        for check in self.security_checks:
            try:
                finding = check["check_fn"](config)
                if finding:
                    finding.compliance_standards = check["compliance"]
                    self.findings.append(finding)
            except Exception as e:
                logger.error(f"Error in check {check['id']}: {e}")
                self.findings.append(ConfigurationFinding(
                    check_id=check["id"],
                    title=check["title"],
                    severity=SeverityLevel.INFO,
                    status="ERROR",
                    description=f"Check execution failed: {str(e)}"
                ))

    def _scan_system_configuration(self):
        """Scan actual system configuration."""
        # Build system config snapshot
        system_config = self._collect_system_config()
        self._scan_configuration(system_config)

    def _collect_system_config(self) -> Dict[str, Any]:
        """Collect actual system configuration values."""
        config = {}
        
        # Collect PAM/auth config if available
        try:
            if os.path.exists("/etc/pam.d/common-password"):
                with open("/etc/pam.d/common-password", "r") as f:
                    config["pam_password"] = f.read()
        except:
            pass
            
        # Collect SSH config
        try:
            if os.path.exists("/etc/ssh/sshd_config"):
                with open("/etc/ssh/sshd_config", "r") as f:
                    config["ssh_config"] = f.read()
        except:
            pass
            
        # Check file permissions on sensitive files
        sensitive_files = ["/etc/passwd", "/etc/shadow", "/etc/ssh/ssh_host_rsa_key"]
        config["file_permissions"] = {}
        for f in sensitive_files:
            if os.path.exists(f):
                config["file_permissions"][f] = oct(os.stat(f).st_mode)[-3:]
        
        return config

    def _check_password_length(self, config: Dict[str, Any]) -> ConfigurationFinding:
        """Check password minimum length requirement."""
        pam_content = config.get("pam_password", "")
        minlen_match = re.search(r'minlen=(\d+)', pam_content)
        
        recommended = "12"
        current = minlen_match.group(1) if minlen_match else "Not configured"
        
        if minlen_match and int(minlen_match.group(1)) >= 12:
            return ConfigurationFinding(
                check_id="AUTH-001",
                title="Password Minimum Length Check",
                severity=SeverityLevel.HIGH,
                status="PASS",
                description="Password minimum length meets requirements",
                current_value=current,
                recommended_value=recommended,
                remediation="N/A"
            )
        else:
            return ConfigurationFinding(
                check_id="AUTH-001",
                title="Password Minimum Length Check",
                severity=SeverityLevel.HIGH,
                status="FAIL",
                description="Password minimum length is insufficient or not configured",
                current_value=current,
                recommended_value=recommended,
                remediation="Set password minimum length to 12 characters in PAM configuration"
            )

    def _check_password_complexity(self, config: Dict[str, Any]) -> ConfigurationFinding:
        """Check password complexity requirements."""
        pam_content = config.get("pam_password", "")
        
        has_upper = "ucredit" in pam_content
        has_lower = "lcredit" in pam_content
        has_digit = "dcredit" in pam_content
        has_other = "ocredit" in pam_content
        
        if all([has_upper, has_lower, has_digit, has_other]):
            return ConfigurationFinding(
                check_id="AUTH-002",
                title="Password Complexity Requirements",
                severity=SeverityLevel.HIGH,
                status="PASS",
                description="Password complexity requirements are configured",
                current_value="All complexity rules enabled",
                recommended_value="Mixed case, numbers, special characters",
                remediation="N/A"
            )
        else:
            missing = []
            if not has_upper: missing.append("uppercase")
            if not has_lower: missing.append("lowercase")
            if not has_digit: missing.append("digits")
            if not has_other: missing.append("special characters")
            
            return ConfigurationFinding(
                check_id="AUTH-002",
                title="Password Complexity Requirements",
                severity=SeverityLevel.HIGH,
                status="FAIL",
                description=f"Missing complexity requirements: {', '.join(missing)}",
                current_value=f"Missing: {', '.join(missing)}",
                recommended_value="All character class requirements enabled",
                remediation="Enable pam_pwquality with ucredit, lcredit, dcredit, ocredit settings"
            )

    def _check_account_lockout(self, config: Dict[str, Any]) -> ConfigurationFinding:
        """Check account lockout policy."""
        pam_content = config.get("pam_password", "")
        has_lockout = "pam_faillock" in pam_content or "pam_tally2" in pam_content
        
        if has_lockout:
            return ConfigurationFinding(
                check_id="AUTH-003",
                title="Account Lockout Policy",
                severity=SeverityLevel.MEDIUM,
                status="PASS",
                description="Account lockout policy is enabled",
                current_value="Configured",
                recommended_value="Lockout after 5 failed attempts",
                remediation="N/A"
            )
        else:
            return ConfigurationFinding(
                check_id="AUTH-003",
                title="Account Lockout Policy",
                severity=SeverityLevel.MEDIUM,
                status="FAIL",
                description="Account lockout is not configured",
                current_value="Not configured",
                recommended_value="Enable pam_faillock module",
                remediation="Configure pam_faillock to lock accounts after failed authentication attempts"
            )

    def _check_session_timeout(self, config: Dict[str, Any]) -> ConfigurationFinding:
        """Check session timeout configuration."""
        ssh_config = config.get("ssh_config", "")
        timeout_match = re.search(r'ClientAliveInterval\s+(\d+)', ssh_config)
        
        if timeout_match and int(timeout_match.group(1)) <= 900:
            return ConfigurationFinding(
                check_id="AUTH-004",
                title="Session Timeout Configuration",
                severity=SeverityLevel.MEDIUM,
                status="PASS",
                description="Session timeout is properly configured",
                current_value=f"{timeout_match.group(1)} seconds",
                recommended_value="900 seconds (15 minutes) or less",
                remediation="N/A"
            )
        else:
            current = timeout_match.group(1) + " seconds" if timeout_match else "Not configured"
            return ConfigurationFinding(
                check_id="AUTH-004",
                title="Session Timeout Configuration",
                severity=SeverityLevel.MEDIUM,
                status="FAIL",
                description="Session timeout is too long or not configured",
                current_value=current,
                recommended_value="900 seconds (15 minutes) or less",
                remediation="Set ClientAliveInterval to 900 or less in sshd_config"
            )

    def _check_tls_version(self, config: Dict[str, Any]) -> ConfigurationFinding:
        """Check TLS version configuration."""
        # This would typically scan web server configs
        # For this implementation, we'll do a simulated check
        tls_config = config.get("tls_config", {})
        
        old_protocols = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
        found_old = any(p in str(config) for p in old_protocols)
        
        if not found_old:
            return ConfigurationFinding(
                check_id="NET-001",
                title="TLS Version Check",
                severity=SeverityLevel.CRITICAL,
                status="PASS",
                description="Only modern TLS protocols are enabled",
                current_value="TLS 1.2+ only",
                recommended_value="TLS 1.2 and TLS 1.3 only",
                remediation="N/A"
            )
        else:
            return ConfigurationFinding(
                check_id="NET-001",
                title="TLS Version Check",
                severity=SeverityLevel.CRITICAL,
                status="FAIL",
                description="Old/insecure SSL/TLS protocols detected",
                current_value="Legacy protocols enabled",
                recommended_value="TLS 1.2 and TLS 1.3 only",
                remediation="Disable SSLv2, SSLv3, TLSv1.0, TLSv1.1 in web server configuration"
            )

    def _check_secure_cookies(self, config: Dict[str, Any]) -> ConfigurationFinding:
        """Check secure cookie flags."""
        cookie_config = str(config.get("cookie_config", ""))
        
        has_secure = "Secure" in cookie_config
        has_httponly = "HttpOnly" in cookie_config
        has_samesite = "SameSite" in cookie_config
        
        if all([has_secure, has_httponly, has_samesite]):
            return ConfigurationFinding(
                check_id="NET-002",
                title="Secure Cookies Configuration",
                severity=SeverityLevel.HIGH,
                status="PASS",
                description="All secure cookie flags are set",
                current_value="Secure, HttpOnly, SameSite flags present",
                recommended_value="All security flags enabled",
                remediation="N/A"
            )
        else:
            missing = []
            if not has_secure: missing.append("Secure")
            if not has_httponly: missing.append("HttpOnly")
            if not has_samesite: missing.append("SameSite")
            
            return ConfigurationFinding(
                check_id="NET-002",
                title="Secure Cookies Configuration",
                severity=SeverityLevel.HIGH,
                status="FAIL",
                description=f"Missing cookie security flags: {', '.join(missing)}",
                current_value=f"Missing: {', '.join(missing)}",
                recommended_value="Secure, HttpOnly, SameSite=Strict",
                remediation="Add Secure, HttpOnly, and SameSite flags to all session cookies"
            )

    def _check_security_headers(self, config: Dict[str, Any]) -> ConfigurationFinding:
        """Check security headers configuration."""
        headers = str(config.get("security_headers", ""))
        
        required_headers = ["Strict-Transport-Security", "Content-Security-Policy", 
                           "X-Frame-Options", "X-Content-Type-Options"]
        found = [h for h in required_headers if h in headers]
        
        if len(found) == len(required_headers):
            return ConfigurationFinding(
                check_id="NET-003",
                title="Security Headers Presence",
                severity=SeverityLevel.HIGH,
                status="PASS",
                description="All recommended security headers are present",
                current_value="All headers configured",
                recommended_value="All security headers enabled",
                remediation="N/A"
            )
        else:
            missing = [h for h in required_headers if h not in headers]
            return ConfigurationFinding(
                check_id="NET-003",
                title="Security Headers Presence",
                severity=SeverityLevel.HIGH,
                status="FAIL",
                description=f"Missing security headers: {', '.join(missing)}",
                current_value=f"Missing: {', '.join(missing)}",
                recommended_value="HSTS, CSP, X-Frame-Options, X-Content-Type-Options",
                remediation="Configure all recommended security headers in web server"
            )

    def _check_file_permissions(self, config: Dict[str, Any]) -> ConfigurationFinding:
        """Check sensitive file permissions."""
        file_perms = config.get("file_permissions", {})
        
        issues = []
        for filepath, perms in file_perms.items():
            if "shadow" in filepath and perms != "000" and int(perms) > 600:
                issues.append(f"{filepath}: {perms} (should be 000 or 400)")
            elif "ssh_host" in filepath and int(perms) > 600:
                issues.append(f"{filepath}: {perms} (should be 600)")
        
        if not issues:
            return ConfigurationFinding(
                check_id="FS-001",
                title="File Permission Check",
                severity=SeverityLevel.HIGH,
                status="PASS",
                description="Sensitive file permissions are secure",
                current_value="All files properly restricted",
                recommended_value="Restrictive permissions on sensitive files",
                remediation="N/A"
            )
        else:
            return ConfigurationFinding(
                check_id="FS-001",
                title="File Permission Check",
                severity=SeverityLevel.HIGH,
                status="FAIL",
                description="Insecure file permissions detected",
                current_value="; ".join(issues),
                recommended_value="000/400 for shadow, 600 for SSH keys",
                remediation="Run chmod 000 /etc/shadow and chmod 600 on SSH private keys"
            )

    def _check_default_credentials(self, config: Dict[str, Any]) -> ConfigurationFinding:
        """Check for default credentials."""
        # This would typically scan config files for known default passwords
        default_patterns = ["admin:admin", "root:root", "password:password", "changeme"]
        found_defaults = [p for p in default_patterns if p in str(config)]
        
        if not found_defaults:
            return ConfigurationFinding(
                check_id="FS-002",
                title="Default Credentials Check",
                severity=SeverityLevel.CRITICAL,
                status="PASS",
                description="No default credentials detected",
                current_value="No defaults found",
                recommended_value="All default credentials changed",
                remediation="N/A"
            )
        else:
            return ConfigurationFinding(
                check_id="FS-002",
                title="Default Credentials Check",
                severity=SeverityLevel.CRITICAL,
                status="FAIL",
                description="Default credentials detected in configuration",
                current_value=f"Found: {', '.join(found_defaults)}",
                recommended_value="No default credentials",
                remediation="Change all default passwords immediately"
            )

    def _check_audit_logging(self, config: Dict[str, Any]) -> ConfigurationFinding:
        """Check if audit logging is enabled."""
        has_audit = "auditd" in str(config).lower() or "audit_log" in str(config).lower()
        
        if has_audit:
            return ConfigurationFinding(
                check_id="LOG-001",
                title="Audit Logging Enabled",
                severity=SeverityLevel.MEDIUM,
                status="PASS",
                description="Security audit logging is enabled",
                current_value="Audit logging configured",
                recommended_value="Audit logging enabled for security events",
                remediation="N/A"
            )
        else:
            return ConfigurationFinding(
                check_id="LOG-001",
                title="Audit Logging Enabled",
                severity=SeverityLevel.MEDIUM,
                status="FAIL",
                description="Security audit logging is not configured",
                current_value="Not configured",
                recommended_value="Auditd or equivalent logging enabled",
                remediation="Install and configure auditd for comprehensive security auditing"
            )

    def _check_log_retention(self, config: Dict[str, Any]) -> ConfigurationFinding:
        """Check log retention policy."""
        log_retention = config.get("log_retention_days")
        
        if log_retention and int(log_retention) >= 90:
            return ConfigurationFinding(
                check_id="LOG-002",
                title="Log Retention Policy",
                severity=SeverityLevel.LOW,
                status="PASS",
                description="Log retention meets compliance requirements",
                current_value=f"{log_retention} days",
                recommended_value="90+ days",
                remediation="N/A"
            )
        else:
            current = f"{log_retention} days" if log_retention else "Not specified"
            return ConfigurationFinding(
                check_id="LOG-002",
                title="Log Retention Policy",
                severity=SeverityLevel.LOW,
                status="FAIL",
                description="Log retention period is insufficient",
                current_value=current,
                recommended_value="90 days minimum",
                remediation="Configure log rotation to retain logs for at least 90 days"
            )

    def _check_api_rate_limiting(self, config: Dict[str, Any]) -> ConfigurationFinding:
        """Check API rate limiting configuration."""
        has_rate_limit = "rate_limit" in str(config).lower() or "throttle" in str(config).lower()
        
        if has_rate_limit:
            return ConfigurationFinding(
                check_id="API-001",
                title="API Rate Limiting",
                severity=SeverityLevel.HIGH,
                status="PASS",
                description="API rate limiting is configured",
                current_value="Rate limiting enabled",
                recommended_value="Per-client rate limits configured",
                remediation="N/A"
            )
        else:
            return ConfigurationFinding(
                check_id="API-001",
                title="API Rate Limiting",
                severity=SeverityLevel.HIGH,
                status="FAIL",
                description="API rate limiting is not configured",
                current_value="Not configured",
                recommended_value="Per-IP and per-user rate limits",
                remediation="Implement rate limiting middleware to prevent abuse and DoS attacks"
            )

    def _check_cors_configuration(self, config: Dict[str, Any]) -> ConfigurationFinding:
        """Check CORS configuration."""
        cors_config = str(config.get("cors", ""))
        has_wildcard = "*" in cors_config and "Access-Control-Allow-Origin" in cors_config
        
        if not has_wildcard:
            return ConfigurationFinding(
                check_id="API-002",
                title="CORS Configuration",
                severity=SeverityLevel.MEDIUM,
                status="PASS",
                description="CORS is properly restricted",
                current_value="No wildcard origins",
                recommended_value="Specific trusted origins only",
                remediation="N/A"
            )
        else:
            return ConfigurationFinding(
                check_id="API-002",
                title="CORS Configuration",
                severity=SeverityLevel.MEDIUM,
                status="FAIL",
                description="CORS allows wildcard origin",
                current_value="Wildcard (*) origin allowed",
                recommended_value="Specific trusted origins only",
                remediation="Replace wildcard (*) with specific trusted origin domains"
            )

    def _generate_scan_id(self) -> str:
        """Generate unique scan ID."""
        timestamp = datetime.utcnow().isoformat()
        return hashlib.sha256(f"scan_{timestamp}".encode()).hexdigest()[:16]

    def generate_report(self, result: ScanResult, format: str = "json") -> str:
        """Generate scan report in specified format."""
        if format == "json":
            return json.dumps({
                "scan_id": result.scan_id,
                "timestamp": result.timestamp,
                "summary": {
                    "total_checks": result.total_checks,
                    "passed": result.passed_checks,
                    "failed": result.failed_checks,
                    "compliance_score": result.compliance_score
                },
                "findings": [
                    {
                        "check_id": f.check_id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "status": f.status,
                        "description": f.description,
                        "current_value": f.current_value,
                        "recommended_value": f.recommended_value,
                        "remediation": f.remediation
                    }
                    for f in result.findings
                ]
            }, indent=2)
        elif format == "markdown":
            md = f"# Security Configuration Hardening Scan Report\n\n"
            md += f"**Scan ID:** {result.scan_id}  \n"
            md += f"**Timestamp:** {result.timestamp}  \n"
            md += f"**Compliance Score:** {result.compliance_score}%  \n\n"
            md += f"## Summary\n\n"
            md += f"- Total Checks: {result.total_checks}\n"
            md += f"- Passed: {result.passed_checks}\n"
            md += f"- Failed: {result.failed_checks}\n\n"
            md += f"## Findings\n\n"
            
            for finding in result.findings:
                status_icon = "✅" if finding.status == "PASS" else "❌"
                md += f"### {status_icon} {finding.title} ({finding.check_id})\n\n"
                md += f"- **Severity:** {finding.severity.value}\n"
                md += f"- **Status:** {finding.status}\n"
                md += f"- **Description:** {finding.description}\n"
                if finding.current_value:
                    md += f"- **Current:** {finding.current_value}\n"
                if finding.recommended_value:
                    md += f"- **Recommended:** {finding.recommended_value}\n"
                if finding.remediation and finding.status != "PASS":
                    md += f"- **Remediation:** {finding.remediation}\n"
                md += "\n"
            
            return md
        else:
            raise ValueError(f"Unsupported format: {format}")

    def get_remediation_prioritization(self, result: ScanResult) -> List[Dict[str, Any]]:
        """Get prioritized list of remediation items."""
        failed_findings = [f for f in result.findings if f.status == "FAIL"]
        
        priority_order = {
            SeverityLevel.CRITICAL: 1,
            SeverityLevel.HIGH: 2,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.LOW: 4,
            SeverityLevel.INFO: 5
        }
        
        sorted_findings = sorted(
            failed_findings,
            key=lambda x: priority_order.get(x.severity, 99)
        )
        
        return [
            {
                "priority": priority_order.get(f.severity),
                "check_id": f.check_id,
                "title": f.title,
                "severity": f.severity.value,
                "remediation": f.remediation
            }
            for f in sorted_findings
        ]
