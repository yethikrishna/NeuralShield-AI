"""
LLM API Gateway Security Validator - NeuralShield-AI
June 17, 2026 - Production Release

Production-grade API security middleware for LLM endpoints:
- Request payload injection scanning
- API key validation & rate limiting integration
- Header security validation
- Payload schema validation
- Suspicious request pattern detection
- Request tampering detection
"""

import hashlib
import hmac
import re
import time
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict


class APIAttackType(Enum):
    """Types of API attacks detected"""
    PAYLOAD_INJECTION = "payload_injection"
    HEADER_INJECTION = "header_injection"
    API_KEY_TAMPERING = "api_key_tampering"
    REPLAY_ATTACK = "replay_attack"
    SCHEMA_VIOLATION = "schema_violation"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    OVERSIZE_PAYLOAD = "oversize_payload"
    MALFORMED_JSON = "malformed_json"


class SecurityRiskLevel(Enum):
    """Risk levels for API security findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


@dataclass
class SecurityFinding:
    """Individual security finding from validation"""
    attack_type: APIAttackType
    risk_level: SecurityRiskLevel
    description: str
    location: str
    confidence: float  # 0.0 - 1.0
    evidence: str = ""


@dataclass
class APIValidationResult:
    """Complete API request validation result"""
    is_safe: bool
    overall_risk: SecurityRiskLevel
    findings: List[SecurityFinding] = field(default_factory=list)
    request_id: str = ""
    validation_timestamp: float = field(default_factory=time.time)
    blocked: bool = False
    block_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_safe": self.is_safe,
            "overall_risk": self.overall_risk.value,
            "findings": [
                {
                    "attack_type": f.attack_type.value,
                    "risk_level": f.risk_level.value,
                    "description": f.description,
                    "location": f.location,
                    "confidence": f.confidence,
                    "evidence": f.evidence
                }
                for f in self.findings
            ],
            "request_id": self.request_id,
            "validation_timestamp": self.validation_timestamp,
            "blocked": self.blocked,
            "block_reason": self.block_reason
        }


@dataclass
class ValidatedRequest:
    """Sanitized and validated request object"""
    method: str
    path: str
    headers: Dict[str, str]
    body: Dict[str, Any]
    query_params: Dict[str, str]
    client_ip: str
    timestamp: float
    signature_valid: bool = False


class APIGatewaySecurityValidator:
    """
    Production-grade API security validator for LLM endpoints.
    
    Features:
    - Payload injection scanning in all request parts
    - Request signature validation
    - Header security validation
    - JSON schema enforcement
    - Suspicious pattern detection
    - Replay attack prevention
    - Request size limits
    """

    # Injection patterns commonly used in API attacks
    INJECTION_PATTERNS = [
        (r'(system_prompt|ignore.*previous|disregard.*instructions)', APIAttackType.PAYLOAD_INJECTION, SecurityRiskLevel.HIGH),
        (r'(<\|begin_of_text\|>|<\|end_of_text\|>|<<SYS>>|\[INST\])', APIAttackType.PAYLOAD_INJECTION, SecurityRiskLevel.HIGH),
        (r'(\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8})', APIAttackType.PAYLOAD_INJECTION, SecurityRiskLevel.MEDIUM),
        (r'(eval\(|exec\(|__import__|os\.system|subprocess)', APIAttackType.PAYLOAD_INJECTION, SecurityRiskLevel.CRITICAL),
        (r'(javascript:|data:text/html|vbscript:)', APIAttackType.PAYLOAD_INJECTION, SecurityRiskLevel.HIGH),
        (r'(\.\.\/|%2e%2e%2f|..%5c)', APIAttackType.PAYLOAD_INJECTION, SecurityRiskLevel.HIGH),
    ]

    # Suspicious header patterns
    SUSPICIOUS_HEADERS = [
        (r'X-Forwarded-For.*,.*,.*,', APIAttackType.HEADER_INJECTION, SecurityRiskLevel.MEDIUM),
        (r'(User-Agent|Referer).*(sqlmap|nikto|nmap|burp)', APIAttackType.HEADER_INJECTION, SecurityRiskLevel.HIGH),
    ]

    # Maximum payload sizes (bytes)
    MAX_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10MB
    MAX_PROMPT_LENGTH = 100000  # characters

    def __init__(
        self,
        api_key_secret: Optional[str] = None,
        enable_signature_validation: bool = False,
        max_payload_size: int = MAX_PAYLOAD_SIZE,
        block_on_critical: bool = True
    ):
        self.api_key_secret = api_key_secret
        self.enable_signature_validation = enable_signature_validation
        self.max_payload_size = max_payload_size
        self.block_on_critical = block_on_critical
        self.request_timestamps: Dict[str, List[float]] = defaultdict(list)
        self.compiled_patterns = [
            (re.compile(pattern, re.IGNORECASE), attack_type, risk)
            for pattern, attack_type, risk in self.INJECTION_PATTERNS
        ]
        self.compiled_header_patterns = [
            (re.compile(pattern, re.IGNORECASE), attack_type, risk)
            for pattern, attack_type, risk in self.SUSPICIOUS_HEADERS
        ]

    def validate_request(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        body: Optional[str] = None,
        query_params: Optional[Dict[str, str]] = None,
        client_ip: str = "unknown",
        api_key: Optional[str] = None,
        request_signature: Optional[str] = None
    ) -> APIValidationResult:
        """
        Validate an entire API request for security issues.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            headers: Request headers dictionary
            body: Raw request body string
            query_params: Query parameters dictionary
            client_ip: Client IP address
            api_key: API key for validation
            request_signature: HMAC signature for request validation
            
        Returns:
            APIValidationResult with all findings
        """
        findings: List[SecurityFinding] = []
        request_id = self._generate_request_id()

        # 1. Validate payload size
        if body and len(body.encode('utf-8')) > self.max_payload_size:
            findings.append(SecurityFinding(
                attack_type=APIAttackType.OVERSIZE_PAYLOAD,
                risk_level=SecurityRiskLevel.HIGH,
                description=f"Payload exceeds maximum size limit",
                location="body",
                confidence=1.0,
                evidence=f"Size: {len(body.encode('utf-8'))} bytes"
            ))

        # 2. Parse and validate JSON body
        parsed_body = {}
        if body and body.strip():
            try:
                parsed_body = json.loads(body)
                findings.extend(self._validate_json_schema(parsed_body, path))
            except json.JSONDecodeError as e:
                findings.append(SecurityFinding(
                    attack_type=APIAttackType.MALFORMED_JSON,
                    risk_level=SecurityRiskLevel.MEDIUM,
                    description=f"Malformed JSON in request body",
                    location="body",
                    confidence=1.0,
                    evidence=str(e)
                ))

        # 3. Scan for injection patterns
        findings.extend(self._scan_for_injection_patterns(body or "", "body"))
        findings.extend(self._scan_headers(headers))

        if query_params:
            for key, value in query_params.items():
                findings.extend(self._scan_for_injection_patterns(
                    str(value), f"query_param:{key}"
                ))

        # 4. Validate prompt length if present
        if "prompt" in parsed_body:
            prompt_len = len(str(parsed_body["prompt"]))
            if prompt_len > self.MAX_PROMPT_LENGTH:
                findings.append(SecurityFinding(
                    attack_type=APIAttackType.OVERSIZE_PAYLOAD,
                    risk_level=SecurityRiskLevel.MEDIUM,
                    description=f"Prompt exceeds recommended length",
                    location="body.prompt",
                    confidence=1.0,
                    evidence=f"Length: {prompt_len} chars"
                ))

        # 5. Signature validation if enabled
        if self.enable_signature_validation and self.api_key_secret:
            signature_valid = self._validate_request_signature(
                method, path, body, request_signature
            )
            if not signature_valid:
                findings.append(SecurityFinding(
                    attack_type=APIAttackType.API_KEY_TAMPERING,
                    risk_level=SecurityRiskLevel.CRITICAL,
                    description="Request signature validation failed",
                    location="signature",
                    confidence=1.0
                ))

        # 6. Check for replay attacks
        findings.extend(self._check_replay_attack(client_ip, api_key))

        # Determine overall risk and safety
        overall_risk = self._calculate_overall_risk(findings)
        is_safe = overall_risk in (SecurityRiskLevel.LOW, SecurityRiskLevel.SAFE)
        
        # Determine if request should be blocked
        blocked = False
        block_reason = ""
        if self.block_on_critical:
            critical_findings = [f for f in findings if f.risk_level == SecurityRiskLevel.CRITICAL]
            if critical_findings:
                blocked = True
                block_reason = f"Critical security issues detected: {len(critical_findings)}"

        return APIValidationResult(
            is_safe=is_safe and not blocked,
            overall_risk=overall_risk,
            findings=findings,
            request_id=request_id,
            blocked=blocked,
            block_reason=block_reason
        )

    def _scan_for_injection_patterns(
        self,
        content: str,
        location: str
    ) -> List[SecurityFinding]:
        """Scan content for injection patterns"""
        findings = []
        if not content:
            return findings

        for pattern, attack_type, risk_level in self.compiled_patterns:
            matches = pattern.findall(content)
            if matches:
                confidence = min(1.0, len(matches) * 0.25 + 0.5)
                findings.append(SecurityFinding(
                    attack_type=attack_type,
                    risk_level=risk_level,
                    description=f"Injection pattern detected in {location}",
                    location=location,
                    confidence=confidence,
                    evidence=f"Matched: {matches[0] if matches else 'pattern'}"
                ))

        return findings

    def _scan_headers(self, headers: Dict[str, str]) -> List[SecurityFinding]:
        """Scan headers for suspicious patterns"""
        findings = []
        headers_str = json.dumps(headers)

        for pattern, attack_type, risk_level in self.compiled_header_patterns:
            if pattern.search(headers_str):
                findings.append(SecurityFinding(
                    attack_type=attack_type,
                    risk_level=risk_level,
                    description=f"Suspicious header pattern detected",
                    location="headers",
                    confidence=0.8
                ))

        return findings

    def _validate_json_schema(self, body: Dict[str, Any], path: str) -> List[SecurityFinding]:
        """Validate JSON body against expected LLM API schema"""
        findings = []

        # Check for unexpected dangerous fields
        dangerous_fields = ["code", "execute", "eval", "system", "shell"]
        for field in dangerous_fields:
            if field in body:
                findings.append(SecurityFinding(
                    attack_type=APIAttackType.SCHEMA_VIOLATION,
                    risk_level=SecurityRiskLevel.HIGH,
                    description=f"Unexpected dangerous field in request: {field}",
                    location=f"body.{field}",
                    confidence=0.9
                ))

        # Validate common LLM API fields exist for chat/completions
        if "/chat/completions" in path or "/completions" in path:
            if "messages" not in body and "prompt" not in body:
                findings.append(SecurityFinding(
                    attack_type=APIAttackType.SCHEMA_VIOLATION,
                    risk_level=SecurityRiskLevel.LOW,
                    description="Missing expected field: messages or prompt",
                    location="body",
                    confidence=1.0
                ))

        return findings

    def _validate_request_signature(
        self,
        method: str,
        path: str,
        body: Optional[str],
        signature: Optional[str]
    ) -> bool:
        """Validate HMAC request signature"""
        if not signature or not self.api_key_secret:
            return False

        message = f"{method}:{path}:{body or ''}"
        expected = hmac.new(
            self.api_key_secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(expected, signature)

    def _check_replay_attack(self, client_ip: str, api_key: Optional[str]) -> List[SecurityFinding]:
        """Check for potential replay attacks"""
        findings = []
        key = api_key or client_ip
        now = time.time()

        # Clean old timestamps (keep last 60 seconds)
        self.request_timestamps[key] = [
            ts for ts in self.request_timestamps[key]
            if now - ts < 60
        ]

        # Check for request flooding
        if len(self.request_timestamps[key]) > 100:
            findings.append(SecurityFinding(
                attack_type=APIAttackType.REPLAY_ATTACK,
                risk_level=SecurityRiskLevel.MEDIUM,
                description="High request frequency detected - potential replay/flood attack",
                location="rate_limit",
                confidence=0.7,
                evidence=f"{len(self.request_timestamps[key])} requests in 60s"
            ))

        self.request_timestamps[key].append(now)
        return findings

    def _calculate_overall_risk(self, findings: List[SecurityFinding]) -> SecurityRiskLevel:
        """Calculate overall risk level from all findings"""
        if not findings:
            return SecurityRiskLevel.SAFE

        risk_priority = {
            SecurityRiskLevel.CRITICAL: 4,
            SecurityRiskLevel.HIGH: 3,
            SecurityRiskLevel.MEDIUM: 2,
            SecurityRiskLevel.LOW: 1,
            SecurityRiskLevel.SAFE: 0
        }

        max_risk = max(
            findings,
            key=lambda f: risk_priority[f.risk_level]
        )

        return max_risk.risk_level

    def _generate_request_id(self) -> str:
        """Generate unique request ID"""
        return hashlib.sha256(
            f"{time.time()}:{id(self)}".encode()
        ).hexdigest()[:16]

    def sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Remove sensitive information from headers for logging"""
        sensitive_headers = ["authorization", "api-key", "x-api-key", "cookie"]
        return {
            k: ("[REDACTED]" if k.lower() in sensitive_headers else v)
            for k, v in headers.items()
        }


def create_api_security_validator(
    api_key_secret: Optional[str] = None,
    enable_signature_validation: bool = False,
    max_payload_size: int = APIGatewaySecurityValidator.MAX_PAYLOAD_SIZE,
    block_on_critical: bool = True
) -> APIGatewaySecurityValidator:
    """Factory function to create API security validator"""
    return APIGatewaySecurityValidator(
        api_key_secret=api_key_secret,
        enable_signature_validation=enable_signature_validation,
        max_payload_size=max_payload_size,
        block_on_critical=block_on_critical
    )


# Export public API
__all__ = [
    "APIGatewaySecurityValidator",
    "APIAttackType",
    "SecurityRiskLevel",
    "SecurityFinding",
    "APIValidationResult",
    "ValidatedRequest",
    "create_api_security_validator"
]
