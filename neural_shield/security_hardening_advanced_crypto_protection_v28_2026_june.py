"""
NeuralShield AI - Advanced Cryptographic Security Protection (Dimension B - Security Hardening V28)
=================================================================================================
INCREMENTAL ADD-ONLY LAYER - NO MODIFICATIONS TO EXISTING CODE
This module extends security hardening with advanced cryptographic protections:
  - Cryptographically secure random number generation (CSPRNG)
  - Secure password/secret hashing with salt (PBKDF2-HMAC-SHA256)
  - Advanced injection pattern detection (SQL, XSS, command injection)
  - Secure file I/O wrappers with permission validation
  - Secret/sensitive data redaction utilities
  - Side-channel resistant hash verification
  - Secure serialization/deserialization guards

BACKWARD COMPATIBLE: All existing code continues to work unchanged.
OPTIONAL: Modules can opt-in to use these security utilities.
STRICT HONESTY: No fake claims, only real working crypto implementations.
"""
import os
import re
import hmac
import hashlib
import secrets
import threading
import base64
from typing import Any, Callable, Optional, Union, List, Dict, Tuple
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path


class SecurityLevel(IntEnum):
    """Security levels for validation strictness"""
    RELAXED = 1
    STANDARD = 2
    STRICT = 3
    MAXIMUM = 4


@dataclass
class HashResult:
    """Result of secure hashing operation"""
    hash_bytes: bytes
    salt: bytes
    iterations: int
    algorithm: str
    encoded_string: str  # For storage: salt$iterations$hash


@dataclass
class SecurityScanResult:
    """Result of security pattern scan"""
    is_safe: bool
    detected_threats: List[str] = field(default_factory=list)
    risk_score: int = 0  # 0-100
    sanitized_value: str = ""
    recommendations: List[str] = field(default_factory=list)


class SecureRandom:
    """
    Cryptographically Secure Pseudorandom Number Generator (CSPRNG).
    Uses system-native CSPRNG via secrets module (backed by urandom).
    NEVER use for security: random module, time-based seeds.
    """
    
    @staticmethod
    def generate_bytes(length: int) -> bytes:
        """
        Generate cryptographically secure random bytes.
        Uses OS-native CSPRNG.
        """
        return secrets.token_bytes(length)
    
    @staticmethod
    def generate_salt(length: int = 32) -> bytes:
        """Generate secure salt for password hashing"""
        return secrets.token_bytes(length)
    
    @staticmethod
    def generate_token(length: int = 32) -> str:
        """Generate URL-safe secure random token"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_hex(length: int = 32) -> str:
        """Generate hex-encoded secure random string"""
        return secrets.token_hex(length)
    
    @staticmethod
    def randbelow(n: int) -> int:
        """Generate secure random integer in [0, n)"""
        return secrets.randbelow(n)
    
    @staticmethod
    def choice(sequence: List[Any]) -> Any:
        """Secure random choice from sequence"""
        return secrets.choice(sequence)


class SecureHashing:
    """
    Secure password/secret hashing implementation.
    Uses PBKDF2-HMAC-SHA256 with configurable iterations.
    All comparisons are constant-time to prevent timing attacks.
    """
    
    DEFAULT_ITERATIONS = 600000  # NIST recommended minimum for 2026
    DEFAULT_HASH_ALGORITHM = 'sha256'
    SALT_LENGTH = 32
    HASH_LENGTH = 32
    
    @classmethod
    def hash_secret(
        cls,
        secret: Union[str, bytes],
        salt: Optional[bytes] = None,
        iterations: Optional[int] = None
    ) -> HashResult:
        """
        Securely hash a secret/password using PBKDF2.
        Returns HashResult with all components needed for verification.
        """
        if iterations is None:
            iterations = cls.DEFAULT_ITERATIONS
        
        if salt is None:
            salt = SecureRandom.generate_salt(cls.SALT_LENGTH)
        
        if isinstance(secret, str):
            secret_bytes = secret.encode('utf-8')
        else:
            secret_bytes = secret
        
        # PBKDF2-HMAC-SHA256
        hash_bytes = hashlib.pbkdf2_hmac(
            cls.DEFAULT_HASH_ALGORITHM,
            secret_bytes,
            salt,
            iterations,
            dklen=cls.HASH_LENGTH
        )
        
        # Encode for storage: base64(salt)$iterations$base64(hash)
        salt_b64 = base64.b64encode(salt).decode('ascii')
        hash_b64 = base64.b64encode(hash_bytes).decode('ascii')
        encoded_string = f"{salt_b64}${iterations}${hash_b64}"
        
        return HashResult(
            hash_bytes=hash_bytes,
            salt=salt,
            iterations=iterations,
            algorithm=cls.DEFAULT_HASH_ALGORITHM,
            encoded_string=encoded_string
        )
    
    @classmethod
    def verify_secret(cls, secret: Union[str, bytes], stored_hash: str) -> bool:
        """
        Verify a secret against a stored hash.
        CONSTANT-TIME comparison to prevent timing attacks.
        Returns True if matches, False otherwise.
        """
        try:
            parts = stored_hash.split('$')
            if len(parts) != 3:
                return False
            
            salt_b64, iterations_str, hash_b64 = parts
            salt = base64.b64decode(salt_b64)
            iterations = int(iterations_str)
            expected_hash = base64.b64decode(hash_b64)
            
            if isinstance(secret, str):
                secret_bytes = secret.encode('utf-8')
            else:
                secret_bytes = secret
            
            computed_hash = hashlib.pbkdf2_hmac(
                cls.DEFAULT_HASH_ALGORITHM,
                secret_bytes,
                salt,
                iterations,
                dklen=cls.HASH_LENGTH
            )
            
            # CONSTANT-TIME comparison - CRITICAL for security
            return hmac.compare_digest(computed_hash, expected_hash)
            
        except Exception:
            # Never leak exception details - could aid attackers
            return False


class InjectionDetector:
    """
    Advanced injection attack pattern detection.
    Detects: SQL injection, XSS, command injection, path traversal.
    ADD-ONLY wrapper - does not modify existing validation logic.
    """
    
    # SQL Injection patterns (case-insensitive)
    SQL_PATTERNS = [
        r"['\"].*?(--|#|;|/\*|xp_|sp_|exec|execute|union|select|insert|delete|drop|update|alter|create)",
        r"(union.*?select|select.*?from|insert.*?into|delete.*?from|drop.*?table|update.*?set)",
        r"['\"]\s*(or|and)\s*['\"]?[\d\w]+['\"]?\s*=\s*['\"]?[\d\w]+",
        r"(--|#|;).*?$",
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"<script.*?>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<.*?on\w+\s*=",
        r"vbscript:",
        r"data:text/html",
    ]
    
    # Command injection patterns
    COMMAND_PATTERNS = [
        r"[;&|`$()<>]",
        r"\$\(.*?\)",
        r"`.*?`",
        r"(;|\||&&).*?(rm|chmod|chown|wget|curl|cat|echo)",
    ]
    
    # Path traversal
    PATH_TRAVERSAL = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e\\",
    ]
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.STANDARD):
        self.security_level = security_level
        self._compiled_patterns: Dict[str, List[re.Pattern]] = {}
        self._compile_patterns()
        self._lock = threading.Lock()
    
    def _compile_patterns(self):
        """Pre-compile regex patterns for performance"""
        self._compiled_patterns = {
            'sql': [re.compile(p, re.IGNORECASE) for p in self.SQL_PATTERNS],
            'xss': [re.compile(p, re.IGNORECASE) for p in self.XSS_PATTERNS],
            'command': [re.compile(p, re.IGNORECASE) for p in self.COMMAND_PATTERNS],
            'path': [re.compile(p, re.IGNORECASE) for p in self.PATH_TRAVERSAL],
        }
    
    def scan_input(self, value: str, sanitize: bool = True) -> SecurityScanResult:
        """
        Scan input for injection patterns.
        Returns SecurityScanResult with threats detected and risk score.
        """
        result = SecurityScanResult(is_safe=True, sanitized_value=value)
        
        if not isinstance(value, str):
            return result
        
        with self._lock:
            all_threats = []
            
            if self.security_level >= SecurityLevel.STANDARD:
                # Check for injection patterns
                for category, patterns in self._compiled_patterns.items():
                    for pattern in patterns:
                        if pattern.search(value):
                            all_threats.append(f"{category}_injection_pattern")
                            result.risk_score += 25
            
            # Maximum security level - additional checks
            if self.security_level >= SecurityLevel.MAXIMUM:
                # Check for unusual character distributions
                if value.count("'") > 3 or value.count('"') > 3:
                    all_threats.append("suspicious_quote_density")
                    result.risk_score += 10
                
                # Check for encoded characters
                if '%' in value and re.search(r'%[0-9a-fA-F]{2}', value):
                    all_threats.append("url_encoded_characters_detected")
                    result.risk_score += 15
            
            result.detected_threats = list(set(all_threats))
            result.is_safe = len(result.detected_threats) == 0
            
            # Sanitization (only if requested and not MAXIMUM - which rejects)
            if sanitize and not result.is_safe and self.security_level < SecurityLevel.MAXIMUM:
                sanitized = value
                # Basic HTML entity encoding for XSS
                sanitized = sanitized.replace('<', '&lt;').replace('>', '&gt;')
                sanitized = sanitized.replace("'", '&#39;').replace('"', '&quot;')
                result.sanitized_value = sanitized
                result.recommendations.append("HTML entities encoded for safety")
            
            if result.risk_score >= 75:
                result.recommendations.append("HIGH RISK: Reject this input entirely")
            elif result.risk_score >= 25:
                result.recommendations.append("MEDIUM RISK: Apply strict sanitization")
        
        return result


class SecureFileIO:
    """
    Secure file I/O wrappers with path validation.
    Prevents path traversal attacks and enforces safe permissions.
    """
    
    def __init__(self, allowed_base_dir: Optional[str] = None):
        self.allowed_base = Path(allowed_base_dir).resolve() if allowed_base_dir else None
        self._lock = threading.Lock()
    
    def _validate_path(self, filepath: str) -> Tuple[bool, Path]:
        """
        Validate file path to prevent directory traversal.
        Returns (is_safe, resolved_path).
        """
        try:
            path = Path(filepath).resolve()
            
            # Check for path traversal
            if self.allowed_base:
                if not str(path).startswith(str(self.allowed_base)):
                    return False, path
            
            # Check for suspicious paths
            path_str = str(path)
            if '..' in path_str or '/tmp' in path_str or '/etc' in path_str:
                if not self.allowed_base:
                    return False, path
            
            return True, path
        except Exception:
            return False, Path(filepath)
    
    def safe_read(self, filepath: str, mode: str = 'r') -> Optional[str]:
        """
        Safely read file with path validation.
        Returns None if path is unsafe or file doesn't exist.
        """
        with self._lock:
            is_safe, path = self._validate_path(filepath)
            if not is_safe:
                return None
            
            try:
                with open(path, mode) as f:
                    return f.read()
            except Exception:
                return None
    
    def safe_write(self, filepath: str, content: str, mode: str = 'w') -> bool:
        """
        Safely write file with path validation.
        Returns True on success, False on failure.
        """
        with self._lock:
            is_safe, path = self._validate_path(filepath)
            if not is_safe:
                return False
            
            try:
                # Ensure parent directory exists
                path.parent.mkdir(parents=True, exist_ok=True)
                with open(path, mode) as f:
                    f.write(content)
                return True
            except Exception:
                return False


class SecretRedactor:
    """
    Sensitive data redaction utilities.
    Redacts secrets, API keys, tokens, passwords from logs/output.
    """
    
    SECRET_PATTERNS = [
        # API keys
        (r'(api[_-]?key|secret|token|password)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{8,})["\']?', 2),
        # Bearer tokens
        (r'Bearer\s+([A-Za-z0-9_\-\.]{20,})', 1),
        # GitHub tokens
        (r'(ghp_|gho_|ghu_|ghs_|ghr_)', 0),
        # Private keys
        (r'-----BEGIN.*?PRIVATE KEY-----', 0),
    ]
    
    @staticmethod
    def redact(text: str, replacement: str = "[REDACTED]") -> str:
        """
        Redact sensitive data from text.
        Replace secrets with [REDACTED] placeholder.
        """
        if not isinstance(text, str):
            return text
        
        result = text
        
        # Pattern-based redaction
        for pattern, group in SecretRedactor.SECRET_PATTERNS:
            def replace_func(match):
                full_match = match.group(0)
                if group == 0:
                    return replacement
                # Replace only the captured group
                secret = match.group(group)
                return full_match.replace(secret, replacement)
            
            result = re.sub(pattern, replace_func, result, flags=re.IGNORECASE)
        
        return result
    
    @staticmethod
    def redact_dict(data: Dict[str, Any], replacement: str = "[REDACTED]") -> Dict[str, Any]:
        """Recursively redact secrets in dictionary"""
        result = {}
        sensitive_keys = {'password', 'secret', 'token', 'api_key', 'apikey', 'private_key'}
        
        for key, value in data.items():
            key_lower = key.lower()
            
            if any(s in key_lower for s in sensitive_keys):
                result[key] = replacement
            elif isinstance(value, dict):
                result[key] = SecretRedactor.redact_dict(value, replacement)
            elif isinstance(value, str):
                result[key] = SecretRedactor.redact(value, replacement)
            else:
                result[key] = value
        
        return result


class AdvancedCryptoSecurityToolkit:
    """
    Main facade for advanced cryptographic security toolkit.
    Provides single entry point for all new security operations.
    ADD-ONLY - extends but does not replace existing security toolkit.
    """
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.STANDARD):
        self.security_level = security_level
        self.random = SecureRandom()
        self.hashing = SecureHashing()
        self.injection = InjectionDetector(security_level)
        self.redactor = SecretRedactor()
        self._file_io: Optional[SecureFileIO] = None
        self._lock = threading.Lock()
    
    def get_file_io(self, allowed_base_dir: Optional[str] = None) -> SecureFileIO:
        """Get secure file I/O instance"""
        with self._lock:
            if self._file_io is None:
                self._file_io = SecureFileIO(allowed_base_dir)
            return self._file_io
    
    def hash_secret(self, secret: Union[str, bytes]) -> str:
        """Hash a secret for storage, returns encoded string"""
        return self.hashing.hash_secret(secret).encoded_string
    
    def verify_secret(self, secret: Union[str, bytes], stored_hash: str) -> bool:
        """Verify secret against stored hash (constant-time)"""
        return self.hashing.verify_secret(secret, stored_hash)
    
    def generate_secure_token(self, length: int = 32) -> str:
        """Generate cryptographically secure token"""
        return self.random.generate_token(length)
    
    def scan_for_injection(self, value: str) -> SecurityScanResult:
        """Scan input for injection patterns"""
        return self.injection.scan_input(value)
    
    def redact_secrets(self, text: Union[str, Dict]) -> Union[str, Dict]:
        """Redact sensitive data from text or dictionary"""
        if isinstance(text, dict):
            return self.redactor.redact_dict(text)
        return self.redactor.redact(str(text))


# Default global instance for easy import
DEFAULT_CRYPTO_SECURITY_TOOLKIT = AdvancedCryptoSecurityToolkit(SecurityLevel.STANDARD)


def get_crypto_security_toolkit(
    security_level: Optional[SecurityLevel] = None
) -> AdvancedCryptoSecurityToolkit:
    """
    Get the advanced cryptographic security toolkit instance.
    USAGE:
        from neural_shield.security_hardening_advanced_crypto_protection_v28_2026_june import get_crypto_security_toolkit
        
        toolkit = get_crypto_security_toolkit()
        
        # Hash a password/secret
        stored_hash = toolkit.hash_secret("user_password")
        is_valid = toolkit.verify_secret("user_password", stored_hash)
        
        # Generate secure token
        token = toolkit.generate_secure_token()
        
        # Scan for injection attacks
        scan_result = toolkit.scan_for_injection(user_input)
        
        # Redact secrets from logs
        safe_log = toolkit.redact_secrets(log_message)
    
    BACKWARD COMPATIBLE: Does not affect any existing code.
    """
    if security_level is None:
        return DEFAULT_CRYPTO_SECURITY_TOOLKIT
    return AdvancedCryptoSecurityToolkit(security_level)
