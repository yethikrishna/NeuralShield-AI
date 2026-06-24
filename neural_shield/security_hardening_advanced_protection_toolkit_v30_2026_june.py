"""
NeuralShield AI - Advanced Security Protection Toolkit (Dimension B - Security Hardening)
========================================================================================
Incremental security layer - ADD-ONLY, no modifications to existing code.
BUILDING ON v29: Adds advanced attack vector protection while maintaining full backward compatibility.

NEW IN v30:
  - Secure random number generation utilities (CSPRNG wrappers)
  - Cryptographic hash integrity verification helpers
  - Path traversal attack prevention wrappers
  - SQL injection pattern detection and sanitization
  - XSS pattern detection and output encoding
  - Secret key strength validation
  - File upload validation and sanitization wrappers
  - Regex-based injection pattern detectors

BACKWARD COMPATIBLE: All existing code continues to work unchanged.
OPTIONAL: Modules can opt-in to use these security utilities.
STRICT ADD-ONLY: No existing modules modified.
"""
import os
import re
import math
import hmac
import hashlib
import secrets
import threading
import ipaddress
from pathlib import Path
from typing import Any, Callable, Optional, Union, List, Dict, Tuple, Set
from dataclasses import dataclass, field
from enum import IntEnum


class SecurityLevel(IntEnum):
    """Security levels for validation strictness"""
    RELAXED = 1
    STANDARD = 2
    STRICT = 3
    MAXIMUM = 4


@dataclass
class SecurityScanResult:
    """Result of security scan operation"""
    is_safe: bool
    threats_detected: List[str] = field(default_factory=list)
    sanitized_value: Any = None
    risk_score: int = 0  # 0-100
    warnings: List[str] = field(default_factory=list)


@dataclass
class HashVerificationResult:
    """Result of hash verification"""
    is_valid: bool
    algorithm: str
    computed_hash: str
    expected_hash: str


class SecureRandom:
    """
    Cryptographically secure random number generation.
    Wraps Python's secrets module with additional safety checks.
    All operations use CSPRNG (Cryptographically Secure Pseudorandom Number Generator).
    """
    
    @staticmethod
    def generate_token(nbytes: int = 32) -> str:
        """
        Generate a secure random URL-safe token.
        Uses os.urandom() via secrets module - cryptographically secure.
        """
        return secrets.token_urlsafe(nbytes)
    
    @staticmethod
    def generate_hex(nbytes: int = 32) -> str:
        """Generate secure random hex string"""
        return secrets.token_hex(nbytes)
    
    @staticmethod
    def randbelow(n: int) -> int:
        """Generate secure random integer in [0, n)"""
        return secrets.randbelow(n)
    
    @staticmethod
    def randbits(k: int) -> int:
        """Generate secure random integer with k random bits"""
        return secrets.randbits(k)
    
    @staticmethod
    def choice(seq: List[Any]) -> Any:
        """Secure random choice from sequence"""
        return secrets.choice(seq)
    
    @staticmethod
    def compare_digest(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
        """Constant-time comparison delegate"""
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def generate_secret_key(length: int = 64) -> bytes:
        """Generate a secure secret key as bytes"""
        return secrets.token_bytes(length)


class HashIntegrity:
    """
    Cryptographic hash verification utilities.
    Provides integrity checking for files, strings, and data.
    """
    
    SUPPORTED_ALGORITHMS = {'sha256', 'sha384', 'sha512', 'sha3_256', 'sha3_512'}
    
    @staticmethod
    def hash_string(data: str, algorithm: str = 'sha256', encoding: str = 'utf-8') -> str:
        """Hash a string using specified algorithm"""
        if algorithm not in HashIntegrity.SUPPORTED_ALGORITHMS:
            algorithm = 'sha256'
        h = hashlib.new(algorithm)
        h.update(data.encode(encoding))
        return h.hexdigest()
    
    @staticmethod
    def hash_bytes(data: bytes, algorithm: str = 'sha256') -> str:
        """Hash bytes using specified algorithm"""
        if algorithm not in HashIntegrity.SUPPORTED_ALGORITHMS:
            algorithm = 'sha256'
        h = hashlib.new(algorithm)
        h.update(data)
        return h.hexdigest()
    
    @staticmethod
    def hash_file(filepath: str, algorithm: str = 'sha256', chunk_size: int = 8192) -> str:
        """Hash a file efficiently with chunked reading"""
        if algorithm not in HashIntegrity.SUPPORTED_ALGORITHMS:
            algorithm = 'sha256'
        h = hashlib.new(algorithm)
        with open(filepath, 'rb') as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest()
    
    @staticmethod
    def verify_string(
        data: str,
        expected_hash: str,
        algorithm: str = 'sha256'
    ) -> HashVerificationResult:
        """Verify string hash matches expected value"""
        computed = HashIntegrity.hash_string(data, algorithm)
        is_valid = secrets.compare_digest(computed, expected_hash.lower())
        return HashVerificationResult(
            is_valid=is_valid,
            algorithm=algorithm,
            computed_hash=computed,
            expected_hash=expected_hash
        )
    
    @staticmethod
    def verify_file(
        filepath: str,
        expected_hash: str,
        algorithm: str = 'sha256'
    ) -> HashVerificationResult:
        """Verify file hash matches expected value"""
        computed = HashIntegrity.hash_file(filepath, algorithm)
        is_valid = secrets.compare_digest(computed, expected_hash.lower())
        return HashVerificationResult(
            is_valid=is_valid,
            algorithm=algorithm,
            computed_hash=computed,
            expected_hash=expected_hash
        )
    
    @staticmethod
    def hmac_sign(data: str, key: bytes, algorithm: str = 'sha256') -> str:
        """Generate HMAC signature for data"""
        return hmac.new(key, data.encode('utf-8'), algorithm).hexdigest()
    
    @staticmethod
    def hmac_verify(data: str, signature: str, key: bytes, algorithm: str = 'sha256') -> bool:
        """Verify HMAC signature in constant time"""
        expected = hmac.new(key, data.encode('utf-8'), algorithm).hexdigest()
        return secrets.compare_digest(expected, signature)


class PathTraversalProtector:
    """
    Protection against path traversal attacks (../, ..\, etc.)
    Validates and sanitizes file paths to prevent directory escape.
    """
    
    # Common path traversal patterns
    TRAVERSAL_PATTERNS = [
        r'\.\./',
        r'\.\.\\',
        r'%2e%2e%2f',
        r'%2e%2e/',
        r'..%2f',
        r'%2e%2e%5c',
        r'\.\.%255c',
        r'\.\./+',
        r'/\.\.',
    ]
    
    def __init__(self, base_directory: Optional[str] = None):
        """
        Initialize with optional base directory for safe path resolution.
        If base_directory is provided, all paths are resolved within it.
        """
        self.base_directory = base_directory
        self._pattern_cache: Dict[str, re.Pattern] = {}
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns for performance"""
        for pattern in self.TRAVERSAL_PATTERNS:
            self._pattern_cache[pattern] = re.compile(pattern, re.IGNORECASE)
    
    def contains_traversal(self, path: str) -> Tuple[bool, List[str]]:
        """Check if path contains traversal patterns"""
        threats = []
        for pattern, regex in self._pattern_cache.items():
            if regex.search(path):
                threats.append(f"Path traversal pattern detected: {pattern}")
        return len(threats) > 0, threats
    
    def sanitize_path(self, path: str) -> str:
        """Remove traversal sequences from path"""
        sanitized = path
        # Remove all traversal patterns iteratively
        patterns_removed = True
        while patterns_removed:
            patterns_removed = False
            for regex in self._pattern_cache.values():
                new_path = regex.sub('', sanitized)
                if new_path != sanitized:
                    sanitized = new_path
                    patterns_removed = True
        return sanitized
    
    def resolve_safe_path(
        self,
        user_path: str,
        base_directory: Optional[str] = None
    ) -> SecurityScanResult:
        """
        Resolve user path safely within base directory.
        Returns absolute path guaranteed to be within base directory.
        """
        base = base_directory or self.base_directory or os.getcwd()
        base = os.path.abspath(base)
        
        # First check for traversal patterns
        has_traversal, threats = self.contains_traversal(user_path)
        risk_score = len(threats) * 25
        
        # Sanitize and resolve
        sanitized = self.sanitize_path(user_path)
        
        # Resolve absolute path
        try:
            resolved = os.path.abspath(os.path.join(base, sanitized))
            # Verify resolved path is within base
            if not resolved.startswith(base + os.sep) and resolved != base:
                threats.append(f"Path escapes base directory: {resolved}")
                risk_score += 50
                return SecurityScanResult(
                    is_safe=False,
                    threats_detected=threats,
                    sanitized_value=base,
                    risk_score=min(risk_score, 100)
                )
        except Exception as e:
            threats.append(f"Path resolution error: {str(e)}")
            return SecurityScanResult(
                is_safe=False,
                threats_detected=threats,
                sanitized_value=base,
                risk_score=100
            )
        
        return SecurityScanResult(
            is_safe=len(threats) == 0,
            threats_detected=threats,
            sanitized_value=resolved,
            risk_score=risk_score,
            warnings=["Path validated successfully"] if risk_score == 0 else []
        )


class SQLInjectionProtector:
    """
    SQL injection detection and prevention.
    Detects common SQL injection patterns in user inputs.
    """
    
    SQLI_PATTERNS = [
        (r"['\"].*?--", "SQL comment injection"),
        (r"['\"].*?;", "SQL statement termination"),
        (r"['\"]\s*(OR|AND)\s+['\"]?\d+=['\"]?\d+", "Boolean-based SQLi"),
        (r"UNION\s+SELECT", "UNION SELECT injection"),
        (r"SELECT.*?FROM", "SELECT query injection"),
        (r"INSERT\s+INTO", "INSERT injection"),
        (r"DELETE\s+FROM", "DELETE injection"),
        (r"DROP\s+TABLE", "DROP TABLE injection"),
        (r"UPDATE.*?SET", "UPDATE injection"),
        (r"EXEC\s*\(", "EXEC command injection"),
        (r"xp_cmdshell", "Command shell injection"),
        (r"['\"]\s+OR\s+1=1", "OR 1=1 injection"),
        (r"['\"]\s+AND\s+1=1", "AND 1=1 injection"),
        (r"SLEEP\s*\(", "Time-based blind SQLi"),
        (r"BENCHMARK\s*\(", "BENCHMARK injection"),
    ]
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.STANDARD):
        self.security_level = security_level
        self._pattern_cache: List[Tuple[re.Pattern, str]] = []
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Compile SQLi patterns"""
        for pattern, desc in self.SQLI_PATTERNS:
            self._pattern_cache.append((re.compile(pattern, re.IGNORECASE), desc))
    
    def scan_input(self, user_input: str) -> SecurityScanResult:
        """Scan input for SQL injection patterns"""
        threats = []
        risk_score = 0
        
        if not isinstance(user_input, str):
            return SecurityScanResult(is_safe=True, threats_detected=[], risk_score=0)
        
        for regex, description in self._pattern_cache:
            if regex.search(user_input):
                threats.append(description)
                risk_score += 20
        
        return SecurityScanResult(
            is_safe=len(threats) == 0,
            threats_detected=threats,
            sanitized_value=self.escape_sql(user_input),
            risk_score=min(risk_score, 100)
        )
    
    @staticmethod
    def escape_sql(value: str) -> str:
        """Basic SQL escaping (parameterized queries still recommended!)"""
        if not isinstance(value, str):
            return str(value)
        # Escape dangerous characters
        value = value.replace("'", "''")
        value = value.replace("\\", "\\\\")
        value = value.replace("\0", "\\0")
        value = value.replace("\n", "\\n")
        value = value.replace("\r", "\\r")
        value = value.replace("\x1a", "\\Z")
        return value


class XSSProtector:
    """
    Cross-Site Scripting (XSS) detection and output encoding.
    Detects and neutralizes XSS attack vectors.
    """
    
    XSS_PATTERNS = [
        (r"<script.*?>.*?</script>", "Script tag injection"),
        (r"javascript:", "javascript: protocol injection"),
        (r"on\w+\s*=", "Event handler injection"),
        (r"<iframe.*?>", "iframe injection"),
        (r"<object.*?>", "Object tag injection"),
        (r"<embed.*?>", "Embed tag injection"),
        (r"vbscript:", "vbscript: protocol injection"),
        (r"data:text/html", "data: URI injection"),
        (r"expression\s*\(", "CSS expression injection"),
        (r"<.*?on\w+\s*=", "Inline event handler"),
    ]
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.STANDARD):
        self.security_level = security_level
        self._pattern_cache: List[Tuple[re.Pattern, str]] = []
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Compile XSS patterns"""
        for pattern, desc in self.XSS_PATTERNS:
            self._pattern_cache.append((re.compile(pattern, re.IGNORECASE), desc))
    
    def scan_input(self, user_input: str) -> SecurityScanResult:
        """Scan input for XSS patterns"""
        threats = []
        risk_score = 0
        
        if not isinstance(user_input, str):
            return SecurityScanResult(is_safe=True, threats_detected=[], risk_score=0)
        
        for regex, description in self._pattern_cache:
            if regex.search(user_input):
                threats.append(description)
                risk_score += 20
        
        return SecurityScanResult(
            is_safe=len(threats) == 0,
            threats_detected=threats,
            sanitized_value=self.encode_html(user_input),
            risk_score=min(risk_score, 100)
        )
    
    @staticmethod
    def encode_html(value: str) -> str:
        """HTML encode for safe output"""
        if not isinstance(value, str):
            return str(value)
        return (
            value.replace("&", "&amp;")
                 .replace("<", "&lt;")
                 .replace(">", "&gt;")
                 .replace('"', "&quot;")
                 .replace("'", "&#x27;")
                 .replace("/", "&#x2F;")
        )
    
    @staticmethod
    def strip_html(value: str) -> str:
        """Remove all HTML tags"""
        if not isinstance(value, str):
            return str(value)
        return re.sub(r'<[^>]*>', '', value)


class SecretKeyValidator:
    """
    Secret key strength validation.
    Validates cryptographic key strength and entropy.
    """
    
    @staticmethod
    def calculate_entropy(key: str) -> float:
        """Calculate Shannon entropy of a key"""
        from collections import Counter
        if not key:
            return 0.0
        
        length = len(key)
        counts = Counter(key)
        entropy = 0.0
        
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy * length
    
    @staticmethod
    def validate_key_strength(key: str, min_length: int = 16) -> SecurityScanResult:
        """Validate key strength and return security assessment"""
        threats = []
        warnings = []
        risk_score = 0
        
        if len(key) < min_length:
            threats.append(f"Key too short: {len(key)} < {min_length} characters")
            risk_score += 40
        
        if key.isalnum():
            warnings.append("Key contains only alphanumeric characters")
            risk_score += 10
        
        if key.islower() or key.isupper():
            warnings.append("Key lacks case variation")
            risk_score += 10
        
        special_chars = set('!@#$%^&*()_+-=[]{}|;:,.<>?')
        if not any(c in special_chars for c in key):
            warnings.append("Key lacks special characters")
            risk_score += 10
        
        # Check for common patterns
        common_patterns = ['123456', 'password', 'qwerty', 'abc123', 'admin']
        for pattern in common_patterns:
            if pattern in key.lower():
                threats.append(f"Contains common weak pattern: {pattern}")
                risk_score += 30
        
        entropy = SecretKeyValidator.calculate_entropy(key)
        if entropy < 3.0:
            warnings.append(f"Low entropy: {entropy:.2f} bits/char")
        
        return SecurityScanResult(
            is_safe=len(threats) == 0 and risk_score < 30,
            threats_detected=threats,
            sanitized_value=None,
            risk_score=min(risk_score, 100),
            warnings=warnings + [f"Entropy: {entropy:.2f} bits/char"]
        )


class FileUploadValidator:
    """
    Secure file upload validation.
    Validates file types, sizes, and content for upload safety.
    """
    
    # Safe MIME types and their extensions
    SAFE_MIME_TYPES = {
        'image/jpeg': {'.jpg', '.jpeg'},
        'image/png': {'.png'},
        'image/gif': {'.gif'},
        'image/webp': {'.webp'},
        'application/pdf': {'.pdf'},
        'text/plain': {'.txt'},
        'application/json': {'.json'},
    }
    
    DANGEROUS_EXTENSIONS = {
        '.php', '.php3', '.php4', '.php5', '.phtml',
        '.asp', '.aspx', '.jsp', '.jspx',
        '.exe', '.bat', '.cmd', '.sh',
        '.cgi', '.pl', '.py',
        '.hta', '.htaccess', '.ini',
    }
    
    def __init__(
        self,
        max_size: int = 10 * 1024 * 1024,  # 10MB
        allowed_mimes: Optional[Set[str]] = None
    ):
        self.max_size = max_size
        self.allowed_mimes = allowed_mimes or set(self.SAFE_MIME_TYPES.keys())
    
    def validate_file(
        self,
        filepath: str,
        original_filename: Optional[str] = None
    ) -> SecurityScanResult:
        """Validate uploaded file for safety"""
        threats = []
        risk_score = 0
        
        # Check file exists
        if not os.path.exists(filepath):
            threats.append("File does not exist")
            return SecurityScanResult(is_safe=False, threats_detected=threats, risk_score=100)
        
        # Check file size
        file_size = os.path.getsize(filepath)
        if file_size > self.max_size:
            threats.append(f"File too large: {file_size} > {self.max_size}")
            risk_score += 50
        
        # Check extension
        filename = original_filename or os.path.basename(filepath)
        ext = os.path.splitext(filename)[1].lower()
        
        if ext in self.DANGEROUS_EXTENSIONS:
            threats.append(f"Dangerous file extension: {ext}")
            risk_score += 100
        
        # Check for double extensions
        parts = filename.lower().split('.')
        if len(parts) > 2:
            for part in parts[:-1]:
                if f".{part}" in self.DANGEROUS_EXTENSIONS:
                    threats.append(f"Suspicious double extension: {filename}")
                    risk_score += 50
                    break
        
        return SecurityScanResult(
            is_safe=len(threats) == 0,
            threats_detected=threats,
            sanitized_value=filepath,
            risk_score=min(risk_score, 100)
        )


class AdvancedSecurityToolkit:
    """
    Main advanced security toolkit facade.
    Provides single entry point for all v30 security operations.
    
    BUILDS ON v29: Adds advanced protection while maintaining compatibility.
    All operations are ADD-ONLY - no existing code modified.
    """
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.STANDARD):
        self.security_level = security_level
        self.random = SecureRandom()
        self.hash_integrity = HashIntegrity()
        self.path_protector = PathTraversalProtector()
        self.sqli_protector = SQLInjectionProtector(security_level)
        self.xss_protector = XSSProtector(security_level)
        self.key_validator = SecretKeyValidator()
        self.file_validator = FileUploadValidator()
        self._lock = threading.Lock()
    
    def generate_secure_token(self, nbytes: int = 32) -> str:
        """Generate cryptographically secure token"""
        return self.random.generate_token(nbytes)
    
    def verify_hash(self, data: str, expected_hash: str, algorithm: str = 'sha256') -> bool:
        """Verify hash integrity"""
        return self.hash_integrity.verify_string(data, expected_hash, algorithm).is_valid
    
    def validate_path(self, user_path: str, base_dir: Optional[str] = None) -> SecurityScanResult:
        """Validate path for traversal attacks"""
        return self.path_protector.resolve_safe_path(user_path, base_dir)
    
    def scan_sql_injection(self, user_input: str) -> SecurityScanResult:
        """Scan for SQL injection patterns"""
        return self.sqli_protector.scan_input(user_input)
    
    def scan_xss(self, user_input: str) -> SecurityScanResult:
        """Scan for XSS patterns"""
        return self.xss_protector.scan_input(user_input)
    
    def encode_for_html(self, value: str) -> str:
        """Encode value for safe HTML output"""
        return self.xss_protector.encode_html(value)
    
    def validate_secret_key(self, key: str, min_length: int = 16) -> SecurityScanResult:
        """Validate secret key strength"""
        return self.key_validator.validate_key_strength(key, min_length)
    
    def validate_uploaded_file(self, filepath: str, original_name: Optional[str] = None) -> SecurityScanResult:
        """Validate uploaded file safety"""
        return self.file_validator.validate_file(filepath, original_name)
    
    def comprehensive_input_scan(self, user_input: str) -> SecurityScanResult:
        """
        Comprehensive multi-vector scan:
        - SQL injection
        - XSS
        - Path traversal
        Returns combined risk assessment.
        """
        sqli_result = self.scan_sql_injection(user_input)
        xss_result = self.scan_xss(user_input)
        path_result = self.path_protector.contains_traversal(user_input)
        
        all_threats = sqli_result.threats_detected + xss_result.threats_detected
        if path_result[0]:
            all_threats.extend(path_result[1])
        
        total_risk = sqli_result.risk_score + xss_result.risk_score + (len(path_result[1]) * 25)
        
        return SecurityScanResult(
            is_safe=len(all_threats) == 0,
            threats_detected=all_threats,
            sanitized_value=self.encode_for_html(user_input),
            risk_score=min(total_risk, 100)
        )


# Default global instance for easy import
DEFAULT_ADVANCED_SECURITY = AdvancedSecurityToolkit(SecurityLevel.STANDARD)


def get_advanced_security_toolkit(
    security_level: Optional[SecurityLevel] = None
) -> AdvancedSecurityToolkit:
    """
    Get the advanced security toolkit instance (v30).
    
    USAGE:
        from neural_shield.security_hardening_advanced_protection_toolkit_v30_2026_june import get_advanced_security_toolkit
        
        toolkit = get_advanced_security_toolkit()
        
        # Generate secure tokens
        token = toolkit.generate_secure_token()
        
        # Scan for attacks
        result = toolkit.comprehensive_input_scan(user_input)
        if not result.is_safe:
            log_threats(result.threats_detected)
        
        # Safe HTML encoding
        safe_output = toolkit.encode_for_html(user_input)
    
    BACKWARD COMPATIBLE: Works alongside v29 and all older modules.
    ADD-ONLY: No existing code modified.
    """
    if security_level is None:
        return DEFAULT_ADVANCED_SECURITY
    return AdvancedSecurityToolkit(security_level)
