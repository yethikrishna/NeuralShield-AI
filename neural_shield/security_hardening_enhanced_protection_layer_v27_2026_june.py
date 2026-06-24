"""
NeuralShield AI - Enhanced Security Protection Layer (Dimension B - Security Hardening)
=====================================================================================
INCREMENTAL BUILD: ADD-ONLY - NO modifications to existing code.
New security layer providing:
  - Path traversal attack prevention
  - SQL/NoSQL injection protection wrappers
  - Cryptographically secure random utilities
  - File upload/content validation
  - XSS & output encoding protection
  - Header security utilities

BACKWARD COMPATIBLE: 100% backward compatible - wraps, extends, layers on top.
OPTIONAL-IN: All features opt-in, existing code continues to work unchanged.
SIDE-CHANNEL RESISTANT: Constant-time operations where applicable.
"""
import os
import re
import hmac
import html
import secrets
import hashlib
import threading
from pathlib import Path
from typing import Any, Callable, Optional, Union, List, Dict, Tuple, Set
from dataclasses import dataclass, field
from enum import IntEnum
from urllib.parse import urlparse, quote


class ProtectionLevel(IntEnum):
    """Protection strictness levels"""
    BASIC = 1
    STANDARD = 2
    STRICT = 3
    PARANOID = 4


@dataclass
class SecurityCheckResult:
    """Result of a security check operation"""
    is_safe: bool
    threats_detected: List[str] = field(default_factory=list)
    sanitized_value: Any = None
    warnings: List[str] = field(default_factory=list)
    confidence_score: float = 1.0


class PathTraversalProtector:
    """
    Protection against path traversal attacks (../, ..\, etc.)
    Validates file paths to prevent directory escape attacks.
    """
    
    # Known dangerous path patterns
    DANGEROUS_PATTERNS = [
        r'\.\.[/\\]',
        r'[/\\]\.\.',
        r'%2e%2e',
        r'%252e%252e',
        r'\.\.%00',
        r'/\.\./',
        r'\\\.\.\\',
    ]
    
    def __init__(self, base_directory: Optional[str] = None, protection_level: ProtectionLevel = ProtectionLevel.STANDARD):
        self.base_directory = os.path.abspath(base_directory) if base_directory else os.getcwd()
        self.protection_level = protection_level
        self._pattern_cache: Dict[str, bool] = {}
        self._lock = threading.Lock()
    
    def is_safe_path(self, file_path: str, allow_absolute: bool = False) -> SecurityCheckResult:
        """
        Check if a file path is safe from traversal attacks.
        Returns SecurityCheckResult with threats detected if any.
        """
        result = SecurityCheckResult(is_safe=True)
        
        # Check for dangerous patterns
        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, file_path, re.IGNORECASE):
                result.is_safe = False
                result.threats_detected.append(f"Path traversal pattern detected: {pattern}")
        
        # Normalize and validate
        try:
            normalized = os.path.normpath(file_path)
            
            # Check for absolute paths unless explicitly allowed
            if not allow_absolute and os.path.isabs(normalized):
                result.is_safe = False
                result.threats_detected.append("Absolute path not allowed")
            
            # Resolve full path and check it stays within base directory
            full_path = os.path.abspath(os.path.join(self.base_directory, normalized))
            
            if self.protection_level >= ProtectionLevel.STRICT:
                if not full_path.startswith(self.base_directory + os.sep) and full_path != self.base_directory:
                    result.is_safe = False
                    result.threats_detected.append("Path escapes base directory boundary")
            
            result.sanitized_value = normalized
            
        except Exception as e:
            result.is_safe = False
            result.threats_detected.append(f"Path validation error: {str(e)}")
        
        return result
    
    def safe_join(self, *paths: str) -> Tuple[bool, Optional[str]]:
        """
        Safely join path components.
        Returns (is_safe, safe_path) tuple.
        """
        combined = os.path.join(*paths)
        check = self.is_safe_path(combined)
        if check.is_safe:
            full_path = os.path.abspath(os.path.join(self.base_directory, os.path.normpath(combined)))
            return True, full_path
        return False, None


class SQLInjectionProtector:
    """
    SQL/NoSQL injection protection utilities.
    Provides input sanitization and pattern detection.
    """
    
    # SQL injection patterns
    SQL_PATTERNS = [
        r"['\";].*(OR|AND).*=.*['\"]",
        r"(--|#|\/\*).*$",
        r"UNION.*SELECT",
        r"INSERT.*INTO",
        r"DELETE.*FROM",
        r"DROP.*TABLE",
        r"UPDATE.*SET",
        r"EXEC.*sp_",
        r"xp_cmdshell",
        r"WAITFOR.*DELAY",
        r"BENCHMARK.*\(",
    ]
    
    # NoSQL injection patterns
    NOSQL_PATTERNS = [
        r'\{"[$][a-z]+',
        r'\$where',
        r'\$gt',
        r'\$lt',
        r'\$ne',
        r'javascript:',
        r'typeof',
    ]
    
    def __init__(self, protection_level: ProtectionLevel = ProtectionLevel.STANDARD):
        self.protection_level = protection_level
        self._sql_regex = [re.compile(p, re.IGNORECASE) for p in self.SQL_PATTERNS]
        self._nosql_regex = [re.compile(p, re.IGNORECASE) for p in self.NOSQL_PATTERNS]
    
    def sanitize_sql_input(self, value: str) -> str:
        """
        Basic SQL input sanitization - escape dangerous characters.
        Note: Parameterized queries are ALWAYS preferred. This is defense-in-depth.
        """
        if not isinstance(value, str):
            return str(value)
        
        # Basic escaping
        sanitized = value.replace("'", "''")
        sanitized = sanitized.replace(";", "")
        sanitized = sanitized.replace("--", "")
        sanitized = sanitized.replace("/*", "")
        sanitized = sanitized.replace("*/", "")
        
        return sanitized
    
    def check_sql_injection(self, value: str) -> SecurityCheckResult:
        """Check input for SQL injection patterns"""
        result = SecurityCheckResult(is_safe=True)
        
        if not isinstance(value, str):
            result.sanitized_value = value
            return result
        
        for i, pattern in enumerate(self._sql_regex):
            if pattern.search(value):
                result.is_safe = False
                result.threats_detected.append(f"SQL injection pattern detected: {self.SQL_PATTERNS[i]}")
        
        result.sanitized_value = self.sanitize_sql_input(value)
        return result
    
    def check_nosql_injection(self, value: str) -> SecurityCheckResult:
        """Check input for NoSQL injection patterns"""
        result = SecurityCheckResult(is_safe=True)
        
        if not isinstance(value, str):
            result.sanitized_value = value
            return result
        
        for i, pattern in enumerate(self._nosql_regex):
            if pattern.search(value):
                result.is_safe = False
                result.threats_detected.append(f"NoSQL injection pattern detected: {self.NOSQL_PATTERNS[i]}")
        
        result.sanitized_value = value
        return result


class SecureRandomGenerator:
    """
    Cryptographically secure random number generation.
    Uses secrets module for CSPRNG operations.
    """
    
    @staticmethod
    def generate_token(length: int = 32) -> str:
        """Generate a cryptographically secure random token string"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_hex(length: int = 32) -> str:
        """Generate a cryptographically secure random hex string"""
        return secrets.token_hex(length)
    
    @staticmethod
    def random_bytes(length: int = 32) -> bytes:
        """Generate cryptographically secure random bytes"""
        return secrets.token_bytes(length)
    
    @staticmethod
    def random_int(min_val: int = 0, max_val: int = 10**18) -> int:
        """Generate cryptographically secure random integer in range [min_val, max_val]"""
        return secrets.randbelow(max_val - min_val + 1) + min_val
    
    @staticmethod
    def choice(sequence: List[Any]) -> Any:
        """Cryptographically secure random choice from sequence"""
        return secrets.choice(sequence)
    
    @staticmethod
    def compare_digest(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
        """Constant-time comparison for security-sensitive operations"""
        if isinstance(a, str):
            a = a.encode('utf-8')
        if isinstance(b, str):
            b = b.encode('utf-8')
        return hmac.compare_digest(a, b)


class XSSProtector:
    """
    Cross-Site Scripting (XSS) protection utilities.
    Provides output encoding and input validation.
    """
    
    DANGEROUS_HTML_TAGS = [
        '<script', '</script>',
        '<iframe', '</iframe>',
        '<object', '</object>',
        '<embed', '</embed>',
        '<form', '</form>',
        'javascript:',
        'vbscript:',
        'onload=', 'onerror=', 'onclick=',
        'onmouseover=', 'onfocus=',
    ]
    
    def __init__(self, protection_level: ProtectionLevel = ProtectionLevel.STANDARD):
        self.protection_level = protection_level
    
    def encode_html(self, content: str) -> str:
        """HTML encode content to prevent XSS"""
        if not isinstance(content, str):
            return str(content)
        return html.escape(content, quote=True)
    
    def encode_attribute(self, content: str) -> str:
        """Encode for HTML attribute context"""
        return self.encode_html(content).replace('"', '&quot;')
    
    def encode_javascript(self, content: str) -> str:
        """Encode for JavaScript string context"""
        if not isinstance(content, str):
            return str(content)
        
        result = []
        for char in content:
            if char.isalnum() or char in '_-.':
                result.append(char)
            else:
                result.append(f'\\x{ord(char):02x}')
        return ''.join(result)
    
    def sanitize_html_content(self, html_content: str) -> SecurityCheckResult:
        """Sanitize HTML content and check for dangerous patterns"""
        result = SecurityCheckResult(is_safe=True)
        
        if not isinstance(html_content, str):
            result.sanitized_value = str(html_content)
            return result
        
        lower_content = html_content.lower()
        
        for tag in self.DANGEROUS_HTML_TAGS:
            if tag.lower() in lower_content:
                result.is_safe = False
                result.threats_detected.append(f"Dangerous HTML pattern detected: {tag}")
        
        # Basic sanitization - remove script tags
        sanitized = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.IGNORECASE | re.DOTALL)
        sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)
        
        result.sanitized_value = sanitized
        return result


class FileContentValidator:
    """
    File upload and content validation security.
    Validates file types, sizes, and content for malware patterns.
    """
    
    # Magic numbers for file type validation
    FILE_MAGIC_NUMBERS = {
        b'\xff\xd8\xff': 'image/jpeg',
        b'\x89PNG\r\n\x1a\n': 'image/png',
        b'GIF87a': 'image/gif',
        b'GIF89a': 'image/gif',
        b'%PDF-': 'application/pdf',
        b'PK\x03\x04': 'application/zip',
        b'\x1f\x8b\x08': 'application/gzip',
        b'BZh': 'application/bzip2',
        b'\x7fELF': 'application/x-executable',
        b'MZ': 'application/x-dosexec',
    }
    
    # Dangerous content patterns (basic heuristic)
    DANGEROUS_CONTENT = [
        b'<script',
        b'<?php',
        b'<%',
        b'#!/usr/bin',
        b'#!/bin/bash',
        b'python',
        b'exec(',
        b'system(',
    ]
    
    def __init__(
        self,
        max_file_size: int = 10 * 1024 * 1024,  # 10MB default
        allowed_mime_types: Optional[List[str]] = None,
        protection_level: ProtectionLevel = ProtectionLevel.STANDARD
    ):
        self.max_file_size = max_file_size
        self.allowed_mime_types = allowed_mime_types
        self.protection_level = protection_level
    
    def validate_file_content(self, file_content: bytes) -> SecurityCheckResult:
        """Validate file content for security issues"""
        result = SecurityCheckResult(is_safe=True)
        
        # Check file size
        if len(file_content) > self.max_file_size:
            result.is_safe = False
            result.threats_detected.append(f"File too large: {len(file_content)} > {self.max_file_size} bytes")
        
        # Detect file type from magic numbers
        detected_type = None
        for magic, mime in self.FILE_MAGIC_NUMBERS.items():
            if file_content.startswith(magic):
                detected_type = mime
                break
        
        # Check against allowed types if specified
        if self.allowed_mime_types and detected_type:
            if detected_type not in self.allowed_mime_types:
                result.is_safe = False
                result.threats_detected.append(f"File type not allowed: {detected_type}")
        
        # Check for dangerous content patterns
        content_lower = file_content.lower()
        for pattern in self.DANGEROUS_CONTENT:
            if pattern in content_lower and self.protection_level >= ProtectionLevel.STRICT:
                result.warnings.append(f"Potentially dangerous content pattern found: {pattern.decode('utf-8', errors='ignore')}")
        
        result.sanitized_value = file_content  # Return original - validation only
        return result
    
    def is_executable_content(self, file_content: bytes) -> bool:
        """Check if content appears to be executable"""
        exec_magics = [b'\x7fELF', b'MZ', b'#!']
        return any(file_content.startswith(m) for m in exec_magics)


class SecurityHeaderManager:
    """
    Security header utilities for web applications.
    Provides secure header configurations.
    """
    
    @staticmethod
    def get_secure_headers() -> Dict[str, str]:
        """Get recommended security headers"""
        return {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Content-Security-Policy': "default-src 'self'",
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        }
    
    @staticmethod
    def sanitize_header_value(value: str) -> str:
        """Sanitize HTTP header value to prevent header injection"""
        if not isinstance(value, str):
            return str(value)
        # Remove CR/LF characters
        return value.replace('\r', '').replace('\n', '')


class EnhancedSecurityLayer:
    """
    Main facade for enhanced security protection layer.
    Single entry point for all new security features.
    """
    
    def __init__(
        self,
        protection_level: ProtectionLevel = ProtectionLevel.STANDARD,
        base_directory: Optional[str] = None
    ):
        self.protection_level = protection_level
        self.path_protector = PathTraversalProtector(base_directory, protection_level)
        self.sql_protector = SQLInjectionProtector(protection_level)
        self.random = SecureRandomGenerator()
        self.xss_protector = XSSProtector(protection_level)
        self.file_validator = FileContentValidator(protection_level=protection_level)
        self.headers = SecurityHeaderManager()
        self._lock = threading.Lock()
    
    def validate_file_upload(self, content: bytes, filename: str) -> SecurityCheckResult:
        """Comprehensive file upload validation"""
        result = SecurityCheckResult(is_safe=True)
        
        # Check filename for path traversal
        path_check = self.path_protector.is_safe_path(filename)
        if not path_check.is_safe:
            result.is_safe = False
            result.threats_detected.extend(path_check.threats_detected)
        
        # Check file content
        content_check = self.file_validator.validate_file_content(content)
        if not content_check.is_safe:
            result.is_safe = False
            result.threats_detected.extend(content_check.threats_detected)
        
        result.warnings.extend(path_check.warnings)
        result.warnings.extend(content_check.warnings)
        result.sanitized_value = content
        
        return result
    
    def safe_database_input(self, value: str, is_nosql: bool = False) -> SecurityCheckResult:
        """Validate database input for injection attacks"""
        if is_nosql:
            return self.sql_protector.check_nosql_injection(value)
        return self.sql_protector.check_sql_injection(value)
    
    def safe_file_operation(self, file_path: str) -> Tuple[bool, Optional[str]]:
        """Validate path and return safe absolute path"""
        return self.path_protector.safe_join(file_path)
    
    def generate_csrf_token(self) -> str:
        """Generate CSRF protection token"""
        return self.random.generate_token(32)
    
    def encode_for_context(self, content: str, context: str = 'html') -> str:
        """
        Encode content for specific output context.
        Contexts: html, attribute, javascript, url
        """
        if context == 'html':
            return self.xss_protector.encode_html(content)
        elif context == 'attribute':
            return self.xss_protector.encode_attribute(content)
        elif context == 'javascript':
            return self.xss_protector.encode_javascript(content)
        elif context == 'url':
            return quote(content, safe='')
        return content


# Default global instance for easy import
DEFAULT_ENHANCED_SECURITY = EnhancedSecurityLayer(ProtectionLevel.STANDARD)


def get_enhanced_security_layer(
    protection_level: Optional[ProtectionLevel] = None,
    base_directory: Optional[str] = None
) -> EnhancedSecurityLayer:
    """
    Get the enhanced security layer instance.
    
    Usage:
        from neural_shield.security_hardening_enhanced_protection_layer_v27_2026_june import get_enhanced_security_layer
        security = get_enhanced_security_layer()
        
        # Validate file upload
        result = security.validate_file_upload(content, filename)
        if result.is_safe:
            process_file(content)
    
    Args:
        protection_level: BASIC, STANDARD, STRICT, or PARANOID
        base_directory: Base directory for path validation
    
    Returns:
        EnhancedSecurityLayer instance
    """
    if protection_level is None and base_directory is None:
        return DEFAULT_ENHANCED_SECURITY
    level = protection_level or ProtectionLevel.STANDARD
    return EnhancedSecurityLayer(level, base_directory)
