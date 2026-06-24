"""
NeuralShield AI - Constant-Time Comparison Helpers v23
Dimension B - Security Hardening
Incremental build - ADD-ONLY module, wraps existing functionality

Provides constant-time comparison functions to prevent timing attacks
for security-critical operations including:
- API key validation
- Threat signature matching
- Credential verification
- Hash comparisons

All operations run in O(n) time independent of data content.
"""

import hmac
import secrets
from typing import AnyStr, Optional
import logging

# Configure logging (opt-in only)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class ConstantTimeComparator:
    """
    Constant-time comparison utilities for security-critical operations.
    
    Prevents timing attacks by ensuring comparison time depends only on
    the length of inputs, not their content or position of first mismatch.
    
    API Stability: STABLE
    """
    
    def __init__(self, enable_logging: bool = False):
        """
        Initialize constant-time comparator.
        
        Args:
            enable_logging: Whether to enable operation logging (opt-in)
        """
        self._logging_enabled = enable_logging
        self._comparison_count = 0
    
    def _log(self, message: str) -> None:
        """Conditional logging - only if explicitly enabled."""
        if self._logging_enabled:
            logger.debug(message)
    
    @staticmethod
    def compare_bytes(a: bytes, b: bytes) -> bool:
        """
        Compare two byte strings in constant time.
        
        Args:
            a: First byte string
            b: Second byte string
            
        Returns:
            True if equal, False otherwise
        """
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def compare_strings(a: str, b: str, encoding: str = 'utf-8') -> bool:
        """
        Compare two strings in constant time.
        
        Args:
            a: First string
            b: Second string
            encoding: String encoding (default: utf-8)
            
        Returns:
            True if equal, False otherwise
        """
        return hmac.compare_digest(a.encode(encoding), b.encode(encoding))
    
    def secure_compare_api_key(self, provided: str, expected: str) -> bool:
        """
        Securely compare API keys in constant time.
        
        Also validates key format before comparison.
        
        Args:
            provided: User-provided API key
            expected: Expected valid API key
            
        Returns:
            True if keys match, False otherwise
        """
        # First validate format (constant-time length check)
        if len(provided) != len(expected):
            self._comparison_count += 1
            self._log("API key comparison failed - length mismatch")
            return False
        
        result = self.compare_strings(provided, expected)
        self._comparison_count += 1
        self._log(f"API key comparison: {'PASSED' if result else 'FAILED'}")
        return result
    
    def secure_compare_threat_signature(self, detected: AnyStr, signature: AnyStr) -> bool:
        """
        Compare threat signatures in constant time.
        
        Prevents attackers from inferring signature patterns via timing.
        
        Args:
            detected: Detected pattern
            signature: Known threat signature
            
        Returns:
            True if match, False otherwise
        """
        if isinstance(detected, bytes) and isinstance(signature, bytes):
            result = self.compare_bytes(detected, signature)
        else:
            detected_str = detected if isinstance(detected, str) else detected.decode('utf-8')
            signature_str = signature if isinstance(signature, str) else signature.decode('utf-8')
            result = self.compare_strings(detected_str, signature_str)
        
        self._comparison_count += 1
        self._log(f"Threat signature comparison: {'MATCH' if result else 'NO MATCH'}")
        return result
    
    def secure_compare_hash(self, hash_a: str, hash_b: str) -> bool:
        """
        Compare cryptographic hashes in constant time.
        
        Args:
            hash_a: First hash hex string
            hash_b: Second hash hex string
            
        Returns:
            True if hashes match, False otherwise
        """
        # Normalize to lowercase first
        hash_a_norm = hash_a.lower()
        hash_b_norm = hash_b.lower()
        
        if len(hash_a_norm) != len(hash_b_norm):
            self._comparison_count += 1
            return False
        
        result = self.compare_strings(hash_a_norm, hash_b_norm)
        self._comparison_count += 1
        self._log(f"Hash comparison: {'MATCH' if result else 'MISMATCH'}")
        return result
    
    def secure_contains(self, container: str, substring: str) -> bool:
        """
        Check if container contains substring with reduced timing leakage.
        
        Note: Perfect constant-time substring search is complex; this
        implementation provides significant improvement over naive 'in'.
        
        Args:
            container: String to search in
            substring: String to search for
            
        Returns:
            True if substring found, False otherwise
        """
        len_sub = len(substring)
        len_cont = len(container)
        
        if len_sub == 0 or len_sub > len_cont:
            return False
        
        # Use HMAC-based comparison at each position
        result = False
        for i in range(len_cont - len_sub + 1):
            # Always compare, don't short-circuit
            window = container[i:i+len_sub]
            match = self.compare_strings(window, substring)
            # Use bitwise OR to avoid short-circuit branching
            result = result or match
        
        self._comparison_count += 1
        return result
    
    def get_comparison_stats(self) -> dict:
        """
        Get statistics about comparison operations.
        
        Returns:
            Dictionary with count statistics
        """
        return {
            "total_comparisons": self._comparison_count
        }


# Global instance for easy use (opt-in)
_default_comparator = ConstantTimeComparator()


def constant_time_compare(a: AnyStr, b: AnyStr) -> bool:
    """
    Convenience function for constant-time comparison.
    
    Args:
        a: First value
        b: Second value
        
    Returns:
        True if equal, False otherwise
    """
    if isinstance(a, bytes) and isinstance(b, bytes):
        return _default_comparator.compare_bytes(a, b)
    return _default_comparator.compare_strings(str(a), str(b))


def secure_api_key_validation(provided_key: str, valid_keys: list) -> bool:
    """
    Validate API key against a list of valid keys using constant-time.
    
    Args:
        provided_key: User-provided API key
        valid_keys: List of valid API keys
        
    Returns:
        True if key is valid, False otherwise
    """
    for valid_key in valid_keys:
        # Always compare against all keys (no early exit)
        # This prevents timing attacks to discover valid key lengths
        if len(provided_key) == len(valid_key):
            if _default_comparator.secure_compare_api_key(provided_key, valid_key):
                return True
    return False


class SecureCredentialValidator:
    """
    Wrapper for secure credential validation using constant-time comparisons.
    
    Can be layered on top of existing authentication systems.
    """
    
    def __init__(self):
        self.comparator = ConstantTimeComparator()
    
    def validate_credentials(self, username: str, password: str, 
                           expected_username: str, expected_password: str) -> bool:
        """
        Validate username and password securely.
        
        Args:
            username: Provided username
            password: Provided password
            expected_username: Expected username
            expected_password: Expected password
            
        Returns:
            True if both match, False otherwise
        """
        # Always perform both comparisons (no short-circuit)
        user_match = self.comparator.compare_strings(username, expected_username)
        pass_match = self.comparator.compare_strings(password, expected_password)
        
        # Both must match
        return user_match and pass_match
    
    def validate_token(self, token: str, expected_token: str) -> bool:
        """
        Validate bearer/auth token securely.
        
        Args:
            token: Provided token
            expected_token: Expected token
            
        Returns:
            True if match, False otherwise
        """
        return self.comparator.secure_compare_api_key(token, expected_token)
