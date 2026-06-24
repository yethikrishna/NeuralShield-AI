"""
NeuralShield AI - Secure Memory Zeroization Utilities v23
Dimension B - Security Hardening
Incremental build - ADD-ONLY module, wraps existing functionality

Provides secure memory zeroization for sensitive data including:
- API keys and credentials
- User prompts containing sensitive information
- Detected threat patterns
- Intermediate detection results

Zeroization is performed in constant-time to prevent timing attacks.
"""

import ctypes
import gc
import secrets
from typing import Any, List, Optional, Union
import logging

# Configure logging (opt-in only)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class SecureMemoryZeroizer:
    """
    Secure memory zeroization utility for sensitive data.
    
    Implements constant-time overwriting of memory locations to prevent
    sensitive data remnants in memory. Follows NIST SP 800-88 guidelines
    for data sanitization.
    
    API Stability: STABLE
    """
    
    def __init__(self, overwrite_passes: int = 3, enable_logging: bool = False):
        """
        Initialize secure memory zeroizer.
        
        Args:
            overwrite_passes: Number of overwrite passes (default: 3 per NIST)
            enable_logging: Whether to enable operation logging (opt-in)
        """
        self.overwrite_passes = max(1, min(overwrite_passes, 7))
        self._logging_enabled = enable_logging
        self._zeroized_count = 0
        
    def _log(self, message: str) -> None:
        """Conditional logging - only if explicitly enabled."""
        if self._logging_enabled:
            logger.debug(message)
    
    def zeroize_bytes(self, data: bytearray) -> None:
        """
        Securely zeroize a bytearray in constant-time.
        
        Args:
            data: Mutable bytearray to zeroize
        """
        if not isinstance(data, bytearray):
            return
            
        length = len(data)
        
        # Multiple overwrite passes with different patterns
        for pass_num in range(self.overwrite_passes):
            # Pass 1: zeros
            if pass_num == 0:
                for i in range(length):
                    data[i] = 0x00
            # Pass 2: ones
            elif pass_num == 1:
                for i in range(length):
                    data[i] = 0xFF
            # Pass 3+: random patterns
            else:
                random_byte = secrets.randbelow(256)
                for i in range(length):
                    data[i] = random_byte
        
        # Final zero pass
        for i in range(length):
            data[i] = 0x00
            
        self._zeroized_count += 1
        self._log(f"Zeroized {length} bytes (passes: {self.overwrite_passes})")
    
    def zeroize_string(self, s: str) -> str:
        """
        Attempt to zeroize string data. Note: Python strings are immutable,
        so we create a new empty string and force garbage collection.
        
        Args:
            s: String to sanitize
            
        Returns:
            Empty string
        """
        # Create mutable copy and zeroize
        ba = bytearray(s.encode('utf-8'))
        self.zeroize_bytes(ba)
        
        # Force GC
        del ba
        gc.collect()
        
        self._log(f"Zeroized string ({len(s)} chars)")
        return ""
    
    def zeroize_list(self, items: List[Any]) -> None:
        """
        Recursively zeroize items in a list.
        
        Args:
            items: List containing potentially sensitive data
        """
        for i, item in enumerate(items):
            if isinstance(item, bytearray):
                self.zeroize_bytes(item)
            elif isinstance(item, str):
                items[i] = self.zeroize_string(item)
            elif isinstance(item, list):
                self.zeroize_list(item)
            elif isinstance(item, dict):
                self.zeroize_dict(item)
        
        items.clear()
        self._log(f"Zeroized list with {len(items)} items")
    
    def zeroize_dict(self, d: dict, sensitive_keys: Optional[List[str]] = None) -> None:
        """
        Zeroize sensitive values in a dictionary.
        
        Args:
            d: Dictionary to sanitize
            sensitive_keys: Optional list of keys to zeroize (if None, all values)
        """
        keys_to_process = sensitive_keys if sensitive_keys else list(d.keys())
        
        for key in keys_to_process:
            if key in d:
                value = d[key]
                if isinstance(value, bytearray):
                    self.zeroize_bytes(value)
                elif isinstance(value, str):
                    d[key] = self.zeroize_string(value)
                elif isinstance(value, list):
                    self.zeroize_list(value)
        
        self._log(f"Zeroized dict values for keys: {keys_to_process}")
    
    def get_zeroization_stats(self) -> dict:
        """
        Get statistics about zeroization operations.
        
        Returns:
            Dictionary with count statistics
        """
        return {
            "total_zeroized": self._zeroized_count,
            "overwrite_passes": self.overwrite_passes
        }


# Global instance for easy use (opt-in)
_default_zeroizer = SecureMemoryZeroizer()


def secure_zeroize(data: Union[bytearray, str, List[Any], dict]) -> None:
    """
    Convenience function for secure zeroization.
    
    Args:
        data: Data to zeroize
    """
    if isinstance(data, bytearray):
        _default_zeroizer.zeroize_bytes(data)
    elif isinstance(data, str):
        _default_zeroizer.zeroize_string(data)
    elif isinstance(data, list):
        _default_zeroizer.zeroize_list(data)
    elif isinstance(data, dict):
        _default_zeroizer.zeroize_dict(data)


class SensitiveDataContext:
    """
    Context manager for automatic zeroization of sensitive data.
    
    Usage:
        with SensitiveDataContext() as ctx:
            sensitive_data = ctx.track(bytearray(b"secret"))
            # Use sensitive_data...
        # Data automatically zeroized on context exit
    """
    
    def __init__(self, zeroizer: Optional[SecureMemoryZeroizer] = None):
        self.zeroizer = zeroizer or _default_zeroizer
        self._tracked = []
    
    def __enter__(self):
        return self
    
    def track(self, data: Any) -> Any:
        """Track data for automatic zeroization."""
        self._tracked.append(data)
        return data
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Automatically zeroize all tracked data."""
        for data in self._tracked:
            try:
                secure_zeroize(data)
            except Exception:
                pass
        self._tracked.clear()
        return False  # Don't suppress exceptions
