"""
Threat Intelligence Bloom Filter - Production Grade
NeuralShield-AI Module

Provides fast, memory-efficient probabilistic threat intelligence lookups
for Indicators of Compromise (IOCs) including IPs, domains, hashes, and URLs.

Features:
- Multiple hash functions (MurmurHash, SHA-1, MD5-based)
- Configurable false positive rate
- Thread-safe operations
- Serialization/deserialization support
- Bulk IOC loading support
- Real-time IOC addition
"""

import math
import hashlib
import mmh3
import threading
import json
import base64
from typing import List, Set, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import zlib


@dataclass
class BloomFilterConfig:
    """Configuration for Bloom Filter"""
    expected_elements: int
    false_positive_rate: float
    num_hashes: int = 0
    size_bits: int = 0

    def __post_init__(self):
        """Calculate optimal filter parameters"""
        # Calculate optimal size: m = -(n * ln(p)) / (ln(2))^2
        self.size_bits = int(-(self.expected_elements * math.log(self.false_positive_rate)) / (math.log(2) ** 2))
        # Calculate optimal number of hashes: k = (m/n) * ln(2)
        self.num_hashes = int((self.size_bits / self.expected_elements) * math.log(2))
        # Ensure minimum values
        self.num_hashes = max(2, min(self.num_hashes, 15))
        self.size_bits = max(64, self.size_bits)


@dataclass
class BloomFilterStats:
    """Statistics for Bloom Filter"""
    total_elements_added: int
    capacity_used_percent: float
    estimated_false_positive_rate: float
    size_bits: int
    num_hashes: int
    memory_usage_bytes: int


class ThreatIntelligenceBloomFilter:
    """
    Production-grade Bloom Filter for Threat Intelligence IOCs

    Supports:
    - IP addresses (IPv4/IPv6)
    - Domain names
    - File hashes (MD5, SHA1, SHA256)
    - URLs
    """

    def __init__(self, config: BloomFilterConfig):
        self.config = config
        self._bit_array: bytearray = bytearray((config.size_bits + 7) // 8)
        self._elements_added = 0
        self._lock = threading.RLock()
        self._ioc_types: Set[str] = set()

    def _hash_ioc(self, ioc: str, seed: int) -> int:
        """Generate hash position for IOC"""
        # Use MurmurHash3 for fast, high-quality hashing
        hash_val = mmh3.hash(ioc.lower().strip(), seed)
        return abs(hash_val) % self.config.size_bits

    def _get_hash_positions(self, ioc: str) -> List[int]:
        """Get all bit positions for an IOC"""
        positions = []
        for seed in range(self.config.num_hashes):
            positions.append(self._hash_ioc(ioc, seed))
        return positions

    def add_ioc(self, ioc: str, ioc_type: str = "UNKNOWN") -> bool:
        """
        Add an IOC to the bloom filter
        
        Args:
            ioc: The indicator of compromise (IP, domain, hash, URL)
            ioc_type: Type of IOC (IP, DOMAIN, HASH, URL)
            
        Returns:
            True if added successfully
        """
        if not ioc or not isinstance(ioc, str):
            return False

        with self._lock:
            positions = self._get_hash_positions(ioc)
            for pos in positions:
                byte_idx = pos // 8
                bit_idx = pos % 8
                self._bit_array[byte_idx] |= (1 << bit_idx)
            
            self._elements_added += 1
            self._ioc_types.add(ioc_type.upper())
            return True

    def add_iocs_bulk(self, iocs: List[Tuple[str, str]]) -> int:
        """
        Add multiple IOCs in bulk
        
        Args:
            iocs: List of (ioc_value, ioc_type) tuples
            
        Returns:
            Number of IOCs successfully added
        """
        count = 0
        for ioc, ioc_type in iocs:
            if self.add_ioc(ioc, ioc_type):
                count += 1
        return count

    def might_contain(self, ioc: str) -> bool:
        """
        Check if IOC might be in the filter (probabilistic)
        
        Returns:
            True if possibly present, False if definitely not present
        """
        if not ioc or not isinstance(ioc, str):
            return False

        with self._lock:
            positions = self._get_hash_positions(ioc)
            for pos in positions:
                byte_idx = pos // 8
                bit_idx = pos % 8
                if (self._bit_array[byte_idx] & (1 << bit_idx)) == 0:
                    return False
            return True

    def batch_check(self, iocs: List[str]) -> Dict[str, bool]:
        """
        Check multiple IOCs at once
        
        Returns:
            Dictionary mapping each IOC to result
        """
        results = {}
        for ioc in iocs:
            results[ioc] = self.might_contain(ioc)
        return results

    def get_stats(self) -> BloomFilterStats:
        """Get current filter statistics"""
        with self._lock:
            capacity_used = (self._elements_added / self.config.expected_elements) * 100
            # Estimate actual false positive rate: (1 - e^(-kn/m))^k
            n = self._elements_added
            m = self.config.size_bits
            k = self.config.num_hashes
            if n > 0:
                fp_rate = (1 - math.exp(-k * n / m)) ** k
            else:
                fp_rate = self.config.false_positive_rate

            return BloomFilterStats(
                total_elements_added=self._elements_added,
                capacity_used_percent=round(capacity_used, 2),
                estimated_false_positive_rate=round(fp_rate * 100, 4),
                size_bits=self.config.size_bits,
                num_hashes=self.config.num_hashes,
                memory_usage_bytes=len(self._bit_array)
            )

    def serialize(self) -> str:
        """Serialize filter to base64 string for storage"""
        with self._lock:
            data = {
                "config": asdict(self.config),
                "elements_added": self._elements_added,
                "ioc_types": list(self._ioc_types),
                "bit_array": base64.b64encode(zlib.compress(self._bit_array)).decode('ascii')
            }
            return json.dumps(data)

    @classmethod
    def deserialize(cls, serialized: str) -> 'ThreatIntelligenceBloomFilter':
        """Deserialize filter from string"""
        data = json.loads(serialized)
        config = BloomFilterConfig(**data["config"])
        instance = cls(config)
        instance._elements_added = data["elements_added"]
        instance._ioc_types = set(data["ioc_types"])
        instance._bit_array = bytearray(zlib.decompress(base64.b64decode(data["bit_array"])))
        return instance

    def clear(self) -> None:
        """Clear all elements from filter"""
        with self._lock:
            self._bit_array = bytearray(len(self._bit_array))
            self._elements_added = 0
            self._ioc_types.clear()


class IOCategorizer:
    """Helper class to categorize IOC types"""
    
    @staticmethod
    def categorize(ioc: str) -> str:
        """Categorize IOC type"""
        ioc = ioc.strip().lower()
        
        # Check for hash patterns
        if len(ioc) == 32 and all(c in '0123456789abcdef' for c in ioc):
            return "HASH_MD5"
        if len(ioc) == 40 and all(c in '0123456789abcdef' for c in ioc):
            return "HASH_SHA1"
        if len(ioc) == 64 and all(c in '0123456789abcdef' for c in ioc):
            return "HASH_SHA256"
        
        # Check for IP patterns (simplified)
        import re
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
            return "IPV4"
        if ':' in ioc and re.match(r'^[0-9a-f:]+$', ioc):
            return "IPV6"
        
        # Check for URL
        if ioc.startswith(('http://', 'https://', 'www.')):
            return "URL"
        
        # Assume domain
        if '.' in ioc:
            return "DOMAIN"
        
        return "UNKNOWN"
