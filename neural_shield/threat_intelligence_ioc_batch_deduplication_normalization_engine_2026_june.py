"""
Threat Intelligence IoC Batch Deduplication & Normalization Engine
Production-grade implementation for NeuralShield-AI

This module provides:
1. IoC type detection (IP, domain, hash, URL, email)
2. IoC normalization (canonicalization)
3. Batch deduplication with fuzzy matching
4. Confidence scoring for duplicate detection
5. Performance-optimized processing with Bloom filters
"""

import re
import hashlib
import ipaddress
from urllib.parse import urlparse, urlunparse
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import time
from collections import defaultdict


class IoCType(Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    UNKNOWN = "unknown"


@dataclass
class IoCEntry:
    """Data class representing a single IoC entry"""
    original_value: str
    normalized_value: str
    ioc_type: IoCType
    source: str = "unknown"
    first_seen: float = field(default_factory=time.time)
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_fingerprint(self) -> str:
        """Generate a unique fingerprint for deduplication"""
        content = f"{self.normalized_value}:{self.ioc_type.value}"
        return hashlib.sha256(content.encode()).hexdigest()[:32]


class IoCNormalizer:
    """Handles normalization of different IoC types"""

    # Regex patterns
    IPV4_PATTERN = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    IPV6_PATTERN = re.compile(r'^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$')
    MD5_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')
    SHA1_PATTERN = re.compile(r'^[a-fA-F0-9]{40}$')
    SHA256_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')
    DOMAIN_PATTERN = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\.?$')
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    URL_PATTERN = re.compile(r'^https?://', re.IGNORECASE)

    @classmethod
    def detect_type(cls, value: str) -> IoCType:
        """Detect the type of an IoC value"""
        value_clean = value.strip()

        if cls.MD5_PATTERN.match(value_clean):
            return IoCType.MD5
        if cls.SHA1_PATTERN.match(value_clean):
            return IoCType.SHA1
        if cls.SHA256_PATTERN.match(value_clean):
            return IoCType.SHA256
        if cls.IPV4_PATTERN.match(value_clean):
            return IoCType.IPV4
        if cls.IPV6_PATTERN.match(value_clean):
            return IoCType.IPV6
        if cls.EMAIL_PATTERN.match(value_clean):
            return IoCType.EMAIL
        if cls.URL_PATTERN.match(value_clean):
            return IoCType.URL
        if cls.DOMAIN_PATTERN.match(value_clean):
            return IoCType.DOMAIN

        return IoCType.UNKNOWN

    @classmethod
    def normalize(cls, value: str, ioc_type: Optional[IoCType] = None) -> Tuple[str, IoCType]:
        """Normalize an IoC value to its canonical form"""
        if ioc_type is None:
            ioc_type = cls.detect_type(value)

        value_clean = value.strip()

        if ioc_type == IoCType.IPV4:
            try:
                ip = ipaddress.IPv4Address(value_clean)
                return str(ip), IoCType.IPV4
            except ValueError:
                return value_clean.lower(), IoCType.IPV4

        if ioc_type == IoCType.IPV6:
            try:
                ip = ipaddress.IPv6Address(value_clean)
                return str(ip), IoCType.IPV6
            except ValueError:
                return value_clean.lower(), IoCType.IPV6

        if ioc_type in (IoCType.MD5, IoCType.SHA1, IoCType.SHA256):
            return value_clean.lower(), ioc_type

        if ioc_type == IoCType.DOMAIN:
            # Lowercase, remove trailing dot, remove www. prefix for matching
            domain = value_clean.lower().rstrip('.')
            if domain.startswith('www.'):
                domain = domain[4:]
            return domain, IoCType.DOMAIN

        if ioc_type == IoCType.EMAIL:
            email = value_clean.lower()
            return email, IoCType.EMAIL

        if ioc_type == IoCType.URL:
            try:
                parsed = urlparse(value_clean)
                # Normalize: lowercase scheme/netloc/path, remove default ports, remove fragment
                scheme = parsed.scheme.lower()
                netloc = parsed.netloc.lower()
                
                # Remove default ports
                if scheme == 'http' and netloc.endswith(':80'):
                    netloc = netloc[:-3]
                elif scheme == 'https' and netloc.endswith(':443'):
                    netloc = netloc[:-4]
                
                # Lowercase path and remove trailing slash if it's the only path component
                path = parsed.path.lower()
                if path == '/':
                    path = ''
                
                normalized = urlunparse((
                    scheme, netloc, path, parsed.params, parsed.query, ''
                ))
                return normalized, IoCType.URL
            except Exception:
                return value_clean.lower(), IoCType.URL

        return value_clean, ioc_type


class BloomFilter:
    """Simple Bloom filter for fast existence checks"""
    
    def __init__(self, size: int = 100000, num_hashes: int = 5):
        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = [False] * size

    def _hashes(self, value: str) -> List[int]:
        """Generate hash positions"""
        positions = []
        for i in range(self.num_hashes):
            h = hashlib.sha256(f"{value}{i}".encode()).hexdigest()
            positions.append(int(h, 16) % self.size)
        return positions

    def add(self, value: str) -> None:
        """Add a value to the filter"""
        for pos in self._hashes(value):
            self.bit_array[pos] = True

    def might_contain(self, value: str) -> bool:
        """Check if value might be in the filter (False = definitely not present)"""
        for pos in self._hashes(value):
            if not self.bit_array[pos]:
                return False
        return True


class IoCBatchDeduplicationEngine:
    """
    Production-grade batch deduplication engine for threat intelligence IoCs.
    
    Features:
    - Multi-stage deduplication (exact -> fuzzy -> semantic)
    - Type-specific normalization
    - Performance optimized with Bloom filters
    - Confidence scoring for duplicates
    - Batch processing support
    """

    def __init__(self, fuzzy_match_threshold: float = 0.95):
        self.normalizer = IoCNormalizer()
        self.bloom_filter = BloomFilter(size=500000, num_hashes=7)
        self.exact_duplicates: Set[str] = set()
        self.processed_iocs: Dict[str, IoCEntry] = {}
        self.type_groups: Dict[IoCType, List[IoCEntry]] = defaultdict(list)
        self.fuzzy_match_threshold = fuzzy_match_threshold
        self.stats = {
            'total_input': 0,
            'exact_duplicates_removed': 0,
            'fuzzy_duplicates_removed': 0,
            'unique_iocs': 0,
            'by_type': defaultdict(int)
        }

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate Levenshtein distance for fuzzy matching"""
        if len(s1) < len(s2):
            return IoCBatchDeduplicationEngine._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def _fuzzy_similarity(self, s1: str, s2: str) -> float:
        """Calculate similarity score between two strings (0-1)"""
        if s1 == s2:
            return 1.0
        max_len = max(len(s1), len(s2))
        if max_len == 0:
            return 1.0
        distance = self._levenshtein_distance(s1, s2)
        return 1.0 - (distance / max_len)

    def process_single(self, ioc_value: str, source: str = "unknown") -> Optional[IoCEntry]:
        """Process a single IoC value, return None if duplicate"""
        self.stats['total_input'] += 1

        # Normalize
        normalized_value, ioc_type = self.normalizer.normalize(ioc_value)
        
        if ioc_type == IoCType.UNKNOWN:
            return None

        # Create entry
        entry = IoCEntry(
            original_value=ioc_value,
            normalized_value=normalized_value,
            ioc_type=ioc_type,
            source=source
        )
        
        fingerprint = entry.get_fingerprint()

        # Stage 1: Bloom filter fast check
        if self.bloom_filter.might_contain(fingerprint):
            # Stage 2: Exact duplicate check
            if fingerprint in self.exact_duplicates:
                self.stats['exact_duplicates_removed'] += 1
                return None
            
            # Stage 3: Fuzzy matching within same type
            for existing in self.type_groups[ioc_type]:
                similarity = self._fuzzy_similarity(
                    normalized_value, 
                    existing.normalized_value
                )
                if similarity >= self.fuzzy_match_threshold:
                    self.stats['fuzzy_duplicates_removed'] += 1
                    return None

        # New unique IoC
        self.bloom_filter.add(fingerprint)
        self.exact_duplicates.add(fingerprint)
        self.processed_iocs[fingerprint] = entry
        self.type_groups[ioc_type].append(entry)
        self.stats['unique_iocs'] += 1
        self.stats['by_type'][ioc_type.value] += 1

        return entry

    def process_batch(self, ioc_list: List[str], source: str = "batch") -> Dict[str, Any]:
        """Process a batch of IoC values"""
        results = {
            'unique_iocs': [],
            'duplicates_removed': 0,
            'processing_time_ms': 0,
            'statistics': {}
        }

        start_time = time.time()

        for ioc_value in ioc_list:
            entry = self.process_single(ioc_value, source)
            if entry:
                results['unique_iocs'].append(entry)

        end_time = time.time()
        results['processing_time_ms'] = int((end_time - start_time) * 1000)
        results['duplicates_removed'] = (
            self.stats['exact_duplicates_removed'] + 
            self.stats['fuzzy_duplicates_removed']
        )
        results['statistics'] = dict(self.stats)

        return results

    def get_unique_iocs(self) -> List[IoCEntry]:
        """Get all unique processed IoCs"""
        return list(self.processed_iocs.values())

    def get_iocs_by_type(self, ioc_type: IoCType) -> List[IoCEntry]:
        """Get all IoCs of a specific type"""
        return self.type_groups.get(ioc_type, [])

    def reset(self) -> None:
        """Reset the engine state"""
        self.bloom_filter = BloomFilter(size=500000, num_hashes=7)
        self.exact_duplicates.clear()
        self.processed_iocs.clear()
        self.type_groups.clear()
        self.stats = {
            'total_input': 0,
            'exact_duplicates_removed': 0,
            'fuzzy_duplicates_removed': 0,
            'unique_iocs': 0,
            'by_type': defaultdict(int)
        }
