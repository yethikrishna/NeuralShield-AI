"""
Threat Intelligence Feed Aggregator with Semantic Caching v8
NeuralShield-AI Feature Expansion - June 2026
ADD-ONLY IMPLEMENTATION - NO EXISTING CODE MODIFIED

This module provides:
1. Multi-source threat intelligence feed aggregation
2. Semantic similarity caching with Bloom filter deduplication
3. IOC (Indicator of Compromise) normalization and deduplication
4. Context enrichment with threat actor mapping
5. Feed health monitoring and quality scoring
"""

import hashlib
import json
import time
import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from enum import Enum
from collections import defaultdict


class FeedType(Enum):
    """Supported threat intelligence feed types"""
    ABUSEIPDB = "abuseipdb"
    VIRUSTOTAL = "virustotal"
    MITRE_ATTACK = "mitre_attack"
    THREATFOX = "threatfox"
    URLHAUS = "urlhaus"
    MALWAREBAZAAR = "malwarebazaar"
    OPENPHISH = "openphish"
    EMERGINGTHREATS = "emergingthreats"


class IOCType(Enum):
    """IOC (Indicator of Compromise) types"""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"


class ThreatSeverity(Enum):
    """Threat severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class IOCEntry:
    """Single Indicator of Compromise entry"""
    value: str
    ioc_type: IOCType
    source: FeedType
    severity: ThreatSeverity
    first_seen: float
    last_seen: float
    confidence: float  # 0.0 - 1.0
    threat_actor: Optional[str] = None
    ttp: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self):
        return hash((self.value, self.ioc_type.value))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "ioc_type": self.ioc_type.value,
            "source": self.source.value,
            "severity": self.severity.value,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "confidence": self.confidence,
            "threat_actor": self.threat_actor,
            "ttp": self.ttp,
            "metadata": self.metadata
        }


class BloomFilter:
    """
    Memory-efficient Bloom filter for fast IOC deduplication
    False positive rate < 0.1% for 1M entries
    """

    def __init__(self, size: int = 2 ** 24, num_hashes: int = 5):
        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = bytearray(size // 8 + 1)
        self.count = 0

    def _get_indices(self, value: str) -> List[int]:
        """Generate multiple hash indices for the value"""
        indices = []
        for i in range(self.num_hashes):
            h = hashlib.sha256(f"{value}:{i}".encode()).hexdigest()
            idx = int(h, 16) % self.size
            indices.append(idx)
        return indices

    def add(self, value: str) -> None:
        """Add a value to the bloom filter"""
        for idx in self._get_indices(value):
            byte_pos = idx // 8
            bit_pos = idx % 8
            self.bit_array[byte_pos] |= (1 << bit_pos)
        self.count += 1

    def __contains__(self, value: str) -> bool:
        """Check if value might be in the filter"""
        for idx in self._get_indices(value):
            byte_pos = idx // 8
            bit_pos = idx % 8
            if not (self.bit_array[byte_pos] & (1 << bit_pos)):
                return False
        return True

    def estimated_false_positive_rate(self) -> float:
        """Calculate estimated false positive rate"""
        n = self.count
        m = self.size
        k = self.num_hashes
        return (1 - (1 - 1 / m) ** (k * n)) ** k


class SemanticCache:
    """
    Semantic similarity cache for threat intelligence
    Uses LSH (Locality Sensitive Hashing) for approximate similarity
    """

    def __init__(self, cache_ttl: int = 3600, similarity_threshold: float = 0.85):
        self.cache_ttl = cache_ttl
        self.similarity_threshold = similarity_threshold
        self._cache: Dict[str, Tuple[Any, float]] = {}  # key -> (value, timestamp)
        self._lsh_buckets: Dict[str, Set[str]] = defaultdict(set)

    def _compute_lsh_signature(self, text: str, bands: int = 8, rows: int = 4) -> List[str]:
        """Compute LSH signature bands for the text"""
        signatures = []
        words = re.findall(r'\w+', text.lower())
        shingles = set()
        
        for i in range(max(1, len(words) - 2)):
            shingle = " ".join(words[i:i + 3])
            shingles.add(shingle)

        if not shingles:
            return [f"band_0_empty"]

        shingle_list = sorted(shingles)
        for band in range(bands):
            band_hash = hashlib.md5()
            start = band * rows
            end = min(start + rows, len(shingle_list))
            for shingle in shingle_list[start:end]:
                band_hash.update(shingle.encode())
            signatures.append(f"band_{band}_{band_hash.hexdigest()[:8]}")

        return signatures

    def get(self, key: str) -> Optional[Any]:
        """Get cached value if exists and not expired"""
        if key in self._cache:
            value, timestamp = self._cache[key]
            if time.time() - timestamp < self.cache_ttl:
                return value
            else:
                del self._cache[key]
        return None

    def put(self, key: str, value: Any) -> None:
        """Store value in cache with TTL"""
        self._cache[key] = (value, time.time())
        
        # Add to LSH buckets for similarity lookup
        if isinstance(key, str):
            for sig in self._compute_lsh_signature(key):
                self._lsh_buckets[sig].add(key)

    def find_similar(self, text: str) -> List[str]:
        """Find semantically similar cached entries"""
        candidates = set()
        for sig in self._compute_lsh_signature(text):
            candidates.update(self._lsh_buckets.get(sig, set()))
        return list(candidates)

    def cleanup(self) -> int:
        """Remove expired entries, return count removed"""
        expired = []
        current = time.time()
        for key, (_, ts) in self._cache.items():
            if current - ts > self.cache_ttl:
                expired.append(key)
        for key in expired:
            del self._cache[key]
        return len(expired)


class ThreatIntelFeedAggregator:
    """
    Main threat intelligence feed aggregator
    Aggregates, normalizes, deduplicates, and enriches threat intelligence
    """

    def __init__(self, cache_ttl: int = 3600, bloom_size: int = 2 ** 24):
        self.bloom_filter = BloomFilter(size=bloom_size)
        self.semantic_cache = SemanticCache(cache_ttl=cache_ttl)
        self.ioc_database: Set[IOCEntry] = set()
        self.feed_health: Dict[FeedType, Dict[str, Any]] = defaultdict(
            lambda: {"success_count": 0, "failure_count": 0, "last_update": 0, "ioc_count": 0}
        )
        self.threat_actor_mapping: Dict[str, Set[IOCEntry]] = defaultdict(set)
        self.ttp_mapping: Dict[str, Set[IOCEntry]] = defaultdict(set)

        # IOC regex patterns
        self._ioc_patterns = {
            IOCType.IPV4: re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            IOCType.DOMAIN: re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'),
            IOCType.MD5: re.compile(r'\b[a-fA-F0-9]{32}\b'),
            IOCType.SHA1: re.compile(r'\b[a-fA-F0-9]{40}\b'),
            IOCType.SHA256: re.compile(r'\b[a-fA-F0-9]{64}\b'),
        }

    def extract_iocs_from_text(self, text: str, source: FeedType = FeedType.THREATFOX) -> List[IOCEntry]:
        """
        Extract IOCs from raw threat feed text
        Returns normalized IOC entries
        """
        iocs = []
        current_time = time.time()

        for ioc_type, pattern in self._ioc_patterns.items():
            matches = pattern.findall(text)
            for match in matches:
                # Basic validation
                if ioc_type == IOCType.IPV4:
                    octets = match.split('.')
                    if not all(0 <= int(o) <= 255 for o in octets):
                        continue

                dedup_key = f"{ioc_type.value}:{match}"
                if dedup_key in self.bloom_filter:
                    continue

                self.bloom_filter.add(dedup_key)

                ioc = IOCEntry(
                    value=match,
                    ioc_type=ioc_type,
                    source=source,
                    severity=ThreatSeverity.MEDIUM,
                    first_seen=current_time,
                    last_seen=current_time,
                    confidence=0.7
                )
                iocs.append(ioc)
                self.ioc_database.add(ioc)

        self.feed_health[source]["success_count"] += 1
        self.feed_health[source]["last_update"] = current_time
        self.feed_health[source]["ioc_count"] += len(iocs)

        return iocs

    def check_ioc(self, value: str) -> Optional[IOCEntry]:
        """
        Check if an indicator exists in the database
        Returns IOCEntry if found, None otherwise
        """
        # Check bloom filter first (fast)
        for ioc_type in IOCType:
            dedup_key = f"{ioc_type.value}:{value}"
            if dedup_key in self.bloom_filter:
                # Linear scan for exact match (bloom can have false positives)
                for ioc in self.ioc_database:
                    if ioc.value == value:
                        return ioc
        return None

    def batch_check_iocs(self, values: List[str]) -> Dict[str, Optional[IOCEntry]]:
        """Batch check multiple IOCs efficiently"""
        results = {}
        for value in values:
            results[value] = self.check_ioc(value)
        return results

    def search_by_threat_actor(self, actor_name: str) -> List[IOCEntry]:
        """Search all IOCs associated with a threat actor"""
        similar = self.semantic_cache.find_similar(actor_name)
        results = []
        for match in similar:
            results.extend(self.threat_actor_mapping.get(match, set()))
        return list(set(results))

    def search_by_ttp(self, ttp_id: str) -> List[IOCEntry]:
        """Search by MITRE ATT&CK technique ID"""
        return list(self.ttp_mapping.get(ttp_id.upper(), set()))

    def get_feed_health_report(self) -> Dict[str, Any]:
        """Get health and quality metrics for all feeds"""
        report = {
            "feeds": {},
            "summary": {
                "total_iocs": len(self.ioc_database),
                "bloom_filter_size": self.bloom_filter.size,
                "bloom_filter_count": self.bloom_filter.count,
                "estimated_fp_rate": self.bloom_filter.estimated_false_positive_rate(),
                "cache_entries": len(self.semantic_cache._cache),
            }
        }

        for feed_type, health in self.feed_health.items():
            total = health["success_count"] + health["failure_count"]
            success_rate = health["success_count"] / total if total > 0 else 0.0
            
            report["feeds"][feed_type.value] = {
                "success_count": health["success_count"],
                "failure_count": health["failure_count"],
                "success_rate": success_rate,
                "ioc_count": health["ioc_count"],
                "last_update_age": time.time() - health["last_update"]
            }

        return report

    def enrich_with_context(self, ioc: IOCEntry, threat_actor: Optional[str] = None,
                           ttp: Optional[str] = None, metadata: Optional[Dict] = None) -> None:
        """Enrich an existing IOC with additional context"""
        if threat_actor:
            ioc.threat_actor = threat_actor
            self.threat_actor_mapping[threat_actor].add(ioc)
            self.semantic_cache.put(threat_actor, ioc)
        if ttp:
            ioc.ttp = ttp
            self.ttp_mapping[ttp].add(ioc)
        if metadata:
            ioc.metadata.update(metadata)

    def export_database(self, filepath: str) -> None:
        """Export IOC database to JSON file"""
        data = [ioc.to_dict() for ioc in self.ioc_database]
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        by_type = defaultdict(int)
        by_severity = defaultdict(int)
        by_source = defaultdict(int)

        for ioc in self.ioc_database:
            by_type[ioc.ioc_type.value] += 1
            by_severity[ioc.severity.name] += 1
            by_source[ioc.source.value] += 1

        return {
            "total_iocs": len(self.ioc_database),
            "by_type": dict(by_type),
            "by_severity": dict(by_severity),
            "by_source": dict(by_source),
            "threat_actors": len(self.threat_actor_mapping),
            "ttps": len(self.ttp_mapping)
        }


# Singleton instance for easy import
_default_aggregator = None


def get_aggregator() -> ThreatIntelFeedAggregator:
    """Get or create the default threat intel aggregator instance"""
    global _default_aggregator
    if _default_aggregator is None:
        _default_aggregator = ThreatIntelFeedAggregator()
    return _default_aggregator


# Export public API
__all__ = [
    'ThreatIntelFeedAggregator',
    'BloomFilter',
    'SemanticCache',
    'IOCEntry',
    'FeedType',
    'IOCType',
    'ThreatSeverity',
    'get_aggregator',
]
