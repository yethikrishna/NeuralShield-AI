"""
NeuralShield AI - Threat Intelligence IoC (Indicators of Compromise) Extractor & Normalizer
Production-grade module for extracting and normalizing IoCs from threat intelligence feeds.

This module provides:
- IoC extraction (IPs, domains, URLs, emails, file hashes, CVE IDs)
- IoC normalization and deduplication
- IoC format validation
- Threat severity scoring
- IoC enrichment with context metadata
"""

import re
import hashlib
import ipaddress
from urllib.parse import urlparse
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import json


class IoCType(Enum):
    """Types of Indicators of Compromise"""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"
    FILENAME = "filename"


class ThreatSeverity(Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class IoC:
    """Data class representing an Indicator of Compromise"""
    value: str
    ioc_type: IoCType
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    confidence: float = 0.75
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    source: str = "unknown"
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert IoC to dictionary for serialization"""
        return {
            "value": self.value,
            "type": self.ioc_type.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "source": self.source,
            "tags": self.tags,
            "metadata": self.metadata
        }


class IoCExtractor:
    """
    Production-grade IoC Extractor that identifies and extracts
    various types of indicators of compromise from text content.
    """

    def __init__(self):
        # Regex patterns for IoC extraction
        self.patterns = {
            IoCType.IPV4: re.compile(
                r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
            ),
            IoCType.IPV6: re.compile(
                r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
                r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:|'
                r'\b:(?::[0-9a-fA-F]{1,4}){1,7}\b'
            ),
            IoCType.DOMAIN: re.compile(
                r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
                r'(?:[a-zA-Z]{2,})\b'
            ),
            IoCType.URL: re.compile(
                r'https?://(?:[-\w.]|%[\da-fA-F]{2})+'
                r'(?:/(?:[-\w_.~!*\'();:@&=+$,/?%#[\]]*))?'
            ),
            IoCType.EMAIL: re.compile(
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            ),
            IoCType.MD5: re.compile(
                r'\b[a-fA-F0-9]{32}\b'
            ),
            IoCType.SHA1: re.compile(
                r'\b[a-fA-F0-9]{40}\b'
            ),
            IoCType.SHA256: re.compile(
                r'\b[a-fA-F0-9]{64}\b'
            ),
            IoCType.CVE: re.compile(
                r'CVE-\d{4}-\d{4,7}\b',
                re.IGNORECASE
            )
        }

        # Known benign patterns to exclude
        self.benign_domains = {
            'example.com', 'localhost', 'test.com', 'sample.com',
            'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com'
        }
        self.benign_ips = {
            '127.0.0.1', '0.0.0.0', '255.255.255.255',
            '192.168.1.1', '10.0.0.1', '172.16.0.1'
        }

    def extract_iocs(self, text: str, source: str = "unknown") -> List[IoC]:
        """
        Extract all IoCs from text content.
        
        Args:
            text: Input text to extract IoCs from
            source: Source identifier for tracking
            
        Returns:
            List of extracted and validated IoC objects
        """
        extracted_iocs = []

        for ioc_type, pattern in self.patterns.items():
            matches = pattern.findall(text)
            for match in matches:
                if self._is_valid_ioc(match, ioc_type):
                    normalized_value = self._normalize_ioc(match, ioc_type)
                    if not self._is_benign(normalized_value, ioc_type):
                        ioc = IoC(
                            value=normalized_value,
                            ioc_type=ioc_type,
                            severity=self._calculate_severity(normalized_value, ioc_type),
                            confidence=self._calculate_confidence(normalized_value, ioc_type),
                            source=source,
                            tags=self._generate_tags(ioc_type)
                        )
                        extracted_iocs.append(ioc)

        return self._deduplicate_iocs(extracted_iocs)

    def _is_valid_ioc(self, value: str, ioc_type: IoCType) -> bool:
        """Validate IoC format"""
        try:
            if ioc_type == IoCType.IPV4:
                ipaddress.IPv4Address(value)
                return True
            elif ioc_type == IoCType.IPV6:
                ipaddress.IPv6Address(value)
                return True
            elif ioc_type == IoCType.URL:
                parsed = urlparse(value)
                return bool(parsed.netloc)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    def _normalize_ioc(self, value: str, ioc_type: IoCType) -> str:
        """Normalize IoC value to standard format"""
        value = value.strip()
        
        if ioc_type in [IoCType.MD5, IoCType.SHA1, IoCType.SHA256, IoCType.CVE]:
            return value.lower()
        elif ioc_type in [IoCType.DOMAIN, IoCType.EMAIL]:
            return value.lower()
        elif ioc_type == IoCType.URL:
            parsed = urlparse(value)
            return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}"
        return value

    def _is_benign(self, value: str, ioc_type: IoCType) -> bool:
        """Check if IoC is known benign"""
        if ioc_type == IoCType.IPV4 and value in self.benign_ips:
            return True
        if ioc_type == IoCType.DOMAIN and value in self.benign_domains:
            return True
        return False

    def _calculate_severity(self, value: str, ioc_type: IoCType) -> ThreatSeverity:
        """Calculate threat severity based on IoC type and characteristics"""
        severity_map = {
            IoCType.CVE: ThreatSeverity.CRITICAL,
            IoCType.SHA256: ThreatSeverity.HIGH,
            IoCType.MD5: ThreatSeverity.HIGH,
            IoCType.SHA1: ThreatSeverity.HIGH,
            IoCType.URL: ThreatSeverity.HIGH,
            IoCType.IPV4: ThreatSeverity.MEDIUM,
            IoCType.IPV6: ThreatSeverity.MEDIUM,
            IoCType.DOMAIN: ThreatSeverity.MEDIUM,
            IoCType.EMAIL: ThreatSeverity.LOW,
            IoCType.FILENAME: ThreatSeverity.LOW
        }
        return severity_map.get(ioc_type, ThreatSeverity.MEDIUM)

    def _calculate_confidence(self, value: str, ioc_type: IoCType) -> float:
        """Calculate confidence score for IoC"""
        confidence_map = {
            IoCType.CVE: 0.98,
            IoCType.SHA256: 0.95,
            IoCType.MD5: 0.90,
            IoCType.SHA1: 0.92,
            IoCType.IPV4: 0.85,
            IoCType.IPV6: 0.85,
            IoCType.URL: 0.80,
            IoCType.DOMAIN: 0.75,
            IoCType.EMAIL: 0.60
        }
        return confidence_map.get(ioc_type, 0.70)

    def _generate_tags(self, ioc_type: IoCType) -> List[str]:
        """Generate relevant tags for IoC"""
        tags = ["ioc", ioc_type.value]
        if ioc_type in [IoCType.MD5, IoCType.SHA1, IoCType.SHA256]:
            tags.append("malware-hash")
        elif ioc_type in [IoCType.IPV4, IoCType.IPV6]:
            tags.append("network")
        elif ioc_type == IoCType.CVE:
            tags.append("vulnerability")
        return tags

    def _deduplicate_iocs(self, iocs: List[IoC]) -> List[IoC]:
        """Remove duplicate IoCs keeping highest confidence"""
        seen = {}
        for ioc in iocs:
            key = (ioc.value, ioc.ioc_type)
            if key not in seen or ioc.confidence > seen[key].confidence:
                seen[key] = ioc
        return list(seen.values())


class IoCEnricher:
    """Enriches IoCs with additional context and metadata"""

    def __init__(self):
        self.tor_exit_nodes = self._load_tor_exit_nodes()
        self.malicious_tlds = {'.xyz', '.top', '.work', '.biz', '.info'}

    def _load_tor_exit_nodes(self) -> Set[str]:
        """Load known Tor exit nodes (simulated for production)"""
        return {
            '185.220.101.1', '185.220.101.2', '185.220.101.3',
            '192.42.116.16', '192.42.116.17'
        }

    def enrich_ioc(self, ioc: IoC) -> IoC:
        """Add enrichment metadata to an IoC"""
        metadata = {}

        if ioc.ioc_type == IoCType.IPV4:
            metadata['is_tor_exit'] = ioc.value in self.tor_exit_nodes
            metadata['is_private'] = self._is_private_ip(ioc.value)
        
        elif ioc.ioc_type == IoCType.DOMAIN:
            metadata['suspicious_tld'] = any(ioc.value.endswith(tld) for tld in self.malicious_tlds)
        
        elif ioc.ioc_type == IoCType.URL:
            parsed = urlparse(ioc.value)
            metadata['has_https'] = parsed.scheme == 'https'
            metadata['domain'] = parsed.netloc

        ioc.metadata.update(metadata)
        
        # Adjust confidence based on enrichment
        if metadata.get('is_tor_exit'):
            ioc.confidence = min(1.0, ioc.confidence + 0.15)
            ioc.severity = ThreatSeverity.HIGH

        return ioc

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            return ipaddress.IPv4Address(ip).is_private
        except:
            return False

    def enrich_batch(self, iocs: List[IoC]) -> List[IoC]:
        """Enrich a batch of IoCs"""
        return [self.enrich_ioc(ioc) for ioc in iocs]


class IoCReporter:
    """Generates reports and exports IoC data"""

    @staticmethod
    def to_json(iocs: List[IoC], pretty: bool = True) -> str:
        """Export IoCs to JSON format"""
        data = {
            "ioc_count": len(iocs),
            "generated_at": datetime.now().isoformat(),
            "iocs": [ioc.to_dict() for ioc in iocs]
        }
        indent = 2 if pretty else None
        return json.dumps(data, indent=indent)

    @staticmethod
    def get_statistics(iocs: List[IoC]) -> Dict[str, Any]:
        """Generate statistics about extracted IoCs"""
        stats = {
            "total_iocs": len(iocs),
            "by_type": {},
            "by_severity": {},
            "average_confidence": 0.0
        }

        for ioc in iocs:
            type_key = ioc.ioc_type.value
            stats["by_type"][type_key] = stats["by_type"].get(type_key, 0) + 1
            
            sev_key = ioc.severity.value
            stats["by_severity"][sev_key] = stats["by_severity"].get(sev_key, 0) + 1

        if iocs:
            stats["average_confidence"] = sum(i.confidence for i in iocs) / len(iocs)

        return stats


# Export main classes
__all__ = ['IoCExtractor', 'IoCEnricher', 'IoCReporter', 'IoC', 'IoCType', 'ThreatSeverity']
