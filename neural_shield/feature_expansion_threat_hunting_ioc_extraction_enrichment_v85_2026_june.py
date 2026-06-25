"""
NeuralShield AI - Threat Hunting IOC Extraction & Enrichment Engine v85
Automated Indicator of Compromise extraction, normalization, and enrichment
DIMENSION A - FEATURE EXPANSION (ADD-ONLY, NO MODIFICATION TO EXISTING CODE)

This module wraps existing threat intelligence functionality with automated
IOC extraction and enrichment capabilities. All existing code paths remain
100% unchanged and backward compatible.

Features:
- Automated IOC pattern extraction (IPs, domains, hashes, URLs, emails)
- IOC normalization and deduplication
- GeoIP enrichment (country, city, coordinates)
- ASN enrichment (network, organization)
- Reputation scoring integration
- TLP (Traffic Light Protocol) classification
- MITRE ATT&CK technique mapping
"""

import re
import ipaddress
import hashlib
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import json


class IOCTYPE(str, Enum):
    """IOC Type enumeration"""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    FILENAME = "filename"


class TLP(str, Enum):
    """Traffic Light Protocol classification"""
    WHITE = "TLP:WHITE"
    GREEN = "TLP:GREEN"
    AMBER = "TLP:AMBER"
    RED = "TLP:RED"


@dataclass
class IOC:
    """Indicator of Compromise data structure"""
    value: str
    ioc_type: IOCTYPE
    confidence: float = 0.0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    source: str = "unknown"
    tlp: TLP = TLP.WHITE
    enrichment: Dict[str, Any] = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)
    reputation_score: float = 0.0  # 0-100, higher = more malicious


@dataclass
class GeoIPData:
    """GeoIP enrichment data"""
    country_code: str = "XX"
    country_name: str = "Unknown"
    city: str = "Unknown"
    latitude: float = 0.0
    longitude: float = 0.0
    timezone: str = "UTC"


@dataclass
class ASNData:
    """ASN enrichment data"""
    asn: int = 0
    asn_org: str = "Unknown"
    network: str = "0.0.0.0/0"
    isp: str = "Unknown"


class IOCPatternExtractor:
    """Regex-based IOC pattern extractor"""
    
    # IOC Regular Expressions
    IPV4_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    IPV6_PATTERN = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b:(?::[0-9a-fA-F]{1,4}){1,7}\b'
    DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    MD5_PATTERN = r'\b[a-fA-F0-9]{32}\b'
    SHA1_PATTERN = r'\b[a-fA-F0-9]{40}\b'
    SHA256_PATTERN = r'\b[a-fA-F0-9]{64}\b'
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    URL_PATTERN = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    
    def __init__(self):
        self.patterns = {
            IOCTYPE.IPV4: re.compile(self.IPV4_PATTERN),
            IOCTYPE.IPV6: re.compile(self.IPV6_PATTERN),
            IOCTYPE.DOMAIN: re.compile(self.DOMAIN_PATTERN),
            IOCTYPE.MD5: re.compile(self.MD5_PATTERN),
            IOCTYPE.SHA1: re.compile(self.SHA1_PATTERN),
            IOCTYPE.SHA256: re.compile(self.SHA256_PATTERN),
            IOCTYPE.EMAIL: re.compile(self.EMAIL_PATTERN),
            IOCTYPE.URL: re.compile(self.URL_PATTERN),
        }
    
    def extract_from_text(self, text: str) -> List[IOC]:
        """Extract all IOCs from raw text content"""
        iocs = []
        seen_values: Set[Tuple[str, IOCTYPE]] = set()
        
        for ioc_type, pattern in self.patterns.items():
            matches = pattern.findall(text)
            for match in matches:
                match_str = str(match).strip()
                # Validate and normalize
                normalized = self._normalize_ioc(match_str, ioc_type)
                if normalized and (normalized, ioc_type) not in seen_values:
                    seen_values.add((normalized, ioc_type))
                    iocs.append(IOC(
                        value=normalized,
                        ioc_type=ioc_type,
                        confidence=self._calculate_confidence(normalized, ioc_type),
                        source="pattern_extraction"
                    ))
        
        return iocs
    
    def _normalize_ioc(self, value: str, ioc_type: IOCTYPE) -> Optional[str]:
        """Normalize IOC value for consistent matching"""
        try:
            if ioc_type == IOCTYPE.IPV4:
                ip = ipaddress.IPv4Address(value)
                # Exclude private/reserved IPs as false positives
                if ip.is_private or ip.is_reserved or ip.is_loopback:
                    return None
                return str(ip)
            
            elif ioc_type == IOCTYPE.IPV6:
                ip = ipaddress.IPv6Address(value)
                if ip.is_private or ip.is_reserved or ip.is_loopback:
                    return None
                return str(ip)
            
            elif ioc_type in [IOCTYPE.MD5, IOCTYPE.SHA1, IOCTYPE.SHA256]:
                return value.lower()
            
            elif ioc_type == IOCTYPE.DOMAIN:
                return value.lower()
            
            elif ioc_type == IOCTYPE.EMAIL:
                return value.lower()
            
            return value
        except (ipaddress.AddressValueError, ValueError):
            return None
    
    def _calculate_confidence(self, value: str, ioc_type: IOCTYPE) -> float:
        """Calculate confidence score for extracted IOC"""
        base_confidence = {
            IOCTYPE.MD5: 0.95,
            IOCTYPE.SHA1: 0.98,
            IOCTYPE.SHA256: 0.99,
            IOCTYPE.IPV4: 0.85,
            IOCTYPE.IPV6: 0.80,
            IOCTYPE.DOMAIN: 0.75,
            IOCTYPE.URL: 0.70,
            IOCTYPE.EMAIL: 0.65,
            IOCTYPE.FILENAME: 0.50,
        }.get(ioc_type, 0.5)
        
        return base_confidence


class IOCEnrichmentEngine:
    """IOC enrichment engine with GeoIP, ASN, and reputation"""
    
    def __init__(self):
        self.extractor = IOCPatternExtractor()
        # Mock enrichment databases (production would use MaxMind, IP2Location, etc.)
        self._init_mock_databases()
    
    def _init_mock_databases(self):
        """Initialize mock enrichment databases for demonstration"""
        # Known malicious IP ranges for testing
        self.known_malicious = {
            "192.168.1.100": {"reputation": 95, "mitre": ["T1071", "T1046"]},
            "10.0.0.50": {"reputation": 85, "mitre": ["T1027", "T1059"]},
            "evil.com": {"reputation": 90, "mitre": ["T1566", "T1071"]},
            "malware.exe": {"reputation": 95, "mitre": ["T1204", "T1059"]},
        }
        
        # Mock GeoIP data
        self.geoip_db = {
            "8.8.8.8": GeoIPData("US", "United States", "Mountain View", 37.386, -122.0838, "America/Los_Angeles"),
            "1.1.1.1": GeoIPData("US", "United States", "San Francisco", 37.7749, -122.4194, "America/Los_Angeles"),
        }
        
        # Mock ASN data
        self.asn_db = {
            "8.8.8.8": ASNData(15169, "Google LLC", "8.8.8.0/24", "Google"),
            "1.1.1.1": ASNData(13335, "Cloudflare Inc", "1.1.1.0/24", "Cloudflare"),
        }
    
    def enrich_ioc(self, ioc: IOC) -> IOC:
        """Enrich a single IOC with contextual data"""
        enrichment = {}
        
        # IP-specific enrichment
        if ioc.ioc_type in [IOCTYPE.IPV4, IOCTYPE.IPV6]:
            enrichment["geoip"] = self._get_geoip(ioc.value)
            enrichment["asn"] = self._get_asn(ioc.value)
        
        # Reputation scoring
        reputation = self._calculate_reputation(ioc)
        ioc.reputation_score = reputation
        enrichment["reputation_level"] = self._get_reputation_level(reputation)
        
        # MITRE ATT&CK mapping
        ioc.mitre_techniques = self._map_mitre_techniques(ioc)
        
        # TLP classification based on reputation
        ioc.tlp = self._classify_tlp(reputation)
        
        ioc.enrichment = enrichment
        return ioc
    
    def enrich_batch(self, iocs: List[IOC]) -> List[IOC]:
        """Enrich a batch of IOCs"""
        return [self.enrich_ioc(ioc) for ioc in iocs]
    
    def extract_and_enrich(self, text: str) -> List[IOC]:
        """Extract IOCs from text and enrich them in one pass"""
        iocs = self.extractor.extract_from_text(text)
        return self.enrich_batch(iocs)
    
    def _get_geoip(self, ip: str) -> Dict[str, Any]:
        """Get GeoIP data for IP address"""
        geoip = self.geoip_db.get(ip, GeoIPData())
        return {
            "country_code": geoip.country_code,
            "country_name": geoip.country_name,
            "city": geoip.city,
            "latitude": geoip.latitude,
            "longitude": geoip.longitude,
            "timezone": geoip.timezone
        }
    
    def _get_asn(self, ip: str) -> Dict[str, Any]:
        """Get ASN data for IP address"""
        asn = self.asn_db.get(ip, ASNData())
        return {
            "asn": asn.asn,
            "organization": asn.asn_org,
            "network": asn.network,
            "isp": asn.isp
        }
    
    def _calculate_reputation(self, ioc: IOC) -> float:
        """Calculate reputation score 0-100"""
        if ioc.value in self.known_malicious:
            return self.known_malicious[ioc.value]["reputation"]
        
        # Hash-based reputation heuristic
        if ioc.ioc_type in [IOCTYPE.MD5, IOCTYPE.SHA1, IOCTYPE.SHA256]:
            return 70.0  # File hashes typically indicate malware
        
        # Domain heuristic
        if ioc.ioc_type == IOCTYPE.DOMAIN:
            if any(tld in ioc.value for tld in ['.tk', '.ml', '.ga', '.cf', '.gq']):
                return 60.0
        
        return 10.0  # Default low reputation
    
    def _get_reputation_level(self, score: float) -> str:
        """Get human-readable reputation level"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        return "UNKNOWN"
    
    def _map_mitre_techniques(self, ioc: IOC) -> List[str]:
        """Map IOC to MITRE ATT&CK techniques"""
        if ioc.value in self.known_malicious:
            return self.known_malicious[ioc.value].get("mitre", [])
        
        # Default techniques based on IOC type
        technique_mapping = {
            IOCTYPE.IPV4: ["T1071", "T1046"],  # Application Layer Protocol, Network Service Scanning
            IOCTYPE.DOMAIN: ["T1566", "T1071"],  # Phishing, Application Layer Protocol
            IOCTYPE.URL: ["T1566", "T1204"],  # Phishing, User Execution
            IOCTYPE.MD5: ["T1204", "T1059"],  # User Execution, Command and Scripting
            IOCTYPE.SHA1: ["T1204", "T1059"],
            IOCTYPE.SHA256: ["T1204", "T1059"],
        }
        return technique_mapping.get(ioc.ioc_type, [])
    
    def _classify_tlp(self, reputation: float) -> TLP:
        """Classify TLP based on reputation score"""
        if reputation >= 80:
            return TLP.RED
        elif reputation >= 60:
            return TLP.AMBER
        elif reputation >= 20:
            return TLP.GREEN
        return TLP.WHITE


class ThreatHuntingIOCManager:
    """Main IOC management interface for threat hunting workflows"""
    
    def __init__(self):
        self.enrichment_engine = IOCEnrichmentEngine()
        self.ioc_database: Dict[str, IOC] = {}
        self.blacklist: Set[str] = set()
        self.whitelist: Set[str] = set()
    
    def process_threat_report(self, report_text: str, source: str = "manual") -> Dict[str, Any]:
        """Process a raw threat report and extract enriched IOCs"""
        iocs = self.enrichment_engine.extract_and_enrich(report_text)
        
        # Update source information
        for ioc in iocs:
            ioc.source = source
            key = f"{ioc.ioc_type}:{ioc.value}"
            if key in self.ioc_database:
                existing = self.ioc_database[key]
                existing.last_seen = datetime.now()
                existing.confidence = max(existing.confidence, ioc.confidence)
            else:
                self.ioc_database[key] = ioc
        
        # Generate summary statistics
        summary = self._generate_summary(iocs)
        
        return {
            "iocs_extracted": len(iocs),
            "iocs": iocs,
            "summary": summary,
            "processed_at": datetime.now().isoformat(),
            "source": source
        }
    
    def _generate_summary(self, iocs: List[IOC]) -> Dict[str, Any]:
        """Generate IOC summary statistics"""
        type_counts: Dict[str, int] = {}
        reputation_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        
        for ioc in iocs:
            type_counts[ioc.ioc_type.value] = type_counts.get(ioc.ioc_type.value, 0) + 1
            rep_level = self.enrichment_engine._get_reputation_level(ioc.reputation_score)
            reputation_counts[rep_level] = reputation_counts.get(rep_level, 0) + 1
        
        return {
            "by_type": type_counts,
            "by_reputation": reputation_counts,
            "total_iocs": len(iocs),
            "high_risk_count": sum(1 for i in iocs if i.reputation_score >= 60)
        }
    
    def export_iocs(self, format_type: str = "json", min_reputation: int = 0) -> str:
        """Export IOCs in various formats"""
        filtered = [
            ioc for ioc in self.ioc_database.values()
            if ioc.reputation_score >= min_reputation
        ]
        
        if format_type == "json":
            return json.dumps([
                {
                    "value": ioc.value,
                    "type": ioc.ioc_type.value,
                    "confidence": ioc.confidence,
                    "reputation": ioc.reputation_score,
                    "tlp": ioc.tlp.value,
                    "mitre_techniques": ioc.mitre_techniques,
                    "source": ioc.source
                }
                for ioc in filtered
            ], indent=2)
        
        elif format_type == "csv":
            lines = ["value,type,confidence,reputation,tlp,source"]
            for ioc in filtered:
                lines.append(f"{ioc.value},{ioc.ioc_type.value},{ioc.confidence},{ioc.reputation_score},{ioc.tlp.value},{ioc.source}")
            return "\n".join(lines)
        
        elif format_type == "stix":
            # Simplified STIX 2.0 format
            return json.dumps({
                "type": "bundle",
                "objects": [
                    {
                        "type": "indicator",
                        "pattern": f"[file:hashes.MD5 = '{ioc.value}']" if ioc.ioc_type == IOCTYPE.MD5 
                                  else f"[network-traffic:dst_ref.value = '{ioc.value}']",
                        "valid_from": ioc.first_seen.isoformat(),
                        "labels": ["malicious-activity"]
                    }
                    for ioc in filtered
                ]
            }, indent=2)
        
        raise ValueError(f"Unsupported export format: {format_type}")
    
    def get_high_risk_iocs(self, threshold: float = 60.0) -> List[IOC]:
        """Get all high-risk IOCs above reputation threshold"""
        return [
            ioc for ioc in self.ioc_database.values()
            if ioc.reputation_score >= threshold
        ]


# Module exports for backward compatibility
__all__ = [
    'IOCTYPE',
    'TLP',
    'IOC',
    'IOCPatternExtractor',
    'IOCEnrichmentEngine',
    'ThreatHuntingIOCManager',
]
