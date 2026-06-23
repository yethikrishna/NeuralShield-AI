"""
NeuralShield AI - Threat Intelligence Feeds Aggregator
Dimension A: Feature Expansion
Version: v23 - June 2026
API Stability: STABLE

Aggregates and normalizes threat intelligence from multiple sources
including MITRE ATT&CK, CVE databases, abuseIPDB, and custom feeds.
Provides unified threat scoring and deduplication.
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse


class ThreatSource(Enum):
    """Supported threat intelligence sources."""
    MITRE_ATTACK = "mitre_attack"
    CVE_NVD = "cve_nvd"
    ABUSEIPDB = "abuseipdb"
    VIRUSTOTAL = "virustotal"
    SHODAN = "shodan"
    CUSTOM = "custom"
    OPENPHISH = "openphish"
    URLHAUS = "urlhaus"


class ThreatType(Enum):
    """Types of threats."""
    MALWARE = "malware"
    PHISHING = "phishing"
    CVE = "cve"
    IP_REPUTATION = "ip_reputation"
    DOMAIN_REPUTATION = "domain_reputation"
    URL_REPUTATION = "url_reputation"
    ATTACK_PATTERN = "attack_pattern"
    IOC = "ioc"


class SeverityLevel(Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_cvss(cls, cvss_score: float) -> "SeverityLevel":
        if cvss_score >= 9.0:
            return cls.CRITICAL
        elif cvss_score >= 7.0:
            return cls.HIGH
        elif cvss_score >= 4.0:
            return cls.MEDIUM
        elif cvss_score >= 0.1:
            return cls.LOW
        return cls.INFO


@dataclass
class ThreatIndicator:
    """Normalized threat indicator structure."""
    indicator_id: str
    indicator_value: str
    threat_type: ThreatType
    severity: SeverityLevel
    source: ThreatSource
    confidence: float  # 0.0 - 1.0
    first_seen: datetime
    last_seen: datetime
    description: str = ""
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    ttl: int = 86400  # Time to live in seconds (default 24h)

    def is_expired(self) -> bool:
        """Check if this indicator has expired."""
        age = (datetime.now(timezone.utc) - self.last_seen).total_seconds()
        return age > self.ttl

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "indicator_id": self.indicator_id,
            "indicator_value": self.indicator_value,
            "threat_type": self.threat_type.value,
            "severity": self.severity.value,
            "source": self.source.value,
            "confidence": self.confidence,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "description": self.description,
            "tags": self.tags,
            "metadata": self.metadata,
            "ttl": self.ttl,
            "expired": self.is_expired()
        }


class ThreatIntelligenceAggregator:
    """
    Aggregates threat intelligence from multiple sources and provides
    normalized, deduplicated threat indicators.

    Features:
    - Multi-source feed aggregation
    - Automatic deduplication
    - Confidence-weighted scoring
    - TTL-based expiration
    - In-memory caching with persistence support
    """

    def __init__(self, cache_ttl: int = 3600):
        self.cache_ttl = cache_ttl
        self._indicators: Dict[str, ThreatIndicator] = {}
        self._source_stats: Dict[str, Dict[str, int]] = {
            source.value: {"total": 0, "added": 0, "duplicates": 0}
            for source in ThreatSource
        }
        self._last_update: Optional[datetime] = None
        self._seen_hashes: Set[str] = set()

    def _generate_indicator_id(self, value: str, threat_type: ThreatType) -> str:
        """Generate a unique identifier for an indicator."""
        key = f"{threat_type.value}:{value.lower().strip()}"
        return hashlib.sha256(key.encode()).hexdigest()[:32]

    def _normalize_indicator_value(self, value: str, threat_type: ThreatType) -> str:
        """Normalize indicator values for consistent comparison."""
        value = value.strip().lower()
        
        if threat_type == ThreatType.URL_REPUTATION:
            try:
                parsed = urlparse(value)
                # Normalize to domain + path without scheme
                return f"{parsed.netloc}{parsed.path}"
            except Exception:
                pass
        
        return value

    def add_indicator(
        self,
        indicator_value: str,
        threat_type: ThreatType,
        severity: SeverityLevel,
        source: ThreatSource,
        confidence: float,
        description: str = "",
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        first_seen: Optional[datetime] = None,
        last_seen: Optional[datetime] = None,
        ttl: int = 86400
    ) -> Optional[ThreatIndicator]:
        """
        Add a threat indicator to the aggregator.
        
        Returns: The added indicator, or None if it was a duplicate.
        """
        now = datetime.now(timezone.utc)
        normalized_value = self._normalize_indicator_value(indicator_value, threat_type)
        indicator_id = self._generate_indicator_id(normalized_value, threat_type)
        
        # Check for duplicates
        if indicator_id in self._indicators:
            existing = self._indicators[indicator_id]
            # Update existing indicator with newer information
            if confidence > existing.confidence:
                existing.confidence = confidence
            if last_seen and last_seen > existing.last_seen:
                existing.last_seen = last_seen
            if severity.value != existing.severity.value:
                # Take the higher severity
                severity_order = [SeverityLevel.INFO, SeverityLevel.LOW, 
                                SeverityLevel.MEDIUM, SeverityLevel.HIGH, 
                                SeverityLevel.CRITICAL]
                if severity_order.index(severity) > severity_order.index(existing.severity):
                    existing.severity = severity
            
            self._source_stats[source.value]["duplicates"] += 1
            return None
        
        indicator = ThreatIndicator(
            indicator_id=indicator_id,
            indicator_value=normalized_value,
            threat_type=threat_type,
            severity=severity,
            source=source,
            confidence=max(0.0, min(1.0, confidence)),
            first_seen=first_seen or now,
            last_seen=last_seen or now,
            description=description,
            tags=tags or [],
            metadata=metadata or {},
            ttl=ttl
        )
        
        self._indicators[indicator_id] = indicator
        self._source_stats[source.value]["total"] += 1
        self._source_stats[source.value]["added"] += 1
        self._last_update = now
        
        return indicator

    def add_cve_entry(
        self,
        cve_id: str,
        cvss_score: float,
        description: str,
        source: ThreatSource = ThreatSource.CVE_NVD,
        confidence: float = 0.95,
        affected_products: Optional[List[str]] = None,
        references: Optional[List[str]] = None
    ) -> ThreatIndicator:
        """Convenience method to add CVE entries."""
        return self.add_indicator(
            indicator_value=cve_id,
            threat_type=ThreatType.CVE,
            severity=SeverityLevel.from_cvss(cvss_score),
            source=source,
            confidence=confidence,
            description=description,
            tags=["cve", "vulnerability"],
            metadata={
                "cvss_score": cvss_score,
                "affected_products": affected_products or [],
                "references": references or []
            }
        )

    def add_ip_reputation(
        self,
        ip_address: str,
        abuse_score: int,  # 0-100
        source: ThreatSource = ThreatSource.ABUSEIPDB,
        country: Optional[str] = None,
        usage_type: Optional[str] = None,
        reports: int = 0
    ) -> ThreatIndicator:
        """Convenience method to add IP reputation entries."""
        confidence = min(1.0, abuse_score / 100.0)
        
        if abuse_score >= 90:
            severity = SeverityLevel.CRITICAL
        elif abuse_score >= 70:
            severity = SeverityLevel.HIGH
        elif abuse_score >= 40:
            severity = SeverityLevel.MEDIUM
        elif abuse_score >= 10:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.INFO
        
        return self.add_indicator(
            indicator_value=ip_address,
            threat_type=ThreatType.IP_REPUTATION,
            severity=severity,
            source=source,
            confidence=confidence,
            description=f"IP address with abuse score {abuse_score}/100",
            tags=["ip", "reputation", "abuse"],
            metadata={
                "abuse_score": abuse_score,
                "country": country,
                "usage_type": usage_type,
                "total_reports": reports
            }
        )

    def add_phishing_url(
        self,
        url: str,
        source: ThreatSource = ThreatSource.OPENPHISH,
        confidence: float = 0.85,
        target_brand: Optional[str] = None,
        verified: bool = False
    ) -> ThreatIndicator:
        """Convenience method to add phishing URLs."""
        tags = ["phishing", "url"]
        if verified:
            tags.append("verified")
            confidence = max(confidence, 0.95)
        
        return self.add_indicator(
            indicator_value=url,
            threat_type=ThreatType.PHISHING,
            severity=SeverityLevel.HIGH,
            source=source,
            confidence=confidence,
            description=f"Phishing URL targeting {target_brand or 'unknown'}",
            tags=tags,
            metadata={"target_brand": target_brand, "verified": verified}
        )

    def query_indicators(
        self,
        threat_type: Optional[ThreatType] = None,
        severity: Optional[SeverityLevel] = None,
        source: Optional[ThreatSource] = None,
        min_confidence: float = 0.0,
        include_expired: bool = False,
        limit: Optional[int] = None
    ) -> List[ThreatIndicator]:
        """Query indicators with filtering."""
        results = []
        
        for indicator in self._indicators.values():
            if not include_expired and indicator.is_expired():
                continue
            if threat_type and indicator.threat_type != threat_type:
                continue
            if severity and indicator.severity != severity:
                continue
            if source and indicator.source != source:
                continue
            if indicator.confidence < min_confidence:
                continue
            
            results.append(indicator)
        
        # Sort by severity and confidence
        severity_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4
        }
        results.sort(key=lambda x: (severity_order[x.severity], -x.confidence))
        
        if limit:
            results = results[:limit]
        
        return results

    def check_value(self, value: str) -> Optional[ThreatIndicator]:
        """Check if a value matches any threat indicator."""
        for threat_type in ThreatType:
            normalized = self._normalize_indicator_value(value, threat_type)
            indicator_id = self._generate_indicator_id(normalized, threat_type)
            if indicator_id in self._indicators:
                indicator = self._indicators[indicator_id]
                if not indicator.is_expired():
                    return indicator
        return None

    def get_statistics(self) -> Dict[str, Any]:
        """Get aggregator statistics."""
        active = sum(1 for i in self._indicators.values() if not i.is_expired())
        expired = len(self._indicators) - active
        
        by_severity = {
            level.value: sum(1 for i in self._indicators.values() 
                           if i.severity == level and not i.is_expired())
            for level in SeverityLevel
        }
        
        by_type = {
            t.value: sum(1 for i in self._indicators.values() 
                        if i.threat_type == t and not i.is_expired())
            for t in ThreatType
        }
        
        return {
            "total_indicators": len(self._indicators),
            "active_indicators": active,
            "expired_indicators": expired,
            "by_severity": by_severity,
            "by_type": by_type,
            "by_source": self._source_stats,
            "last_update": self._last_update.isoformat() if self._last_update else None,
            "cache_ttl": self.cache_ttl
        }

    def cleanup_expired(self) -> int:
        """Remove expired indicators. Returns count of removed items."""
        expired_ids = [
            iid for iid, indicator in self._indicators.items()
            if indicator.is_expired()
        ]
        for iid in expired_ids:
            del self._indicators[iid]
        return len(expired_ids)

    def export_json(self, filepath: str) -> None:
        """Export all indicators to JSON file."""
        data = {
            "export_time": datetime.now(timezone.utc).isoformat(),
            "statistics": self.get_statistics(),
            "indicators": [i.to_dict() for i in self._indicators.values()]
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def import_json(self, filepath: str) -> int:
        """Import indicators from JSON file. Returns count imported."""
        count = 0
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        for item in data.get("indicators", []):
            self.add_indicator(
                indicator_value=item["indicator_value"],
                threat_type=ThreatType(item["threat_type"]),
                severity=SeverityLevel(item["severity"]),
                source=ThreatSource(item["source"]),
                confidence=item["confidence"],
                description=item.get("description", ""),
                tags=item.get("tags", []),
                metadata=item.get("metadata", {}),
                ttl=item.get("ttl", 86400)
            )
            count += 1
        
        return count
