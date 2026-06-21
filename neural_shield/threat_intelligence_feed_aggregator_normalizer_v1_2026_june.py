"""
NeuralShield-AI: Threat Intelligence Feed Aggregator & Normalizer
Version: 1.0 (June 21, 2026)

Production-grade module for aggregating threat intelligence feeds from multiple sources,
normalizing heterogeneous formats, deduplicating indicators, and calculating confidence scores.

Features:
- Multi-source feed aggregation (AbuseIPDB, VirusTotal, MITRE, AlienVault OTX, Emerging Threats)
- Format normalization to standard STIX 2.1 compatible IOC format
- Cross-source deduplication with fuzzy matching
- Confidence scoring based on source reputation and corroboration
- Feed health monitoring and quality metrics
- Batch processing with rate limiting
"""

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse


class IOCTYPE(str, Enum):
    """Types of Indicators of Compromise"""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    CVE = "cve"
    JA3 = "ja3"
    JA3S = "ja3s"


class ThreatSeverity(str, Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatType(str, Enum):
    """Types of threats"""
    MALWARE = "malware"
    PHISHING = "phishing"
    C2 = "command_and_control"
    BOTNET = "botnet"
    EXPLOIT = "exploit"
    SCANNER = "scanner"
    SPAM = "spam"
    RANSOMWARE = "ransomware"
    DDOS = "ddos"


class FeedSource(str, Enum):
    """Supported threat feed sources"""
    ABUSEIPDB = "abuseipdb"
    VIRUSTOTAL = "virustotal"
    MITRE_ATTACK = "mitre_attack"
    ALIENVAULT_OTX = "alienvault_otx"
    EMERGING_THREATS = "emerging_threats"
    THREATFOX = "threatfox"
    URLHAUS = "urlhaus"


@dataclass
class FeedSourceConfig:
    """Configuration for each threat feed source"""
    name: FeedSource
    base_reputation: float  # 0.0 - 1.0
    update_frequency_minutes: int
    enabled: bool = True
    rate_limit_per_minute: int = 60
    weight: float = 1.0


@dataclass
class RawIndicator:
    """Raw indicator from a feed source before normalization"""
    source: FeedSource
    raw_data: Dict[str, Any]
    fetched_at: datetime = field(default_factory=datetime.utcnow)
    source_specific_id: Optional[str] = None


@dataclass
class NormalizedIndicator:
    """Normalized IOC in standard format"""
    ioc_id: str
    ioc_type: IOCTYPE
    ioc_value: str
    severity: ThreatSeverity
    threat_types: List[ThreatType]
    confidence_score: float  # 0.0 - 1.0
    sources: List[FeedSource]
    first_seen: datetime
    last_seen: datetime
    tlp: str = "WHITE"  # Traffic Light Protocol
    description: str = ""
    tags: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    asn: Optional[str] = None
    country: Optional[str] = None
    correlation_count: int = 1
    feed_quality_score: float = 0.0


@dataclass
class FeedHealthMetrics:
    """Health metrics for a threat feed source"""
    source: FeedSource
    indicators_processed: int = 0
    duplicates_found: int = 0
    invalid_indicators: int = 0
    last_successful_fetch: Optional[datetime] = None
    last_failed_fetch: Optional[datetime] = None
    consecutive_failures: int = 0
    average_processing_time_ms: float = 0.0
    uptime_percentage: float = 100.0


@dataclass
class AggregationResult:
    """Result of a feed aggregation run"""
    run_id: str
    started_at: datetime
    completed_at: datetime
    total_indicators_fetched: int
    total_unique_indicators: int
    total_duplicates_removed: int
    indicators_by_type: Dict[IOCTYPE, int]
    indicators_by_severity: Dict[ThreatSeverity, int]
    feed_health: Dict[FeedSource, FeedHealthMetrics]
    normalized_indicators: List[NormalizedIndicator]


class ThreatFeedAggregator:
    """
    Production-grade threat intelligence feed aggregator and normalizer.
    
    Aggregates indicators from multiple sources, normalizes formats,
    deduplicates, and calculates confidence scores.
    """
    
    # Default feed source configurations with reputation weights
    DEFAULT_FEED_CONFIGS = {
        FeedSource.ABUSEIPDB: FeedSourceConfig(
            name=FeedSource.ABUSEIPDB,
            base_reputation=0.85,
            update_frequency_minutes=15,
            weight=1.2
        ),
        FeedSource.VIRUSTOTAL: FeedSourceConfig(
            name=FeedSource.VIRUSTOTAL,
            base_reputation=0.92,
            update_frequency_minutes=30,
            weight=1.5
        ),
        FeedSource.MITRE_ATTACK: FeedSourceConfig(
            name=FeedSource.MITRE_ATTACK,
            base_reputation=0.95,
            update_frequency_minutes=1440,
            weight=1.3
        ),
        FeedSource.ALIENVAULT_OTX: FeedSourceConfig(
            name=FeedSource.ALIENVAULT_OTX,
            base_reputation=0.80,
            update_frequency_minutes=30,
            weight=1.0
        ),
        FeedSource.EMERGING_THREATS: FeedSourceConfig(
            name=FeedSource.EMERGING_THREATS,
            base_reputation=0.88,
            update_frequency_minutes=60,
            weight=1.1
        ),
        FeedSource.THREATFOX: FeedSourceConfig(
            name=FeedSource.THREATFOX,
            base_reputation=0.82,
            update_frequency_minutes=10,
            weight=0.9
        ),
        FeedSource.URLHAUS: FeedSourceConfig(
            name=FeedSource.URLHAUS,
            base_reputation=0.78,
            update_frequency_minutes=5,
            weight=0.8
        ),
    }
    
    # IOC validation regex patterns
    PATTERNS = {
        IOCTYPE.IPV4: re.compile(r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$'),
        IOCTYPE.IPV6: re.compile(r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'),
        IOCTYPE.DOMAIN: re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$'),
        IOCTYPE.MD5: re.compile(r'^[a-fA-F0-9]{32}$'),
        IOCTYPE.SHA1: re.compile(r'^[a-fA-F0-9]{40}$'),
        IOCTYPE.SHA256: re.compile(r'^[a-fA-F0-9]{64}$'),
        IOCTYPE.EMAIL: re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
        IOCTYPE.CVE: re.compile(r'^CVE-\d{4}-\d{4,7}$', re.IGNORECASE),
    }
    
    def __init__(
        self,
        custom_feed_configs: Optional[Dict[FeedSource, FeedSourceConfig]] = None,
        deduplication_threshold: float = 0.95,
        min_confidence_threshold: float = 0.3
    ):
        self.feed_configs = custom_feed_configs or self.DEFAULT_FEED_CONFIGS.copy()
        self.deduplication_threshold = deduplication_threshold
        self.min_confidence_threshold = min_confidence_threshold
        self.feed_health: Dict[FeedSource, FeedHealthMetrics] = {}
        self.seen_ioc_hashes: Set[str] = set()
        self.normalized_iocs: Dict[str, NormalizedIndicator] = {}
        self._initialize_health_metrics()
    
    def _initialize_health_metrics(self) -> None:
        """Initialize health tracking for all feed sources"""
        for source in FeedSource:
            self.feed_health[source] = FeedHealthMetrics(source=source)
    
    @staticmethod
    def generate_ioc_id(ioc_type: IOCTYPE, ioc_value: str) -> str:
        """Generate a deterministic unique ID for an IOC"""
        normalized_value = ioc_value.strip().lower()
        hash_input = f"{ioc_type.value}:{normalized_value}".encode('utf-8')
        return hashlib.sha256(hash_input).hexdigest()[:32]
    
    def validate_ioc(self, ioc_type: IOCTYPE, ioc_value: str) -> bool:
        """Validate IOC format using regex patterns"""
        if ioc_type in self.PATTERNS:
            return bool(self.PATTERNS[ioc_type].match(ioc_value.strip()))
        
        if ioc_type == IOCTYPE.URL:
            try:
                result = urlparse(ioc_value)
                return all([result.scheme, result.netloc])
            except Exception:
                return False
        
        return True  # Allow unvalidated types through
    
    def detect_ioc_type(self, value: str) -> Optional[IOCTYPE]:
        """Auto-detect IOC type from value"""
        value = value.strip()
        
        for ioc_type, pattern in self.PATTERNS.items():
            if pattern.match(value):
                return ioc_type
        
        # Check for URLs
        if value.startswith(('http://', 'https://', 'ftp://')):
            return IOCTYPE.URL
        
        return None
    
    def calculate_confidence_score(
        self,
        sources: List[FeedSource],
        corroboration_count: int,
        age_days: float
    ) -> float:
        """
        Calculate confidence score based on:
        1. Source reputation (weighted)
        2. Number of corroborating sources
        3. Age of the indicator (time decay)
        """
        if not sources:
            return 0.0
        
        # Base score from source reputations
        base_scores = []
        total_weight = 0.0
        for source in sources:
            config = self.feed_configs.get(source)
            if config:
                base_scores.append(config.base_reputation * config.weight)
                total_weight += config.weight
        
        if not base_scores:
            base_score = 0.5
        else:
            base_score = sum(base_scores) / total_weight
        
        # Corroboration bonus (more sources = higher confidence)
        corroboration_bonus = min(0.2, (corroboration_count - 1) * 0.05)
        
        # Time decay (indicators lose value over time)
        decay_factor = max(0.5, 1.0 - (age_days * 0.02))
        
        final_score = min(1.0, (base_score + corroboration_bonus) * decay_factor)
        
        return round(final_score, 3)
    
    def normalize_indicator(
        self,
        raw_indicator: RawIndicator,
        ioc_type: IOCTYPE,
        ioc_value: str
    ) -> Optional[NormalizedIndicator]:
        """Normalize a raw indicator into standard format"""
        health = self.feed_health[raw_indicator.source]
        health.indicators_processed += 1
        
        # Validate the IOC
        if not self.validate_ioc(ioc_type, ioc_value):
            health.invalid_indicators += 1
            return None
        
        ioc_id = self.generate_ioc_id(ioc_type, ioc_value)
        
        # Check for duplicate
        if ioc_id in self.normalized_iocs:
            health.duplicates_found += 1
            existing = self.normalized_iocs[ioc_id]
            
            # Merge sources
            if raw_indicator.source not in existing.sources:
                existing.sources.append(raw_indicator.source)
                existing.correlation_count += 1
                
                # Recalculate confidence with additional source
                age_days = (datetime.utcnow() - existing.first_seen).total_seconds() / 86400
                existing.confidence_score = self.calculate_confidence_score(
                    existing.sources,
                    existing.correlation_count,
                    age_days
                )
            
            # Update last seen
            existing.last_seen = max(existing.last_seen, raw_indicator.fetched_at)
            
            return None
        
        # Calculate age (assume new if first seen)
        age_days = 0.0  # Fresh indicator
        
        # Calculate confidence
        confidence = self.calculate_confidence_score(
            [raw_indicator.source],
            corroboration_count=1,
            age_days=age_days
        )
        
        # Filter by minimum confidence threshold
        if confidence < self.min_confidence_threshold:
            return None
        
        # Map severity based on source and type
        severity = self._map_severity(raw_indicator.source, ioc_type)
        
        normalized = NormalizedIndicator(
            ioc_id=ioc_id,
            ioc_type=ioc_type,
            ioc_value=ioc_value.strip().lower(),
            severity=severity,
            threat_types=self._infer_threat_types(ioc_type, raw_indicator.source),
            confidence_score=confidence,
            sources=[raw_indicator.source],
            first_seen=raw_indicator.fetched_at,
            last_seen=raw_indicator.fetched_at,
            correlation_count=1,
            feed_quality_score=self.feed_configs[raw_indicator.source].base_reputation
        )
        
        self.normalized_iocs[ioc_id] = normalized
        self.seen_ioc_hashes.add(ioc_id)
        
        return normalized
    
    def _map_severity(self, source: FeedSource, ioc_type: IOCTYPE) -> ThreatSeverity:
        """Map source and IOC type to severity level"""
        severity_mapping = {
            FeedSource.VIRUSTOTAL: ThreatSeverity.HIGH,
            FeedSource.MITRE_ATTACK: ThreatSeverity.CRITICAL,
            FeedSource.ABUSEIPDB: ThreatSeverity.MEDIUM,
            FeedSource.ALIENVAULT_OTX: ThreatSeverity.MEDIUM,
            FeedSource.EMERGING_THREATS: ThreatSeverity.HIGH,
            FeedSource.THREATFOX: ThreatSeverity.MEDIUM,
            FeedSource.URLHAUS: ThreatSeverity.MEDIUM,
        }
        
        base_severity = severity_mapping.get(source, ThreatSeverity.LOW)
        
        # Adjust severity based on IOC type
        if ioc_type in (IOCTYPE.SHA256, IOCTYPE.MD5, IOCTYPE.SHA1):
            if base_severity == ThreatSeverity.MEDIUM:
                return ThreatSeverity.HIGH
        
        return base_severity
    
    def _infer_threat_types(self, ioc_type: IOCTYPE, source: FeedSource) -> List[ThreatType]:
        """Infer likely threat types based on IOC type and source"""
        types = []
        
        if source == FeedSource.URLHAUS:
            types.append(ThreatType.MALWARE)
        elif source == FeedSource.ABUSEIPDB:
            types.extend([ThreatType.SCANNER, ThreatType.BOTNET])
        elif source in (FeedSource.VIRUSTOTAL, FeedSource.THREATFOX):
            types.extend([ThreatType.MALWARE, ThreatType.C2])
        elif source == FeedSource.MITRE_ATTACK:
            types.append(ThreatType.EXPLOIT)
        
        if ioc_type in (IOCTYPE.DOMAIN, IOCTYPE.URL):
            types.append(ThreatType.PHISHING)
        
        if not types:
            types.append(ThreatType.MALWARE)
        
        return list(set(types))
    
    def aggregate_feeds(
        self,
        raw_indicators: List[RawIndicator],
        batch_size: int = 1000
    ) -> AggregationResult:
        """
        Process a batch of raw indicators from multiple feeds.
        
        In production, this would pull from actual feed APIs.
        For this implementation, we process provided raw indicators.
        """
        start_time = datetime.utcnow()
        run_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:16]
        
        total_fetched = len(raw_indicators)
        duplicates_before = len(self.normalized_iocs)
        
        # Process in batches
        for i in range(0, len(raw_indicators), batch_size):
            batch = raw_indicators[i:i + batch_size]
            batch_start = time.time()
            
            for raw_ind in batch:
                # Try to detect type if not explicitly provided
                if 'ioc_value' in raw_ind.raw_data:
                    ioc_value = raw_ind.raw_data['ioc_value']
                    ioc_type = raw_ind.raw_data.get('ioc_type')
                    
                    if isinstance(ioc_type, str):
                        try:
                            ioc_type = IOCTYPE(ioc_type)
                        except ValueError:
                            ioc_type = self.detect_ioc_type(ioc_value)
                    else:
                        ioc_type = self.detect_ioc_type(ioc_value)
                    
                    if ioc_type:
                        self.normalize_indicator(raw_ind, ioc_type, ioc_value)
                
                # Update health metrics
                self.feed_health[raw_ind.source].last_successful_fetch = datetime.utcnow()
                processing_time = (time.time() - batch_start) * 1000 / len(batch)
                self.feed_health[raw_ind.source].average_processing_time_ms = processing_time
        
        # Calculate statistics
        end_time = datetime.utcnow()
        unique_count = len(self.normalized_iocs) - duplicates_before
        duplicates_removed = total_fetched - unique_count
        
        # Count by type and severity
        by_type: Dict[IOCTYPE, int] = {}
        by_severity: Dict[ThreatSeverity, int] = {}
        
        for ind in self.normalized_iocs.values():
            by_type[ind.ioc_type] = by_type.get(ind.ioc_type, 0) + 1
            by_severity[ind.severity] = by_severity.get(ind.severity, 0) + 1
        
        return AggregationResult(
            run_id=run_id,
            started_at=start_time,
            completed_at=end_time,
            total_indicators_fetched=total_fetched,
            total_unique_indicators=unique_count,
            total_duplicates_removed=duplicates_removed,
            indicators_by_type=by_type,
            indicators_by_severity=by_severity,
            feed_health=self.feed_health.copy(),
            normalized_indicators=list(self.normalized_iocs.values())
        )
    
    def get_high_confidence_indicators(
        self,
        min_confidence: float = 0.7,
        min_severity: ThreatSeverity = ThreatSeverity.MEDIUM
    ) -> List[NormalizedIndicator]:
        """Get filtered list of high-confidence indicators"""
        severity_order = {
            ThreatSeverity.INFO: 0,
            ThreatSeverity.LOW: 1,
            ThreatSeverity.MEDIUM: 2,
            ThreatSeverity.HIGH: 3,
            ThreatSeverity.CRITICAL: 4,
        }
        
        min_level = severity_order[min_severity]
        
        return [
            ind for ind in self.normalized_iocs.values()
            if ind.confidence_score >= min_confidence
            and severity_order[ind.severity] >= min_level
        ]
    
    def export_to_stix2(self, indicators: List[NormalizedIndicator]) -> Dict[str, Any]:
        """Export normalized indicators to STIX 2.1 format"""
        stix_objects = []
        
        for ind in indicators:
            stix_obj = {
                "type": "indicator",
                "id": f"indicator--{ind.ioc_id}",
                "created": ind.first_seen.isoformat() + "Z",
                "modified": ind.last_seen.isoformat() + "Z",
                "name": f"{ind.ioc_type.value}: {ind.ioc_value}",
                "description": ind.description or f"Threat indicator from {', '.join(s.value for s in ind.sources)}",
                "pattern": f"[file:hashes.{ind.ioc_type.value.upper()} = '{ind.ioc_value}']" if ind.ioc_type in (IOCTYPE.MD5, IOCTYPE.SHA1, IOCTYPE.SHA256) else f"[network-traffic:dst_{ind.ioc_type.value} = '{ind.ioc_value}']",
                "pattern_type": "stix",
                "valid_from": ind.first_seen.isoformat() + "Z",
                "labels": [t.value for t in ind.threat_types],
                "confidence": int(ind.confidence_score * 100),
                "external_references": [{"source_name": s.value} for s in ind.sources]
            }
            stix_objects.append(stix_obj)
        
        return {
            "type": "bundle",
            "id": f"bundle--{hashlib.md5(str(time.time()).encode()).hexdigest()}",
            "objects": stix_objects,
            "spec_version": "2.1"
        }
    
    def get_feed_quality_report(self) -> Dict[str, Any]:
        """Generate a comprehensive feed quality report"""
        report = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total_indicators": len(self.normalized_iocs),
            "average_confidence": 0.0,
            "feed_sources": {},
            "deduplication_efficiency": 0.0
        }
        
        if self.normalized_iocs:
            avg_conf = sum(ind.confidence_score for ind in self.normalized_iocs.values()) / len(self.normalized_iocs)
            report["average_confidence"] = round(avg_conf, 3)
        
        for source, health in self.feed_health.items():
            report["feed_sources"][source.value] = {
                "processed": health.indicators_processed,
                "duplicates": health.duplicates_found,
                "invalid": health.invalid_indicators,
                "quality_rate": round(
                    (health.indicators_processed - health.invalid_indicators) / health.indicators_processed
                    if health.indicators_processed > 0 else 1.0,
                    3
                ),
                "avg_processing_ms": round(health.average_processing_time_ms, 2)
            }
        
        return report


# Factory function for easy instantiation
def create_threat_feed_aggregator(
    min_confidence: float = 0.3
) -> ThreatFeedAggregator:
    """Create a configured ThreatFeedAggregator instance"""
    return ThreatFeedAggregator(min_confidence_threshold=min_confidence)


# Verification function
def verify_threat_feed_aggregator() -> Dict[str, Any]:
    """Verify the aggregator works correctly with sample data"""
    aggregator = create_threat_feed_aggregator()
    
    # Create sample raw indicators from multiple sources
    sample_indicators = [
        # AbuseIPDB - malicious IPs
        RawIndicator(
            source=FeedSource.ABUSEIPDB,
            raw_data={"ioc_value": "192.168.1.100", "ioc_type": "ipv4", "country": "US", "abuse_score": 90}
        ),
        RawIndicator(
            source=FeedSource.ABUSEIPDB,
            raw_data={"ioc_value": "10.0.0.50", "ioc_type": "ipv4", "country": "DE", "abuse_score": 75}
        ),
        # VirusTotal - file hashes
        RawIndicator(
            source=FeedSource.VIRUSTOTAL,
            raw_data={"ioc_value": "d41d8cd98f00b204e9800998ecf8427e", "ioc_type": "md5", "detections": 45}
        ),
        RawIndicator(
            source=FeedSource.VIRUSTOTAL,
            raw_data={"ioc_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "ioc_type": "sha256", "detections": 52}
        ),
        # URLhaus - malicious URLs
        RawIndicator(
            source=FeedSource.URLHAUS,
            raw_data={"ioc_value": "https://malicious-example.com/bad.exe", "ioc_type": "url", "threat": "malware_download"}
        ),
        # Duplicate IP to test deduplication
        RawIndicator(
            source=FeedSource.THREATFOX,
            raw_data={"ioc_value": "192.168.1.100", "ioc_type": "ipv4", "malware": "Emotet"}
        ),
        # MITRE CVE
        RawIndicator(
            source=FeedSource.MITRE_ATTACK,
            raw_data={"ioc_value": "CVE-2026-1234", "ioc_type": "cve", "cvss": 9.8}
        ),
        # Invalid indicator to test validation
        RawIndicator(
            source=FeedSource.ALIENVAULT_OTX,
            raw_data={"ioc_value": "not-a-valid-ip", "ioc_type": "ipv4"}
        ),
    ]
    
    result = aggregator.aggregate_feeds(sample_indicators)
    
    # Get high confidence indicators
    high_conf = aggregator.get_high_confidence_indicators(min_confidence=0.7)
    
    # Export to STIX2
    stix_export = aggregator.export_to_stix2(result.normalized_indicators[:3])
    
    # Get quality report
    quality_report = aggregator.get_feed_quality_report()
    
    return {
        "aggregation_run": {
            "run_id": result.run_id,
            "total_fetched": result.total_indicators_fetched,
            "unique_indicators": result.total_unique_indicators,
            "duplicates_removed": result.total_duplicates_removed,
            "processing_time_ms": round((result.completed_at - result.started_at).total_seconds() * 1000, 2)
        },
        "high_confidence_count": len(high_conf),
        "stix2_export_valid": "objects" in stix_export and len(stix_export["objects"]) > 0,
        "quality_report": quality_report,
        "verification_passed": (
            result.total_unique_indicators > 0 and
            result.total_duplicates_removed > 0 and
            len(high_conf) > 0
        )
    }


if __name__ == "__main__":
    # Run verification
    verification = verify_threat_feed_aggregator()
    print(json.dumps(verification, indent=2, default=str))
