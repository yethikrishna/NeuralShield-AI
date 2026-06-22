"""
Threat Intelligence Alert Correlation Context Enricher v75
NeuralShield AI - Advanced Security Module

This module provides advanced alert correlation and context enrichment capabilities
for threat intelligence processing. It adds contextual metadata to security alerts,
correlates related alerts across different data sources, and improves detection accuracy
by providing richer context for security analysts.

API Stability: STABLE
Backward Compatible: YES
Incremental Addition: YES (no existing code modified)
"""

import hashlib
import json
import time
import re
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import threading


class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AlertType(Enum):
    """Types of security alerts"""
    NETWORK_ANOMALY = "network_anomaly"
    MALWARE_DETECTION = "malware_detection"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK_ATTEMPT = "jailbreak_attempt"
    ADVERSARIAL_INPUT = "adversarial_input"
    RAG_POISONING = "rag_poisoning"
    MEMORY_CORRUPTION = "memory_corruption"


class EnrichmentSource(Enum):
    """Sources of enrichment data"""
    GEOLOCATION = "geolocation"
    THREAT_FEED = "threat_feed"
    VULNERABILITY_DB = "vulnerability_db"
    ASSET_INVENTORY = "asset_inventory"
    USER_CONTEXT = "user_context"
    HISTORICAL_DATA = "historical_data"
    MITRE_ATTACK = "mitre_attack"
    IOC_REPUTATION = "ioc_reputation"


@dataclass
class EnrichedAlert:
    """Data structure for enriched security alerts"""
    alert_id: str
    original_alert: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    severity: AlertSeverity = AlertSeverity.MEDIUM
    alert_type: AlertType = AlertType.NETWORK_ANOMALY
    enrichment_data: Dict[str, Any] = field(default_factory=dict)
    correlated_alerts: List[str] = field(default_factory=list)
    confidence_score: float = 0.5
    mitre_techniques: List[str] = field(default_factory=list)
    false_positive_probability: float = 0.0
    threat_actor_tags: List[str] = field(default_factory=list)
    ioc_matches: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format"""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "severity": self.severity.value,
            "alert_type": self.alert_type.value,
            "enrichment_data": self.enrichment_data,
            "correlated_alerts": self.correlated_alerts,
            "confidence_score": self.confidence_score,
            "mitre_techniques": self.mitre_techniques,
            "false_positive_probability": self.false_positive_probability,
            "threat_actor_tags": self.threat_actor_tags,
            "ioc_matches": self.ioc_matches,
            "original_alert": self.original_alert
        }


class AlertCorrelationEngine:
    """Engine for correlating related security alerts"""

    def __init__(self, correlation_window_seconds: int = 3600):
        self.correlation_window = correlation_window_seconds
        self.alert_history: deque = deque(maxlen=10000)
        self.correlation_rules: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._initialize_correlation_rules()

    def _initialize_correlation_rules(self):
        """Initialize default correlation rules"""
        self.correlation_rules = [
            {
                "name": "same_source_ip",
                "fields": ["source_ip"],
                "min_matches": 3,
                "time_window": 300,
                "severity_boost": 0.2
            },
            {
                "name": "same_target_asset",
                "fields": ["target_asset", "asset_id"],
                "min_matches": 2,
                "time_window": 600,
                "severity_boost": 0.15
            },
            {
                "name": "similar_ioc_pattern",
                "fields": ["ioc_value", "hash_md5", "hash_sha256"],
                "min_matches": 2,
                "time_window": 1800,
                "severity_boost": 0.25
            },
            {
                "name": "attack_chain_sequence",
                "fields": ["mitre_technique"],
                "min_matches": 2,
                "time_window": 3600,
                "severity_boost": 0.3
            }
        ]

    def add_alert(self, alert: EnrichedAlert) -> List[str]:
        """Add alert and find correlated alerts"""
        with self._lock:
            correlated = []
            current_time = time.time()

            # Clean old alerts outside window
            while self.alert_history and (current_time - self.alert_history[0].timestamp) > self.correlation_window:
                self.alert_history.popleft()

            # Check correlation with existing alerts
            for existing_alert in self.alert_history:
                if self._check_correlation(alert, existing_alert):
                    correlated.append(existing_alert.alert_id)
                    if alert.alert_id not in existing_alert.correlated_alerts:
                        existing_alert.correlated_alerts.append(alert.alert_id)

            self.alert_history.append(alert)
            return correlated

    def _check_correlation(self, alert1: EnrichedAlert, alert2: EnrichedAlert) -> bool:
        """Check if two alerts should be correlated"""
        if alert1.alert_id == alert2.alert_id:
            return False

        time_diff = abs(alert1.timestamp - alert2.timestamp)

        for rule in self.correlation_rules:
            if time_diff > rule["time_window"]:
                continue

            matches = 0
            for field in rule["fields"]:
                val1 = alert1.original_alert.get(field)
                val2 = alert2.original_alert.get(field)
                if val1 and val2 and val1 == val2:
                    matches += 1

            if matches >= rule["min_matches"]:
                return True

        return False

    def get_alert_clusters(self, min_cluster_size: int = 2) -> List[List[str]]:
        """Get clusters of correlated alerts"""
        clusters = []
        visited = set()

        with self._lock:
            for alert in self.alert_history:
                if alert.alert_id in visited:
                    continue

                cluster = [alert.alert_id]
                stack = alert.correlated_alerts.copy()
                visited.add(alert.alert_id)

                while stack:
                    corr_id = stack.pop()
                    if corr_id not in visited:
                        visited.add(corr_id)
                        cluster.append(corr_id)
                        # Find the actual alert object
                        for a in self.alert_history:
                            if a.alert_id == corr_id:
                                stack.extend([cid for cid in a.correlated_alerts if cid not in visited])
                                break

                if len(cluster) >= min_cluster_size:
                    clusters.append(cluster)

        return clusters


class ContextEnricher:
    """Context enrichment processor for security alerts"""

    def __init__(self):
        self.enrichment_sources: Dict[EnrichmentSource, Any] = {}
        self.ioc_patterns = self._compile_ioc_patterns()
        self.mitre_technique_mapping = self._initialize_mitre_mapping()

    def _compile_ioc_patterns(self) -> Dict[str, re.Pattern]:
        """Compile regex patterns for IOC extraction"""
        return {
            "ipv4": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            "domain": re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'),
            "url": re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'),
            "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
            "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b')
        }

    def _initialize_mitre_mapping(self) -> Dict[str, List[str]]:
        """Initialize MITRE ATT&CK technique mappings"""
        return {
            "prompt_injection": ["T1059", "T1204", "T1036"],
            "jailbreak_attempt": ["T1498", "T1059", "T1562"],
            "data_exfiltration": ["T1041", "T1020", "T1048"],
            "privilege_escalation": ["T1068", "T1548", "T1078"],
            "malware_detection": ["T1204", "T1059", "T1027"],
            "unauthorized_access": ["T1078", "T1110", "T1087"],
            "adversarial_input": ["T1498", "T1565", "T1036"],
            "rag_poisoning": ["T1565", "T1567", "T1027"]
        }

    def enrich_alert(self, alert: Dict[str, Any]) -> EnrichedAlert:
        """Enrich a raw security alert with contextual data"""
        alert_id = self._generate_alert_id(alert)

        enriched = EnrichedAlert(
            alert_id=alert_id,
            original_alert=alert,
            timestamp=alert.get("timestamp", time.time())
        )

        # Extract and set alert type
        alert_type_str = alert.get("alert_type", "network_anomaly")
        try:
            enriched.alert_type = AlertType(alert_type_str)
        except ValueError:
            enriched.alert_type = AlertType.NETWORK_ANOMALY

        # Extract and set severity
        severity_str = alert.get("severity", "medium")
        try:
            enriched.severity = AlertSeverity(severity_str)
        except ValueError:
            enriched.severity = AlertSeverity.MEDIUM

        # Apply enrichments
        enriched.ioc_matches = self._extract_iocs(alert)
        enriched.mitre_techniques = self._map_mitre_techniques(enriched.alert_type)
        enriched.enrichment_data = self._gather_context_data(alert)
        enriched.confidence_score = self._calculate_confidence(alert, enriched)
        enriched.false_positive_probability = self._calculate_fp_probability(alert, enriched)
        enriched.threat_actor_tags = self._identify_threat_actors(alert, enriched)

        return enriched

    def _generate_alert_id(self, alert: Dict[str, Any]) -> str:
        """Generate deterministic alert ID"""
        alert_str = json.dumps(alert, sort_keys=True)
        return f"alert_{hashlib.sha256(alert_str.encode()).hexdigest()[:16]}"

    def _extract_iocs(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract Indicators of Compromise from alert"""
        iocs = []
        alert_text = json.dumps(alert).lower()

        for ioc_type, pattern in self.ioc_patterns.items():
            matches = pattern.findall(alert_text)
            for match in matches:
                iocs.append({
                    "type": ioc_type,
                    "value": match,
                    "source": "auto_extracted"
                })

        return iocs

    def _map_mitre_techniques(self, alert_type: AlertType) -> List[str]:
        """Map alert type to MITRE ATT&CK techniques"""
        return self.mitre_technique_mapping.get(alert_type.value, [])

    def _gather_context_data(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Gather contextual data from various sources"""
        context = {
            "enrichment_timestamp": time.time(),
            "enrichment_version": "v75",
            "source_ip_info": self._enrich_ip(alert.get("source_ip")),
            "asset_criticality": self._assess_asset_criticality(alert),
            "temporal_context": self._analyze_temporal_context(alert),
            "environmental_context": self._get_environmental_context(alert)
        }
        return context

    def _enrich_ip(self, ip: Optional[str]) -> Dict[str, Any]:
        """Enrich IP address with metadata"""
        if not ip:
            return {}

        # Simulated geolocation enrichment
        is_private = ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                                   "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                                   "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                                   "172.30.", "172.31.", "127."))

        return {
            "ip": ip,
            "is_private": is_private,
            "is_external": not is_private,
            "reputation_score": 0.1 if is_private else 0.5,
            "known_bad": False
        }

    def _assess_asset_criticality(self, alert: Dict[str, Any]) -> str:
        """Assess criticality of affected asset"""
        asset_tags = str(alert.get("asset_tags", "")).lower()
        target = str(alert.get("target", "")).lower()

        high_criticality_keywords = ["prod", "production", "database", "pii", "secret", "key", "admin", "root"]
        medium_criticality_keywords = ["staging", "test", "internal"]

        if any(kw in asset_tags or kw in target for kw in high_criticality_keywords):
            return "critical"
        elif any(kw in asset_tags or kw in target for kw in medium_criticality_keywords):
            return "medium"
        return "low"

    def _analyze_temporal_context(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze temporal context of alert"""
        ts = alert.get("timestamp", time.time())
        if isinstance(ts, (int, float)):
            struct_time = time.localtime(ts)
            hour = struct_time.tm_hour
            is_business_hours = 9 <= hour <= 17
            is_weekend = struct_time.tm_wday >= 5

            return {
                "hour_of_day": hour,
                "is_business_hours": is_business_hours,
                "is_weekend": is_weekend,
                "anomaly_score": 0.3 if (not is_business_hours or is_weekend) else 0.0
            }
        return {}

    def _get_environmental_context(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Get environmental context"""
        return {
            "network_zone": alert.get("network_zone", "unknown"),
            "authentication_status": alert.get("authenticated", False),
            "user_privilege_level": alert.get("privilege_level", "standard")
        }

    def _calculate_confidence(self, alert: Dict[str, Any], enriched: EnrichedAlert) -> float:
        """Calculate confidence score for alert"""
        base_score = float(alert.get("confidence", 0.5))

        # Boost based on IOC matches
        ioc_boost = min(len(enriched.ioc_matches) * 0.05, 0.2)

        # Boost based on MITRE mapping
        mitre_boost = min(len(enriched.mitre_techniques) * 0.03, 0.1)

        # Asset criticality factor
        criticality_factor = 0.1 if enriched.enrichment_data.get("asset_criticality") == "critical" else 0.0

        confidence = base_score + ioc_boost + mitre_boost + criticality_factor
        return max(0.0, min(1.0, confidence))

    def _calculate_fp_probability(self, alert: Dict[str, Any], enriched: EnrichedAlert) -> float:
        """Calculate false positive probability"""
        fp_score = 0.0

        # Higher FP probability for low severity, low confidence
        if enriched.severity == AlertSeverity.LOW:
            fp_score += 0.2
        if enriched.confidence_score < 0.3:
            fp_score += 0.3

        # Lower FP for critical assets
        if enriched.enrichment_data.get("asset_criticality") == "critical":
            fp_score -= 0.1

        return max(0.0, min(1.0, fp_score))

    def _identify_threat_actors(self, alert: Dict[str, Any], enriched: EnrichedAlert) -> List[str]:
        """Identify potential threat actor tags"""
        tags = []

        alert_text = json.dumps(alert).lower()
        actor_patterns = {
            "apt": ["apt", "advanced persistent threat", "nation state"],
            "ransomware": ["ransom", "encrypt", "bitcoin", "wallet"],
            "phishing": ["phish", "credential", "login", "password"],
            "insider": ["insider", "employee", "internal"],
            "script_kiddie": ["script", "kiddie", "automated", "scanner"]
        }

        for actor, patterns in actor_patterns.items():
            if any(p in alert_text for p in patterns):
                tags.append(actor)

        # Add based on alert type
        if enriched.alert_type in [AlertType.PROMPT_INJECTION, AlertType.JAILBREAK_ATTEMPT]:
            tags.append("llm_attacker")

        return tags


class AlertCorrelationContextEnricher:
    """
    Main class for Alert Correlation and Context Enrichment v75

    Combines alert correlation engine with context enrichment capabilities
    to provide comprehensive threat intelligence processing.
    """

    def __init__(self, correlation_window: int = 3600):
        self.correlation_engine = AlertCorrelationEngine(correlation_window)
        self.context_enricher = ContextEnricher()
        self.processed_count = 0
        self.enrichment_stats: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

    def process_alert(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a raw security alert: enrich and correlate

        Args:
            raw_alert: Raw security alert dictionary

        Returns:
            Fully enriched alert with correlations
        """
        with self._lock:
            # Enrich alert with context
            enriched = self.context_enricher.enrich_alert(raw_alert)

            # Correlate with other alerts
            correlated = self.correlation_engine.add_alert(enriched)
            enriched.correlated_alerts = correlated

            # Update statistics
            self.processed_count += 1
            self.enrichment_stats[enriched.severity.value] += 1
            self.enrichment_stats[enriched.alert_type.value] += 1

            # Adjust confidence based on correlations
            if correlated:
                correlation_boost = min(len(correlated) * 0.05, 0.2)
                enriched.confidence_score = min(1.0, enriched.confidence_score + correlation_boost)

            return enriched.to_dict()

    def process_alerts_batch(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process a batch of alerts"""
        return [self.process_alert(alert) for alert in alerts]

    def get_correlation_clusters(self) -> List[List[str]]:
        """Get clusters of correlated alerts"""
        return self.correlation_engine.get_alert_clusters()

    def get_enrichment_statistics(self) -> Dict[str, Any]:
        """Get enrichment processing statistics"""
        with self._lock:
            return {
                "total_processed": self.processed_count,
                "severity_distribution": dict(self.enrichment_stats),
                "active_clusters": len(self.get_correlation_clusters()),
                "enrichment_version": "v75",
                "correlation_window_seconds": self.correlation_engine.correlation_window
            }

    def get_high_confidence_alerts(self, min_confidence: float = 0.7) -> List[Dict[str, Any]]:
        """Get alerts with confidence score above threshold"""
        high_conf = []
        for alert in self.correlation_engine.alert_history:
            if alert.confidence_score >= min_confidence:
                high_conf.append(alert.to_dict())
        return high_conf


# Export public interface
__all__ = [
    "AlertCorrelationContextEnricher",
    "AlertSeverity",
    "AlertType",
    "EnrichmentSource",
    "EnrichedAlert"
]
