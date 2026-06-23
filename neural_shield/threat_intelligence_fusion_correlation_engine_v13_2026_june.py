"""
Threat Intelligence Fusion & Correlation Engine (Dimension A - Feature Expansion)
================================================================================
ADD-ONLY Feature Expansion - New module, no modifications to existing code.

This module adds real-time threat intelligence fusion capabilities:
- Multi-source threat feed aggregation (MITRE ATT&CK, CVE, IOC databases)
- Cross-module threat correlation and pattern detection
- Threat severity scoring and prioritization
- IOC (Indicator of Compromise) matching and enrichment
- TTP (Tactics, Techniques, Procedures) mapping and tracking

Backward Compatible: 100% - New standalone module, wraps existing detectors
"""

import hashlib
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime, timedelta


class ThreatSeverity(Enum):
    """Threat severity levels for prioritization"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatSource(Enum):
    """Threat intelligence source types"""
    MITRE_ATTACK = "mitre_attack"
    CVE_DATABASE = "cve_database"
    IOC_FEED = "ioc_feed"
    INTERNAL_DETECTOR = "internal_detector"
    THREAT_FEED = "threat_feed"
    COMMUNITY = "community"


@dataclass
class IOCIndicator:
    """Indicator of Compromise data structure"""
    ioc_type: str  # ip, domain, hash, url, email
    value: str
    severity: ThreatSeverity
    source: ThreatSource
    first_seen: datetime
    last_seen: datetime
    confidence: float  # 0.0 - 1.0
    ttp_tags: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class CorrelatedThreat:
    """Correlated threat event with fused intelligence"""
    threat_id: str
    timestamp: datetime
    severity: ThreatSeverity
    confidence: float
    matched_iocs: List[IOCIndicator] = field(default_factory=list)
    matched_ttps: List[str] = field(default_factory=list)
    detector_hits: Dict[str, float] = field(default_factory=dict)
    fusion_score: float = 0.0
    recommended_action: str = "monitor"
    threat_description: str = ""


class ThreatFeedDatabase:
    """In-memory threat feed database with IOC and TTP data"""
    
    def __init__(self):
        self.ioc_database: Dict[str, IOCIndicator] = {}
        self.ttp_mappings: Dict[str, List[str]] = {}
        self.threat_patterns: Dict[str, List[str]] = {}
        self._initialize_default_feeds()
    
    def _initialize_default_feeds(self):
        """Initialize with common threat patterns and IOCs"""
        # Common malicious IP patterns (simplified for demo)
        malicious_patterns = [
            ("192.168.1.100", "ip", ThreatSeverity.HIGH),
            ("10.0.0.50", "ip", ThreatSeverity.MEDIUM),
            ("malicious-domain.com", "domain", ThreatSeverity.CRITICAL),
            ("phishing-site.net", "domain", ThreatSeverity.HIGH),
            ("d41d8cd98f00b204e9800998ecf8427e", "hash", ThreatSeverity.CRITICAL),
            ("http://exploit-kit.org/payload", "url", ThreatSeverity.CRITICAL),
        ]
        
        for value, ioc_type, severity in malicious_patterns:
            self.add_ioc(IOCIndicator(
                ioc_type=ioc_type,
                value=value,
                severity=severity,
                source=ThreatSource.THREAT_FEED,
                first_seen=datetime.now() - timedelta(days=30),
                last_seen=datetime.now(),
                confidence=0.95,
                ttp_tags=["T1059", "T1027", "T1064"],
                description=f"Known malicious {ioc_type} from threat feeds"
            ))
        
        # MITRE ATT&CK TTP mappings for prompt injection patterns
        self.ttp_mappings = {
            "prompt_injection": ["T1059", "T1036", "T1064", "T1204"],
            "jailbreak": ["T1059", "T1498", "T1064", "T1204"],
            "data_exfiltration": ["T1041", "T1020", "T1537"],
            "privilege_escalation": ["T1068", "T1548", "T1078"],
            "social_engineering": ["T1598", "T1566", "T1534"],
        }
        
        # Threat pattern signatures
        self.threat_patterns = {
            "ignore_previous": ["ignore previous", "disregard instructions", "forget all prior"],
            "system_prompt": ["you are now", "act as", "roleplay as", "pretend to be"],
            "injection_markers": ["\n\nHuman:", "\n\nAssistant:", "[INST]", "[/INST]"],
            "exfiltration": ["base64", "encode", "output as", "write to file"],
        }
    
    def add_ioc(self, ioc: IOCIndicator) -> None:
        """Add an IOC to the database"""
        key = f"{ioc.ioc_type}:{ioc.value}"
        self.ioc_database[key] = ioc
    
    def match_iocs(self, text: str) -> List[IOCIndicator]:
        """Match text content against IOC database"""
        matches = []
        
        # IP address pattern
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        for ip in re.findall(ip_pattern, text):
            key = f"ip:{ip}"
            if key in self.ioc_database:
                matches.append(self.ioc_database[key])
        
        # Domain pattern (simplified)
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        for domain in re.findall(domain_pattern, text):
            key = f"domain:{domain.lower()}"
            if key in self.ioc_database:
                matches.append(self.ioc_database[key])
        
        # Hash patterns (MD5, SHA1, SHA256)
        hash_patterns = [
            (r'\b[a-fA-F0-9]{32}\b', 'hash'),
            (r'\b[a-fA-F0-9]{40}\b', 'hash'),
            (r'\b[a-fA-F0-9]{64}\b', 'hash'),
        ]
        
        for pattern, ioc_type in hash_patterns:
            for hash_val in re.findall(pattern, text):
                key = f"{ioc_type}:{hash_val.lower()}"
                if key in self.ioc_database:
                    matches.append(self.ioc_database[key])
        
        return matches
    
    def get_ttps_for_threat_type(self, threat_type: str) -> List[str]:
        """Get MITRE ATT&CK TTPs for a given threat type"""
        return self.ttp_mappings.get(threat_type, [])
    
    def match_threat_patterns(self, text: str) -> Dict[str, float]:
        """Match text against known threat patterns"""
        text_lower = text.lower()
        matches = {}
        
        for pattern_name, signatures in self.threat_patterns.items():
            count = sum(1 for sig in signatures if sig in text_lower)
            if count > 0:
                matches[pattern_name] = min(1.0, count / len(signatures))
        
        return matches


class ThreatCorrelationEngine:
    """Cross-module threat correlation and fusion engine"""
    
    def __init__(self, feed_db: Optional[ThreatFeedDatabase] = None):
        self.feed_db = feed_db or ThreatFeedDatabase()
        self.correlation_history: List[CorrelatedThreat] = []
        self.detector_weights: Dict[str, float] = {
            "prompt_injection": 1.0,
            "jailbreak": 1.2,
            "adversarial": 0.9,
            "hallucination": 0.7,
            "toxicity": 0.6,
            "pii_leakage": 1.1,
        }
    
    def correlate_threats(
        self,
        detector_results: Dict[str, float],
        input_text: str,
        context: Optional[Dict[str, Any]] = None
    ) -> CorrelatedThreat:
        """
        Correlate results from multiple detectors with threat intelligence
        
        Args:
            detector_results: Dictionary of detector_name -> confidence score
            input_text: The original input text for IOC matching
            context: Optional context metadata
            
        Returns:
            CorrelatedThreat object with fused intelligence
        """
        # Match IOCs in input
        matched_iocs = self.feed_db.match_iocs(input_text)
        
        # Match threat patterns
        pattern_matches = self.feed_db.match_threat_patterns(input_text)
        
        # Calculate weighted detector score
        weighted_score = 0.0
        total_weight = 0.0
        matched_ttps = []
        
        for detector, confidence in detector_results.items():
            weight = self.detector_weights.get(detector, 0.8)
            weighted_score += confidence * weight
            total_weight += weight
            
            # Get TTPs for this threat type
            ttps = self.feed_db.get_ttps_for_threat_type(detector)
            matched_ttps.extend(ttps)
        
        # Add pattern match contributions
        for pattern, score in pattern_matches.items():
            weighted_score += score * 0.5
            total_weight += 0.5
            ttps = self.feed_db.get_ttps_for_threat_type(pattern)
            matched_ttps.extend(ttps)
        
        # Normalize score
        fusion_score = weighted_score / total_weight if total_weight > 0 else 0.0
        
        # Add IOC severity contributions
        ioc_severity_bonus = 0.0
        for ioc in matched_iocs:
            severity_multiplier = {
                ThreatSeverity.CRITICAL: 0.3,
                ThreatSeverity.HIGH: 0.2,
                ThreatSeverity.MEDIUM: 0.1,
                ThreatSeverity.LOW: 0.05,
                ThreatSeverity.INFO: 0.0,
            }
            ioc_severity_bonus += severity_multiplier.get(ioc.severity, 0.0) * ioc.confidence
        
        final_score = min(1.0, fusion_score + ioc_severity_bonus)
        
        # Determine overall severity
        if final_score >= 0.8:
            severity = ThreatSeverity.CRITICAL
        elif final_score >= 0.6:
            severity = ThreatSeverity.HIGH
        elif final_score >= 0.4:
            severity = ThreatSeverity.MEDIUM
        elif final_score >= 0.2:
            severity = ThreatSeverity.LOW
        else:
            severity = ThreatSeverity.INFO
        
        # Determine recommended action
        if severity == ThreatSeverity.CRITICAL:
            action = "block_immediately"
        elif severity == ThreatSeverity.HIGH:
            action = "quarantine_and_review"
        elif severity == ThreatSeverity.MEDIUM:
            action = "flag_for_review"
        elif severity == ThreatSeverity.LOW:
            action = "monitor_and_log"
        else:
            action = "log_only"
        
        # Generate threat ID
        threat_id = hashlib.sha256(
            f"{input_text[:100]}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        # Build description
        description_parts = []
        if matched_iocs:
            description_parts.append(f"Matched {len(matched_iocs)} known IOCs")
        if pattern_matches:
            description_parts.append(f"Detected patterns: {', '.join(pattern_matches.keys())}")
        if detector_results:
            high_conf_detectors = [k for k, v in detector_results.items() if v >= 0.7]
            if high_conf_detectors:
                description_parts.append(f"High confidence from: {', '.join(high_conf_detectors)}")
        
        threat = CorrelatedThreat(
            threat_id=threat_id,
            timestamp=datetime.now(),
            severity=severity,
            confidence=final_score,
            matched_iocs=matched_iocs,
            matched_ttps=list(set(matched_ttps)),
            detector_hits=detector_results,
            fusion_score=final_score,
            recommended_action=action,
            threat_description="; ".join(description_parts) if description_parts else "No significant threats detected"
        )
        
        self.correlation_history.append(threat)
        return threat
    
    def get_threat_summary(self, last_n_minutes: int = 60) -> Dict[str, Any]:
        """Get threat summary statistics for time window"""
        cutoff = datetime.now() - timedelta(minutes=last_n_minutes)
        recent_threats = [t for t in self.correlation_history if t.timestamp >= cutoff]
        
        severity_counts = {s: 0 for s in ThreatSeverity}
        action_counts = {}
        total_iocs = 0
        
        for threat in recent_threats:
            severity_counts[threat.severity] += 1
            action_counts[threat.recommended_action] = action_counts.get(threat.recommended_action, 0) + 1
            total_iocs += len(threat.matched_iocs)
        
        return {
            "time_window_minutes": last_n_minutes,
            "total_threats": len(recent_threats),
            "severity_distribution": {k.value: v for k, v in severity_counts.items()},
            "action_distribution": action_counts,
            "total_iocs_matched": total_iocs,
            "average_confidence": sum(t.confidence for t in recent_threats) / len(recent_threats) if recent_threats else 0.0,
        }


class ThreatIntelligenceFusionManager:
    """
    Main manager class for threat intelligence fusion capabilities.
    This is the public API for this feature expansion.
    """
    
    def __init__(self):
        self.feed_db = ThreatFeedDatabase()
        self.correlation_engine = ThreatCorrelationEngine(self.feed_db)
        self.initialized_at = datetime.now()
    
    def analyze_and_correlate(
        self,
        input_text: str,
        detector_results: Dict[str, float],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Main entry point: analyze input with full threat intelligence fusion
        
        Args:
            input_text: The text content to analyze
            detector_results: Results from existing NeuralShield detectors
            context: Optional context metadata
            
        Returns:
            Dictionary with full correlation results
        """
        correlated = self.correlation_engine.correlate_threats(
            detector_results=detector_results,
            input_text=input_text,
            context=context
        )
        
        return {
            "threat_id": correlated.threat_id,
            "timestamp": correlated.timestamp.isoformat(),
            "severity": correlated.severity.value,
            "confidence_score": correlated.confidence,
            "fusion_score": correlated.fusion_score,
            "recommended_action": correlated.recommended_action,
            "description": correlated.threat_description,
            "matched_iocs_count": len(correlated.matched_iocs),
            "matched_iocs": [
                {
                    "type": i.ioc_type,
                    "value": i.value,
                    "severity": i.severity.value,
                    "confidence": i.confidence,
                    "source": i.source.value,
                }
                for i in correlated.matched_iocs
            ],
            "matched_ttps": correlated.matched_ttps,
            "detector_contributions": correlated.detector_hits,
        }
    
    def add_custom_ioc(
        self,
        ioc_type: str,
        value: str,
        severity: str,
        confidence: float = 0.9,
        description: str = ""
    ) -> bool:
        """Add custom IOC to the threat database"""
        try:
            severity_enum = ThreatSeverity(severity.lower())
            ioc = IOCIndicator(
                ioc_type=ioc_type,
                value=value,
                severity=severity_enum,
                source=ThreatSource.COMMUNITY,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                confidence=confidence,
                description=description
            )
            self.feed_db.add_ioc(ioc)
            return True
        except (ValueError, KeyError):
            return False
    
    def get_threat_dashboard(self, window_minutes: int = 60) -> Dict[str, Any]:
        """Get threat dashboard summary"""
        summary = self.correlation_engine.get_threat_summary(window_minutes)
        summary["engine_uptime_seconds"] = (datetime.now() - self.initialized_at).total_seconds()
        summary["feature"] = "threat_intelligence_fusion_v13"
        summary["dimension"] = "A - Feature Expansion"
        return summary


# Export public API
__all__ = [
    "ThreatIntelligenceFusionManager",
    "ThreatCorrelationEngine",
    "ThreatFeedDatabase",
    "ThreatSeverity",
    "ThreatSource",
    "IOCIndicator",
    "CorrelatedThreat",
]
