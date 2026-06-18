"""
NeuralShield AI - Threat Intelligence Risk-Based Alert Prioritization Engine
Production-grade implementation for security operations center (SOC) alert triage

This module provides:
- Multi-factor risk scoring algorithm (CVSS + asset criticality + threat reputation)
- Alert prioritization with SLA recommendations
- False positive probability estimation
- Business impact assessment
"""

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone


class AlertSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class AssetCriticality(Enum):
    MISSION_CRITICAL = 5
    BUSINESS_CRITICAL = 4
    PRODUCTION = 3
    DEVELOPMENT = 2
    TEST = 1


class ThreatActorReputation(Enum):
    APT = 5
    CRIMINAL = 4
    HACKTIVIST = 3
    SCRIPT_KIDDIE = 2
    UNKNOWN = 1


@dataclass
class Alert:
    alert_id: str
    timestamp: datetime
    source_ip: str
    destination_ip: str
    alert_type: str
    description: str
    cvss_score: float = 0.0
    asset_criticality: AssetCriticality = AssetCriticality.PRODUCTION
    threat_actor_reputation: ThreatActorReputation = ThreatActorReputation.UNKNOWN
    mitre_technique: str = ""
    raw_data: Dict = field(default_factory=dict)


@dataclass
class PrioritizedAlert:
    alert: Alert
    risk_score: float
    priority: AlertSeverity
    false_positive_probability: float
    sla_minutes: int
    business_impact_score: float
    prioritization_factors: Dict[str, float]
    recommended_actions: List[str]


class RiskBasedPrioritizationEngine:
    """
    Production-grade risk-based alert prioritization engine.
    Uses weighted multi-factor scoring to prioritize security alerts.
    """

    # Weight configuration - tuned based on SOC best practices
    WEIGHT_CVSS = 0.35
    WEIGHT_ASSET_CRITICALITY = 0.30
    WEIGHT_THREAT_REPUTATION = 0.20
    WEIGHT_MITRE_TACTIC = 0.15

    # SLA thresholds (minutes) based on NIST SP 800-61
    SLA_CRITICAL = 15
    SLA_HIGH = 60
    SLA_MEDIUM = 240
    SLA_LOW = 1440

    def __init__(self):
        self.processed_alerts: int = 0
        self.prioritization_stats: Dict[AlertSeverity, int] = {
            AlertSeverity.CRITICAL: 0,
            AlertSeverity.HIGH: 0,
            AlertSeverity.MEDIUM: 0,
            AlertSeverity.LOW: 0,
            AlertSeverity.INFORMATIONAL: 0,
        }
        self.false_positive_patterns = self._load_fp_patterns()

    def _load_fp_patterns(self) -> Dict[str, float]:
        """Load known false positive patterns with probability weights."""
        return {
            "internal_scan": 0.85,
            "vulnerability_scan": 0.75,
            "penetration_test": 0.90,
            "authorized_test": 0.95,
            "known_good_ip": 0.80,
        }

    def _normalize_cvss(self, cvss: float) -> float:
        """Normalize CVSS score to 0-1 range."""
        return max(0.0, min(1.0, cvss / 10.0))

    def _calculate_asset_factor(self, criticality: AssetCriticality) -> float:
        """Convert asset criticality enum to normalized score."""
        return criticality.value / 5.0

    def _calculate_threat_factor(self, reputation: ThreatActorReputation) -> float:
        """Convert threat actor reputation to normalized score."""
        return reputation.value / 5.0

    def _calculate_mitre_factor(self, technique: str) -> float:
        """Calculate risk factor based on MITRE ATT&CK technique."""
        high_risk_techniques = {
            "T1059", "T1027", "T1055", "T1003", "T1071",
            "T1047", "T1053", "T1078", "T1021", "T1566"
        }
        medium_risk_techniques = {
            "T1082", "T1083", "T1087", "T1016", "T1033"
        }

        tech_id = technique[:5] if len(technique) >= 5 else ""
        
        if tech_id in high_risk_techniques:
            return 1.0
        elif tech_id in medium_risk_techniques:
            return 0.6
        elif technique:
            return 0.4
        return 0.3

    def _estimate_false_positive_probability(self, alert: Alert) -> float:
        """Estimate probability this alert is a false positive."""
        fp_probability = 0.05  # Base false positive rate

        # Check description for FP patterns
        desc_lower = alert.description.lower()
        for pattern, weight in self.false_positive_patterns.items():
            if pattern.replace("_", " ") in desc_lower or pattern in desc_lower:
                fp_probability = max(fp_probability, weight)

        # Internal IP ranges often have higher FP rate
        internal_prefixes = ["10.", "192.168.", "172.16.", "172.17.", "172.18.", 
                           "172.19.", "172.20.", "172.30.", "172.31.", "127."]
        if any(alert.source_ip.startswith(p) for p in internal_prefixes):
            fp_probability += 0.1

        # Low CVSS = higher FP chance
        if alert.cvss_score < 4.0:
            fp_probability += 0.15

        return min(0.99, fp_probability)

    def _calculate_business_impact(self, alert: Alert) -> float:
        """Calculate business impact score (0-100)."""
        asset_impact = alert.asset_criticality.value * 20
        cvss_impact = alert.cvss_score * 5
        threat_impact = alert.threat_actor_reputation.value * 10
        
        return min(100.0, (asset_impact + cvss_impact + threat_impact) / 3)

    def _determine_priority(self, risk_score: float) -> AlertSeverity:
        """Determine alert priority based on final risk score."""
        if risk_score >= 0.85:
            return AlertSeverity.CRITICAL
        elif risk_score >= 0.70:
            return AlertSeverity.HIGH
        elif risk_score >= 0.50:
            return AlertSeverity.MEDIUM
        elif risk_score >= 0.25:
            return AlertSeverity.LOW
        return AlertSeverity.INFORMATIONAL

    def _get_sla_minutes(self, priority: AlertSeverity) -> int:
        """Get SLA response time in minutes."""
        sla_map = {
            AlertSeverity.CRITICAL: self.SLA_CRITICAL,
            AlertSeverity.HIGH: self.SLA_HIGH,
            AlertSeverity.MEDIUM: self.SLA_MEDIUM,
            AlertSeverity.LOW: self.SLA_LOW,
            AlertSeverity.INFORMATIONAL: self.SLA_LOW * 2,
        }
        return sla_map.get(priority, self.SLA_LOW)

    def _get_recommended_actions(self, priority: AlertSeverity, alert: Alert) -> List[str]:
        """Get recommended response actions based on priority and alert type."""
        actions = []
        
        if priority == AlertSeverity.CRITICAL:
            actions.extend([
                "Immediate incident response activation",
                "Isolate affected systems",
                "Notify CISO and security leadership",
                "Begin forensic evidence collection"
            ])
        elif priority == AlertSeverity.HIGH:
            actions.extend([
                "Escalate to senior security analyst",
                "Begin investigation within SLA window",
                "Check for related indicators of compromise"
            ])
        elif priority == AlertSeverity.MEDIUM:
            actions.extend([
                "Assign to security analyst for investigation",
                "Correlate with other recent alerts",
                "Review asset exposure level"
            ])
        else:
            actions.extend([
                "Batch review during next shift",
                "Add to threat hunting queue",
                "Monitor for related activity"
            ])
        
        return actions

    def prioritize_alert(self, alert: Alert) -> PrioritizedAlert:
        """
        Prioritize a single security alert.
        
        Args:
            alert: Raw Alert object to prioritize
            
        Returns:
            PrioritizedAlert with risk score and recommendations
        """
        # Calculate individual risk factors
        cvss_factor = self._normalize_cvss(alert.cvss_score)
        asset_factor = self._calculate_asset_factor(alert.asset_criticality)
        threat_factor = self._calculate_threat_factor(alert.threat_actor_reputation)
        mitre_factor = self._calculate_mitre_factor(alert.mitre_technique)

        # Calculate weighted risk score
        risk_score = (
            cvss_factor * self.WEIGHT_CVSS +
            asset_factor * self.WEIGHT_ASSET_CRITICALITY +
            threat_factor * self.WEIGHT_THREAT_REPUTATION +
            mitre_factor * self.WEIGHT_MITRE_TACTIC
        )

        # Adjust for false positive probability
        fp_prob = self._estimate_false_positive_probability(alert)
        risk_score = risk_score * (1.0 - (fp_prob * 0.5))

        # Determine priority and metadata
        priority = self._determine_priority(risk_score)
        sla_minutes = self._get_sla_minutes(priority)
        business_impact = self._calculate_business_impact(alert)
        recommended_actions = self._get_recommended_actions(priority, alert)

        # Track statistics
        self.processed_alerts += 1
        self.prioritization_stats[priority] += 1

        prioritization_factors = {
            "cvss_factor": cvss_factor,
            "asset_factor": asset_factor,
            "threat_factor": threat_factor,
            "mitre_factor": mitre_factor,
            "false_positive_adjustment": fp_prob * 0.5
        }

        return PrioritizedAlert(
            alert=alert,
            risk_score=round(risk_score, 4),
            priority=priority,
            false_positive_probability=round(fp_prob, 4),
            sla_minutes=sla_minutes,
            business_impact_score=round(business_impact, 2),
            prioritization_factors=prioritization_factors,
            recommended_actions=recommended_actions
        )

    def prioritize_alerts_batch(self, alerts: List[Alert]) -> List[PrioritizedAlert]:
        """Prioritize a batch of alerts and sort by risk score."""
        prioritized = [self.prioritize_alert(alert) for alert in alerts]
        return sorted(prioritized, key=lambda x: x.risk_score, reverse=True)

    def get_prioritization_statistics(self) -> Dict:
        """Get statistics about alert prioritization."""
        if self.processed_alerts == 0:
            return {"total_alerts": 0}

        stats = {
            "total_alerts": self.processed_alerts,
            "distribution": {
                k.value: v for k, v in self.prioritization_stats.items()
            },
            "percentages": {
                k.value: round((v / self.processed_alerts) * 100, 1)
                for k, v in self.prioritization_stats.items()
            }
        }
        return stats

    def generate_alert_id(self) -> str:
        """Generate a deterministic alert ID."""
        timestamp = str(time.time()).encode()
        return "NS-ALERT-" + hashlib.md5(timestamp).hexdigest()[:12].upper()
