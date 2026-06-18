"""
Threat Intelligence Automated Triage & Prioritization Engine
Production-Grade Implementation - June 19, 2026

This module provides automated threat triage and prioritization capabilities:
- Multi-dimensional risk scoring (CVSS, MITRE, business impact)
- SLA-based escalation recommendations
- Automated severity classification
- Triage queue management
- False positive probability assessment
"""

import re
import hashlib
import time
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from collections import defaultdict


class ThreatSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class SLALevel(Enum):
    IMMEDIATE = "IMMEDIATE"  # 15 minutes
    URGENT = "URGENT"        # 1 hour
    STANDARD = "STANDARD"    # 4 hours
    NORMAL = "NORMAL"        # 24 hours
    LOW = "LOW"              # 72 hours


class TriageStatus(Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    ESCALATED = "ESCALATED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


@dataclass
class ThreatIndicator:
    indicator_type: str  # ip, domain, hash, url, email
    value: str
    first_seen: datetime
    last_seen: datetime
    confidence: float  # 0.0 - 1.0
    source: str
    threat_types: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TriageResult:
    threat_id: str
    final_severity: ThreatSeverity
    priority_score: float  # 0.0 - 100.0
    sla_level: SLALevel
    escalation_recommended: bool
    false_positive_probability: float  # 0.0 - 1.0
    risk_factors: List[str]
    mitigating_factors: List[str]
    triage_timestamp: datetime
    status: TriageStatus
    recommended_actions: List[str] = field(default_factory=list)
    assignee: Optional[str] = None


class MITREAttackWeights:
    """MITRE ATT&CK technique severity weights based on real-world impact."""
    
    TECHNIQUE_WEIGHTS = {
        "T1059": 85,   # Command and Scripting Interpreter
        "T1053": 90,   # Scheduled Task/Job
        "T1027": 80,   # Obfuscated Files or Information
        "T1055": 95,   # Process Injection
        "T1003": 95,   # Credential Dumping
        "T1071": 75,   # Application Layer Protocol
        "T1078": 90,   # Valid Accounts
        "T1083": 70,   # File and Directory Discovery
        "T1082": 75,   # System Information Discovery
        "T1046": 80,   # Network Service Scanning
        "T1047": 85,   # Windows Management Instrumentation
        "T1057": 70,   # Process Discovery
        "T1012": 65,   # Query Registry
        "T1069": 80,   # Permission Groups Discovery
        "T1018": 75,   # Remote System Discovery
        "T1033": 70,   # System Owner/User Discovery
        "T1007": 65,   # System Service Discovery
        "T1124": 60,   # System Time Discovery
        "T1518": 70,   # Software Discovery
        "T1087": 75,   # Account Discovery
    }
    
    TACTIC_WEIGHTS = {
        "initial-access": 85,
        "execution": 90,
        "persistence": 85,
        "privilege-escalation": 95,
        "defense-evasion": 90,
        "credential-access": 95,
        "discovery": 70,
        "lateral-movement": 90,
        "collection": 85,
        "command-and-control": 85,
        "exfiltration": 95,
        "impact": 95,
    }


class ThreatIntelligenceTriageEngine:
    """
    Automated Threat Triage & Prioritization Engine
    
    Features:
    - Multi-dimensional risk scoring
    - MITRE ATT&CK weighted prioritization
    - CVSS score integration
    - False positive probability analysis
    - SLA-based escalation
    - Triage queue management
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._default_config()
        self.triage_history: Dict[str, TriageResult] = {}
        self.triage_queue: List[str] = []
        self.mitre_weights = MITREAttackWeights()
        self.severity_thresholds = self.config["severity_thresholds"]
        self.sla_rules = self.config["sla_rules"]
        
    def _default_config(self) -> Dict[str, Any]:
        return {
            "severity_thresholds": {
                "CRITICAL": 85.0,
                "HIGH": 70.0,
                "MEDIUM": 50.0,
                "LOW": 25.0,
            },
            "sla_rules": {
                "CRITICAL": SLALevel.IMMEDIATE,
                "HIGH": SLALevel.URGENT,
                "MEDIUM": SLALevel.STANDARD,
                "LOW": SLALevel.NORMAL,
                "INFORMATIONAL": SLALevel.LOW,
            },
            "false_positive_indicators": [
                r"test", r"demo", r"sample", r"example",
                r"localhost", r"127\.0\.0\.1", r"192\.168\.",
                r"10\.", r"172\.(1[6-9]|2[0-9]|3[0-1])\.",
            ],
            "weight_factors": {
                "cvss": 0.30,
                "mitre": 0.25,
                "confidence": 0.20,
                "business_impact": 0.15,
                "timeliness": 0.10,
            },
            "business_asset_criticality": {
                "domain_controller": 100,
                "database_server": 95,
                "email_server": 90,
                "web_server": 80,
                "workstation": 60,
                "iot_device": 40,
            }
        }
    
    def generate_threat_id(self, threat_data: Dict[str, Any]) -> str:
        """Generate deterministic threat ID."""
        content = json.dumps(threat_data, sort_keys=True)
        return f"THREAT-{hashlib.sha256(content.encode()).hexdigest()[:16].upper()}"
    
    def calculate_cvss_score(self, cvss_data: Dict[str, Any]) -> float:
        """Calculate normalized CVSS score (0-100 scale)."""
        base_score = cvss_data.get("base_score", 5.0)
        return min(100.0, (base_score / 10.0) * 100.0)
    
    def calculate_mitre_score(self, mitre_data: Dict[str, Any]) -> float:
        """Calculate MITRE ATT&CK based score."""
        techniques = mitre_data.get("techniques", [])
        tactics = mitre_data.get("tactics", [])
        
        if not techniques and not tactics:
            return 50.0  # Default neutral score
        
        technique_scores = []
        for tech in techniques:
            tech_id = tech[:5] if isinstance(tech, str) else str(tech)[:5]
            technique_scores.append(
                self.mitre_weights.TECHNIQUE_WEIGHTS.get(tech_id, 60)
            )
        
        tactic_scores = []
        for tactic in tactics:
            tactic_scores.append(
                self.mitre_weights.TACTIC_WEIGHTS.get(tactic.lower(), 60)
            )
        
        all_scores = technique_scores + tactic_scores
        return sum(all_scores) / len(all_scores) if all_scores else 50.0
    
    def calculate_confidence_score(self, threat_data: Dict[str, Any]) -> float:
        """Calculate confidence score based on source quality."""
        source_confidence = {
            "virustotal": 95,
            "alienvault": 90,
            "ibm_xforce": 90,
            "mandiant": 95,
            "fireeye": 95,
            "crowdstrike": 95,
            "internal_sensor": 85,
            "user_report": 60,
            "open_source": 70,
        }
        
        source = threat_data.get("source", "open_source").lower()
        base_confidence = source_confidence.get(source, 65)
        
        # Adjust based on number of sources
        num_sources = threat_data.get("num_sources", 1)
        source_multiplier = min(1.2, 0.8 + (num_sources * 0.1))
        
        return min(100.0, base_confidence * source_multiplier)
    
    def calculate_business_impact_score(self, threat_data: Dict[str, Any]) -> float:
        """Calculate business impact based on affected assets."""
        affected_assets = threat_data.get("affected_assets", [])
        if not affected_assets:
            return 50.0  # Default medium impact
        
        asset_scores = []
        for asset in affected_assets:
            asset_type = asset.get("type", "workstation").lower()
            asset_scores.append(
                self.config["business_asset_criticality"].get(asset_type, 50)
            )
        
        return max(asset_scores) if asset_scores else 50.0
    
    def calculate_timeliness_score(self, threat_data: Dict[str, Any]) -> float:
        """Calculate timeliness score - newer threats get higher priority."""
        first_seen = threat_data.get("first_seen")
        if not first_seen:
            return 70.0
        
        if isinstance(first_seen, str):
            try:
                first_seen = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
            except:
                return 70.0
        
        age_hours = (datetime.now() - first_seen).total_seconds() / 3600
        
        # Newer threats = higher score
        if age_hours < 1:
            return 100.0
        elif age_hours < 6:
            return 90.0
        elif age_hours < 24:
            return 80.0
        elif age_hours < 72:
            return 60.0
        else:
            return 40.0
    
    def calculate_false_positive_probability(self, threat_data: Dict[str, Any]) -> float:
        """Calculate probability this is a false positive (0.0 = real, 1.0 = false positive)."""
        fp_score = 0.0
        indicators = threat_data.get("indicators", [])
        threat_desc = json.dumps(threat_data).lower()
        
        # Check for common false positive patterns
        for pattern in self.config["false_positive_indicators"]:
            if re.search(pattern, threat_desc, re.IGNORECASE):
                fp_score += 0.15
        
        # Low confidence sources
        source = threat_data.get("source", "").lower()
        if source in ["user_report", "open_source"]:
            fp_score += 0.10
        
        # Single source = higher FP chance
        if threat_data.get("num_sources", 1) == 1:
            fp_score += 0.10
        
        # No affected assets = higher FP chance
        if not threat_data.get("affected_assets"):
            fp_score += 0.15
        
        return min(1.0, fp_score)
    
    def determine_severity(self, priority_score: float) -> ThreatSeverity:
        """Determine severity level from priority score."""
        thresholds = self.severity_thresholds
        if priority_score >= thresholds["CRITICAL"]:
            return ThreatSeverity.CRITICAL
        elif priority_score >= thresholds["HIGH"]:
            return ThreatSeverity.HIGH
        elif priority_score >= thresholds["MEDIUM"]:
            return ThreatSeverity.MEDIUM
        elif priority_score >= thresholds["LOW"]:
            return ThreatSeverity.LOW
        else:
            return ThreatSeverity.INFORMATIONAL
    
    def determine_sla(self, severity: ThreatSeverity) -> SLALevel:
        """Determine SLA level based on severity."""
        return self.sla_rules.get(severity.value, SLALevel.NORMAL)
    
    def generate_recommendations(
        self, 
        severity: ThreatSeverity, 
        threat_data: Dict[str, Any]
    ) -> List[str]:
        """Generate actionable recommendations based on triage results."""
        recommendations = []
        
        if severity == ThreatSeverity.CRITICAL:
            recommendations.extend([
                "Immediate security team notification required",
                "Initiate incident response procedures",
                "Isolate affected systems immediately",
                "Begin forensic evidence collection",
                "Executive notification required within 1 hour",
            ])
        elif severity == ThreatSeverity.HIGH:
            recommendations.extend([
                "Escalate to senior security analyst",
                "Begin immediate investigation",
                "Block IOCs at perimeter security devices",
                "Monitor affected systems for lateral movement",
            ])
        elif severity == ThreatSeverity.MEDIUM:
            recommendations.extend([
                "Assign to security analyst for investigation",
                "Add IOCs to monitoring watchlist",
                "Review related alerts for correlation",
            ])
        elif severity == ThreatSeverity.LOW:
            recommendations.extend([
                "Add to routine security review queue",
                "Monitor for related activity",
                "Update threat intelligence feeds",
            ])
        else:
            recommendations.extend([
                "Log for historical tracking",
                "No immediate action required",
            ])
        
        # Add specific mitigations based on threat type
        threat_types = threat_data.get("threat_types", [])
        if "ransomware" in threat_types:
            recommendations.append("Verify backup integrity and offline status")
        if "phishing" in threat_types:
            recommendations.append("Notify email security team for blocking")
        if "data_exfiltration" in threat_types:
            recommendations.append("Review data loss prevention alerts")
        
        return recommendations
    
    def triage_threat(self, threat_data: Dict[str, Any]) -> TriageResult:
        """
        Main triage function - performs full automated triage of a threat.
        
        Returns comprehensive TriageResult with priority score, severity,
        SLA requirements, escalation recommendations, and false positive assessment.
        """
        threat_id = self.generate_threat_id(threat_data)
        
        # Calculate component scores
        weights = self.config["weight_factors"]
        
        cvss_score = self.calculate_cvss_score(threat_data.get("cvss", {}))
        mitre_score = self.calculate_mitre_score(threat_data.get("mitre", {}))
        confidence_score = self.calculate_confidence_score(threat_data)
        business_impact_score = self.calculate_business_impact_score(threat_data)
        timeliness_score = self.calculate_timeliness_score(threat_data)
        
        # Calculate weighted final priority score
        priority_score = (
            (cvss_score * weights["cvss"]) +
            (mitre_score * weights["mitre"]) +
            (confidence_score * weights["confidence"]) +
            (business_impact_score * weights["business_impact"]) +
            (timeliness_score * weights["timeliness"])
        )
        
        # Adjust for false positive probability
        fp_probability = self.calculate_false_positive_probability(threat_data)
        priority_score = priority_score * (1.0 - (fp_probability * 0.5))
        
        # Determine severity and SLA
        severity = self.determine_severity(priority_score)
        sla_level = self.determine_sla(severity)
        
        # Determine escalation need
        escalation_needed = (
            severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH] 
            and fp_probability < 0.3
        )
        
        # Build risk and mitigating factors
        risk_factors = []
        mitigating_factors = []
        
        if cvss_score > 80:
            risk_factors.append(f"High CVSS score ({cvss_score:.1f})")
        if mitre_score > 80:
            risk_factors.append(f"High MITRE ATT&CK impact ({mitre_score:.1f})")
        if business_impact_score > 80:
            risk_factors.append("Critical business assets affected")
        if timeliness_score > 85:
            risk_factors.append("Recently observed threat")
        
        if fp_probability > 0.3:
            mitigating_factors.append(f"High false positive probability ({fp_probability:.1%})")
        if confidence_score < 50:
            mitigating_factors.append("Low threat intelligence confidence")
        if threat_data.get("num_sources", 1) == 1:
            mitigating_factors.append("Single source only")
        
        # Generate recommendations
        recommendations = self.generate_recommendations(severity, threat_data)
        
        triage_result = TriageResult(
            threat_id=threat_id,
            final_severity=severity,
            priority_score=round(priority_score, 2),
            sla_level=sla_level,
            escalation_recommended=escalation_needed,
            false_positive_probability=round(fp_probability, 3),
            risk_factors=risk_factors,
            mitigating_factors=mitigating_factors,
            triage_timestamp=datetime.now(),
            status=TriageStatus.TRIAGED,
            recommended_actions=recommendations,
        )
        
        # Store in history and queue
        self.triage_history[threat_id] = triage_result
        if escalation_needed:
            self.triage_queue.insert(0, threat_id)
        else:
            self.triage_queue.append(threat_id)
        
        return triage_result
    
    def batch_triage(self, threat_list: List[Dict[str, Any]]) -> List[TriageResult]:
        """Process multiple threats in batch."""
        return [self.triage_threat(threat) for threat in threat_list]
    
    def get_triage_queue(self, severity_filter: Optional[ThreatSeverity] = None) -> List[TriageResult]:
        """Get prioritized triage queue, optionally filtered by severity."""
        results = [
            self.triage_history[tid] for tid in self.triage_queue
            if tid in self.triage_history
        ]
        
        if severity_filter:
            results = [r for r in results if r.final_severity == severity_filter]
        
        # Sort by priority score descending
        return sorted(results, key=lambda x: x.priority_score, reverse=True)
    
    def get_triage_statistics(self) -> Dict[str, Any]:
        """Get triage statistics and metrics."""
        all_results = list(self.triage_history.values())
        
        severity_counts = defaultdict(int)
        for result in all_results:
            severity_counts[result.final_severity.value] += 1
        
        escalation_count = sum(1 for r in all_results if r.escalation_recommended)
        
        return {
            "total_triaged": len(all_results),
            "severity_distribution": dict(severity_counts),
            "escalation_rate": escalation_count / len(all_results) if all_results else 0,
            "average_priority_score": (
                sum(r.priority_score for r in all_results) / len(all_results) 
                if all_results else 0
            ),
            "average_false_positive_probability": (
                sum(r.false_positive_probability for r in all_results) / len(all_results)
                if all_results else 0
            ),
            "queue_length": len(self.triage_queue),
            "triage_timestamp": datetime.now().isoformat(),
        }
    
    def update_triage_status(
        self, 
        threat_id: str, 
        new_status: TriageStatus,
        analyst_notes: Optional[str] = None
    ) -> bool:
        """Update triage status (analyst override)."""
        if threat_id not in self.triage_history:
            return False
        
        self.triage_history[threat_id].status = new_status
        
        # Remove from queue if resolved or false positive
        if new_status in [TriageStatus.RESOLVED, TriageStatus.FALSE_POSITIVE]:
            if threat_id in self.triage_queue:
                self.triage_queue.remove(threat_id)
        
        return True
