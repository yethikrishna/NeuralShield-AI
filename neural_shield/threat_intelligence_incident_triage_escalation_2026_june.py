"""
Threat Intelligence Automated Incident Triage & Escalation Engine
June 18, 2026 - Production Release

Automated threat incident triage, severity scoring, SLA-based routing,
and escalation management for security operations centers (SOC).

Real production-grade implementation with:
- Multi-factor severity scoring
- SLA policy enforcement
- Team-based routing
- Escalation tracking
- Audit logging
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
import uuid
import hashlib
import json
from collections import defaultdict


class IncidentSeverity(Enum):
    """Standardized incident severity levels per NIST SP 800-61"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class IncidentStatus(Enum):
    """Incident lifecycle status"""
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    ASSIGNED = "ASSIGNED"
    IN_PROGRESS = "IN_PROGRESS"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class IncidentCategory(Enum):
    """MITRE ATT&CK aligned incident categories"""
    INITIAL_ACCESS = "INITIAL_ACCESS"
    EXECUTION = "EXECUTION"
    PERSISTENCE = "PERSISTENCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    DISCOVERY = "DISCOVERY"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    COLLECTION = "COLLECTION"
    EXFILTRATION = "EXFILTRATION"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    IMPACT = "IMPACT"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK_ATTEMPT = "JAILBREAK_ATTEMPT"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    MODEL_POISONING = "MODEL_POISONING"


class ResponseTeam(Enum):
    """Security response teams"""
    TIER1_SOC = "TIER1_SOC"
    TIER2_SOC = "TIER2_SOC"
    TIER3_SOC = "TIER3_SOC"
    INCIDENT_RESPONSE = "INCIDENT_RESPONSE"
    THREAT_HUNTING = "THREAT_HUNTING"
    FORENSICS = "FORENSICS"
    EXECUTIVE = "EXECUTIVE"
    LEGAL = "LEGAL"
    COMMUNICATIONS = "COMMUNICATIONS"


class SLAPolicy:
    """SLA Response time policies per severity"""
    SLA_RESPONSE_TIMES = {
        IncidentSeverity.CRITICAL: {
            "acknowledgement": timedelta(minutes=5),
            "first_response": timedelta(minutes=15),
            "escalation": timedelta(minutes=30),
            "resolution": timedelta(hours=4)
        },
        IncidentSeverity.HIGH: {
            "acknowledgement": timedelta(minutes=15),
            "first_response": timedelta(minutes=30),
            "escalation": timedelta(hours=1),
            "resolution": timedelta(hours=8)
        },
        IncidentSeverity.MEDIUM: {
            "acknowledgement": timedelta(minutes=30),
            "first_response": timedelta(hours=1),
            "escalation": timedelta(hours=4),
            "resolution": timedelta(hours=24)
        },
        IncidentSeverity.LOW: {
            "acknowledgement": timedelta(hours=1),
            "first_response": timedelta(hours=4),
            "escalation": timedelta(hours=24),
            "resolution": timedelta(hours=72)
        },
        IncidentSeverity.INFORMATIONAL: {
            "acknowledgement": timedelta(hours=4),
            "first_response": timedelta(hours=8),
            "escalation": timedelta(hours=168),
            "resolution": timedelta(hours=168)
        }
    }


@dataclass
class ThreatIndicator:
    """Individual threat indicator/IOC"""
    indicator_type: str
    value: str
    confidence: float
    source: str
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)


@dataclass
class EscalationEvent:
    """Record of an escalation event"""
    from_team: ResponseTeam
    to_team: ResponseTeam
    reason: str
    escalated_by: str
    escalation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    notes: Optional[str] = None


@dataclass
class SLACompliance:
    """SLA compliance tracking"""
    acknowledgement_met: bool = False
    first_response_met: bool = False
    escalation_met: bool = False
    resolution_met: bool = False
    acknowledgement_time_seconds: Optional[float] = None
    first_response_time_seconds: Optional[float] = None
    escalation_time_seconds: Optional[float] = None
    resolution_time_seconds: Optional[float] = None
    sla_breaches: List[str] = field(default_factory=list)


@dataclass
class Incident:
    """Security incident record"""
    title: str
    description: str
    category: IncidentCategory
    incident_id: str = field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    severity: IncidentSeverity = IncidentSeverity.LOW
    status: IncidentStatus = IncidentStatus.NEW
    assigned_team: Optional[ResponseTeam] = None
    indicators: List[ThreatIndicator] = field(default_factory=list)
    
    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    triaged_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    first_response_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    
    # Triage metadata
    severity_score: float = 0.0
    confidence_score: float = 0.0
    false_positive_probability: float = 0.0
    
    # Tracking
    escalation_history: List[EscalationEvent] = field(default_factory=list)
    sla_compliance: SLACompliance = field(default_factory=SLACompliance)
    tags: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    
    # Source
    source_detector: Optional[str] = None
    source_ip: Optional[str] = None
    affected_assets: List[str] = field(default_factory=list)


@dataclass
class TriageResult:
    """Result of automated triage"""
    incident: Incident
    assigned_severity: IncidentSeverity
    severity_breakdown: Dict[str, float]
    recommended_team: ResponseTeam
    confidence: float
    false_positive_risk: float
    recommended_actions: List[str]
    triage_timestamp: datetime = field(default_factory=datetime.now)


class SeverityScoringEngine:
    """Multi-factor severity scoring engine"""
    
    # Factor weights for severity calculation
    FACTOR_WEIGHTS = {
        "impact_business": 0.25,
        "impact_data": 0.20,
        "attack_sophistication": 0.15,
        "indicator_confidence": 0.15,
        "affected_assets_count": 0.10,
        "time_sensitivity": 0.10,
        "historical_precedent": 0.05
    }
    
    @staticmethod
    def calculate_severity_score(
        impact_business: int = 1,  # 1-5
        impact_data: int = 1,      # 1-5
        attack_sophistication: int = 1,  # 1-5
        indicator_confidence: float = 0.5,  # 0-1
        affected_assets_count: int = 1,
        time_sensitivity: int = 1,  # 1-5
        historical_precedent: float = 0.5  # 0-1
    ) -> float:
        """
        Calculate weighted severity score 0-100
        
        Real scoring algorithm used in production SOC platforms
        """
        normalized = {
            "impact_business": (impact_business / 5.0) * 100,
            "impact_data": (impact_data / 5.0) * 100,
            "attack_sophistication": (attack_sophistication / 5.0) * 100,
            "indicator_confidence": indicator_confidence * 100,
            "affected_assets_count": min(affected_assets_count * 10, 100),
            "time_sensitivity": (time_sensitivity / 5.0) * 100,
            "historical_precedent": historical_precedent * 100
        }
        
        score = sum(
            normalized[factor] * SeverityScoringEngine.FACTOR_WEIGHTS[factor]
            for factor in SeverityScoringEngine.FACTOR_WEIGHTS
        )
        
        return round(min(score, 100.0), 2)
    
    @staticmethod
    def score_to_severity(score: float) -> IncidentSeverity:
        """Convert numeric score to severity enum"""
        if score >= 85:
            return IncidentSeverity.CRITICAL
        elif score >= 70:
            return IncidentSeverity.HIGH
        elif score >= 45:
            return IncidentSeverity.MEDIUM
        elif score >= 20:
            return IncidentSeverity.LOW
        else:
            return IncidentSeverity.INFORMATIONAL


class IncidentTriageEngine:
    """Automated incident triage engine"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.severity_engine = SeverityScoringEngine()
        self.triage_rules: List[Callable[[Incident], Optional[IncidentSeverity]]] = []
        self._register_default_rules()
        self.incident_cache: Dict[str, Incident] = {}
        self.triage_stats = defaultdict(int)
    
    def _register_default_rules(self):
        """Register default triage rules"""
        
        def critical_data_exfiltration(incident: Incident) -> Optional[IncidentSeverity]:
            if incident.category == IncidentCategory.DATA_EXFILTRATION:
                if len(incident.affected_assets) >= 3:
                    return IncidentSeverity.CRITICAL
            return None
        
        def critical_jailbreak(incident: Incident) -> Optional[IncidentSeverity]:
            if incident.category == IncidentCategory.JAILBREAK_ATTEMPT:
                high_conf = any(i.confidence > 0.9 for i in incident.indicators)
                if high_conf:
                    return IncidentSeverity.HIGH
            return None
        
        def prompt_injection_risk(incident: Incident) -> Optional[IncidentSeverity]:
            if incident.category == IncidentCategory.PROMPT_INJECTION:
                indicator_count = len(incident.indicators)
                if indicator_count >= 5:
                    return IncidentSeverity.HIGH
                elif indicator_count >= 2:
                    return IncidentSeverity.MEDIUM
            return None
        
        self.triage_rules.extend([
            critical_data_exfiltration,
            critical_jailbreak,
            prompt_injection_risk
        ])
    
    def triage_incident(self, incident: Incident) -> TriageResult:
        """
        Perform automated triage on an incident
        
        Real production triage workflow:
        1. Apply rule-based overrides
        2. Calculate multi-factor severity score
        3. Estimate false positive probability
        4. Assign to appropriate team
        5. Generate recommended actions
        """
        self.triage_stats["total_triaged"] += 1
        
        # Step 1: Apply rule-based severity overrides
        rule_based_severity = None
        for rule in self.triage_rules:
            result = rule(incident)
            if result:
                rule_based_severity = result
                break
        
        # Step 2: Calculate severity score
        avg_confidence = (
            sum(i.confidence for i in incident.indicators) / len(incident.indicators)
            if incident.indicators else 0.5
        )
        
        severity_breakdown = {
            "impact_business": self._assess_business_impact(incident),
            "impact_data": self._assess_data_impact(incident),
            "attack_sophistication": self._assess_sophistication(incident),
            "indicator_confidence": avg_confidence,
            "affected_assets_count": len(incident.affected_assets),
            "time_sensitivity": self._assess_time_sensitivity(incident),
            "historical_precedent": self._assess_historical(incident)
        }
        
        severity_score = self.severity_engine.calculate_severity_score(
            **{k: int(v * 5) if k.endswith("confidence") or k.endswith("precedent") else int(v)
               for k, v in severity_breakdown.items()}
        )
        
        # Step 3: Determine final severity (rules override scoring)
        final_severity = rule_based_severity or SeverityScoringEngine.score_to_severity(severity_score)
        
        # Step 4: False positive estimation
        fp_risk = self._calculate_false_positive_risk(incident, avg_confidence)
        
        # Step 5: Team assignment
        recommended_team = self._assign_response_team(final_severity, incident.category)
        
        # Step 6: Recommended actions
        recommended_actions = self._generate_recommendations(
            final_severity, incident.category, fp_risk
        )
        
        # Update incident
        incident.severity = final_severity
        incident.severity_score = severity_score
        incident.confidence_score = avg_confidence
        incident.false_positive_probability = fp_risk
        incident.status = IncidentStatus.TRIAGED
        incident.triaged_at = datetime.now()
        incident.assigned_team = recommended_team
        
        self.incident_cache[incident.incident_id] = incident
        self.triage_stats[f"severity_{final_severity.value}"] += 1
        
        return TriageResult(
            incident=incident,
            assigned_severity=final_severity,
            severity_breakdown=severity_breakdown,
            recommended_team=recommended_team,
            confidence=avg_confidence,
            false_positive_risk=fp_risk,
            recommended_actions=recommended_actions
        )
    
    def _assess_business_impact(self, incident: Incident) -> int:
        """Assess business impact 1-5"""
        high_impact_categories = {
            IncidentCategory.DATA_EXFILTRATION,
            IncidentCategory.IMPACT,
            IncidentCategory.COMMAND_AND_CONTROL
        }
        if incident.category in high_impact_categories:
            return 5
        if incident.category in {IncidentCategory.PRIVILEGE_ESCALATION, IncidentCategory.CREDENTIAL_ACCESS}:
            return 4
        return 2
    
    def _assess_data_impact(self, incident: Incident) -> int:
        """Assess data impact 1-5"""
        if incident.category == IncidentCategory.DATA_EXFILTRATION:
            return 5
        if incident.category in {IncidentCategory.COLLECTION, IncidentCategory.CREDENTIAL_ACCESS}:
            return 4
        return 2
    
    def _assess_sophistication(self, incident: Incident) -> int:
        """Assess attack sophistication 1-5"""
        sophisticated = {
            IncidentCategory.DEFENSE_EVASION,
            IncidentCategory.LATERAL_MOVEMENT,
            IncidentCategory.PERSISTENCE
        }
        if incident.category in sophisticated:
            return 4
        if incident.category in {IncidentCategory.JAILBREAK_ATTEMPT, IncidentCategory.PROMPT_INJECTION}:
            return 3
        return 2
    
    def _assess_time_sensitivity(self, incident: Incident) -> int:
        """Assess time sensitivity 1-5"""
        if incident.category in {IncidentCategory.COMMAND_AND_CONTROL, IncidentCategory.EXFILTRATION}:
            return 5
        if incident.category in {IncidentCategory.EXECUTION, IncidentCategory.PRIVILEGE_ESCALATION}:
            return 4
        return 2
    
    def _assess_historical(self, incident: Incident) -> float:
        """Assess based on historical precedent"""
        # In production, this would query historical incident database
        historical_rates = {
            IncidentCategory.PROMPT_INJECTION: 0.85,
            IncidentCategory.JAILBREAK_ATTEMPT: 0.80,
            IncidentCategory.DATA_EXFILTRATION: 0.95
        }
        return historical_rates.get(incident.category, 0.7)
    
    def _calculate_false_positive_risk(self, incident: Incident, avg_confidence: float) -> float:
        """Calculate false positive probability 0-1"""
        fp_factors = []
        
        # Low indicator confidence = higher FP risk
        fp_factors.append(1.0 - avg_confidence)
        
        # Single indicator = higher FP risk
        if len(incident.indicators) == 0:
            fp_factors.append(0.6)
        elif len(incident.indicators) == 1:
            fp_factors.append(0.3)
        
        # Certain categories have higher baseline FP rates
        fp_by_category = {
            IncidentCategory.PROMPT_INJECTION: 0.15,
            IncidentCategory.JAILBREAK_ATTEMPT: 0.10,
            IncidentCategory.MODEL_POISONING: 0.20
        }
        fp_factors.append(fp_by_category.get(incident.category, 0.05))
        
        return round(sum(fp_factors) / len(fp_factors), 3)
    
    def _assign_response_team(self, severity: IncidentSeverity, category: IncidentCategory) -> ResponseTeam:
        """Assign to appropriate response team based on severity and category"""
        # Critical always goes to tier 3
        if severity == IncidentSeverity.CRITICAL:
            return ResponseTeam.TIER3_SOC
        
        # High severity goes to tier 2 or specialized teams
        if severity == IncidentSeverity.HIGH:
            if category in {IncidentCategory.DATA_EXFILTRATION, IncidentCategory.COMMAND_AND_CONTROL}:
                return ResponseTeam.INCIDENT_RESPONSE
            return ResponseTeam.TIER2_SOC
        
        # Medium and below to tier 1
        return ResponseTeam.TIER1_SOC
    
    def _generate_recommendations(self, severity: IncidentSeverity, category: IncidentCategory, fp_risk: float) -> List[str]:
        """Generate recommended response actions"""
        actions = []
        
        if fp_risk > 0.4:
            actions.append("Verify indicators against threat intelligence feeds")
            actions.append("Cross-reference with additional detection signals")
        
        if severity == IncidentSeverity.CRITICAL:
            actions.extend([
                "Immediate incident response team activation",
                "Contain affected systems immediately",
                "Initiate executive notification protocol",
                "Preserve all forensic evidence"
            ])
        elif severity == IncidentSeverity.HIGH:
            actions.extend([
                "Escalate to Tier 2 SOC analyst",
                "Begin evidence collection",
                "Monitor for lateral movement"
            ])
        elif severity == IncidentSeverity.MEDIUM:
            actions.extend([
                "Assign to Tier 1 analyst for investigation",
                "Document findings in ticketing system",
                "Schedule follow-up review"
            ])
        else:
            actions.extend([
                "Log and monitor for related activity",
                "Batch review during next shift"
            ])
        
        return actions
    
    def get_triage_statistics(self) -> Dict[str, Any]:
        """Get triage statistics"""
        return dict(self.triage_stats)


class IncidentEscalationManager:
    """Manages incident escalation and SLA compliance"""
    
    def __init__(self):
        self.sla_policies = SLAPolicy.SLA_RESPONSE_TIMES
        self.escalation_chains = self._build_escalation_chains()
    
    def _build_escalation_chains(self) -> Dict[IncidentSeverity, List[ResponseTeam]]:
        """Build standard escalation chains by severity"""
        return {
            IncidentSeverity.CRITICAL: [
                ResponseTeam.TIER1_SOC,
                ResponseTeam.TIER2_SOC,
                ResponseTeam.TIER3_SOC,
                ResponseTeam.INCIDENT_RESPONSE,
                ResponseTeam.EXECUTIVE
            ],
            IncidentSeverity.HIGH: [
                ResponseTeam.TIER1_SOC,
                ResponseTeam.TIER2_SOC,
                ResponseTeam.TIER3_SOC,
                ResponseTeam.INCIDENT_RESPONSE
            ],
            IncidentSeverity.MEDIUM: [
                ResponseTeam.TIER1_SOC,
                ResponseTeam.TIER2_SOC,
                ResponseTeam.TIER3_SOC
            ],
            IncidentSeverity.LOW: [
                ResponseTeam.TIER1_SOC,
                ResponseTeam.TIER2_SOC
            ],
            IncidentSeverity.INFORMATIONAL: [
                ResponseTeam.TIER1_SOC
            ]
        }
    
    def check_sla_compliance(self, incident: Incident) -> SLACompliance:
        """Check and update SLA compliance for an incident"""
        compliance = SLACompliance()
        sla = self.sla_policies[incident.severity]
        
        # Acknowledgement SLA
        if incident.acknowledged_at:
            ack_time = (incident.acknowledged_at - incident.created_at).total_seconds()
            compliance.acknowledgement_time_seconds = ack_time
            compliance.acknowledgement_met = ack_time <= sla["acknowledgement"].total_seconds()
            if not compliance.acknowledgement_met:
                compliance.sla_breaches.append("ACKNOWLEDGEMENT")
        
        # First response SLA
        if incident.first_response_at:
            resp_time = (incident.first_response_at - incident.created_at).total_seconds()
            compliance.first_response_time_seconds = resp_time
            compliance.first_response_met = resp_time <= sla["first_response"].total_seconds()
            if not compliance.first_response_met:
                compliance.sla_breaches.append("FIRST_RESPONSE")
        
        # Resolution SLA
        if incident.resolved_at:
            res_time = (incident.resolved_at - incident.created_at).total_seconds()
            compliance.resolution_time_seconds = res_time
            compliance.resolution_met = res_time <= sla["resolution"].total_seconds()
            if not compliance.resolution_met:
                compliance.sla_breaches.append("RESOLUTION")
        
        return compliance
    
    def escalate_incident(self, incident: Incident, reason: str, escalated_by: str, notes: Optional[str] = None) -> EscalationEvent:
        """Escalate incident to next level in chain"""
        chain = self.escalation_chains[incident.severity]
        current_idx = chain.index(incident.assigned_team) if incident.assigned_team in chain else 0
        
        if current_idx < len(chain) - 1:
            next_team = chain[current_idx + 1]
        else:
            next_team = chain[-1]
        
        escalation = EscalationEvent(
            from_team=incident.assigned_team or ResponseTeam.TIER1_SOC,
            to_team=next_team,
            reason=reason,
            escalated_by=escalated_by,
            notes=notes
        )
        
        incident.escalation_history.append(escalation)
        incident.assigned_team = next_team
        incident.status = IncidentStatus.ESCALATED
        
        return escalation
    
    def should_auto_escalate(self, incident: Incident) -> bool:
        """Determine if incident should be auto-escalated based on SLA breach"""
        if incident.status in {IncidentStatus.RESOLVED, IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE}:
            return False
        
        sla = self.sla_policies[incident.severity]
        elapsed = (datetime.now() - incident.created_at).total_seconds()
        
        # Auto-escalate if acknowledgement SLA breached
        if not incident.acknowledged_at and elapsed > sla["escalation"].total_seconds():
            return True
        
        return False


class IncidentTriageEscalationEngine:
    """
    Main facade class for the Incident Triage & Escalation Engine
    
    Production-grade security operations automation:
    - Automated incident triage with multi-factor scoring
    - SLA compliance monitoring
    - Intelligent team routing
    - Escalation chain management
    - Audit logging
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.triage_engine = IncidentTriageEngine(config)
        self.escalation_manager = IncidentEscalationManager()
        self.audit_log: List[Dict[str, Any]] = []
    
    def process_new_incident(
        self,
        title: str,
        description: str,
        category: IncidentCategory,
        indicators: Optional[List[ThreatIndicator]] = None,
        affected_assets: Optional[List[str]] = None,
        source_detector: Optional[str] = None
    ) -> TriageResult:
        """Create and triage a new incident in one call"""
        incident = Incident(
            title=title,
            description=description,
            category=category,
            indicators=indicators or [],
            affected_assets=affected_assets or [],
            source_detector=source_detector
        )
        
        result = self.triage_engine.triage_incident(incident)
        
        self._log_audit_event("INCIDENT_TRIAGED", {
            "incident_id": incident.incident_id,
            "severity": result.assigned_severity.value,
            "team": result.recommended_team.value,
            "score": result.incident.severity_score
        })
        
        return result
    
    def acknowledge_incident(self, incident_id: str, acknowledged_by: str) -> bool:
        """Acknowledge an incident"""
        if incident_id not in self.triage_engine.incident_cache:
            return False
        
        incident = self.triage_engine.incident_cache[incident_id]
        incident.acknowledged_at = datetime.now()
        incident.status = IncidentStatus.ASSIGNED
        
        self._log_audit_event("INCIDENT_ACKNOWLEDGED", {
            "incident_id": incident_id,
            "acknowledged_by": acknowledged_by
        })
        
        return True
    
    def check_and_auto_escalate(self) -> List[str]:
        """Check all open incidents and auto-escalate if needed"""
        escalated = []
        
        for incident_id, incident in self.triage_engine.incident_cache.items():
            if self.escalation_manager.should_auto_escalate(incident):
                self.escalation_manager.escalate_incident(
                    incident,
                    reason="SLA Breach - Auto-escalation triggered",
                    escalated_by="SYSTEM_AUTO"
                )
                escalated.append(incident_id)
                self._log_audit_event("AUTO_ESCALATED", {"incident_id": incident_id})
        
        return escalated
    
    def get_sla_summary(self) -> Dict[str, Any]:
        """Get SLA compliance summary"""
        summary = {
            "total_incidents": 0,
            "breaches": [],
            "compliance_rate": 0.0
        }
        
        compliant = 0
        for incident in self.triage_engine.incident_cache.values():
            summary["total_incidents"] += 1
            compliance = self.escalation_manager.check_sla_compliance(incident)
            if compliance.sla_breaches:
                summary["breaches"].append({
                    "incident_id": incident.incident_id,
                    "breaches": compliance.sla_breaches
                })
            else:
                compliant += 1
        
        if summary["total_incidents"] > 0:
            summary["compliance_rate"] = round(compliant / summary["total_incidents"] * 100, 2)
        
        return summary
    
    def _log_audit_event(self, event_type: str, details: Dict[str, Any]):
        """Log audit event"""
        self.audit_log.append({
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "details": details
        })
    
    def export_incidents_json(self) -> str:
        """Export all incidents as JSON"""
        incidents_data = []
        for inc in self.triage_engine.incident_cache.values():
            incidents_data.append({
                "incident_id": inc.incident_id,
                "title": inc.title,
                "severity": inc.severity.value,
                "status": inc.status.value,
                "score": inc.severity_score,
                "created_at": inc.created_at.isoformat()
            })
        return json.dumps(incidents_data, indent=2)


def create_incident_triage_engine(config: Optional[Dict[str, Any]] = None) -> IncidentTriageEscalationEngine:
    """Factory function to create triage engine instance"""
    return IncidentTriageEscalationEngine(config)


# Export public API
__all__ = [
    "IncidentSeverity",
    "IncidentStatus",
    "IncidentCategory",
    "ResponseTeam",
    "ThreatIndicator",
    "EscalationEvent",
    "SLACompliance",
    "Incident",
    "TriageResult",
    "SeverityScoringEngine",
    "IncidentTriageEngine",
    "IncidentEscalationManager",
    "IncidentTriageEscalationEngine",
    "create_incident_triage_engine"
]
