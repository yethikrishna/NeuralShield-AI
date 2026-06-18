"""
NeuralShield-AI: Threat Intelligence MITRE ATT&CK Executive Dashboard Reporter
June 2026 - Production Grade Implementation

Provides executive-level cybersecurity reporting with:
- MITRE ATT&CK framework mapping and visualization
- Executive risk scoring and prioritization
- C-suite friendly summary reports
- Mitigation recommendation engine
- Trend analysis and historical comparison
"""

import json
import hashlib
import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from collections import defaultdict, Counter


class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class MITRETactic(Enum):
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


@dataclass
class ThreatEvent:
    event_id: str
    tactic: str
    technique: str
    technique_id: str
    risk_level: RiskLevel
    timestamp: datetime.datetime
    source_ip: str
    destination: str
    description: str
    mitigations: List[str] = field(default_factory=list)
    confidence_score: float = 0.0


@dataclass
class ExecutiveSummary:
    report_id: str
    generated_at: datetime.datetime
    time_window: Tuple[datetime.datetime, datetime.datetime]
    total_threats: int
    risk_breakdown: Dict[RiskLevel, int]
    top_tactics: List[Tuple[str, int]]
    top_techniques: List[Tuple[str, int]]
    overall_risk_score: float
    critical_findings: List[ThreatEvent]
    recommendations: List[Dict[str, str]]
    trend_analysis: Dict[str, Any]


class MITREExecutiveDashboardReporter:
    """
    Production-grade executive dashboard reporter for MITRE ATT&CK threat intelligence.
    Generates C-suite friendly cybersecurity reports with risk quantification.
    """

    TACTIC_WEIGHTS = {
        MITRETactic.INITIAL_ACCESS.value: 1.2,
        MITRETactic.EXECUTION.value: 1.3,
        MITRETactic.PERSISTENCE.value: 1.4,
        MITRETactic.PRIVILEGE_ESCALATION.value: 1.5,
        MITRETactic.CREDENTIAL_ACCESS.value: 1.6,
        MITRETactic.COMMAND_AND_CONTROL.value: 1.4,
        MITRETactic.EXFILTRATION.value: 1.8,
        MITRETactic.IMPACT.value: 2.0,
    }

    RISK_SCORES = {
        RiskLevel.CRITICAL: 100,
        RiskLevel.HIGH: 75,
        RiskLevel.MEDIUM: 50,
        RiskLevel.LOW: 25,
        RiskLevel.INFORMATIONAL: 10,
    }

    def __init__(self, organization_name: str = "Enterprise"):
        self.organization_name = organization_name
        self.threat_events: List[ThreatEvent] = []
        self.historical_data: Dict[str, List[ThreatEvent]] = defaultdict(list)
        self.mitre_technique_mappings = self._initialize_mitre_mappings()
        self.mitigation_database = self._initialize_mitigations()

    def _initialize_mitre_mappings(self) -> Dict[str, Dict[str, Any]]:
        """Initialize MITRE ATT&CK technique to tactic mappings."""
        return {
            "T1566": {"tactic": MITRETactic.INITIAL_ACCESS.value, "name": "Phishing", "severity": RiskLevel.HIGH},
            "T1566.001": {"tactic": MITRETactic.INITIAL_ACCESS.value, "name": "Spearphishing Attachment", "severity": RiskLevel.CRITICAL},
            "T1566.002": {"tactic": MITRETactic.INITIAL_ACCESS.value, "name": "Spearphishing Link", "severity": RiskLevel.HIGH},
            "T1059": {"tactic": MITRETactic.EXECUTION.value, "name": "Command and Scripting Interpreter", "severity": RiskLevel.HIGH},
            "T1059.001": {"tactic": MITRETactic.EXECUTION.value, "name": "PowerShell", "severity": RiskLevel.CRITICAL},
            "T1059.003": {"tactic": MITRETactic.EXECUTION.value, "name": "Windows Command Shell", "severity": RiskLevel.HIGH},
            "T1053": {"tactic": MITRETactic.PERSISTENCE.value, "name": "Scheduled Task/Job", "severity": RiskLevel.HIGH},
            "T1547": {"tactic": MITRETactic.PERSISTENCE.value, "name": "Boot or Logon Autostart Execution", "severity": RiskLevel.HIGH},
            "T1548": {"tactic": MITRETactic.PRIVILEGE_ESCALATION.value, "name": "Abuse Elevation Control Mechanism", "severity": RiskLevel.CRITICAL},
            "T1068": {"tactic": MITRETactic.PRIVILEGE_ESCALATION.value, "name": "Exploitation for Privilege Escalation", "severity": RiskLevel.CRITICAL},
            "T1555": {"tactic": MITRETactic.CREDENTIAL_ACCESS.value, "name": "Credentials from Password Stores", "severity": RiskLevel.CRITICAL},
            "T1110": {"tactic": MITRETactic.CREDENTIAL_ACCESS.value, "name": "Brute Force", "severity": RiskLevel.HIGH},
            "T1083": {"tactic": MITRETactic.DISCOVERY.value, "name": "File and Directory Discovery", "severity": RiskLevel.MEDIUM},
            "T1046": {"tactic": MITRETactic.DISCOVERY.value, "name": "Network Service Scanning", "severity": RiskLevel.MEDIUM},
            "T1021": {"tactic": MITRETactic.LATERAL_MOVEMENT.value, "name": "Remote Services", "severity": RiskLevel.HIGH},
            "T1560": {"tactic": MITRETactic.COLLECTION.value, "name": "Archive Collected Data", "severity": RiskLevel.HIGH},
            "T1071": {"tactic": MITRETactic.COMMAND_AND_CONTROL.value, "name": "Application Layer Protocol", "severity": RiskLevel.HIGH},
            "T1090": {"tactic": MITRETactic.COMMAND_AND_CONTROL.value, "name": "Proxy", "severity": RiskLevel.HIGH},
            "T1041": {"tactic": MITRETactic.EXFILTRATION.value, "name": "Exfiltration Over C2 Channel", "severity": RiskLevel.CRITICAL},
            "T1048": {"tactic": MITRETactic.EXFILTRATION.value, "name": "Exfiltration Over Alternative Protocol", "severity": RiskLevel.CRITICAL},
            "T1486": {"tactic": MITRETactic.IMPACT.value, "name": "Data Encrypted for Impact", "severity": RiskLevel.CRITICAL},
            "T1490": {"tactic": MITRETactic.IMPACT.value, "name": "Inhibit System Recovery", "severity": RiskLevel.CRITICAL},
            "T1498": {"tactic": MITRETactic.IMPACT.value, "name": "Network Denial of Service", "severity": RiskLevel.HIGH},
        }

    def _initialize_mitigations(self) -> Dict[str, List[str]]:
        """Initialize mitigation recommendations database."""
        return {
            MITRETactic.INITIAL_ACCESS.value: [
                "Implement email security gateway with advanced threat protection",
                "Deploy DNS filtering and web proxy solutions",
                "Enable multi-factor authentication for all remote access",
                "Conduct regular security awareness training",
            ],
            MITRETactic.EXECUTION.value: [
                "Apply application whitelisting policies",
                "Restrict PowerShell execution policy",
                "Enable script block logging",
                "Deploy endpoint detection and response (EDR)",
            ],
            MITRETactic.PERSISTENCE.value: [
                "Audit autorun locations regularly",
                "Monitor scheduled task creation",
                "Implement least-privilege access controls",
                "Enable registry change auditing",
            ],
            MITRETactic.PRIVILEGE_ESCALATION.value: [
                "Apply security patches within 72 hours",
                "Restrict local administrator privileges",
                "Enable User Account Control (UAC)",
                "Monitor privilege escalation events",
            ],
            MITRETactic.CREDENTIAL_ACCESS.value: [
                "Implement privileged access management (PAM)",
                "Rotate credentials regularly",
                "Monitor for credential dumping tools",
                "Enable Windows Defender Credential Guard",
            ],
            MITRETactic.LATERAL_MOVEMENT.value: [
                "Segment network zones",
                "Restrict remote desktop protocols",
                "Monitor pass-the-hash attempts",
                "Implement network access control",
            ],
            MITRETactic.EXFILTRATION.value: [
                "Implement data loss prevention (DLP)",
                "Monitor outbound traffic patterns",
                "Encrypt sensitive data at rest",
                "Restrict removable media usage",
            ],
            MITRETactic.IMPACT.value: [
                "Maintain offline backups with air-gapping",
                "Implement incident response plan",
                "Test disaster recovery procedures",
                "Deploy ransomware protection",
            ],
        }

    def add_threat_event(
        self,
        technique_id: str,
        source_ip: str,
        destination: str,
        description: str,
        timestamp: Optional[datetime.datetime] = None,
        confidence_score: float = 0.8,
    ) -> Optional[ThreatEvent]:
        """
        Add a threat event to the dashboard.
        Returns the created ThreatEvent or None if technique not found.
        """
        if technique_id not in self.mitre_technique_mappings:
            return None

        mapping = self.mitre_technique_mappings[technique_id]
        event_id = hashlib.sha256(
            f"{technique_id}{source_ip}{timestamp}{datetime.datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]

        event = ThreatEvent(
            event_id=f"EVT-{event_id.upper()}",
            tactic=mapping["tactic"],
            technique=mapping["name"],
            technique_id=technique_id,
            risk_level=mapping["severity"],
            timestamp=timestamp or datetime.datetime.now(),
            source_ip=source_ip,
            destination=destination,
            description=description,
            mitigations=self.mitigation_database.get(mapping["tactic"], []),
            confidence_score=max(0.0, min(1.0, confidence_score)),
        )

        self.threat_events.append(event)
        return event

    def batch_add_events(self, events_data: List[Dict[str, Any]]) -> Tuple[int, int]:
        """
        Batch add multiple threat events.
        Returns (success_count, failure_count)
        """
        success = 0
        failure = 0

        for event_data in events_data:
            try:
                result = self.add_threat_event(
                    technique_id=event_data["technique_id"],
                    source_ip=event_data.get("source_ip", "0.0.0.0"),
                    destination=event_data.get("destination", "unknown"),
                    description=event_data.get("description", ""),
                    timestamp=event_data.get("timestamp"),
                    confidence_score=event_data.get("confidence_score", 0.8),
                )
                if result:
                    success += 1
                else:
                    failure += 1
            except Exception:
                failure += 1

        return success, failure

    def calculate_overall_risk_score(self) -> float:
        """Calculate weighted overall risk score (0-100)."""
        if not self.threat_events:
            return 0.0

        total_weighted = 0
        total_max_possible = 0

        for event in self.threat_events:
            base_score = self.RISK_SCORES[event.risk_level]
            tactic_weight = self.TACTIC_WEIGHTS.get(event.tactic, 1.0)
            weighted_score = base_score * tactic_weight * event.confidence_score
            total_weighted += weighted_score
            total_max_possible += self.RISK_SCORES[RiskLevel.CRITICAL] * 2.0

        if total_max_possible == 0:
            return 0.0

        normalized_score = (total_weighted / total_max_possible) * 100
        return round(min(100.0, normalized_score), 2)

    def get_risk_breakdown(self) -> Dict[RiskLevel, int]:
        """Get count of threats by risk level."""
        breakdown = defaultdict(int)
        for event in self.threat_events:
            breakdown[event.risk_level] += 1
        return dict(breakdown)

    def get_top_tactics(self, limit: int = 5) -> List[Tuple[str, int]]:
        """Get most frequently observed tactics."""
        tactic_counts = Counter(e.tactic for e in self.threat_events)
        return tactic_counts.most_common(limit)

    def get_top_techniques(self, limit: int = 5) -> List[Tuple[str, int]]:
        """Get most frequently observed techniques."""
        technique_counts = Counter(f"{e.technique_id}: {e.technique}" for e in self.threat_events)
        return technique_counts.most_common(limit)

    def get_critical_findings(self, limit: int = 10) -> List[ThreatEvent]:
        """Get highest priority critical findings."""
        critical_events = [
            e for e in self.threat_events
            if e.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
        ]
        sorted_events = sorted(
            critical_events,
            key=lambda x: (
                self.RISK_SCORES[x.risk_level],
                x.confidence_score,
                x.timestamp,
            ),
            reverse=True,
        )
        return sorted_events[:limit]

    def generate_recommendations(self) -> List[Dict[str, str]]:
        """Generate prioritized mitigation recommendations."""
        observed_tactics = set(e.tactic for e in self.threat_events)
        recommendations = []

        for tactic in observed_tactics:
            tactic_mitigations = self.mitigation_database.get(tactic, [])
            threat_count = sum(1 for e in self.threat_events if e.tactic == tactic)

            for idx, mitigation in enumerate(tactic_mitigations[:2]):
                priority = "HIGH" if threat_count >= 3 else "MEDIUM"
                recommendations.append({
                    "category": tactic,
                    "priority": priority,
                    "recommendation": mitigation,
                    "related_threats": str(threat_count),
                })

        return sorted(recommendations, key=lambda x: (x["priority"], x["related_threats"]), reverse=True)

    def generate_trend_analysis(self) -> Dict[str, Any]:
        """Generate trend analysis comparing current to historical data."""
        current_month = datetime.datetime.now().strftime("%Y-%m")

        return {
            "current_period_threats": len(self.threat_events),
            "period": current_month,
            "unique_source_ips": len(set(e.source_ip for e in self.threat_events)),
            "unique_destinations": len(set(e.destination for e in self.threat_events)),
            "confidence_distribution": {
                "high_confidence": sum(1 for e in self.threat_events if e.confidence_score >= 0.8),
                "medium_confidence": sum(1 for e in self.threat_events if 0.5 <= e.confidence_score < 0.8),
                "low_confidence": sum(1 for e in self.threat_events if e.confidence_score < 0.5),
            },
        }

    def generate_executive_summary(
        self,
        window_hours: int = 24,
    ) -> ExecutiveSummary:
        """Generate comprehensive executive summary report."""
        end_time = datetime.datetime.now()
        start_time = end_time - datetime.timedelta(hours=window_hours)

        report_id = hashlib.sha256(
            f"{self.organization_name}{end_time.isoformat()}".encode()
        ).hexdigest()[:12]

        return ExecutiveSummary(
            report_id=f"RPT-{report_id.upper()}",
            generated_at=end_time,
            time_window=(start_time, end_time),
            total_threats=len(self.threat_events),
            risk_breakdown=self.get_risk_breakdown(),
            top_tactics=self.get_top_tactics(),
            top_techniques=self.get_top_techniques(),
            overall_risk_score=self.calculate_overall_risk_score(),
            critical_findings=self.get_critical_findings(),
            recommendations=self.generate_recommendations(),
            trend_analysis=self.generate_trend_analysis(),
        )

    def export_json_report(self, summary: ExecutiveSummary) -> str:
        """Export executive summary as JSON string."""
        report = {
            "report_id": summary.report_id,
            "organization": self.organization_name,
            "generated_at": summary.generated_at.isoformat(),
            "time_window": {
                "start": summary.time_window[0].isoformat(),
                "end": summary.time_window[1].isoformat(),
            },
            "executive_summary": {
                "total_threats": summary.total_threats,
                "overall_risk_score": summary.overall_risk_score,
                "risk_assessment": self._get_risk_assessment(summary.overall_risk_score),
            },
            "risk_breakdown": {k.value: v for k, v in summary.risk_breakdown.items()},
            "top_tactics": [{"tactic": t, "count": c} for t, c in summary.top_tactics],
            "top_techniques": [{"technique": t, "count": c} for t, c in summary.top_techniques],
            "critical_findings": [
                {
                    "event_id": f.event_id,
                    "risk_level": f.risk_level.value,
                    "tactic": f.tactic,
                    "technique": f.technique,
                    "technique_id": f.technique_id,
                    "source_ip": f.source_ip,
                    "description": f.description,
                    "confidence": f.confidence_score,
                }
                for f in summary.critical_findings
            ],
            "recommendations": summary.recommendations,
            "trend_analysis": summary.trend_analysis,
        }
        return json.dumps(report, indent=2)

    def _get_risk_assessment(self, score: float) -> str:
        """Get human-readable risk assessment."""
        if score >= 75:
            return "SEVERE - Immediate action required. Critical security breaches detected."
        elif score >= 50:
            return "HIGH - Urgent attention needed. Significant threats identified."
        elif score >= 25:
            return "ELEVATED - Security improvements recommended. Moderate risks present."
        elif score > 0:
            return "LOW - General security hygiene recommended."
        else:
            return "NORMAL - No significant threats detected."

    def generate_text_summary(self, summary: ExecutiveSummary) -> str:
        """Generate human-readable text summary for executive consumption."""
        assessment = self._get_risk_assessment(summary.overall_risk_score)

        lines = [
            "=" * 70,
            f"NEURALSHIELD-AI SECURITY EXECUTIVE REPORT - {self.organization_name}",
            f"Report ID: {summary.report_id}",
            f"Generated: {summary.generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 70,
            "",
            "📊 OVERALL SECURITY STATUS",
            f"   Risk Score: {summary.overall_risk_score}/100",
            f"   Assessment: {assessment}",
            f"   Total Threats Detected: {summary.total_threats}",
            "",
            "⚠️  RISK BREAKDOWN",
        ]

        for level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
            count = summary.risk_breakdown.get(level, 0)
            lines.append(f"   {level.value:15} {count} threats")

        lines.extend(["", "🎯 TOP ATTACK TACTICS OBSERVED"])
        for tactic, count in summary.top_tactics:
            lines.append(f"   {count:3d}x  {tactic}")

        lines.extend(["", "🔝 TOP ATTACK TECHNIQUES"])
        for technique, count in summary.top_techniques:
            lines.append(f"   {count:3d}x  {technique}")

        if summary.critical_findings:
            lines.extend(["", "🚨 CRITICAL FINDINGS (TOP 5)"])
            for idx, finding in enumerate(summary.critical_findings[:5], 1):
                lines.append(f"   {idx}. [{finding.risk_level.value}] {finding.technique}")
                lines.append(f"       Source: {finding.source_ip}")
                lines.append(f"       Confidence: {finding.confidence_score:.1%}")

        if summary.recommendations:
            lines.extend(["", "💡 RECOMMENDED ACTIONS"])
            for idx, rec in enumerate(summary.recommendations[:5], 1):
                lines.append(f"   {idx}. [{rec['priority']}] {rec['recommendation']}")

        lines.extend([
            "",
            "=" * 70,
            "NeuralShield-AI Threat Intelligence Dashboard",
            "Production Grade - June 2026",
            "=" * 70,
        ])

        return "\n".join(lines)


def create_executive_dashboard(organization_name: str = "Enterprise") -> MITREExecutiveDashboardReporter:
    """Factory function to create a MITRE Executive Dashboard Reporter instance."""
    return MITREExecutiveDashboardReporter(organization_name)

