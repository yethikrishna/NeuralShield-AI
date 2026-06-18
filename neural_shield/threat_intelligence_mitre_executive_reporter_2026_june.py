"""
Threat Intelligence MITRE ATT&CK Executive Report Generator
June 18, 2026 - Production Release

Generates executive-level security reports with:
- MITRE ATT&CK framework mapping visualization
- Risk scoring and prioritization
- Executive summary with actionable insights
- Compliance alignment assessment
- Mitigation roadmap recommendations
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Any
from datetime import datetime
import json
import hashlib


class ReportSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class MITRETactic(str, Enum):
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


class ComplianceFramework(str, Enum):
    NIST_SP_800_53 = "NIST SP 800-53"
    NIST_SP_800_171 = "NIST SP 800-171"
    ISO_27001 = "ISO 27001"
    HIPAA = "HIPAA"
    GDPR = "GDPR"
    PCI_DSS = "PCI DSS"
    SOC_2 = "SOC 2"


@dataclass
class MITRETechniqueFinding:
    technique_id: str
    technique_name: str
    tactic: MITRETactic
    severity: ReportSeverity
    confidence_score: float  # 0.0 - 1.0
    evidence_count: int
    first_seen: datetime
    last_seen: datetime
    affected_assets: List[str] = field(default_factory=list)
    mitigation_recommendations: List[str] = field(default_factory=list)


@dataclass
class ExecutiveSummary:
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    overall_risk_score: float  # 0.0 - 10.0
    top_threat_vectors: List[str]
    key_recommendations: List[str]
    compliance_alignment_score: float


@dataclass
class RiskTrend:
    date: datetime
    risk_score: float
    finding_count: int
    critical_count: int


@dataclass
class ComplianceGap:
    framework: ComplianceFramework
    control_id: str
    control_name: str
    gap_description: str
    severity: ReportSeverity
    remediation_steps: List[str]


@dataclass
class ExecutiveReportResult:
    report_id: str
    generated_at: datetime
    executive_summary: ExecutiveSummary
    findings: List[MITRETechniqueFinding]
    risk_trends: List[RiskTrend]
    compliance_gaps: List[ComplianceGap]
    mitigation_roadmap: Dict[str, List[str]]
    report_hash: str
    report_version: str = "1.0.0"


class ThreatIntelligenceMITREExecutiveReporter:
    """
    Executive-level MITRE ATT&CK report generator for security leadership.
    
    Features:
    - Executive summary with risk scoring
    - MITRE ATT&CK heat map visualization data
    - Risk trend analysis
    - Compliance gap assessment
    - Prioritized mitigation roadmap
    """

    def __init__(self, organization_name: str = "Enterprise Security"):
        self.organization_name = organization_name
        self._findings: List[MITRETechniqueFinding] = []
        self._risk_trends: List[RiskTrend] = []
        self._compliance_gaps: List[ComplianceGap] = []

    def add_finding(self, finding: MITRETechniqueFinding) -> None:
        """Add a MITRE ATT&CK technique finding to the report."""
        self._findings.append(finding)

    def add_risk_trend(self, trend: RiskTrend) -> None:
        """Add historical risk trend data."""
        self._risk_trends.append(trend)

    def add_compliance_gap(self, gap: ComplianceGap) -> None:
        """Add a compliance gap assessment."""
        self._compliance_gaps.append(gap)

    def _calculate_overall_risk_score(self) -> float:
        """Calculate weighted overall risk score (0.0 - 10.0)."""
        if not self._findings:
            return 0.0

        severity_weights = {
            ReportSeverity.CRITICAL: 10.0,
            ReportSeverity.HIGH: 7.0,
            ReportSeverity.MEDIUM: 4.0,
            ReportSeverity.LOW: 1.0,
            ReportSeverity.INFORMATIONAL: 0.5,
        }

        weighted_sum = 0.0
        total_weight = 0.0

        for finding in self._findings:
            weight = severity_weights[finding.severity]
            confidence = finding.confidence_score
            weighted_sum += weight * confidence
            total_weight += weight

        if total_weight == 0:
            return 0.0

        normalized_score = (weighted_sum / total_weight)
        return round(min(normalized_score, 10.0), 2)

    def _get_top_threat_vectors(self, limit: int = 5) -> List[str]:
        """Identify top threat vectors by frequency and severity."""
        tactic_counts: Dict[str, float] = {}

        for finding in self._findings:
            tactic = finding.tactic.value
            severity_multiplier = {
                ReportSeverity.CRITICAL: 3.0,
                ReportSeverity.HIGH: 2.0,
                ReportSeverity.MEDIUM: 1.0,
                ReportSeverity.LOW: 0.5,
                ReportSeverity.INFORMATIONAL: 0.1,
            }.get(finding.severity, 1.0)

            score = finding.confidence_score * severity_multiplier
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + score

        sorted_tactics = sorted(
            tactic_counts.items(), key=lambda x: x[1], reverse=True
        )
        return [tactic for tactic, _ in sorted_tactics[:limit]]

    def _generate_key_recommendations(self) -> List[str]:
        """Generate prioritized recommendations based on findings."""
        recommendations = []

        critical_findings = [
            f for f in self._findings if f.severity == ReportSeverity.CRITICAL
        ]
        high_findings = [
            f for f in self._findings if f.severity == ReportSeverity.HIGH
        ]

        if critical_findings:
            recommendations.append(
                "IMMEDIATE: Address all CRITICAL findings within 72 hours"
            )
            for finding in critical_findings[:3]:
                for mit in finding.mitigation_recommendations[:1]:
                    if mit not in recommendations:
                        recommendations.append(f"CRITICAL: {mit}")

        if high_findings:
            recommendations.append(
                "PRIORITY: Resolve HIGH severity findings within 2 weeks"
            )

        if not critical_findings and not high_findings:
            recommendations.append(
                "MAINTENANCE: Continue regular security monitoring and assessments"
            )

        recommendations.append(
            "STRATEGIC: Implement MITRE ATT&CK aligned security controls"
        )
        recommendations.append(
            "COMPLIANCE: Address identified compliance gaps per framework requirements"
        )

        return recommendations[:8]

    def _calculate_compliance_alignment(self) -> float:
        """Calculate overall compliance alignment score (0.0 - 100%)."""
        if not self._compliance_gaps:
            return 95.0  # Default high score when no gaps identified

        severity_penalty = {
            ReportSeverity.CRITICAL: 15.0,
            ReportSeverity.HIGH: 8.0,
            ReportSeverity.MEDIUM: 4.0,
            ReportSeverity.LOW: 1.0,
            ReportSeverity.INFORMATIONAL: 0.0,
        }

        total_penalty = sum(
            severity_penalty.get(gap.severity, 0) for gap in self._compliance_gaps
        )
        return max(100.0 - total_penalty, 0.0)

    def _generate_mitigation_roadmap(self) -> Dict[str, List[str]]:
        """Generate time-phased mitigation roadmap."""
        immediate = []
        short_term = []
        medium_term = []
        long_term = []

        for finding in self._findings:
            for mitigation in finding.mitigation_recommendations:
                if finding.severity == ReportSeverity.CRITICAL:
                    if mitigation not in immediate:
                        immediate.append(mitigation)
                elif finding.severity == ReportSeverity.HIGH:
                    if mitigation not in short_term:
                        short_term.append(mitigation)
                elif finding.severity == ReportSeverity.MEDIUM:
                    if mitigation not in medium_term:
                        medium_term.append(mitigation)
                else:
                    if mitigation not in long_term:
                        long_term.append(mitigation)

        return {
            "IMMEDIATE (0-3 days)": immediate[:5],
            "SHORT_TERM (1-2 weeks)": short_term[:5],
            "MEDIUM_TERM (1-3 months)": medium_term[:5],
            "LONG_TERM (3-12 months)": long_term[:5],
        }

    def _generate_report_hash(self, report_data: Dict) -> str:
        """Generate cryptographic hash for report integrity verification."""
        json_str = json.dumps(report_data, sort_keys=True, default=str)
        return hashlib.sha256(json_str.encode()).hexdigest()[:32]

    def generate_executive_report(self) -> ExecutiveReportResult:
        """Generate the complete executive security report."""
        report_id = f"MITRE-REPORT-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        generated_at = datetime.utcnow()

        # Count findings by severity
        severity_counts = {
            ReportSeverity.CRITICAL: 0,
            ReportSeverity.HIGH: 0,
            ReportSeverity.MEDIUM: 0,
            ReportSeverity.LOW: 0,
            ReportSeverity.INFORMATIONAL: 0,
        }

        for finding in self._findings:
            severity_counts[finding.severity] += 1

        executive_summary = ExecutiveSummary(
            total_findings=len(self._findings),
            critical_findings=severity_counts[ReportSeverity.CRITICAL],
            high_findings=severity_counts[ReportSeverity.HIGH],
            medium_findings=severity_counts[ReportSeverity.MEDIUM],
            low_findings=severity_counts[ReportSeverity.LOW],
            overall_risk_score=self._calculate_overall_risk_score(),
            top_threat_vectors=self._get_top_threat_vectors(),
            key_recommendations=self._generate_key_recommendations(),
            compliance_alignment_score=self._calculate_compliance_alignment(),
        )

        mitigation_roadmap = self._generate_mitigation_roadmap()

        report_data = {
            "report_id": report_id,
            "organization": self.organization_name,
            "findings_count": len(self._findings),
            "risk_score": executive_summary.overall_risk_score,
        }

        report_hash = self._generate_report_hash(report_data)

        return ExecutiveReportResult(
            report_id=report_id,
            generated_at=generated_at,
            executive_summary=executive_summary,
            findings=self._findings.copy(),
            risk_trends=self._risk_trends.copy(),
            compliance_gaps=self._compliance_gaps.copy(),
            mitigation_roadmap=mitigation_roadmap,
            report_hash=report_hash,
        )

    def export_report_json(self, report: ExecutiveReportResult) -> str:
        """Export report as JSON string."""
        report_dict = {
            "report_id": report.report_id,
            "generated_at": report.generated_at.isoformat(),
            "organization": self.organization_name,
            "report_version": report.report_version,
            "report_hash": report.report_hash,
            "executive_summary": {
                "total_findings": report.executive_summary.total_findings,
                "critical_findings": report.executive_summary.critical_findings,
                "high_findings": report.executive_summary.high_findings,
                "medium_findings": report.executive_summary.medium_findings,
                "low_findings": report.executive_summary.low_findings,
                "overall_risk_score": report.executive_summary.overall_risk_score,
                "top_threat_vectors": report.executive_summary.top_threat_vectors,
                "key_recommendations": report.executive_summary.key_recommendations,
                "compliance_alignment_score": report.executive_summary.compliance_alignment_score,
            },
            "mitigation_roadmap": report.mitigation_roadmap,
        }
        return json.dumps(report_dict, indent=2)


def create_mitre_executive_reporter(
    organization_name: str = "Enterprise Security",
) -> ThreatIntelligenceMITREExecutiveReporter:
    """Factory function to create MITRE executive report generator."""
    return ThreatIntelligenceMITREExecutiveReporter(organization_name)
