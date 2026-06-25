"""
NeuralShield AI - MITRE ATT&CK Threat Hunting Report Generator
Dimension A - Feature Expansion (v84)

A comprehensive threat hunting report generation module that creates structured,
exportable security reports with MITRE ATT&CK mapping, evidence tracking,
and remediation recommendations.

ADD-ONLY implementation - no modifications to existing code.
"""

import json
import datetime
import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path


class SeverityLevel(Enum):
    """Severity levels for threat findings"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class ReportStatus(Enum):
    """Report generation status"""
    DRAFT = "DRAFT"
    REVIEW = "REVIEW"
    FINAL = "FINAL"
    ARCHIVED = "ARCHIVED"


class MITRECategory(Enum):
    """MITRE ATT&CK tactic categories"""
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
class EvidenceItem:
    """Single piece of evidence supporting a finding"""
    evidence_id: str
    timestamp: str
    source: str
    description: str
    data_type: str = "text"
    raw_data: Optional[str] = None
    confidence: float = 0.0

    def __post_init__(self):
        if not self.evidence_id:
            self.evidence_id = f"EVID-{hashlib.md5((self.timestamp + self.source).encode()).hexdigest()[:8].upper()}"


@dataclass
class ThreatFinding:
    """Single threat finding with MITRE mapping"""
    finding_id: str
    title: str
    description: str
    severity: SeverityLevel
    mitre_technique: str
    mitre_tactic: MITRECategory
    evidence: List[EvidenceItem] = field(default_factory=list)
    confidence_score: float = 0.0
    false_positive_probability: float = 0.0
    status: str = "OPEN"
    remediation_steps: List[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    def __post_init__(self):
        if not self.finding_id:
            self.finding_id = f"FIND-{hashlib.md5(self.title.encode()).hexdigest()[:8].upper()}"


@dataclass
class ExecutiveSummary:
    """Executive summary for the report"""
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    top_threats: List[str] = field(default_factory=list)
    key_recommendations: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    overall_assessment: str = ""


@dataclass
class ThreatHuntingReport:
    """Complete threat hunting report"""
    report_id: str
    title: str
    description: str
    generated_at: str
    generated_by: str = "NeuralShield AI"
    version: str = "1.0.0"
    status: ReportStatus = ReportStatus.DRAFT
    executive_summary: ExecutiveSummary = field(default_factory=ExecutiveSummary)
    findings: List[ThreatFinding] = field(default_factory=list)
    hunt_scope: Dict[str, Any] = field(default_factory=dict)
    methodology: List[str] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    mitre_coverage: Dict[str, int] = field(default_factory=dict)

    def __post_init__(self):
        if not self.report_id:
            self.report_id = f"THR-{datetime.datetime.now().strftime('%Y%m%d')}-{hashlib.md5(self.title.encode()).hexdigest()[:6].upper()}"


class ThreatHuntingReportGenerator:
    """
    Main report generator class for creating structured threat hunting reports.
    
    Features:
    - Create and manage threat findings with MITRE ATT&CK mapping
    - Add evidence with confidence scoring
    - Generate executive summaries automatically
    - Export to JSON, Markdown, and HTML formats
    - Calculate risk scores and coverage metrics
    """

    def __init__(self, output_dir: str = "./reports"):
        """Initialize the report generator"""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._reports: Dict[str, ThreatHuntingReport] = {}

    def create_report(self, title: str, description: str = "",
                     hunt_scope: Optional[Dict[str, Any]] = None) -> str:
        """
        Create a new threat hunting report
        
        Args:
            title: Report title
            description: Report description
            hunt_scope: Dictionary defining the hunt scope (time window, assets, etc.)
            
        Returns:
            report_id: Unique identifier for the report
        """
        report = ThreatHuntingReport(
            report_id="",
            title=title,
            description=description,
            generated_at=datetime.datetime.now().isoformat(),
            hunt_scope=hunt_scope or {},
            methodology=[
                "Automated prompt injection detection",
                "LLM output hallucination analysis",
                "Context boundary violation checking",
                "MITRE ATT&CK technique mapping",
                "Confidence scoring and false positive analysis"
            ],
            tools_used=[
                "NeuralShield AI Security Framework",
                "Prompt Injection Ensemble Detector",
                "Context Chain Analyzer",
                "MITRE ATT&CK Coverage Analyzer"
            ]
        )
        self._reports[report.report_id] = report
        self._update_executive_summary(report.report_id)
        return report.report_id

    def add_finding(self, report_id: str, title: str, description: str,
                   severity: SeverityLevel, mitre_technique: str,
                   mitre_tactic: MITRECategory, confidence: float = 0.0,
                   remediation_steps: Optional[List[str]] = None) -> str:
        """
        Add a threat finding to a report
        
        Args:
            report_id: Target report identifier
            title: Finding title
            description: Detailed description
            severity: Severity level
            mitre_technique: MITRE ATT&CK technique ID (e.g., T1059)
            mitre_tactic: MITRE ATT&CK tactic category
            confidence: Confidence score (0.0 - 1.0)
            remediation_steps: List of remediation recommendations
            
        Returns:
            finding_id: Unique finding identifier
        """
        if report_id not in self._reports:
            raise ValueError(f"Report {report_id} not found")

        finding = ThreatFinding(
            finding_id="",
            title=title,
            description=description,
            severity=severity,
            mitre_technique=mitre_technique,
            mitre_tactic=mitre_tactic,
            confidence_score=confidence,
            remediation_steps=remediation_steps or []
        )

        self._reports[report_id].findings.append(finding)
        self._update_executive_summary(report_id)
        return finding.finding_id

    def add_evidence(self, report_id: str, finding_id: str,
                    source: str, description: str,
                    raw_data: Optional[str] = None,
                    confidence: float = 0.0) -> str:
        """
        Add evidence to a specific finding
        
        Args:
            report_id: Target report identifier
            finding_id: Target finding identifier
            source: Evidence source
            description: Evidence description
            raw_data: Optional raw data
            confidence: Evidence confidence score
            
        Returns:
            evidence_id: Unique evidence identifier
        """
        if report_id not in self._reports:
            raise ValueError(f"Report {report_id} not found")

        report = self._reports[report_id]
        finding = next((f for f in report.findings if f.finding_id == finding_id), None)
        
        if not finding:
            raise ValueError(f"Finding {finding_id} not found in report")

        evidence = EvidenceItem(
            evidence_id="",
            timestamp=datetime.datetime.now().isoformat(),
            source=source,
            description=description,
            raw_data=raw_data,
            confidence=confidence
        )

        finding.evidence.append(evidence)
        return evidence.evidence_id

    def _update_executive_summary(self, report_id: str) -> None:
        """Update executive summary based on current findings"""
        report = self._reports[report_id]
        summary = report.executive_summary

        # Count findings by severity
        summary.total_findings = len(report.findings)
        summary.critical_findings = sum(1 for f in report.findings if f.severity == SeverityLevel.CRITICAL)
        summary.high_findings = sum(1 for f in report.findings if f.severity == SeverityLevel.HIGH)
        summary.medium_findings = sum(1 for f in report.findings if f.severity == SeverityLevel.MEDIUM)
        summary.low_findings = sum(1 for f in report.findings if f.severity == SeverityLevel.LOW)

        # Calculate risk score (weighted: Critical=10, High=5, Medium=2, Low=1)
        summary.risk_score = (
            summary.critical_findings * 10 +
            summary.high_findings * 5 +
            summary.medium_findings * 2 +
            summary.low_findings * 1
        )

        # Update MITRE coverage
        coverage = {}
        for finding in report.findings:
            tactic = finding.mitre_tactic.value
            coverage[tactic] = coverage.get(tactic, 0) + 1
        report.mitre_coverage = coverage

        # Generate overall assessment
        if summary.risk_score >= 50:
            summary.overall_assessment = "CRITICAL - Immediate action required. Multiple high-severity threats detected."
        elif summary.risk_score >= 25:
            summary.overall_assessment = "HIGH - Urgent review recommended. Significant threats identified."
        elif summary.risk_score >= 10:
            summary.overall_assessment = "MEDIUM - Review scheduled. Moderate risk exposure detected."
        else:
            summary.overall_assessment = "LOW - Standard monitoring. Minimal risk exposure."

        # Top threats (critical and high severity)
        summary.top_threats = [
            f.title for f in report.findings 
            if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)
        ][:5]

        # Key recommendations
        summary.key_recommendations = self._generate_recommendations(report)

    def _generate_recommendations(self, report: ThreatHuntingReport) -> List[str]:
        """Generate remediation recommendations based on findings"""
        recommendations = []
        
        if report.executive_summary.critical_findings > 0:
            recommendations.append("IMMEDIATE: Isolate affected systems and initiate incident response protocol")
        
        if report.executive_summary.high_findings > 0:
            recommendations.append("URGENT: Deploy targeted detection rules for identified attack patterns")
        
        if any("T1059" in f.mitre_technique or "Execution" in f.mitre_tactic.value for f in report.findings):
            recommendations.append("Implement strict input validation and command execution controls")
        
        if any("Injection" in f.title for f in report.findings):
            recommendations.append("Enhance prompt injection detection with contextual analysis")
        
        if len(recommendations) < 3:
            recommendations.extend([
                "Schedule regular security posture reviews",
                "Update security playbooks with new TTPs",
                "Conduct team security awareness training"
            ])

        return recommendations[:5]

    def export_to_json(self, report_id: str, filepath: Optional[str] = None) -> str:
        """Export report to JSON format"""
        if report_id not in self._reports:
            raise ValueError(f"Report {report_id} not found")

        report = self._reports[report_id]
        data = asdict(report)
        
        # Convert enums to values
        data["status"] = report.status.value
        for i, finding in enumerate(report.findings):
            data["findings"][i]["severity"] = finding.severity.value
            data["findings"][i]["mitre_tactic"] = finding.mitre_tactic.value

        if not filepath:
            filepath = str(self.output_dir / f"{report_id}.json")
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        return filepath

    def export_to_markdown(self, report_id: str, filepath: Optional[str] = None) -> str:
        """Export report to Markdown format"""
        if report_id not in self._reports:
            raise ValueError(f"Report {report_id} not found")

        report = self._reports[report_id]
        
        md_content = [
            f"# {report.title}",
            f"**Report ID:** {report.report_id}",
            f"**Generated:** {report.generated_at}",
            f"**Generated by:** {report.generated_by}",
            f"**Status:** {report.status.value}",
            f"**Version:** {report.version}",
            "",
            "## Executive Summary",
            f"**Overall Assessment:** {report.executive_summary.overall_assessment}",
            f"**Risk Score:** {report.executive_summary.risk_score}",
            "",
            "### Findings Summary",
            f"- Total Findings: {report.executive_summary.total_findings}",
            f"- Critical: {report.executive_summary.critical_findings}",
            f"- High: {report.executive_summary.high_findings}",
            f"- Medium: {report.executive_summary.medium_findings}",
            f"- Low: {report.executive_summary.low_findings}",
            "",
            "### Top Threats",
        ]

        for threat in report.executive_summary.top_threats:
            md_content.append(f"- {threat}")

        md_content.extend([
            "",
            "### Key Recommendations",
        ])

        for rec in report.executive_summary.key_recommendations:
            md_content.append(f"- {rec}")

        md_content.extend([
            "",
            "## Detailed Findings",
        ])

        for finding in report.findings:
            md_content.extend([
                f"### {finding.title} ({finding.finding_id})",
                f"**Severity:** {finding.severity.value}",
                f"**MITRE Technique:** {finding.mitre_technique}",
                f"**MITRE Tactic:** {finding.mitre_tactic.value}",
                f"**Confidence:** {finding.confidence_score:.1%}",
                "",
                f"**Description:** {finding.description}",
                "",
            ])

            if finding.evidence:
                md_content.append("**Evidence:**")
                for ev in finding.evidence:
                    md_content.append(f"- [{ev.evidence_id}] {ev.source}: {ev.description}")
                md_content.append("")

            if finding.remediation_steps:
                md_content.append("**Remediation Steps:**")
                for step in finding.remediation_steps:
                    md_content.append(f"1. {step}")
                md_content.append("")

        md_content.extend([
            "## MITRE ATT&CK Coverage",
        ])

        for tactic, count in report.mitre_coverage.items():
            md_content.append(f"- {tactic}: {count} finding(s)")

        if not filepath:
            filepath = str(self.output_dir / f"{report_id}.md")
        
        with open(filepath, 'w') as f:
            f.write('\n'.join(md_content))
        
        return filepath

    def get_report(self, report_id: str) -> Optional[ThreatHuntingReport]:
        """Get a report by ID"""
        return self._reports.get(report_id)

    def list_reports(self) -> List[Dict[str, str]]:
        """List all generated reports with metadata"""
        return [
            {
                "report_id": rid,
                "title": r.title,
                "generated_at": r.generated_at,
                "status": r.status.value,
                "findings_count": len(r.findings)
            }
            for rid, r in self._reports.items()
        ]


# Module exports
__all__ = [
    "ThreatHuntingReportGenerator",
    "ThreatHuntingReport",
    "ThreatFinding",
    "EvidenceItem",
    "ExecutiveSummary",
    "SeverityLevel",
    "MITRECategory",
    "ReportStatus"
]
