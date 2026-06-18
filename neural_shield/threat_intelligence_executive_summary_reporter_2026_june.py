"""
Threat Intelligence Executive Summary Reporter
Production-grade security reporting engine for NeuralShield-AI

Generates executive-level security reports, executive summaries,
and board-ready threat intelligence briefings with metrics and insights.
"""

import json
import hashlib
import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from collections import Counter, defaultdict
from enum import Enum


class SeverityLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ReportType(Enum):
    EXECUTIVE_SUMMARY = "EXECUTIVE_SUMMARY"
    BOARD_BRIEFING = "BOARD_BRIEFING"
    TECHNICAL_DETAIL = "TECHNICAL_DETAIL"
    WEEKLY_DIGEST = "WEEKLY_DIGEST"


@dataclass
class ThreatEvent:
    event_id: str
    timestamp: str
    severity: str
    threat_type: str
    source: str
    description: str
    mitre_technique: Optional[str] = None
    affected_assets: Optional[List[str]] = None
    confidence_score: float = 0.0


@dataclass
class ReportMetrics:
    total_threats: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    unique_threat_types: int = 0
    unique_sources: int = 0
    avg_confidence: float = 0.0
    top_threat_types: List[tuple] = None
    top_sources: List[tuple] = None
    mitre_coverage: Dict[str, int] = None


class ThreatIntelligenceExecutiveSummaryReporter:
    """
    Production-grade executive summary reporter for threat intelligence.
    
    Features:
    - Generates multiple report formats (executive, board, technical, weekly)
    - Calculates comprehensive security metrics
    - Provides risk assessment and trend analysis
    - Exports to JSON, Markdown, and plain text formats
    - Includes executive recommendations
    """
    
    def __init__(self, organization_name: str = "Enterprise Security"):
        self.organization_name = organization_name
        self.threat_events: List[ThreatEvent] = []
        self.generated_reports: List[Dict[str, Any]] = []
        
    def add_threat_event(self, event: ThreatEvent) -> None:
        """Add a threat event to the reporting database"""
        self.threat_events.append(event)
        
    def add_threat_events_batch(self, events: List[ThreatEvent]) -> None:
        """Add multiple threat events"""
        self.threat_events.extend(events)
        
    def calculate_metrics(self) -> ReportMetrics:
        """Calculate comprehensive threat metrics"""
        if not self.threat_events:
            return ReportMetrics()
            
        metrics = ReportMetrics()
        metrics.total_threats = len(self.threat_events)
        
        # Severity counts
        severity_counter = Counter(e.severity.upper() for e in self.threat_events)
        metrics.critical_count = severity_counter.get("CRITICAL", 0)
        metrics.high_count = severity_counter.get("HIGH", 0)
        metrics.medium_count = severity_counter.get("MEDIUM", 0)
        metrics.low_count = severity_counter.get("LOW", 0)
        
        # Threat types
        type_counter = Counter(e.threat_type for e in self.threat_events)
        metrics.unique_threat_types = len(type_counter)
        metrics.top_threat_types = type_counter.most_common(5)
        
        # Sources
        source_counter = Counter(e.source for e in self.threat_events)
        metrics.unique_sources = len(source_counter)
        metrics.top_sources = source_counter.most_common(5)
        
        # Confidence
        confidences = [e.confidence_score for e in self.threat_events if e.confidence_score > 0]
        if confidences:
            metrics.avg_confidence = sum(confidences) / len(confidences)
            
        # MITRE coverage
        mitre_counter = Counter(
            e.mitre_technique for e in self.threat_events 
            if e.mitre_technique
        )
        metrics.mitre_coverage = dict(mitre_counter.most_common(10))
        
        return metrics
        
    def calculate_risk_score(self, metrics: ReportMetrics) -> Dict[str, Any]:
        """Calculate overall risk score and assessment"""
        total = metrics.total_threats
        if total == 0:
            return {
                "risk_level": "LOW",
                "risk_score": 0.0,
                "assessment": "No threats detected - security posture is healthy"
            }
            
        # Weighted risk calculation
        weighted_score = (
            metrics.critical_count * 100 +
            metrics.high_count * 50 +
            metrics.medium_count * 20 +
            metrics.low_count * 5
        ) / total
        
        if weighted_score >= 70:
            risk_level = "CRITICAL"
            assessment = "Immediate action required - critical threats detected"
        elif weighted_score >= 40:
            risk_level = "HIGH"
            assessment = "Elevated risk - security review recommended"
        elif weighted_score >= 20:
            risk_level = "MEDIUM"
            assessment = "Moderate risk - routine monitoring advised"
        else:
            risk_level = "LOW"
            assessment = "Low risk - security posture is healthy"
            
        return {
            "risk_level": risk_level,
            "risk_score": round(weighted_score, 2),
            "assessment": assessment,
            "weighted_components": {
                "critical_contribution": round((metrics.critical_count * 100) / max(total, 1), 2),
                "high_contribution": round((metrics.high_count * 50) / max(total, 1), 2),
                "medium_contribution": round((metrics.medium_count * 20) / max(total, 1), 2),
                "low_contribution": round((metrics.low_count * 5) / max(total, 1), 2)
            }
        }
        
    def generate_executive_recommendations(self, risk_data: Dict, metrics: ReportMetrics) -> List[str]:
        """Generate executive security recommendations"""
        recommendations = []
        
        if risk_data["risk_level"] == "CRITICAL":
            recommendations.append("🔴 ACTIVATE INCIDENT RESPONSE: Immediate security team mobilization required")
            recommendations.append("🔴 CONDUCT EMERGENCY SECURITY REVIEW: All critical systems must be audited")
            recommendations.append("🔴 ENABLE HEIGHTENED MONITORING: Increase logging and alerting thresholds")
            
        if risk_data["risk_level"] in ["CRITICAL", "HIGH"]:
            recommendations.append("🟠 SCHEDULE EXECUTIVE BRIEFING: Present findings to leadership within 24 hours")
            recommendations.append("🟠 REVIEW ACCESS CONTROLS: Audit all privileged accounts and permissions")
            recommendations.append("🟠 UPDATE THREAT INTELLIGENCE FEEDS: Ensure latest IOCs are deployed")
            
        if metrics.critical_count > 0:
            recommendations.append(f"⚠️  ADDRESS {metrics.critical_count} CRITICAL THREAT(S): Prioritize remediation of critical findings")
            
        if metrics.high_count > 3:
            recommendations.append(f"⚠️  REMEDIATE {metrics.high_count} HIGH-SEVERITY ISSUES: Schedule within 72 hours")
            
        # Always applicable best practices
        recommendations.extend([
            "✅ CONDUCT REGULAR SECURITY TRAINING: Continue employee security awareness programs",
            "✅ MAINTAIN PATCH MANAGEMENT: Ensure all systems are up-to-date",
            "✅ REVIEW BACKUP STRATEGY: Verify data recovery procedures are tested",
            "✅ IMPLEMENT ZERO-TRUST ARCHITECTURE: Continue least-privilege access enforcement"
        ])
        
        return recommendations
        
    def generate_report(self, report_type: ReportType = ReportType.EXECUTIVE_SUMMARY) -> Dict[str, Any]:
        """Generate a comprehensive threat intelligence report"""
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"
        metrics = self.calculate_metrics()
        risk_data = self.calculate_risk_score(metrics)
        recommendations = self.generate_executive_recommendations(risk_data, metrics)
        
        report_id = hashlib.sha256(
            f"{timestamp}{self.organization_name}{metrics.total_threats}".encode()
        ).hexdigest()[:16]
        
        report = {
            "report_id": report_id,
            "report_type": report_type.value,
            "generated_at": timestamp,
            "organization": self.organization_name,
            "summary": {
                "executive_overview": self._generate_executive_overview(metrics, risk_data),
                "risk_assessment": risk_data,
                "metrics": asdict(metrics),
                "key_findings": self._generate_key_findings(metrics, risk_data),
                "recommendations": recommendations
            },
            "threat_breakdown": {
                "by_severity": {
                    "CRITICAL": metrics.critical_count,
                    "HIGH": metrics.high_count,
                    "MEDIUM": metrics.medium_count,
                    "LOW": metrics.low_count
                },
                "by_type": dict(metrics.top_threat_types) if metrics.top_threat_types else {},
                "by_source": dict(metrics.top_sources) if metrics.top_sources else {},
                "mitre_coverage": metrics.mitre_coverage or {}
            },
            "report_metadata": {
                "total_events_analyzed": metrics.total_threats,
                "report_version": "1.0.0",
                "engine": "NeuralShield-AI Executive Reporter v2026.06"
            }
        }
        
        self.generated_reports.append(report)
        return report
        
    def _generate_executive_overview(self, metrics: ReportMetrics, risk_data: Dict) -> str:
        """Generate human-readable executive overview text"""
        overview = [
            f"SECURITY EXECUTIVE REPORT - {self.organization_name}",
            f"",
            f"Analysis Period: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            f"Total Threat Events Analyzed: {metrics.total_threats}",
            f"",
            f"RISK ASSESSMENT: {risk_data['risk_level']} (Score: {risk_data['risk_score']}/100)",
            f"{risk_data['assessment']}",
            f"",
            f"SEVERITY BREAKDOWN:",
            f"  Critical: {metrics.critical_count} events",
            f"  High:     {metrics.high_count} events",
            f"  Medium:   {metrics.medium_count} events", 
            f"  Low:      {metrics.low_count} events"
        ]
        return "\n".join(overview)
        
    def _generate_key_findings(self, metrics: ReportMetrics, risk_data: Dict) -> List[str]:
        """Generate key findings bullet points"""
        findings = []
        
        findings.append(f"Total security events processed: {metrics.total_threats}")
        
        if metrics.critical_count > 0:
            findings.append(f"CRITICAL ALERT: {metrics.critical_count} critical severity threat(s) require immediate attention")
            
        if metrics.top_threat_types:
            top_type, top_count = metrics.top_threat_types[0]
            findings.append(f"Most prevalent threat type: {top_type} ({top_count} occurrences)")
            
        if metrics.avg_confidence > 0:
            findings.append(f"Average threat confidence score: {metrics.avg_confidence:.2f}")
            
        findings.append(f"Unique threat vectors identified: {metrics.unique_threat_types}")
        findings.append(f"Threat sources monitored: {metrics.unique_sources}")
        
        return findings
        
    def export_to_markdown(self, report: Dict[str, Any]) -> str:
        """Export report to Markdown format"""
        md = [
            f"# {report['organization']} - Threat Intelligence Executive Report",
            f"",
            f"**Report ID:** `{report['report_id']}`",
            f"**Generated:** {report['generated_at']}",
            f"**Type:** {report['report_type']}",
            f"",
            f"## Executive Overview",
            f"```",
            report['summary']['executive_overview'],
            f"```",
            f"",
            f"## Risk Assessment",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Risk Level | **{report['summary']['risk_assessment']['risk_level']}** |",
            f"| Risk Score | {report['summary']['risk_assessment']['risk_score']}/100 |",
            f"",
            f"## Security Metrics",
            f"",
            f"| Category | Count |",
            f"|----------|-------|",
            f"| Total Threats | {report['summary']['metrics']['total_threats']} |",
            f"| Critical | {report['summary']['metrics']['critical_count']} |",
            f"| High | {report['summary']['metrics']['high_count']} |",
            f"| Medium | {report['summary']['metrics']['medium_count']} |",
            f"| Low | {report['summary']['metrics']['low_count']} |",
            f"",
            f"## Key Findings",
            f""
        ]
        
        for finding in report['summary']['key_findings']:
            md.append(f"- {finding}")
            
        md.extend([
            f"",
            f"## Executive Recommendations",
            f""
        ])
        
        for rec in report['summary']['recommendations']:
            md.append(f"- {rec}")
            
        return "\n".join(md)
        
    def export_to_json(self, report: Dict[str, Any], pretty: bool = True) -> str:
        """Export report to JSON format"""
        indent = 2 if pretty else None
        return json.dumps(report, indent=indent)
        
    def clear_events(self) -> None:
        """Clear all stored threat events"""
        self.threat_events.clear()
