"""
Threat Intelligence Automated Report Generator - NeuralShield-AI
June 2026 Production Implementation
Real, working automated security report generation engine.
Generates comprehensive, actionable threat intelligence reports with executive summaries,
technical details, mitigation recommendations, and compliance mappings.
"""
import datetime
import uuid
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from collections import Counter
class ReportType(Enum):
    """Types of security reports that can be generated."""
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_DEEP_DIVE = "technical_deep_dive"
    INCIDENT_POST_MORTEM = "incident_post_mortem"
    THREAT_LANDSCAPE = "threat_landscape"
    COMPLIANCE_ASSESSMENT = "compliance_assessment"
    WEEKLY_DIGEST = "weekly_digest"
class SeverityLevel(Enum):
    """Severity classification levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
@dataclass
class ThreatIndicator:
    """Individual threat indicator data."""
    indicator_id: str
    indicator_type: str  # ip, domain, hash, url, email
    value: str
    severity: SeverityLevel
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    source: str
    confidence: float  # 0.0 - 1.0
    mitre_techniques: List[str] = field(default_factory=list)
    associated_threat_actors: List[str] = field(default_factory=list)
    false_positive_rate: float = 0.0
@dataclass
class ReportSection:
    """Section within a generated report."""
    section_id: str
    title: str
    content: str
    priority: int
    metrics: Dict[str, Any] = field(default_factory=dict)
    visualizations: List[Dict[str, Any]] = field(default_factory=list)
@dataclass
class GeneratedReport:
    """Complete generated security report."""
    report_id: str
    report_type: ReportType
    title: str
    generated_at: datetime.datetime
    time_range_start: datetime.datetime
    time_range_end: datetime.datetime
    sections: List[ReportSection] = field(default_factory=list)
    summary_metrics: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[Dict[str, Any]] = field(default_factory=list)
    format: str = "markdown"  # markdown, html, json
    def to_markdown(self) -> str:
        """Convert report to markdown format."""
        lines = [f"# {self.title}", ""]
        lines.append(f"**Generated:** {self.generated_at.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Time Range:** {self.time_range_start.strftime('%Y-%m-%d')} to {self.time_range_end.strftime('%Y-%m-%d')}")
        lines.append(f"**Report Type:** {self.report_type.value}")
        lines.append("")
        
        # Executive Summary Metrics
        lines.append("## Key Metrics Summary")
        lines.append("")
        for key, value in self.summary_metrics.items():
            lines.append(f"- **{key.replace('_', ' ').title()}:** {value}")
        lines.append("")
        
        # Sections
        for section in sorted(self.sections, key=lambda s: s.priority):
            lines.append(f"## {section.title}")
            lines.append("")
            lines.append(section.content)
            lines.append("")
            
            if section.metrics:
                lines.append("### Metrics")
                lines.append("")
                for key, value in section.metrics.items():
                    lines.append(f"- {key.replace('_', ' ').title()}: {value}")
                lines.append("")
        
        # Recommendations
        if self.recommendations:
            lines.append("## Actionable Recommendations")
            lines.append("")
            for i, rec in enumerate(self.recommendations, 1):
                lines.append(f"### {i}. {rec.get('title', 'Recommendation')}")
                lines.append(f"**Priority:** {rec.get('priority', 'medium').upper()}")
                lines.append("")
                lines.append(rec.get('description', ''))
                lines.append("")
                if 'steps' in rec:
                    lines.append("**Implementation Steps:**")
                    for step in rec['steps']:
                        lines.append(f"- {step}")
                    lines.append("")
        
        return "\n".join(lines)
    def to_json(self) -> str:
        """Convert report to JSON format."""
        return json.dumps({
            "report_id": self.report_id,
            "report_type": self.report_type.value,
            "title": self.title,
            "generated_at": self.generated_at.isoformat(),
            "time_range": {
                "start": self.time_range_start.isoformat(),
                "end": self.time_range_end.isoformat()
            },
            "summary_metrics": self.summary_metrics,
            "sections": [
                {
                    "section_id": s.section_id,
                    "title": s.title,
                    "content": s.content,
                    "metrics": s.metrics
                }
                for s in self.sections
            ],
            "recommendations": self.recommendations
        }, indent=2)
class ThreatIntelligenceReportGenerator:
    """
    Production-grade automated threat intelligence report generator.
    
    Features:
    - Multiple report types for different audiences
    - Executive summaries with key metrics
    - Technical deep dives with IOC details
    - MITRE ATT&CK framework mapping
    - Prioritized actionable recommendations
    - Compliance alignment reporting
    - Multiple output formats (markdown, JSON)
    """
    
    def __init__(self, organization_name: str = "Security Operations Center"):
        """
        Initialize the report generator.
        
        Args:
            organization_name: Name for report branding
        """
        self.organization_name = organization_name
        self.reports_generated = 0
        self._report_history: List[GeneratedReport] = []
    
    def generate_executive_summary(
        self,
        threat_indicators: List[ThreatIndicator],
        time_range_days: int = 7,
        include_recommendations: bool = True
    ) -> GeneratedReport:
        """
        Generate an executive summary report for leadership.
        
        Args:
            threat_indicators: List of threat indicators to analyze
            time_range_days: Number of days covered by this report
            include_recommendations: Whether to include recommendations
            
        Returns:
            Generated executive summary report
        """
        end_time = datetime.datetime.now()
        start_time = end_time - datetime.timedelta(days=time_range_days)
        
        report = GeneratedReport(
            report_id=str(uuid.uuid4()),
            report_type=ReportType.EXECUTIVE_SUMMARY,
            title=f"{self.organization_name} - Threat Intelligence Executive Summary",
            generated_at=end_time,
            time_range_start=start_time,
            time_range_end=end_time
        )
        
        # Calculate summary metrics
        report.summary_metrics = self._calculate_summary_metrics(threat_indicators)
        
        # Executive Overview section
        overview_content = self._generate_executive_overview(threat_indicators, report.summary_metrics)
        report.sections.append(ReportSection(
            section_id="executive_overview",
            title="Executive Overview",
            content=overview_content,
            priority=1,
            metrics=report.summary_metrics
        ))
        
        # Threat Trend Analysis
        trend_content = self._generate_threat_trend_analysis(threat_indicators)
        report.sections.append(ReportSection(
            section_id="threat_trends",
            title="Threat Trend Analysis",
            content=trend_content,
            priority=2
        ))
        
        # Critical Threats section
        critical_content = self._generate_critical_threats_summary(threat_indicators)
        report.sections.append(ReportSection(
            section_id="critical_threats",
            title="Critical Threats Requiring Immediate Attention",
            content=critical_content,
            priority=3
        ))
        
        if include_recommendations:
            report.recommendations = self._generate_prioritized_recommendations(threat_indicators)
        
        self.reports_generated += 1
        self._report_history.append(report)
        return report
    
    def generate_technical_deep_dive(
        self,
        threat_indicators: List[ThreatIndicator],
        include_raw_iocs: bool = True
    ) -> GeneratedReport:
        """
        Generate a technical deep dive report for security analysts.
        
        Args:
            threat_indicators: List of threat indicators
            include_raw_iocs: Whether to include raw IOC lists
            
        Returns:
            Generated technical report
        """
        end_time = datetime.datetime.now()
        start_time = end_time - datetime.timedelta(days=7)
        
        report = GeneratedReport(
            report_id=str(uuid.uuid4()),
            report_type=ReportType.TECHNICAL_DEEP_DIVE,
            title=f"{self.organization_name} - Technical Threat Intelligence Report",
            generated_at=end_time,
            time_range_start=start_time,
            time_range_end=end_time
        )
        
        report.summary_metrics = self._calculate_summary_metrics(threat_indicators)
        
        # IOC Breakdown
        ioc_content = self._generate_ioc_breakdown(threat_indicators)
        report.sections.append(ReportSection(
            section_id="ioc_breakdown",
            title="Indicator of Compromise (IOC) Breakdown",
            content=ioc_content,
            priority=1
        ))
        
        # MITRE ATT&CK Mapping
        mitre_content = self._generate_mitre_mapping_summary(threat_indicators)
        report.sections.append(ReportSection(
            section_id="mitre_mapping",
            title="MITRE ATT&CK Technique Mapping",
            content=mitre_content,
            priority=2
        ))
        
        # Threat Actor Analysis
        actor_content = self._generate_threat_actor_analysis(threat_indicators)
        report.sections.append(ReportSection(
            section_id="threat_actors",
            title="Threat Actor Intelligence",
            content=actor_content,
            priority=3
        ))
        
        if include_raw_iocs:
            raw_ioc_content = self._generate_raw_ioc_list(threat_indicators)
            report.sections.append(ReportSection(
                section_id="raw_iocs",
                title="Raw IOC List for Blocking",
                content=raw_ioc_content,
                priority=4
            ))
        
        self.reports_generated += 1
        self._report_history.append(report)
        return report
    
    def generate_compliance_assessment(
        self,
        threat_indicators: List[ThreatIndicator],
        framework: str = "NIST"
    ) -> GeneratedReport:
        """
        Generate a compliance assessment report.
        
        Args:
            threat_indicators: List of threat indicators
            framework: Compliance framework (NIST, ISO27001, PCI-DSS)
            
        Returns:
            Generated compliance report
        """
        end_time = datetime.datetime.now()
        start_time = end_time - datetime.timedelta(days=30)
        
        report = GeneratedReport(
            report_id=str(uuid.uuid4()),
            report_type=ReportType.COMPLIANCE_ASSESSMENT,
            title=f"{self.organization_name} - Security Compliance Assessment ({framework})",
            generated_at=end_time,
            time_range_start=start_time,
            time_range_end=end_time
        )
        
        report.summary_metrics = self._calculate_summary_metrics(threat_indicators)
        
        # Compliance Status
        compliance_content = self._generate_compliance_status(threat_indicators, framework)
        report.sections.append(ReportSection(
            section_id="compliance_status",
            title=f"{framework} Compliance Status",
            content=compliance_content,
            priority=1
        ))
        
        # Control Effectiveness
        control_content = self._generate_control_effectiveness(threat_indicators)
        report.sections.append(ReportSection(
            section_id="control_effectiveness",
            title="Security Control Effectiveness",
            content=control_content,
            priority=2
        ))
        
        self.reports_generated += 1
        self._report_history.append(report)
        return report
    
    def _calculate_summary_metrics(self, indicators: List[ThreatIndicator]) -> Dict[str, Any]:
        """Calculate summary metrics from threat indicators."""
        if not indicators:
            return {
                "total_threats": 0,
                "critical_threats": 0,
                "high_threats": 0,
                "medium_threats": 0,
                "unique_ips": 0,
                "unique_domains": 0,
                "average_confidence": 0.0
            }
        
        severity_counts = Counter(i.severity.value for i in indicators)
        type_counts = Counter(i.indicator_type for i in indicators)
        avg_confidence = sum(i.confidence for i in indicators) / len(indicators)
        
        return {
            "total_threats": len(indicators),
            "critical_threats": severity_counts.get("critical", 0),
            "high_threats": severity_counts.get("high", 0),
            "medium_threats": severity_counts.get("medium", 0),
            "low_threats": severity_counts.get("low", 0),
            "unique_ips": type_counts.get("ip", 0),
            "unique_domains": type_counts.get("domain", 0),
            "unique_hashes": type_counts.get("hash", 0),
            "unique_urls": type_counts.get("url", 0),
            "average_confidence": round(avg_confidence, 2),
            "distinct_sources": len(set(i.source for i in indicators))
        }
    
    def _generate_executive_overview(self, indicators: List[ThreatIndicator], metrics: Dict[str, Any]) -> str:
        """Generate executive overview narrative."""
        if not indicators:
            return "No threat indicators detected during this reporting period. Security posture remains stable."
        
        critical_count = metrics.get("critical_threats", 0)
        high_count = metrics.get("high_threats", 0)
        total = metrics.get("total_threats", 0)
        
        narrative = []
        
        if critical_count > 0 or high_count > 0:
            risk_level = "ELEVATED" if critical_count > 0 else "MODERATE"
            narrative.append(f"**Overall Threat Level: {risk_level}**")
            narrative.append("")
            narrative.append(f"During this reporting period, the security monitoring infrastructure detected {total} distinct threat indicators.")
            
            if critical_count > 0:
                narrative.append(f"Of particular concern are the {critical_count} CRITICAL severity threats that require immediate executive attention and resource allocation.")
            
            if high_count > 0:
                narrative.append(f"An additional {high_count} HIGH severity threats were identified that should be addressed within the next 24-48 hours.")
        else:
            narrative.append("**Overall Threat Level: LOW**")
            narrative.append("")
            narrative.append(f"The organization detected {total} threat indicators during this period, all classified at MEDIUM or LOW severity. Security posture remains robust.")
        
        narrative.append("")
        narrative.append(f"Threat intelligence was sourced from {metrics.get('distinct_sources', 0)} distinct feeds with an average confidence score of {metrics.get('average_confidence', 0)}.")
        
        return "\n".join(narrative)
    
    def _generate_threat_trend_analysis(self, indicators: List[ThreatIndicator]) -> str:
        """Generate threat trend analysis content."""
        if not indicators:
            return "No trend data available for the reporting period."
        
        # Group by severity
        severity_trends = Counter(i.severity.value for i in indicators)
        type_trends = Counter(i.indicator_type for i in indicators)
        
        content = ["### Threat Distribution by Severity", ""]
        for severity in ['critical', 'high', 'medium', 'low']:
            count = severity_trends.get(severity, 0)
            pct = round((count / len(indicators)) * 100, 1) if indicators else 0
            content.append(f"- **{severity.upper()}**: {count} indicators ({pct}%)")
        
        content.append("")
        content.append("### Threat Distribution by Type")
        content.append("")
        for ioc_type, count in type_trends.most_common():
            pct = round((count / len(indicators)) * 100, 1)
            content.append(f"- **{ioc_type.upper()}**: {count} ({pct}%)")
        
        return "\n".join(content)
    
    def _generate_critical_threats_summary(self, indicators: List[ThreatIndicator]) -> str:
        """Generate critical threats summary."""
        critical = [i for i in indicators if i.severity == SeverityLevel.CRITICAL]
        high = [i for i in indicators if i.severity == SeverityLevel.HIGH]
        
        if not critical and not high:
            return "No CRITICAL or HIGH severity threats detected during this reporting period."
        
        content = []
        
        if critical:
            content.append("#### CRITICAL Severity Threats")
            content.append("")
            for threat in critical[:5]:  # Top 5
                content.append(f"- **{threat.indicator_type.upper()}**: `{threat.value}`")
                content.append(f"  - Source: {threat.source}")
                content.append(f"  - Confidence: {round(threat.confidence * 100, 1)}%")
                if threat.mitre_techniques:
                    content.append(f"  - MITRE Techniques: {', '.join(threat.mitre_techniques[:3])}")
                content.append("")
        
        if high:
            content.append("#### HIGH Severity Threats")
            content.append("")
            for threat in high[:5]:  # Top 5
                content.append(f"- **{threat.indicator_type.upper()}**: `{threat.value}`")
                content.append(f"  - Source: {threat.source}")
                content.append(f"  - Confidence: {round(threat.confidence * 100, 1)}%")
                content.append("")
        
        return "\n".join(content)
    
    def _generate_ioc_breakdown(self, indicators: List[ThreatIndicator]) -> str:
        """Generate detailed IOC breakdown."""
        content = ["This section provides detailed breakdown of all indicators by type for analyst review.", ""]
        
        for ioc_type in ['ip', 'domain', 'hash', 'url', 'email']:
            type_indicators = [i for i in indicators if i.indicator_type == ioc_type]
            if type_indicators:
                content.append(f"### {ioc_type.upper()} Indicators ({len(type_indicators)})")
                content.append("")
                content.append("| Value | Severity | Confidence | Source |")
                content.append("|-------|----------|------------|--------|")
                for ioc in sorted(type_indicators, key=lambda x: x.severity.value):
                    content.append(f"| `{ioc.value[:50]}` | {ioc.severity.value.upper()} | {round(ioc.confidence * 100, 1)}% | {ioc.source} |")
                content.append("")
        
        return "\n".join(content)
    
    def _generate_mitre_mapping_summary(self, indicators: List[ThreatIndicator]) -> str:
        """Generate MITRE ATT&CK mapping summary."""
        all_techniques = []
        for i in indicators:
            all_techniques.extend(i.mitre_techniques)
        
        if not all_techniques:
            return "No MITRE ATT&CK technique mappings available for the current indicator set."
        
        technique_counts = Counter(all_techniques)
        
        content = ["### Most Frequently Observed Techniques", ""]
        for technique, count in technique_counts.most_common(10):
            content.append(f"- **{technique}**: Observed {count} time(s)")
        
        content.append("")
        content.append("### Tactical Distribution")
        content.append("")
        content.append("- Initial Access: Check phishing and external remote services")
        content.append("- Execution: Monitor for suspicious process execution")
        content.append("- Persistence: Review registry and scheduled task modifications")
        content.append("- Command & Control: Inspect unusual network connections")
        
        return "\n".join(content)
    
    def _generate_threat_actor_analysis(self, indicators: List[ThreatIndicator]) -> str:
        """Generate threat actor analysis."""
        all_actors = []
        for i in indicators:
            all_actors.extend(i.associated_threat_actors)
        
        if not all_actors:
            return "No specific threat actor associations identified for the current indicators."
        
        actor_counts = Counter(all_actors)
        
        content = ["### Identified Threat Actors", ""]
        for actor, count in actor_counts.most_common():
            content.append(f"- **{actor}**: Associated with {count} indicator(s)")
        
        content.append("")
        content.append("### Recommended Actions")
        content.append("")
        content.append("1. Cross-reference identified actors with MITRE ATT&CK threat groups")
        content.append("2. Update detection rules for actor-specific TTPs")
        content.append("3. Monitor for follow-on activity from associated groups")
        
        return "\n".join(content)
    
    def _generate_raw_ioc_list(self, indicators: List[ThreatIndicator]) -> str:
        """Generate raw IOC list suitable for blocking."""
        content = ["### Indicators for Blocking/Monitoring", ""]
        content.append("Below is a consolidated list of indicators for direct import into security tools.")
        content.append("")
        
        for ioc_type in ['ip', 'domain', 'hash', 'url']:
            type_indicators = [i for i in indicators if i.indicator_type == ioc_type and i.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]]
            if type_indicators:
                content.append(f"#### {ioc_type.upper()}s (High/Critical Only)")
                content.append("")
                content.append("```")
                for ioc in type_indicators:
                    content.append(ioc.value)
                content.append("```")
                content.append("")
        
        return "\n".join(content)
    
    def _generate_compliance_status(self, indicators: List[ThreatIndicator], framework: str) -> str:
        """Generate compliance status content."""
        metrics = self._calculate_summary_metrics(indicators)
        critical = metrics.get("critical_threats", 0)
        high = metrics.get("high_threats", 0)
        
        content = [f"### {framework} Security Posture Assessment", ""]
        
        if critical == 0 and high == 0:
            content.append("**Status: COMPLIANT**")
            content.append("")
            content.append("No critical or high severity threats detected. Security controls appear to be operating effectively.")
        elif critical > 0:
            content.append("**Status: NON-COMPLIANT - IMMEDIATE ACTION REQUIRED**")
            content.append("")
            content.append(f"Critical security issues detected ({critical} CRITICAL threats). Immediate remediation required to maintain compliance.")
        else:
            content.append("**Status: AT RISK**")
            content.append("")
            content.append(f"High severity threats detected ({high} HIGH). Remediation required within compliance timeframes.")
        
        return "\n".join(content)
    
    def _generate_control_effectiveness(self, indicators: List[ThreatIndicator]) -> str:
        """Generate control effectiveness analysis."""
        content = ["### Security Control Effectiveness Metrics", ""]
        
        high_confidence = [i for i in indicators if i.confidence >= 0.8]
        content.append(f"- **Detection Rate**: {len(indicators)} threats detected")
        content.append(f"- **High Confidence Detections**: {len(high_confidence)} ({round(len(high_confidence)/len(indicators)*100 if indicators else 0, 1)}%)")
        content.append(f"- **False Positive Estimate**: {round(sum(i.false_positive_rate for i in indicators) / len(indicators) * 100 if indicators else 0, 1)}%")
        
        return "\n".join(content)
    
    def _generate_prioritized_recommendations(self, indicators: List[ThreatIndicator]) -> List[Dict[str, Any]]:
        """Generate prioritized actionable recommendations."""
        recommendations = []
        critical = [i for i in indicators if i.severity == SeverityLevel.CRITICAL]
        high = [i for i in indicators if i.severity == SeverityLevel.HIGH]
        
        if critical:
            recommendations.append({
                "title": "Immediate Blocking of Critical IOCs",
                "priority": "CRITICAL",
                "description": f"Block {len(critical)} CRITICAL severity indicators immediately at the network perimeter, email gateway, and endpoint protection layers.",
                "steps": [
                    "Import IOC list into firewall/NGFW",
                    "Update email security gateway rules",
                    "Deploy endpoint detection rules",
                    "Verify blocks are operational within 1 hour"
                ]
            })
        
        if high:
            recommendations.append({
                "title": "Rapid Remediation of High Severity Threats",
                "priority": "HIGH",
                "description": f"Address {len(high)} HIGH severity indicators within 24-48 hours through targeted blocking and monitoring.",
                "steps": [
                    "Add indicators to SIEM watchlist",
                    "Review logs for past activity",
                    "Implement blocks in security tools",
                    "Schedule follow-up verification"
                ]
            })
        
        recommendations.append({
            "title": "Detection Rule Enhancement",
            "priority": "MEDIUM",
            "description": "Update detection signatures based on observed threat actor TTPs and MITRE techniques.",
            "steps": [
                "Review MITRE ATT&CK mappings",
                "Create/update detection analytics",
                "Test rules in staging environment",
                "Deploy to production sensors"
            ]
        })
        
        recommendations.append({
            "title": "Threat Intelligence Feed Optimization",
            "priority": "MEDIUM",
            "description": "Continuously refine intelligence sources based on confidence scores and false positive rates.",
            "steps": [
                "Review feed quality metrics",
                "Deprioritize low-confidence sources",
                "Add specialized feeds for observed threats",
                "Implement feed deduplication"
            ]
        })
        
        return recommendations
    
    def get_report_history(self) -> List[GeneratedReport]:
        """Get history of all generated reports."""
        return self._report_history.copy()
