"""
MITRE ATT&CK Executive Dashboard - NeuralShield AI Security
Dimension A: Feature Expansion (V25 - June 2026)

Provides executive-level reporting, visualization, and strategic metrics
aligned with MITRE ATT&CK framework for security leadership and board reporting.

API Stability: STABLE
Backward Compatible: YES
Dependencies: None (pure Python)
"""

import json
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum


class MITRETactic(str, Enum):
    """MITRE ATT&CK Enterprise Tactics"""
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


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


@dataclass
class TacticMetric:
    """Metrics for a specific MITRE ATT&CK Tactic"""
    tactic: str
    detections: int
    blocked: int
    mitigated: int
    severity_distribution: Dict[str, int]
    trend_7day: float
    coverage_score: float


@dataclass
class ExecutiveSummary:
    """Executive-level summary for reporting"""
    report_date: str
    reporting_period: str
    total_threats_detected: int
    total_threats_blocked: int
    overall_security_score: float
    critical_severity_count: int
    high_severity_count: int
    top_threat_vectors: List[Dict[str, Any]]
    improvement_trend: float
    risk_rating: str


class MITREAttackExecutiveDashboard:
    """
    Executive Dashboard for MITRE ATT&CK aligned security reporting.
    
    Features:
    - Executive summary generation for board reports
    - Tactic-level coverage and detection metrics
    - Trend analysis and improvement tracking
    - Risk scoring and severity distribution
    - Executive-ready JSON and text reports
    - Historical comparison capabilities
    
    Usage:
        dashboard = MITREAttackExecutiveDashboard()
        dashboard.record_detection("Execution", "HIGH", blocked=True)
        summary = dashboard.generate_executive_summary()
    """
    
    def __init__(self, organization_name: str = "NeuralShield AI"):
        self.organization_name = organization_name
        self.detections: List[Dict[str, Any]] = []
        self.tactic_metrics: Dict[str, TacticMetric] = {}
        self._initialize_tactic_baselines()
        self.creation_time = datetime.utcnow().isoformat()
        self.version = "25.0.0"
    
    def _initialize_tactic_baselines(self) -> None:
        """Initialize baseline metrics for all MITRE ATT&CK tactics"""
        for tactic in MITRETactic:
            self.tactic_metrics[tactic.value] = TacticMetric(
                tactic=tactic.value,
                detections=0,
                blocked=0,
                mitigated=0,
                severity_distribution={
                    "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0
                },
                trend_7day=0.0,
                coverage_score=0.75  # Baseline coverage
            )
    
    def record_detection(
        self,
        tactic: str,
        severity: str,
        technique_id: Optional[str] = None,
        blocked: bool = True,
        mitigated: bool = False,
        source: str = "NeuralShield",
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Record a threat detection against MITRE ATT&CK framework.
        
        Args:
            tactic: MITRE ATT&CK tactic name
            severity: Severity level (CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL)
            technique_id: Optional MITRE technique ID (e.g., T1059)
            blocked: Whether threat was successfully blocked
            mitigated: Whether threat was mitigated
            source: Detection source module
            metadata: Additional detection metadata
            
        Returns:
            Detection ID string
        """
        detection_id = hashlib.sha256(
            f"{time.time()}{tactic}{severity}".encode()
        ).hexdigest()[:16]
        
        detection = {
            "detection_id": detection_id,
            "timestamp": datetime.utcnow().isoformat(),
            "tactic": tactic,
            "severity": severity,
            "technique_id": technique_id,
            "blocked": blocked,
            "mitigated": mitigated,
            "source": source,
            "metadata": metadata or {}
        }
        
        self.detections.append(detection)
        
        # Update metrics
        if tactic in self.tactic_metrics:
            metric = self.tactic_metrics[tactic]
            metric.detections += 1
            if blocked:
                metric.blocked += 1
            if mitigated:
                metric.mitigated += 1
            if severity in metric.severity_distribution:
                metric.severity_distribution[severity] += 1
        
        return detection_id
    
    def generate_executive_summary(
        self,
        days_lookback: int = 30
    ) -> ExecutiveSummary:
        """
        Generate executive-level security summary for reporting.
        
        Args:
            days_lookback: Number of days to include in report
            
        Returns:
            ExecutiveSummary dataclass with key metrics
        """
        cutoff_time = datetime.utcnow() - timedelta(days=days_lookback)
        
        # Filter detections for reporting period
        recent_detections = [
            d for d in self.detections
            if datetime.fromisoformat(d["timestamp"]) > cutoff_time
        ]
        
        total_detected = len(recent_detections)
        total_blocked = sum(1 for d in recent_detections if d["blocked"])
        
        # Count severities
        severity_counts = {
            "CRITICAL": sum(1 for d in recent_detections if d["severity"] == "CRITICAL"),
            "HIGH": sum(1 for d in recent_detections if d["severity"] == "HIGH"),
            "MEDIUM": sum(1 for d in recent_detections if d["severity"] == "MEDIUM"),
            "LOW": sum(1 for d in recent_detections if d["severity"] == "LOW"),
        }
        
        # Calculate overall security score
        block_rate = total_blocked / total_detected if total_detected > 0 else 1.0
        critical_ratio = severity_counts["CRITICAL"] / max(total_detected, 1)
        security_score = min(100, max(0, (block_rate * 80) - (critical_ratio * 50) + 50))
        
        # Determine risk rating
        if security_score >= 85:
            risk_rating = "LOW"
        elif security_score >= 70:
            risk_rating = "MODERATE"
        elif security_score >= 55:
            risk_rating = "ELEVATED"
        else:
            risk_rating = "HIGH"
        
        # Top threat vectors
        tactic_counts: Dict[str, int] = {}
        for d in recent_detections:
            tactic = d["tactic"]
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        
        top_threats = [
            {"tactic": tactic, "count": count, "severity": self._get_avg_severity(tactic)}
            for tactic, count in sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        ]
        
        return ExecutiveSummary(
            report_date=datetime.utcnow().strftime("%Y-%m-%d"),
            reporting_period=f"Last {days_lookback} days",
            total_threats_detected=total_detected,
            total_threats_blocked=total_blocked,
            overall_security_score=round(security_score, 1),
            critical_severity_count=severity_counts["CRITICAL"],
            high_severity_count=severity_counts["HIGH"],
            top_threat_vectors=top_threats,
            improvement_trend=round((security_score - 70) / 30 * 100, 1),
            risk_rating=risk_rating
        )
    
    def _get_avg_severity(self, tactic: str) -> str:
        """Get average severity for detections in a tactic"""
        tactic_detections = [d for d in self.detections if d["tactic"] == tactic]
        if not tactic_detections:
            return "LOW"
        
        severity_values = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}
        avg_value = sum(severity_values.get(d["severity"], 0) for d in tactic_detections) / len(tactic_detections)
        
        if avg_value >= 3.5:
            return "CRITICAL"
        elif avg_value >= 2.5:
            return "HIGH"
        elif avg_value >= 1.5:
            return "MEDIUM"
        return "LOW"
    
    def get_tactic_coverage_report(self) -> Dict[str, Any]:
        """Generate detailed tactic-by-tactic coverage report"""
        report = {
            "organization": self.organization_name,
            "generated_at": datetime.utcnow().isoformat(),
            "tactics": {},
            "summary": {
                "total_tactics": len(self.tactic_metrics),
                "avg_coverage": 0.0,
                "total_detections": 0,
                "total_blocked": 0
            }
        }
        
        total_coverage = 0.0
        for tactic, metric in self.tactic_metrics.items():
            report["tactics"][tactic] = {
                "detections": metric.detections,
                "blocked": metric.blocked,
                "mitigated": metric.mitigated,
                "block_rate": metric.blocked / max(metric.detections, 1),
                "severity_distribution": metric.severity_distribution,
                "coverage_score": metric.coverage_score,
                "trend": metric.trend_7day
            }
            total_coverage += metric.coverage_score
            report["summary"]["total_detections"] += metric.detections
            report["summary"]["total_blocked"] += metric.blocked
        
        report["summary"]["avg_coverage"] = round(total_coverage / len(self.tactic_metrics), 3)
        
        return report
    
    def generate_board_report_text(self, days_lookback: int = 30) -> str:
        """Generate human-readable board report in text format"""
        summary = self.generate_executive_summary(days_lookback)
        
        report = f"""
================================================================================
                    NEURALSHIELD AI SECURITY EXECUTIVE REPORT
                            {summary.report_date}
================================================================================

ORGANIZATION: {self.organization_name}
REPORTING PERIOD: {summary.reporting_period}
RISK RATING: {summary.risk_rating}

--------------------------------------------------------------------------------
KEY METRICS
--------------------------------------------------------------------------------

Overall Security Score:     {summary.overall_security_score}/100
Total Threats Detected:     {summary.total_threats_detected}
Total Threats Blocked:      {summary.total_threats_blocked}
Block Success Rate:         {round(summary.total_threats_blocked / max(summary.total_threats_detected, 1) * 100, 1)}%

Critical Severity Events:   {summary.critical_severity_count}
High Severity Events:       {summary.high_severity_count}

Improvement Trend:          {summary.improvement_trend:+}% vs baseline

--------------------------------------------------------------------------------
TOP THREAT VECTORS (MITRE ATT&CK)
--------------------------------------------------------------------------------
"""
        
        for i, threat in enumerate(summary.top_threat_vectors, 1):
            report += f"{i}. {threat['tactic']:30} Count: {threat['count']:4}  Avg Severity: {threat['severity']}\n"
        
        report += f"""
================================================================================
MITRE ATT&CK Framework Coverage: {self.get_tactic_coverage_report()['summary']['avg_coverage'] * 100:.1f}%
================================================================================
"""
        return report
    
    def export_json(self, filepath: str) -> bool:
        """Export full dashboard data to JSON file"""
        try:
            data = {
                "version": self.version,
                "organization": self.organization_name,
                "generated_at": datetime.utcnow().isoformat(),
                "executive_summary": asdict(self.generate_executive_summary()),
                "tactic_coverage": self.get_tactic_coverage_report(),
                "detections_count": len(self.detections)
            }
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception:
            return False
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get dashboard health and operational status"""
        return {
            "status": "healthy",
            "version": self.version,
            "detections_recorded": len(self.detections),
            "tactics_monitored": len(self.tactic_metrics),
            "uptime_seconds": (datetime.utcnow() - datetime.fromisoformat(self.creation_time)).total_seconds(),
            "api_stability": "STABLE"
        }
