"""
Security Metrics & Analytics Dashboard - NeuralShield-AI
June 2026 Production Release
Real-time security analytics, threat metrics aggregation, and compliance reporting.
Provides security scoring, trend analysis, and actionable insights dashboard.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
import json
import csv
import uuid
from pathlib import Path
import statistics


class SecurityLevel(str, Enum):
    """Overall security posture levels"""
    EXCELLENT = "EXCELLENT"
    GOOD = "GOOD"
    FAIR = "FAIR"
    POOR = "POOR"
    CRITICAL = "CRITICAL"


class MetricType(str, Enum):
    """Types of security metrics tracked"""
    THREAT_DETECTION_RATE = "THREAT_DETECTION_RATE"
    FALSE_POSITIVE_RATE = "FALSE_POSITIVE_RATE"
    RESPONSE_TIME = "RESPONSE_TIME"
    BLOCKED_ATTACKS = "BLOCKED_ATTACKS"
    ALERTS_GENERATED = "ALERTS_GENERATED"
    SESSIONS_MONITORED = "SESSIONS_MONITORED"
    PII_REDACTIONS = "PII_REDACTIONS"
    JAILBREAK_ATTEMPTS = "JAILBREAK_ATTEMPTS"
    PROMPT_INJECTIONS = "PROMPT_INJECTIONS"
    HALLUCINATIONS_DETECTED = "HALLUCINATIONS_DETECTED"


class AlertSeverity(str, Enum):
    """Alert severity levels for dashboard notifications"""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class MetricDataPoint:
    """Single metric data point with timestamp"""
    metric_type: MetricType
    value: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tags: Dict[str, str] = field(default_factory=dict)
    source: str = "unknown"


@dataclass
class DashboardAlert:
    """Dashboard alert for threshold breaches"""
    severity: AlertSeverity
    message: str
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    metric_type: Optional[MetricType] = None
    current_value: Optional[float] = None
    threshold_value: Optional[float] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged: bool = False


@dataclass
class SecurityScore:
    """Calculated security score with breakdown"""
    overall_score: float  # 0-100
    security_level: SecurityLevel
    detection_effectiveness: float
    response_effectiveness: float
    coverage_score: float
    accuracy_score: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    factors: Dict[str, float] = field(default_factory=dict)


@dataclass
class TrendAnalysis:
    """Trend analysis results for metrics"""
    metric_type: MetricType
    trend_direction: str  # "improving", "worsening", "stable"
    trend_percentage: float
    baseline_value: float
    current_value: float
    period_hours: int
    confidence: float


@dataclass
class DashboardReport:
    """Generated security dashboard report"""
    report_type: str
    time_range_start: datetime
    time_range_end: datetime
    security_score: SecurityScore
    metrics_summary: Dict[str, Any]
    top_threats: List[Dict[str, Any]]
    alerts: List[DashboardAlert]
    trends: List[TrendAnalysis]
    recommendations: List[str]
    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class AlertThreshold:
    """Threshold configuration for metric alerts"""
    
    def __init__(self):
        self.thresholds: Dict[MetricType, Tuple[float, AlertSeverity]] = {
            MetricType.FALSE_POSITIVE_RATE: (0.15, AlertSeverity.WARNING),
            MetricType.JAILBREAK_ATTEMPTS: (10.0, AlertSeverity.CRITICAL),
            MetricType.PROMPT_INJECTIONS: (5.0, AlertSeverity.ERROR),
            MetricType.RESPONSE_TIME: (5000.0, AlertSeverity.WARNING),  # ms
        }
    
    def check_threshold(self, metric: MetricDataPoint) -> Optional[DashboardAlert]:
        """Check if metric value breaches any threshold"""
        if metric.metric_type in self.thresholds:
            threshold, severity = self.thresholds[metric.metric_type]
            if metric.value > threshold:
                return DashboardAlert(
                    severity=severity,
                    message=f"{metric.metric_type.value} breached threshold: {metric.value:.2f} > {threshold}",
                    metric_type=metric.metric_type,
                    current_value=metric.value,
                    threshold_value=threshold
                )
        return None
    
    def set_threshold(self, metric_type: MetricType, value: float, severity: AlertSeverity) -> None:
        """Set custom threshold for a metric"""
        self.thresholds[metric_type] = (value, severity)


class MetricsAggregator:
    """Aggregates and processes security metrics data"""
    
    def __init__(self, max_history_points: int = 10000):
        self.metrics_history: deque = deque(maxlen=max_history_points)
        self.metric_sums: Dict[MetricType, float] = defaultdict(float)
        self.metric_counts: Dict[MetricType, int] = defaultdict(int)
        self.threshold_engine = AlertThreshold()
        self.active_alerts: List[DashboardAlert] = []
    
    def record_metric(self, metric: MetricDataPoint) -> Optional[DashboardAlert]:
        """Record a new metric data point"""
        self.metrics_history.append(metric)
        self.metric_sums[metric.metric_type] += metric.value
        self.metric_counts[metric.metric_type] += 1
        
        # Check threshold
        alert = self.threshold_engine.check_threshold(metric)
        if alert:
            self.active_alerts.append(alert)
        return alert
    
    def get_metric_average(self, metric_type: MetricType, window_minutes: int = 60) -> float:
        """Get average value for a metric in the time window"""
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        values = [
            m.value for m in self.metrics_history
            if m.metric_type == metric_type and m.timestamp >= cutoff
        ]
        return statistics.mean(values) if values else 0.0
    
    def get_metric_sum(self, metric_type: MetricType, window_minutes: int = 60) -> float:
        """Get sum of values for a metric in the time window"""
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        return sum(
            m.value for m in self.metrics_history
            if m.metric_type == metric_type and m.timestamp >= cutoff
        )
    
    def get_all_metrics_summary(self, window_minutes: int = 60) -> Dict[str, Any]:
        """Get summary of all metrics"""
        summary = {}
        for metric_type in MetricType:
            summary[metric_type.value] = {
                "average": self.get_metric_average(metric_type, window_minutes),
                "sum": self.get_metric_sum(metric_type, window_minutes),
                "count": sum(1 for m in self.metrics_history if m.metric_type == metric_type)
            }
        return summary
    
    def get_recent_alerts(self, limit: int = 50) -> List[DashboardAlert]:
        """Get most recent alerts"""
        return sorted(self.active_alerts, key=lambda a: a.timestamp, reverse=True)[:limit]


class SecurityScorer:
    """Calculates overall security posture score"""
    
    WEIGHTS = {
        "detection_effectiveness": 0.30,
        "response_effectiveness": 0.25,
        "coverage_score": 0.20,
        "accuracy_score": 0.25,
    }
    
    @staticmethod
    def calculate_score(metrics: Dict[str, Any]) -> SecurityScore:
        """Calculate comprehensive security score"""
        # Detection effectiveness (based on threat detection rate)
        detection_rate = metrics.get(MetricType.THREAT_DETECTION_RATE.value, {}).get("average", 0.85)
        detection_effectiveness = min(100.0, detection_rate * 100)
        
        # Response effectiveness (based on response time)
        avg_response_ms = metrics.get(MetricType.RESPONSE_TIME.value, {}).get("average", 100.0)
        response_effectiveness = max(0.0, 100.0 - (avg_response_ms / 100.0))
        
        # Coverage score (based on sessions monitored vs threats found)
        sessions = metrics.get(MetricType.SESSIONS_MONITORED.value, {}).get("sum", 100)
        threats = metrics.get(MetricType.BLOCKED_ATTACKS.value, {}).get("sum", 5)
        coverage_score = min(100.0, (threats / max(1, sessions)) * 1000)
        
        # Accuracy score (based on false positive rate)
        fp_rate = metrics.get(MetricType.FALSE_POSITIVE_RATE.value, {}).get("average", 0.05)
        accuracy_score = max(0.0, 100.0 - (fp_rate * 100))
        
        # Weighted overall score
        overall_score = (
            detection_effectiveness * SecurityScorer.WEIGHTS["detection_effectiveness"] +
            response_effectiveness * SecurityScorer.WEIGHTS["response_effectiveness"] +
            coverage_score * SecurityScorer.WEIGHTS["coverage_score"] +
            accuracy_score * SecurityScorer.WEIGHTS["accuracy_score"]
        )
        
        # Determine security level
        if overall_score >= 90:
            level = SecurityLevel.EXCELLENT
        elif overall_score >= 75:
            level = SecurityLevel.GOOD
        elif overall_score >= 60:
            level = SecurityLevel.FAIR
        elif overall_score >= 40:
            level = SecurityLevel.POOR
        else:
            level = SecurityLevel.CRITICAL
        
        return SecurityScore(
            overall_score=round(overall_score, 2),
            security_level=level,
            detection_effectiveness=round(detection_effectiveness, 2),
            response_effectiveness=round(response_effectiveness, 2),
            coverage_score=round(coverage_score, 2),
            accuracy_score=round(accuracy_score, 2),
            factors={
                "detection_weight": SecurityScorer.WEIGHTS["detection_effectiveness"],
                "response_weight": SecurityScorer.WEIGHTS["response_effectiveness"],
                "coverage_weight": SecurityScorer.WEIGHTS["coverage_score"],
                "accuracy_weight": SecurityScorer.WEIGHTS["accuracy_score"],
            }
        )


class TrendAnalyzer:
    """Analyzes metric trends over time"""
    
    @staticmethod
    def analyze_trend(
        aggregator: MetricsAggregator,
        metric_type: MetricType,
        period_hours: int = 24
    ) -> TrendAnalysis:
        """Analyze trend for a specific metric"""
        now = datetime.now(timezone.utc)
        baseline_cutoff = now - timedelta(hours=period_hours * 2)
        current_cutoff = now - timedelta(hours=period_hours)
        
        # Baseline period (older half)
        baseline_values = [
            m.value for m in aggregator.metrics_history
            if m.metric_type == metric_type 
            and baseline_cutoff <= m.timestamp < current_cutoff
        ]
        
        # Current period (newer half)
        current_values = [
            m.value for m in aggregator.metrics_history
            if m.metric_type == metric_type 
            and m.timestamp >= current_cutoff
        ]
        
        baseline_avg = statistics.mean(baseline_values) if baseline_values else 0.0
        current_avg = statistics.mean(current_values) if current_values else 0.0
        
        # Calculate trend
        if baseline_avg > 0:
            trend_pct = ((current_avg - baseline_avg) / baseline_avg) * 100
        else:
            trend_pct = 0.0
        
        # Determine direction
        if metric_type in [MetricType.FALSE_POSITIVE_RATE, MetricType.RESPONSE_TIME]:
            # Lower is better
            if trend_pct < -5:
                direction = "improving"
            elif trend_pct > 5:
                direction = "worsening"
            else:
                direction = "stable"
        else:
            # Higher is better
            if trend_pct > 5:
                direction = "improving"
            elif trend_pct < -5:
                direction = "worsening"
            else:
                direction = "stable"
        
        confidence = min(1.0, (len(baseline_values) + len(current_values)) / 100.0)
        
        return TrendAnalysis(
            metric_type=metric_type,
            trend_direction=direction,
            trend_percentage=round(trend_pct, 2),
            baseline_value=round(baseline_avg, 4),
            current_value=round(current_avg, 4),
            period_hours=period_hours,
            confidence=round(confidence, 2)
        )


class SecurityAnalyticsDashboard:
    """
    Main Security Metrics & Analytics Dashboard Engine.
    
    Features:
    - Real-time metric collection and aggregation
    - Security posture scoring (0-100)
    - Trend analysis and anomaly detection
    - Threshold-based alerting
    - Automated report generation (JSON/CSV)
    - Actionable security recommendations
    """
    
    def __init__(self, reports_directory: str = "./security_reports"):
        self.aggregator = MetricsAggregator()
        self.scorer = SecurityScorer()
        self.trend_analyzer = TrendAnalyzer()
        self.reports_directory = Path(reports_directory)
        self.reports_directory.mkdir(parents=True, exist_ok=True)
    
    def record_threat_detection(
        self,
        detection_rate: float,
        source: str = "detector",
        tags: Optional[Dict[str, str]] = None
    ) -> Optional[DashboardAlert]:
        """Record threat detection rate metric"""
        return self.aggregator.record_metric(MetricDataPoint(
            metric_type=MetricType.THREAT_DETECTION_RATE,
            value=detection_rate,
            source=source,
            tags=tags or {}
        ))
    
    def record_blocked_attack(
        self,
        count: int = 1,
        attack_type: str = "unknown",
        source: str = "defender"
    ) -> Optional[DashboardAlert]:
        """Record blocked attack"""
        return self.aggregator.record_metric(MetricDataPoint(
            metric_type=MetricType.BLOCKED_ATTACKS,
            value=float(count),
            source=source,
            tags={"attack_type": attack_type}
        ))
    
    def record_jailbreak_attempt(
        self,
        count: int = 1,
        technique: str = "unknown"
    ) -> Optional[DashboardAlert]:
        """Record jailbreak attempt"""
        return self.aggregator.record_metric(MetricDataPoint(
            metric_type=MetricType.JAILBREAK_ATTEMPTS,
            value=float(count),
            tags={"technique": technique}
        ))
    
    def record_prompt_injection(
        self,
        count: int = 1,
        injection_type: str = "unknown"
    ) -> Optional[DashboardAlert]:
        """Record prompt injection detection"""
        return self.aggregator.record_metric(MetricDataPoint(
            metric_type=MetricType.PROMPT_INJECTIONS,
            value=float(count),
            tags={"injection_type": injection_type}
        ))
    
    def get_current_security_score(self) -> SecurityScore:
        """Get current overall security score"""
        metrics = self.aggregator.get_all_metrics_summary()
        return SecurityScorer.calculate_score(metrics)
    
    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Get complete dashboard summary"""
        metrics = self.aggregator.get_all_metrics_summary()
        score = self.get_current_security_score()
        alerts = self.aggregator.get_recent_alerts(10)
        
        # Analyze key trends
        key_metrics = [
            MetricType.THREAT_DETECTION_RATE,
            MetricType.FALSE_POSITIVE_RATE,
            MetricType.JAILBREAK_ATTEMPTS,
        ]
        trends = [TrendAnalyzer.analyze_trend(self.aggregator, m) for m in key_metrics]
        
        return {
            "security_score": {
                "overall": score.overall_score,
                "level": score.security_level.value,
                "breakdown": {
                    "detection": score.detection_effectiveness,
                    "response": score.response_effectiveness,
                    "coverage": score.coverage_score,
                    "accuracy": score.accuracy_score
                }
            },
            "metrics_summary": metrics,
            "active_alerts_count": len([a for a in alerts if not a.acknowledged]),
            "recent_alerts": [
                {
                    "severity": a.severity.value,
                    "message": a.message,
                    "time": a.timestamp.isoformat()
                }
                for a in alerts[:5]
            ],
            "trends": [
                {
                    "metric": t.metric_type.value,
                    "direction": t.trend_direction,
                    "change_pct": t.trend_percentage
                }
                for t in trends
            ]
        }
    
    def generate_report(
        self,
        report_type: str = "daily",
        hours_back: int = 24
    ) -> DashboardReport:
        """Generate comprehensive security report"""
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours_back)
        
        metrics = self.aggregator.get_all_metrics_summary(hours_back * 60)
        score = SecurityScorer.calculate_score(metrics)
        
        # Get top threats
        top_threats = self._get_top_threats(metrics)
        
        # Get alerts
        alerts = self.aggregator.get_recent_alerts(20)
        
        # Analyze all trends
        all_trends = [
            TrendAnalyzer.analyze_trend(self.aggregator, mt)
            for mt in MetricType
        ]
        
        # Generate recommendations
        recommendations = self._generate_recommendations(score, alerts, all_trends)
        
        report = DashboardReport(
            report_type=report_type,
            time_range_start=start_time,
            time_range_end=end_time,
            security_score=score,
            metrics_summary=metrics,
            top_threats=top_threats,
            alerts=alerts,
            trends=all_trends,
            recommendations=recommendations
        )
        
        self._save_report(report)
        return report
    
    def _get_top_threats(self, metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify top threats from metrics"""
        threats = []
        threat_counts = {
            "jailbreak_attempts": metrics.get(MetricType.JAILBREAK_ATTEMPTS.value, {}).get("sum", 0),
            "prompt_injections": metrics.get(MetricType.PROMPT_INJECTIONS.value, {}).get("sum", 0),
            "hallucinations": metrics.get(MetricType.HALLUCINATIONS_DETECTED.value, {}).get("sum", 0),
        }
        
        for threat_type, count in sorted(threat_counts.items(), key=lambda x: x[1], reverse=True):
            if count > 0:
                threats.append({
                    "threat_type": threat_type,
                    "count": count,
                    "severity": "HIGH" if count > 10 else "MEDIUM" if count > 5 else "LOW"
                })
        return threats[:5]
    
    def _generate_recommendations(
        self,
        score: SecurityScore,
        alerts: List[DashboardAlert],
        trends: List[TrendAnalysis]
    ) -> List[str]:
        """Generate actionable security recommendations"""
        recommendations = []
        
        if score.security_level in [SecurityLevel.POOR, SecurityLevel.CRITICAL]:
            recommendations.append("Immediate security review recommended - overall posture is concerning")
        
        if score.accuracy_score < 70:
            recommendations.append("Review false positive tuning - high FP rate impacting accuracy")
        
        if score.response_effectiveness < 70:
            recommendations.append("Optimize threat response pipeline - response times elevated")
        
        worsening = [t for t in trends if t.trend_direction == "worsening"]
        for trend in worsening[:3]:
            recommendations.append(f"Monitor {trend.metric_type.value} - showing worsening trend")
        
        critical_alerts = [a for a in alerts if a.severity == AlertSeverity.CRITICAL and not a.acknowledged]
        if critical_alerts:
            recommendations.append(f"Address {len(critical_alerts)} unacknowledged critical alerts immediately")
        
        if not recommendations:
            recommendations.append("Security posture looks healthy - continue regular monitoring")
        
        return recommendations
    
    def _save_report(self, report: DashboardReport) -> None:
        """Save report to JSON file"""
        report_file = self.reports_directory / f"report_{report.report_id}.json"
        
        report_data = {
            "report_id": report.report_id,
            "report_type": report.report_type,
            "generated_at": report.generated_at.isoformat(),
            "time_range": {
                "start": report.time_range_start.isoformat(),
                "end": report.time_range_end.isoformat()
            },
            "security_score": {
                "overall": report.security_score.overall_score,
                "level": report.security_score.security_level.value,
                "detection": report.security_score.detection_effectiveness,
                "response": report.security_score.response_effectiveness,
                "coverage": report.security_score.coverage_score,
                "accuracy": report.security_score.accuracy_score
            },
            "recommendations": report.recommendations
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
    
    def export_metrics_csv(self, filename: str) -> str:
        """Export all metrics to CSV file"""
        filepath = self.reports_directory / filename
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "metric_type", "value", "source", "tags"
            ])
            
            for metric in self.aggregator.metrics_history:
                writer.writerow([
                    metric.timestamp.isoformat(),
                    metric.metric_type.value,
                    metric.value,
                    metric.source,
                    json.dumps(metric.tags)
                ])
        
        return str(filepath)


# Factory function
def create_security_dashboard() -> SecurityAnalyticsDashboard:
    """Create and initialize a Security Analytics Dashboard"""
    return SecurityAnalyticsDashboard()


# Public API
__all__ = [
    "SecurityLevel",
    "MetricType",
    "AlertSeverity",
    "MetricDataPoint",
    "DashboardAlert",
    "SecurityScore",
    "TrendAnalysis",
    "DashboardReport",
    "MetricsAggregator",
    "SecurityScorer",
    "TrendAnalyzer",
    "SecurityAnalyticsDashboard",
    "create_security_dashboard"
]
