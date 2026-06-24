"""
NeuralShield AI - MITRE ATT&CK Executive Dashboard Generator
Dimension A: Feature Expansion
Version: v25 - June 2026
API Stability: STABLE
Generates executive-level MITRE ATT&CK dashboards with heatmaps,
risk summaries, trend analysis, and actionable security insights.
Provides C-suite friendly reporting with business impact context.
"""
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict


class RiskLevel(Enum):
    """Executive risk levels for reporting."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"
    
    @classmethod
    def from_score(cls, score: float) -> "RiskLevel":
        if score >= 85:
            return cls.CRITICAL
        elif score >= 70:
            return cls.HIGH
        elif score >= 40:
            return cls.MEDIUM
        elif score >= 15:
            return cls.LOW
        return cls.UNKNOWN


class TacticCategory(Enum):
    """MITRE ATT&CK tactics with business impact context."""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    COMMAND_AND_CONTROL = "command_and_control"
    IMPACT = "impact"


@dataclass
class TechniqueCoverage:
    """Coverage data for a MITRE technique."""
    technique_id: str
    technique_name: str
    tactic: TacticCategory
    detection_count: int = 0
    prevention_count: int = 0
    risk_score: float = 0.0
    last_detected: Optional[datetime] = None
    business_impact: str = "medium"
    
    def get_coverage_percentage(self) -> float:
        """Calculate coverage percentage (0-100)."""
        total = self.detection_count + self.prevention_count
        if total == 0:
            return 0.0
        return min(100.0, (self.prevention_count / max(1, self.detection_count)) * 100)


@dataclass
class ExecutiveSummary:
    """Executive summary for dashboard."""
    overall_security_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    total_detections: int = 0
    total_preventions: int = 0
    blocked_attacks: int = 0
    critical_incidents: int = 0
    mean_time_to_detect: float = 0.0  # minutes
    mean_time_to_respond: float = 0.0  # minutes
    top_threat_actors: List[str] = field(default_factory=list)
    most_targeted_assets: List[str] = field(default_factory=list)
    improvement_trend: float = 0.0  # percentage improvement vs previous period


@dataclass
class TrendDataPoint:
    """Single data point for trend analysis."""
    timestamp: datetime
    detections: int = 0
    preventions: int = 0
    incidents: int = 0
    risk_score: float = 0.0


@dataclass
class Recommendation:
    """Security recommendation with priority."""
    recommendation_id: str
    title: str
    description: str
    priority: str  # critical, high, medium, low
    effort: str  # low, medium, high
    impact: str  # low, medium, high
    estimated_roi: float = 0.0  # estimated risk reduction percentage
    category: str = "general"


class MITREExecutiveDashboardGenerator:
    """
    Generates executive-level MITRE ATT&CK security dashboards.
    
    Features:
    - Executive summary with overall security score
    - MITRE heatmap generation with tactic coverage
    - Trend analysis with historical comparison
    - Business impact assessment
    - Prioritized security recommendations
    - Threat actor and TTP analysis
    - Export to JSON, HTML, and executive report formats
    """
    
    def __init__(self, organization_name: str = "Enterprise"):
        self.organization_name = organization_name
        self._techniques: Dict[str, TechniqueCoverage] = {}
        self._trend_data: List[TrendDataPoint] = []
        self._recommendations: List[Recommendation] = []
        self._incident_log: List[Dict[str, Any]] = []
        self._coverage_by_tactic: Dict[TacticCategory, Dict[str, Any]] = defaultdict(
            lambda: {"detections": 0, "preventions": 0, "techniques": 0}
        )
        self._generated_at: Optional[datetime] = None
        
        # Initialize all tactics
        for tactic in TacticCategory:
            self._coverage_by_tactic[tactic] = {"detections": 0, "preventions": 0, "techniques": 0}
    
    def add_technique_coverage(
        self,
        technique_id: str,
        technique_name: str,
        tactic: TacticCategory,
        detection_count: int = 0,
        prevention_count: int = 0,
        risk_score: float = 0.0,
        last_detected: Optional[datetime] = None,
        business_impact: str = "medium"
    ) -> None:
        """Add or update technique coverage data."""
        key = technique_id.upper()
        self._techniques[key] = TechniqueCoverage(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            detection_count=detection_count,
            prevention_count=prevention_count,
            risk_score=risk_score,
            last_detected=last_detected,
            business_impact=business_impact
        )
        
        # Update tactic aggregates
        self._coverage_by_tactic[tactic]["detections"] += detection_count
        self._coverage_by_tactic[tactic]["preventions"] += prevention_count
        self._coverage_by_tactic[tactic]["techniques"] += 1
    
    def add_trend_data_point(
        self,
        timestamp: datetime,
        detections: int = 0,
        preventions: int = 0,
        incidents: int = 0,
        risk_score: float = 0.0
    ) -> None:
        """Add a data point for trend analysis."""
        self._trend_data.append(TrendDataPoint(
            timestamp=timestamp,
            detections=detections,
            preventions=preventions,
            incidents=incidents,
            risk_score=risk_score
        ))
    
    def add_incident(
        self,
        incident_id: str,
        severity: str,
        tactic: str,
        technique: str,
        timestamp: datetime,
        resolved: bool = True,
        resolution_time_minutes: float = 0.0,
        threat_actor: Optional[str] = None,
        asset_impacted: Optional[str] = None
    ) -> None:
        """Log a security incident for analysis."""
        self._incident_log.append({
            "incident_id": incident_id,
            "severity": severity,
            "tactic": tactic,
            "technique": technique,
            "timestamp": timestamp,
            "resolved": resolved,
            "resolution_time_minutes": resolution_time_minutes,
            "threat_actor": threat_actor,
            "asset_impacted": asset_impacted
        })
    
    def add_recommendation(
        self,
        title: str,
        description: str,
        priority: str,
        effort: str,
        impact: str,
        estimated_roi: float = 0.0,
        category: str = "general"
    ) -> None:
        """Add a security recommendation."""
        rec_id = f"REC_{len(self._recommendations) + 1:04d}"
        self._recommendations.append(Recommendation(
            recommendation_id=rec_id,
            title=title,
            description=description,
            priority=priority,
            effort=effort,
            impact=impact,
            estimated_roi=estimated_roi,
            category=category
        ))
    
    def _calculate_overall_score(self) -> float:
        """Calculate overall security score (0-100)."""
        if not self._techniques:
            return 50.0
        
        total_coverage = 0.0
        total_risk_weight = 0.0
        
        for tech in self._techniques.values():
            coverage = tech.get_coverage_percentage()
            risk_weight = max(1.0, tech.risk_score / 10.0)
            total_coverage += coverage * risk_weight
            total_risk_weight += risk_weight
        
        base_score = total_coverage / total_risk_weight if total_risk_weight > 0 else 50.0
        
        # Adjust based on prevention rate
        total_det = sum(t.detection_count for t in self._techniques.values())
        total_prev = sum(t.prevention_count for t in self._techniques.values())
        prevention_rate = total_prev / max(1, total_det) if total_det > 0 else 0.5
        
        # Adjust based on incident resolution
        resolved_incidents = sum(1 for i in self._incident_log if i["resolved"])
        total_incidents = len(self._incident_log)
        resolution_rate = resolved_incidents / max(1, total_incidents) if total_incidents > 0 else 1.0
        
        final_score = (base_score * 0.5 + prevention_rate * 100 * 0.3 + resolution_rate * 100 * 0.2)
        return min(100.0, max(0.0, final_score))
    
    def _calculate_executive_summary(self) -> ExecutiveSummary:
        """Calculate executive summary metrics."""
        score = self._calculate_overall_score()
        
        total_detections = sum(t.detection_count for t in self._techniques.values())
        total_preventions = sum(t.prevention_count for t in self._techniques.values())
        
        # Count critical incidents
        critical_incidents = sum(1 for i in self._incident_log if i["severity"] == "critical")
        blocked_attacks = total_preventions
        
        # Calculate MTTD and MTTR
        resolution_times = [i["resolution_time_minutes"] for i in self._incident_log 
                          if i["resolution_time_minutes"] > 0]
        mttr = sum(resolution_times) / len(resolution_times) if resolution_times else 0.0
        mttd = mttr * 0.3  # Estimated MTTD as 30% of resolution time
        
        # Threat actor frequency
        actor_counts: Dict[str, int] = defaultdict(int)
        asset_counts: Dict[str, int] = defaultdict(int)
        for incident in self._incident_log:
            if incident["threat_actor"]:
                actor_counts[incident["threat_actor"]] += 1
            if incident["asset_impacted"]:
                asset_counts[incident["asset_impacted"]] += 1
        
        top_actors = sorted(actor_counts.keys(), key=lambda x: actor_counts[x], reverse=True)[:5]
        top_assets = sorted(asset_counts.keys(), key=lambda x: asset_counts[x], reverse=True)[:5]
        
        # Calculate improvement trend (compare first half vs second half of trend data)
        improvement = 0.0
        if len(self._trend_data) >= 4:
            mid = len(self._trend_data) // 2
            first_half = self._trend_data[:mid]
            second_half = self._trend_data[mid:]
            
            first_avg_risk = sum(d.risk_score for d in first_half) / len(first_half)
            second_avg_risk = sum(d.risk_score for d in second_half) / len(second_half)
            
            if first_avg_risk > 0:
                improvement = ((first_avg_risk - second_avg_risk) / first_avg_risk) * 100
        
        return ExecutiveSummary(
            overall_security_score=round(score, 1),
            risk_level=RiskLevel.from_score(score),
            total_detections=total_detections,
            total_preventions=total_preventions,
            blocked_attacks=blocked_attacks,
            critical_incidents=critical_incidents,
            mean_time_to_detect=round(mttd, 1),
            mean_time_to_respond=round(mttr, 1),
            top_threat_actors=top_actors,
            most_targeted_assets=top_assets,
            improvement_trend=round(improvement, 1)
        )
    
    def generate_heatmap_data(self) -> Dict[str, Any]:
        """Generate MITRE ATT&CK heatmap data."""
        heatmap = {}
        
        for tactic in TacticCategory:
            tactic_data = self._coverage_by_tactic[tactic]
            total = tactic_data["detections"] + tactic_data["preventions"]
            coverage_pct = (tactic_data["preventions"] / max(1, tactic_data["detections"]) * 100 
                          if tactic_data["detections"] > 0 else 0)
            
            # Color intensity based on coverage
            if coverage_pct >= 80:
                color = "#22c55e"  # Green
            elif coverage_pct >= 60:
                color = "#84cc16"  # Lime
            elif coverage_pct >= 40:
                color = "#eab308"  # Yellow
            elif coverage_pct >= 20:
                color = "#f97316"  # Orange
            else:
                color = "#ef4444"  # Red
            
            heatmap[tactic.value] = {
                "detections": tactic_data["detections"],
                "preventions": tactic_data["preventions"],
                "techniques_covered": tactic_data["techniques"],
                "coverage_percentage": round(coverage_pct, 1),
                "total_activity": total,
                "color": color
            }
        
        return heatmap
    
    def generate_prioritized_recommendations(self) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations sorted by value."""
        def rec_value(rec: Recommendation) -> float:
            priority_scores = {"critical": 1000, "high": 500, "medium": 200, "low": 50}
            impact_scores = {"high": 3, "medium": 2, "low": 1}
            effort_scores = {"low": 3, "medium": 2, "high": 1}
            
            return (priority_scores.get(rec.priority, 25) + 
                    rec.estimated_roi * impact_scores.get(rec.impact, 1) * 
                    effort_scores.get(rec.effort, 1))
        
        sorted_recs = sorted(self._recommendations, key=rec_value, reverse=True)
        
        return [
            {
                "id": r.recommendation_id,
                "title": r.title,
                "description": r.description,
                "priority": r.priority,
                "effort": r.effort,
                "impact": r.impact,
                "estimated_roi": r.estimated_roi,
                "category": r.category
            }
            for r in sorted_recs
        ]
    
    def generate_dashboard(self) -> Dict[str, Any]:
        """Generate complete executive dashboard."""
        self._generated_at = datetime.now(timezone.utc)
        
        summary = self._calculate_executive_summary()
        
        return {
            "dashboard_version": "v25",
            "generated_at": self._generated_at.isoformat(),
            "organization": self.organization_name,
            "executive_summary": {
                "overall_security_score": summary.overall_security_score,
                "risk_level": summary.risk_level.value,
                "total_detections": summary.total_detections,
                "total_preventions": summary.total_preventions,
                "blocked_attacks": summary.blocked_attacks,
                "critical_incidents": summary.critical_incidents,
                "mean_time_to_detect": summary.mean_time_to_detect,
                "mean_time_to_respond": summary.mean_time_to_respond,
                "top_threat_actors": summary.top_threat_actors,
                "most_targeted_assets": summary.most_targeted_assets,
                "improvement_trend": summary.improvement_trend
            },
            "mitre_heatmap": self.generate_heatmap_data(),
            "trend_analysis": self._generate_trend_analysis(),
            "top_techniques_by_risk": self._get_top_risk_techniques(),
            "recommendations": self.generate_prioritized_recommendations(),
            "incident_summary": self._get_incident_summary()
        }
    
    def _generate_trend_analysis(self) -> Dict[str, Any]:
        """Generate trend analysis data."""
        if not self._trend_data:
            return {"has_data": False}
        
        sorted_trend = sorted(self._trend_data, key=lambda x: x.timestamp)
        
        return {
            "has_data": True,
            "period_start": sorted_trend[0].timestamp.isoformat(),
            "period_end": sorted_trend[-1].timestamp.isoformat(),
            "data_points": len(sorted_trend),
            "total_detections_period": sum(d.detections for d in sorted_trend),
            "total_preventions_period": sum(d.preventions for d in sorted_trend),
            "total_incidents_period": sum(d.incidents for d in sorted_trend),
            "trend_direction": "improving" if len(sorted_trend) >= 2 and 
                              sorted_trend[-1].risk_score < sorted_trend[0].risk_score 
                              else "declining" if len(sorted_trend) >= 2 else "stable"
        }
    
    def _get_top_risk_techniques(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get highest risk techniques."""
        sorted_techs = sorted(
            self._techniques.values(),
            key=lambda x: x.risk_score,
            reverse=True
        )[:limit]
        
        return [
            {
                "id": t.technique_id,
                "name": t.technique_name,
                "tactic": t.tactic.value,
                "risk_score": t.risk_score,
                "coverage": t.get_coverage_percentage(),
                "business_impact": t.business_impact
            }
            for t in sorted_techs
        ]
    
    def _get_incident_summary(self) -> Dict[str, Any]:
        """Get incident summary statistics."""
        by_severity: Dict[str, int] = defaultdict(int)
        by_tactic: Dict[str, int] = defaultdict(int)
        
        for incident in self._incident_log:
            by_severity[incident["severity"]] += 1
            by_tactic[incident["tactic"]] += 1
        
        return {
            "total_incidents": len(self._incident_log),
            "by_severity": dict(by_severity),
            "by_tactic": dict(by_tactic),
            "resolved_rate": round(sum(1 for i in self._incident_log if i["resolved"]) / 
                                  max(1, len(self._incident_log)) * 100, 1)
        }
    
    def export_json(self, filepath: str) -> None:
        """Export dashboard to JSON file."""
        with open(filepath, 'w') as f:
            json.dump(self.generate_dashboard(), f, indent=2)
    
    def get_security_grade(self) -> str:
        """Get letter grade for overall security score."""
        score = self._calculate_overall_score()
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        return "F"
