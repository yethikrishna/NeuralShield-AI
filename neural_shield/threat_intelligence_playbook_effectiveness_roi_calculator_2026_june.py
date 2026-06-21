"""
Threat Intelligence Playbook Effectiveness Metrics & ROI Calculator
Real, production-grade security metrics engine

This module provides comprehensive measurement of incident response playbook
effectiveness and calculates Return on Investment (ROI) for security operations:
1. Playbook execution success rate tracking
2. Mean Time To Respond (MTTR) calculation
3. Cost avoidance & ROI analysis
4. Performance benchmarking
5. Continuous improvement recommendations
6. SLA compliance monitoring

Author: NeuralShield-AI Security Team
Version: 1.0.0 - June 2026
"""

import hashlib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import statistics
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PlaybookOutcome(Enum):
    SUCCESS = "success"
    PARTIAL = "partial_success"
    FAILED = "failed"
    ESCALATED = "escalated"
    FALSE_POSITIVE = "false_positive"


class CostCategory(Enum):
    TOOL_COST = "tool_cost"
    PERSONNEL_COST = "personnel_cost"
    TRAINING_COST = "training_cost"
    INCIDENT_COST = "incident_cost"
    DOWNTIME_COST = "downtime_cost"
    REGULATORY_FINE = "regulatory_fine"


@dataclass
class PlaybookExecution:
    execution_id: str
    playbook_id: str
    playbook_name: str
    threat_type: str
    start_time: datetime
    end_time: Optional[datetime] = None
    outcome: PlaybookOutcome = PlaybookOutcome.SUCCESS
    analyst_hours: float = 0.0
    steps_completed: int = 0
    total_steps: int = 0
    containment_success: bool = True
    eradication_success: bool = True
    recovery_success: bool = True
    false_positive: bool = False
    escalation_required: bool = False
    notes: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration_minutes(self) -> float:
        if self.end_time and self.start_time:
            return (self.end_time - self.start_time).total_seconds() / 60
        return 0.0
    
    @property
    def completion_rate(self) -> float:
        if self.total_steps > 0:
            return self.steps_completed / self.total_steps
        return 0.0


@dataclass
class ROICalculation:
    playbook_id: str
    total_investment: float = 0.0
    total_cost_avoided: float = 0.0
    incidents_prevented: int = 0
    incidents_contained: int = 0
    mttr_improvement_pct: float = 0.0
    roi_ratio: float = 0.0
    roi_percentage: float = 0.0
    payback_months: float = 0.0
    break_even_incidents: int = 0
    cost_breakdown: Dict[str, float] = field(default_factory=dict)
    assumptions: List[str] = field(default_factory=list)


@dataclass
class EffectivenessMetrics:
    playbook_id: str
    playbook_name: str
    total_executions: int = 0
    success_count: int = 0
    failure_count: int = 0
    partial_count: int = 0
    false_positive_count: int = 0
    escalation_count: int = 0
    success_rate: float = 0.0
    avg_duration_minutes: float = 0.0
    median_duration_minutes: float = 0.0
    p95_duration_minutes: float = 0.0
    avg_completion_rate: float = 0.0
    containment_rate: float = 0.0
    eradication_rate: float = 0.0
    recovery_rate: float = 0.0
    sla_compliance_rate: float = 0.0
    quality_score: float = 0.0
    trend_30d: float = 0.0
    recommendations: List[str] = field(default_factory=list)


class PlaybookEffectivenessEngine:
    """Main playbook effectiveness and ROI calculation engine"""
    
    # Industry benchmarks based on Verizon DBIR and SANS reports
    INDUSTRY_BENCHMARKS = {
        "ransomware": {
            "avg_mttr_hours": 72,
            "avg_cost_per_incident": 4500000,
            "containment_rate": 0.65
        },
        "phishing": {
            "avg_mttr_hours": 4,
            "avg_cost_per_incident": 150000,
            "containment_rate": 0.85
        },
        "data_exfiltration": {
            "avg_mttr_hours": 48,
            "avg_cost_per_incident": 3500000,
            "containment_rate": 0.55
        },
        "lateral_movement": {
            "avg_mttr_hours": 24,
            "avg_cost_per_incident": 1200000,
            "containment_rate": 0.60
        },
        "default": {
            "avg_mttr_hours": 28,
            "avg_cost_per_incident": 850000,
            "containment_rate": 0.70
        }
    }
    
    # Cost parameters for ROI calculation
    COST_PARAMS = {
        "analyst_hourly_rate": 125,
        "senior_analyst_hourly_rate": 225,
        "incident_response_retainer_hourly": 350,
        "downtime_cost_per_hour": 5000,
        "data_breach_cost_per_record": 165,
        "regulatory_fine_base": 1000000
    }
    
    # SLA thresholds (minutes)
    SLA_THRESHOLDS = {
        "critical": 60,
        "high": 120,
        "medium": 240,
        "low": 480
    }
    
    def __init__(self):
        self.execution_history: List[PlaybookExecution] = []
        self.playbook_inventory: Dict[str, Dict] = {}
    
    def record_execution(self, execution: PlaybookExecution) -> str:
        """Record a playbook execution for metrics tracking"""
        self.execution_history.append(execution)
        logger.info(f"Recorded execution {execution.execution_id}: "
                   f"{execution.playbook_name} - {execution.outcome.value}, "
                   f"Duration: {execution.duration_minutes:.1f}min")
        return execution.execution_id
    
    def register_playbook(self, playbook_id: str, name: str, 
                         threat_type: str, development_cost: float,
                         maintenance_cost_monthly: float,
                         target_sla_minutes: int = 120):
        """Register a playbook in the inventory for ROI tracking"""
        self.playbook_inventory[playbook_id] = {
            "name": name,
            "threat_type": threat_type,
            "development_cost": development_cost,
            "maintenance_cost_monthly": maintenance_cost_monthly,
            "target_sla_minutes": target_sla_minutes,
            "registration_date": datetime.utcnow()
        }
        logger.info(f"Registered playbook: {name} ({playbook_id})")
    
    def calculate_effectiveness(self, playbook_id: str, 
                               lookback_days: int = 90) -> EffectivenessMetrics:
        """Calculate comprehensive effectiveness metrics for a playbook"""
        cutoff = datetime.utcnow() - timedelta(days=lookback_days)
        executions = [e for e in self.execution_history 
                     if e.playbook_id == playbook_id and e.start_time >= cutoff]
        
        if not executions:
            return EffectivenessMetrics(playbook_id=playbook_id, 
                                       playbook_name="Unknown")
        
        pb_info = self.playbook_inventory.get(playbook_id, {})
        
        # Count outcomes
        outcomes = [e.outcome for e in executions]
        success_count = outcomes.count(PlaybookOutcome.SUCCESS)
        partial_count = outcomes.count(PlaybookOutcome.PARTIAL)
        failure_count = outcomes.count(PlaybookOutcome.FAILED)
        fp_count = outcomes.count(PlaybookOutcome.FALSE_POSITIVE)
        escalation_count = outcomes.count(PlaybookOutcome.ESCALATED)
        
        # Duration metrics
        durations = [e.duration_minutes for e in executions if e.duration_minutes > 0]
        completion_rates = [e.completion_rate for e in executions]
        
        # Success rates
        containment_rate = sum(1 for e in executions if e.containment_success) / len(executions)
        eradication_rate = sum(1 for e in executions if e.eradication_success) / len(executions)
        recovery_rate = sum(1 for e in executions if e.recovery_success) / len(executions)
        
        # SLA compliance
        sla_threshold = pb_info.get("target_sla_minutes", 120)
        sla_compliant = sum(1 for d in durations if d <= sla_threshold)
        sla_rate = sla_compliant / len(durations) if durations else 0
        
        # Calculate metrics
        metrics = EffectivenessMetrics(
            playbook_id=playbook_id,
            playbook_name=pb_info.get("name", executions[0].playbook_name),
            total_executions=len(executions),
            success_count=success_count,
            failure_count=failure_count,
            partial_count=partial_count,
            false_positive_count=fp_count,
            escalation_count=escalation_count,
            success_rate=round(success_count / len(executions) * 100, 1),
            avg_duration_minutes=round(statistics.mean(durations) if durations else 0, 1),
            median_duration_minutes=round(statistics.median(durations) if durations else 0, 1),
            p95_duration_minutes=round(self._percentile(durations, 95) if durations else 0, 1),
            avg_completion_rate=round(statistics.mean(completion_rates) * 100, 1),
            containment_rate=round(containment_rate * 100, 1),
            eradication_rate=round(eradication_rate * 100, 1),
            recovery_rate=round(recovery_rate * 100, 1),
            sla_compliance_rate=round(sla_rate * 100, 1),
            quality_score=0.0
        )
        
        # Calculate overall quality score (0-100)
        quality_components = [
            metrics.success_rate * 0.30,
            metrics.containment_rate * 0.25,
            metrics.sla_compliance_rate * 0.20,
            metrics.avg_completion_rate * 0.15,
            (100 - min(100, metrics.avg_duration_minutes / 2)) * 0.10
        ]
        metrics.quality_score = round(sum(quality_components), 1)
        
        # Generate recommendations
        metrics.recommendations = self._generate_recommendations(metrics, pb_info)
        
        logger.info(f"Effectiveness calculated for {playbook_id}: "
                   f"Score={metrics.quality_score}, Success={metrics.success_rate}%")
        return metrics
    
    def calculate_roi(self, playbook_id: str, months_active: int = 12) -> ROICalculation:
        """Calculate ROI for a playbook implementation"""
        pb_info = self.playbook_inventory.get(playbook_id, {})
        threat_type = pb_info.get("threat_type", "default")
        benchmarks = self.INDUSTRY_BENCHMARKS.get(threat_type, 
                                                  self.INDUSTRY_BENCHMARKS["default"])
        
        executions = [e for e in self.execution_history if e.playbook_id == playbook_id]
        
        # Calculate total investment
        dev_cost = pb_info.get("development_cost", 0)
        monthly_maintenance = pb_info.get("maintenance_cost_monthly", 500)
        analyst_time_cost = sum(e.analyst_hours * self.COST_PARAMS["analyst_hourly_rate"] 
                               for e in executions)
        
        total_investment = dev_cost + (monthly_maintenance * months_active) + analyst_time_cost
        
        # Calculate cost avoided
        successful_containments = sum(1 for e in executions if e.containment_success)
        full_preventions = sum(1 for e in executions 
                              if e.outcome == PlaybookOutcome.SUCCESS 
                              and not e.escalation_required)
        
        # MTTR improvement vs industry benchmark
        actual_mttr_hours = statistics.mean([e.duration_minutes / 60 for e in executions
                                            if e.duration_minutes > 0]) if executions else 0
        industry_mttr = benchmarks["avg_mttr_hours"]
        mttr_improvement = max(0, industry_mttr - actual_mttr_hours)
        mttr_improvement_pct = (mttr_improvement / industry_mttr * 100) if industry_mttr > 0 else 0
        
        # Cost avoided calculations
        incident_cost_avoided = successful_containments * benchmarks["avg_cost_per_incident"] * 0.7
        downtime_avoided = mttr_improvement * self.COST_PARAMS["downtime_cost_per_hour"] * len(executions)
        escalation_cost_avoided = sum(1 for e in executions if not e.escalation_required) * 5000
        
        total_cost_avoided = incident_cost_avoided + downtime_avoided + escalation_cost_avoided
        
        # ROI calculations
        roi_ratio = total_cost_avoided / total_investment if total_investment > 0 else float('inf')
        roi_percentage = (roi_ratio - 1) * 100 if roi_ratio != float('inf') else 999
        
        # Payback period
        monthly_savings = total_cost_avoided / months_active if months_active > 0 else 0
        payback_months = total_investment / monthly_savings if monthly_savings > 0 else 0
        
        roi = ROICalculation(
            playbook_id=playbook_id,
            total_investment=round(total_investment, 2),
            total_cost_avoided=round(total_cost_avoided, 2),
            incidents_prevented=full_preventions,
            incidents_contained=successful_containments,
            mttr_improvement_pct=round(mttr_improvement_pct, 1),
            roi_ratio=round(roi_ratio, 2),
            roi_percentage=round(roi_percentage, 1),
            payback_months=round(payback_months, 1),
            break_even_incidents=int(total_investment / benchmarks["avg_cost_per_incident"]) + 1,
            cost_breakdown={
                "development": round(dev_cost, 2),
                "maintenance": round(monthly_maintenance * months_active, 2),
                "analyst_time": round(analyst_time_cost, 2)
            },
            assumptions=[
                f"Industry avg cost per incident: ${benchmarks['avg_cost_per_incident']:,}",
                f"Industry avg MTTR: {industry_mttr} hours",
                f"Downtime cost: ${self.COST_PARAMS['downtime_cost_per_hour']}/hour",
                f"Analyst rate: ${self.COST_PARAMS['analyst_hourly_rate']}/hour"
            ]
        )
        
        logger.info(f"ROI calculated for {playbook_id}: "
                   f"ROI={roi.roi_percentage}%, Payback={roi.payback_months}mo")
        return roi
    
    def generate_benchmark_report(self, playbook_ids: List[str] = None) -> Dict[str, Any]:
        """Generate comparative benchmark report across multiple playbooks"""
        if playbook_ids is None:
            playbook_ids = list(self.playbook_inventory.keys())
        
        all_metrics = {}
        all_roi = {}
        
        for pb_id in playbook_ids:
            all_metrics[pb_id] = self.calculate_effectiveness(pb_id)
            all_roi[pb_id] = self.calculate_roi(pb_id)
        
        # Find top performers
        sorted_by_quality = sorted(all_metrics.values(), 
                                  key=lambda m: m.quality_score, reverse=True)
        sorted_by_roi = sorted(all_roi.values(), 
                              key=lambda r: r.roi_percentage, reverse=True)
        
        return {
            "report_generated": datetime.utcnow().isoformat(),
            "total_playbooks": len(playbook_ids),
            "overall_average_quality": round(statistics.mean([m.quality_score for m in all_metrics.values()]), 1),
            "overall_average_success_rate": round(statistics.mean([m.success_rate for m in all_metrics.values()]), 1),
            "overall_average_roi": round(statistics.mean([r.roi_percentage for r in all_roi.values()]), 1),
            "top_performers_quality": [m.playbook_name for m in sorted_by_quality[:3]],
            "top_performers_roi": [self.playbook_inventory.get(r.playbook_id, {}).get("name", r.playbook_id) 
                                  for r in sorted_by_roi[:3]],
            "playbook_details": {
                pb_id: {
                    "name": self.playbook_inventory.get(pb_id, {}).get("name", pb_id),
                    "quality_score": all_metrics[pb_id].quality_score,
                    "success_rate": all_metrics[pb_id].success_rate,
                    "roi_percentage": all_roi[pb_id].roi_percentage,
                    "mttr_minutes": all_metrics[pb_id].avg_duration_minutes
                } for pb_id in playbook_ids
            }
        }
    
    def _percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile of a dataset"""
        if not data:
            return 0.0
        sorted_data = sorted(data)
        k = (len(sorted_data) - 1) * percentile / 100
        f = int(k)
        c = f + 1 if f + 1 < len(sorted_data) else f
        if f == c:
            return sorted_data[f]
        return sorted_data[f] + (k - f) * (sorted_data[c] - sorted_data[f])
    
    def _generate_recommendations(self, metrics: EffectivenessMetrics, 
                                  pb_info: Dict) -> List[str]:
        """Generate improvement recommendations based on metrics"""
        recs = []
        
        if metrics.success_rate < 70:
            recs.append(f"⚠️ Low success rate ({metrics.success_rate}%). Review playbook step clarity and decision points.")
        
        if metrics.containment_rate < 80:
            recs.append(f"⚠️ Containment rate only {metrics.containment_rate}%. Strengthen early isolation procedures.")
        
        if metrics.sla_compliance_rate < 90:
            recs.append(f"⚠️ SLA compliance {metrics.sla_compliance_rate}%. Reduce manual steps, add automation.")
        
        if metrics.escalation_count > metrics.total_executions * 0.3:
            recs.append(f"⚠️ High escalation rate. Expand playbook coverage for edge cases.")
        
        if metrics.false_positive_count > metrics.total_executions * 0.2:
            recs.append(f"⚠️ High false positive rate ({metrics.false_positive_count}). Improve detection thresholds.")
        
        if metrics.quality_score >= 90:
            recs.append("✅ Excellent quality! This playbook is production-ready and high-performing.")
        elif metrics.quality_score >= 75:
            recs.append("✅ Good quality. Minor refinements recommended.")
        elif metrics.quality_score >= 60:
            recs.append("⚠️ Moderate quality. Several areas need improvement.")
        else:
            recs.append("❌ Poor quality. Major overhaul recommended before production use.")
        
        return recs


# Export public API
__all__ = [
    "PlaybookEffectivenessEngine",
    "PlaybookExecution",
    "ROICalculation",
    "EffectivenessMetrics",
    "PlaybookOutcome",
    "CostCategory"
]
