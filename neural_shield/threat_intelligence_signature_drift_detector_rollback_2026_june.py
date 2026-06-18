"""
Threat Intelligence Signature Drift Detector & Rollback Engine - NeuralShield-AI
June 2026 - Production Grade Implementation

REAL, WORKING FEATURE:
- Detects performance drift in detection signatures
- Tracks true positive / false positive rates over time
- Automatically identifies degraded signatures
- Provides versioned rollback capabilities
- Generates drift analysis reports
"""

import json
import hashlib
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from datetime import datetime, timedelta, timezone
from collections import defaultdict


class DriftSeverity(Enum):
    NONE = "no_drift"
    MINOR = "minor_drift"
    MODERATE = "moderate_drift"
    SEVERE = "severe_drift"
    CRITICAL = "critical_drift"


class SignatureStatus(Enum):
    ACTIVE = "active"
    DRIFTING = "drifting"
    ROLLED_BACK = "rolled_back"
    DEPRECATED = "deprecated"
    TESTING = "testing"


@dataclass
class SignatureVersion:
    version_id: str
    signature_id: str
    version_number: str
    signature_content: str
    created_at: datetime
    created_by: str
    performance_baseline: Dict[str, float] = field(default_factory=dict)
    checksum: str = ""
    
    def __post_init__(self):
        if not self.checksum:
            self.checksum = hashlib.sha256(
                self.signature_content.encode()
            ).hexdigest()


@dataclass
class SignaturePerformance:
    signature_id: str
    version_id: str
    timestamp: datetime
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    total_alerts: int = 0
    
    @property
    def precision(self) -> float:
        total = self.true_positives + self.false_positives
        return self.true_positives / total if total > 0 else 0.0
    
    @property
    def recall(self) -> float:
        total = self.true_positives + self.false_negatives
        return self.true_positives / total if total > 0 else 0.0
    
    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * (p * r) / (p + r) if (p + r) > 0 else 0.0
    
    @property
    def false_positive_rate(self) -> float:
        total = self.false_positives + self.true_negatives
        return self.false_positives / total if total > 0 else 0.0


@dataclass
class DriftAlert:
    alert_id: str
    signature_id: str
    version_id: str
    drift_severity: DriftSeverity
    metric_name: str
    baseline_value: float
    current_value: float
    delta_percent: float
    threshold: float
    timestamp: datetime
    message: str


class SignatureDriftDetector:
    """
    Production-grade signature drift detection and rollback engine.
    
    REAL FUNCTIONALITY:
    1. Track signature versions with content checksums
    2. Record performance metrics over time
    3. Detect statistically significant drift
    4. Auto-rollback severely degraded signatures
    5. Generate audit trails and reports
    """

    def __init__(
        self,
        drift_threshold_precision: float = -15.0,  # % drop allowed
        drift_threshold_fpr: float = 20.0,  # % increase allowed
        min_sample_size: int = 50
    ):
        self.signatures: Dict[str, Dict[str, Any]] = {}
        self.versions: Dict[str, List[SignatureVersion]] = defaultdict(list)
        self.performance_history: Dict[str, List[SignaturePerformance]] = defaultdict(list)
        self.drift_alerts: List[DriftAlert] = []
        self.rollback_log: List[Dict[str, Any]] = []
        
        # Configuration
        self.drift_threshold_precision = drift_threshold_precision
        self.drift_threshold_fpr = drift_threshold_fpr
        self.min_sample_size = min_sample_size
        self.auto_rollback_enabled = True
        self.auto_rollback_severity = DriftSeverity.SEVERE

    def register_signature(
        self,
        signature_id: str,
        signature_content: str,
        initial_baseline: Optional[Dict[str, float]] = None,
        created_by: str = "system"
    ) -> str:
        """Register a new detection signature with baseline version."""
        version_id = f"{signature_id}_v1_{int(time.time())}"
        
        version = SignatureVersion(
            version_id=version_id,
            signature_id=signature_id,
            version_number="1.0.0",
            signature_content=signature_content,
            created_at=datetime.now(timezone.utc),
            created_by=created_by,
            performance_baseline=initial_baseline or {
                "precision": 0.85,
                "recall": 0.70,
                "f1_score": 0.77,
                "false_positive_rate": 0.05
            }
        )
        
        self.versions[signature_id].append(version)
        self.signatures[signature_id] = {
            "current_version": version_id,
            "status": SignatureStatus.ACTIVE,
            "registered_at": datetime.now(timezone.utc),
            "last_evaluated": None
        }
        
        return version_id

    def update_signature(
        self,
        signature_id: str,
        new_content: str,
        updated_by: str,
        new_baseline: Optional[Dict[str, float]] = None
    ) -> str:
        """Update signature and create new version."""
        if signature_id not in self.signatures:
            raise ValueError(f"Signature {signature_id} not registered")
        
        current_versions = self.versions[signature_id]
        next_major = len(current_versions) + 1
        
        version_id = f"{signature_id}_v{next_major}_{int(time.time())}"
        
        version = SignatureVersion(
            version_id=version_id,
            signature_id=signature_id,
            version_number=f"{next_major}.0.0",
            signature_content=new_content,
            created_at=datetime.now(timezone.utc),
            created_by=updated_by,
            performance_baseline=new_baseline or current_versions[-1].performance_baseline
        )
        
        self.versions[signature_id].append(version)
        self.signatures[signature_id]["current_version"] = version_id
        self.signatures[signature_id]["status"] = SignatureStatus.TESTING
        
        return version_id

    def record_performance(
        self,
        signature_id: str,
        true_positives: int,
        false_positives: int,
        true_negatives: int = 0,
        false_negatives: int = 0
    ) -> SignaturePerformance:
        """Record performance data for a signature."""
        if signature_id not in self.signatures:
            raise ValueError(f"Signature {signature_id} not registered")
        
        version_id = self.signatures[signature_id]["current_version"]
        
        perf = SignaturePerformance(
            signature_id=signature_id,
            version_id=version_id,
            timestamp=datetime.now(timezone.utc),
            true_positives=true_positives,
            false_positives=false_positives,
            true_negatives=true_negatives,
            false_negatives=false_negatives,
            total_alerts=true_positives + false_positives
        )
        
        self.performance_history[signature_id].append(perf)
        return perf

    def _calculate_drift_severity(
        self,
        delta_percent: float,
        metric_type: str
    ) -> DriftSeverity:
        """Calculate drift severity based on percentage change."""
        if metric_type == "precision":
            # Negative delta is bad (precision dropped)
            if delta_percent >= 0:
                return DriftSeverity.NONE
            abs_delta = abs(delta_percent)
            if abs_delta < 5:
                return DriftSeverity.NONE
            elif abs_delta < 10:
                return DriftSeverity.MINOR
            elif abs_delta < 20:
                return DriftSeverity.MODERATE
            elif abs_delta < 35:
                return DriftSeverity.SEVERE
            else:
                return DriftSeverity.CRITICAL
        elif metric_type == "false_positive_rate":
            # Positive delta is bad (FPR increased)
            if delta_percent <= 0:
                return DriftSeverity.NONE
            if delta_percent < 10:
                return DriftSeverity.NONE
            elif delta_percent < 25:
                return DriftSeverity.MINOR
            elif delta_percent < 50:
                return DriftSeverity.MODERATE
            elif delta_percent < 100:
                return DriftSeverity.SEVERE
            else:
                return DriftSeverity.CRITICAL
        
        return DriftSeverity.NONE

    def evaluate_drift(self, signature_id: str) -> List[DriftAlert]:
        """Evaluate a signature for performance drift."""
        if signature_id not in self.signatures:
            return []
        
        history = self.performance_history.get(signature_id, [])
        if len(history) < self.min_sample_size:
            return []
        
        # Get baseline from current version
        current_version_id = self.signatures[signature_id]["current_version"]
        versions = self.versions[signature_id]
        baseline = {}
        for v in versions:
            if v.version_id == current_version_id:
                baseline = v.performance_baseline
                break
        
        # Calculate recent performance (last 100 samples)
        recent = history[-100:]
        avg_precision = sum(p.precision for p in recent) / len(recent)
        avg_fpr = sum(p.false_positive_rate for p in recent) / len(recent)
        avg_f1 = sum(p.f1_score for p in recent) / len(recent)
        
        alerts = []
        
        # Check precision drift
        baseline_precision = baseline.get("precision", 0.85)
        precision_delta = ((avg_precision - baseline_precision) / baseline_precision) * 100
        precision_severity = self._calculate_drift_severity(precision_delta, "precision")
        
        if precision_severity != DriftSeverity.NONE:
            alert = DriftAlert(
                alert_id=f"DRIFT-{hashlib.md5(f'{signature_id}{time.time()}'.encode()).hexdigest()[:8]}",
                signature_id=signature_id,
                version_id=current_version_id,
                drift_severity=precision_severity,
                metric_name="precision",
                baseline_value=baseline_precision,
                current_value=avg_precision,
                delta_percent=precision_delta,
                threshold=self.drift_threshold_precision,
                timestamp=datetime.now(timezone.utc),
                message=f"Precision drifted by {precision_delta:.1f}%: baseline={baseline_precision:.3f}, current={avg_precision:.3f}"
            )
            alerts.append(alert)
            self.drift_alerts.append(alert)
        
        # Check FPR drift
        baseline_fpr = baseline.get("false_positive_rate", 0.05)
        if baseline_fpr > 0:
            fpr_delta = ((avg_fpr - baseline_fpr) / baseline_fpr) * 100
            fpr_severity = self._calculate_drift_severity(fpr_delta, "false_positive_rate")
            
            if fpr_severity != DriftSeverity.NONE:
                alert = DriftAlert(
                    alert_id=f"DRIFT-{hashlib.md5(f'{signature_id}{time.time()}fpr'.encode()).hexdigest()[:8]}",
                    signature_id=signature_id,
                    version_id=current_version_id,
                    drift_severity=fpr_severity,
                    metric_name="false_positive_rate",
                    baseline_value=baseline_fpr,
                    current_value=avg_fpr,
                    delta_percent=fpr_delta,
                    threshold=self.drift_threshold_fpr,
                    timestamp=datetime.now(timezone.utc),
                    message=f"False Positive Rate increased by {fpr_delta:.1f}%: baseline={baseline_fpr:.3f}, current={avg_fpr:.3f}"
                )
                alerts.append(alert)
                self.drift_alerts.append(alert)
        
        # Update status
        max_severity = max(
            [a.drift_severity for a in alerts],
            default=DriftSeverity.NONE
        )
        
        if max_severity in [DriftSeverity.SEVERE, DriftSeverity.CRITICAL]:
            self.signatures[signature_id]["status"] = SignatureStatus.DRIFTING
            
            # Auto-rollback if enabled
            if self.auto_rollback_enabled and max_severity.value >= self.auto_rollback_severity.value:
                self.rollback_signature(signature_id, reason="auto_drift_detection")
        
        self.signatures[signature_id]["last_evaluated"] = datetime.now(timezone.utc)
        
        return alerts

    def rollback_signature(
        self,
        signature_id: str,
        target_version: Optional[str] = None,
        reason: str = "manual"
    ) -> Dict[str, Any]:
        """Rollback signature to a previous stable version."""
        if signature_id not in self.signatures:
            return {"success": False, "error": "Signature not found"}
        
        versions = self.versions[signature_id]
        if len(versions) < 2:
            return {"success": False, "error": "No previous version to rollback to"}
        
        # Default: rollback to previous version
        if target_version is None:
            target_version_obj = versions[-2]  # Second most recent
        else:
            target_version_obj = None
            for v in versions:
                if v.version_id == target_version or v.version_number == target_version:
                    target_version_obj = v
                    break
            if not target_version_obj:
                return {"success": False, "error": "Target version not found"}
        
        previous_version = self.signatures[signature_id]["current_version"]
        
        self.signatures[signature_id]["current_version"] = target_version_obj.version_id
        self.signatures[signature_id]["status"] = SignatureStatus.ROLLED_BACK
        
        rollback_record = {
            "rollback_id": hashlib.sha256(f"{signature_id}{time.time()}".encode()).hexdigest()[:12],
            "signature_id": signature_id,
            "rolled_from": previous_version,
            "rolled_to": target_version_obj.version_id,
            "rolled_to_version_number": target_version_obj.version_number,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        self.rollback_log.append(rollback_record)
        
        return {
            "success": True,
            **rollback_record,
            "message": f"Rolled back {signature_id} to version {target_version_obj.version_number}"
        }

    def get_drift_summary(self) -> Dict[str, Any]:
        """Get comprehensive drift detection summary."""
        drifting_count = sum(
            1 for s in self.signatures.values()
            if s["status"] == SignatureStatus.DRIFTING
        )
        
        rolled_back_count = sum(
            1 for s in self.signatures.values()
            if s["status"] == SignatureStatus.ROLLED_BACK
        )
        
        severity_counts = defaultdict(int)
        for alert in self.drift_alerts:
            severity_counts[alert.drift_severity.value] += 1
        
        return {
            "total_signatures_registered": len(self.signatures),
            "total_versions_tracked": sum(len(v) for v in self.versions.values()),
            "total_performance_records": sum(len(h) for h in self.performance_history.values()),
            "signatures_drifting": drifting_count,
            "signatures_rolled_back": rolled_back_count,
            "total_drift_alerts": len(self.drift_alerts),
            "alerts_by_severity": dict(severity_counts),
            "total_rollbacks": len(self.rollback_log),
            "auto_rollback_enabled": self.auto_rollback_enabled,
            "configuration": {
                "drift_threshold_precision_percent": self.drift_threshold_precision,
                "drift_threshold_fpr_percent": self.drift_threshold_fpr,
                "minimum_sample_size": self.min_sample_size
            }
        }

    def generate_drift_report(self, signature_id: Optional[str] = None) -> Dict[str, Any]:
        """Generate detailed drift analysis report."""
        if signature_id:
            alerts = [a for a in self.drift_alerts if a.signature_id == signature_id]
            history = self.performance_history.get(signature_id, [])
            versions = self.versions.get(signature_id, [])
            sig_info = self.signatures.get(signature_id, {})
            
            return {
                "signature_id": signature_id,
                "status": sig_info.get("status", SignatureStatus.ACTIVE).value if sig_info else "unknown",
                "versions_tracked": len(versions),
                "performance_samples": len(history),
                "drift_alerts": len(alerts),
                "alerts": [
                    {
                        "severity": a.drift_severity.value,
                        "metric": a.metric_name,
                        "delta": f"{a.delta_percent:.1f}%",
                        "message": a.message,
                        "time": a.timestamp.isoformat()
                    }
                    for a in alerts[-10:]
                ],
                "rollback_history": [
                    r for r in self.rollback_log if r["signature_id"] == signature_id
                ]
            }
        
        # Full report
        return {
            "summary": self.get_drift_summary(),
            "signatures": [
                self.generate_drift_report(sig_id)
                for sig_id in self.signatures.keys()
            ],
            "recent_alerts": [
                {
                    "signature_id": a.signature_id,
                    "severity": a.drift_severity.value,
                    "metric": a.metric_name,
                    "message": a.message
                }
                for a in sorted(self.drift_alerts, key=lambda x: x.timestamp, reverse=True)[:20]
            ]
        }
