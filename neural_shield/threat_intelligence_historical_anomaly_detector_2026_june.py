"""
Threat Intelligence Historical Anomaly Detector - Production Grade
NeuralShield-AI Module
June 18, 2026

Provides historical baseline tracking and real-time anomaly detection for:
- Request frequency anomalies (sudden traffic spikes)
- User behavior pattern deviations
- Threat signature evolution tracking
- Statistical outlier detection using Z-score & IQR methods
- Rolling window baseline calculation
- Adaptive thresholding with confidence scoring
- Historical trend analysis
"""
import re
import math
import time
import hashlib
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
from datetime import datetime, timedelta
import threading
import statistics


class AnomalyType(Enum):
    """Types of detectable anomalies"""
    FREQUENCY_SPIKE = "FREQUENCY_SPIKE"
    FREQUENCY_DROP = "FREQUENCY_DROP"
    BEHAVIOR_DEVIATION = "BEHAVIOR_DEVIATION"
    THREAT_SIGNATURE_SHIFT = "THREAT_SIGNATURE_SHIFT"
    USER_OUTLIER = "USER_OUTLIER"
    IP_GEO_ANOMALY = "IP_GEO_ANOMALY"
    STATISTICAL_OUTLIER = "STATISTICAL_OUTLIER"


class AnomalySeverity(Enum):
    """Anomaly severity levels"""
    NORMAL = "NORMAL"
    WARNING = "WARNING"
    ALERT = "ALERT"
    CRITICAL = "CRITICAL"


@dataclass
class AnomalyDetectionResult:
    """Complete anomaly detection result"""
    is_anomaly: bool
    severity: AnomalySeverity
    anomaly_score: float
    anomaly_types: List[AnomalyType] = field(default_factory=list)
    baseline_metrics: Dict[str, float] = field(default_factory=dict)
    current_metrics: Dict[str, float] = field(default_factory=dict)
    deviation_details: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    timestamp: float = field(default_factory=time.time)
    recommended_action: str = "MONITOR"


@dataclass
class BaselineWindow:
    """Time window for baseline calculation"""
    window_size_seconds: int
    data_points: deque = field(default_factory=deque)
    timestamps: deque = field(default_factory=deque)
    max_points: int = 10000

    def add_point(self, value: float, timestamp: Optional[float] = None):
        """Add a data point to the window"""
        ts = timestamp or time.time()
        self.data_points.append(value)
        self.timestamps.append(ts)
        
        while len(self.data_points) > self.max_points:
            self.data_points.popleft()
            self.timestamps.popleft()
        
        # Remove points outside window
        cutoff = ts - self.window_size_seconds
        while self.timestamps and self.timestamps[0] < cutoff:
            self.data_points.popleft()
            self.timestamps.popleft()

    def get_statistics(self) -> Dict[str, float]:
        """Calculate statistics for the window"""
        if not self.data_points:
            return {"count": 0, "mean": 0, "std": 0, "min": 0, "max": 0, "median": 0, "q1": 0, "q3": 0}
        
        data = list(self.data_points)
        sorted_data = sorted(data)
        n = len(data)
        
        mean = sum(data) / n
        variance = sum((x - mean) ** 2 for x in data) / n if n > 0 else 0
        std = math.sqrt(variance)
        
        median = sorted_data[n // 2] if n % 2 == 1 else (sorted_data[n // 2 - 1] + sorted_data[n // 2]) / 2
        q1 = sorted_data[n // 4] if n >= 4 else sorted_data[0]
        q3 = sorted_data[(3 * n) // 4] if n >= 4 else sorted_data[-1]
        
        return {
            "count": n,
            "mean": mean,
            "std": std,
            "min": min(data),
            "max": max(data),
            "median": median,
            "q1": q1,
            "q3": q3,
            "iqr": q3 - q1
        }


class HistoricalAnomalyDetector:
    """
    Production-grade historical anomaly detector with:
    - Rolling baseline windows (1min, 5min, 15min, 1hour)
    - Z-score and IQR outlier detection
    - Multi-dimensional anomaly scoring
    - Thread-safe operation
    - Adaptive thresholding
    """
    
    def __init__(self, 
                 short_window_sec: int = 60,
                 medium_window_sec: int = 300,
                 long_window_sec: int = 900,
                 z_score_threshold: float = 3.0,
                 iqr_factor: float = 1.5):
        """
        Initialize anomaly detector
        
        Args:
            short_window_sec: Short rolling window (default: 60s)
            medium_window_sec: Medium rolling window (default: 5min)
            long_window_sec: Long rolling window (default: 15min)
            z_score_threshold: Z-score threshold for anomaly detection
            iqr_factor: IQR factor for outlier detection
        """
        self.z_score_threshold = z_score_threshold
        self.iqr_factor = iqr_factor
        
        # Baseline windows for different time scales
        self.baselines = {
            "request_rate": {
                "short": BaselineWindow(short_window_sec),
                "medium": BaselineWindow(medium_window_sec),
                "long": BaselineWindow(long_window_sec)
            },
            "threat_score": {
                "short": BaselineWindow(short_window_sec),
                "medium": BaselineWindow(medium_window_sec),
                "long": BaselineWindow(long_window_sec)
            },
            "unique_users": {
                "short": BaselineWindow(short_window_sec),
                "medium": BaselineWindow(medium_window_sec),
                "long": BaselineWindow(long_window_sec)
            }
        }
        
        # Per-user tracking
        self.user_baselines: Dict[str, BaselineWindow] = {}
        
        # Per-IP tracking
        self.ip_baselines: Dict[str, BaselineWindow] = {}
        
        # Request counter for rate calculation
        self._request_counter = 0
        self._last_rate_calc = time.time()
        
        # Detection statistics
        self.stats = {
            "total_checked": 0,
            "anomalies_detected": 0,
            "anomaly_types": defaultdict(int),
            "severity_counts": defaultdict(int)
        }
        
        self._lock = threading.RLock()
    
    def _calculate_z_score(self, value: float, mean: float, std: float) -> float:
        """Calculate Z-score, handle zero std deviation"""
        if std == 0:
            return 0.0 if abs(value - mean) < 1e-10 else float('inf')
        return abs(value - mean) / std
    
    def _is_iqr_outlier(self, value: float, q1: float, q3: float) -> Tuple[bool, float]:
        """Check if value is IQR outlier, return (is_outlier, deviation_score)"""
        iqr = q3 - q1
        lower_bound = q1 - self.iqr_factor * iqr
        upper_bound = q3 + self.iqr_factor * iqr
        
        if value < lower_bound:
            deviation = (lower_bound - value) / max(iqr, 1e-10)
            return True, deviation
        elif value > upper_bound:
            deviation = (value - upper_bound) / max(iqr, 1e-10)
            return True, deviation
        return False, 0.0
    
    def update_baseline(self, 
                        request_rate: float, 
                        threat_score: float = 0.0,
                        user_id: Optional[str] = None,
                        ip_address: Optional[str] = None) -> None:
        """
        Update baseline metrics with new data
        
        Args:
            request_rate: Current requests per second
            threat_score: Current threat score (0-1)
            user_id: Optional user identifier
            ip_address: Optional IP address
        """
        with self._lock:
            ts = time.time()
            
            # Update global baselines
            self.baselines["request_rate"]["short"].add_point(request_rate, ts)
            self.baselines["request_rate"]["medium"].add_point(request_rate, ts)
            self.baselines["request_rate"]["long"].add_point(request_rate, ts)
            
            self.baselines["threat_score"]["short"].add_point(threat_score, ts)
            self.baselines["threat_score"]["medium"].add_point(threat_score, ts)
            self.baselines["threat_score"]["long"].add_point(threat_score, ts)
            
            # Update per-user baseline
            if user_id:
                if user_id not in self.user_baselines:
                    self.user_baselines[user_id] = BaselineWindow(3600)
                self.user_baselines[user_id].add_point(threat_score, ts)
            
            # Update per-IP baseline
            if ip_address:
                if ip_address not in self.ip_baselines:
                    self.ip_baselines[ip_address] = BaselineWindow(3600)
                self.ip_baselines[ip_address].add_point(request_rate, ts)
    
    def detect_anomalies(self,
                         current_request_rate: float,
                         current_threat_score: float = 0.0,
                         user_id: Optional[str] = None,
                         ip_address: Optional[str] = None) -> AnomalyDetectionResult:
        """
        Detect anomalies against historical baselines
        
        Args:
            current_request_rate: Current requests per second
            current_threat_score: Current threat score
            user_id: Optional user identifier
            ip_address: Optional IP address
            
        Returns:
            AnomalyDetectionResult with complete analysis
        """
        with self._lock:
            self.stats["total_checked"] += 1
            
            anomaly_types: List[AnomalyType] = []
            anomaly_scores: List[float] = []
            deviation_details: Dict[str, Any] = {}
            
            # Get baseline statistics
            rate_stats_long = self.baselines["request_rate"]["long"].get_statistics()
            threat_stats_long = self.baselines["threat_score"]["long"].get_statistics()
            
            baseline_metrics = {
                "baseline_request_rate_mean": rate_stats_long["mean"],
                "baseline_request_rate_std": rate_stats_long["std"],
                "baseline_threat_mean": threat_stats_long["mean"],
                "baseline_threat_std": threat_stats_long["std"],
                "baseline_sample_count": rate_stats_long["count"]
            }
            
            current_metrics = {
                "current_request_rate": current_request_rate,
                "current_threat_score": current_threat_score
            }
            
            # 1. Frequency spike/drop detection (Z-score)
            if rate_stats_long["count"] >= 10:  # Need sufficient data
                rate_z = self._calculate_z_score(
                    current_request_rate,
                    rate_stats_long["mean"],
                    rate_stats_long["std"]
                )
                
                deviation_details["request_rate_z_score"] = rate_z
                
                if rate_z > self.z_score_threshold:
                    if current_request_rate > rate_stats_long["mean"]:
                        anomaly_types.append(AnomalyType.FREQUENCY_SPIKE)
                    else:
                        anomaly_types.append(AnomalyType.FREQUENCY_DROP)
                    anomaly_scores.append(min(rate_z / 5.0, 1.0))
            
            # 2. IQR outlier detection
            if rate_stats_long["count"] >= 4:
                is_outlier, iqr_dev = self._is_iqr_outlier(
                    current_request_rate,
                    rate_stats_long["q1"],
                    rate_stats_long["q3"]
                )
                if is_outlier:
                    anomaly_types.append(AnomalyType.STATISTICAL_OUTLIER)
                    anomaly_scores.append(min(iqr_dev / 3.0, 1.0))
                    deviation_details["iqr_deviation"] = iqr_dev
            
            # 3. Threat score anomaly detection
            if threat_stats_long["count"] >= 10:
                threat_z = self._calculate_z_score(
                    current_threat_score,
                    threat_stats_long["mean"],
                    threat_stats_long["std"]
                )
                
                deviation_details["threat_z_score"] = threat_z
                
                if threat_z > self.z_score_threshold and current_threat_score > threat_stats_long["mean"]:
                    anomaly_types.append(AnomalyType.THREAT_SIGNATURE_SHIFT)
                    anomaly_scores.append(min(threat_z / 5.0, 1.0))
            
            # 4. Per-user behavior anomaly
            if user_id and user_id in self.user_baselines:
                user_stats = self.user_baselines[user_id].get_statistics()
                if user_stats["count"] >= 5:
                    user_z = self._calculate_z_score(
                        current_threat_score,
                        user_stats["mean"],
                        user_stats["std"]
                    )
                    if user_z > self.z_score_threshold * 0.8:
                        anomaly_types.append(AnomalyType.USER_OUTLIER)
                        anomaly_scores.append(min(user_z / 4.0, 1.0))
                        deviation_details["user_deviation_z"] = user_z
            
            # Calculate overall anomaly score
            overall_score = max(anomaly_scores) if anomaly_scores else 0.0
            
            # Determine severity
            if overall_score >= 0.8:
                severity = AnomalySeverity.CRITICAL
            elif overall_score >= 0.5:
                severity = AnomalySeverity.ALERT
            elif overall_score >= 0.25:
                severity = AnomalySeverity.WARNING
            else:
                severity = AnomalySeverity.NORMAL
            
            # Determine action
            if severity == AnomalySeverity.CRITICAL:
                action = "TRIGGER_ALERT_AND_RATE_LIMIT"
            elif severity == AnomalySeverity.ALERT:
                action = "FLAG_AND_INVESTIGATE"
            elif severity == AnomalySeverity.WARNING:
                action = "INCREASE_MONITORING"
            else:
                action = "NORMAL_MONITORING"
            
            is_anomaly = len(anomaly_types) > 0 and severity != AnomalySeverity.NORMAL
            
            if is_anomaly:
                self.stats["anomalies_detected"] += 1
                for at in anomaly_types:
                    self.stats["anomaly_types"][at.value] += 1
                self.stats["severity_counts"][severity.value] += 1
            
            confidence = min(0.95, 0.5 + (rate_stats_long["count"] / 100.0) * 0.45)
            
            return AnomalyDetectionResult(
                is_anomaly=is_anomaly,
                severity=severity,
                anomaly_score=round(overall_score, 4),
                anomaly_types=anomaly_types,
                baseline_metrics=baseline_metrics,
                current_metrics=current_metrics,
                deviation_details=deviation_details,
                confidence=round(confidence, 4),
                recommended_action=action
            )
    
    def get_detection_statistics(self) -> Dict[str, Any]:
        """Get anomaly detection statistics"""
        with self._lock:
            anomaly_rate = (self.stats["anomalies_detected"] / max(self.stats["total_checked"], 1)) * 100
            return {
                "total_events_analyzed": self.stats["total_checked"],
                "anomalies_detected": self.stats["anomalies_detected"],
                "anomaly_rate_percent": round(anomaly_rate, 2),
                "anomaly_type_breakdown": dict(self.stats["anomaly_types"]),
                "severity_breakdown": dict(self.stats["severity_counts"]),
                "tracked_users": len(self.user_baselines),
                "tracked_ips": len(self.ip_baselines)
            }
    
    def get_baseline_summary(self) -> Dict[str, Any]:
        """Get current baseline summary"""
        with self._lock:
            return {
                "request_rate": {
                    window: self.baselines["request_rate"][window].get_statistics()
                    for window in ["short", "medium", "long"]
                },
                "threat_score": {
                    window: self.baselines["threat_score"][window].get_statistics()
                    for window in ["short", "medium", "long"]
                }
            }
    
    def record_request(self) -> float:
        """Record a request and return current request rate"""
        with self._lock:
            self._request_counter += 1
            now = time.time()
            elapsed = now - self._last_rate_calc
            
            if elapsed >= 1.0:
                rate = self._request_counter / elapsed
                self._request_counter = 0
                self._last_rate_calc = now
                return rate
            return self._request_counter / max(elapsed, 0.1)
