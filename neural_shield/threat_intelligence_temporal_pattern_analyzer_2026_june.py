"""
NeuralShield-AI: Threat Intelligence Temporal Pattern Analyzer
June 2026 - Real Production-Grade Implementation

Analyzes time-based patterns in threat intelligence data to detect:
- Periodic attack patterns
- Anomalous activity spikes
- Emerging threat trends
- Seasonal attack patterns
- Temporal correlation between threat events
"""

import time
import math
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from collections import defaultdict, deque
from enum import Enum


class PatternType(Enum):
    PERIODIC = "periodic"
    ANOMALY_SPIKE = "anomaly_spike"
    EMERGING_TREND = "emerging_trend"
    SEASONAL = "seasonal"
    BURST = "burst"
    CORRELATED = "correlated"


class ThreatSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TemporalEvent:
    timestamp: float
    threat_type: str
    source_ip: str
    severity: ThreatSeverity
    metadata: Dict[str, Any]


@dataclass
class DetectedPattern:
    pattern_type: PatternType
    confidence: float
    start_time: float
    end_time: float
    description: str
    affected_threats: List[str]
    severity_score: float


@dataclass
class AnomalyResult:
    is_anomaly: bool
    anomaly_score: float
    baseline_mean: float
    baseline_std: float
    current_value: float
    threshold: float


class TemporalPatternAnalyzer:
    """
    Production-grade temporal pattern analyzer for threat intelligence.
    Uses statistical methods, sliding windows, and autocorrelation.
    """

    def __init__(
        self,
        window_size_seconds: int = 3600,  # 1 hour default window
        sliding_step_seconds: int = 300,   # 5 minute steps
        anomaly_threshold_sigma: float = 3.0,
        min_events_for_analysis: int = 10
    ):
        self.window_size = window_size_seconds
        self.sliding_step = sliding_step_seconds
        self.anomaly_threshold = anomaly_threshold_sigma
        self.min_events = min_events_for_analysis
        
        # Event storage - bounded deque for memory efficiency
        self.events: deque = deque(maxlen=100000)
        
        # Time bucket storage for fast aggregation
        self.time_buckets: Dict[int, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        
        # Baseline statistics
        self.baselines: Dict[str, Dict[str, float]] = {}
        self.pattern_history: List[DetectedPattern] = []
        
        # Autocorrelation lags to check
        self.autocorrelation_lags = [60, 300, 900, 1800, 3600, 7200, 14400, 86400]

    def add_event(self, event: TemporalEvent) -> None:
        """Add a threat event to the analyzer."""
        self.events.append(event)
        
        # Bucket events by 60-second intervals
        bucket_key = int(event.timestamp // 60)
        self.time_buckets[bucket_key][event.threat_type] += 1
        self.time_buckets[bucket_key]["_total"] += 1

    def add_event_simple(
        self,
        threat_type: str,
        source_ip: str = "unknown",
        severity: ThreatSeverity = ThreatSeverity.MEDIUM,
        metadata: Optional[Dict] = None
    ) -> None:
        """Simplified interface to add events with current timestamp."""
        event = TemporalEvent(
            timestamp=time.time(),
            threat_type=threat_type,
            source_ip=source_ip,
            severity=severity,
            metadata=metadata or {}
        )
        self.add_event(event)

    def _get_time_series(self, threat_type: Optional[str] = None) -> List[Tuple[int, int]]:
        """Get time series data for a specific threat type or all threats."""
        series = []
        key = threat_type if threat_type else "_total"
        
        for bucket, counts in sorted(self.time_buckets.items()):
            series.append((bucket * 60, counts.get(key, 0)))
        
        return series

    def _calculate_statistics(self, values: List[float]) -> Tuple[float, float]:
        """Calculate mean and standard deviation."""
        if not values:
            return 0.0, 0.0
        
        n = len(values)
        mean = sum(values) / n
        variance = sum((x - mean) ** 2 for x in values) / n
        std = math.sqrt(variance)
        
        return mean, std

    def detect_anomaly(
        self,
        threat_type: Optional[str] = None,
        window_minutes: int = 60
    ) -> AnomalyResult:
        """
        Detect anomalies using z-score method on sliding window.
        Returns anomaly score and detection result.
        """
        series = self._get_time_series(threat_type)
        if len(series) < self.min_events:
            return AnomalyResult(
                is_anomaly=False,
                anomaly_score=0.0,
                baseline_mean=0.0,
                baseline_std=0.0,
                current_value=0.0,
                threshold=self.anomaly_threshold
            )

        # Get recent window and historical baseline
        cutoff_time = time.time() - (window_minutes * 60)
        recent_values = []
        historical_values = []
        
        for ts, count in series:
            if ts >= cutoff_time:
                recent_values.append(count)
            else:
                historical_values.append(count)
        
        if not historical_values or not recent_values:
            return AnomalyResult(
                is_anomaly=False,
                anomaly_score=0.0,
                baseline_mean=0.0,
                baseline_std=0.0,
                current_value=0.0,
                threshold=self.anomaly_threshold
            )

        baseline_mean, baseline_std = self._calculate_statistics(historical_values)
        current_mean, _ = self._calculate_statistics(recent_values)
        
        if baseline_std == 0:
            anomaly_score = 0.0 if current_mean <= baseline_mean else 5.0
        else:
            anomaly_score = abs(current_mean - baseline_mean) / baseline_std
        
        is_anomaly = anomaly_score >= self.anomaly_threshold
        
        return AnomalyResult(
            is_anomaly=is_anomaly,
            anomaly_score=anomaly_score,
            baseline_mean=baseline_mean,
            baseline_std=baseline_std,
            current_value=current_mean,
            threshold=self.anomaly_threshold
        )

    def _calculate_autocorrelation(self, values: List[float], lag: int) -> float:
        """Calculate autocorrelation at specified lag."""
        if len(values) <= lag:
            return 0.0
        
        mean, std = self._calculate_statistics(values)
        if std == 0:
            return 0.0
        
        n = len(values) - lag
        autocorr = sum(
            (values[i] - mean) * (values[i + lag] - mean)
            for i in range(n)
        ) / (n * std * std)
        
        return autocorr

    def detect_periodic_patterns(
        self,
        threat_type: Optional[str] = None,
        min_correlation: float = 0.6
    ) -> List[Dict[str, Any]]:
        """
        Detect periodic patterns using autocorrelation.
        Identifies recurring attack patterns at common intervals.
        """
        series = self._get_time_series(threat_type)
        if len(series) < 50:
            return []
        
        values = [count for _, count in series]
        detected_periods = []
        
        for lag_seconds in self.autocorrelation_lags:
            lag_buckets = lag_seconds // 60  # convert to bucket intervals
            if lag_buckets >= len(values):
                continue
                
            corr = self._calculate_autocorrelation(values, lag_buckets)
            
            if corr >= min_correlation:
                detected_periods.append({
                    "period_seconds": lag_seconds,
                    "period_minutes": lag_seconds // 60,
                    "autocorrelation": corr,
                    "confidence": min(0.95, corr * 0.8 + 0.2)
                })
        
        return sorted(detected_periods, key=lambda x: -x["confidence"])

    def detect_emerging_trends(
        self,
        threat_type: Optional[str] = None,
        lookback_hours: int = 24,
        trend_threshold: float = 2.0
    ) -> Dict[str, Any]:
        """
        Detect emerging threat trends using linear regression slope.
        Identifies threats that are increasing significantly over time.
        """
        series = self._get_time_series(threat_type)
        if len(series) < 10:
            return {
                "is_emerging": False,
                "trend_slope": 0.0,
                "growth_ratio": 1.0,
                "confidence": 0.0
            }
        
        cutoff_time = time.time() - (lookback_hours * 3600)
        recent_series = [(ts, count) for ts, count in series if ts >= cutoff_time]
        
        if len(recent_series) < 5:
            return {
                "is_emerging": False,
                "trend_slope": 0.0,
                "growth_ratio": 1.0,
                "confidence": 0.0
            }
        
        # Simple linear regression for trend slope
        n = len(recent_series)
        x_values = list(range(n))
        y_values = [count for _, count in recent_series]
        
        x_mean = sum(x_values) / n
        y_mean = sum(y_values) / n
        
        numerator = sum(
            (x - x_mean) * (y - y_mean)
            for x, y in zip(x_values, y_values)
        )
        denominator = sum((x - x_mean) ** 2 for x in x_values)
        
        slope = numerator / denominator if denominator != 0 else 0.0
        
        # Calculate growth ratio (first half vs second half)
        mid = n // 2
        first_half_avg = sum(y_values[:mid]) / mid if mid > 0 else 0
        second_half_avg = sum(y_values[mid:]) / (n - mid) if (n - mid) > 0 else 0
        
        growth_ratio = (
            second_half_avg / first_half_avg
            if first_half_avg > 0 else float('inf')
        )
        
        is_emerging = slope > 0 and growth_ratio >= trend_threshold
        confidence = min(0.9, (slope * 10 + growth_ratio) / 15) if is_emerging else 0.0
        
        return {
            "is_emerging": is_emerging,
            "trend_slope": slope,
            "growth_ratio": growth_ratio,
            "confidence": max(0.0, min(1.0, confidence))
        }

    def detect_burst_activity(
        self,
        threat_type: Optional[str] = None,
        burst_window_seconds: int = 300,
        min_burst_multiplier: float = 3.0
    ) -> Dict[str, Any]:
        """
        Detect burst activity - sudden high-volume events in short windows.
        """
        series = self._get_time_series(threat_type)
        if len(series) < 5:
            return {
                "is_burst": False,
                "burst_intensity": 0.0,
                "peak_count": 0,
                "baseline_rate": 0.0
            }
        
        all_counts = [count for _, count in series]
        baseline_rate = sum(all_counts) / len(all_counts) if all_counts else 0
        
        # Check recent windows for burst activity
        recent_cutoff = time.time() - burst_window_seconds
        recent_counts = [
            count for ts, count in series
            if ts >= recent_cutoff
        ]
        
        if not recent_counts:
            return {
                "is_burst": False,
                "burst_intensity": 0.0,
                "peak_count": 0,
                "baseline_rate": baseline_rate
            }
        
        peak_count = max(recent_counts)
        burst_intensity = peak_count / baseline_rate if baseline_rate > 0 else float('inf')
        is_burst = burst_intensity >= min_burst_multiplier and peak_count >= 5
        
        return {
            "is_burst": is_burst,
            "burst_intensity": burst_intensity,
            "peak_count": peak_count,
            "baseline_rate": baseline_rate
        }

    def analyze_all_patterns(self) -> List[DetectedPattern]:
        """Run full analysis and return all detected patterns."""
        results = []
        now = time.time()
        
        # 1. Check for anomalies
        anomaly_result = self.detect_anomaly()
        if anomaly_result.is_anomaly:
            results.append(DetectedPattern(
                pattern_type=PatternType.ANOMALY_SPIKE,
                confidence=min(0.95, anomaly_result.anomaly_score / 5),
                start_time=now - 3600,
                end_time=now,
                description=f"Anomaly detected: {anomaly_result.current_value:.1f} events vs baseline {anomaly_result.baseline_mean:.1f}",
                affected_threats=["all_threats"],
                severity_score=min(1.0, anomaly_result.anomaly_score / 10)
            ))
        
        # 2. Check for periodic patterns
        periodic_patterns = self.detect_periodic_patterns()
        for pattern in periodic_patterns[:3]:
            results.append(DetectedPattern(
                pattern_type=PatternType.PERIODIC,
                confidence=pattern["confidence"],
                start_time=now - 86400,
                end_time=now,
                description=f"Periodic attack pattern detected every {pattern['period_minutes']} minutes",
                affected_threats=["all_threats"],
                severity_score=0.6
            ))
        
        # 3. Check for emerging trends
        trend_result = self.detect_emerging_trends()
        if trend_result["is_emerging"]:
            results.append(DetectedPattern(
                pattern_type=PatternType.EMERGING_TREND,
                confidence=trend_result["confidence"],
                start_time=now - 86400,
                end_time=now,
                description=f"Emerging threat trend detected: {trend_result['growth_ratio']:.1f}x growth",
                affected_threats=["all_threats"],
                severity_score=0.7
            ))
        
        # 4. Check for burst activity
        burst_result = self.detect_burst_activity()
        if burst_result["is_burst"]:
            results.append(DetectedPattern(
                pattern_type=PatternType.BURST,
                confidence=min(0.9, burst_result["burst_intensity"] / 10),
                start_time=now - 300,
                end_time=now,
                description=f"Burst activity detected: peak {burst_result['peak_count']} events",
                affected_threats=["all_threats"],
                severity_score=0.8
            ))
        
        self.pattern_history.extend(results)
        return results

    def get_temporal_summary(self) -> Dict[str, Any]:
        """Get comprehensive summary of temporal analysis."""
        return {
            "total_events": len(self.events),
            "time_buckets_analyzed": len(self.time_buckets),
            "patterns_detected_total": len(self.pattern_history),
            "current_anomaly": self.detect_anomaly(),
            "periodic_patterns": self.detect_periodic_patterns(),
            "emerging_trends": self.detect_emerging_trends(),
            "burst_activity": self.detect_burst_activity()
        }


# Export public interface
__all__ = [
    "TemporalPatternAnalyzer",
    "TemporalEvent",
    "DetectedPattern",
    "AnomalyResult",
    "PatternType",
    "ThreatSeverity"
]
