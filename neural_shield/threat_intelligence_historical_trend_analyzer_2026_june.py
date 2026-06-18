"""
NeuralShield-AI: Threat Intelligence Historical Trend Analyzer
June 2026 - Production Grade Implementation
Real working feature: Analyzes historical threat intelligence data to detect trends,
calculate moving averages, identify anomalies, and provide basic forecasting.
Enables security teams to understand threat patterns over time and make
data-driven decisions.
"""
import time
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from collections import defaultdict, deque
from datetime import datetime, timedelta
import statistics


class TrendDirection(Enum):
    """Direction of trend movement"""
    INCREASING = "increasing"
    DECREASING = "decreasing"
    STABLE = "stable"
    VOLATILE = "volatile"
    UNKNOWN = "unknown"


class AnomalySeverity(Enum):
    """Severity level for detected anomalies"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ThreatDataPoint:
    """Single data point in historical threat timeline"""
    timestamp: float
    threat_count: int
    threat_severity_avg: float
    unique_threat_types: int
    source_ip_count: int
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format"""
        return {
            "timestamp": self.timestamp,
            "datetime": datetime.fromtimestamp(self.timestamp).isoformat(),
            "threat_count": self.threat_count,
            "threat_severity_avg": self.threat_severity_avg,
            "unique_threat_types": self.unique_threat_types,
            "source_ip_count": self.source_ip_count,
            "metadata": self.metadata
        }


@dataclass
class TrendAnalysisResult:
    """Result of trend analysis for a time window"""
    window_start: float
    window_end: float
    data_points_count: int
    avg_threat_count: float
    avg_severity: float
    trend_direction: TrendDirection
    trend_slope: float
    volatility_score: float
    anomaly_count: int
    peak_threat_count: int
    peak_timestamp: Optional[float]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format"""
        return {
            "window_start": self.window_start,
            "window_end": self.window_end,
            "window_start_iso": datetime.fromtimestamp(self.window_start).isoformat(),
            "window_end_iso": datetime.fromtimestamp(self.window_end).isoformat(),
            "data_points_count": self.data_points_count,
            "avg_threat_count": round(self.avg_threat_count, 4),
            "avg_severity": round(self.avg_severity, 4),
            "trend_direction": self.trend_direction.value,
            "trend_slope": round(self.trend_slope, 6),
            "volatility_score": round(self.volatility_score, 4),
            "anomaly_count": self.anomaly_count,
            "peak_threat_count": self.peak_threat_count,
            "peak_timestamp": self.peak_timestamp,
            "peak_datetime": datetime.fromtimestamp(self.peak_timestamp).isoformat() if self.peak_timestamp else None
        }


@dataclass
class DetectedAnomaly:
    """Represents a detected anomaly in the data"""
    timestamp: float
    anomaly_type: str
    severity: AnomalySeverity
    expected_value: float
    actual_value: float
    deviation_percent: float
    description: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format"""
        return {
            "timestamp": self.timestamp,
            "datetime": datetime.fromtimestamp(self.timestamp).isoformat(),
            "anomaly_type": self.anomaly_type,
            "severity": self.severity.value,
            "expected_value": round(self.expected_value, 4),
            "actual_value": round(self.actual_value, 4),
            "deviation_percent": round(self.deviation_percent, 2),
            "description": self.description
        }


class HistoricalTrendAnalyzer:
    """
    Production-grade historical threat trend analyzer.
    
    Features:
    - Moving average calculation (SMA, EMA)
    - Trend detection and slope calculation
    - Anomaly detection using statistical methods
    - Volatility analysis
    - Peak detection
    - Basic forecasting using linear regression
    - Time window aggregation
    """

    def __init__(
        self,
        max_data_points: int = 10000,
        anomaly_sensitivity: float = 2.0,  # Number of standard deviations
        moving_average_window: int = 7,
        enable_forecasting: bool = True
    ):
        """
        Initialize the historical trend analyzer.
        
        Args:
            max_data_points: Maximum number of data points to store
            anomaly_sensitivity: Z-score threshold for anomaly detection
            moving_average_window: Default window size for moving averages
            enable_forecasting: Whether to enable forecasting features
        """
        self._data_points: deque = deque(maxlen=max_data_points)
        self._max_data_points = max_data_points
        self._anomaly_sensitivity = anomaly_sensitivity
        self._ma_window = moving_average_window
        self._enable_forecasting = enable_forecasting
        self._anomalies: List[DetectedAnomaly] = []

    def add_data_point(self, data_point: ThreatDataPoint) -> None:
        """
        Add a new data point to the analyzer.
        
        Args:
            data_point: ThreatDataPoint to add
        """
        self._data_points.append(data_point)
        
        # Check for anomalies in real-time if we have enough data
        if len(self._data_points) >= self._ma_window * 2:
            self._check_realtime_anomaly(data_point)

    def add_data_points_batch(self, data_points: List[ThreatDataPoint]) -> None:
        """
        Add multiple data points in batch.
        
        Args:
            data_points: List of ThreatDataPoint objects
        """
        # Sort by timestamp first
        sorted_points = sorted(data_points, key=lambda x: x.timestamp)
        for point in sorted_points:
            self.add_data_point(point)

    def _check_realtime_anomaly(self, point: ThreatDataPoint) -> None:
        """Check if a new data point is anomalous"""
        recent_points = list(self._data_points)[-self._ma_window * 4:-1]
        if len(recent_points) < 5:
            return

        threat_counts = [p.threat_count for p in recent_points]
        mean_count = statistics.mean(threat_counts)
        std_count = statistics.stdev(threat_counts) if len(threat_counts) > 1 else 0

        if std_count > 0:
            z_score = abs(point.threat_count - mean_count) / std_count
            
            if z_score > self._anomaly_sensitivity:
                deviation = ((point.threat_count - mean_count) / mean_count * 100) if mean_count > 0 else 0
                
                if z_score > 4.0:
                    severity = AnomalySeverity.CRITICAL
                elif z_score > 3.0:
                    severity = AnomalySeverity.HIGH
                elif z_score > 2.5:
                    severity = AnomalySeverity.MEDIUM
                else:
                    severity = AnomalySeverity.LOW
                
                anomaly = DetectedAnomaly(
                    timestamp=point.timestamp,
                    anomaly_type="threat_count_spike",
                    severity=severity,
                    expected_value=mean_count,
                    actual_value=point.threat_count,
                    deviation_percent=deviation,
                    description=f"Threat count spike detected: {point.threat_count} (expected ~{mean_count:.1f})"
                )
                self._anomalies.append(anomaly)

    def calculate_sma(self, field: str = "threat_count", window: Optional[int] = None) -> List[float]:
        """
        Calculate Simple Moving Average (SMA).
        
        Args:
            field: Field to calculate MA for ("threat_count", "threat_severity_avg", etc.)
            window: Window size (defaults to initialized value)
            
        Returns:
            List of SMA values
        """
        window_size = window or self._ma_window
        values = self._get_field_values(field)
        
        if len(values) < window_size:
            return []
        
        sma_values = []
        for i in range(window_size - 1, len(values)):
            window_vals = values[i - window_size + 1:i + 1]
            sma_values.append(sum(window_vals) / window_size)
        
        return sma_values

    def calculate_ema(self, field: str = "threat_count", window: Optional[int] = None) -> List[float]:
        """
        Calculate Exponential Moving Average (EMA).
        
        Args:
            field: Field to calculate EMA for
            window: Window size
            
        Returns:
            List of EMA values
        """
        window_size = window or self._ma_window
        values = self._get_field_values(field)
        
        if len(values) < window_size:
            return []
        
        multiplier = 2 / (window_size + 1)
        ema_values = [sum(values[:window_size]) / window_size]
        
        for i in range(window_size, len(values)):
            ema = (values[i] * multiplier) + (ema_values[-1] * (1 - multiplier))
            ema_values.append(ema)
        
        return ema_values

    def _get_field_values(self, field: str) -> List[float]:
        """Extract field values from data points"""
        field_map = {
            "threat_count": lambda p: p.threat_count,
            "threat_severity_avg": lambda p: p.threat_severity_avg,
            "unique_threat_types": lambda p: p.unique_threat_types,
            "source_ip_count": lambda p: p.source_ip_count
        }
        getter = field_map.get(field, lambda p: p.threat_count)
        return [float(getter(p)) for p in self._data_points]

    def detect_trend(self, field: str = "threat_count", lookback: int = 30) -> TrendAnalysisResult:
        """
        Detect trend in recent data.
        
        Args:
            field: Field to analyze
            lookback: Number of recent points to analyze
            
        Returns:
            TrendAnalysisResult with trend information
        """
        points = list(self._data_points)[-lookback:] if len(self._data_points) > lookback else list(self._data_points)
        
        if len(points) < 3:
            return TrendAnalysisResult(
                window_start=points[0].timestamp if points else 0,
                window_end=points[-1].timestamp if points else 0,
                data_points_count=len(points),
                avg_threat_count=0,
                avg_severity=0,
                trend_direction=TrendDirection.UNKNOWN,
                trend_slope=0,
                volatility_score=0,
                anomaly_count=0,
                peak_threat_count=0,
                peak_timestamp=None
            )

        values = self._get_field_values_for_points(points, field)
        threat_counts = [p.threat_count for p in points]
        severities = [p.threat_severity_avg for p in points]
        
        # Calculate linear regression slope
        slope = self._calculate_slope(values)
        
        # Determine trend direction
        if abs(slope) < 0.01:
            direction = TrendDirection.STABLE
        elif slope > 0.1:
            direction = TrendDirection.INCREASING
        elif slope < -0.1:
            direction = TrendDirection.DECREASING
        else:
            direction = TrendDirection.VOLATILE
        
        # Calculate volatility (coefficient of variation)
        mean_val = statistics.mean(values) if values else 0
        std_val = statistics.stdev(values) if len(values) > 1 else 0
        volatility = (std_val / mean_val) if mean_val > 0 else 0
        
        # Find peak
        peak_idx = threat_counts.index(max(threat_counts)) if threat_counts else 0
        
        window_anomalies = [a for a in self._anomalies 
                          if points[0].timestamp <= a.timestamp <= points[-1].timestamp]
        
        return TrendAnalysisResult(
            window_start=points[0].timestamp,
            window_end=points[-1].timestamp,
            data_points_count=len(points),
            avg_threat_count=statistics.mean(threat_counts) if threat_counts else 0,
            avg_severity=statistics.mean(severities) if severities else 0,
            trend_direction=direction,
            trend_slope=slope,
            volatility_score=volatility,
            anomaly_count=len(window_anomalies),
            peak_threat_count=max(threat_counts) if threat_counts else 0,
            peak_timestamp=points[peak_idx].timestamp if threat_counts else None
        )

    def _get_field_values_for_points(self, points: List[ThreatDataPoint], field: str) -> List[float]:
        """Get field values for specific points"""
        field_map = {
            "threat_count": lambda p: p.threat_count,
            "threat_severity_avg": lambda p: p.threat_severity_avg,
            "unique_threat_types": lambda p: p.unique_threat_types,
            "source_ip_count": lambda p: p.source_ip_count
        }
        getter = field_map.get(field, lambda p: p.threat_count)
        return [float(getter(p)) for p in points]

    def _calculate_slope(self, values: List[float]) -> float:
        """Calculate linear regression slope"""
        n = len(values)
        if n < 2:
            return 0
        
        x_indices = list(range(n))
        x_mean = sum(x_indices) / n
        y_mean = sum(values) / n
        
        numerator = sum((x_indices[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((x_indices[i] - x_mean) ** 2 for i in range(n))
        
        return numerator / denominator if denominator != 0 else 0

    def detect_anomalies(self, field: str = "threat_count") -> List[DetectedAnomaly]:
        """
        Run full anomaly detection on all historical data.
        
        Args:
            field: Field to check for anomalies
            
        Returns:
            List of detected anomalies
        """
        points = list(self._data_points)
        if len(points) < 10:
            return []
        
        values = self._get_field_values_for_points(points, field)
        window_size = min(10, len(values) // 3)
        
        anomalies = []
        
        for i in range(window_size, len(values)):
            window_vals = values[max(0, i - window_size):i]
            mean_val = statistics.mean(window_vals)
            std_val = statistics.stdev(window_vals) if len(window_vals) > 1 else 0
            
            if std_val > 0:
                z_score = abs(values[i] - mean_val) / std_val
                
                if z_score > self._anomaly_sensitivity:
                    deviation = ((values[i] - mean_val) / mean_val * 100) if mean_val > 0 else 0
                    
                    if z_score > 4.0:
                        severity = AnomalySeverity.CRITICAL
                    elif z_score > 3.0:
                        severity = AnomalySeverity.HIGH
                    elif z_score > 2.5:
                        severity = AnomalySeverity.MEDIUM
                    else:
                        severity = AnomalySeverity.LOW
                    
                    anomaly = DetectedAnomaly(
                        timestamp=points[i].timestamp,
                        anomaly_type=f"{field}_anomaly",
                        severity=severity,
                        expected_value=mean_val,
                        actual_value=values[i],
                        deviation_percent=deviation,
                        description=f"{field} anomaly: {values[i]} (expected ~{mean_val:.1f}, z-score: {z_score:.2f})"
                    )
                    anomalies.append(anomaly)
        
        return anomalies

    def forecast(self, field: str = "threat_count", steps: int = 5) -> List[Dict[str, Any]]:
        """
        Simple linear forecasting for future values.
        
        Args:
            field: Field to forecast
            steps: Number of steps to forecast ahead
            
        Returns:
            List of forecasted values with confidence intervals
        """
        if not self._enable_forecasting or len(self._data_points) < 10:
            return []
        
        points = list(self._data_points)
        values = self._get_field_values_for_points(points, field)
        
        # Use last 30 points for forecasting
        recent_values = values[-30:] if len(values) > 30 else values
        n = len(recent_values)
        
        # Calculate linear regression
        slope = self._calculate_slope(recent_values)
        intercept = statistics.mean(recent_values) - slope * (n - 1) / 2
        
        # Calculate prediction error (RMSE)
        predictions = [slope * i + intercept for i in range(n)]
        rmse = math.sqrt(sum((predictions[i] - recent_values[i]) ** 2 for i in range(n)) / n)
        
        # Time interval between points (estimate)
        if len(points) >= 2:
            time_interval = (points[-1].timestamp - points[0].timestamp) / (len(points) - 1)
        else:
            time_interval = 3600  # Default 1 hour
        
        forecasts = []
        last_timestamp = points[-1].timestamp
        
        for step in range(1, steps + 1):
            forecast_value = slope * (n + step - 1) + intercept
            forecasts.append({
                "step": step,
                "forecast_timestamp": last_timestamp + (step * time_interval),
                "forecast_datetime": datetime.fromtimestamp(last_timestamp + (step * time_interval)).isoformat(),
                "forecast_value": max(0, round(forecast_value, 2)),
                "lower_bound": max(0, round(forecast_value - 1.96 * rmse, 2)),
                "upper_bound": round(forecast_value + 1.96 * rmse, 2),
                "confidence_level": "95%"
            })
        
        return forecasts

    def aggregate_by_time_window(
        self,
        window_seconds: int = 3600  # 1 hour default
    ) -> List[Dict[str, Any]]:
        """
        Aggregate data points into time windows.
        
        Args:
            window_seconds: Window size in seconds
            
        Returns:
            List of aggregated window data
        """
        if not self._data_points:
            return []
        
        points = sorted(self._data_points, key=lambda x: x.timestamp)
        start_time = points[0].timestamp
        
        windows = defaultdict(list)
        
        for point in points:
            window_idx = int((point.timestamp - start_time) // window_seconds)
            windows[window_idx].append(point)
        
        aggregated = []
        for window_idx in sorted(windows.keys()):
            window_points = windows[window_idx]
            window_start = start_time + (window_idx * window_seconds)
            
            threat_counts = [p.threat_count for p in window_points]
            severities = [p.threat_severity_avg for p in window_points]
            
            aggregated.append({
                "window_start": window_start,
                "window_start_iso": datetime.fromtimestamp(window_start).isoformat(),
                "window_end": window_start + window_seconds,
                "window_end_iso": datetime.fromtimestamp(window_start + window_seconds).isoformat(),
                "points_in_window": len(window_points),
                "total_threats": sum(threat_counts),
                "avg_threats_per_point": round(statistics.mean(threat_counts), 2) if threat_counts else 0,
                "max_threats_in_point": max(threat_counts) if threat_counts else 0,
                "avg_severity": round(statistics.mean(severities), 4) if severities else 0,
                "total_unique_types": sum(p.unique_threat_types for p in window_points),
                "total_source_ips": sum(p.source_ip_count for p in window_points)
            })
        
        return aggregated

    def get_anomalies(self) -> List[DetectedAnomaly]:
        """Get all detected anomalies"""
        return self._anomalies.copy()

    def get_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive summary of historical analysis.
        
        Returns:
            Dictionary with summary statistics
        """
        points = list(self._data_points)
        if not points:
            return {"status": "no_data"}
        
        threat_counts = [p.threat_count for p in points]
        severities = [p.threat_severity_avg for p in points]
        
        trend = self.detect_trend()
        
        return {
            "total_data_points": len(points),
            "time_coverage": {
                "start": points[0].timestamp,
                "start_iso": datetime.fromtimestamp(points[0].timestamp).isoformat(),
                "end": points[-1].timestamp,
                "end_iso": datetime.fromtimestamp(points[-1].timestamp).isoformat(),
                "duration_hours": round((points[-1].timestamp - points[0].timestamp) / 3600, 2)
            },
            "threat_statistics": {
                "total_threats": sum(threat_counts),
                "avg_threats_per_point": round(statistics.mean(threat_counts), 2),
                "max_threats_single_point": max(threat_counts),
                "min_threats_single_point": min(threat_counts)
            },
            "severity_statistics": {
                "avg_severity": round(statistics.mean(severities), 4),
                "max_severity": round(max(severities), 4),
                "min_severity": round(min(severities), 4)
            },
            "current_trend": trend.to_dict(),
            "total_anomalies_detected": len(self._anomalies),
            "anomalies_by_severity": {
                "critical": sum(1 for a in self._anomalies if a.severity == AnomalySeverity.CRITICAL),
                "high": sum(1 for a in self._anomalies if a.severity == AnomalySeverity.HIGH),
                "medium": sum(1 for a in self._anomalies if a.severity == AnomalySeverity.MEDIUM),
                "low": sum(1 for a in self._anomalies if a.severity == AnomalySeverity.LOW)
            }
        }

    def __len__(self) -> int:
        return len(self._data_points)
