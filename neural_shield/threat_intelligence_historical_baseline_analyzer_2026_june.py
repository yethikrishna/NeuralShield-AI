"""
Threat Intelligence Historical Baseline Analyzer
Production-grade module for establishing and monitoring threat baseline patterns

This module provides:
- Statistical baseline calculation from historical threat data
- Real-time anomaly detection against established baselines
- Baseline drift detection and alerting
- Time-window based pattern analysis
- Confidence scoring for baseline deviations
"""

import json
import time
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict, deque
from datetime import datetime, timedelta
import math

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class BaselineMetrics:
    """Data structure for baseline metrics storage"""
    mean_threat_score: float = 0.0
    std_threat_score: float = 0.0
    min_threat_score: float = 0.0
    max_threat_score: float = 0.0
    threat_count_per_hour: Dict[str, int] = field(default_factory=dict)
    threat_type_distribution: Dict[str, float] = field(default_factory=dict)
    source_ip_frequency: Dict[str, float] = field(default_factory=dict)
    attack_vector_frequency: Dict[str, float] = field(default_factory=dict)
    sample_size: int = 0
    baseline_timestamp: float = 0.0
    confidence_level: float = 0.0


@dataclass
class AnomalyResult:
    """Result structure for anomaly detection"""
    is_anomaly: bool
    anomaly_score: float
    deviation_from_baseline: float
    baseline_comparison: Dict[str, Any]
    contributing_factors: List[str]
    severity_level: str
    recommendation: str
    timestamp: float


class ThreatIntelligenceHistoricalBaselineAnalyzer:
    """
    Production-grade baseline analyzer for threat intelligence
    
    Establishes statistical baselines from historical threat data and detects
    anomalies in real-time threat feeds against these baselines.
    """
    
    def __init__(
        self,
        baseline_window_hours: int = 168,  # 7 days default
        anomaly_threshold_std: float = 2.5,
        min_samples_for_baseline: int = 100,
        drift_detection_enabled: bool = True
    ):
        self.baseline_window_hours = baseline_window_hours
        self.anomaly_threshold_std = anomaly_threshold_std
        self.min_samples_for_baseline = min_samples_for_baseline
        self.drift_detection_enabled = drift_detection_enabled
        
        # Data storage
        self._historical_data: deque = deque(maxlen=100000)
        self._current_baseline: Optional[BaselineMetrics] = None
        self._baseline_history: List[BaselineMetrics] = []
        self._drift_alerts: List[Dict[str, Any]] = []
        
        # Configuration
        self._severity_levels = {
            'low': {'threshold': 1.0, 'color': 'yellow'},
            'medium': {'threshold': 2.0, 'color': 'orange'},
            'high': {'threshold': 3.0, 'color': 'red'},
            'critical': {'threshold': 4.0, 'color': 'purple'}
        }
        
        logger.info(f"Baseline Analyzer initialized with {baseline_window_hours}h window")
    
    def add_historical_threat(self, threat_data: Dict[str, Any]) -> bool:
        """
        Add threat data to historical dataset for baseline calculation
        
        Args:
            threat_data: Dictionary containing threat information
                Required fields: threat_score, threat_type, timestamp
                Optional fields: source_ip, attack_vector, severity
                
        Returns:
            True if successfully added
        """
        required_fields = ['threat_score', 'threat_type', 'timestamp']
        for field in required_fields:
            if field not in threat_data:
                logger.warning(f"Missing required field: {field}")
                return False
        
        # Normalize and validate
        try:
            threat_data['threat_score'] = float(threat_data['threat_score'])
            threat_data['timestamp'] = float(threat_data['timestamp'])
        except (ValueError, TypeError):
            logger.warning("Invalid numeric values in threat data")
            return False
        
        self._historical_data.append(threat_data)
        return True
    
    def calculate_baseline(self, force_recalculate: bool = False) -> Tuple[bool, BaselineMetrics]:
        """
        Calculate statistical baseline from historical data
        
        Args:
            force_recalculate: Force recalculation even if baseline exists
            
        Returns:
            Tuple of (success, BaselineMetrics)
        """
        if self._current_baseline and not force_recalculate:
            return True, self._current_baseline
        
        if len(self._historical_data) < self.min_samples_for_baseline:
            logger.warning(
                f"Insufficient samples for baseline: {len(self._historical_data)} "
                f"need {self.min_samples_for_baseline}"
            )
            return False, BaselineMetrics()
        
        # Filter data within baseline window
        cutoff_time = time.time() - (self.baseline_window_hours * 3600)
        window_data = [
            d for d in self._historical_data 
            if d['timestamp'] >= cutoff_time
        ]
        
        if not window_data:
            logger.warning("No data within baseline window")
            return False, BaselineMetrics()
        
        # Calculate statistics
        threat_scores = [d['threat_score'] for d in window_data]
        n = len(window_data)
        
        # Basic stats
        mean_score = sum(threat_scores) / n
        variance = sum((x - mean_score) ** 2 for x in threat_scores) / n
        std_score = math.sqrt(variance) if variance > 0 else 0.0
        
        # Threat type distribution
        threat_type_counts = defaultdict(int)
        for d in window_data:
            threat_type_counts[d['threat_type']] += 1
        
        threat_type_dist = {
            t: c / n for t, c in threat_type_counts.items()
        }
        
        # Hourly distribution
        hourly_counts = defaultdict(int)
        for d in window_data:
            hour_key = datetime.fromtimestamp(d['timestamp']).strftime('%H')
            hourly_counts[hour_key] += 1
        
        # Source IP frequency (if available)
        ip_counts = defaultdict(int)
        for d in window_data:
            ip = d.get('source_ip', 'unknown')
            ip_counts[ip] += 1
        
        ip_frequency = {
            ip: c / n for ip, c in ip_counts.items()
        }
        
        # Attack vector frequency
        vector_counts = defaultdict(int)
        for d in window_data:
            vector = d.get('attack_vector', 'unknown')
            vector_counts[vector] += 1
        
        vector_frequency = {
            v: c / n for v, c in vector_counts.items()
        }
        
        # Confidence calculation based on sample size
        confidence = min(1.0, n / (self.min_samples_for_baseline * 2))
        
        baseline = BaselineMetrics(
            mean_threat_score=mean_score,
            std_threat_score=std_score,
            min_threat_score=min(threat_scores),
            max_threat_score=max(threat_scores),
            threat_count_per_hour=dict(hourly_counts),
            threat_type_distribution=threat_type_dist,
            source_ip_frequency=ip_frequency,
            attack_vector_frequency=vector_frequency,
            sample_size=n,
            baseline_timestamp=time.time(),
            confidence_level=confidence
        )
        
        self._current_baseline = baseline
        self._baseline_history.append(baseline)
        
        # Check for baseline drift if enabled
        if self.drift_detection_enabled and len(self._baseline_history) > 1:
            self._detect_baseline_drift()
        
        logger.info(
            f"Baseline calculated: {n} samples, "
            f"mean={mean_score:.3f}, std={std_score:.3f}, "
            f"confidence={confidence:.2f}"
        )
        
        return True, baseline
    
    def detect_anomaly(self, threat_data: Dict[str, Any]) -> AnomalyResult:
        """
        Detect if threat data is anomalous compared to baseline
        
        Args:
            threat_data: Threat data to analyze
            
        Returns:
            AnomalyResult with detection details
        """
        if not self._current_baseline:
            success, _ = self.calculate_baseline()
            if not success:
                return AnomalyResult(
                    is_anomaly=False,
                    anomaly_score=0.0,
                    deviation_from_baseline=0.0,
                    baseline_comparison={},
                    contributing_factors=["Baseline not yet established"],
                    severity_level="unknown",
                    recommendation="Collect more historical data first",
                    timestamp=time.time()
                )
        
        baseline = self._current_baseline
        contributing_factors = []
        total_deviation = 0.0
        
        # 1. Threat score deviation (primary factor)
        threat_score = float(threat_data.get('threat_score', 0))
        score_deviation = abs(threat_score - baseline.mean_threat_score)
        
        if baseline.std_threat_score > 0:
            score_std_devs = score_deviation / baseline.std_threat_score
        else:
            score_std_devs = score_deviation if score_deviation > 0 else 0
        
        if score_std_devs > self.anomaly_threshold_std:
            contributing_factors.append(
                f"Threat score deviation: {score_std_devs:.2f}σ from mean"
            )
            total_deviation += score_std_devs
        
        # 2. Threat type rarity check
        threat_type = threat_data.get('threat_type', 'unknown')
        type_frequency = baseline.threat_type_distribution.get(threat_type, 0.0)
        
        if type_frequency < 0.01:  # Less than 1% occurrence
            rarity_score = (1.0 - type_frequency) * 2
            contributing_factors.append(
                f"Rare threat type: {threat_type} ({type_frequency:.2%} occurrence)"
            )
            total_deviation += rarity_score
        
        # 3. Source IP rarity check
        source_ip = threat_data.get('source_ip', 'unknown')
        ip_frequency = baseline.source_ip_frequency.get(source_ip, 0.0)
        
        if ip_frequency < 0.005:  # Less than 0.5% occurrence
            ip_rarity = (1.0 - ip_frequency) * 1.5
            contributing_factors.append(
                f"Unusual source IP: {source_ip}"
            )
            total_deviation += ip_rarity
        
        # 4. Hourly pattern check
        current_hour = datetime.fromtimestamp(
            threat_data.get('timestamp', time.time())
        ).strftime('%H')
        
        hourly_avg = baseline.threat_count_per_hour.get(current_hour, 0)
        if hourly_avg == 0 and len(baseline.threat_count_per_hour) > 0:
            contributing_factors.append(
                f"Unusual activity hour: {current_hour}:00"
            )
            total_deviation += 1.0
        
        # Determine severity
        anomaly_score = total_deviation / max(1, len(contributing_factors)) if contributing_factors else 0
        is_anomaly = anomaly_score >= self.anomaly_threshold_std
        
        severity_level = 'normal'
        for level, config in sorted(
            self._severity_levels.items(), 
            key=lambda x: x[1]['threshold'], 
            reverse=True
        ):
            if anomaly_score >= config['threshold']:
                severity_level = level
                break
        
        # Generate recommendation
        if is_anomaly:
            if severity_level == 'critical':
                recommendation = "Immediate investigation required - activate incident response"
            elif severity_level == 'high':
                recommendation = "Priority investigation recommended - flag for security team review"
            elif severity_level == 'medium':
                recommendation = "Monitor closely - schedule for review within 24 hours"
            else:
                recommendation = "Log and monitor - no immediate action required"
        else:
            recommendation = "Within normal baseline parameters - routine monitoring"
        
        return AnomalyResult(
            is_anomaly=is_anomaly,
            anomaly_score=round(anomaly_score, 3),
            deviation_from_baseline=round(score_std_devs, 3),
            baseline_comparison={
                'baseline_mean': round(baseline.mean_threat_score, 3),
                'baseline_std': round(baseline.std_threat_score, 3),
                'actual_score': round(threat_score, 3),
                'sample_size': baseline.sample_size
            },
            contributing_factors=contributing_factors,
            severity_level=severity_level,
            recommendation=recommendation,
            timestamp=time.time()
        )
    
    def _detect_baseline_drift(self) -> None:
        """Detect significant drift between consecutive baselines"""
        if len(self._baseline_history) < 2:
            return
        
        current = self._baseline_history[-1]
        previous = self._baseline_history[-2]
        
        drift_detected = False
        drift_factors = []
        
        # Check mean shift
        mean_shift = abs(current.mean_threat_score - previous.mean_threat_score)
        if mean_shift > (previous.std_threat_score * 0.5):
            drift_detected = True
            drift_factors.append(f"Mean threat score shifted: {mean_shift:.3f}")
        
        # Check distribution shift
        type_shift = 0.0
        all_types = set(current.threat_type_distribution.keys()) | set(previous.threat_type_distribution.keys())
        for t in all_types:
            curr = current.threat_type_distribution.get(t, 0)
            prev = previous.threat_type_distribution.get(t, 0)
            type_shift += abs(curr - prev)
        
        if type_shift > 0.3:  # More than 30% distribution change
            drift_detected = True
            drift_factors.append(f"Threat type distribution shifted: {type_shift:.1%}")
        
        if drift_detected:
            alert = {
                'drift_detected': True,
                'factors': drift_factors,
                'previous_baseline_time': previous.baseline_timestamp,
                'current_baseline_time': current.baseline_timestamp,
                'timestamp': time.time()
            }
            self._drift_alerts.append(alert)
            logger.warning(f"Baseline drift detected: {drift_factors}")
    
    def get_baseline_summary(self) -> Dict[str, Any]:
        """Get human-readable baseline summary"""
        if not self._current_baseline:
            return {'status': 'No baseline established'}
        
        b = self._current_baseline
        return {
            'status': 'active',
            'summary': {
                'sample_size': b.sample_size,
                'confidence_level': f"{b.confidence_level:.1%}",
                'mean_threat_score': round(b.mean_threat_score, 3),
                'std_deviation': round(b.std_threat_score, 3),
                'score_range': f"{b.min_threat_score:.2f} - {b.max_threat_score:.2f}"
            },
            'top_threat_types': dict(sorted(
                b.threat_type_distribution.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:5]),
            'drift_alerts_count': len(self._drift_alerts),
            'baseline_age_hours': round(
                (time.time() - b.baseline_timestamp) / 3600, 1
            )
        }
    
    def export_baseline(self, filepath: str) -> bool:
        """Export baseline to JSON file for persistence"""
        if not self._current_baseline:
            return False
        
        try:
            export_data = {
                'baseline': {
                    'mean_threat_score': self._current_baseline.mean_threat_score,
                    'std_threat_score': self._current_baseline.std_threat_score,
                    'min_threat_score': self._current_baseline.min_threat_score,
                    'max_threat_score': self._current_baseline.max_threat_score,
                    'threat_type_distribution': self._current_baseline.threat_type_distribution,
                    'sample_size': self._current_baseline.sample_size,
                    'confidence_level': self._current_baseline.confidence_level,
                    'timestamp': self._current_baseline.baseline_timestamp
                },
                'export_time': time.time(),
                'version': '1.0.0'
            }
            
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            logger.info(f"Baseline exported to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to export baseline: {e}")
            return False
