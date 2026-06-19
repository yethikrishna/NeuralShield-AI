"""
Threat Intelligence False Positive Reduction Engine
Production-grade implementation for NeuralShield-AI

This module implements a Bayesian false positive reduction system
for threat intelligence alerts, using historical baselines, context
awareness, and feedback learning to reduce alert fatigue.
"""

import hashlib
import json
import ipaddress
import time
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Any, Tuple
from collections import defaultdict
from enum import Enum


class FPConfidence(Enum):
    """Confidence levels for false positive classification"""
    SUPPRESS = "SUPPRESS"      # High confidence false positive
    REVIEW = "REVIEW"          # Potential false positive
    NORMAL = "NORMAL"          # Standard classification
    ESCALATE = "ESCALATE"      # High confidence true positive


@dataclass
class AlertContext:
    """Context for a single security alert"""
    alert_id: str
    alert_type: str
    source_ip: str
    destination_ip: str
    timestamp: float
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    ioc_value: str
    ioc_type: str  # IP, DOMAIN, HASH, URL
    raw_alert_data: Dict = field(default_factory=dict)
    confidence_score: float = 0.0
    is_false_positive: Optional[bool] = None
    feedback_count: int = 0
    
    def get_pattern_hash(self) -> str:
        """Generate a hash for the alert pattern"""
        pattern = f"{self.alert_type}:{self.ioc_type}:{self.ioc_value}"
        return hashlib.sha256(pattern.encode()).hexdigest()[:32]


@dataclass
class HistoricalBaseline:
    """Historical baseline for a threat pattern"""
    pattern_hash: str
    total_occurrences: int = 0
    false_positive_count: int = 0
    true_positive_count: int = 0
    last_seen: float = 0.0
    first_seen: float = 0.0
    
    def get_fp_rate(self, laplace_alpha: float = 1.0) -> float:
        """Get false positive rate with Laplace smoothing"""
        total = self.false_positive_count + self.true_positive_count
        return (self.false_positive_count + laplace_alpha) / (total + 2 * laplace_alpha)
    
    def get_sample_count(self) -> int:
        return self.false_positive_count + self.true_positive_count


class FalsePositiveReductionEngine:
    """
    Bayesian False Positive Reduction Engine
    
    Uses statistical learning and context awareness to reduce
    false positives in threat intelligence alerts.
    
    Core Features:
    - Bayesian probability calculation with Laplace smoothing
    - Historical baseline tracking
    - Context-aware whitelisting (private IPs, test domains)
    - Time-decayed weighting of recent patterns
    - Feedback learning loop
    - Performance statistics tracking
    """
    
    # RFC 1918 private IP ranges
    PRIVATE_IP_NETS = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
    ]
    
    # Common test/development domain patterns
    TEST_DOMAIN_PATTERNS = [
        'test.', 'dev.', 'local.', 'staging.', 'example.',
        '.test', '.local', '.internal', '.localhost'
    ]
    
    def __init__(self,
                 fp_threshold: float = 0.75,
                 max_history: int = 10000,
                 time_half_life_hours: float = 168.0,  # 7 days
                 laplace_alpha: float = 1.0):
        """
        Initialize the False Positive Reduction Engine
        
        Args:
            fp_threshold: Probability threshold for FP classification
            max_history: Maximum number of historical patterns to track
            time_half_life_hours: Half-life for time decay weighting
            laplace_alpha: Smoothing parameter for Bayesian calculation
        """
        self.fp_threshold = fp_threshold
        self.max_history = max_history
        self.time_half_life_hours = time_half_life_hours
        self.laplace_alpha = laplace_alpha
        
        # Historical baselines
        self.baselines: Dict[str, HistoricalBaseline] = {}
        
        # Statistics
        self.stats = {
            'total_alerts_processed': 0,
            'false_positives_detected': 0,
            'true_positives_confirmed': 0,
            'feedback_received': 0,
            'whitelist_hits': 0
        }
    
    @staticmethod
    def _is_private_ip(ip_str: str) -> bool:
        """Check if IP is in private/reserved ranges"""
        try:
            ip = ipaddress.ip_address(ip_str)
            for net in FalsePositiveReductionEngine.PRIVATE_IP_NETS:
                if ip in net:
                    return True
            return False
        except ValueError:
            return False
    
    @staticmethod
    def _is_test_domain(domain: str) -> bool:
        """Check if domain is a test/development domain"""
        domain_lower = domain.lower()
        for pattern in FalsePositiveReductionEngine.TEST_DOMAIN_PATTERNS:
            if pattern in domain_lower:
                return True
        return False
    
    def _get_time_decay_factor(self, last_seen: float, now: float) -> float:
        """Calculate time decay factor using exponential decay"""
        time_diff_hours = (now - last_seen) / 3600.0
        decay_factor = 2 ** (-time_diff_hours / self.time_half_life_hours)
        return decay_factor
    
    def _calculate_bayesian_fp_prob(self, baseline: HistoricalBaseline) -> float:
        """
        Calculate Bayesian probability that pattern is a false positive
        
        P(FP | Pattern) = (FP_count + α) / (FP_count + TP_count + 2α)
        """
        return baseline.get_fp_rate(self.laplace_alpha)
    
    def _get_whitelist_score(self, alert: AlertContext) -> float:
        """
        Calculate whitelist score based on context
        
        Returns:
            0.0 - No whitelist match
            0.5 - Partial whitelist match
            1.0 - Strong whitelist match (private IP, test domain)
        """
        score = 0.0
        
        # Check source IP
        if self._is_private_ip(alert.source_ip):
            score += 0.5
        
        # Check destination IP
        if self._is_private_ip(alert.destination_ip):
            score += 0.5
        
        # Check IOC value for IPs
        if alert.ioc_type == 'IP' and self._is_private_ip(alert.ioc_value):
            score += 0.5
        
        # Check domain IOCs
        if alert.ioc_type == 'DOMAIN' and self._is_test_domain(alert.ioc_value):
            score += 0.5
        
        return min(score, 1.0)
    
    def process_alert(self, alert: AlertContext) -> Tuple[float, FPConfidence]:
        """
        Process a single alert and return false positive probability
        
        Args:
            alert: AlertContext object
            
        Returns:
            (fp_probability, confidence_level)
        """
        now = time.time()
        pattern_hash = alert.get_pattern_hash()
        
        self.stats['total_alerts_processed'] += 1
        
        # Step 1: Get whitelist score
        whitelist_score = self._get_whitelist_score(alert)
        
        if whitelist_score >= 0.5:
            self.stats['whitelist_hits'] += 1
        
        # Step 2: Get historical baseline
        baseline = self.baselines.get(pattern_hash)
        
        if baseline is None:
            # New pattern - no history
            historical_fp_prob = 0.5  # Uninformative prior
            history_weight = 0.0
        else:
            # Apply time decay
            decay = self._get_time_decay_factor(baseline.last_seen, now)
            historical_fp_prob = self._calculate_bayesian_fp_prob(baseline)
            
            # Weight based on sample size (more samples = more weight)
            sample_count = baseline.get_sample_count()
            history_weight = min(sample_count / 100.0, 0.6)
        
        # Step 3: Combine scores
        # Whitelist gets higher weight for strong matches
        whitelist_weight = whitelist_score * 0.8
        
        # Weighted combination
        total_weight = whitelist_weight + history_weight
        
        if total_weight > 0:
            fp_probability = (
                whitelist_score * whitelist_weight +
                historical_fp_prob * history_weight
            ) / total_weight
        else:
            fp_probability = 0.5  # Default: uncertain
        
        # Step 4: Determine confidence level
        if fp_probability >= 0.9:
            confidence = FPConfidence.SUPPRESS
            self.stats['false_positives_detected'] += 1
        elif fp_probability >= self.fp_threshold:
            confidence = FPConfidence.REVIEW
        elif fp_probability >= 0.4:
            confidence = FPConfidence.NORMAL
        else:
            confidence = FPConfidence.ESCALATE
            self.stats['true_positives_confirmed'] += 1
        
        alert.confidence_score = fp_probability
        alert.is_false_positive = (fp_probability >= self.fp_threshold)
        
        # Update baseline last seen
        if baseline is not None:
            baseline.last_seen = now
        
        return fp_probability, confidence
    
    def process_batch(self, alerts: List[AlertContext]) -> List[Tuple[float, FPConfidence]]:
        """Process a batch of alerts"""
        return [self.process_alert(alert) for alert in alerts]
    
    def record_feedback(self, alert: AlertContext, is_actually_fp: bool) -> None:
        """
        Record human feedback for learning
        
        Args:
            alert: The alert that was reviewed
            is_actually_fp: True if human marked as false positive
        """
        pattern_hash = alert.get_pattern_hash()
        now = time.time()
        
        # Get or create baseline
        if pattern_hash not in self.baselines:
            self.baselines[pattern_hash] = HistoricalBaseline(
                pattern_hash=pattern_hash,
                first_seen=now
            )
        
        baseline = self.baselines[pattern_hash]
        baseline.total_occurrences += 1
        
        if is_actually_fp:
            baseline.false_positive_count += 1
        else:
            baseline.true_positive_count += 1
        
        baseline.last_seen = now
        alert.feedback_count += 1
        
        self.stats['feedback_received'] += 1
        
        # Prune old entries if needed
        if len(self.baselines) > self.max_history:
            # Remove oldest by last_seen
            sorted_patterns = sorted(
                self.baselines.items(),
                key=lambda x: x[1].last_seen
            )
            remove_count = len(self.baselines) - self.max_history
            for key, _ in sorted_patterns[:remove_count]:
                del self.baselines[key]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get engine performance statistics"""
        stats = dict(self.stats)
        
        # Calculate derived metrics
        if stats['total_alerts_processed'] > 0:
            stats['fp_reduction_rate'] = (
                stats['false_positives_detected'] / stats['total_alerts_processed']
            )
        else:
            stats['fp_reduction_rate'] = 0.0
        
        stats['baseline_count'] = len(self.baselines)
        
        # Sample size distribution
        sample_counts = [b.get_sample_count() for b in self.baselines.values()]
        if sample_counts:
            stats['avg_samples_per_baseline'] = sum(sample_counts) / len(sample_counts)
        else:
            stats['avg_samples_per_baseline'] = 0
        
        return stats
    
    def export_model(self, filepath: str) -> None:
        """Export baseline model to JSON file"""
        export_data = {
            'metadata': {
                'export_time': time.time(),
                'fp_threshold': self.fp_threshold,
                'time_half_life_hours': self.time_half_life_hours,
                'laplace_alpha': self.laplace_alpha
            },
            'statistics': self.get_statistics(),
            'baselines': [
                asdict(baseline) for baseline in self.baselines.values()
            ]
        }
        
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)
    
    def import_model(self, filepath: str) -> None:
        """Import baseline model from JSON file"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        self.fp_threshold = data['metadata']['fp_threshold']
        self.time_half_life_hours = data['metadata']['time_half_life_hours']
        self.laplace_alpha = data['metadata']['laplace_alpha']
        
        self.baselines = {}
        for baseline_data in data['baselines']:
            self.baselines[baseline_data['pattern_hash']] = HistoricalBaseline(
                **baseline_data
            )


# Export public interface
__all__ = [
    'FPConfidence',
    'AlertContext',
    'HistoricalBaseline',
    'FalsePositiveReductionEngine'
]
