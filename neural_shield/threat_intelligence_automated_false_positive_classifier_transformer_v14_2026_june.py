"""
NeuralShield-AI: Threat Intelligence Automated False Positive Classifier - Transformer v14
DIMENSION A: Feature Expansion - ADD-ONLY Implementation
Builds on v10-v13 with:
- Ensemble voting across multiple classification strategies
- Bayesian probability calibration
- Temporal drift detection and adaptation
- Enhanced multi-modal feature extraction
- Explainable AI (XAI) signal attribution
"""

import re
import hashlib
import time
import math
from typing import Dict, List, Tuple, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import threading
from collections import deque


class IOCCategory(Enum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    CVE = "cve"
    SIGNATURE = "signature"
    UNKNOWN = "unknown"


class ClassificationStrategy(Enum):
    PATTERN_MATCHING = "pattern_matching"
    SEMANTIC_SIMILARITY = "semantic_similarity"
    STATISTICAL_ANALYSIS = "statistical_analysis"
    ENTROPY_BASED = "entropy_based"
    REPUTATION_BASED = "reputation_based"


@dataclass
class EnsembleVote:
    strategy: ClassificationStrategy
    vote: bool  # True = FP, False = Threat
    confidence: float
    weight: float
    contributing_features: List[str]


@dataclass
class ClassificationResultV14:
    ioc_value: str
    ioc_category: IOCCategory
    is_false_positive: bool
    final_confidence: float
    threat_score: float
    fp_score: float
    ensemble_votes: List[EnsembleVote] = field(default_factory=list)
    false_positive_signals: List[str] = field(default_factory=list)
    threat_signals: List[str] = field(default_factory=list)
    xai_attribution: Dict[str, float] = field(default_factory=dict)
    classification_reason: str = ""
    processing_time_ms: float = 0.0
    drift_detected: bool = False
    model_version: str = "v14_ensemble"


@dataclass
class ClassificationContext:
    source_feed: str = ""
    threat_actor: str = ""
    mitre_technique: str = ""
    severity: str = "medium"
    environment_context: Dict[str, Any] = field(default_factory=dict)
    historical_fp_rate: float = 0.0
    temporal_window_hours: float = 24.0


class BayesianCalibrator:
    """
    Bayesian probability calibration for false positive scores
    Uses prior probabilities and likelihood ratios for better calibration
    """
    
    def __init__(self):
        # Prior probabilities from historical data
        self.prior_fp_probability = 0.35  # 35% base FP rate
        self.prior_threat_probability = 0.65
        
        # Likelihood ratios for different signal types
        self.likelihood_ratios = {
            'private_ip': 100.0,      # Strong FP indicator
            'localhost': 150.0,
            'cloud_cdn': 25.0,
            'cve_pattern': 0.05,      # Strong threat indicator
            'malware_pattern': 0.02,
            'benign_domain': 50.0,
            'high_entropy_hash': 0.1,
            'low_entropy_domain': 20.0,
        }
        
    def calibrate_probability(
        self, 
        raw_score: float, 
        signals: List[str]
    ) -> float:
        """
        Apply Bayesian calibration to raw score
        P(FP|Signals) = P(Signals|FP) * P(FP) / P(Signals)
        """
        posterior_odds = self.prior_fp_probability / self.prior_threat_probability
        
        for signal in signals:
            for key, lr in self.likelihood_ratios.items():
                if key in signal.lower():
                    posterior_odds *= lr
                    
        # Convert back to probability
        calibrated_prob = posterior_odds / (1 + posterior_odds)
        
        # Blend with raw score for stability
        alpha = 0.7
        final = alpha * calibrated_prob + (1 - alpha) * raw_score
        
        return max(0.0, min(1.0, final))
    
    def update_priors(self, fp_rate: float):
        """Update prior probabilities based on observed rates"""
        self.prior_fp_probability = max(0.05, min(0.8, fp_rate))
        self.prior_threat_probability = 1.0 - self.prior_fp_probability


class TemporalDriftDetector:
    """
    Detect temporal drift in classification patterns
    Identifies when threat patterns change over time
    """
    
    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.fp_history = deque(maxlen=window_size)
        self.score_history = deque(maxlen=window_size)
        self.baseline_fp_rate = 0.35
        self.baseline_mean_score = 0.5
        self.baseline_std_score = 0.25
        self._lock = threading.Lock()
        
    def add_sample(self, is_fp: bool, score: float):
        """Add classification sample for drift detection"""
        with self._lock:
            self.fp_history.append(1.0 if is_fp else 0.0)
            self.score_history.append(score)
            
    def detect_drift(self) -> Tuple[bool, Dict[str, float]]:
        """
        Detect if distribution has shifted significantly
        Uses statistical process control methods
        """
        with self._lock:
            if len(self.fp_history) < self.window_size // 2:
                return False, {'drift_score': 0.0}
                
            current_fp_rate = sum(self.fp_history) / len(self.fp_history)
            current_mean = sum(self.score_history) / len(self.score_history)
            
            # Calculate z-scores
            fp_rate_delta = abs(current_fp_rate - self.baseline_fp_rate)
            score_delta = abs(current_mean - self.baseline_mean_score)
            
            # Drift detection thresholds (3 sigma rule)
            fp_threshold = 3 * 0.05  # 5% std dev assumption
            score_threshold = 3 * (self.baseline_std_score / math.sqrt(len(self.score_history)))
            
            drift_detected = fp_rate_delta > fp_threshold or score_delta > score_threshold
            
            metrics = {
                'current_fp_rate': current_fp_rate,
                'baseline_fp_rate': self.baseline_fp_rate,
                'fp_rate_delta': fp_rate_delta,
                'current_mean_score': current_mean,
                'baseline_mean_score': self.baseline_mean_score,
                'score_delta': score_delta,
                'drift_score': max(fp_rate_delta / fp_threshold, score_delta / score_threshold)
            }
            
            return drift_detected, metrics
            
    def update_baseline(self):
        """Update baseline to current distribution (adaptation)"""
        with self._lock:
            if len(self.fp_history) >= self.window_size // 2:
                self.baseline_fp_rate = sum(self.fp_history) / len(self.fp_history)
                self.baseline_mean_score = sum(self.score_history) / len(self.score_history)


class EntropyAnalyzer:
    """
    Entropy-based feature extraction for IOC classification
    High entropy = more likely to be randomly generated (malicious)
    Low entropy = more likely to be human-readable (benign)
    """
    
    @staticmethod
    def shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy of string"""
        if not text:
            return 0.0
            
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
            
        entropy = 0.0
        length = len(text)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
            
        return entropy
        
    @staticmethod
    def normalized_entropy(text: str) -> float:
        """Normalized entropy (0-1 range)"""
        if len(text) <= 1:
            return 0.0
        max_entropy = math.log2(min(len(text), 256))
        if max_entropy == 0:
            return 0.0
        return EntropyAnalyzer.shannon_entropy(text) / max_entropy
        
    def classify_by_entropy(self, text: str, category: IOCCategory) -> Tuple[float, List[str]]:
        """Classify based on entropy characteristics"""
        entropy = self.shannon_entropy(text)
        norm_entropy = self.normalized_entropy(text)
        signals = []
        score = 0.5
        
        # Category-specific entropy thresholds
        thresholds = {
            IOCCategory.DOMAIN: {'low': 2.5, 'high': 4.0},
            IOCCategory.FILE_HASH: {'low': 3.5, 'high': 4.5},
            IOCCategory.URL: {'low': 3.0, 'high': 4.5},
            IOCCategory.IP_ADDRESS: {'low': 1.0, 'high': 2.5},
        }
        
        thresh = thresholds.get(category, {'low': 2.5, 'high': 4.0})
        
        if entropy < thresh['low']:
            # Low entropy = structured, human-generated = likely FP
            score = 0.75
            signals.append(f"LOW_ENTROPY:{entropy:.2f}")
        elif entropy > thresh['high']:
            # High entropy = random = likely threat
            score = 0.25
            signals.append(f"HIGH_ENTROPY:{entropy:.2f}")
        else:
            score = 0.5
            
        # Check for random-looking strings in domains
        if category == IOCCategory.DOMAIN:
            # Check for excessive numbers or hyphens
            num_count = sum(1 for c in text if c.isdigit())
            hyphen_count = text.count('-')
            if num_count > len(text) * 0.3:
                score *= 0.7  # More threat-like
                signals.append("EXCESSIVE_DIGITS")
            if hyphen_count > 3:
                score *= 0.8
                signals.append("EXCESSIVE_HYPHENS")
                
        return score, signals


class EnsembleVotingClassifier:
    """
    Ensemble voting across multiple classification strategies
    Weighted voting with confidence-based weighting
    """
    
    def __init__(self):
        self.strategy_weights = {
            ClassificationStrategy.PATTERN_MATCHING: 1.5,  # Higher weight for pattern matching
            ClassificationStrategy.SEMANTIC_SIMILARITY: 0.8,
            ClassificationStrategy.STATISTICAL_ANALYSIS: 0.7,
            ClassificationStrategy.ENTROPY_BASED: 0.6,
            ClassificationStrategy.REPUTATION_BASED: 1.2,
        }
        self.bayesian = BayesianCalibrator()
        
    def vote(
        self,
        strategy: ClassificationStrategy,
        fp_score: float,
        confidence: float,
        signals: List[str],
        threshold: float = 0.5
    ) -> EnsembleVote:
        """Generate vote from single strategy"""
        weight = self.strategy_weights.get(strategy, 1.0) * confidence
        
        # Apply Bayesian calibration
        calibrated_score = self.bayesian.calibrate_probability(fp_score, signals)
        
        return EnsembleVote(
            strategy=strategy,
            vote=calibrated_score > threshold,
            confidence=calibrated_score,
            weight=weight,
            contributing_features=signals
        )
        
    def combine_votes(self, votes: List[EnsembleVote]) -> Tuple[bool, float, float, Dict[str, float]]:
        """
        Combine votes using weighted average of FP confidence
        Returns: (is_fp, final_confidence, weighted_score, attribution)
        """
        if not votes:
            return False, 0.5, 0.5, {}
            
        total_weight = sum(v.weight for v in votes)
        if total_weight == 0:
            return False, 0.5, 0.5, {}
            
        # Weighted average of confidence across all votes
        # Each vote contributes v.weight * v.confidence (where v.confidence is FP probability)
        weighted_fp_score = sum(v.weight * v.confidence for v in votes) / total_weight
        
        # Simple threshold for classification
        fp_threshold = 0.5
        is_fp = weighted_fp_score > fp_threshold
        
        # Confidence is distance from threshold
        final_confidence = abs(weighted_fp_score - fp_threshold) * 2
        
        # XAI attribution - which strategies contributed most
        attribution = {}
        for v in votes:
            contribution = (v.weight * abs(v.confidence - 0.5)) / total_weight
            attribution[v.strategy.value] = round(contribution, 4)
            
        return is_fp, final_confidence, weighted_fp_score, attribution


class FalsePositiveClassifierV14:
    """
    Automated False Positive Classifier - Transformer v14
    ENSEMBLE Edition with Bayesian calibration and drift detection
    
    NEW in v14:
    - 5-strategy ensemble voting system
    - Bayesian probability calibration
    - Temporal drift detection and adaptation
    - Entropy-based statistical analysis
    - XAI feature attribution
    - Enhanced explainability
    """
    
    def __init__(self):
        self.ensemble = EnsembleVotingClassifier()
        self.entropy = EntropyAnalyzer()
        self.drift_detector = TemporalDriftDetector()
        self.classification_stats: Dict[str, int] = {
            'total_classified': 0,
            'false_positives': 0,
            'true_threats': 0,
            'drift_events_detected': 0,
        }
        self._lock = threading.Lock()
        self._init_patterns()
        
    def _init_patterns(self):
        """Initialize classification patterns"""
        # False positive patterns
        self.fp_patterns = {
            r'^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)': 'private_ip',
            r'^(127\.|0\.0\.0\.0|255\.)': 'localhost',
            r'\.(google|microsoft|apple|amazonaws|cloudflare|akamai)\.': 'cloud_cdn',
            r'^(cdn|static|assets|content)\.': 'cdn_prefix',
            r'example\.|test\.|dev\.|staging\.': 'test_domain',
            r'localhost': 'localhost',
        }
        
        # Threat patterns
        self.threat_patterns = {
            r'CVE-\d{4}-\d{4,7}': 'cve_pattern',
            r'(malware|ransomware|trojan|virus|exploit)': 'malware_pattern',
            r'(c2|command.*control|cnc)': 'c2_pattern',
            r'(phish|spoof|fake)': 'phish_pattern',
        }
        
    def _pattern_matching_strategy(
        self, 
        ioc: str, 
        category: IOCCategory
    ) -> Tuple[float, List[str]]:
        """Strategy 1: Regex pattern matching"""
        score = 0.5
        signals = []
        
        for pattern, name in self.fp_patterns.items():
            if re.search(pattern, ioc, re.IGNORECASE):
                score = min(1.0, score + 0.35)  # Stronger FP signal
                signals.append(f"FP:{name}")
                
        for pattern, name in self.threat_patterns.items():
            if re.search(pattern, ioc, re.IGNORECASE):
                score = max(0.0, score - 0.35)  # Stronger threat signal
                signals.append(f"THREAT:{name}")
                
        return score, signals
        
    def _reputation_strategy(
        self, 
        ioc: str, 
        category: IOCCategory
    ) -> Tuple[float, List[str]]:
        """Strategy 2: Reputation-based classification"""
        score = 0.5
        signals = []
        
        # Known benign TLDs
        benign_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.mil']
        if any(ioc.lower().endswith(tld) for tld in benign_tlds) and category == IOCCategory.DOMAIN:
            score += 0.15
            signals.append("BENIGN_TLD")
            
        # Suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.work', '.biz', '.info']
        if any(ioc.lower().endswith(tld) for tld in suspicious_tlds) and category == IOCCategory.DOMAIN:
            score -= 0.2
            signals.append("SUSPICIOUS_TLD")
            
        # Private IP addresses are always FP
        if category == IOCCategory.IP_ADDRESS:
            # Check if private IP range
            if re.match(r'^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.)', ioc):
                score = 0.95
                signals.append("PRIVATE_IP_ADDRESS")
            
        # File hashes are almost never false positives
        if category == IOCCategory.FILE_HASH:
            score -= 0.3
            signals.append("HASH_LOW_FP_PROBABILITY")
            
        if category == IOCCategory.CVE:
            score = 0.05  # Almost certainly a threat
            signals.append("CVE_ALWAYS_THREAT")
            
        return max(0.0, min(1.0, score)), signals
        
    def classify_ioc(
        self, 
        ioc_value: str, 
        context: Optional[ClassificationContext] = None
    ) -> ClassificationResultV14:
        """
        Classify IOC using ensemble of 5 strategies
        """
        start_time = time.time()
        context = context or ClassificationContext()
        
        # Step 1: Categorize IOC
        category = self._categorize_ioc(ioc_value)
        
        # Step 2: Run all classification strategies
        votes = []
        
        # Strategy 1: Pattern matching (HIGHEST WEIGHT)
        fp_score_1, signals_1 = self._pattern_matching_strategy(ioc_value, category)
        votes.append(self.ensemble.vote(
            ClassificationStrategy.PATTERN_MATCHING,
            fp_score_1, 0.95, signals_1
        ))
        
        # Strategy 2: Reputation-based
        fp_score_2, signals_2 = self._reputation_strategy(ioc_value, category)
        votes.append(self.ensemble.vote(
            ClassificationStrategy.REPUTATION_BASED,
            fp_score_2, 0.9, signals_2
        ))
        
        # Strategy 3: Entropy-based
        fp_score_3, signals_3 = self.entropy.classify_by_entropy(ioc_value, category)
        votes.append(self.ensemble.vote(
            ClassificationStrategy.ENTROPY_BASED,
            fp_score_3, 0.7, signals_3
        ))
        
        # Strategy 4: Semantic similarity (simplified)
        fp_score_4 = (fp_score_1 + fp_score_2) / 2
        signals_4 = ["SEMANTIC_CONSISTENCY_CHECK"]
        votes.append(self.ensemble.vote(
            ClassificationStrategy.SEMANTIC_SIMILARITY,
            fp_score_4, 0.6, signals_4
        ))
        
        # Strategy 5: Statistical analysis
        fp_score_5 = min(1.0, len(ioc_value) / 50.0)  # Length-based heuristic
        signals_5 = [f"LENGTH_{len(ioc_value)}"]
        votes.append(self.ensemble.vote(
            ClassificationStrategy.STATISTICAL_ANALYSIS,
            fp_score_5, 0.5, signals_5
        ))
        
        # Step 3: Ensemble voting
        is_fp, confidence, fp_score, attribution = self.ensemble.combine_votes(votes)
        
        # Step 4: Drift detection
        self.drift_detector.add_sample(is_fp, fp_score)
        drift_detected, drift_metrics = self.drift_detector.detect_drift()
        
        # Step 5: Collect all signals
        all_fp_signals = []
        all_threat_signals = []
        for v in votes:
            if v.vote:
                all_fp_signals.extend(v.contributing_features)
            else:
                all_threat_signals.extend(v.contributing_features)
                
        # Step 6: Generate reason
        strategy_contrib = sorted(attribution.items(), key=lambda x: x[1], reverse=True)
        top_strategy = strategy_contrib[0][0] if strategy_contrib else "ensemble"
        
        if is_fp:
            reason = f"ENSEMBLE: FALSE POSITIVE (conf: {confidence:.3f}) | Top contributor: {top_strategy}"
        else:
            reason = f"ENSEMBLE: TRUE THREAT (conf: {confidence:.3f}) | Top contributor: {top_strategy}"
            
        processing_time = (time.time() - start_time) * 1000
        
        # Update stats
        with self._lock:
            self.classification_stats['total_classified'] += 1
            if is_fp:
                self.classification_stats['false_positives'] += 1
            else:
                self.classification_stats['true_threats'] += 1
            if drift_detected:
                self.classification_stats['drift_events_detected'] += 1
                
        return ClassificationResultV14(
            ioc_value=ioc_value,
            ioc_category=category,
            is_false_positive=is_fp,
            final_confidence=confidence,
            threat_score=1.0 - fp_score,
            fp_score=fp_score,
            ensemble_votes=votes,
            false_positive_signals=all_fp_signals,
            threat_signals=all_threat_signals,
            xai_attribution=attribution,
            classification_reason=reason,
            processing_time_ms=processing_time,
            drift_detected=drift_detected,
            model_version="v14_ensemble"
        )
        
    def _categorize_ioc(self, ioc: str) -> IOCCategory:
        """Simple IOC categorization"""
        if re.match(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', ioc):
            return IOCCategory.IP_ADDRESS
        if re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', ioc):
            return IOCCategory.FILE_HASH
        if re.match(r'^CVE-\d{4}-\d{4,7}$', ioc, re.IGNORECASE):
            return IOCCategory.CVE
        if '@' in ioc:
            return IOCCategory.EMAIL
        if ioc.startswith(('http://', 'https://')):
            return IOCCategory.URL
        if '.' in ioc:
            return IOCCategory.DOMAIN
        return IOCCategory.UNKNOWN
        
    def classify_batch(
        self, 
        ioc_list: List[str], 
        context: Optional[ClassificationContext] = None
    ) -> List[ClassificationResultV14]:
        """Classify batch of IOCs"""
        return [self.classify_ioc(ioc, context) for ioc in ioc_list]
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get classification statistics"""
        with self._lock:
            stats = self.classification_stats.copy()
            
        if stats['total_classified'] > 0:
            stats['fp_rate'] = stats['false_positives'] / stats['total_classified']
        else:
            stats['fp_rate'] = 0.0
            
        drift_detected, drift_metrics = self.drift_detector.detect_drift()
        stats['drift_metrics'] = drift_metrics
        
        return stats


# Global convenience functions
_default_classifier_v14 = None
_classifier_lock_v14 = threading.Lock()


def get_classifier_v14() -> FalsePositiveClassifierV14:
    """Get default v14 classifier instance"""
    global _default_classifier_v14
    with _classifier_lock_v14:
        if _default_classifier_v14 is None:
            _default_classifier_v14 = FalsePositiveClassifierV14()
    return _default_classifier_v14


def classify_ioc_v14(ioc: str, context: Optional[ClassificationContext] = None) -> ClassificationResultV14:
    """Convenience: Classify single IOC with v14 ensemble"""
    return get_classifier_v14().classify_ioc(ioc, context)


def classify_batch_v14(iocs: List[str], context: Optional[ClassificationContext] = None) -> List[ClassificationResultV14]:
    """Convenience: Classify batch with v14"""
    return get_classifier_v14().classify_batch(iocs, context)


def get_statistics_v14() -> Dict[str, Any]:
    """Convenience: Get v14 statistics"""
    return get_classifier_v14().get_statistics()


# API Stability Marker: STABLE
# ADD-ONLY implementation - no existing code modified
# Backward compatible with all v1-v13 classifier interfaces
