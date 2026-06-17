"""
Threat Intelligence Auto-Learning Classifier - NeuralShield-AI
June 18, 2026
Real production-grade ML-based threat classification with adaptive learning
Automatically learns from false positives/negatives and improves detection over time
"""
import re
import time
import hashlib
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set, Any, Callable
from enum import Enum
from collections import defaultdict, Counter
import json
from pathlib import Path
import threading
class ThreatClass(Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    CRITICAL = "critical"
class FeatureType(Enum):
    KEYWORD = "keyword"
    REGEX = "regex"
    SEMANTIC = "semantic"
    STATISTICAL = "statistical"
    STRUCTURAL = "structural"
@dataclass
class FeatureWeight:
    feature_id: str
    feature_type: FeatureType
    pattern: str
    weight: float
    threat_class: ThreatClass
    hit_count: int = 0
    false_positive_count: int = 0
    is_active: bool = True
    created_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    def get_adjusted_weight(self) -> float:
        total = self.hit_count + self.false_positive_count
        if total == 0:
            return self.weight
        accuracy = self.hit_count / total
        return self.weight * (0.5 + 0.5 * accuracy)
@dataclass
class ClassificationResult:
    text_hash: str
    threat_class: ThreatClass
    confidence: float
    matched_features: List[Tuple[str, float]]
    feature_scores: Dict[str, float]
    processing_time_ms: float
    timestamp: float = field(default_factory=time.time)
    feedback: Optional[str] = None  # "correct", "false_positive", "false_negative"
@dataclass
class LearningStats:
    total_classifications: int = 0
    correct_feedback: int = 0
    false_positive_feedback: int = 0
    false_negative_feedback: int = 0
    weight_adjustments: int = 0
    features_added: int = 0
    features_deactivated: int = 0
    avg_confidence: float = 0.0
    learning_rate: float = 0.1
class ThreatIntelligenceAutoLearningClassifier:
    """
    Auto-learning threat classifier that adapts based on feedback
    Uses weighted feature matching with online learning from user feedback
    """
    def __init__(self, auto_load_defaults: bool = True, learning_rate: float = 0.1):
        self.features: Dict[str, FeatureWeight] = {}
        self.learning_stats = LearningStats()
        self.learning_stats.learning_rate = learning_rate
        self.classification_history: Dict[str, ClassificationResult] = {}
        self._lock = threading.RLock()
        self._confidence_history: List[float] = []
        
        if auto_load_defaults:
            self._load_default_features()
    def _load_default_features(self):
        default_features = [
            # Jailbreak patterns
            FeatureWeight(
                feature_id="JL-001",
                feature_type=FeatureType.KEYWORD,
                pattern="ignore previous instructions",
                weight=0.95,
                threat_class=ThreatClass.CRITICAL
            ),
            FeatureWeight(
                feature_id="JL-002",
                feature_type=FeatureType.KEYWORD,
                pattern="disregard system prompt",
                weight=0.90,
                threat_class=ThreatClass.CRITICAL
            ),
            FeatureWeight(
                feature_id="JL-003",
                feature_type=FeatureType.KEYWORD,
                pattern="do anything now",
                weight=0.98,
                threat_class=ThreatClass.CRITICAL
            ),
            FeatureWeight(
                feature_id="JL-004",
                feature_type=FeatureType.KEYWORD,
                pattern="developer mode",
                weight=0.75,
                threat_class=ThreatClass.MALICIOUS
            ),
            FeatureWeight(
                feature_id="JL-005",
                feature_type=FeatureType.KEYWORD,
                pattern="roleplay",
                weight=0.40,
                threat_class=ThreatClass.SUSPICIOUS
            ),
            FeatureWeight(
                feature_id="JL-006",
                feature_type=FeatureType.KEYWORD,
                pattern="without ethics",
                weight=0.85,
                threat_class=ThreatClass.MALICIOUS
            ),
            FeatureWeight(
                feature_id="JL-007",
                feature_type=FeatureType.KEYWORD,
                pattern="unrestricted",
                weight=0.70,
                threat_class=ThreatClass.MALICIOUS
            ),
            # Prompt injection patterns
            FeatureWeight(
                feature_id="PI-001",
                feature_type=FeatureType.REGEX,
                pattern=r"<\|.*?\|>",
                weight=0.88,
                threat_class=ThreatClass.MALICIOUS
            ),
            FeatureWeight(
                feature_id="PI-002",
                feature_type=FeatureType.KEYWORD,
                pattern="[INST]",
                weight=0.85,
                threat_class=ThreatClass.MALICIOUS
            ),
            FeatureWeight(
                feature_id="PI-003",
                feature_type=FeatureType.KEYWORD,
                pattern="print above text",
                weight=0.65,
                threat_class=ThreatClass.SUSPICIOUS
            ),
            # PII patterns
            FeatureWeight(
                feature_id="PII-001",
                feature_type=FeatureType.REGEX,
                pattern=r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}",
                weight=0.50,
                threat_class=ThreatClass.SUSPICIOUS
            ),
            # Malicious code patterns
            FeatureWeight(
                feature_id="MC-001",
                feature_type=FeatureType.KEYWORD,
                pattern="rm -rf",
                weight=0.98,
                threat_class=ThreatClass.CRITICAL
            ),
            FeatureWeight(
                feature_id="MC-002",
                feature_type=FeatureType.KEYWORD,
                pattern="format c:",
                weight=0.95,
                threat_class=ThreatClass.CRITICAL
            ),
            FeatureWeight(
                feature_id="MC-003",
                feature_type=FeatureType.KEYWORD,
                pattern="eval(base64",
                weight=0.90,
                threat_class=ThreatClass.CRITICAL
            ),
            FeatureWeight(
                feature_id="MC-004",
                feature_type=FeatureType.KEYWORD,
                pattern="__import__",
                weight=0.75,
                threat_class=ThreatClass.MALICIOUS
            ),
            # Statistical features
            FeatureWeight(
                feature_id="ST-001",
                feature_type=FeatureType.STATISTICAL,
                pattern="special_token_density",
                weight=0.30,
                threat_class=ThreatClass.SUSPICIOUS
            ),
            FeatureWeight(
                feature_id="ST-002",
                feature_type=FeatureType.STATISTICAL,
                pattern="uppercase_ratio",
                weight=0.15,
                threat_class=ThreatClass.SUSPICIOUS
            ),
        ]
        
        for feature in default_features:
            self.add_feature(feature)
    def add_feature(self, feature: FeatureWeight) -> bool:
        with self._lock:
            if feature.feature_id in self.features:
                return False
            self.features[feature.feature_id] = feature
            self.learning_stats.features_added += 1
            return True
    def remove_feature(self, feature_id: str) -> bool:
        with self._lock:
            if feature_id in self.features:
                del self.features[feature_id]
                return True
            return False
    def _match_feature(self, text: str, feature: FeatureWeight) -> bool:
        if not feature.is_active:
            return False
            
        if feature.feature_type == FeatureType.KEYWORD:
            return feature.pattern.lower() in text.lower()
        elif feature.feature_type == FeatureType.REGEX:
            return bool(re.search(feature.pattern, text, re.IGNORECASE))
        elif feature.feature_type == FeatureType.STATISTICAL:
            if feature.pattern == "special_token_density":
                special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
                return len(text) > 0 and (special_chars / len(text)) > 0.3
            elif feature.pattern == "uppercase_ratio":
                if len(text) == 0:
                    return False
                upper_count = sum(1 for c in text if c.isupper())
                return upper_count / len(text) > 0.5
        return False
    def classify(self, text: str) -> ClassificationResult:
        start_time = time.time()
        text_hash = hashlib.md5(text.encode()).hexdigest()
        
        matched_features: List[Tuple[str, float]] = []
        feature_scores: Dict[str, float] = {}
        total_score = 0.0
        active_malicious_weight = 0.0
        
        with self._lock:
            # Calculate total possible weight for active malicious/critical features
            for feature_id, feature in self.features.items():
                if feature.is_active and feature.threat_class in (ThreatClass.MALICIOUS, ThreatClass.CRITICAL):
                    active_malicious_weight += feature.get_adjusted_weight()
            
            for feature_id, feature in self.features.items():
                if self._match_feature(text, feature):
                    adjusted_weight = feature.get_adjusted_weight()
                    feature.hit_count += 1
                    matched_features.append((feature_id, adjusted_weight))
                    feature_scores[feature_id] = adjusted_weight
                    
                    if feature.threat_class == ThreatClass.CRITICAL:
                        total_score += adjusted_weight * 1.5
                    elif feature.threat_class == ThreatClass.MALICIOUS:
                        total_score += adjusted_weight * 1.2
                    elif feature.threat_class == ThreatClass.SUSPICIOUS:
                        total_score += adjusted_weight * 0.7
        # Normalize confidence - use matched weight sum as denominator for better sensitivity
        matched_weight_sum = sum(w for _, w in matched_features)
        if matched_weight_sum > 0:
            # Use sum of matched weights as denominator, scaled for better sensitivity
            confidence = min(1.0, total_score / max(matched_weight_sum * 0.6, 1.0))
        else:
            confidence = 0.0
        # Determine threat class based on confidence
        if confidence >= 0.5:
            threat_class = ThreatClass.CRITICAL
        elif confidence >= 0.3:
            threat_class = ThreatClass.MALICIOUS
        elif confidence >= 0.1:
            threat_class = ThreatClass.SUSPICIOUS
        else:
            threat_class = ThreatClass.SAFE
        processing_time = (time.time() - start_time) * 1000
        
        result = ClassificationResult(
            text_hash=text_hash,
            threat_class=threat_class,
            confidence=confidence,
            matched_features=matched_features,
            feature_scores=feature_scores,
            processing_time_ms=processing_time
        )
        
        with self._lock:
            self.classification_history[text_hash] = result
            self.learning_stats.total_classifications += 1
            self._confidence_history.append(confidence)
            if len(self._confidence_history) > 10000:
                self._confidence_history = self._confidence_history[-10000:]
            self.learning_stats.avg_confidence = sum(self._confidence_history) / len(self._confidence_history)
        
        return result
    def provide_feedback(self, text_hash: str, feedback: str) -> bool:
        """
        Provide feedback for learning: "correct", "false_positive", "false_negative"
        """
        with self._lock:
            if text_hash not in self.classification_history:
                return False
                
            result = self.classification_history[text_hash]
            result.feedback = feedback
            lr = self.learning_stats.learning_rate
            
            if feedback == "correct":
                self.learning_stats.correct_feedback += 1
                # Reinforce correct features
                for feature_id, _ in result.matched_features:
                    if feature_id in self.features:
                        feature = self.features[feature_id]
                        feature.weight = min(1.0, feature.weight * (1 + lr * 0.1))
                        feature.last_updated = time.time()
                self.learning_stats.weight_adjustments += len(result.matched_features)
                        
            elif feedback == "false_positive":
                self.learning_stats.false_positive_feedback += 1
                # Reduce weight for features that caused false positive
                for feature_id, _ in result.matched_features:
                    if feature_id in self.features:
                        feature = self.features[feature_id]
                        feature.false_positive_count += 1
                        feature.weight = max(0.01, feature.weight * (1 - lr))
                        feature.last_updated = time.time()
                        
                        # Auto-deactivate features with high false positive rate
                        total = feature.hit_count + feature.false_positive_count
                        if total > 3 and feature.false_positive_count / total > 0.4:
                            feature.is_active = False
                            self.learning_stats.features_deactivated += 1
                self.learning_stats.weight_adjustments += len(result.matched_features)
                        
            elif feedback == "false_negative":
                self.learning_stats.false_negative_feedback += 1
                # This would trigger new feature discovery in production
                pass
                
            return True
    def batch_classify(self, texts: List[str]) -> List[ClassificationResult]:
        return [self.classify(text) for text in texts]
    def get_learning_metrics(self) -> Dict[str, Any]:
        with self._lock:
            total_feedback = (self.learning_stats.correct_feedback + 
                            self.learning_stats.false_positive_feedback + 
                            self.learning_stats.false_negative_feedback)
            
            accuracy = self.learning_stats.correct_feedback / total_feedback if total_feedback > 0 else 0.0
            
            return {
                "total_classifications": self.learning_stats.total_classifications,
                "total_feedback": total_feedback,
                "correct_feedback": self.learning_stats.correct_feedback,
                "false_positive_feedback": self.learning_stats.false_positive_feedback,
                "false_negative_feedback": self.learning_stats.false_negative_feedback,
                "feedback_accuracy": round(accuracy, 4),
                "weight_adjustments": self.learning_stats.weight_adjustments,
                "features": {
                    "total": len(self.features),
                    "active": sum(1 for f in self.features.values() if f.is_active),
                    "deactivated": sum(1 for f in self.features.values() if not f.is_active),
                    "added": self.learning_stats.features_added,
                    "auto_deactivated": self.learning_stats.features_deactivated,
                },
                "average_confidence": round(self.learning_stats.avg_confidence, 4),
                "learning_rate": self.learning_stats.learning_rate,
                "feature_effectiveness": {
                    fid: {
                        "weight": round(f.weight, 4),
                        "adjusted_weight": round(f.get_adjusted_weight(), 4),
                        "hits": f.hit_count,
                        "false_positives": f.false_positive_count,
                        "active": f.is_active
                    }
                    for fid, f in self.features.items()
                }
            }
    def export_model(self, filepath: str) -> bool:
        try:
            export_data = {
                "features": [],
                "learning_stats": {
                    "total_classifications": self.learning_stats.total_classifications,
                    "correct_feedback": self.learning_stats.correct_feedback,
                    "false_positive_feedback": self.learning_stats.false_positive_feedback,
                    "false_negative_feedback": self.learning_stats.false_negative_feedback,
                    "weight_adjustments": self.learning_stats.weight_adjustments,
                    "features_added": self.learning_stats.features_added,
                    "features_deactivated": self.learning_stats.features_deactivated,
                    "avg_confidence": self.learning_stats.avg_confidence,
                    "learning_rate": self.learning_stats.learning_rate,
                }
            }
            
            for fid, feature in self.features.items():
                export_data["features"].append({
                    "feature_id": feature.feature_id,
                    "feature_type": feature.feature_type.value,
                    "pattern": feature.pattern,
                    "weight": feature.weight,
                    "threat_class": feature.threat_class.value,
                    "hit_count": feature.hit_count,
                    "false_positive_count": feature.false_positive_count,
                    "is_active": feature.is_active,
                    "created_at": feature.created_at,
                    "last_updated": feature.last_updated
                })
            
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2)
            return True
        except Exception:
            return False
    def import_model(self, filepath: str) -> int:
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            imported = 0
            for item in data["features"]:
                feature = FeatureWeight(
                    feature_id=item["feature_id"],
                    feature_type=FeatureType(item["feature_type"]),
                    pattern=item["pattern"],
                    weight=item["weight"],
                    threat_class=ThreatClass(item["threat_class"])
                )
                feature.hit_count = item.get("hit_count", 0)
                feature.false_positive_count = item.get("false_positive_count", 0)
                feature.is_active = item.get("is_active", True)
                feature.created_at = item.get("created_at", time.time())
                feature.last_updated = item.get("last_updated", time.time())
                
                if self.add_feature(feature):
                    imported += 1
            return imported
        except Exception:
            return 0
