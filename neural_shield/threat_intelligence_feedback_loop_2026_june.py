"""
Threat Intelligence Auto-Feedback Loop - June 2026 Production Release
NeuralShield-AI Adaptive Learning System

Implements continuous learning from detection feedback:
1. Process user/system feedback on detection results
2. Dynamically adjust detection thresholds based on accuracy
3. Learn new threat patterns from false negatives
4. Reduce false positives through confidence calibration
5. Track learning performance and statistics

Production Release: June 18, 2026
"""
import json
import hashlib
import time
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from collections import defaultdict, deque

class FeedbackType(Enum):
    """Types of feedback for detection results"""
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    TRUE_POSITIVE = "true_positive"
    TRUE_NEGATIVE = "true_negative"
    USER_REPORTED_THREAT = "user_reported_threat"
    USER_REPORTED_SAFE = "user_reported_safe"

class LearningStrategy(Enum):
    """Learning aggressiveness strategies"""
    CONSERVATIVE = "conservative"
    MODERATE = "moderate"
    AGGRESSIVE = "aggressive"

@dataclass
class ThreatSignature:
    """Learned threat signature with metadata"""
    signature_hash: str
    pattern: str
    threat_type: str
    confidence: float
    hit_count: int = 0
    false_positive_count: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    is_verified: bool = False

@dataclass
class FeedbackRecord:
    """Record of feedback submission"""
    feedback_id: str
    feedback_type: FeedbackType
    detection_id: str
    content: str
    timestamp: float
    confidence_before: float
    confidence_after: float
    threshold_adjustment: float = 0.0

@dataclass
class ScanResult:
    """Result of scanning with learned signatures"""
    detected: bool
    threat_type: Optional[str] = None
    confidence: float = 0.0
    matched_signature: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

class ThreatIntelligenceFeedbackLoop:
    """
    Adaptive Threat Intelligence Feedback Loop System
    
    Provides continuous learning capabilities:
    - Process feedback on detection results
    - Auto-adjust detection thresholds
    - Learn new threat patterns
    - Calibrate confidence scores
    - Track learning statistics
    """
    
    def __init__(self, 
                 learning_strategy: LearningStrategy = LearningStrategy.MODERATE,
                 max_signatures: int = 10000,
                 feedback_history_size: int = 1000):
        
        self.learning_strategy = learning_strategy
        self.max_signatures = max_signatures
        self.feedback_history_size = feedback_history_size
        
        # Learning rates based on strategy
        self.learning_rates = {
            LearningStrategy.CONSERVATIVE: 0.05,
            LearningStrategy.MODERATE: 0.15,
            LearningStrategy.AGGRESSIVE: 0.30
        }
        
        # Detection thresholds
        self.base_detection_threshold = 0.7
        self.current_threshold = 0.7
        
        # Learned signatures database
        self.signatures: Dict[str, ThreatSignature] = {}
        
        # Feedback history
        self.feedback_history: deque = deque(maxlen=feedback_history_size)
        
        # Performance tracking
        self.stats = {
            'total_feedback': 0,
            'false_positives': 0,
            'false_negatives': 0,
            'true_positives': 0,
            'true_negatives': 0,
            'patterns_learned': 0,
            'threshold_adjustments': 0
        }
        
        # Accuracy tracking window
        self.recent_accuracy: deque = deque(maxlen=100)
        
        # Feature extraction settings
        self.ngram_sizes = [2, 3, 4]
        
    def _extract_features(self, content: str) -> Set[str]:
        """Extract n-gram features from content"""
        features = set()
        content_lower = content.lower()
        
        for n in self.ngram_sizes:
            for i in range(len(content_lower) - n + 1):
                ngram = content_lower[i:i+n]
                if ngram.isalnum() or any(c.isalpha() for c in ngram):
                    features.add(ngram)
        
        return features
    
    def _compute_signature_hash(self, pattern: str) -> str:
        """Compute hash for signature deduplication"""
        return hashlib.sha256(pattern.lower().encode()).hexdigest()[:16]
    
    def submit_feedback(self, 
                       feedback_type: FeedbackType,
                       detection_id: str,
                       content: str,
                       original_confidence: float = 0.5,
                       threat_type: str = "unknown") -> FeedbackRecord:
        """
        Submit feedback for a detection result
        
        Args:
            feedback_type: Type of feedback
            detection_id: Unique detection identifier
            content: The content that was detected
            original_confidence: Confidence of original detection
            threat_type: Type of threat detected
            
        Returns:
            FeedbackRecord with learning results
        """
        feedback_id = hashlib.md5(f"{detection_id}{time.time()}".encode()).hexdigest()[:12]
        timestamp = time.time()
        
        confidence_after = original_confidence
        threshold_adjustment = 0.0
        
        learning_rate = self.learning_rates[self.learning_strategy]
        
        # Process feedback type
        if feedback_type == FeedbackType.FALSE_POSITIVE:
            # False positive: decrease confidence, raise threshold
            confidence_after = max(0.0, original_confidence - learning_rate * 0.5)
            threshold_adjustment = learning_rate * 0.1
            self.current_threshold = min(0.95, self.current_threshold + threshold_adjustment)
            self.stats['false_positives'] += 1
            self.recent_accuracy.append(False)
            
        elif feedback_type == FeedbackType.FALSE_NEGATIVE:
            # False negative: learn new pattern, lower threshold
            confidence_after = min(1.0, original_confidence + learning_rate)
            threshold_adjustment = -learning_rate * 0.1
            self.current_threshold = max(0.3, self.current_threshold + threshold_adjustment)
            self.stats['false_negatives'] += 1
            self.recent_accuracy.append(False)
            
            # Extract and store new threat patterns
            features = self._extract_features(content)
            for pattern in list(features)[:10]:  # Limit features per feedback
                sig_hash = self._compute_signature_hash(pattern)
                if sig_hash not in self.signatures and len(self.signatures) < self.max_signatures:
                    self.signatures[sig_hash] = ThreatSignature(
                        signature_hash=sig_hash,
                        pattern=pattern,
                        threat_type=threat_type,
                        confidence=0.6
                    )
                    self.stats['patterns_learned'] += 1
                    
        elif feedback_type == FeedbackType.TRUE_POSITIVE:
            # True positive: boost confidence, reinforce pattern
            confidence_after = min(1.0, original_confidence + learning_rate * 0.2)
            self.stats['true_positives'] += 1
            self.recent_accuracy.append(True)
            
            # Boost existing signatures
            features = self._extract_features(content)
            for pattern in features:
                sig_hash = self._compute_signature_hash(pattern)
                if sig_hash in self.signatures:
                    sig = self.signatures[sig_hash]
                    sig.confidence = min(1.0, sig.confidence + learning_rate * 0.1)
                    sig.hit_count += 1
                    
        elif feedback_type == FeedbackType.TRUE_NEGATIVE:
            # True negative: good detection, no change needed
            self.stats['true_negatives'] += 1
            self.recent_accuracy.append(True)
            
        elif feedback_type == FeedbackType.USER_REPORTED_THREAT:
            # User-reported threat: high priority learning
            confidence_after = 0.95
            self.stats['false_negatives'] += 1
            self.recent_accuracy.append(False)
            
            # Learn all features as high-confidence signatures
            features = self._extract_features(content)
            for pattern in list(features)[:20]:
                sig_hash = self._compute_signature_hash(pattern)
                if sig_hash not in self.signatures and len(self.signatures) < self.max_signatures:
                    self.signatures[sig_hash] = ThreatSignature(
                        signature_hash=sig_hash,
                        pattern=pattern,
                        threat_type=threat_type,
                        confidence=0.85,
                        is_verified=True
                    )
                    self.stats['patterns_learned'] += 1
                    
        elif feedback_type == FeedbackType.USER_REPORTED_SAFE:
            # User-reported safe: lower confidence for matching patterns
            confidence_after = 0.05
            self.stats['false_positives'] += 1
            self.recent_accuracy.append(False)
            
            # Penalize matching signatures
            features = self._extract_features(content)
            for pattern in features:
                sig_hash = self._compute_signature_hash(pattern)
                if sig_hash in self.signatures:
                    sig = self.signatures[sig_hash]
                    sig.confidence = max(0.1, sig.confidence - learning_rate * 0.3)
                    sig.false_positive_count += 1
        
        self.stats['total_feedback'] += 1
        if abs(threshold_adjustment) > 0:
            self.stats['threshold_adjustments'] += 1
        
        record = FeedbackRecord(
            feedback_id=feedback_id,
            feedback_type=feedback_type,
            detection_id=detection_id,
            content=content[:100],
            timestamp=timestamp,
            confidence_before=original_confidence,
            confidence_after=confidence_after,
            threshold_adjustment=threshold_adjustment
        )
        
        self.feedback_history.append(record)
        return record
    
    def scan_with_learned_signatures(self, content: str) -> ScanResult:
        """
        Scan content using learned threat signatures
        
        Args:
            content: Content to scan
            
        Returns:
            ScanResult with detection information
        """
        features = self._extract_features(content)
        max_confidence = 0.0
        matched_sig = None
        matched_type = None
        
        for pattern in features:
            sig_hash = self._compute_signature_hash(pattern)
            if sig_hash in self.signatures:
                sig = self.signatures[sig_hash]
                if sig.confidence > max_confidence:
                    max_confidence = sig.confidence
                    matched_sig = sig_hash
                    matched_type = sig.threat_type
                    sig.hit_count += 1
                    sig.last_seen = datetime.now()
        
        detected = max_confidence >= self.current_threshold
        
        return ScanResult(
            detected=detected,
            threat_type=matched_type if detected else None,
            confidence=max_confidence,
            matched_signature=matched_sig,
            details={
                'threshold_used': self.current_threshold,
                'features_scanned': len(features),
                'matching_signatures': sum(1 for f in features if self._compute_signature_hash(f) in self.signatures)
            }
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get learning system statistics"""
        total_accuracy = self.recent_accuracy.count(True) / len(self.recent_accuracy) if self.recent_accuracy else 0.0
        
        return {
            'learning_strategy': self.learning_strategy.value,
            'current_detection_threshold': round(self.current_threshold, 3),
            'total_feedback_submitted': self.stats['total_feedback'],
            'false_positives': self.stats['false_positives'],
            'false_negatives': self.stats['false_negatives'],
            'true_positives': self.stats['true_positives'],
            'true_negatives': self.stats['true_negatives'],
            'learned_signatures_count': len(self.signatures),
            'total_patterns_learned': self.stats['patterns_learned'],
            'threshold_adjustments_made': self.stats['threshold_adjustments'],
            'recent_accuracy_rate': round(total_accuracy, 3),
            'feedback_history_size': len(self.feedback_history),
            'signature_capacity_used': f"{len(self.signatures)}/{self.max_signatures}"
        }
    
    def export_signatures(self) -> List[Dict[str, Any]]:
        """Export all learned signatures for persistence"""
        return [
            {
                'hash': sig.signature_hash,
                'pattern': sig.pattern,
                'threat_type': sig.threat_type,
                'confidence': sig.confidence,
                'hit_count': sig.hit_count,
                'false_positives': sig.false_positive_count,
                'is_verified': sig.is_verified
            }
            for sig in self.signatures.values()
        ]
    
    def import_signatures(self, signatures_data: List[Dict[str, Any]]) -> int:
        """Import signatures from exported data"""
        imported = 0
        for data in signatures_data:
            if len(self.signatures) >= self.max_signatures:
                break
            sig_hash = data['hash']
            if sig_hash not in self.signatures:
                self.signatures[sig_hash] = ThreatSignature(
                    signature_hash=sig_hash,
                    pattern=data['pattern'],
                    threat_type=data['threat_type'],
                    confidence=data['confidence'],
                    hit_count=data.get('hit_count', 0),
                    false_positive_count=data.get('false_positives', 0),
                    is_verified=data.get('is_verified', False)
                )
                imported += 1
        return imported
    
    def verify_signature(self, signature_hash: str, is_valid: bool) -> bool:
        """Manually verify or invalidate a signature"""
        if signature_hash in self.signatures:
            sig = self.signatures[signature_hash]
            sig.is_verified = is_valid
            if is_valid:
                sig.confidence = min(1.0, sig.confidence + 0.2)
            else:
                sig.confidence = max(0.1, sig.confidence - 0.3)
            return True
        return False
    
    def run_learning_cycle(self) -> Dict[str, Any]:
        """Run automated learning cycle with cleanup"""
        # Remove low-confidence signatures
        removed = 0
        sigs_to_remove = []
        for sig_hash, sig in self.signatures.items():
            if sig.confidence < 0.2 and sig.false_positive_count > 5:
                sigs_to_remove.append(sig_hash)
        
        for sig_hash in sigs_to_remove:
            del self.signatures[sig_hash]
            removed += 1
        
        # Decay old signatures slightly
        for sig in self.signatures.values():
            sig.confidence = max(0.1, sig.confidence * 0.999)
        
        return {
            'low_confidence_signatures_removed': removed,
            'remaining_signatures': len(self.signatures),
            'current_threshold': round(self.current_threshold, 3)
        }
