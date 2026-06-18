"""
Threat Intelligence Signature Drift Detector with Auto-Rollback
Production-grade implementation for NeuralShield-AI

This module provides:
1. Signature baseline tracking and versioning
2. Drift detection using statistical analysis (KL divergence, cosine similarity)
3. Automated rollback to stable signatures when drift exceeds threshold
4. Audit logging and drift history
5. Confidence scoring for signature validity
"""

import hashlib
import json
import time
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from collections import defaultdict
import math

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class SignatureVersion:
    """Represents a versioned threat signature"""
    signature_id: str
    version: str
    pattern: str
    created_at: float
    confidence_score: float
    is_stable: bool = False
    hash_digest: str = ""

    def __post_init__(self):
        self.hash_digest = hashlib.sha256(
            f"{self.signature_id}:{self.version}:{self.pattern}".encode()
        ).hexdigest()


@dataclass
class DriftMetrics:
    """Metrics for signature drift analysis"""
    signature_id: str
    previous_version: str
    current_version: str
    cosine_similarity: float
    kl_divergence: float
    edit_distance: int
    drift_score: float
    drift_detected: bool
    timestamp: float = field(default_factory=time.time)


class SignatureDriftDetector:
    """
    Detects drift in threat signatures and triggers auto-rollback.
    
    Uses multiple statistical methods to detect meaningful changes:
    - Cosine similarity for vector space comparison
    - KL divergence for probability distribution shift
    - Levenshtein distance for pattern changes
    """

    def __init__(
        self,
        drift_threshold: float = 0.3,
        similarity_threshold: float = 0.7,
        max_versions: int = 10,
        auto_rollback_enabled: bool = True
    ):
        self.drift_threshold = drift_threshold
        self.similarity_threshold = similarity_threshold
        self.max_versions = max_versions
        self.auto_rollback_enabled = auto_rollback_enabled
        
        self.signature_versions: Dict[str, List[SignatureVersion]] = defaultdict(list)
        self.stable_signatures: Dict[str, SignatureVersion] = {}
        self.drift_history: List[DriftMetrics] = []
        self.rollback_events: List[Dict[str, Any]] = []
        self.baseline_signatures: Dict[str, Dict[str, float]] = {}

    def _char_frequency_vector(self, text: str) -> Dict[str, float]:
        """Create character frequency vector for similarity comparison"""
        freq = defaultdict(int)
        for c in text.lower():
            freq[c] += 1
        total = len(text) if text else 1
        return {c: count / total for c, count in freq.items()}

    def _cosine_similarity(self, vec1: Dict[str, float], vec2: Dict[str, float]) -> float:
        """Calculate cosine similarity between two frequency vectors"""
        all_chars = set(vec1.keys()) | set(vec2.keys())
        dot_product = sum(vec1.get(c, 0) * vec2.get(c, 0) for c in all_chars)
        norm1 = math.sqrt(sum(v * v for v in vec1.values()))
        norm2 = math.sqrt(sum(v * v for v in vec2.values()))
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        return dot_product / (norm1 * norm2)

    def _kl_divergence(self, p: Dict[str, float], q: Dict[str, float]) -> float:
        """Calculate Kullback-Leibler divergence with smoothing"""
        epsilon = 1e-10
        divergence = 0.0
        all_chars = set(p.keys()) | set(q.keys())
        
        for c in all_chars:
            p_val = p.get(c, epsilon)
            q_val = q.get(c, epsilon)
            divergence += p_val * math.log((p_val + epsilon) / (q_val + epsilon))
        
        return min(abs(divergence), 10.0)  # Cap for stability

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate edit distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]

    def register_signature(
        self,
        signature_id: str,
        pattern: str,
        version: str,
        confidence_score: float = 0.8
    ) -> SignatureVersion:
        """Register a new signature version"""
        sig_version = SignatureVersion(
            signature_id=signature_id,
            version=version,
            pattern=pattern,
            created_at=time.time(),
            confidence_score=confidence_score
        )
        
        versions = self.signature_versions[signature_id]
        versions.append(sig_version)
        
        # Keep only max_versions
        if len(versions) > self.max_versions:
            versions.pop(0)
        
        # Store baseline for first version
        if len(versions) == 1:
            self.baseline_signatures[signature_id] = self._char_frequency_vector(pattern)
            sig_version.is_stable = True
            self.stable_signatures[signature_id] = sig_version
        
        return sig_version

    def detect_drift(self, signature_id: str, new_pattern: str) -> Optional[DriftMetrics]:
        """
        Detect drift between new pattern and baseline/stable version.
        Returns drift metrics if drift is detected.
        """
        if signature_id not in self.stable_signatures:
            return None
        
        stable = self.stable_signatures[signature_id]
        
        vec_stable = self._char_frequency_vector(stable.pattern)
        vec_new = self._char_frequency_vector(new_pattern)
        
        similarity = self._cosine_similarity(vec_stable, vec_new)
        divergence = self._kl_divergence(vec_stable, vec_new)
        edit_dist = self._levenshtein_distance(stable.pattern, new_pattern)
        
        # Normalize metrics
        norm_edit = edit_dist / max(len(stable.pattern), len(new_pattern), 1)
        drift_score = (
            (1 - similarity) * 0.4 +
            min(divergence / 5.0, 1.0) * 0.3 +
            norm_edit * 0.3
        )
        
        drift_detected = (
            drift_score > self.drift_threshold or
            similarity < self.similarity_threshold
        )
        
        metrics = DriftMetrics(
            signature_id=signature_id,
            previous_version=stable.version,
            current_version="new",
            cosine_similarity=similarity,
            kl_divergence=divergence,
            edit_distance=edit_dist,
            drift_score=drift_score,
            drift_detected=drift_detected
        )
        
        self.drift_history.append(metrics)
        return metrics

    def should_rollback(self, signature_id: str, new_pattern: str) -> Tuple[bool, Optional[DriftMetrics]]:
        """Determine if rollback is needed for a new signature pattern"""
        metrics = self.detect_drift(signature_id, new_pattern)
        if metrics is None:
            return False, None
        
        if self.auto_rollback_enabled and metrics.drift_detected:
            return True, metrics
        return False, metrics

    def rollback_to_stable(self, signature_id: str) -> Optional[SignatureVersion]:
        """Rollback signature to last known stable version"""
        if signature_id not in self.stable_signatures:
            logger.warning(f"No stable version found for {signature_id}")
            return None
        
        stable = self.stable_signatures[signature_id]
        
        rollback_event = {
            "signature_id": signature_id,
            "rolled_back_to_version": stable.version,
            "timestamp": time.time(),
            "reason": "signature_drift_detected"
        }
        self.rollback_events.append(rollback_event)
        
        logger.info(
            f"Rolled back signature {signature_id} to stable version {stable.version}"
        )
        return stable

    def mark_as_stable(self, signature_id: str, version: str) -> bool:
        """Mark a signature version as stable after validation"""
        versions = self.signature_versions.get(signature_id, [])
        for sig in versions:
            if sig.version == version:
                sig.is_stable = True
                self.stable_signatures[signature_id] = sig
                # Update baseline
                self.baseline_signatures[signature_id] = self._char_frequency_vector(sig.pattern)
                logger.info(f"Marked signature {signature_id} version {version} as stable")
                return True
        return False

    def get_drift_summary(self) -> Dict[str, Any]:
        """Get summary of drift detection statistics"""
        total_checks = len(self.drift_history)
        drift_detected_count = sum(1 for m in self.drift_history if m.drift_detected)
        rollback_count = len(self.rollback_events)
        
        avg_similarity = (
            sum(m.cosine_similarity for m in self.drift_history) / total_checks
            if total_checks > 0 else 1.0
        )
        
        return {
            "total_signature_checks": total_checks,
            "drift_detected_count": drift_detected_count,
            "drift_rate": drift_detected_count / total_checks if total_checks > 0 else 0,
            "rollback_count": rollback_count,
            "average_similarity": avg_similarity,
            "active_stable_signatures": len(self.stable_signatures),
            "auto_rollback_enabled": self.auto_rollback_enabled
        }

    def export_state(self) -> str:
        """Export detector state for persistence"""
        state = {
            "stable_signatures": {
                k: {
                    "signature_id": v.signature_id,
                    "version": v.version,
                    "pattern": v.pattern,
                    "confidence_score": v.confidence_score
                }
                for k, v in self.stable_signatures.items()
            },
            "drift_summary": self.get_drift_summary(),
            "exported_at": datetime.utcnow().isoformat()
        }
        return json.dumps(state, indent=2)
