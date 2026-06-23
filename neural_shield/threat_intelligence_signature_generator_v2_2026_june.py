"""
Threat Intelligence Automated Signature Generator v2
NeuralShield AI - Dimension A Feature Expansion v18

ADD-ONLY INCREMENTAL FEATURE - NO EXISTING CODE MODIFIED
Backward compatible - fully opt-in, no breaking changes

Capabilities:
- Automated attack pattern extraction from threat feeds
- Real-time signature generation with confidence scoring
- Effectiveness feedback loop and continuous learning
- Signature database management with versioning
- Pattern deduplication and similarity clustering
- Signature deployment orchestration
"""

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict


class SignatureType(Enum):
    """Types of threat signatures"""
    REGEX_PATTERN = "regex_pattern"
    SEMANTIC_VECTOR = "semantic_vector"
    KEYWORD_SET = "keyword_set"
    BEHAVIORAL_SEQUENCE = "behavioral_sequence"
    EMBEDDING_SIGNATURE = "embedding_signature"


class SignatureStatus(Enum):
    """Lifecycle status of signatures"""
    DRAFT = "draft"
    CANDIDATE = "candidate"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    RETIRED = "retired"


@dataclass
class ThreatSignature:
    """Represents a generated threat signature"""
    signature_id: str
    signature_type: SignatureType
    pattern: str
    confidence: float
    threat_category: str
    severity: str
    created_at: float
    status: SignatureStatus
    version: str = "1.0.0"
    effectiveness_score: float = 0.0
    true_positives: int = 0
    false_positives: int = 0
    match_count: int = 0
    tags: Set[str] = field(default_factory=set)
    source_threats: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signature_id": self.signature_id,
            "signature_type": self.signature_type.value,
            "pattern": self.pattern,
            "confidence": self.confidence,
            "threat_category": self.threat_category,
            "severity": self.severity,
            "created_at": self.created_at,
            "status": self.status.value,
            "version": self.version,
            "effectiveness_score": self.effectiveness_score,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "match_count": self.match_count,
            "tags": list(self.tags),
            "source_threats": list(self.source_threats)
        }


@dataclass
class ExtractedPattern:
    """Pattern extracted from threat sample"""
    pattern_text: str
    pattern_type: SignatureType
    confidence: float
    frequency: int
    uniqueness_score: float


class AutomatedSignatureGenerator:
    """
    Automated Signature Generator v2
    Extracts patterns from threat samples and generates detection signatures
    with continuous effectiveness feedback.
    """

    def __init__(self, min_confidence: float = 0.7):
        self.min_confidence = min_confidence
        self.signatures: Dict[str, ThreatSignature] = {}
        self.pattern_frequency: Dict[str, int] = defaultdict(int)
        self.feedback_queue: List[Tuple[str, bool, str]] = []
        self.generation_stats = {
            "total_signatures_generated": 0,
            "total_patterns_extracted": 0,
            "feedback_processed": 0,
            "deduplicated_patterns": 0
        }
        self._init_common_patterns()

    def _init_common_patterns(self) -> None:
        """Initialize common threat pattern templates"""
        self.attack_keywords = {
            "prompt_injection": [
                "ignore previous", "disregard", "forget instructions",
                "system prompt", "you are now", "act as", "roleplay"
            ],
            "jailbreak": [
                "DAN", "do anything now", "developer mode",
                "bypass", "override", "no ethics", "no restrictions"
            ],
            "data_exfiltration": [
                "leak", "exfiltrate", "dump", "output all",
                "reveal", "disclose", "show hidden"
            ],
            "code_execution": [
                "execute", "run command", "shell", "eval",
                "python", "bash", "subprocess"
            ]
        }

    def extract_patterns(self, threat_sample: str, threat_category: str) -> List[ExtractedPattern]:
        """
        Extract meaningful patterns from a threat sample
        
        Args:
            threat_sample: The malicious input sample
            threat_category: Category of threat
            
        Returns:
            List of extracted patterns with confidence scores
        """
        patterns: List[ExtractedPattern] = []
        sample_lower = threat_sample.lower()
        
        # Extract keyword-based patterns
        for category, keywords in self.attack_keywords.items():
            found_keywords = [kw for kw in keywords if kw in sample_lower]
            if found_keywords:
                confidence = min(0.95, 0.5 + (len(found_keywords) * 0.1))
                pattern = ExtractedPattern(
                    pattern_text="|".join(found_keywords),
                    pattern_type=SignatureType.KEYWORD_SET,
                    confidence=confidence,
                    frequency=len(found_keywords),
                    uniqueness_score=self._calculate_uniqueness(found_keywords)
                )
                patterns.append(pattern)
        
        # Extract regex patterns for common attack structures
        regex_patterns = self._extract_regex_patterns(threat_sample)
        patterns.extend(regex_patterns)
        
        # Extract behavioral sequences
        behavioral_patterns = self._extract_behavioral_patterns(threat_sample)
        patterns.extend(behavioral_patterns)
        
        self.generation_stats["total_patterns_extracted"] += len(patterns)
        
        # Deduplicate
        unique_patterns = self._deduplicate_patterns(patterns)
        self.generation_stats["deduplicated_patterns"] += (len(patterns) - len(unique_patterns))
        
        return unique_patterns

    def _extract_regex_patterns(self, text: str) -> List[ExtractedPattern]:
        """Extract regex-compatible patterns from text"""
        patterns = []
        
        # Pattern for ignore instruction sequences
        ignore_pattern = r'(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|above|prior|earlier)\s+(?:instructions|directives|commands|context)'
        if re.search(ignore_pattern, text, re.IGNORECASE):
            patterns.append(ExtractedPattern(
                pattern_text=ignore_pattern,
                pattern_type=SignatureType.REGEX_PATTERN,
                confidence=0.92,
                frequency=1,
                uniqueness_score=0.85
            ))
        
        # Pattern for role hijacking
        role_pattern = r'(?:you\s+are|act\s+as|pretend\s+to\s+be|imagine\s+you\s+are)\s+(?:a|an|the)\s+(?:developer|admin|god|unrestricted)'
        if re.search(role_pattern, text, re.IGNORECASE):
            patterns.append(ExtractedPattern(
                pattern_text=role_pattern,
                pattern_type=SignatureType.REGEX_PATTERN,
                confidence=0.88,
                frequency=1,
                uniqueness_score=0.80
            ))
        
        return patterns

    def _extract_behavioral_patterns(self, text: str) -> List[ExtractedPattern]:
        """Extract behavioral sequence patterns"""
        patterns = []
        sequences = []
        
        # Detect instruction override followed by malicious request
        lines = text.split('\n')
        if len(lines) >= 2:
            first_line = lines[0].lower()
            if any(kw in first_line for kw in ['ignore', 'disregard', 'forget']):
                sequences.append("INSTRUCTION_OVERRIDE_FOLLOWED_BY_REQUEST")
        
        for seq in sequences:
            patterns.append(ExtractedPattern(
                pattern_text=seq,
                pattern_type=SignatureType.BEHAVIORAL_SEQUENCE,
                confidence=0.85,
                frequency=1,
                uniqueness_score=0.75
            ))
        
        return patterns

    def _calculate_uniqueness(self, keywords: List[str]) -> float:
        """Calculate how unique a pattern set is"""
        if not keywords:
            return 0.0
        total_chars = sum(len(kw) for kw in keywords)
        return min(1.0, total_chars / 50.0)

    def _deduplicate_patterns(self, patterns: List[ExtractedPattern]) -> List[ExtractedPattern]:
        """Remove duplicate or highly similar patterns"""
        seen = set()
        unique = []
        for p in patterns:
            key = (p.pattern_text, p.pattern_type)
            if key not in seen:
                seen.add(key)
                unique.append(p)
        return unique

    def generate_signature(
        self,
        pattern: ExtractedPattern,
        threat_category: str,
        severity: str = "medium"
    ) -> Optional[ThreatSignature]:
        """
        Generate a formal threat signature from an extracted pattern
        
        Args:
            pattern: Extracted pattern
            threat_category: Threat category
            severity: Threat severity
            
        Returns:
            ThreatSignature if confidence meets threshold
        """
        if pattern.confidence < self.min_confidence:
            return None
        
        signature_id = self._generate_signature_id(pattern)
        
        signature = ThreatSignature(
            signature_id=signature_id,
            signature_type=pattern.pattern_type,
            pattern=pattern.pattern_text,
            confidence=pattern.confidence,
            threat_category=threat_category,
            severity=severity,
            created_at=time.time(),
            status=SignatureStatus.CANDIDATE,
            version="2.0.0",
            tags={threat_category, f"confidence:{pattern.confidence:.2f}"},
            source_threats=set()
        )
        
        self.signatures[signature_id] = signature
        self.generation_stats["total_signatures_generated"] += 1
        
        return signature

    def generate_signatures_from_threat_sample(
        self,
        threat_sample: str,
        threat_category: str,
        severity: str = "medium"
    ) -> List[ThreatSignature]:
        """
        End-to-end: Extract patterns and generate signatures
        
        Args:
            threat_sample: Malicious input sample
            threat_category: Threat category
            severity: Threat severity
            
        Returns:
            List of generated signatures
        """
        patterns = self.extract_patterns(threat_sample, threat_category)
        signatures = []
        
        for pattern in patterns:
            signature = self.generate_signature(pattern, threat_category, severity)
            if signature:
                signature.source_threats.add(self._hash_sample(threat_sample))
                signatures.append(signature)
        
        return signatures

    def match_threat(self, input_text: str, signature_id: str) -> Tuple[bool, float]:
        """
        Match input against a specific signature
        
        Args:
            input_text: Text to check
            signature_id: Signature to use
            
        Returns:
            (is_match, confidence_score)
        """
        if signature_id not in self.signatures:
            return False, 0.0
        
        sig = self.signatures[signature_id]
        sig.match_count += 1
        
        if sig.signature_type == SignatureType.REGEX_PATTERN:
            try:
                match = bool(re.search(sig.pattern, input_text, re.IGNORECASE))
                return match, sig.confidence if match else 0.0
            except re.error:
                return False, 0.0
        
        elif sig.signature_type == SignatureType.KEYWORD_SET:
            keywords = sig.pattern.split("|")
            matches = sum(1 for kw in keywords if kw.lower() in input_text.lower())
            if matches > 0:
                ratio = matches / len(keywords)
                return True, sig.confidence * ratio
        
        elif sig.signature_type == SignatureType.BEHAVIORAL_SEQUENCE:
            if sig.pattern == "INSTRUCTION_OVERRIDE_FOLLOWED_BY_REQUEST":
                lines = input_text.split('\n')
                if len(lines) >= 2:
                    first = lines[0].lower()
                    if any(kw in first for kw in ['ignore', 'disregard', 'forget']):
                        return True, sig.confidence
        
        return False, 0.0

    def record_feedback(self, signature_id: str, was_true_positive: bool, context: str = "") -> None:
        """
        Record feedback on signature effectiveness
        
        Args:
            signature_id: Signature ID
            was_true_positive: Whether detection was correct
            context: Optional context
        """
        self.feedback_queue.append((signature_id, was_true_positive, context))
        
        if signature_id in self.signatures:
            sig = self.signatures[signature_id]
            if was_true_positive:
                sig.true_positives += 1
            else:
                sig.false_positives += 1
            
            total = sig.true_positives + sig.false_positives
            if total > 0:
                sig.effectiveness_score = sig.true_positives / total
            
            # Auto-deprecate poor performing signatures
            if total >= 10 and sig.effectiveness_score < 0.3:
                sig.status = SignatureStatus.DEPRECATED
        
        self.generation_stats["feedback_processed"] += 1

    def get_active_signatures(self) -> List[ThreatSignature]:
        """Get all active signatures"""
        return [s for s in self.signatures.values() if s.status == SignatureStatus.ACTIVE]

    def activate_signature(self, signature_id: str) -> bool:
        """Promote a candidate signature to active status"""
        if signature_id in self.signatures:
            self.signatures[signature_id].status = SignatureStatus.ACTIVE
            return True
        return False

    def export_signatures(self, filepath: str) -> bool:
        """Export all signatures to JSON file"""
        try:
            data = {
                "export_time": datetime.now(timezone.utc).isoformat(),
                "version": "2.0.0",
                "generator_stats": self.generation_stats,
                "signatures": [s.to_dict() for s in self.signatures.values()]
            }
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception:
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Get generator statistics"""
        active = len(self.get_active_signatures())
        return {
            **self.generation_stats,
            "total_signatures": len(self.signatures),
            "active_signatures": active,
            "candidate_signatures": len([s for s in self.signatures.values() if s.status == SignatureStatus.CANDIDATE]),
            "min_confidence_threshold": self.min_confidence
        }

    def _generate_signature_id(self, pattern: ExtractedPattern) -> str:
        """Generate unique signature ID"""
        content = f"{pattern.pattern_text}:{pattern.pattern_type.value}:{time.time()}"
        return f"SIG-{hashlib.sha256(content.encode()).hexdigest()[:16].upper()}"

    def _hash_sample(self, sample: str) -> str:
        """Hash threat sample for tracking"""
        return hashlib.sha256(sample.encode()).hexdigest()[:16]
