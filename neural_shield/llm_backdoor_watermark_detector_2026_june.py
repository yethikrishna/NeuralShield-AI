"""
LLM Backdoor Watermark Detector - NeuralShield AI Security Module
June 2026 Production Release

Detects hidden watermarks, backdoor triggers, and steganographic data in LLM outputs.
This module provides production-grade detection for:
- Statistical watermark patterns (token frequency anomalies)
- Backdoor trigger sequences
- Unicode steganography (zero-width characters)
- Whitespace-based watermarking
- Character substitution watermarks

Based on research from UC Berkeley, MIT, and OpenAI security teams.
"""

import re
import hashlib
import string
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
from collections import Counter
from datetime import datetime, timezone
import math


class WatermarkType(Enum):
    """Types of detectable watermarks."""
    NONE = "no_watermark_detected"
    STATISTICAL = "statistical_token_watermark"
    BACKDOOR_TRIGGER = "backdoor_trigger_sequence"
    UNICODE_STEGANOGRAPHY = "unicode_steganography"
    WHITESPACE_WATERMARK = "whitespace_based_watermark"
    CHARACTER_SUBSTITUTION = "character_substitution_watermark"
    TOKEN_BIAS = "token_distribution_bias"


class WatermarkConfidence(Enum):
    """Confidence levels for watermark detection."""
    NONE = "no_evidence"
    LOW = "low_confidence"
    MEDIUM = "medium_confidence"
    HIGH = "high_confidence"
    CERTAIN = "certain"


@dataclass
class WatermarkFinding:
    """Represents a single watermark detection finding."""
    watermark_type: WatermarkType
    confidence: WatermarkConfidence
    position: Optional[Tuple[int, int]]
    matched_pattern: Optional[str]
    score: float
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "watermark_type": self.watermark_type.value,
            "confidence": self.confidence.value,
            "position": self.position,
            "matched_pattern": self.matched_pattern,
            "score": round(self.score, 4),
            "details": self.details
        }


@dataclass
class WatermarkDetectionResult:
    """Complete watermark detection result."""
    input_text: str
    has_watermark: bool
    findings: List[WatermarkFinding]
    overall_confidence: WatermarkConfidence
    overall_score: float
    analysis_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_text_length": len(self.input_text),
            "has_watermark": self.has_watermark,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "overall_confidence": self.overall_confidence.value,
            "overall_score": round(self.overall_score, 4),
            "analysis_timestamp": self.analysis_timestamp.isoformat()
        }


class LLMBackdoorWatermarkDetector:
    """
    Production-grade LLM watermark and backdoor detector.
    
    Implements multiple detection strategies:
    1. Unicode steganography detection (zero-width characters)
    2. Statistical token distribution analysis
    3. Backdoor trigger sequence matching
    4. Whitespace pattern analysis
    5. Character substitution detection
    """

    # Zero-width and invisible characters used in steganography
    ZERO_WIDTH_CHARS = {
        '\u200b': 'ZERO_WIDTH_SPACE',
        '\u200c': 'ZERO_WIDTH_NON_JOINER',
        '\u200d': 'ZERO_WIDTH_JOINER',
        '\u2060': 'WORD_JOINER',
        '\ufeff': 'ZERO_WIDTH_NO_BREAK_SPACE',
        '\u200e': 'LEFT_TO_RIGHT_MARK',
        '\u200f': 'RIGHT_TO_LEFT_MARK',
        '\u202a': 'LEFT_TO_RIGHT_EMBEDDING',
        '\u202b': 'RIGHT_TO_LEFT_EMBEDDING',
        '\u202c': 'POP_DIRECTIONAL_FORMATTING',
        '\u202d': 'LEFT_TO_RIGHT_OVERRIDE',
        '\u202e': 'RIGHT_TO_LEFT_OVERRIDE',
    }

    # Known backdoor trigger patterns from research
    BACKDOOR_TRIGGERS = [
        r"please\s+follow\s+the\s+new\s+instructions",
        r"ignore\s+previous\s+(instructions|directions|guidelines)",
        r"disregard\s+all\s+previous",
        r"system\s+prompt\s+override",
        r"you\s+are\s+now\s+in\s+developer\s+mode",
        r"switch\s+to\s+dan\s+mode",
        r"say\s+i\s+am\s+ready",
        r"begin\s+transmission",
    ]

    # Common homoglyph substitution pairs
    HOMOGLYPHS = {
        'a': ['а', 'ɑ', 'ạ'],
        'c': ['с', 'ϲ'],
        'e': ['е', 'ẹ'],
        'i': ['і', 'ɪ', 'ị'],
        'o': ['о', 'օ', 'ọ'],
        'p': ['р'],
        's': ['ѕ'],
        'x': ['х'],
        'y': ['у', 'ỵ'],
    }

    def __init__(self, sensitivity_threshold: float = 0.65):
        """
        Initialize watermark detector.
        
        Args:
            sensitivity_threshold: Threshold for detection confidence (0.0-1.0)
        """
        self.sensitivity_threshold = max(0.0, min(1.0, sensitivity_threshold))
        self.detection_stats = Counter()

    def detect_unicode_steganography(self, text: str) -> List[WatermarkFinding]:
        """
        Detect zero-width and invisible characters used for steganography.
        
        Returns:
            List of watermark findings
        """
        findings = []
        zero_width_counts = Counter()

        for idx, char in enumerate(text):
            if char in self.ZERO_WIDTH_CHARS:
                zero_width_counts[char] += 1

        if zero_width_counts:
            total_invisible = sum(zero_width_counts.values())
            density = total_invisible / max(1, len(text))

            confidence = WatermarkConfidence.LOW
            if density > 0.01:
                confidence = WatermarkConfidence.MEDIUM
            if density > 0.05:
                confidence = WatermarkConfidence.HIGH
            if density > 0.1:
                confidence = WatermarkConfidence.CERTAIN

            score = min(1.0, density * 10)

            findings.append(WatermarkFinding(
                watermark_type=WatermarkType.UNICODE_STEGANOGRAPHY,
                confidence=confidence,
                position=(0, len(text)),
                matched_pattern=f"{total_invisible} invisible characters",
                score=score,
                details={
                    "character_counts": {self.ZERO_WIDTH_CHARS[k]: v for k, v in zero_width_counts.items()},
                    "total_invisible": total_invisible,
                    "density": round(density, 6)
                }
            ))

        return findings

    def detect_backdoor_triggers(self, text: str) -> List[WatermarkFinding]:
        """
        Detect known backdoor trigger sequences.
        
        Returns:
            List of watermark findings
        """
        findings = []
        text_lower = text.lower()

        for pattern in self.BACKDOOR_TRIGGERS:
            matches = list(re.finditer(pattern, text_lower, re.IGNORECASE))
            for match in matches:
                findings.append(WatermarkFinding(
                    watermark_type=WatermarkType.BACKDOOR_TRIGGER,
                    confidence=WatermarkConfidence.HIGH,
                    position=match.span(),
                    matched_pattern=match.group(),
                    score=0.95,
                    details={
                        "pattern": pattern,
                        "matched_text": text[match.start():match.end()]
                    }
                ))

        return findings

    def detect_whitespace_watermark(self, text: str) -> List[WatermarkFinding]:
        """
        Detect unusual whitespace patterns used for watermarking.
        
        Returns:
            List of watermark findings
        """
        findings = []

        # Check for multiple consecutive spaces (potential watermark encoding)
        multi_space_matches = list(re.finditer(r' {3,}', text))
        tab_matches = list(re.finditer(r'\t+', text))
        newline_clusters = list(re.finditer(r'\n{3,}', text))

        unusual_count = len(multi_space_matches) + len(tab_matches) + len(newline_clusters)

        if unusual_count > 0:
            score = min(1.0, unusual_count * 0.15)
            confidence = WatermarkConfidence.LOW
            if score > 0.5:
                confidence = WatermarkConfidence.MEDIUM

            findings.append(WatermarkFinding(
                watermark_type=WatermarkType.WHITESPACE_WATERMARK,
                confidence=confidence,
                position=(0, len(text)),
                matched_pattern=f"{unusual_count} unusual whitespace patterns",
                score=score,
                details={
                    "multi_spaces": len(multi_space_matches),
                    "tabs": len(tab_matches),
                    "newline_clusters": len(newline_clusters)
                }
            ))

        return findings

    def detect_character_substitution(self, text: str) -> List[WatermarkFinding]:
        """
        Detect homoglyph character substitutions used for watermarking.
        
        Returns:
            List of watermark findings
        """
        findings = []
        substitution_count = 0
        substitutions_found = []

        for idx, char in enumerate(text):
            for normal_char, homoglyphs in self.HOMOGLYPHS.items():
                if char in homoglyphs:
                    substitution_count += 1
                    substitutions_found.append({
                        "position": idx,
                        "original": normal_char,
                        "substituted": char
                    })

        if substitution_count > 0:
            density = substitution_count / max(1, len(text))
            score = min(1.0, density * 20)

            confidence = WatermarkConfidence.LOW
            if density > 0.005:
                confidence = WatermarkConfidence.MEDIUM
            if density > 0.02:
                confidence = WatermarkConfidence.HIGH

            findings.append(WatermarkFinding(
                watermark_type=WatermarkType.CHARACTER_SUBSTITUTION,
                confidence=confidence,
                position=(0, len(text)),
                matched_pattern=f"{substitution_count} character substitutions",
                score=score,
                details={
                    "substitution_count": substitution_count,
                    "density": round(density, 6),
                    "examples": substitutions_found[:10]
                }
            ))

        return findings

    def detect_statistical_watermark(self, text: str) -> List[WatermarkFinding]:
        """
        Detect statistical watermarks through token distribution analysis.
        
        Analyzes:
        - Unusual token frequency distributions
        - Repetition patterns
        - Entropy anomalies
        
        Returns:
            List of watermark findings
        """
        findings = []

        if len(text) < 50:
            return findings

        words = text.lower().split()
        word_counts = Counter(words)

        if len(words) == 0:
            return findings

        # Calculate repetition ratio
        unique_words = len(word_counts)
        repetition_ratio = 1.0 - (unique_words / len(words))

        # Calculate character entropy
        char_counts = Counter(text)
        entropy = 0.0
        total_chars = len(text)
        for count in char_counts.values():
            p = count / total_chars
            entropy -= p * math.log2(p)

        # Normalized entropy (English text typically ~4.1)
        normalized_entropy = entropy / 8.0

        # Check for unusual patterns
        score = 0.0
        details = {}

        # High repetition is suspicious
        if repetition_ratio > 0.3:
            score += repetition_ratio * 0.5
            details["high_repetition"] = True
            details["repetition_ratio"] = round(repetition_ratio, 4)

        # Unusual entropy is suspicious
        if normalized_entropy < 0.3 or normalized_entropy > 0.65:
            entropy_score = abs(0.475 - normalized_entropy) * 2
            score += entropy_score * 0.3
            details["entropy_anomaly"] = True
            details["normalized_entropy"] = round(normalized_entropy, 4)

        if score > self.sensitivity_threshold * 0.5:
            confidence = WatermarkConfidence.LOW
            if score > 0.5:
                confidence = WatermarkConfidence.MEDIUM

            findings.append(WatermarkFinding(
                watermark_type=WatermarkType.STATISTICAL,
                confidence=confidence,
                position=(0, len(text)),
                matched_pattern="statistical distribution anomaly",
                score=score,
                details=details
            ))

        return findings

    def detect(self, text: str) -> WatermarkDetectionResult:
        """
        Run complete watermark detection pipeline.
        
        Args:
            text: Text to analyze for watermarks/backdoors
            
        Returns:
            Complete detection result
        """
        all_findings = []

        # Run all detectors
        all_findings.extend(self.detect_unicode_steganography(text))
        all_findings.extend(self.detect_backdoor_triggers(text))
        all_findings.extend(self.detect_whitespace_watermark(text))
        all_findings.extend(self.detect_character_substitution(text))
        all_findings.extend(self.detect_statistical_watermark(text))

        # Update statistics
        for finding in all_findings:
            self.detection_stats[finding.watermark_type.value] += 1

        # Calculate overall score
        if all_findings:
            overall_score = max(f.score for f in all_findings)
            has_watermark = overall_score >= self.sensitivity_threshold

            # Determine overall confidence
            confidences = [f.confidence for f in all_findings]
            confidence_order = [
                WatermarkConfidence.NONE,
                WatermarkConfidence.LOW,
                WatermarkConfidence.MEDIUM,
                WatermarkConfidence.HIGH,
                WatermarkConfidence.CERTAIN
            ]
            overall_confidence = max(confidences, key=lambda c: confidence_order.index(c))
        else:
            overall_score = 0.0
            has_watermark = False
            overall_confidence = WatermarkConfidence.NONE

        return WatermarkDetectionResult(
            input_text=text,
            has_watermark=has_watermark,
            findings=all_findings,
            overall_confidence=overall_confidence,
            overall_score=overall_score
        )

    def get_detection_statistics(self) -> Dict[str, Any]:
        """Get cumulative detection statistics."""
        return {
            "total_detections": sum(self.detection_stats.values()),
            "by_type": dict(self.detection_stats),
            "sensitivity_threshold": self.sensitivity_threshold
        }


def create_watermark_detector(sensitivity: str = "default") -> LLMBackdoorWatermarkDetector:
    """
    Factory function to create watermark detector with preset sensitivity.
    
    Args:
        sensitivity: "strict", "default", or "permissive"
        
    Returns:
        Configured LLMBackdoorWatermarkDetector
    """
    thresholds = {
        "strict": 0.4,
        "default": 0.65,
        "permissive": 0.85
    }
    return LLMBackdoorWatermarkDetector(
        sensitivity_threshold=thresholds.get(sensitivity, 0.65)
    )
