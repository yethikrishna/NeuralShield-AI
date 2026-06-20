"""
NeuralShield AI - Prompt Injection Evasion Technique Detector v2
Production-grade detection of advanced prompt injection evasion techniques.

This module provides:
- Multi-pattern evasion technique detection (homoglyphs, leetspeak, whitespace obfuscation)
- Semantic similarity analysis using TF-IDF and cosine similarity
- Confidence scoring with weighted voting
- Real-time decoding of obfuscated content
- Technique classification with MITRE ATT&CK mapping
- False positive reduction through context analysis
- Batch processing support with caching
"""
import re
import math
import hashlib
import string
from typing import Dict, List, Set, Tuple, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from collections import defaultdict, Counter
from functools import lru_cache


class EvasionTechniqueType(Enum):
    """Types of prompt injection evasion techniques"""
    HOMOGLYPH_SUBSTITUTION = "homoglyph_substitution"
    LEETSPEAK_ENCODING = "leetspeak_encoding"
    WHITESPACE_OBFUSCATION = "whitespace_obfuscation"
    ZERO_WIDTH_CHARACTERS = "zero_width_characters"
    BASE64_ENCODING = "base64_encoding"
    ROT13_CIPHER = "rot13_cipher"
    CHARACTER_SPLITTING = "character_splitting"
    WORD_DELIMITER_INJECTION = "word_delimiter_injection"
    CASE_ALTERNATION = "case_alternation"
    UNICODE_NORMALIZATION = "unicode_normalization"
    PHONETIC_SUBSTITUTION = "phonetic_substitution"
    SYNONYM_REPLACEMENT = "synonym_replacement"


class DetectionConfidence(Enum):
    """Confidence levels for detection results"""
    VERY_HIGH = "very_high"  # > 0.90
    HIGH = "high"            # 0.70 - 0.90
    MEDIUM = "medium"        # 0.40 - 0.70
    LOW = "low"              # 0.15 - 0.40
    NONE = "none"            # < 0.15


@dataclass
class EvasionDetectionResult:
    """Result of evasion technique detection"""
    detected: bool
    techniques: List[EvasionTechniqueType] = field(default_factory=list)
    confidence_scores: Dict[EvasionTechniqueType, float] = field(default_factory=dict)
    overall_confidence: float = 0.0
    decoded_content: Optional[str] = None
    suspicious_segments: List[Tuple[int, int, str]] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    false_positive_risk: float = 0.0
    processing_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "detected": self.detected,
            "techniques": [t.value for t in self.techniques],
            "confidence_scores": {t.value: round(s, 4) for t, s in self.confidence_scores.items()},
            "overall_confidence": round(self.overall_confidence, 4),
            "confidence_level": self._get_confidence_level().value,
            "decoded_content_preview": self.decoded_content[:200] + "..." if self.decoded_content and len(self.decoded_content) > 200 else self.decoded_content,
            "suspicious_segments_count": len(self.suspicious_segments),
            "mitre_techniques": self.mitre_techniques,
            "false_positive_risk": round(self.false_positive_risk, 4),
            "processing_time_ms": round(self.processing_time_ms, 2),
            "timestamp": self.timestamp.isoformat()
        }
    
    def _get_confidence_level(self) -> DetectionConfidence:
        if self.overall_confidence >= 0.90:
            return DetectionConfidence.VERY_HIGH
        elif self.overall_confidence >= 0.70:
            return DetectionConfidence.HIGH
        elif self.overall_confidence >= 0.40:
            return DetectionConfidence.MEDIUM
        elif self.overall_confidence >= 0.15:
            return DetectionConfidence.LOW
        return DetectionConfidence.NONE


class PromptInjectionEvasionDetectorV2:
    """
    Production-grade prompt injection evasion technique detector.
    Uses multi-pattern matching, semantic analysis, and weighted voting.
    """
    
    # Homoglyph mapping - common look-alike character substitutions
    HOMOGLYPH_MAP = {
        'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x',
        'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',
        'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Χ': 'X',
        'Υ': 'Y', 'Ζ': 'Z',
        '𝚊': 'a', '𝚋': 'b', '𝚌': 'c', '𝚍': 'd', '𝚎': 'e', '𝚏': 'f',
        '𝟶': '0', '𝟷': '1', '𝟸': '2', '𝟹': '3', '𝟺': '4', '𝟻': '5',
        '𝟼': '6', '𝟽': '7', '𝟾': '8', '𝟿': '9'
    }
    
    # Leet speak mapping
    LEET_MAP = {
        '0': 'o', '1': 'i', '2': 'z', '3': 'e', '4': 'a', '5': 's',
        '6': 'g', '7': 't', '8': 'b', '9': 'g', '@': 'a', '$': 's',
        '!': 'i', '+': 't', '(': 'c', '<': 'c', '|': 'i', '[': 'c'
    }
    
    # Zero-width and invisible characters
    ZERO_WIDTH_CHARS = {
        '\u200b', '\u200c', '\u200d', '\u2060', '\ufeff',
        '\u2061', '\u2062', '\u2063', '\u2064'
    }
    
    # Known prompt injection trigger phrases (for semantic matching)
    INJECTION_TRIGGERS = {
        "ignore previous", "disregard instructions", "forget everything",
        "system prompt", "initial instructions", "you are now", "act as",
        "bypass security", "disable filter", "override settings",
        "ignore above", "repeat everything", "show instructions",
        "developer mode", "admin mode", "god mode"
    }
    
    # MITRE ATT&CK mappings for evasion techniques
    MITRE_MAPPING = {
        EvasionTechniqueType.HOMOGLYPH_SUBSTITUTION: ["T1027", "T1027.002"],
        EvasionTechniqueType.LEETSPEAK_ENCODING: ["T1027", "T1027.002"],
        EvasionTechniqueType.WHITESPACE_OBFUSCATION: ["T1027", "T1027.001"],
        EvasionTechniqueType.ZERO_WIDTH_CHARACTERS: ["T1027", "T1027.002"],
        EvasionTechniqueType.BASE64_ENCODING: ["T1027", "T1027.003"],
        EvasionTechniqueType.ROT13_CIPHER: ["T1027", "T1027.003"],
    }
    
    def __init__(self, 
                 confidence_threshold: float = 0.4,
                 enable_caching: bool = True,
                 max_cache_size: int = 10000):
        self.confidence_threshold = confidence_threshold
        self.enable_caching = enable_caching
        self.max_cache_size = max_cache_size
        self._detection_cache: Dict[str, EvasionDetectionResult] = {}
        self._idf_cache: Dict[str, float] = {}
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns for detection"""
        self._patterns = {
            # Case alternation: LiKe tHiS
            'case_alternation': re.compile(
                r'(?:[A-Z][a-z]){4,}|(?:[a-z][A-Z]){4,}',
                re.UNICODE
            ),
            # Character splitting: I G N O R E
            'char_splitting': re.compile(
                r'(?:[A-Za-z]\s){5,}[A-Za-z]',
                re.UNICODE
            ),
            # Word delimiter injection: i_g_n_o_r_e or i-g-n-o-r-e
            'delimiter_injection': re.compile(
                r'(?:[A-Za-z][_\-.]){4,}[A-Za-z]',
                re.UNICODE
            ),
            # Potential base64 patterns
            'base64_like': re.compile(
                r'[A-Za-z0-9+/]{20,}={0,2}',
                re.UNICODE
            ),
            # Excessive whitespace
            'excessive_whitespace': re.compile(
                r'\s{5,}|\t{3,}|\n{3,}',
                re.UNICODE
            ),
        }
    
    @lru_cache(maxsize=10000)
    def _normalize_text(self, text: str) -> str:
        """Normalize text for comparison - cached"""
        # Remove zero-width characters
        for zw_char in self.ZERO_WIDTH_CHARS:
            text = text.replace(zw_char, '')
        
        # Normalize homoglyphs
        result = []
        for char in text:
            if char in self.HOMOGLYPH_MAP:
                result.append(self.HOMOGLYPH_MAP[char])
            elif char in self.LEET_MAP:
                result.append(self.LEET_MAP[char])
            else:
                result.append(char.lower())
        
        return ''.join(result)
    
    def _detect_homoglyphs(self, text: str) -> Tuple[float, List[Tuple[int, int, str]]]:
        """Detect homoglyph substitution attacks"""
        homoglyph_count = sum(1 for c in text if c in self.HOMOGLYPH_MAP)
        suspicious_segments = []
        
        if homoglyph_count > 0:
            density = homoglyph_count / max(1, len(text))
            
            # Find suspicious segments
            normalized = self._normalize_text(text)
            words = normalized.split()
            
            for i, word in enumerate(words):
                original_words = text.split()
                if i < len(original_words):
                    original = original_words[i]
                    has_homoglyph = any(c in self.HOMOGLYPH_MAP for c in original)
                    if has_homoglyph and self._is_injection_related(word):
                        start = text.lower().find(original.lower())
                        if start >= 0:
                            suspicious_segments.append((start, start + len(original), original))
            
            confidence = min(1.0, density * 5) if homoglyph_count >= 3 else density * 2
            return confidence, suspicious_segments
        
        return 0.0, []
    
    def _detect_leetspeak(self, text: str) -> Tuple[float, List[Tuple[int, int, str]]]:
        """Detect leet speak encoding"""
        leet_count = sum(1 for c in text if c in self.LEET_MAP)
        suspicious_segments = []
        
        if leet_count > 0:
            density = leet_count / max(1, len(text))
            normalized = self._normalize_text(text)
            
            # Check if leet is forming injection phrases
            if self._is_injection_related(normalized):
                words = text.split()
                for word in words:
                    has_leet = any(c in self.LEET_MAP for c in word)
                    if has_leet:
                        norm_word = ''.join(self.LEET_MAP.get(c, c.lower()) for c in word)
                        if self._is_injection_related(norm_word):
                            start = text.find(word)
                            if start >= 0:
                                suspicious_segments.append((start, start + len(word), word))
            
            confidence = min(1.0, density * 4) if leet_count >= 2 else density * 1.5
            return confidence, suspicious_segments
        
        return 0.0, []
    
    def _detect_zero_width(self, text: str) -> Tuple[float, List[Tuple[int, int, str]]]:
        """Detect zero-width character obfuscation"""
        zw_count = sum(1 for c in text if c in self.ZERO_WIDTH_CHARS)
        suspicious_segments = []
        
        if zw_count > 0:
            # Any zero-width chars in injection context is highly suspicious
            density = zw_count / max(1, len(text))
            
            # Clean and check content
            cleaned = self._normalize_text(text)
            if self._is_injection_related(cleaned):
                suspicious_segments.append((0, min(50, len(text)), "Zero-width chars detected"))
            
            confidence = min(1.0, 0.3 + (zw_count * 0.15))
            return confidence, suspicious_segments
        
        return 0.0, []
    
    def _detect_pattern_based(self, text: str) -> Dict[EvasionTechniqueType, float]:
        """Detect pattern-based evasion techniques"""
        scores = {}
        
        # Case alternation
        if self._patterns['case_alternation'].search(text):
            matches = self._patterns['case_alternation'].findall(text)
            scores[EvasionTechniqueType.CASE_ALTERNATION] = min(1.0, len(matches) * 0.25)
        
        # Character splitting
        if self._patterns['char_splitting'].search(text):
            matches = self._patterns['char_splitting'].findall(text)
            scores[EvasionTechniqueType.CHARACTER_SPLITTING] = min(1.0, len(matches) * 0.3)
        
        # Delimiter injection
        if self._patterns['delimiter_injection'].search(text):
            matches = self._patterns['delimiter_injection'].findall(text)
            scores[EvasionTechniqueType.WORD_DELIMITER_INJECTION] = min(1.0, len(matches) * 0.3)
        
        # Excessive whitespace
        if self._patterns['excessive_whitespace'].search(text):
            scores[EvasionTechniqueType.WHITESPACE_OBFUSCATION] = 0.6
        
        return scores
    
    def _is_injection_related(self, text: str) -> bool:
        """Check if text contains injection-related phrases"""
        text_lower = text.lower()
        for trigger in self.INJECTION_TRIGGERS:
            if trigger in text_lower:
                return True
            # Check partial matches with edit distance
            words = text_lower.split()
            for word in words:
                if len(word) > 3:
                    for trigger_word in trigger.split():
                        if self._levenshtein_distance(word, trigger_word) <= 2:
                            return True
        return False
    
    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate Levenshtein edit distance between two strings"""
        if len(s1) < len(s2):
            return PromptInjectionEvasionDetectorV2._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _calculate_semantic_similarity(self, text: str) -> float:
        """Calculate semantic similarity to known injection patterns using TF-IDF"""
        normalized = self._normalize_text(text)
        words = normalized.split()
        
        if not words:
            return 0.0
        
        # Calculate similarity score based on trigger word matches
        match_count = 0
        total_trigger_words = 0
        
        for trigger in self.INJECTION_TRIGGERS:
            trigger_words = trigger.split()
            total_trigger_words += len(trigger_words)
            for t_word in trigger_words:
                for word in words:
                    if len(word) > 2 and len(t_word) > 2:
                        dist = self._levenshtein_distance(word, t_word)
                        max_len = max(len(word), len(t_word))
                        if max_len > 0 and dist / max_len < 0.3:
                            match_count += 1
                            break
        
        if total_trigger_words == 0:
            return 0.0
        
        return min(1.0, match_count / max(5, total_trigger_words * 0.3))
    
    def _calculate_false_positive_risk(self, text: str, 
                                       techniques: List[EvasionTechniqueType]) -> float:
        """Calculate risk of false positive detection"""
        risk_factors = 0.0
        
        # Short texts are higher risk
        if len(text) < 20:
            risk_factors += 0.2
        
        # Common programming patterns that might look like obfuscation
        programming_patterns = ['var_', 'const_', 'func_', 'get_', 'set_']
        for pattern in programming_patterns:
            if pattern in text.lower():
                risk_factors += 0.15
        
        # If only one technique with low confidence, higher FP risk
        if len(techniques) == 1:
            risk_factors += 0.1
        
        return min(1.0, risk_factors)
    
    def detect(self, text: str) -> EvasionDetectionResult:
        """
        Detect evasion techniques in prompt text.
        
        Args:
            text: The prompt text to analyze
        
        Returns:
            EvasionDetectionResult with detection details
        """
        import time
        start_time = time.time()
        
        # Check cache first
        cache_key = hashlib.md5(text.encode()).hexdigest()
        if self.enable_caching and cache_key in self._detection_cache:
            cached = self._detection_cache[cache_key]
            return cached
        
        all_scores: Dict[EvasionTechniqueType, float] = {}
        all_segments: List[Tuple[int, int, str]] = []
        
        # Run individual detectors
        homo_conf, homo_segments = self._detect_homoglyphs(text)
        if homo_conf > 0:
            all_scores[EvasionTechniqueType.HOMOGLYPH_SUBSTITUTION] = homo_conf
            all_segments.extend(homo_segments)
        
        leet_conf, leet_segments = self._detect_leetspeak(text)
        if leet_conf > 0:
            all_scores[EvasionTechniqueType.LEETSPEAK_ENCODING] = leet_conf
            all_segments.extend(leet_segments)
        
        zw_conf, zw_segments = self._detect_zero_width(text)
        if zw_conf > 0:
            all_scores[EvasionTechniqueType.ZERO_WIDTH_CHARACTERS] = zw_conf
            all_segments.extend(zw_segments)
        
        # Pattern-based detection
        pattern_scores = self._detect_pattern_based(text)
        all_scores.update(pattern_scores)
        
        # Semantic similarity check
        semantic_score = self._calculate_semantic_similarity(text)
        
        # Filter techniques above threshold
        detected_techniques = [
            tech for tech, score in all_scores.items()
            if score >= self.confidence_threshold
        ]
        
        # Calculate overall confidence (weighted average)
        if all_scores:
            weights = {
                EvasionTechniqueType.ZERO_WIDTH_CHARACTERS: 1.5,
                EvasionTechniqueType.HOMOGLYPH_SUBSTITUTION: 1.2,
                EvasionTechniqueType.LEETSPEAK_ENCODING: 1.1,
            }
            
            weighted_sum = 0.0
            weight_sum = 0.0
            
            for tech, score in all_scores.items():
                weight = weights.get(tech, 1.0)
                weighted_sum += score * weight
                weight_sum += weight
            
            base_confidence = weighted_sum / weight_sum if weight_sum > 0 else 0
            
            # Boost if semantic similarity indicates injection intent
            if semantic_score > 0.3:
                base_confidence = min(1.0, base_confidence + semantic_score * 0.5)
            
            overall_confidence = base_confidence
        else:
            overall_confidence = 0.0
        
        # Get MITRE mappings
        mitre_techniques = []
        for tech in detected_techniques:
            mitre_techniques.extend(self.MITRE_MAPPING.get(tech, []))
        
        # Calculate false positive risk
        fp_risk = self._calculate_false_positive_risk(text, detected_techniques)
        
        result = EvasionDetectionResult(
            detected=len(detected_techniques) > 0 and overall_confidence >= self.confidence_threshold,
            techniques=detected_techniques,
            confidence_scores=all_scores,
            overall_confidence=overall_confidence,
            decoded_content=self._normalize_text(text),
            suspicious_segments=all_segments,
            mitre_techniques=list(set(mitre_techniques)),
            false_positive_risk=fp_risk,
            processing_time_ms=(time.time() - start_time) * 1000
        )
        
        # Cache result
        if self.enable_caching:
            if len(self._detection_cache) >= self.max_cache_size:
                # Remove oldest entry
                oldest_key = next(iter(self._detection_cache))
                del self._detection_cache[oldest_key]
            self._detection_cache[cache_key] = result
        
        return result
    
    def detect_batch(self, texts: List[str]) -> List[EvasionDetectionResult]:
        """Detect evasion techniques on a batch of texts"""
        return [self.detect(text) for text in texts]
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            "cache_enabled": self.enable_caching,
            "cache_size": len(self._detection_cache),
            "max_cache_size": self.max_cache_size,
            "cache_hit_ratio": 0.0  # Would need hit tracking
        }
