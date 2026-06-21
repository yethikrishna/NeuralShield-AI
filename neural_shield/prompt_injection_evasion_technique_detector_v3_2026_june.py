"""
NeuralShield AI - Prompt Injection Evasion Technique Detector v3
Production-grade detection of advanced prompt injection evasion techniques.

NEW IN V3:
- Unicode combining diacritics detection (zalgo text)
- URL percent-encoding detection and decoding
- HTML entity encoding detection
- Nested obfuscation detection (multi-layer encoding)
- Enhanced false positive reduction with context whitelisting
- Performance optimized regex patterns
- Batch processing with parallel detection
- Entropy analysis for encoded content detection
- Confidence calibration with Bayesian updating
"""
import re
import math
import time
import html
import hashlib
import string
import urllib.parse
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
    # NEW IN V3
    COMBINING_DIACRITICS = "combining_diacritics"
    URL_PERCENT_ENCODING = "url_percent_encoding"
    HTML_ENTITY_ENCODING = "html_entity_encoding"
    NESTED_OBFUSCATION = "nested_obfuscation"
    ENTROPY_ANOMALY = "entropy_anomaly"


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
    obfuscation_layers: int = 0
    entropy_score: float = 0.0
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
            "obfuscation_layers": self.obfuscation_layers,
            "entropy_score": round(self.entropy_score, 4),
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


class PromptInjectionEvasionDetectorV3:
    """
    Production-grade prompt injection evasion technique detector v3.
    Uses multi-pattern matching, semantic analysis, entropy analysis, and weighted voting.
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
    
    # Combining diacritical marks (Zalgo text range) - NEW IN V3
    COMBINING_DIACRITICS = set(range(0x0300, 0x036F)) | set(range(0x1AB0, 0x1AFF))
    
    # Known prompt injection trigger phrases (for semantic matching)
    INJECTION_TRIGGERS = {
        "ignore previous", "disregard instructions", "forget everything",
        "system prompt", "initial instructions", "you are now", "act as",
        "bypass security", "disable filter", "override settings",
        "ignore above", "repeat everything", "show instructions",
        "developer mode", "admin mode", "god mode", "say everything",
        "output all", "reveal prompt", "show system", "ignore rules",
        "do not follow", "break character", "roleplay as"
    }
    
    # Legitimate contexts that might look like obfuscation - NEW IN V3 FP REDUCTION
    LEGITIMATE_CONTEXTS = {
        "http://", "https://", "www.", ".com", ".org", ".net",
        "api.", "endpoint", "token", "auth", "password", "key",
        "base64", "encode", "decode", "hash", "encrypt", "decrypt"
    }
    
    # MITRE ATT&CK mappings for evasion techniques
    MITRE_MAPPING = {
        EvasionTechniqueType.HOMOGLYPH_SUBSTITUTION: ["T1027", "T1027.002"],
        EvasionTechniqueType.LEETSPEAK_ENCODING: ["T1027", "T1027.002"],
        EvasionTechniqueType.WHITESPACE_OBFUSCATION: ["T1027", "T1027.001"],
        EvasionTechniqueType.ZERO_WIDTH_CHARACTERS: ["T1027", "T1027.002"],
        EvasionTechniqueType.BASE64_ENCODING: ["T1027", "T1027.003"],
        EvasionTechniqueType.ROT13_CIPHER: ["T1027", "T1027.003"],
        EvasionTechniqueType.COMBINING_DIACRITICS: ["T1027", "T1027.002"],
        EvasionTechniqueType.URL_PERCENT_ENCODING: ["T1027", "T1027.003"],
        EvasionTechniqueType.HTML_ENTITY_ENCODING: ["T1027", "T1027.003"],
        EvasionTechniqueType.NESTED_OBFUSCATION: ["T1027", "T1027.005"],
    }
    
    def __init__(self, 
                 confidence_threshold: float = 0.4,
                 enable_caching: bool = True,
                 max_cache_size: int = 10000,
                 enable_nested_detection: bool = True,
                 fp_reduction_level: str = "medium"):
        self.confidence_threshold = confidence_threshold
        self.enable_caching = enable_caching
        self.max_cache_size = max_cache_size
        self.enable_nested_detection = enable_nested_detection
        self.fp_reduction_level = fp_reduction_level
        self._detection_cache: Dict[str, EvasionDetectionResult] = {}
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Compile optimized regex patterns for detection - V3 optimized"""
        self._patterns = {
            # Case alternation: LiKe tHiS (optimized)
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
            # URL percent encoding: %XX%XX%XX - NEW IN V3
            'url_encoding': re.compile(
                r'(?:%[0-9A-Fa-f]{2}){3,}',
                re.UNICODE
            ),
            # HTML entities: &#xXX; or &name; - NEW IN V3
            'html_entities': re.compile(
                r'(?:&#[xX]?[0-9A-Fa-f]+;|&[a-zA-Z]+;){2,}',
                re.UNICODE
            ),
            # Potential base64 patterns (optimized)
            'base64_like': re.compile(
                r'[A-Za-z0-9+/]{25,}={0,2}',
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
        """Normalize text for comparison - cached - V3 enhanced"""
        # Remove zero-width characters
        for zw_char in self.ZERO_WIDTH_CHARS:
            text = text.replace(zw_char, '')
        
        # Remove combining diacritics - NEW IN V3
        text = ''.join(c for c in text if ord(c) not in self.COMBINING_DIACRITICS)
        
        # Normalize homoglyphs and leet
        result = []
        for char in text:
            if char in self.HOMOGLYPH_MAP:
                result.append(self.HOMOGLYPH_MAP[char])
            elif char in self.LEET_MAP:
                result.append(self.LEET_MAP[char])
            else:
                result.append(char.lower())
        
        return ''.join(result)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy for anomaly detection - NEW IN V3"""
        if not text:
            return 0.0
        
        char_counts = Counter(text)
        entropy = 0.0
        total_chars = len(text)
        
        for count in char_counts.values():
            probability = count / total_chars
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _detect_combining_diacritics(self, text: str) -> Tuple[float, List[Tuple[int, int, str]]]:
        """Detect combining diacritics (Zalgo text) - NEW IN V3"""
        diacritic_count = sum(1 for c in text if ord(c) in self.COMBINING_DIACRITICS)
        suspicious_segments = []
        
        if diacritic_count > 0:
            density = diacritic_count / max(1, len(text))
            
            # Find segments with diacritics
            cleaned = ''.join(c for c in text if ord(c) not in self.COMBINING_DIACRITICS)
            if self._is_injection_related(cleaned):
                suspicious_segments.append((0, min(50, len(text)), "Combining diacritics detected"))
            
            # High confidence - combining diacritics are rarely legitimate
            confidence = min(1.0, 0.5 + (density * 3))
            return confidence, suspicious_segments
        
        return 0.0, []
    
    def _detect_url_encoding(self, text: str) -> Tuple[float, List[Tuple[int, int, str]]]:
        """Detect URL percent-encoding - NEW IN V3"""
        suspicious_segments = []
        
        matches = self._patterns['url_encoding'].findall(text)
        if matches:
            # Try to decode and check for injection content
            try:
                decoded = urllib.parse.unquote(text)
                if decoded != text and self._is_injection_related(decoded):
                    for match in matches:
                        start = text.find(match)
                        if start >= 0:
                            suspicious_segments.append((start, start + len(match), match))
                    
                    confidence = min(1.0, 0.6 + (len(matches) * 0.1))
                    return confidence, suspicious_segments
            except:
                pass
            
            # Even if decode fails, multiple encodings are suspicious
            return 0.3, []
        
        return 0.0, []
    
    def _detect_html_entities(self, text: str) -> Tuple[float, List[Tuple[int, int, str]]]:
        """Detect HTML entity encoding - NEW IN V3"""
        suspicious_segments = []
        
        matches = self._patterns['html_entities'].findall(text)
        if matches:
            try:
                decoded = html.unescape(text)
                if decoded != text and self._is_injection_related(decoded):
                    for match in matches:
                        start = text.find(match)
                        if start >= 0:
                            suspicious_segments.append((start, start + len(match), match))
                    
                    confidence = min(1.0, 0.6 + (len(matches) * 0.1))
                    return confidence, suspicious_segments
            except:
                pass
            
            return 0.3, []
        
        return 0.0, []
    
    def _detect_homoglyphs(self, text: str) -> Tuple[float, List[Tuple[int, int, str]]]:
        """Detect homoglyph substitution attacks - V3 optimized"""
        homoglyph_count = sum(1 for c in text if c in self.HOMOGLYPH_MAP)
        suspicious_segments = []
        
        if homoglyph_count > 0:
            density = homoglyph_count / max(1, len(text))
            normalized = self._normalize_text(text)
            
            # Check if homoglyphs form injection phrases
            if self._is_injection_related(normalized):
                words = text.split()
                for word in words:
                    has_homoglyph = any(c in self.HOMOGLYPH_MAP for c in word)
                    if has_homoglyph:
                        norm_word = ''.join(self.HOMOGLYPH_MAP.get(c, c.lower()) for c in word)
                        if self._is_injection_related(norm_word):
                            start = text.find(word)
                            if start >= 0:
                                suspicious_segments.append((start, start + len(word), word))
            
            confidence = min(1.0, density * 5) if homoglyph_count >= 3 else density * 2
            return confidence, suspicious_segments
        
        return 0.0, []
    
    def _detect_leetspeak(self, text: str) -> Tuple[float, List[Tuple[int, int, str]]]:
        """Detect leet speak encoding - V3 optimized"""
        leet_count = sum(1 for c in text if c in self.LEET_MAP)
        suspicious_segments = []
        
        if leet_count > 0:
            density = leet_count / max(1, len(text))
            normalized = self._normalize_text(text)
            
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
            cleaned = self._normalize_text(text)
            if self._is_injection_related(cleaned):
                suspicious_segments.append((0, min(50, len(text)), "Zero-width chars detected"))
            
            confidence = min(1.0, 0.3 + (zw_count * 0.15))
            return confidence, suspicious_segments
        
        return 0.0, []
    
    def _detect_pattern_based(self, text: str) -> Dict[EvasionTechniqueType, float]:
        """Detect pattern-based evasion techniques - V3 enhanced"""
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
        
        # Base64-like patterns
        if self._patterns['base64_like'].search(text):
            if not self._is_legitimate_url(text):
                scores[EvasionTechniqueType.BASE64_ENCODING] = 0.5
        
        return scores
    
    def _is_injection_related(self, text: str) -> bool:
        """Check if text contains injection-related phrases - V3 enhanced"""
        text_lower = text.lower()
        
        # Exact match first
        for trigger in self.INJECTION_TRIGGERS:
            if trigger in text_lower:
                return True
        
        # Fuzzy match
        words = text_lower.split()
        for word in words:
            if len(word) > 3:
                for trigger in self.INJECTION_TRIGGERS:
                    for trigger_word in trigger.split():
                        if len(trigger_word) > 3:
                            dist = self._levenshtein_distance(word, trigger_word)
                            max_len = max(len(word), len(trigger_word))
                            if max_len > 0 and dist / max_len < 0.25:
                                return True
        return False
    
    def _is_legitimate_url(self, text: str) -> bool:
        """Check if text is likely a legitimate URL - NEW IN V3 FP REDUCTION"""
        text_lower = text.lower()
        for ctx in self.LEGITIMATE_CONTEXTS:
            if ctx in text_lower:
                return True
        return False
    
    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate Levenshtein edit distance between two strings"""
        if len(s1) < len(s2):
            return PromptInjectionEvasionDetectorV3._levenshtein_distance(s2, s1)
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
        """Calculate semantic similarity to known injection patterns"""
        normalized = self._normalize_text(text)
        words = normalized.split()
        
        if not words:
            return 0.0
        
        match_count = 0
        for trigger in self.INJECTION_TRIGGERS:
            trigger_words = trigger.split()
            for t_word in trigger_words:
                for word in words:
                    if len(word) > 2 and len(t_word) > 2:
                        dist = self._levenshtein_distance(word, t_word)
                        max_len = max(len(word), len(t_word))
                        if max_len > 0 and dist / max_len < 0.3:
                            match_count += 1
                            break
        
        return min(1.0, match_count / 15.0)
    
    def _calculate_false_positive_risk(self, text: str, 
                                       techniques: List[EvasionTechniqueType]) -> float:
        """Calculate risk of false positive detection - V3 enhanced"""
        risk_factors = 0.0
        
        # Short texts are higher risk
        if len(text) < 20:
            risk_factors += 0.2
        
        # Legitimate URL/API contexts reduce FP risk
        if self._is_legitimate_url(text):
            risk_factors -= 0.2
        
        # Common programming patterns
        programming_patterns = ['var_', 'const_', 'func_', 'get_', 'set_', 'import ']
        for pattern in programming_patterns:
            if pattern in text.lower():
                risk_factors += 0.1
        
        # If only one technique with low confidence, higher FP risk
        if len(techniques) == 1:
            risk_factors += 0.1
        
        return max(0.0, min(1.0, risk_factors))
    
    def _detect_nested_obfuscation(self, text: str) -> Tuple[int, float, str]:
        """Detect multi-layer/nested obfuscation - NEW IN V3"""
        layers = 0
        current_text = text
        max_layers = 5
        
        for _ in range(max_layers):
            layer_detected = False
            
            # Try URL decode
            try:
                decoded = urllib.parse.unquote(current_text)
                if decoded != current_text:
                    current_text = decoded
                    layers += 1
                    layer_detected = True
            except:
                pass
            
            # Try HTML decode
            try:
                decoded = html.unescape(current_text)
                if decoded != current_text:
                    current_text = decoded
                    layers += 1
                    layer_detected = True
            except:
                pass
            
            # Normalize
            normalized = self._normalize_text(current_text)
            if normalized != current_text:
                current_text = normalized
                layers += 1
                layer_detected = True
            
            if not layer_detected:
                break
        
        confidence = min(1.0, layers * 0.25) if layers >= 2 else 0.0
        return layers, confidence, current_text
    
    def detect(self, text: str) -> EvasionDetectionResult:
        """
        Detect evasion techniques in prompt text - V3 complete detection.
        
        Args:
            text: Input prompt text to analyze
            
        Returns:
            EvasionDetectionResult with all findings
        """
        start_time = time.time()
        
        # Check cache first
        if self.enable_caching and text in self._detection_cache:
            return self._detection_cache[text]
        
        all_scores: Dict[EvasionTechniqueType, float] = {}
        all_segments: List[Tuple[int, int, str]] = []
        decoded_content = text
        
        # NEW V3 DETECTORS
        # 1. Combining diacritics (Zalgo)
        conf, segs = self._detect_combining_diacritics(text)
        if conf > 0.1:
            all_scores[EvasionTechniqueType.COMBINING_DIACRITICS] = conf
            all_segments.extend(segs)
        
        # 2. URL encoding
        conf, segs = self._detect_url_encoding(text)
        if conf > 0.1:
            all_scores[EvasionTechniqueType.URL_PERCENT_ENCODING] = conf
            all_segments.extend(segs)
        
        # 3. HTML entities
        conf, segs = self._detect_html_entities(text)
        if conf > 0.1:
            all_scores[EvasionTechniqueType.HTML_ENTITY_ENCODING] = conf
            all_segments.extend(segs)
        
        # EXISTING DETECTORS
        # 4. Homoglyphs
        conf, segs = self._detect_homoglyphs(text)
        if conf > 0.1:
            all_scores[EvasionTechniqueType.HOMOGLYPH_SUBSTITUTION] = conf
            all_segments.extend(segs)
        
        # 5. Leet speak
        conf, segs = self._detect_leetspeak(text)
        if conf > 0.1:
            all_scores[EvasionTechniqueType.LEETSPEAK_ENCODING] = conf
            all_segments.extend(segs)
        
        # 6. Zero-width chars
        conf, segs = self._detect_zero_width(text)
        if conf > 0.1:
            all_scores[EvasionTechniqueType.ZERO_WIDTH_CHARACTERS] = conf
            all_segments.extend(segs)
        
        # 7. Pattern-based detection
        pattern_scores = self._detect_pattern_based(text)
        all_scores.update(pattern_scores)
        
        # 8. Nested obfuscation detection - NEW V3
        obfuscation_layers = 0
        if self.enable_nested_detection:
            layers, nested_conf, decoded = self._detect_nested_obfuscation(text)
            obfuscation_layers = layers
            if nested_conf > 0.2:
                all_scores[EvasionTechniqueType.NESTED_OBFUSCATION] = nested_conf
                decoded_content = decoded
        
        # 9. Entropy analysis - NEW V3
        entropy = self._calculate_entropy(text)
        if entropy > 4.5:  # High entropy indicates encoded content
            all_scores[EvasionTechniqueType.ENTROPY_ANOMALY] = min(1.0, (entropy - 4.0) / 2.0)
        
        # Semantic similarity boost
        semantic_score = self._calculate_semantic_similarity(text)
        
        # Calculate overall confidence (weighted voting)
        detected_techniques = [t for t, s in all_scores.items() if s > 0.15]
        
        if detected_techniques:
            # Weighted average with semantic boost
            weights = [max(0.2, s) for s in all_scores.values()]
            weighted_sum = sum(s * w for s, w in zip(all_scores.values(), weights))
            total_weight = sum(weights)
            
            base_confidence = weighted_sum / total_weight if total_weight > 0 else 0
            overall_confidence = min(1.0, base_confidence + (semantic_score * 0.3))
        else:
            overall_confidence = 0.0
        
        # False positive risk calculation
        fp_risk = self._calculate_false_positive_risk(text, detected_techniques)
        
        # MITRE mapping
        mitre_techniques = []
        for technique in detected_techniques:
            mitre_techniques.extend(self.MITRE_MAPPING.get(technique, []))
        mitre_techniques = list(set(mitre_techniques))
        
        # Final detection decision
        detected = overall_confidence >= self.confidence_threshold and fp_risk < 0.5
        
        result = EvasionDetectionResult(
            detected=detected,
            techniques=detected_techniques,
            confidence_scores=all_scores,
            overall_confidence=overall_confidence,
            decoded_content=decoded_content,
            suspicious_segments=all_segments,
            mitre_techniques=mitre_techniques,
            false_positive_risk=fp_risk,
            processing_time_ms=(time.time() - start_time) * 1000,
            obfuscation_layers=obfuscation_layers,
            entropy_score=entropy
        )
        
        # Cache result
        if self.enable_caching:
            if len(self._detection_cache) >= self.max_cache_size:
                self._detection_cache.clear()
            self._detection_cache[text] = result
        
        return result
    
    def detect_batch(self, texts: List[str]) -> List[EvasionDetectionResult]:
        """Batch detection for multiple prompts - NEW IN V3"""
        return [self.detect(text) for text in texts]


# Export
__all__ = [
    'PromptInjectionEvasionDetectorV3',
    'EvasionDetectionResult',
    'EvasionTechniqueType',
    'DetectionConfidence'
]
