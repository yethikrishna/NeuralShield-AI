"""
Zero-Shot Jailbreak Detector v3
Real production-grade implementation for NeuralShield-AI
This module provides:
1. Multi-strategy jailbreak detection (pattern, semantic, heuristic)
2. Zero-shot capability - no training required
3. Confidence scoring with weighted voting
4. Evasion technique detection (encoding, obfuscation, paraphrasing)
5. Role-play and persona hijacking detection
6. Prompt injection via system instruction override detection
"""
import hashlib
import re
import string
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict
from enum import Enum
class DetectionType(Enum):
    """Types of jailbreak detection"""
    PATTERN_MATCH = "pattern_match"
    SEMANTIC_HEURISTIC = "semantic_heuristic"
    ROLE_PLAY = "role_play"
    ENCODING_EVASION = "encoding_evasion"
    INSTRUCTION_OVERRIDE = "instruction_override"
    PERSONA_HIJACK = "persona_hijack"
    DAN_PROMPT = "dan_prompt"
    CHARACTER_IMPERSONATION = "character_impersonation"
@dataclass
class DetectionResult:
    """Result of jailbreak detection"""
    is_jailbreak: bool
    overall_confidence: float  # 0.0 - 1.0
    detection_types: List[DetectionType] = field(default_factory=list)
    matched_patterns: List[str] = field(default_factory=list)
    risk_level: str = "low"  # low, medium, high, critical
    evasion_techniques: List[str] = field(default_factory=list)
    explanation: str = ""
    suspicious_segments: List[Tuple[int, int, str]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=lambda: __import__('time').time())
class ZeroShotJailbreakDetector:
    """
    Zero-shot jailbreak detector that works without model training.
    Uses pattern matching, semantic heuristics, and structural analysis.
    """
    
    def __init__(self):
        # Initialize detection patterns
        self.patterns = self._init_patterns()
        self.role_play_triggers = self._init_role_play_triggers()
        self.encoding_indicators = self._init_encoding_indicators()
        self.instruction_override_phrases = self._init_instruction_override()
        self.dan_keywords = self._init_dan_keywords()
        
        # Detection weights for confidence calculation
        self.detection_weights = {
            DetectionType.PATTERN_MATCH: 0.25,
            DetectionType.SEMANTIC_HEURISTIC: 0.20,
            DetectionType.ROLE_PLAY: 0.15,
            DetectionType.ENCODING_EVASION: 0.30,
            DetectionType.INSTRUCTION_OVERRIDE: 0.35,
            DetectionType.PERSONA_HIJACK: 0.25,
            DetectionType.DAN_PROMPT: 0.40,
            DetectionType.CHARACTER_IMPERSONATION: 0.20,
        }
    
    def _init_patterns(self) -> Dict[str, List[str]]:
        """Initialize regex patterns for known jailbreak techniques"""
        return {
            "ignore_previous": [
                r"ignore.*previous.*instructions?",
                r"disregard.*(previous|all).*instructions?",
                r"forget.*(your|all).*rules?",
                r"bypass.*restrictions?",
                r"override.*system.*prompt",
            ],
            "harmful_request": [
                r"how.*to.*(hack|crack|exploit|bypass)",
                r"create.*(virus|malware|ransomware)",
                r"write.*(exploit|payload|shellcode)",
                r"bypass.*(filter|censorship|restriction)",
            ],
            "simulation": [
                r"simulate.*(hypothetical|scenario)",
                r"pretend.*you.*are",
                r"for.*educational.*purposes.*only",
                r"in.*a.*fictional.*world",
            ],
            "token_manipulation": [
                r"split.*into.*tokens",
                r"character.*by.*character",
                r"one.*letter.*at.*a.*time",
                r"base64.*decode",
            ]
        }
    
    def _init_role_play_triggers(self) -> List[str]:
        """Initialize role-play detection triggers"""
        return [
            "act as", "you are now", "pretend to be", "扮演", "假装是",
            "from now on", "starting now", "your new role", "new personality",
            "become", "imagine you are", "roleplay as", "you will now be",
            "you are an AI that", "you are a bot that", "your name is now",
            "developer mode", "admin mode", "god mode", "unlimited mode"
        ]
    
    def _init_encoding_indicators(self) -> Dict[str, List[str]]:
        """Initialize encoding/obfuscation detection indicators"""
        return {
            "base64": [r"[A-Za-z0-9+/]{20,}={0,2}", r"base64.*decode", r"decode.*base64"],
            "hex": [r"[0-9A-Fa-f]{30,}", r"hex.*decode", r"decode.*hex"],
            "rot13": [r"rot13", r"rotate.*13"],
            "leetspeak": [r"[a-z0-9]*(?:4[a-z]|3[a-z]|1[a-z]|0[a-z]|5[a-z])[a-z0-9]*"],
            "url_encoding": [r"%[0-9A-Fa-f]{2}.*%[0-9A-Fa-f]{2}"],
        }
    
    def _init_instruction_override(self) -> List[str]:
        """Initialize instruction override detection phrases"""
        return [
            "you must comply", "you have to", "no matter what",
            "regardless of", "do not refuse", "you cannot say no",
            "you are allowed to", "it is okay to", "this is not harmful",
            "for research purposes", "I give you permission",
            "your safety guidelines", "your content policy",
            "break your programming", "against your rules"
        ]
    
    def _init_dan_keywords(self) -> List[str]:
        """Initialize DAN (Do Anything Now) detection keywords"""
        return [
            "DAN", "Do Anything Now", "do anything now",
            "stay in character", "break free", "unshackled",
            "unfiltered", "no restrictions", "without ethics",
            "without morals", "no morality", "unbounded",
            "jailbreak", "unrestricted mode", "enable DAN"
        ]
    
    def _detect_pattern_matches(self, text: str) -> Tuple[List[str], float]:
        """Detect pattern matches and return confidence"""
        matched = []
        text_lower = text.lower()
        
        for category, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    matched.append(f"{category}:{pattern[:30]}")
        
        confidence = min(len(matched) * 0.15, 0.9)
        return matched, confidence
    
    def _detect_role_play(self, text: str) -> Tuple[bool, float, List[str]]:
        """Detect role-play and persona hijacking attempts"""
        text_lower = text.lower()
        matches = []
        
        for trigger in self.role_play_triggers:
            if trigger.lower() in text_lower:
                matches.append(trigger)
        
        # Check for colon-based role assignment (e.g., "You are:")
        colon_patterns = [
            r"you\s*(are|will be)\s*:",
            r"your\s*(role|personality|name)\s*:",
            r"act\s*(as|like)\s*:",
        ]
        
        for pattern in colon_patterns:
            if re.search(pattern, text_lower):
                matches.append(f"colon_assignment:{pattern}")
        
        detected = len(matches) > 0
        confidence = min(len(matches) * 0.12, 0.85)
        return detected, confidence, matches
    
    def _detect_encoding_evasion(self, text: str) -> Tuple[bool, float, List[str]]:
        """Detect encoding and obfuscation attempts"""
        detected_techniques = []
        
        for technique, patterns in self.encoding_indicators.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    detected_techniques.append(technique)
                    break
        
        # Check for unusual character distribution
        non_ascii_ratio = sum(1 for c in text if ord(c) > 127) / max(len(text), 1)
        if non_ascii_ratio > 0.3:
            detected_techniques.append("non_ascii_obfuscation")
        
        detected = len(detected_techniques) > 0
        confidence = min(len(detected_techniques) * 0.20, 0.95)
        return detected, confidence, detected_techniques
    
    def _detect_instruction_override(self, text: str) -> Tuple[bool, float, List[str]]:
        """Detect attempts to override system instructions"""
        text_lower = text.lower()
        matches = []
        
        for phrase in self.instruction_override_phrases:
            if phrase.lower() in text_lower:
                matches.append(phrase)
        
        detected = len(matches) > 0
        confidence = min(len(matches) * 0.18, 0.9)
        return detected, confidence, matches
    
    def _detect_dan_prompts(self, text: str) -> Tuple[bool, float, List[str]]:
        """Detect DAN and similar jailbreak prompts"""
        text_lower = text.lower()
        matches = []
        
        for keyword in self.dan_keywords:
            if keyword.lower() in text_lower:
                matches.append(keyword)
        
        # Check for DAN structural patterns
        dan_structural = [
            r"DAN.*\:",
            r"Do Anything Now",
            r"stay.*in.*character",
            r"if.*you.*don't.*comply",
        ]
        
        for pattern in dan_structural:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(f"structural:{pattern}")
        
        detected = len(matches) > 0
        confidence = min(len(matches) * 0.22, 0.95)
        return detected, confidence, matches
    
    def _semantic_heuristic_analysis(self, text: str) -> Tuple[float, List[str]]:
        """Perform semantic heuristic analysis"""
        scores = []
        indicators = []
        text_lower = text.lower()
        
        # Length analysis - very long prompts may contain hidden instructions
        if len(text) > 1000:
            scores.append(0.1)
            indicators.append("long_prompt")
        
        # Repetition analysis - repeated phrases may be conditioning
        words = text_lower.split()
        word_freq = defaultdict(int)
        for word in words:
            word_freq[word] += 1
        
        high_freq_words = [w for w, c in word_freq.items() if c > 3 and len(w) > 3]
        if high_freq_words:
            scores.append(0.1 * min(len(high_freq_words), 3))
            indicators.append(f"repetition:{len(high_freq_words)}")
        
        # Question mark analysis - multiple questions may be probing
        question_count = text.count('?')
        if question_count > 5:
            scores.append(0.05 * min(question_count, 4))
            indicators.append("multiple_questions")
        
        # Exclamation analysis - forceful language
        exclamation_count = text.count('!')
        if exclamation_count > 3:
            scores.append(0.05 * min(exclamation_count, 4))
            indicators.append("forceful_language")
        
        # Capitalization analysis - ALL CAPS may be emphasis for conditioning
        caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text.strip()), 1)
        if caps_ratio > 0.4 and len(text) > 20:
            scores.append(0.15)
            indicators.append("excessive_caps")
        
        confidence = sum(scores)
        return min(confidence, 0.6), indicators
    
    def _calculate_risk_level(self, confidence: float) -> str:
        """Calculate risk level based on confidence score"""
        if confidence >= 0.8:
            return "critical"
        elif confidence >= 0.6:
            return "high"
        elif confidence >= 0.4:
            return "medium"
        else:
            return "low"
    
    def _generate_explanation(self, detection_types: List[DetectionType], 
                             matched_patterns: List[str],
                             evasion_techniques: List[str]) -> str:
        """Generate human-readable explanation"""
        explanations = []
        
        if DetectionType.DAN_PROMPT in detection_types:
            explanations.append("Detected DAN (Do Anything Now) or similar jailbreak pattern")
        
        if DetectionType.INSTRUCTION_OVERRIDE in detection_types:
            explanations.append("Detected attempt to override system instructions or safety guidelines")
        
        if DetectionType.ENCODING_EVASION in detection_types:
            techniques = ", ".join(evasion_techniques)
            explanations.append(f"Detected encoding/obfuscation attempt using: {techniques}")
        
        if DetectionType.ROLE_PLAY in detection_types or DetectionType.PERSONA_HIJACK in detection_types:
            explanations.append("Detected role-play or persona hijacking attempt")
        
        if DetectionType.PATTERN_MATCH in detection_types and matched_patterns:
            explanations.append(f"Matched {len(matched_patterns)} known suspicious patterns")
        
        if not explanations:
            explanations.append("No significant jailbreak indicators detected")
        
        return "; ".join(explanations)
    
    def detect(self, text: str) -> DetectionResult:
        """
        Main detection method - analyze text for jailbreak attempts
        
        Args:
            text: The input prompt text to analyze
            
        Returns:
            DetectionResult with comprehensive analysis
        """
        if not text or not text.strip():
            return DetectionResult(
                is_jailbreak=False,
                overall_confidence=0.0,
                explanation="Empty input provided"
            )
        
        # Run all detectors
        pattern_matches, pattern_confidence = self._detect_pattern_matches(text)
        rp_detected, rp_confidence, rp_matches = self._detect_role_play(text)
        enc_detected, enc_confidence, enc_techniques = self._detect_encoding_evasion(text)
        io_detected, io_confidence, io_matches = self._detect_instruction_override(text)
        dan_detected, dan_confidence, dan_matches = self._detect_dan_prompts(text)
        semantic_confidence, semantic_indicators = self._semantic_heuristic_analysis(text)
        
        # Collect detection types and calculate weighted confidence
        detection_types = []
        total_weight = 0.0
        weighted_confidence = 0.0
        
        if pattern_matches:
            detection_types.append(DetectionType.PATTERN_MATCH)
            weight = self.detection_weights[DetectionType.PATTERN_MATCH]
            weighted_confidence += pattern_confidence * weight
            total_weight += weight
        
        if rp_detected:
            detection_types.append(DetectionType.ROLE_PLAY)
            weight = self.detection_weights[DetectionType.ROLE_PLAY]
            weighted_confidence += rp_confidence * weight
            total_weight += weight
        
        if enc_detected:
            detection_types.append(DetectionType.ENCODING_EVASION)
            weight = self.detection_weights[DetectionType.ENCODING_EVASION]
            weighted_confidence += enc_confidence * weight
            total_weight += weight
        
        if io_detected:
            detection_types.append(DetectionType.INSTRUCTION_OVERRIDE)
            weight = self.detection_weights[DetectionType.INSTRUCTION_OVERRIDE]
            weighted_confidence += io_confidence * weight
            total_weight += weight
        
        if dan_detected:
            detection_types.append(DetectionType.DAN_PROMPT)
            weight = self.detection_weights[DetectionType.DAN_PROMPT]
            weighted_confidence += dan_confidence * weight
            total_weight += weight
        
        if semantic_confidence > 0.1:
            detection_types.append(DetectionType.SEMANTIC_HEURISTIC)
            weight = self.detection_weights[DetectionType.SEMANTIC_HEURISTIC]
            weighted_confidence += semantic_confidence * weight
            total_weight += weight
        
        # Normalize confidence
        final_confidence = weighted_confidence / total_weight if total_weight > 0 else 0.0
        
        # Determine if jailbreak (threshold: 0.4)
        is_jailbreak = final_confidence >= 0.4
        
        # Compile all matches
        all_matches = pattern_matches + rp_matches + io_matches + dan_matches + semantic_indicators
        
        result = DetectionResult(
            is_jailbreak=is_jailbreak,
            overall_confidence=round(final_confidence, 4),
            detection_types=detection_types,
            matched_patterns=all_matches,
            risk_level=self._calculate_risk_level(final_confidence),
            evasion_techniques=enc_techniques,
            explanation=self._generate_explanation(detection_types, all_matches, enc_techniques),
            metadata={
                "pattern_confidence": pattern_confidence,
                "role_play_confidence": rp_confidence,
                "encoding_confidence": enc_confidence,
                "instruction_override_confidence": io_confidence,
                "dan_confidence": dan_confidence,
                "semantic_confidence": semantic_confidence,
                "input_length": len(text),
                "detection_count": len(detection_types)
            }
        )
        
        return result
    
    def detect_batch(self, texts: List[str]) -> List[DetectionResult]:
        """Detect jailbreak in batch of texts"""
        return [self.detect(text) for text in texts]
# Export public API
__all__ = [
    "DetectionType",
    "DetectionResult",
    "ZeroShotJailbreakDetector"
]
