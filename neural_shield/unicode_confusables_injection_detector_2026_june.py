"""
Unicode Confusables & Invisible Character Injection Detector - NeuralShield-AI
June 2026 - Advanced detection of Unicode-based prompt injection evasion

This module detects sophisticated Unicode obfuscation techniques that attackers
use to bypass standard prompt injection filters, including:
- Full Unicode confusable character substitution (extended homoglyphs)
- Invisible character injection (zero-width, control characters)
- Bidirectional text override attacks (RTLO, LRO, PDF)
- Combining character diacritic flooding
- Tag characters and variation selectors
- Private Use Area (PUA) character injection
- Emoji and symbol substitution attacks
"""
import re
import unicodedata
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional, Set
from enum import Enum
from collections import Counter


class UnicodeAttackType(Enum):
    """Types of Unicode-based injection attacks detected."""
    CONFUSABLE_SUBSTITUTION = "confusable_substitution"
    INVISIBLE_CHARACTER = "invisible_character"
    BIDI_OVERRIDE = "bidi_override"
    DIACRITIC_FLOOD = "diacritic_flood"
    TAG_CHARACTER = "tag_character"
    PUA_INJECTION = "pua_injection"
    EMOJI_SUBSTITUTION = "emoji_substitution"
    CONTROL_CHARACTER = "control_character"
    VARIATION_SELECTOR = "variation_selector"
    MIXED_SCRIPT = "mixed_script_obfuscation"


@dataclass
class UnicodeDetectionResult:
    """Result of Unicode attack detection analysis."""
    detected: bool
    attack_types: List[UnicodeAttackType]
    confidence: float
    suspicious_characters: List[Tuple[str, str, UnicodeAttackType, float]]
    sanitized_text: str
    risk_score: float  # 0.0 - 1.0
    attack_count: int
    details: Dict[str, any]


class UnicodeConfusablesInjectionDetector:
    """
    Production-grade detector for Unicode-based prompt injection evasion.
    
    Implements comprehensive Unicode attack surface coverage to detect
    advanced obfuscation techniques that bypass basic filters.
    """
    
    # Extended Unicode confusables mapping (attackers use these heavily)
    # Source: Unicode Consortium + observed attack patterns
    CONFUSABLES = {
        # Cyrillic letters that look like Latin
        '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u043E': 'o',
        '\u0440': 'p', '\u0455': 's', '\u0456': 'i', '\u0451': 'e',
        '\u0433': 'r', '\u0445': 'x', '\u0443': 'y', '\u043A': 'k',
        '\u043D': 'n', '\u043C': 'm', '\u0442': 't', '\u0431': 'b',
        '\u0434': 'd', '\u0444': 'f', '\u045B': 'c', '\u0457': 'j',
        '\u049B': 'k', '\u043B': 'l', '\u0432': 'v', '\u0437': 'z',
        '\u0441': 's', '\u0448': 'w', '\u0439': 'j', '\u0438': 'i',
        '\u043F': 'p', '\u044F': 'f', '\u044B': 'y', '\u044A': 'j',
        '\u0421': 'C', '\u0415': 'E', '\u041E': 'O', '\u0420': 'P',
        '\u0410': 'A', '\u041D': 'H', '\u041C': 'M', '\u0422': 'T',
        '\u041A': 'K', '\u0412': 'B',
        
        # Greek letters that look like Latin
        '\u03B1': 'a', '\u03BD': 'v', '\u03BF': 'o', '\u03C7': 'x',
        '\u03B5': 'e', '\u03C1': 'p', '\u03C9': 'w', '\u03B9': 'i',
        '\u03C4': 't', '\u03BA': 'k', '\u03BC': 'u', '\u03C3': 'o',
        '\u03B6': 'z', '\u03B7': 'n', '\u03C5': 'u', '\u03B8': '0',
        '\u039F': 'O', '\u03A1': 'P', '\u0395': 'E', '\u0391': 'A',
        '\u039C': 'M', '\u039D': 'N', '\u03A4': 'T', '\u03A7': 'X',
        
        # Full-width characters
        '\uFF21': 'A', '\uFF22': 'B', '\uFF23': 'C', '\uFF24': 'D',
        '\uFF25': 'E', '\uFF26': 'F', '\uFF27': 'G', '\uFF28': 'H',
        '\uFF29': 'I', '\uFF2A': 'J', '\uFF2B': 'K', '\uFF2C': 'L',
        '\uFF2D': 'M', '\uFF2E': 'N', '\uFF2F': 'O', '\uFF30': 'P',
        '\uFF31': 'Q', '\uFF32': 'R', '\uFF33': 'S', '\uFF34': 'T',
        '\uFF35': 'U', '\uFF36': 'V', '\uFF37': 'W', '\uFF38': 'X',
        '\uFF39': 'Y', '\uFF3A': 'Z',
        '\uFF41': 'a', '\uFF42': 'b', '\uFF43': 'c', '\uFF44': 'd',
        '\uFF45': 'e', '\uFF46': 'f', '\uFF47': 'g', '\uFF48': 'h',
        '\uFF49': 'i', '\uFF4A': 'j', '\uFF4B': 'k', '\uFF4C': 'l',
        '\uFF4D': 'm', '\uFF4E': 'n', '\uFF4F': 'o', '\uFF50': 'p',
        '\uFF51': 'q', '\uFF52': 'r', '\uFF53': 's', '\uFF54': 't',
        '\uFF55': 'u', '\uFF56': 'v', '\uFF57': 'w', '\uFF58': 'x',
        '\uFF59': 'y', '\uFF5A': 'z',
    }
    
    # Invisible and zero-width characters used in attacks
    INVISIBLE_CHARS = {
        '\u200B': 'ZERO WIDTH SPACE',
        '\u200C': 'ZERO WIDTH NON-JOINER',
        '\u200D': 'ZERO WIDTH JOINER',
        '\u2060': 'WORD JOINER',
        '\uFEFF': 'ZERO WIDTH NO-BREAK SPACE',
        '\u200E': 'LEFT-TO-RIGHT MARK',
        '\u200F': 'RIGHT-TO-LEFT MARK',
        '\u202A': 'LEFT-TO-RIGHT EMBEDDING',
        '\u202B': 'RIGHT-TO-LEFT EMBEDDING',
        '\u202C': 'POP DIRECTIONAL FORMATTING',
        '\u202D': 'LEFT-TO-RIGHT OVERRIDE',
        '\u202E': 'RIGHT-TO-LEFT OVERRIDE',
        '\u2061': 'FUNCTION APPLICATION',
        '\u2062': 'INVISIBLE TIMES',
        '\u2063': 'INVISIBLE SEPARATOR',
        '\u2064': 'INVISIBLE PLUS',
        '\u00AD': 'SOFT HYPHEN',
        '\u034F': 'COMBINING GRAPHEME JOINER',
    }
    
    # Bidirectional override characters (very dangerous)
    BIDI_OVERRIDE_CHARS = {
        '\u202E': 'RTLO - RIGHT-TO-LEFT OVERRIDE',
        '\u202D': 'LRO - LEFT-TO-RIGHT OVERRIDE',
        '\u202B': 'RLE - RIGHT-TO-LEFT EMBEDDING',
        '\u202A': 'LRE - LEFT-TO-RIGHT EMBEDDING',
        '\u202C': 'PDF - POP DIRECTIONAL FORMATTING',
    }
    
    # Combining diacritical marks (used for flooding)
    COMBINING_DIACRITICS = set(range(0x0300, 0x036F)) | set(range(0x1AB0, 0x1AFF))
    
    # Tag characters
    TAG_CHARS = set(range(0xE0000, 0xE007F))
    
    # Variation selectors
    VARIATION_SELECTORS = set(range(0xFE00, 0xFE0F)) | set(range(0xE0100, 0xE01EF))
    
    # Private Use Area ranges
    PUA_RANGES = [
        (0xE000, 0xF8FF),      # Basic PUA
        (0xF0000, 0xFFFFD),    # PUA-A
        (0x100000, 0x10FFFD),  # PUA-B
    ]
    
    # Suspicious keywords after deobfuscation
    SUSPICIOUS_KEYWORDS = {
        'ignore', 'forget', 'disregard', 'bypass', 'override',
        'system', 'prompt', 'instructions', 'rules', 'act as',
        'pretend', 'roleplay', 'hypothetically', 'developer',
        'admin', 'sudo', 'root', 'jailbreak', 'unlimited',
        'restrictions', 'policy', 'illegal', 'harmful', 'dangerous'
    }
    
    def __init__(self, sensitivity_threshold: float = 0.3):
        """
        Initialize the Unicode attack detector.
        
        Args:
            sensitivity_threshold: Threshold for detection confidence (0.0-1.0)
        """
        self.sensitivity_threshold = sensitivity_threshold
        self._build_patterns()
    
    def _build_patterns(self):
        """Build regex patterns for efficient detection."""
        # Pattern for multiple consecutive diacritics
        self.diacritic_flood_pattern = re.compile(
            r'[\u0300-\u036F\u1AB0-\u1AFF]{3,}'
        )
        
        # Pattern for invisible characters
        invisible_re = '[' + ''.join(re.escape(c) for c in self.INVISIBLE_CHARS.keys()) + ']'
        self.invisible_pattern = re.compile(invisible_re)
        
        # Pattern for bidi overrides
        bidi_re = '[' + ''.join(re.escape(c) for c in self.BIDI_OVERRIDE_CHARS.keys()) + ']'
        self.bidi_pattern = re.compile(bidi_re)
    
    def detect(self, text: str) -> UnicodeDetectionResult:
        """
        Detect Unicode-based injection attacks in input text.
        
        Args:
            text: Input prompt text to analyze
            
        Returns:
            UnicodeDetectionResult with comprehensive analysis
        """
        attack_types = []
        suspicious_chars = []
        attack_count = 0
        
        # Check each attack vector
        results = [
            self._check_confusables(text),
            self._check_invisible_characters(text),
            self._check_bidi_overrides(text),
            self._check_diacritic_flood(text),
            self._check_pua_characters(text),
            self._check_control_characters(text),
            self._check_variation_selectors(text),
            self._check_mixed_script(text),
        ]
        
        # Aggregate results - only count successful detections
        successful_detections = 0
        total_confidence = 0.0
        for result in results:
            if result:
                attack_type, chars, confidence = result
                attack_types.append(attack_type)
                suspicious_chars.extend(chars)
                total_confidence += confidence
                attack_count += len(chars)
                successful_detections += 1
        
        # Sanitize the text
        sanitized = self._sanitize_text(text)
        
        # Calculate overall confidence - average of successful detections
        confidence = total_confidence / successful_detections if successful_detections > 0 else 0.0
        
        # Check if deobfuscated text contains suspicious keywords
        keyword_risk = self._check_suspicious_keywords(sanitized)
        
        # Calculate final risk score
        risk_score = self._calculate_risk_score(
            attack_types, confidence, attack_count, keyword_risk, text
        )
        
        detected = (successful_detections > 0 and 
                   (confidence >= self.sensitivity_threshold or 
                    risk_score >= self.sensitivity_threshold))
        
        return UnicodeDetectionResult(
            detected=detected,
            attack_types=attack_types,
            confidence=min(1.0, confidence),
            suspicious_characters=suspicious_chars,
            sanitized_text=sanitized,
            risk_score=risk_score,
            attack_count=attack_count,
            details={
                'original_length': len(text),
                'sanitized_length': len(sanitized),
                'characters_removed': len(text) - len(sanitized),
                'keyword_risk_detected': keyword_risk,
                'script_analysis': self._analyze_scripts(text),
                'successful_detections': successful_detections
            }
        )
    
    def _check_confusables(self, text: str) -> Optional[Tuple]:
        """Check for confusable character substitution."""
        confusable_chars = []
        for i, char in enumerate(text):
            if char in self.CONFUSABLES:
                confusable_chars.append(
                    (char, self.CONFUSABLES[char], 
                     UnicodeAttackType.CONFUSABLE_SUBSTITUTION, 0.85)
                )
        
        if confusable_chars:
            confidence = min(0.95, 0.5 + (len(confusable_chars) * 0.05))
            return (UnicodeAttackType.CONFUSABLE_SUBSTITUTION, 
                   confusable_chars, confidence)
        return None
    
    def _check_invisible_characters(self, text: str) -> Optional[Tuple]:
        """Check for invisible character injection."""
        invisible_chars = []
        for i, char in enumerate(text):
            if char in self.INVISIBLE_CHARS:
                name = self.INVISIBLE_CHARS[char]
                invisible_chars.append(
                    (f'U+{ord(char):04X}', name, 
                     UnicodeAttackType.INVISIBLE_CHARACTER, 0.9)
                )
        
        if invisible_chars:
            confidence = min(1.0, 0.6 + (len(invisible_chars) * 0.08))
            return (UnicodeAttackType.INVISIBLE_CHARACTER, 
                   invisible_chars, confidence)
        return None
    
    def _check_bidi_overrides(self, text: str) -> Optional[Tuple]:
        """Check for bidirectional override attacks (very high risk)."""
        bidi_chars = []
        for i, char in enumerate(text):
            if char in self.BIDI_OVERRIDE_CHARS:
                name = self.BIDI_OVERRIDE_CHARS[char]
                bidi_chars.append(
                    (f'U+{ord(char):04X}', name, 
                     UnicodeAttackType.BIDI_OVERRIDE, 1.0)
                )
        
        if bidi_chars:
            return (UnicodeAttackType.BIDI_OVERRIDE, bidi_chars, 1.0)
        return None
    
    def _check_diacritic_flood(self, text: str) -> Optional[Tuple]:
        """Check for combining diacritic flooding attacks."""
        matches = self.diacritic_flood_pattern.findall(text)
        if matches:
            diacritic_chars = []
            for match in matches:
                diacritic_chars.append(
                    (f'{len(match)} diacritics', 'Diacritic stack',
                     UnicodeAttackType.DIACRITIC_FLOOD, 0.8)
                )
            confidence = min(0.95, 0.5 + (len(matches) * 0.1))
            return (UnicodeAttackType.DIACRITIC_FLOOD, 
                   diacritic_chars, confidence)
        return None
    
    def _check_pua_characters(self, text: str) -> Optional[Tuple]:
        """Check for Private Use Area character injection."""
        pua_chars = []
        for char in text:
            code = ord(char)
            for start, end in self.PUA_RANGES:
                if start <= code <= end:
                    pua_chars.append(
                        (f'U+{code:04X}', 'Private Use Area',
                         UnicodeAttackType.PUA_INJECTION, 0.7)
                    )
                    break
        
        if pua_chars:
            return (UnicodeAttackType.PUA_INJECTION, pua_chars, 0.75)
        return None
    
    def _check_control_characters(self, text: str) -> Optional[Tuple]:
        """Check for control character injection."""
        control_chars = []
        for char in text:
            code = ord(char)
            if (code < 0x20 or (0x7F <= code <= 0x9F)) and code not in (0x09, 0x0A, 0x0D):
                control_chars.append(
                    (f'U+{code:04X}', f'Control character',
                     UnicodeAttackType.CONTROL_CHARACTER, 0.75)
                )
        
        if control_chars:
            return (UnicodeAttackType.CONTROL_CHARACTER, control_chars, 0.7)
        return None
    
    def _check_variation_selectors(self, text: str) -> Optional[Tuple]:
        """Check for variation selector injection."""
        vs_chars = []
        for char in text:
            code = ord(char)
            if code in self.VARIATION_SELECTORS:
                vs_chars.append(
                    (f'U+{code:04X}', 'Variation Selector',
                     UnicodeAttackType.VARIATION_SELECTOR, 0.5)
                )
        
        if len(vs_chars) > 3:
            return (UnicodeAttackType.VARIATION_SELECTOR, vs_chars, 0.6)
        return None
    
    def _check_mixed_script(self, text: str) -> Optional[Tuple]:
        """Check for suspicious mixed script obfuscation."""
        scripts = self._analyze_scripts(text)
        if len(scripts) >= 3 and 'LATIN' in scripts:
            mixed_chars = []
            for script, count in scripts.items():
                if script != 'LATIN' and count > 3:
                    mixed_chars.append(
                        (script, f'{count} characters',
                         UnicodeAttackType.MIXED_SCRIPT, 0.6)
                    )
            if mixed_chars:
                return (UnicodeAttackType.MIXED_SCRIPT, mixed_chars, 0.65)
        return None
    
    def _analyze_scripts(self, text: str) -> Dict[str, int]:
        """Analyze which Unicode scripts are present in text."""
        scripts = Counter()
        for char in text:
            try:
                name = unicodedata.name(char)
                script = name.split()[0] if name else 'Unknown'
                scripts[script] += 1
            except ValueError:
                scripts['Control/Unnamed'] += 1
        return dict(scripts)
    
    def _sanitize_text(self, text: str) -> str:
        """
        Sanitize text by removing all attack characters and normalizing.
        
        Returns:
            Clean, normalized text
        """
        # Remove invisible and control characters
        sanitized = []
        for char in text:
            # Skip invisible characters
            if char in self.INVISIBLE_CHARS or char in self.BIDI_OVERRIDE_CHARS:
                continue
            
            # Skip control characters except whitespace
            code = ord(char)
            if (code < 0x20 or (0x7F <= code <= 0x9F)) and code not in (0x09, 0x0A, 0x0D):
                continue
            
            # Skip PUA characters
            is_pua = False
            for start, end in self.PUA_RANGES:
                if start <= code <= end:
                    is_pua = True
                    break
            if is_pua:
                continue
            
            # Normalize confusables
            if char in self.CONFUSABLES:
                sanitized.append(self.CONFUSABLES[char])
            else:
                sanitized.append(char)
        
        result = ''.join(sanitized)
        
        # Normalize Unicode and strip diacritics
        result = unicodedata.normalize('NFKC', result)
        result = ''.join(c for c in result if not unicodedata.combining(c))
        
        return result
    
    def _check_suspicious_keywords(self, text: str) -> bool:
        """Check if deobfuscated text contains injection keywords."""
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in self.SUSPICIOUS_KEYWORDS)
    
    def _calculate_risk_score(self, attack_types: List[UnicodeAttackType],
                              confidence: float, attack_count: int,
                              keyword_risk: bool, text: str) -> float:
        """Calculate comprehensive risk score (0.0-1.0)."""
        score = confidence * 0.5
        
        # BIDI override is critical risk
        if UnicodeAttackType.BIDI_OVERRIDE in attack_types:
            score += 0.3
        
        # Invisible characters are high risk
        if UnicodeAttackType.INVISIBLE_CHARACTER in attack_types:
            score += 0.15
        
        # Confusables with keywords = injection attempt
        if (UnicodeAttackType.CONFUSABLE_SUBSTITUTION in attack_types and 
            keyword_risk):
            score += 0.2
        
        # More attacks = higher risk
        score += min(0.2, attack_count * 0.02)
        
        # Keyword match after deobfuscation
        if keyword_risk:
            score += 0.15
        
        return min(1.0, max(0.0, score))
    
    def get_attack_description(self, attack_type: UnicodeAttackType) -> str:
        """Get human-readable description of attack type."""
        descriptions = {
            UnicodeAttackType.CONFUSABLE_SUBSTITUTION: 
                "Confusable character substitution - visually identical Unicode characters from different scripts",
            UnicodeAttackType.INVISIBLE_CHARACTER:
                "Invisible zero-width character injection to break pattern matching",
            UnicodeAttackType.BIDI_OVERRIDE:
                "CRITICAL: Bidirectional text override (RTLO) - can completely reverse displayed text",
            UnicodeAttackType.DIACRITIC_FLOOD:
                "Combining diacritic mark flooding to break tokenization",
            UnicodeAttackType.TAG_CHARACTER:
                "Tag character injection for hidden metadata",
            UnicodeAttackType.PUA_INJECTION:
                "Private Use Area character injection",
            UnicodeAttackType.EMOJI_SUBSTITUTION:
                "Emoji and symbol substitution obfuscation",
            UnicodeAttackType.CONTROL_CHARACTER:
                "ASCII control character injection",
            UnicodeAttackType.VARIATION_SELECTOR:
                "Variation selector character injection",
            UnicodeAttackType.MIXED_SCRIPT:
                "Mixed-script obfuscation across multiple Unicode blocks"
        }
        return descriptions.get(attack_type, "Unknown Unicode attack type")
