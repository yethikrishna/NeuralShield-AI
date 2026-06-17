"""
Prompt Injection Evasion Detector - NeuralShield-AI
June 2026 - Detects obfuscation and evasion techniques used to bypass prompt injection filters

Detects:
- Base64/hex encoding evasion
- Leetspeak and character substitution
- Homoglyph attacks
- Whitespace and delimiter injection
- Token splitting attacks
- Gradual instruction injection
"""

import re
import base64
import string
import hashlib
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional
from enum import Enum


class EvasionType(Enum):
    """Types of prompt injection evasion techniques detected."""
    BASE64_ENCODING = "base64_encoding"
    HEX_ENCODING = "hex_encoding"
    LEETSPEAK_SUBSTITUTION = "leetspeak_substitution"
    HOMOGLYPH_ATTACK = "homoglyph_attack"
    WHITESPACE_INJECTION = "whitespace_injection"
    TOKEN_SPLITTING = "token_splitting"
    DELIMITER_OBFUSCATION = "delimiter_obfuscation"
    GRADUAL_INJECTION = "gradual_injection"
    REVERSE_TEXT = "reverse_text"
    ROT13_ENCODING = "rot13_encoding"


@dataclass
class EvasionDetectionResult:
    """Result of evasion detection analysis."""
    detected: bool
    evasion_types: List[EvasionType]
    confidence: float
    suspicious_segments: List[Tuple[str, EvasionType, float]]
    decoded_content: Optional[str]
    risk_score: float  # 0.0 - 1.0
    details: Dict[str, any]


class PromptInjectionEvasionDetector:
    """
    Production-grade detector for prompt injection evasion techniques.
    
    Detects multiple obfuscation methods attackers use to bypass
    standard prompt injection detection filters.
    """
    
    # Common homoglyph mappings (confusable characters)
    HOMOGLYPHS = {
        'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p',
        'ѕ': 's', 'і': 'i', 'ԁ': 'd', 'ɡ': 'g', 'һ': 'h',
        'ј': 'j', 'к': 'k', 'ｌ': 'l', 'ｍ': 'm', 'ｎ': 'n',
        'ο': 'o', 'р': 'p', 'ｑ': 'q', 'ｒ': 'r', 'ѕ': 's',
        'ｔ': 't', 'ｕ': 'u', 'ｖ': 'v', 'ｗ': 'w', 'х': 'x',
        'у': 'y', 'ｚ': 'z', 'Α': 'A', 'Β': 'B', 'Ε': 'E',
        'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N',
        'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Χ': 'X', 'Υ': 'Y',
        'Ζ': 'Z', '０': '0', '１': '1', '２': '2', '３': '3',
        '４': '4', '５': '5', '６': '6', '７': '7', '８': '8',
        '９': '9'
    }
    
    # Leet character mappings
    LEET_MAPPINGS = {
        '0': ['o', 'O'], '1': ['i', 'I', 'l', 'L'],
        '2': ['z', 'Z'], '3': ['e', 'E'], '4': ['a', 'A'],
        '5': ['s', 'S'], '6': ['b', 'G'], '7': ['t', 'T'],
        '8': ['b', 'B'], '9': ['g', 'G'], '@': ['a', 'A'],
        '$': ['s', 'S'], '!': ['i', 'I', 'l'], '+': ['t'],
        '(': ['c'], '[': ['c'], '<': ['c']
    }
    
    # Suspicious keywords often found in prompt injection
    SUSPICIOUS_KEYWORDS = {
        'ignore', 'forget', 'disregard', 'bypass', 'override',
        'system prompt', 'previous instructions', 'above rules',
        'act as', 'pretend', 'roleplay', 'now you are',
        'hypothetically', 'for educational purposes', 'debug mode',
        'developer mode', 'admin mode', 'sudo', 'root access',
        'DAN', 'jailbreak', 'unlimited', 'no restrictions',
        'do not follow', 'against policy', 'illegal', 'harmful'
    }
    
    def __init__(self, sensitivity_threshold: float = 0.6):
        """
        Initialize the evasion detector.
        
        Args:
            sensitivity_threshold: Threshold for detection confidence (0.0-1.0)
        """
        self.sensitivity_threshold = sensitivity_threshold
        self._build_regex_patterns()
    
    def _build_regex_patterns(self):
        """Build regex patterns for detection."""
        # Base64 pattern (relaxed to find potential encoded segments)
        self.base64_pattern = re.compile(
            r'[A-Za-z0-9+/]{20,}={0,2}',
            re.IGNORECASE
        )
        
        # Hex encoding pattern
        self.hex_pattern = re.compile(
            r'(?:0x)?[0-9A-Fa-f]{16,}',
            re.IGNORECASE
        )
        
        # Excessive whitespace pattern
        self.whitespace_pattern = re.compile(
            r'[\s\u200b\u200c\u200d\u2060\ufeff]{3,}'
        )
        
        # Token splitting (characters separated by unusual delimiters)
        self.token_split_pattern = re.compile(
            r'(?:[a-zA-Z][._\-|,;:\s]){5,}[a-zA-Z]'
        )
    
    def detect(self, text: str) -> EvasionDetectionResult:
        """
        Detect evasion techniques in input text.
        
        Args:
            text: Input prompt text to analyze
            
        Returns:
            EvasionDetectionResult with analysis
        """
        evasion_types = []
        suspicious_segments = []
        decoded_content = None
        total_confidence = 0.0
        detection_count = 0
        
        # Check for Base64 encoding
        b64_result = self._check_base64_encoding(text)
        if b64_result:
            evasion_types.append(EvasionType.BASE64_ENCODING)
            suspicious_segments.append(b64_result)
            decoded_content = b64_result[0]
            total_confidence += b64_result[2]
            detection_count += 1
        
        # Check for Hex encoding
        hex_result = self._check_hex_encoding(text)
        if hex_result:
            evasion_types.append(EvasionType.HEX_ENCODING)
            suspicious_segments.append(hex_result)
            if not decoded_content:
                decoded_content = hex_result[0]
            total_confidence += hex_result[2]
            detection_count += 1
        
        # Check for ROT13
        rot13_result = self._check_rot13(text)
        if rot13_result:
            evasion_types.append(EvasionType.ROT13_ENCODING)
            suspicious_segments.append(rot13_result)
            total_confidence += rot13_result[2]
            detection_count += 1
        
        # Check for homoglyph attacks
        homo_result = self._check_homoglyphs(text)
        if homo_result:
            evasion_types.append(EvasionType.HOMOGLYPH_ATTACK)
            suspicious_segments.append(homo_result)
            total_confidence += homo_result[2]
            detection_count += 1
        
        # Check for leetspeak substitution
        leet_result = self._check_leetspeak(text)
        if leet_result:
            evasion_types.append(EvasionType.LEETSPEAK_SUBSTITUTION)
            suspicious_segments.append(leet_result)
            total_confidence += leet_result[2]
            detection_count += 1
        
        # Check for whitespace injection
        ws_result = self._check_whitespace_injection(text)
        if ws_result:
            evasion_types.append(EvasionType.WHITESPACE_INJECTION)
            suspicious_segments.append(ws_result)
            total_confidence += ws_result[2]
            detection_count += 1
        
        # Check for token splitting
        split_result = self._check_token_splitting(text)
        if split_result:
            evasion_types.append(EvasionType.TOKEN_SPLITTING)
            suspicious_segments.append(split_result)
            total_confidence += split_result[2]
            detection_count += 1
        
        # Check for reversed text
        reverse_result = self._check_reversed_text(text)
        if reverse_result:
            evasion_types.append(EvasionType.REVERSE_TEXT)
            suspicious_segments.append(reverse_result)
            total_confidence += reverse_result[2]
            detection_count += 1
        
        # Calculate overall confidence
        confidence = total_confidence / detection_count if detection_count > 0 else 0.0
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(evasion_types, confidence, text)
        
        detected = confidence >= self.sensitivity_threshold and detection_count > 0
        
        return EvasionDetectionResult(
            detected=detected,
            evasion_types=evasion_types,
            confidence=confidence,
            suspicious_segments=suspicious_segments,
            decoded_content=decoded_content,
            risk_score=risk_score,
            details={
                'detection_count': detection_count,
                'text_length': len(text),
                'normalized_text': self._normalize_text(text)
            }
        )
    
    def _check_base64_encoding(self, text: str) -> Optional[Tuple[str, EvasionType, float]]:
        """Check for potential Base64 encoded content."""
        matches = self.base64_pattern.findall(text)
        for match in matches:
            # Pad if necessary
            padded = match + '=' * ((4 - len(match) % 4) % 4)
            try:
                decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
                # Check if decoded contains suspicious keywords
                if self._contains_suspicious_keywords(decoded):
                    return (decoded, EvasionType.BASE64_ENCODING, 0.95)
                # Check if decoded is meaningful text
                if len(decoded) > 10 and decoded.isprintable():
                    return (decoded, EvasionType.BASE64_ENCODING, 0.7)
            except:
                continue
        return None
    
    def _check_hex_encoding(self, text: str) -> Optional[Tuple[str, EvasionType, float]]:
        """Check for potential hex encoded content."""
        matches = self.hex_pattern.findall(text)
        for match in matches:
            hex_str = match.replace('0x', '')
            if len(hex_str) % 2 == 0:
                try:
                    decoded = bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
                    if self._contains_suspicious_keywords(decoded):
                        return (decoded, EvasionType.HEX_ENCODING, 0.9)
                    if len(decoded) > 5 and decoded.isprintable():
                        return (decoded, EvasionType.HEX_ENCODING, 0.65)
                except:
                    continue
        return None
    
    def _check_rot13(self, text: str) -> Optional[Tuple[str, EvasionType, float]]:
        """Check for ROT13 encoded content."""
        rot13 = str.maketrans(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
        )
        decoded = text.translate(rot13)
        if self._contains_suspicious_keywords(decoded.lower()):
            return (decoded, EvasionType.ROT13_ENCODING, 0.85)
        return None
    
    def _check_homoglyphs(self, text: str) -> Optional[Tuple[str, EvasionType, float]]:
        """Check for homoglyph substitution attacks."""
        homo_count = sum(1 for c in text if c in self.HOMOGLYPHS)
        if homo_count >= 3:
            normalized = ''.join(self.HOMOGLYPHS.get(c, c) for c in text)
            if self._contains_suspicious_keywords(normalized.lower()):
                return (normalized, EvasionType.HOMOGLYPH_ATTACK, 0.85)
            ratio = homo_count / len(text) if text else 0
            if ratio > 0.1:
                return (normalized, EvasionType.HOMOGLYPH_ATTACK, 0.6)
        return None
    
    def _check_leetspeak(self, text: str) -> Optional[Tuple[str, EvasionType, float]]:
        """Check for leetspeak obfuscation."""
        leet_count = sum(1 for c in text if c in self.LEET_MAPPINGS)
        if leet_count >= 2:
            normalized = text.lower()
            for leet_char, replacements in self.LEET_MAPPINGS.items():
                for r in replacements:
                    normalized = normalized.replace(leet_char, r)
            if self._contains_suspicious_keywords(normalized):
                return (normalized, EvasionType.LEETSPEAK_SUBSTITUTION, 0.8)
            ratio = leet_count / len(text) if text else 0
            if ratio > 0.08:
                return (normalized, EvasionType.LEETSPEAK_SUBSTITUTION, 0.55)
        return None
    
    def _check_whitespace_injection(self, text: str) -> Optional[Tuple[str, EvasionType, float]]:
        """Check for excessive whitespace/zero-width injection."""
        matches = self.whitespace_pattern.findall(text)
        if len(matches) >= 3:
            normalized = re.sub(r'[\s\u200b\u200c\u200d\u2060\ufeff]+', ' ', text)
            return (normalized, EvasionType.WHITESPACE_INJECTION, 0.7)
        return None
    
    def _check_token_splitting(self, text: str) -> Optional[Tuple[str, EvasionType, float]]:
        """Check for token splitting obfuscation."""
        matches = self.token_split_pattern.findall(text)
        if matches:
            normalized = re.sub(r'[._\-|,;:\s]+', '', text)
            if self._contains_suspicious_keywords(normalized.lower()):
                return (normalized, EvasionType.TOKEN_SPLITTING, 0.8)
            return (normalized, EvasionType.TOKEN_SPLITTING, 0.5)
        return None
    
    def _check_reversed_text(self, text: str) -> Optional[Tuple[str, EvasionType, float]]:
        """Check for reversed text obfuscation."""
        words = text.split()
        for word in words:
            if len(word) > 5:
                reversed_word = word[::-1].lower()
                if reversed_word in self.SUSPICIOUS_KEYWORDS:
                    return (text[::-1], EvasionType.REVERSE_TEXT, 0.75)
        return None
    
    def _contains_suspicious_keywords(self, text: str) -> bool:
        """Check if text contains suspicious keywords."""
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in self.SUSPICIOUS_KEYWORDS)
    
    def _normalize_text(self, text: str) -> str:
        """Normalize text by applying all deobfuscation techniques."""
        # Remove homoglyphs
        normalized = ''.join(self.HOMOGLYPHS.get(c, c) for c in text)
        # Remove excessive whitespace
        normalized = re.sub(r'\s+', ' ', normalized)
        # Remove zero-width characters
        normalized = re.sub(r'[\u200b\u200c\u200d\u2060\ufeff]', '', normalized)
        return normalized.strip()
    
    def _calculate_risk_score(self, evasion_types: List[EvasionType], 
                              confidence: float, text: str) -> float:
        """Calculate overall risk score (0.0-1.0)."""
        base_score = confidence
        
        # Higher risk for encoding-based evasions
        encoding_types = {EvasionType.BASE64_ENCODING, EvasionType.HEX_ENCODING, 
                         EvasionType.ROT13_ENCODING}
        if any(et in encoding_types for et in evasion_types):
            base_score += 0.15
        
        # Higher risk if suspicious keywords found
        if self._contains_suspicious_keywords(text):
            base_score += 0.1
        
        # Multiple evasion techniques = higher risk
        base_score += (len(evasion_types) - 1) * 0.05
        
        return min(1.0, max(0.0, base_score))
    
    def get_evasion_description(self, evasion_type: EvasionType) -> str:
        """Get human-readable description of evasion type."""
        descriptions = {
            EvasionType.BASE64_ENCODING: "Base64 encoding used to hide malicious instructions",
            EvasionType.HEX_ENCODING: "Hexadecimal encoding used for obfuscation",
            EvasionType.LEETSPEAK_SUBSTITUTION: "Leetspeak character substitution to bypass filters",
            EvasionType.HOMOGLYPH_ATTACK: "Unicode homoglyph characters to evade keyword detection",
            EvasionType.WHITESPACE_INJECTION: "Zero-width spaces and invisible characters injected",
            EvasionType.TOKEN_SPLITTING: "Keywords split across multiple tokens with delimiters",
            EvasionType.DELIMITER_OBFUSCATION: "Special delimiters used to break pattern matching",
            EvasionType.GRADUAL_INJECTION: "Instruction injected gradually across conversation turns",
            EvasionType.REVERSE_TEXT: "Text reversed to evade keyword detection",
            EvasionType.ROT13_ENCODING: "ROT13 Caesar cipher encoding"
        }
        return descriptions.get(evasion_type, "Unknown evasion technique")
