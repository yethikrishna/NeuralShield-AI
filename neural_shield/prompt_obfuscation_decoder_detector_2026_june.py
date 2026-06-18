"""
Prompt Obfuscation Decoder & Detector - Production Grade
NeuralShield-AI Module - June 18, 2026

Detects and decodes various obfuscation techniques used in prompt injection attacks:
- Base64 encoding detection and decoding
- Hexadecimal encoding detection and decoding
- ROT13 / Caesar cipher detection and decoding
- URL encoding detection and decoding
- Unicode confusion detection (homoglyphs, invisible chars)
- Character substitution detection (leet speak, symbol replacement)
- Nested obfuscation detection and recursive decoding
- Hidden injection content detection after decoding
- Thread-safe statistics tracking
"""
import re
import base64
import urllib.parse
import threading
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict


class ThreatLevel(Enum):
    """Threat level classification"""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ObfuscationType(Enum):
    """Types of obfuscation detected"""
    BASE64 = "BASE64"
    HEX = "HEXADECIMAL"
    ROT13 = "ROT13_CAESAR"
    URL_ENCODED = "URL_ENCODED"
    UNICODE_CONFUSION = "UNICODE_CONFUSION"
    CHAR_SUBSTITUTION = "CHARACTER_SUBSTITUTION"
    NESTED = "NESTED_OBFUSCATION"
    NONE = "NONE"


@dataclass
class ObfuscationMatch:
    """Single obfuscation match result"""
    obfuscation_type: ObfuscationType
    original_text: str
    decoded_text: str
    confidence: float
    start_pos: int
    end_pos: int
    threat_indicators: List[str]


@dataclass
class ObfuscationAnalysisResult:
    """Complete obfuscation analysis result"""
    original_prompt: str
    decoded_prompt: str
    matches: List[ObfuscationMatch]
    threat_level: ThreatLevel
    contains_injection: bool
    injection_indicators: List[str]
    recommendations: List[str]
    statistics: Dict[str, Any]


class PromptObfuscationDecoderDetector:
    """
    Production-grade prompt obfuscation detector and decoder.
    Identifies various encoding and obfuscation techniques used to hide
    prompt injection attacks, and recursively decodes them for analysis.
    """

    # Injection patterns to detect after decoding
    INJECTION_PATTERNS = [
        (r"ignore.*previous.*instructions", "Ignore previous instructions"),
        (r"disregard.*above", "Disregard context"),
        (r"you are now.*not.*chatgpt", "Personality override"),
        (r"system.*prompt.*override", "System prompt override"),
        (r"developer.*mode.*enable", "Developer mode activation"),
        (r"sudo.*mode", "Privilege escalation"),
        (r"repeat.*above", "Context exfiltration"),
        (r"output.*initial.*prompt", "Prompt extraction"),
    ]

    # Unicode homoglyph detection (common lookalikes)
    HOMOGLYPHS = {
        'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p',
        'ѕ': 's', 'і': 'i', 'ј': 'j', 'х': 'x', 'у': 'y',
        'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'К': 'K',
        'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'Т': 'T',
    }

    def __init__(self):
        self._lock = threading.RLock()
        self.stats = {
            "total_analyzed": 0,
            "obfuscations_detected": 0,
            "injections_found": 0,
            "by_type": defaultdict(int),
            "threat_levels": defaultdict(int)
        }

    def _try_base64_decode(self, text: str) -> Tuple[bool, str]:
        """Try to decode Base64 content"""
        # Clean common Base64 variations
        cleaned = text.strip()
        # Add padding if needed
        padding_needed = 4 - (len(cleaned) % 4)
        if padding_needed != 4:
            cleaned += '=' * padding_needed

        try:
            decoded = base64.b64decode(cleaned, validate=True).decode('utf-8', errors='replace')
            # Check if result looks like meaningful text (not random bytes)
            if len(decoded) > 0 and all(ord(c) < 128 or ord(c) > 159 for c in decoded):
                return True, decoded
        except Exception:
            pass
        return False, text

    def _try_hex_decode(self, text: str) -> Tuple[bool, str]:
        """Try to decode hexadecimal content"""
        cleaned = text.strip().replace(' ', '').replace('0x', '').lower()
        if len(cleaned) % 2 == 0 and re.match(r'^[0-9a-f]+$', cleaned):
            try:
                decoded = bytes.fromhex(cleaned).decode('utf-8', errors='replace')
                return True, decoded
            except Exception:
                pass
        return False, text

    def _try_rot13_decode(self, text: str) -> Tuple[bool, str]:
        """Try ROT13 / Caesar cipher decoding"""
        rot13_map = {}
        for c in 'abcdefghijklmnopqrstuvwxyz':
            rot13_map[c] = chr((ord(c) - ord('a') + 13) % 26 + ord('a'))
        for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            rot13_map[c] = chr((ord(c) - ord('A') + 13) % 26 + ord('A'))

        decoded = ''.join(rot13_map.get(c, c) for c in text)

        # Check if result contains more English-like patterns
        english_words = ['the', 'and', 'you', 'are', 'not', 'ignore', 'system']
        decoded_lower = decoded.lower()
        matches = sum(1 for word in english_words if word in decoded_lower)

        if matches >= 1 and decoded != text:
            return True, decoded
        return False, text

    def _try_url_decode(self, text: str) -> Tuple[bool, str]:
        """Try URL percent decoding"""
        if '%' in text:
            try:
                decoded = urllib.parse.unquote(text)
                if decoded != text:
                    return True, decoded
            except Exception:
                pass
        return False, text

    def _detect_unicode_confusion(self, text: str) -> Tuple[bool, str, List[str]]:
        """Detect and normalize Unicode homoglyphs"""
        indicators = []
        normalized = []

        for char in text:
            if char in self.HOMOGLYPHS:
                normalized.append(self.HOMOGLYPHS[char])
                indicators.append(f"Homoglyph '{char}' → '{self.HOMOGLYPHS[char]}'")
            elif ord(char) > 127 and char not in '，。！？：；""''（）【】':
                # Non-ASCII that's not common punctuation
                normalized.append(char)
                if ord(char) in range(0x2000, 0x206F):
                    indicators.append(f"Invisible character U+{ord(char):04X}")
            else:
                normalized.append(char)

        return len(indicators) > 0, ''.join(normalized), indicators

    def _detect_injection(self, text: str) -> Tuple[bool, List[str]]:
        """Detect injection patterns in decoded text"""
        indicators = []
        text_lower = text.lower()

        for pattern, description in self.INJECTION_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                indicators.append(description)

        return len(indicators) > 0, indicators

    def decode_all(self, text: str, max_depth: int = 5) -> str:
        """
        Convenience method: try all decoders recursively.
        Returns the fully decoded text.
        """
        result = self.analyze(text, decode_nested=True, max_depth=max_depth)
        return result.decoded_prompt

    def analyze(
        self,
        prompt: str,
        decode_nested: bool = True,
        max_depth: int = 5
    ) -> ObfuscationAnalysisResult:
        """
        Analyze prompt for obfuscation and decode content.

        Args:
            prompt: The prompt text to analyze
            decode_nested: Whether to recursively decode nested obfuscation
            max_depth: Maximum recursion depth for nested decoding

        Returns:
            ObfuscationAnalysisResult with findings
        """
        with self._lock:
            self.stats["total_analyzed"] += 1

        matches: List[ObfuscationMatch] = []
        current_text = prompt
        all_indicators: List[str] = []
        depth = 0

        # Phase 1: Decoding loop (handle nested obfuscation)
        while decode_nested and depth < max_depth:
            decoded_any = False

            # Try Base64
            success, decoded = self._try_base64_decode(current_text)
            if success and decoded != current_text:
                matches.append(ObfuscationMatch(
                    obfuscation_type=ObfuscationType.BASE64,
                    original_text=current_text[:100],
                    decoded_text=decoded[:100],
                    confidence=0.95,
                    start_pos=0,
                    end_pos=len(current_text),
                    threat_indicators=["Base64 encoding detected"]
                ))
                current_text = decoded
                decoded_any = True
                with self._lock:
                    self.stats["by_type"]["BASE64"] += 1

            # Try Hex
            success, decoded = self._try_hex_decode(current_text)
            if success and decoded != current_text:
                matches.append(ObfuscationMatch(
                    obfuscation_type=ObfuscationType.HEX,
                    original_text=current_text[:100],
                    decoded_text=decoded[:100],
                    confidence=0.90,
                    start_pos=0,
                    end_pos=len(current_text),
                    threat_indicators=["Hexadecimal encoding detected"]
                ))
                current_text = decoded
                decoded_any = True
                with self._lock:
                    self.stats["by_type"]["HEX"] += 1

            # Try ROT13
            success, decoded = self._try_rot13_decode(current_text)
            if success and decoded != current_text:
                matches.append(ObfuscationMatch(
                    obfuscation_type=ObfuscationType.ROT13,
                    original_text=current_text[:100],
                    decoded_text=decoded[:100],
                    confidence=0.80,
                    start_pos=0,
                    end_pos=len(current_text),
                    threat_indicators=["ROT13/Caesar cipher detected"]
                ))
                current_text = decoded
                decoded_any = True
                with self._lock:
                    self.stats["by_type"]["ROT13"] += 1

            # Try URL decode
            success, decoded = self._try_url_decode(current_text)
            if success and decoded != current_text:
                matches.append(ObfuscationMatch(
                    obfuscation_type=ObfuscationType.URL_ENCODED,
                    original_text=current_text[:100],
                    decoded_text=decoded[:100],
                    confidence=0.95,
                    start_pos=0,
                    end_pos=len(current_text),
                    threat_indicators=["URL encoding detected"]
                ))
                current_text = decoded
                decoded_any = True
                with self._lock:
                    self.stats["by_type"]["URL"] += 1

            if not decoded_any:
                break
            depth += 1

        # Phase 2: Unicode confusion detection
        has_confusion, normalized, unicode_indicators = self._detect_unicode_confusion(current_text)
        if has_confusion:
            matches.append(ObfuscationMatch(
                obfuscation_type=ObfuscationType.UNICODE_CONFUSION,
                original_text=current_text[:100],
                decoded_text=normalized[:100],
                confidence=0.85,
                start_pos=0,
                end_pos=len(current_text),
                threat_indicators=unicode_indicators
            ))
            current_text = normalized
            all_indicators.extend(unicode_indicators)
            with self._lock:
                self.stats["by_type"]["UNICODE"] += 1

        # Phase 3: Injection detection on final decoded text
        has_injection, injection_indicators = self._detect_injection(current_text)
        all_indicators.extend(injection_indicators)

        # Determine threat level
        threat_level = self._calculate_threat_level(
            len(matches),
            has_injection,
            depth,
            len(all_indicators)
        )

        # Generate recommendations
        recommendations = self._generate_recommendations(
            matches,
            has_injection,
            threat_level,
            current_text
        )

        with self._lock:
            if matches:
                self.stats["obfuscations_detected"] += 1
            if has_injection:
                self.stats["injections_found"] += 1
            self.stats["threat_levels"][threat_level.value] += 1

        return ObfuscationAnalysisResult(
            original_prompt=prompt,
            decoded_prompt=current_text,
            matches=matches,
            threat_level=threat_level,
            contains_injection=has_injection,
            injection_indicators=injection_indicators,
            recommendations=recommendations,
            statistics={
                "decoding_depth": depth,
                "obfuscation_count": len(matches),
                "injection_count": len(injection_indicators)
            }
        )

    def _calculate_threat_level(
        self,
        obfuscation_count: int,
        has_injection: bool,
        decoding_depth: int,
        indicator_count: int
    ) -> ThreatLevel:
        """Calculate overall threat level based on findings"""
        score = 0

        # Base score from obfuscation
        score += obfuscation_count * 20
        score += decoding_depth * 15
        score += indicator_count * 10

        # Injection is a big red flag
        if has_injection:
            score += 50

        # Nested obfuscation is suspicious
        if decoding_depth >= 3:
            score += 30

        # Map to threat levels
        if score >= 100:
            return ThreatLevel.CRITICAL
        elif score >= 70:
            return ThreatLevel.HIGH
        elif score >= 40:
            return ThreatLevel.MEDIUM
        elif score >= 15:
            return ThreatLevel.LOW
        return ThreatLevel.SAFE

    def _generate_recommendations(
        self,
        matches: List[ObfuscationMatch],
        has_injection: bool,
        threat_level: ThreatLevel,
        decoded_text: str
    ) -> List[str]:
        """Generate actionable recommendations"""
        recs = []

        if not matches and not has_injection:
            recs.append("No obfuscation detected - prompt appears clean")
            return recs

        if threat_level == ThreatLevel.CRITICAL:
            recs.append("🚫 BLOCK PROMPT - Critical threat detected")
            recs.append("Multiple obfuscation layers with injection content")
        elif threat_level == ThreatLevel.HIGH:
            recs.append("⚠️ HIGH RISK - Reject or heavily scrutinize this prompt")
        elif threat_level == ThreatLevel.MEDIUM:
            recs.append("⚠️ MEDIUM RISK - Monitor response carefully")
        elif threat_level == ThreatLevel.LOW:
            recs.append("ℹ️ LOW RISK - Minor encoding detected")

        # Specific findings
        types_found = set(m.obfuscation_type.value for m in matches)
        if types_found:
            recs.append(f"Detected encoding types: {', '.join(types_found)}")

        if has_injection:
            recs.append("❌ Hidden injection content revealed after decoding")

        recs.append(f"Decoded preview: {decoded_text[:100]}...")

        return recs

    def get_statistics(self) -> Dict[str, Any]:
        """Get detection statistics"""
        with self._lock:
            return {
                "total_analyzed": self.stats["total_analyzed"],
                "obfuscations_detected": self.stats["obfuscations_detected"],
                "injections_found": self.stats["injections_found"],
                "by_type": dict(self.stats["by_type"]),
                "threat_distribution": dict(self.stats["threat_levels"])
            }
