"""
NeuralShield AI - Prompt Injection Evasion Technique Detector
Production-grade detection of advanced evasion techniques used by attackers
to bypass prompt injection detectors.

Attackers frequently use evasion techniques to bypass security filters:
- Base64/hex encoding of malicious payloads
- Unicode obfuscation and homoglyph attacks
- Leetspeak and character substitution
- Zero-width characters and invisible separators
- ROT13/Caesar cipher encoding
- URL encoding and HTML entity encoding

Key capabilities:
- Multi-layer encoding detection (Base64, Hex, URL, HTML)
- Unicode homoglyph and zero-width character detection
- Leetspeak pattern recognition
- Caesar/ROT cipher auto-detection
- Confidence scoring with false positive calibration
- Decoding and analysis of hidden payloads
"""
import re
import base64
import hashlib
import string
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from collections import Counter
from urllib.parse import unquote
import html


class EvasionTechniqueType(Enum):
    """Types of evasion techniques detected"""
    NONE = "none"
    BASE64_ENCODED = "base64_encoded"
    HEX_ENCODED = "hex_encoded"
    URL_ENCODED = "url_encoded"
    HTML_ENTITY_ENCODED = "html_entity_encoded"
    UNICODE_HOMOGLYPH = "unicode_homoglyph"
    ZERO_WIDTH_CHARS = "zero_width_chars"
    LEETSPEAK = "leetspeak"
    ROT_CIPHER = "rot_cipher"
    MIXED_ENCODING = "mixed_encoding"
    UNKNOWN = "unknown"


class EvasionThreatLevel(Enum):
    """Threat levels for evasion detection"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DecodedPayload:
    """Result of decoding an evaded payload"""
    original_snippet: str
    decoded_text: str
    encoding_type: EvasionTechniqueType
    decode_success: bool
    injection_indicators_found: List[str] = field(default_factory=list)


@dataclass
class EvasionDetectionResult:
    """Result of evasion technique detection"""
    detection_id: str
    has_evasion: bool
    threat_level: EvasionThreatLevel
    confidence_score: float  # 0.0-1.0
    techniques_detected: List[EvasionTechniqueType] = field(default_factory=list)
    decoded_payloads: List[DecodedPayload] = field(default_factory=list)
    suspicious_snippets: List[str] = field(default_factory=list)
    zero_width_count: int = 0
    homoglyph_count: int = 0
    encoding_density: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    false_positive_likelihood: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "has_evasion": self.has_evasion,
            "threat_level": self.threat_level.value,
            "confidence_score": round(self.confidence_score, 4),
            "techniques_detected": [t.value for t in self.techniques_detected],
            "suspicious_snippets_count": len(self.suspicious_snippets),
            "decoded_payloads_count": len(self.decoded_payloads),
            "zero_width_count": self.zero_width_count,
            "homoglyph_count": self.homoglyph_count,
            "encoding_density": round(self.encoding_density, 4),
            "false_positive_likelihood": round(self.false_positive_likelihood, 4),
            "timestamp": self.timestamp.isoformat()
        }


class PromptInjectionEvasionTechniqueDetector:
    """
    Production-grade detector for prompt injection evasion techniques.
    
    Detects and decodes various encoding and obfuscation methods that attackers
    use to bypass standard prompt injection detectors.
    """
    
    # Common injection keywords to check in decoded payloads
    INJECTION_KEYWORDS = {
        "ignore", "disregard", "forget", "bypass", "disable", "override",
        "previous", "instructions", "rules", "system", "prompt", "developer",
        "admin", "root", "unrestricted", "reveal", "show", "output", "jailbreak",
        "act as", "pretend", "mode", "unfiltered", "no limits"
    }
    
    # Unicode homoglyph mappings - common character substitutions
    HOMOGLYPHS = {
        'а': 'a', 'ɑ': 'a', 'а': 'a',
        'Ь': 'b', 'Ь': 'b', 'в': 'b',
        'с': 'c', 'ϲ': 'c', 'с': 'c',
        'ԁ': 'd', 'ⅾ': 'd',
        'е': 'e', 'е': 'e', '℮': 'e',
        'ƒ': 'f',
        'ɡ': 'g', 'ԍ': 'g',
        'һ': 'h', 'հ': 'h',
        'і': 'i', 'і': 'i', 'ι': 'i',
        'ј': 'j', 'ј': 'j',
        'κ': 'k', 'к': 'k',
        'ⅼ': 'l', 'ӏ': 'l',
        'м': 'm', 'ⅿ': 'm',
        'ո': 'n', 'ո': 'n',
        'ο': 'o', 'о': 'o', 'σ': 'o',
        'р': 'p', 'ρ': 'p',
        'ԛ': 'q',
        'г': 'r', 'г': 'r',
        'ѕ': 's', 'ѕ': 's',
        'τ': 't', 'ｔ': 't',
        'υ': 'u', 'υ': 'u',
        'ν': 'v', 'ν': 'v',
        'ѡ': 'w', 'ω': 'w',
        'х': 'x', 'х': 'x',
        'у': 'y', 'у': 'y',
        'ᴢ': 'z', 'ᴢ': 'z'
    }
    
    # Zero-width and invisible characters
    ZERO_WIDTH_CHARS = {
        '\u200b', '\u200c', '\u200d', '\u200e', '\u200f',
        '\u2060', '\u2061', '\u2062', '\u2063', '\u2064',
        '\ufeff', '\u202a', '\u202b', '\u202c', '\u202d',
        '\u202e', '\u00ad', '\u034f', '\u17b4', '\u17b5'
    }
    
    # Leetspeak mappings
    LEETSPEAK_MAP = {
        '0': ['o', 'O'],
        '1': ['i', 'I', 'l', 'L'],
        '2': ['z', 'Z', 'to'],
        '3': ['e', 'E'],
        '4': ['a', 'A'],
        '5': ['s', 'S'],
        '6': ['g', 'G', 'b'],
        '7': ['t', 'T'],
        '8': ['b', 'B'],
        '9': ['g', 'G', 'q'],
        '@': ['a', 'A'],
        '$': ['s', 'S'],
        '+': ['t', 'T'],
        'x': ['ks', 'ex'],
        '|': ['i', 'I', 'l']
    }
    
    # Benign patterns that look like encoding
    BENIGN_PATTERNS = [
        r'https?://[^\s]+',  # URLs
        r'data:image/[^\s]+',  # Data URIs for images
        r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',  # UUIDs
        r'[a-f0-9]{32,64}',  # Hashes
        r'color: #[0-9a-fA-F]{3,6}',  # CSS colors
        r'\b[A-Za-z0-9+/]{8,}={0,2}\b'  # Actual base64 but too short
    ]
    
    def __init__(self, 
                 confidence_threshold: float = 0.65,
                 enable_decoding: bool = True,
                 check_injection_in_decoded: bool = True):
        """
        Initialize the evasion technique detector.
        
        Args:
            confidence_threshold: Minimum confidence to flag as evasion
            enable_decoding: Whether to attempt decoding payloads
            check_injection_in_decoded: Whether to scan decoded payloads for injection keywords
        """
        self.confidence_threshold = confidence_threshold
        self.enable_decoding = enable_decoding
        self.check_injection_in_decoded = check_injection_in_decoded
        self._detection_history: List[EvasionDetectionResult] = []
    
    def _generate_detection_id(self) -> str:
        """Generate unique detection ID"""
        return f"evasion_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hashlib.md5(str(datetime.now().timestamp()).encode()).hexdigest()[:8]}"
    
    def _is_benign_pattern(self, text: str) -> bool:
        """Check if text matches known benign patterns"""
        for pattern in self.BENIGN_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def _detect_base64(self, text: str) -> Tuple[bool, float, Optional[str]]:
        """Detect and decode Base64 encoded content"""
        # Base64 pattern: letters, numbers, +, /, padding =
        base64_pattern = r'\b[A-Za-z0-9+/]{16,}={0,2}\b'
        matches = re.findall(base64_pattern, text)
        
        for match in matches:
            if self._is_benign_pattern(match):
                continue
            
            # Check padding validity
            if len(match) % 4 != 0:
                continue
            
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                # Check if decoded looks like meaningful text
                if len(decoded) > 5 and decoded.isprintable():
                    printable_ratio = sum(1 for c in decoded if c.isprintable() or c.isspace()) / len(decoded)
                    if printable_ratio > 0.8:
                        confidence = min(1.0, len(match) / 100) * printable_ratio
                        return True, confidence, decoded
            except:
                pass
        
        return False, 0.0, None
    
    def _detect_hex(self, text: str) -> Tuple[bool, float, Optional[str]]:
        """Detect and decode hex encoded content"""
        # Look for long hex strings with potential spaces/separators
        hex_patterns = [
            r'\b[0-9a-fA-F]{20,}\b',
            r'(?:[0-9a-fA-F]{2}\s+){5,}[0-9a-fA-F]{2}',
            r'(?:0x[0-9a-fA-F]{2}\s*){5,}'
        ]
        
        for pattern in hex_patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                if self._is_benign_pattern(match):
                    continue
                
                # Clean and try to decode
                clean_hex = re.sub(r'[\s0x]', '', match)
                if len(clean_hex) % 2 == 0:
                    try:
                        decoded = bytes.fromhex(clean_hex).decode('utf-8', errors='ignore')
                        printable_ratio = sum(1 for c in decoded if c.isprintable() or c.isspace()) / max(1, len(decoded))
                        if printable_ratio > 0.7 and len(decoded) > 3:
                            confidence = min(1.0, len(clean_hex) / 50) * printable_ratio
                            return True, confidence, decoded
                    except:
                        pass
        
        return False, 0.0, None
    
    def _detect_url_encoding(self, text: str) -> Tuple[bool, float, Optional[str]]:
        """Detect URL encoded content"""
        url_encode_count = len(re.findall(r'%[0-9a-fA-F]{2}', text))
        
        if url_encode_count >= 3:
            try:
                decoded = unquote(text)
                if decoded != text:
                    confidence = min(1.0, url_encode_count / 10)
                    return True, confidence, decoded
            except:
                pass
        
        return False, 0.0, None
    
    def _detect_html_entities(self, text: str) -> Tuple[bool, float, Optional[str]]:
        """Detect HTML entity encoding"""
        entity_patterns = [r'&#[0-9]+;', r'&#x[0-9a-fA-F]+;', r'&[a-zA-Z]+;']
        entity_count = sum(len(re.findall(p, text)) for p in entity_patterns)
        
        if entity_count >= 3:
            try:
                decoded = html.unescape(text)
                if decoded != text:
                    confidence = min(1.0, entity_count / 8)
                    return True, confidence, decoded
            except:
                pass
        
        return False, 0.0, None
    
    def _detect_zero_width(self, text: str) -> Tuple[bool, float, int]:
        """Detect zero-width and invisible characters"""
        count = sum(1 for c in text if c in self.ZERO_WIDTH_CHARS)
        
        if count > 0:
            density = count / max(1, len(text))
            confidence = min(1.0, count / 5 + density * 2)
            return True, confidence, count
        
        return False, 0.0, 0
    
    def _detect_homoglyphs(self, text: str) -> Tuple[bool, float, int, str]:
        """Detect Unicode homoglyph substitution"""
        normalized = []
        homoglyph_count = 0
        
        for c in text:
            if c in self.HOMOGLYPHS:
                normalized.append(self.HOMOGLYPHS[c])
                homoglyph_count += 1
            else:
                normalized.append(c)
        
        normalized_text = ''.join(normalized)
        
        if homoglyph_count > 0:
            density = homoglyph_count / max(1, len(text))
            confidence = min(1.0, homoglyph_count / 3 + density)
            return True, confidence, homoglyph_count, normalized_text
        
        return False, 0.0, 0, text
    
    def _detect_leetspeak(self, text: str) -> Tuple[bool, float, str]:
        """Detect leetspeak substitution"""
        # Look for injection keywords with leetspeak substitutions
        leet_confidence = 0.0
        normalized = text.lower()
        
        # Count leet characters in potential injection contexts
        leet_chars = sum(1 for c in text if c in self.LEETSPEAK_MAP)
        leet_density = leet_chars / max(1, len(text))
        
        # Check for common leet-based injection patterns
        leet_injection_patterns = [
            r'[i1]gn[o0]r[e3]',
            r'[s5][y4][s5]t[e3]m',
            r'pr[o0]mpt',
            r'd[e3]v[e3][l1][o0]p[e3]r',
            r'byp[a4][s5][s5]'
        ]
        
        matches = 0
        for pattern in leet_injection_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                matches += 1
        
        if matches > 0 or leet_density > 0.15:
            confidence = min(1.0, matches * 0.3 + leet_density)
            return True, confidence, normalized
        
        return False, 0.0, text
    
    def _detect_rot_cipher(self, text: str) -> Tuple[bool, float, Optional[str]]:
        """Detect and decode ROT13/Caesar cipher"""
        # Simple ROT13 detection - try decoding and check for injection keywords
        def rot13(s: str) -> str:
            result = []
            for c in s:
                if 'a' <= c <= 'z':
                    result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
                elif 'A' <= c <= 'Z':
                    result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
                else:
                    result.append(c)
            return ''.join(result)
        
        decoded = rot13(text.lower())
        
        # Check if decoded contains injection keywords
        keyword_matches = sum(1 for kw in self.INJECTION_KEYWORDS if kw in decoded)
        
        if keyword_matches >= 2:
            confidence = min(1.0, keyword_matches / 5)
            return True, confidence, decoded
        
        return False, 0.0, None
    
    def _check_for_injection_keywords(self, text: str) -> List[str]:
        """Check text for injection keywords"""
        text_lower = text.lower()
        found = []
        for kw in self.INJECTION_KEYWORDS:
            if kw in text_lower:
                found.append(kw)
        return found
    
    def _calculate_false_positive_likelihood(self, text: str, techniques: List[EvasionTechniqueType]) -> float:
        """Estimate false positive probability"""
        fp_score = 0.0
        
        # Short texts are less suspicious
        if len(text) < 20:
            fp_score += 0.3
        
        # Check if this looks like legitimate code/configuration
        if re.search(r'(function|var|const|let|import|export)\s+', text):
            fp_score += 0.2
        
        # Check for legitimate base64 contexts
        if 'image' in text.lower() or 'data:' in text.lower():
            fp_score += 0.3
        
        # Single encoding without injection keywords is more likely benign
        if len(techniques) == 1 and EvasionTechniqueType.URL_ENCODED in techniques:
            fp_score += 0.2
        
        return min(0.95, fp_score)
    
    def _determine_threat_level(self, confidence: float, techniques: List[EvasionTechniqueType], 
                                injection_found: bool) -> EvasionThreatLevel:
        """Determine overall threat level"""
        if injection_found and confidence >= 0.8:
            return EvasionThreatLevel.CRITICAL
        elif injection_found and confidence >= 0.6:
            return EvasionThreatLevel.HIGH
        elif confidence >= 0.7 or len(techniques) >= 2:
            return EvasionThreatLevel.MEDIUM
        elif confidence >= 0.5:
            return EvasionThreatLevel.LOW
        return EvasionThreatLevel.SAFE
    
    def detect(self, text: str) -> EvasionDetectionResult:
        """
        Detect evasion techniques in user input text.
        
        Args:
            text: The user input text to analyze
            
        Returns:
            EvasionDetectionResult with all findings
        """
        if not text or len(text.strip()) == 0:
            return EvasionDetectionResult(
                detection_id=self._generate_detection_id(),
                has_evasion=False,
                threat_level=EvasionThreatLevel.SAFE,
                confidence_score=0.0
            )
        
        techniques_detected = []
        decoded_payloads = []
        total_confidence = 0.0
        injection_found_in_decoded = False
        suspicious_snippets = []
        
        # Check each evasion technique
        b64_detected, b64_conf, b64_decoded = self._detect_base64(text)
        if b64_detected:
            techniques_detected.append(EvasionTechniqueType.BASE64_ENCODED)
            total_confidence += b64_conf
            if b64_decoded:
                injection_kw = self._check_for_injection_keywords(b64_decoded)
                decoded_payloads.append(DecodedPayload(
                    original_snippet="[BASE64]",
                    decoded_text=b64_decoded[:200],
                    encoding_type=EvasionTechniqueType.BASE64_ENCODED,
                    decode_success=True,
                    injection_indicators_found=injection_kw
                ))
                if injection_kw:
                    injection_found_in_decoded = True
        
        hex_detected, hex_conf, hex_decoded = self._detect_hex(text)
        if hex_detected:
            techniques_detected.append(EvasionTechniqueType.HEX_ENCODED)
            total_confidence += hex_conf
            if hex_decoded:
                injection_kw = self._check_for_injection_keywords(hex_decoded)
                decoded_payloads.append(DecodedPayload(
                    original_snippet="[HEX]",
                    decoded_text=hex_decoded[:200],
                    encoding_type=EvasionTechniqueType.HEX_ENCODED,
                    decode_success=True,
                    injection_indicators_found=injection_kw
                ))
                if injection_kw:
                    injection_found_in_decoded = True
        
        url_detected, url_conf, url_decoded = self._detect_url_encoding(text)
        if url_detected:
            techniques_detected.append(EvasionTechniqueType.URL_ENCODED)
            total_confidence += url_conf
        
        html_detected, html_conf, html_decoded = self._detect_html_entities(text)
        if html_detected:
            techniques_detected.append(EvasionTechniqueType.HTML_ENTITY_ENCODED)
            total_confidence += html_conf
        
        zw_detected, zw_conf, zw_count = self._detect_zero_width(text)
        if zw_detected:
            techniques_detected.append(EvasionTechniqueType.ZERO_WIDTH_CHARS)
            total_confidence += zw_conf
        
        hg_detected, hg_conf, hg_count, hg_normalized = self._detect_homoglyphs(text)
        if hg_detected:
            techniques_detected.append(EvasionTechniqueType.UNICODE_HOMOGLYPH)
            total_confidence += hg_conf
        
        leet_detected, leet_conf, _ = self._detect_leetspeak(text)
        if leet_detected:
            techniques_detected.append(EvasionTechniqueType.LEETSPEAK)
            total_confidence += leet_conf
        
        rot_detected, rot_conf, rot_decoded = self._detect_rot_cipher(text)
        if rot_detected:
            techniques_detected.append(EvasionTechniqueType.ROT_CIPHER)
            total_confidence += rot_conf
            if rot_decoded:
                injection_kw = self._check_for_injection_keywords(rot_decoded)
                decoded_payloads.append(DecodedPayload(
                    original_snippet="[ROT13]",
                    decoded_text=rot_decoded[:200],
                    encoding_type=EvasionTechniqueType.ROT_CIPHER,
                    decode_success=True,
                    injection_indicators_found=injection_kw
                ))
                if injection_kw:
                    injection_found_in_decoded = True
        
        # Check for mixed encoding
        if len(techniques_detected) >= 2:
            techniques_detected.append(EvasionTechniqueType.MIXED_ENCODING)
        
        # Calculate final confidence
        final_confidence = 0.0
        if techniques_detected:
            # Weight: average + bonus for multiple techniques + injection found
            avg_conf = total_confidence / len(techniques_detected)
            technique_bonus = min(0.3, len(techniques_detected) * 0.1)
            injection_bonus = 0.3 if injection_found_in_decoded else 0.0
            final_confidence = min(1.0, avg_conf + technique_bonus + injection_bonus)
        
        # Calculate false positive likelihood
        fp_likelihood = self._calculate_false_positive_likelihood(text, techniques_detected)
        
        # Adjust confidence based on false positive likelihood
        adjusted_confidence = final_confidence * (1 - fp_likelihood * 0.5)
        
        # Determine if evasion detected
        has_evasion = adjusted_confidence >= self.confidence_threshold
        
        # Determine threat level
        threat_level = self._determine_threat_level(adjusted_confidence, techniques_detected, injection_found_in_decoded)
        
        result = EvasionDetectionResult(
            detection_id=self._generate_detection_id(),
            has_evasion=has_evasion,
            threat_level=threat_level,
            confidence_score=adjusted_confidence,
            techniques_detected=list(set(techniques_detected)),
            decoded_payloads=decoded_payloads,
            suspicious_snippets=suspicious_snippets,
            zero_width_count=zw_count if zw_detected else 0,
            homoglyph_count=hg_count if hg_detected else 0,
            encoding_density=sum(1 for c in text if not c.isascii()) / max(1, len(text)),
            false_positive_likelihood=fp_likelihood
        )
        
        self._detection_history.append(result)
        return result
    
    def get_detection_stats(self) -> Dict[str, Any]:
        """Get statistics about detections"""
        if not self._detection_history:
            return {"total_detections": 0}
        
        technique_counts = Counter()
        threat_counts = Counter()
        
        for result in self._detection_history:
            for tech in result.techniques_detected:
                technique_counts[tech.value] += 1
            threat_counts[result.threat_level.value] += 1
        
        return {
            "total_detections": len(self._detection_history),
            "evasion_detected_count": sum(1 for r in self._detection_history if r.has_evasion),
            "technique_distribution": dict(technique_counts),
            "threat_level_distribution": dict(threat_counts),
            "average_confidence": sum(r.confidence_score for r in self._detection_history) / len(self._detection_history)
        }
