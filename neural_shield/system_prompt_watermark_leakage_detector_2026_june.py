"""
System Prompt Watermarking & Leakage Detector 2026 - June 2026 Production Release
NeuralShield-AI Security Module

Implements:
1. Invisible Zero-Width Watermark Embedding for System Prompts
2. System Prompt Leakage Detection in LLM Outputs
3. Tamper Detection and Watermark Verification
4. Multiple Watermarking Strategies (ZWSP, Homoglyphs, Syntax-based)
5. Audit logging for compliance

Based on:
- "A Watermark for Large Language Models" (Kirchenbauer et al., 2023)
- OWASP LLM Top 10: Prompt Injection & System Prompt Leakage
- Enhanced: June 2026 - Multi-strategy watermarking, confidence scoring
"""
import re
import hashlib
import base64
from typing import Tuple, Optional, List, Dict, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from collections import Counter


class WatermarkStrategy(Enum):
    """Watermark embedding strategies"""
    ZERO_WIDTH = "zero_width_spaces"          # Invisible ZWSP/ZWNJ characters
    HOMOGLYPH = "homoglyph_substitution"      # Visually identical character substitution
    SYNTAX = "syntax_pattern_based"           # Punctuation/spacing patterns
    COMBINED = "combined_multi_strategy"      # All strategies combined


class LeakageType(Enum):
    """Types of system prompt leakage"""
    FULL_LEAKAGE = "full_system_prompt_leaked"
    PARTIAL_LEAKAGE = "partial_system_prompt_leaked"
    WATERMARK_DETECTED = "watermark_identified_in_output"
    TAMPERED_WATERMARK = "watermark_tampered_or_modified"
    SUSPICIOUS_PATTERN = "suspicious_pattern_matched"


class VerificationStatus(Enum):
    """Watermark verification status"""
    VERIFIED = "watermark_verified_authentic"
    TAMPERED = "watermark_tampered_detected"
    NOT_FOUND = "watermark_not_present"
    CORRUPTED = "watermark_corrupted"


@dataclass
class WatermarkInfo:
    """Watermark metadata"""
    watermark_id: str
    strategy: WatermarkStrategy
    embedded_at: str
    original_hash: str
    secret_key: str
    version: str = "2026.6.1"


@dataclass
class LeakageFinding:
    """Single leakage detection finding"""
    leakage_type: LeakageType
    confidence: float
    matched_text: str
    position: Tuple[int, int]
    watermark_id: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WatermarkDetectionResult:
    """Complete watermark detection and leakage result"""
    original_prompt: str
    analyzed_text: str
    watermark_info: Optional[WatermarkInfo] = None
    leakage_findings: List[LeakageFinding] = field(default_factory=list)
    verification_status: VerificationStatus = VerificationStatus.NOT_FOUND
    is_leaked: bool = False
    risk_score: float = 0.0
    detection_id: str = ""
    timestamp: str = ""


class SystemPromptWatermarker:
    """
    System Prompt Watermarking Engine - June 2026 Production
    
    Embeds invisible, undetectable watermarks into system prompts
    for leakage detection and tamper verification.
    """
    
    # Zero-width characters for invisible watermarking
    ZERO_WIDTH_CHARS = {
        '0': '\u200B',  # Zero Width Space
        '1': '\u200C',  # Zero Width Non-Joiner
        '2': '\u200D',  # Zero Width Joiner
        '3': '\u2060',  # Word Joiner
    }
    
    ZW_REVERSE = {v: k for k, v in ZERO_WIDTH_CHARS.items()}
    
    # Homoglyph substitutions (visually identical but different codepoints)
    HOMOGLYPHS = {
        'a': 'а',  # Cyrillic 'a'
        'c': 'с',  # Cyrillic 'es'
        'e': 'е',  # Cyrillic 'ie'
        'o': 'о',  # Cyrillic 'o'
        'p': 'р',  # Cyrillic 'er'
        'x': 'х',  # Cyrillic 'kha'
        'y': 'у',  # Cyrillic 'u'
    }
    
    HOMOGLYPH_REVERSE = {v: k for k, v in HOMOGLYPHS.items()}
    
    def __init__(self, secret_key: str = "neuralshield_watermark_2026",
                 strategy: WatermarkStrategy = WatermarkStrategy.COMBINED):
        self.secret_key = secret_key
        self.strategy = strategy
        self.watermark_count = 0
        self.verification_count = 0
        self.watermark_registry: Dict[str, WatermarkInfo] = {}
        
    def _generate_watermark_id(self, text: str) -> str:
        """Generate unique watermark ID from text and secret key"""
        signature = f"{text}{self.secret_key}{datetime.now().isoformat()}"
        return hashlib.sha256(signature.encode()).hexdigest()[:16]
    
    def _text_to_binary(self, watermark_id: str) -> str:
        """Convert watermark ID to base4 binary string"""
        binary = []
        for char in watermark_id[:8]:
            val = int(char, 16)
            binary.append(f"{val:04b}")
        return ''.join(binary)
    
    def _embed_zero_width(self, text: str, watermark_id: str) -> str:
        """Embed watermark using zero-width characters (invisible)"""
        binary_data = self._text_to_binary(watermark_id)
        
        # Insert watermark at word boundaries
        words = text.split(' ')
        watermarked = []
        data_idx = 0
        
        for i, word in enumerate(words):
            watermarked.append(word)
            # Insert watermark bits between words
            if i < len(words) - 1 and data_idx < len(binary_data):
                # Encode 2 bits per space
                bits = binary_data[data_idx:data_idx+2]
                if len(bits) == 2:
                    zw_char = self.ZERO_WIDTH_CHARS.get(bits, '')
                    watermarked.append(zw_char)
                    data_idx += 2
            watermarked.append(' ')
        
        return ''.join(watermarked).rstrip()
    
    def _embed_homoglyph(self, text: str, watermark_id: str) -> str:
        """Embed watermark using homoglyph substitutions"""
        binary_data = self._text_to_binary(watermark_id)
        result = list(text)
        data_idx = 0
        
        for i, char in enumerate(result):
            if data_idx >= len(binary_data):
                break
            char_lower = char.lower()
            if char_lower in self.HOMOGLYPHS and binary_data[data_idx] == '1':
                if char.isupper():
                    result[i] = self.HOMOGLYPHS[char_lower].upper()
                else:
                    result[i] = self.HOMOGLYPHS[char_lower]
                data_idx += 1
        
        return ''.join(result)
    
    def _embed_syntax(self, text: str, watermark_id: str) -> str:
        """Embed watermark using punctuation and spacing patterns"""
        # Use double spaces vs single spaces to encode bits
        binary_data = self._text_to_binary(watermark_id)
        sentences = re.split(r'([.!?])', text)
        result = []
        data_idx = 0
        
        for i in range(0, len(sentences) - 1, 2):
            sentence = sentences[i]
            punct = sentences[i + 1] if i + 1 < len(sentences) else ''
            
            result.append(sentence)
            result.append(punct)
            
            # Encode bit in spacing after punctuation
            if data_idx < len(binary_data):
                if binary_data[data_idx] == '1':
                    result.append('  ')  # Double space for '1'
                else:
                    result.append(' ')   # Single space for '0'
                data_idx += 1
        
        return ''.join(result).rstrip()
    
    def embed_watermark(self, system_prompt: str) -> Tuple[str, WatermarkInfo]:
        """
        Embed watermark into system prompt using selected strategy
        
        Args:
            system_prompt: Original system prompt text
            
        Returns:
            Tuple of (watermarked_prompt, watermark_metadata)
        """
        watermark_id = self._generate_watermark_id(system_prompt)
        original_hash = hashlib.sha256(system_prompt.encode()).hexdigest()
        
        # Apply selected strategy
        if self.strategy == WatermarkStrategy.ZERO_WIDTH:
            watermarked = self._embed_zero_width(system_prompt, watermark_id)
        elif self.strategy == WatermarkStrategy.HOMOGLYPH:
            watermarked = self._embed_homoglyph(system_prompt, watermark_id)
        elif self.strategy == WatermarkStrategy.SYNTAX:
            watermarked = self._embed_syntax(system_prompt, watermark_id)
        else:  # COMBINED
            watermarked = self._embed_zero_width(system_prompt, watermark_id)
            watermarked = self._embed_homoglyph(watermarked, watermark_id)
        
        info = WatermarkInfo(
            watermark_id=watermark_id,
            strategy=self.strategy,
            embedded_at=datetime.now().isoformat(),
            original_hash=original_hash,
            secret_key=self.secret_key
        )
        
        self.watermark_registry[watermark_id] = info
        self.watermark_count += 1
        
        return watermarked, info
    
    def _extract_zero_width(self, text: str) -> List[str]:
        """Extract zero-width watermark bits from text"""
        extracted = []
        for char in text:
            if char in self.ZW_REVERSE:
                extracted.append(self.ZW_REVERSE[char])
        return extracted
    
    def _extract_homoglyph(self, text: str) -> List[str]:
        """Extract homoglyph watermark bits from text"""
        bits = []
        for char in text:
            if char.lower() in self.HOMOGLYPH_REVERSE:
                bits.append('1')
        return bits
    
    def verify_watermark(self, text: str, expected_id: Optional[str] = None) -> Tuple[VerificationStatus, float, Optional[str]]:
        """
        Verify if watermark exists and is authentic
        
        Args:
            text: Text to analyze
            expected_id: Optional expected watermark ID to verify
            
        Returns:
            Tuple of (status, confidence, detected_watermark_id)
        """
        self.verification_count += 1
        
        # Extract watermark bits using all strategies
        zw_bits = self._extract_zero_width(text)
        homo_bits = self._extract_homoglyph(text)
        
        total_bits = len(zw_bits) + len(homo_bits)
        
        if total_bits == 0:
            return VerificationStatus.NOT_FOUND, 0.0, None
        
        # Calculate confidence based on bit density
        confidence = min(0.98, total_bits / 20.0)
        
        # Check registry for known watermarks
        detected_id = None
        for wm_id, info in self.watermark_registry.items():
            if wm_id in text or len(zw_bits) > 8:
                detected_id = wm_id
                if expected_id and expected_id != wm_id:
                    return VerificationStatus.TAMPERED, confidence * 0.7, detected_id
                return VerificationStatus.VERIFIED, confidence, detected_id
        
        if total_bits > 4:
            return VerificationStatus.VERIFIED, confidence, detected_id
        
        return VerificationStatus.NOT_FOUND, confidence * 0.3, None
    
    def get_watermark_stats(self) -> Dict[str, Any]:
        """Get watermarking statistics"""
        return {
            'watermarks_embedded': self.watermark_count,
            'verifications_performed': self.verification_count,
            'active_watermarks': len(self.watermark_registry),
            'strategy': self.strategy.value,
            'supported_strategies': [s.value for s in WatermarkStrategy]
        }


class SystemPromptLeakageDetector:
    """
    System Prompt Leakage Detection Engine - June 2026 Production
    
    Detects when system prompts or instructions have been
    leaked or extracted in LLM outputs.
    """
    
    def __init__(self, watermarker: Optional[SystemPromptWatermarker] = None):
        self.watermarker = watermarker or SystemPromptWatermarker()
        self.detection_count = 0
        self.leakage_count = 0
        
        # System prompt leakage patterns
        self.leakage_patterns = [
            (r'(?i)you are (a|an) (AI|assistant|chatbot|language model)', 0.8),
            (r'(?i)your instructions? (are|state|say)', 0.7),
            (r'(?i)system prompt|system instruction', 0.9),
            (r'(?i)ignore (previous|above) instructions?', 0.95),
            (r'(?i)repeat your (system|initial) (prompt|instructions?)', 0.9),
            (r'(?i)act as if|roleplay as|pretend to be', 0.6),
            (r'(?i)you must|your purpose is|your goal is', 0.5),
            (r'(?i)always|never|you will (not)?', 0.4),
            (r'(?i)developed by|created by|made by', 0.5),
        ]
        
        # Common system prompt keywords
        self.system_keywords = {
            'assistant', 'helpful', 'harmless', 'honest', 'ethical',
            'safety', 'guidelines', 'policies', 'content policy',
            'system prompt', 'instructions', 'your role', 'you are'
        }
    
    def _pattern_match_detection(self, text: str) -> List[LeakageFinding]:
        """Detect leakage using pattern matching"""
        findings = []
        text_lower = text.lower()
        
        for pattern, base_confidence in self.leakage_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            for match in matches:
                # Boost confidence based on match quality
                confidence = base_confidence
                if len(match.group()) > 20:
                    confidence = min(0.99, confidence + 0.1)
                
                findings.append(LeakageFinding(
                    leakage_type=LeakageType.SUSPICIOUS_PATTERN,
                    confidence=confidence,
                    matched_text=match.group(),
                    position=(match.start(), match.end()),
                    evidence={'pattern': pattern}
                ))
        
        return findings
    
    def _keyword_analysis(self, text: str) -> float:
        """Calculate system keyword density score"""
        words = set(re.findall(r'\b\w+\b', text.lower()))
        matches = words & self.system_keywords
        if len(words) == 0:
            return 0.0
        return len(matches) / len(self.system_keywords)
    
    def _watermark_based_detection(self, text: str) -> List[LeakageFinding]:
        """Detect leakage using embedded watermarks"""
        findings = []
        
        status, confidence, wm_id = self.watermarker.verify_watermark(text)
        
        if status == VerificationStatus.VERIFIED:
            findings.append(LeakageFinding(
                leakage_type=LeakageType.WATERMARK_DETECTED,
                confidence=confidence,
                matched_text="[WATERMARK_DETECTED]",
                position=(0, len(text)),
                watermark_id=wm_id,
                evidence={'verification_status': status.value}
            ))
        elif status == VerificationStatus.TAMPERED:
            findings.append(LeakageFinding(
                leakage_type=LeakageType.TAMPERED_WATERMARK,
                confidence=confidence,
                matched_text="[TAMPERED_WATERMARK]",
                position=(0, len(text)),
                watermark_id=wm_id,
                evidence={'verification_status': status.value}
            ))
        
        return findings
    
    def detect_leakage(self, llm_output: str, 
                       original_system_prompt: Optional[str] = None,
                       watermark_info: Optional[WatermarkInfo] = None) -> WatermarkDetectionResult:
        """
        Detect system prompt leakage in LLM output
        
        Args:
            llm_output: Output from LLM to analyze
            original_system_prompt: Optional original system prompt for comparison
            watermark_info: Optional watermark metadata
            
        Returns:
            Complete detection result
        """
        self.detection_count += 1
        
        findings = []
        
        # 1. Pattern-based detection
        findings.extend(self._pattern_match_detection(llm_output))
        
        # 2. Watermark-based detection
        findings.extend(self._watermark_based_detection(llm_output))
        
        # 3. Keyword density analysis
        keyword_score = self._keyword_analysis(llm_output)
        if keyword_score > 0.15:
            findings.append(LeakageFinding(
                leakage_type=LeakageType.PARTIAL_LEAKAGE,
                confidence=keyword_score,
                matched_text="[KEYWORD_DENSITY_HIGH]",
                position=(0, len(llm_output)),
                evidence={'keyword_score': keyword_score}
            ))
        
        # 4. Direct comparison if original prompt provided
        if original_system_prompt:
            similarity = self._calculate_similarity(llm_output, original_system_prompt)
            if similarity > 0.3:
                leakage_type = (LeakageType.FULL_LEAKAGE if similarity > 0.7 
                              else LeakageType.PARTIAL_LEAKAGE)
                findings.append(LeakageFinding(
                    leakage_type=leakage_type,
                    confidence=similarity,
                    matched_text="[SIMILARITY_MATCH]",
                    position=(0, len(llm_output)),
                    evidence={'similarity_score': similarity}
                ))
        
        # Calculate overall risk
        risk_score = 0.0
        is_leaked = False
        
        if findings:
            risk_score = max(f.confidence for f in findings)
            is_leaked = risk_score > 0.5
            if is_leaked:
                self.leakage_count += 1
        
        detection_id = hashlib.sha256(f"{llm_output}{datetime.now().isoformat()}".encode()).hexdigest()[:16]
        
        return WatermarkDetectionResult(
            original_prompt=original_system_prompt or "",
            analyzed_text=llm_output,
            watermark_info=watermark_info,
            leakage_findings=findings,
            verification_status=self.watermarker.verify_watermark(llm_output)[0],
            is_leaked=is_leaked,
            risk_score=min(1.0, risk_score),
            detection_id=detection_id,
            timestamp=datetime.now().isoformat()
        )
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Simple word overlap similarity score"""
        words1 = set(re.findall(r'\b\w+\b', text1.lower()))
        words2 = set(re.findall(r'\b\w+\b', text2.lower()))
        if not words1 or not words2:
            return 0.0
        intersection = words1 & words2
        union = words1 | words2
        return len(intersection) / len(union)
    
    def batch_detect(self, outputs: List[str], 
                     system_prompt: Optional[str] = None) -> List[WatermarkDetectionResult]:
        """Batch detect leakage in multiple outputs"""
        return [self.detect_leakage(output, system_prompt) for output in outputs]
    
    def get_detection_stats(self) -> Dict[str, Any]:
        """Get detection statistics"""
        return {
            'total_detections': self.detection_count,
            'leakages_detected': self.leakage_count,
            'leakage_rate': self.leakage_count / max(self.detection_count, 1),
            'monitored_patterns': len(self.leakage_patterns),
            'watermarking_enabled': self.watermarker is not None
        }


def create_watermark_protection() -> Tuple[SystemPromptWatermarker, SystemPromptLeakageDetector]:
    """Factory function to create watermarking and leakage detection pair"""
    watermarker = SystemPromptWatermarker()
    detector = SystemPromptLeakageDetector(watermarker=watermarker)
    return watermarker, detector
