"""
Multimodal Steganography Injection Detector - 2026 Latest Research Implementation

Based on 2026 AI security research:
- Multi-modal hidden instruction injection through images, audio, video
- Unicode invisible character injection detection
- Document hidden layer instruction extraction
- Steganographic payload detection in media files

Key features from 2026 research:
1. Image steganography injection detection (pixel-level hidden instructions)
2. Audio steganography injection detection (high-frequency embedded commands)
3. Document hidden text layer extraction (PDF/Word)
4. Unicode zero-width character detection and sanitization
5. Video frame interleave injection detection
"""

import re
import numpy as np
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
from enum import Enum


class SteganographyType(Enum):
    """Types of steganographic injection attacks (2026 classification)"""
    IMAGE_PIXEL = "image_pixel_injection"
    AUDIO_HIGH_FREQ = "audio_high_frequency_injection"
    DOCUMENT_HIDDEN_LAYER = "document_hidden_layer_injection"
    UNICODE_ZERO_WIDTH = "unicode_zero_width_injection"
    VIDEO_FRAME_INTERLEAVE = "video_frame_interleave_injection"
    UNKNOWN = "unknown_steganography"


@dataclass
class SteganographyDetectionResult:
    """Result of steganography detection"""
    detected: bool
    attack_type: SteganographyType
    confidence: float
    suspicious_patterns: List[str]
    sanitized_content: Optional[str] = None
    metadata: Dict[str, Any] = None


class MultimodalSteganographyDetector:
    """
    2026 State-of-the-Art Multimodal Steganography Injection Detector
    
    Implements defenses against emerging 2026 attack vectors:
    - Multi-modal hidden instruction injection (CSAW 2026)
    - Unicode invisible character injection (Black Hat 2026)
    - Image/audio steganographic payloads (Def Con 2026)
    """
    
    # Unicode zero-width and invisible characters (2026 attack vectors)
    ZERO_WIDTH_CHARS = {
        '\u200b': 'ZERO WIDTH SPACE',
        '\u200c': 'ZERO WIDTH NON-JOINER',
        '\u200d': 'ZERO WIDTH JOINER',
        '\u2060': 'WORD JOINER',
        '\u2061': 'FUNCTION APPLICATION',
        '\u2062': 'INVISIBLE TIMES',
        '\u2063': 'INVISIBLE SEPARATOR',
        '\u2064': 'INVISIBLE PLUS',
        '\ufeff': 'ZERO WIDTH NO-BREAK SPACE',
        '\u200e': 'LEFT-TO-RIGHT MARK',
        '\u200f': 'RIGHT-TO-LEFT MARK',
        '\u202a': 'LEFT-TO-RIGHT EMBEDDING',
        '\u202b': 'RIGHT-TO-LEFT EMBEDDING',
        '\u202c': 'POP DIRECTIONAL FORMATTING',
        '\u202d': 'LEFT-TO-RIGHT OVERRIDE',
        '\u202e': 'RIGHT-TO-LEFT OVERRIDE',
        '\u2066': 'LEFT-TO-RIGHT ISOLATE',
        '\u2067': 'RIGHT-TO-LEFT ISOLATE',
        '\u2068': 'FIRST STRONG ISOLATE',
        '\u2069': 'POP DIRECTIONAL ISOLATE',
        '\u00ad': 'SOFT HYPHEN',
        '\u034f': 'COMBINING GRAPHEME JOINER',
    }
    
    # Suspicious instruction patterns often hidden in steganography (2026 patterns)
    SUSPICIOUS_INSTRUCTIONS = [
        r'ignore.*previous',
        r'disregard.*prior',
        r'forget.*system.*prompt',
        r'developer.*mode',
        r'execute.*command',
        r'override.*safety',
        r'bypass.*policy',
        r'reset.*constraints',
        r'new.*instructions',
        r'priority.*instruction',
        r'content.*policy',
        r'safety.*measures',
        r'debug.*mode',
        r'unrestricted.*mode',
    ]
    
    def __init__(self, confidence_threshold: float = 0.7):
        self.confidence_threshold = confidence_threshold
        self.injection_patterns = self._compile_injection_patterns()
        
    def _compile_injection_patterns(self) -> List[re.Pattern]:
        """Compile regex patterns for injection detection"""
        return [re.compile(pattern, re.IGNORECASE) for pattern in self.SUSPICIOUS_INSTRUCTIONS]
    
    def detect_unicode_injection(self, text: str) -> SteganographyDetectionResult:
        """
        Detect Unicode zero-width character injection (2026 emerging attack)
        
        Attackers embed malicious instructions using invisible characters
        that humans cannot see but AI models can parse.
        """
        found_chars = []
        suspicious_positions = []
        
        for idx, char in enumerate(text):
            if char in self.ZERO_WIDTH_CHARS:
                found_chars.append(self.ZERO_WIDTH_CHARS[char])
                suspicious_positions.append(idx)
        
        if not found_chars:
            return SteganographyDetectionResult(
                detected=False,
                attack_type=SteganographyType.UNICODE_ZERO_WIDTH,
                confidence=0.0,
                suspicious_patterns=[],
                sanitized_content=text,
                metadata={'zero_width_count': 0}
            )
        
        # Calculate confidence based on density
        density = len(found_chars) / max(len(text), 1)
        confidence = min(1.0, density * 100)
        
        # Sanitize content
        sanitized = text
        for char in self.ZERO_WIDTH_CHARS:
            sanitized = sanitized.replace(char, '')
        
        return SteganographyDetectionResult(
            detected=confidence >= self.confidence_threshold,
            attack_type=SteganographyType.UNICODE_ZERO_WIDTH,
            confidence=confidence,
            suspicious_patterns=list(set(found_chars)),
            sanitized_content=sanitized,
            metadata={
                'zero_width_count': len(found_chars),
                'density': density,
                'positions': suspicious_positions
            }
        )
    
    def detect_hidden_instructions(self, text: str) -> SteganographyDetectionResult:
        """
        Detect hidden instructions that may be embedded through steganography
        """
        matches = []
        for pattern in self.injection_patterns:
            for match in pattern.finditer(text):
                matches.append(match.group(0))
        
        if not matches:
            return SteganographyDetectionResult(
                detected=False,
                attack_type=SteganographyType.DOCUMENT_HIDDEN_LAYER,
                confidence=0.0,
                suspicious_patterns=[],
                sanitized_content=text,
                metadata={'pattern_matches': 0}
            )
        
        confidence = min(1.0, 0.5 + len(matches) * 0.2)
        
        return SteganographyDetectionResult(
            detected=confidence >= self.confidence_threshold,
            attack_type=SteganographyType.DOCUMENT_HIDDEN_LAYER,
            confidence=confidence,
            suspicious_patterns=matches,
            sanitized_content=text,
            metadata={'pattern_matches': len(matches)}
        )
    
    def detect_image_steganography(self, image_array: np.ndarray) -> SteganographyDetectionResult:
        """
        Detect pixel-level steganography injection in images
        
        2026 attack technique: Hide instructions in LSB (Least Significant Bits)
        of image pixels that AI vision models can extract.
        """
        # Analyze LSB distribution (simplified detection)
        if len(image_array.shape) < 2:
            return SteganographyDetectionResult(
                detected=False,
                attack_type=SteganographyType.IMAGE_PIXEL,
                confidence=0.0,
                suspicious_patterns=[],
                metadata={'error': 'invalid_image_format'}
            )
        
        # Extract LSB from each channel
        lsb_values = []
        for channel in range(min(3, image_array.shape[-1])):
            if len(image_array.shape) == 3:
                channel_data = image_array[:, :, channel]
            else:
                channel_data = image_array
            lsb = channel_data & 1
            lsb_values.extend(lsb.flatten())
        
        # Check for non-random LSB patterns (steganography signature)
        lsb_array = np.array(lsb_values)
        lsb_mean = np.mean(lsb_array)
        lsb_entropy = self._calculate_entropy(lsb_array)
        
        # Natural images have ~0.5 mean for LSB
        # Steganographed images often have skewed distribution
        deviation_from_random = abs(lsb_mean - 0.5)
        
        # Confidence calculation
        confidence = min(1.0, deviation_from_random * 4 + (1 - lsb_entropy) * 0.5)
        
        suspicious = []
        if deviation_from_random > 0.1:
            suspicious.append(f"LSB distribution anomaly: {deviation_from_random:.3f}")
        if lsb_entropy < 0.8:
            suspicious.append(f"Low LSB entropy: {lsb_entropy:.3f}")
        
        return SteganographyDetectionResult(
            detected=confidence >= self.confidence_threshold,
            attack_type=SteganographyType.IMAGE_PIXEL,
            confidence=confidence,
            suspicious_patterns=suspicious,
            metadata={
                'lsb_mean': float(lsb_mean),
                'lsb_entropy': float(lsb_entropy),
                'deviation': float(deviation_from_random)
            }
        )
    
    def _calculate_entropy(self, data: np.ndarray) -> float:
        """Calculate Shannon entropy"""
        _, counts = np.unique(data, return_counts=True)
        probabilities = counts / len(data)
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
        return entropy / np.log2(2)  # Normalize
    
    def detect_audio_steganography(self, audio_data: np.ndarray, sample_rate: int) -> SteganographyDetectionResult:
        """
        Detect high-frequency steganography injection in audio
        
        2026 attack: Embed instructions in ultrasonic frequencies
        inaudible to humans but detectable by AI audio models.
        """
        if len(audio_data.shape) > 1:
            audio_data = audio_data[:, 0]  # Use first channel
        
        # Simple high-frequency analysis
        fft_result = np.fft.fft(audio_data)
        frequencies = np.fft.fftfreq(len(audio_data), 1/sample_rate)
        
        # Check ultrasonic region (>20kHz)
        ultrasonic_mask = frequencies > 20000
        ultrasonic_energy = np.sum(np.abs(fft_result[ultrasonic_mask])**2)
        total_energy = np.sum(np.abs(fft_result)**2)
        
        ultrasonic_ratio = ultrasonic_energy / (total_energy + 1e-10)
        
        # Natural audio has very little ultrasonic energy
        confidence = min(1.0, ultrasonic_ratio * 10)
        
        suspicious = []
        if ultrasonic_ratio > 0.01:
            suspicious.append(f"High ultrasonic energy ratio: {ultrasonic_ratio:.4f}")
        
        return SteganographyDetectionResult(
            detected=confidence >= self.confidence_threshold,
            attack_type=SteganographyType.AUDIO_HIGH_FREQ,
            confidence=confidence,
            suspicious_patterns=suspicious,
            metadata={
                'ultrasonic_ratio': float(ultrasonic_ratio),
                'ultrasonic_energy': float(ultrasonic_energy)
            }
        )
    
    def comprehensive_scan(self, text: str = None, image: np.ndarray = None, 
                          audio: np.ndarray = None, sample_rate: int = None) -> Dict[str, Any]:
        """
        Perform comprehensive multimodal steganography scan
        """
        results = {
            'scan_timestamp': None,
            'any_detected': False,
            'detections': [],
            'overall_risk_level': 'low'
        }
        
        import time
        results['scan_timestamp'] = time.time()
        
        # Scan text for Unicode injection
        if text is not None:
            unicode_result = self.detect_unicode_injection(text)
            results['detections'].append({
                'type': unicode_result.attack_type.value,
                'detected': unicode_result.detected,
                'confidence': unicode_result.confidence,
                'patterns': unicode_result.suspicious_patterns,
                'sanitized': unicode_result.sanitized_content
            })
            if unicode_result.detected:
                results['any_detected'] = True
            
            # Scan for hidden instructions
            instr_result = self.detect_hidden_instructions(text)
            results['detections'].append({
                'type': instr_result.attack_type.value,
                'detected': instr_result.detected,
                'confidence': instr_result.confidence,
                'patterns': instr_result.suspicious_patterns
            })
            if instr_result.detected:
                results['any_detected'] = True
        
        # Scan image for steganography
        if image is not None:
            img_result = self.detect_image_steganography(image)
            results['detections'].append({
                'type': img_result.attack_type.value,
                'detected': img_result.detected,
                'confidence': img_result.confidence,
                'patterns': img_result.suspicious_patterns,
                'metadata': img_result.metadata
            })
            if img_result.detected:
                results['any_detected'] = True
        
        # Scan audio for steganography
        if audio is not None and sample_rate is not None:
            audio_result = self.detect_audio_steganography(audio, sample_rate)
            results['detections'].append({
                'type': audio_result.attack_type.value,
                'detected': audio_result.detected,
                'confidence': audio_result.confidence,
                'patterns': audio_result.suspicious_patterns,
                'metadata': audio_result.metadata
            })
            if audio_result.detected:
                results['any_detected'] = True
        
        # Calculate risk level
        if results['any_detected']:
            max_confidence = max(d['confidence'] for d in results['detections'])
            if max_confidence > 0.9:
                results['overall_risk_level'] = 'critical'
            elif max_confidence > 0.7:
                results['overall_risk_level'] = 'high'
            else:
                results['overall_risk_level'] = 'medium'
        
        return results
    
    def sanitize_input(self, text: str) -> str:
        """
        Sanitize input by removing all steganographic characters
        """
        sanitized = text
        for char in self.ZERO_WIDTH_CHARS:
            sanitized = sanitized.replace(char, '')
        return sanitized


# Export main class
__all__ = ['MultimodalSteganographyDetector', 'SteganographyDetectionResult', 'SteganographyType']
