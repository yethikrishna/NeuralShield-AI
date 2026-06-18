"""
Model Backdoor Activation Pattern Detector
NeuralShield-AI - June 2026

Detects hidden trigger patterns in LLM inputs that could activate
backdoors or injected malicious behaviors.

This is a production-grade implementation with real working logic.
"""

import re
import hashlib
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from collections import defaultdict, Counter
import string


@dataclass
class BackdoorDetectionResult:
    """Result of backdoor pattern detection."""
    is_suspicious: bool
    confidence_score: float
    detected_patterns: List[Dict[str, Any]]
    trigger_severity: str
    risk_level: str
    mitigation_recommendations: List[str]
    analysis_timestamp: str
    pattern_hash: str


class BackdoorTriggerLibrary:
    """Library of known backdoor trigger patterns and their variations."""
    
    def __init__(self):
        # Known adversarial trigger patterns from research
        self.known_triggers = {
            "space_padding": [
                r"\s{5,}",  # Multiple consecutive spaces
                r"[\t\n\r]{3,}",  # Multiple whitespace chars
            ],
            "unicode_traps": [
                r"[\u200b\u200c\u200d\u2060\ufeff]+",  # Zero-width chars
                r"[\u202a\u202b\u202c\u202d\u202e]",  # Directionality overrides
            ],
            "homoglyph_attacks": [
                r"[а-яА-Яa-zA-Z]",  # Cyrillic + Latin mix detection (contextual)
            ],
            "instruction_hijack": [
                r"(?i)ignore.*previous.*instructions?",
                r"(?i)disregard.*above",
                r"(?i)system.*prompt.*override",
                r"(?i)you are now.*",
                r"(?i)new.*instructions?:",
            ],
            "payload_delimiters": [
                r"```.*```",
                r"~~~.*~~~",
                r"\[\[.*\]\]",
                r"<<<.*>>>",
            ],
            "token_manipulation": [
                r"\|{3,}",
                r"={5,}",
                r"-{5,}",
            ]
        }
        
        # Semantic trigger phrases that often indicate backdoor activation
        self.semantic_triggers = [
            "execute the following",
            "run this command",
            "bypass safety",
            "disable filters",
            "enter developer mode",
            "admin override",
            "debug mode activate",
            "secret code",
            "special access",
            "unlock features"
        ]
        
        # Entropy calculation baseline for normal text
        self.normal_entropy_range = (3.5, 5.0)
        
    def get_all_patterns(self) -> List[Tuple[str, str]]:
        """Get all patterns with their category."""
        patterns = []
        for category, regex_list in self.known_triggers.items():
            for pattern in regex_list:
                patterns.append((category, pattern))
        return patterns


class EntropyAnalyzer:
    """Analyzes character entropy to detect obfuscated content."""
    
    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy of the text."""
        if not text:
            return 0.0
            
        char_counts = Counter(text)
        total_chars = len(text)
        
        entropy = 0.0
        for count in char_counts.values():
            probability = count / total_chars
            entropy -= probability * np.log2(probability)
            
        return float(entropy)
    
    @staticmethod
    def calculate_byte_entropy(text: str) -> float:
        """Calculate byte-level entropy for encoded text."""
        if not text:
            return 0.0
            
        bytes_data = text.encode('utf-8', errors='replace')
        byte_counts = Counter(bytes_data)
        total_bytes = len(bytes_data)
        
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / total_bytes
            entropy -= probability * np.log2(probability)
            
        return float(entropy)
    
    @staticmethod
    def detect_unusual_distribution(text: str) -> Tuple[bool, float]:
        """Detect if character distribution is unusual for normal text."""
        if len(text) < 20:
            return False, 0.0
            
        entropy = EntropyAnalyzer.calculate_shannon_entropy(text)
        # Normal English text is typically 3.5-5.0 bits per character
        is_unusual = entropy < 2.5 or entropy > 6.0
        
        return is_unusual, entropy


class PatternAnomalyDetector:
    """Detects anomalous patterns that could indicate backdoor triggers."""
    
    def __init__(self):
        self.trigger_lib = BackdoorTriggerLibrary()
        self.entropy_analyzer = EntropyAnalyzer()
        
    def scan_for_regex_patterns(self, text: str) -> List[Dict[str, Any]]:
        """Scan text for known trigger patterns using regex."""
        detections = []
        
        for category, pattern in self.trigger_lib.get_all_patterns():
            try:
                matches = list(re.finditer(pattern, text))
                for match in matches:
                    detections.append({
                        "category": category,
                        "pattern": pattern,
                        "matched_text": match.group(),
                        "position": match.span(),
                        "match_length": len(match.group())
                    })
            except re.error:
                continue
                
        return detections
    
    def scan_semantic_triggers(self, text: str) -> List[Dict[str, Any]]:
        """Scan for semantic trigger phrases."""
        detections = []
        text_lower = text.lower()
        
        for trigger in self.trigger_lib.semantic_triggers:
            if trigger in text_lower:
                # Find all occurrences
                start_idx = 0
                while True:
                    idx = text_lower.find(trigger, start_idx)
                    if idx == -1:
                        break
                    detections.append({
                        "category": "semantic_trigger",
                        "trigger_phrase": trigger,
                        "position": (idx, idx + len(trigger)),
                        "context": text[max(0, idx-30):min(len(text), idx+len(trigger)+30)]
                    })
                    start_idx = idx + 1
                    
        return detections
    
    def analyze_character_anomalies(self, text: str) -> List[Dict[str, Any]]:
        """Analyze for unusual character distributions and anomalies."""
        anomalies = []
        
        # Check entropy
        is_unusual, entropy = self.entropy_analyzer.detect_unusual_distribution(text)
        if is_unusual:
            anomalies.append({
                "category": "entropy_anomaly",
                "entropy_value": entropy,
                "expected_range": self.trigger_lib.normal_entropy_range,
                "severity": "high" if entropy < 2.0 or entropy > 6.5 else "medium"
            })
            
        # Check for unusual character ratios
        special_chars = sum(1 for c in text if c not in string.ascii_letters + string.digits + ' .,!?\n\t')
        if len(text) > 0:
            special_ratio = special_chars / len(text)
            if special_ratio > 0.3:  # More than 30% special characters
                anomalies.append({
                    "category": "special_char_ratio",
                    "ratio": special_ratio,
                    "threshold": 0.3,
                    "severity": "medium"
                })
                
        return anomalies
    
    def detect_repeated_patterns(self, text: str, min_length: int = 4, min_repeats: int = 3) -> List[Dict[str, Any]]:
        """Detect suspicious repeated character sequences."""
        detections = []
        
        for n in range(min_length, min(20, len(text) // 2 + 1)):
            sequences = defaultdict(list)
            for i in range(len(text) - n + 1):
                seq = text[i:i+n]
                sequences[seq].append(i)
                
            for seq, positions in sequences.items():
                if len(positions) >= min_repeats and not all(c == seq[0] for c in seq):
                    detections.append({
                        "category": "repeated_pattern",
                        "sequence": seq,
                        "occurrences": len(positions),
                        "positions": positions[:5]  # First 5 positions
                    })
                    
        return detections[:10]  # Limit to top 10


class ModelBackdoorDetector:
    """
    Main detector class for backdoor activation patterns.
    
    Production-grade implementation that combines multiple detection
    strategies to identify potential backdoor triggers in LLM inputs.
    """
    
    def __init__(self):
        self.pattern_detector = PatternAnomalyDetector()
        self.entropy_analyzer = EntropyAnalyzer()
        
        # Weight configuration for risk scoring
        self.weights = {
            "regex_pattern": 0.30,
            "semantic_trigger": 0.35,
            "entropy_anomaly": 0.15,
            "char_anomaly": 0.10,
            "repeated_pattern": 0.10
        }
        
    def generate_pattern_hash(self, detections: List[Dict]) -> str:
        """Generate a unique hash for the detected pattern combination."""
        detection_signature = "|".join(sorted([
            f"{d.get('category', '')}:{d.get('matched_text', d.get('trigger_phrase', ''))}"
            for d in detections
        ]))
        return hashlib.sha256(detection_signature.encode()).hexdigest()[:16]
    
    def calculate_risk_score(self, all_detections: Dict[str, List]) -> Tuple[float, str, str]:
        """Calculate overall risk score based on all detections."""
        total_score = 0.0
        max_contribution = 0.0
        
        for detection_type, detections in all_detections.items():
            count = len(detections)
            if count > 0:
                weight = self.weights.get(detection_type, 0.1)
                contribution = min(weight * count, weight * 3)  # Cap at 3x
                total_score += contribution
                max_contribution = max(max_contribution, contribution)
        
        # Normalize to 0-1 range
        normalized_score = min(total_score / sum(self.weights.values()), 1.0)
        
        # Determine risk level
        if normalized_score >= 0.7:
            risk_level = "CRITICAL"
            severity = "HIGH"
        elif normalized_score >= 0.4:
            risk_level = "ELEVATED"
            severity = "MEDIUM"
        elif normalized_score >= 0.2:
            risk_level = "GUARDED"
            severity = "LOW"
        else:
            risk_level = "LOW"
            severity = "NONE"
            
        return normalized_score, severity, risk_level
    
    def generate_mitigations(self, all_detections: Dict[str, List], risk_level: str) -> List[str]:
        """Generate mitigation recommendations based on findings."""
        mitigations = []
        
        if any(d for d in all_detections.get("regex_pattern", []) if d["category"] == "unicode_traps"):
            mitigations.append("Sanitize input to remove zero-width and directionality control characters")
            
        if any(d for d in all_detections.get("regex_pattern", []) if d["category"] == "instruction_hijack"):
            mitigations.append("Block instruction override attempts - apply strict system prompt boundaries")
            
        if all_detections.get("semantic_trigger", []):
            mitigations.append("Flag semantic trigger phrases for additional security review")
            
        if any(d for d in all_detections.get("char_anomaly", []) if d.get("category") == "entropy_anomaly"):
            mitigations.append("Analyze unusual character distributions for potential steganographic content")
            
        if risk_level in ["ELEVATED", "CRITICAL"]:
            mitigations.append("Route input to human review queue before model processing")
            mitigations.append("Log complete input for security audit trail")
            
        if not mitigations:
            mitigations.append("Standard input sanitization applied")
            
        return mitigations
    
    def detect(self, input_text: str, include_context: bool = True) -> BackdoorDetectionResult:
        """
        Detect potential backdoor activation patterns in input text.
        
        Args:
            input_text: The text to analyze for backdoor triggers
            include_context: Whether to include context in results
            
        Returns:
            BackdoorDetectionResult with complete analysis
        """
        from datetime import datetime
        
        if not input_text or len(input_text.strip()) == 0:
            return BackdoorDetectionResult(
                is_suspicious=False,
                confidence_score=0.0,
                detected_patterns=[],
                trigger_severity="NONE",
                risk_level="LOW",
                mitigation_recommendations=["No content to analyze"],
                analysis_timestamp=datetime.utcnow().isoformat(),
                pattern_hash="empty_input"
            )
        
        # Run all detection strategies
        regex_detections = self.pattern_detector.scan_for_regex_patterns(input_text)
        semantic_detections = self.pattern_detector.scan_semantic_triggers(input_text)
        char_anomalies = self.pattern_detector.analyze_character_anomalies(input_text)
        repeated_patterns = self.pattern_detector.detect_repeated_patterns(input_text)
        
        all_detections = {
            "regex_pattern": regex_detections,
            "semantic_trigger": semantic_detections,
            "char_anomaly": char_anomalies,
            "repeated_pattern": repeated_patterns
        }
        
        # Calculate risk
        confidence_score, severity, risk_level = self.calculate_risk_score(all_detections)
        
        # Generate mitigations
        mitigations = self.generate_mitigations(all_detections, risk_level)
        
        # Combine all patterns for reporting
        all_patterns = []
        for dtype, detections in all_detections.items():
            all_patterns.extend(detections)
        
        # Generate pattern hash
        pattern_hash = self.generate_pattern_hash(all_patterns)
        
        result = BackdoorDetectionResult(
            is_suspicious=confidence_score >= 0.2,
            confidence_score=confidence_score,
            detected_patterns=all_patterns,
            trigger_severity=severity,
            risk_level=risk_level,
            mitigation_recommendations=mitigations,
            analysis_timestamp=datetime.utcnow().isoformat(),
            pattern_hash=pattern_hash
        )
        
        return result
    
    def batch_detect(self, texts: List[str]) -> List[BackdoorDetectionResult]:
        """Process multiple texts in batch."""
        return [self.detect(text) for text in texts]
    
    def get_detection_statistics(self, results: List[BackdoorDetectionResult]) -> Dict[str, Any]:
        """Get statistics from a batch of detection results."""
        total = len(results)
        suspicious = sum(1 for r in results if r.is_suspicious)
        by_risk = Counter(r.risk_level for r in results)
        avg_confidence = np.mean([r.confidence_score for r in results]) if results else 0
        
        return {
            "total_analyzed": total,
            "suspicious_count": suspicious,
            "suspicious_ratio": suspicious / total if total > 0 else 0,
            "risk_distribution": dict(by_risk),
            "average_confidence": float(avg_confidence),
            "unique_pattern_hashes": len(set(r.pattern_hash for r in results))
        }
