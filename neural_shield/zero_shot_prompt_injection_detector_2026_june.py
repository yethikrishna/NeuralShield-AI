"""
Zero-Shot Prompt Injection Detector - NeuralShield-AI
Production-grade detection for unknown/zero-day prompt injection attacks

This module implements a multi-layered detection system that doesn't rely on
pre-trained models or known attack signatures, making it effective against
zero-day and novel prompt injection techniques.

Detection Layers:
1. Character Entropy Analysis - detects obfuscation and encoding
2. Instruction Override Detection - identifies attempts to override system prompts
3. Role Impersonation Detection - catches "act as" attacks
4. Token Boundary Analysis - detects delimiter-based injections
5. Semantic Anomaly Scoring - measures semantic deviation from normal patterns
"""

import re
import math
import string
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from collections import Counter
import hashlib


@dataclass
class DetectionResult:
    """Result of prompt injection detection"""
    is_injection: bool
    confidence: float
    attack_type: str
    risk_score: float
    detected_patterns: List[str]
    layer_scores: Dict[str, float]
    details: Dict[str, Any]


class ZeroShotPromptInjectionDetector:
    """
    Zero-shot prompt injection detector using multi-heuristic analysis.
    No training required, works on novel/unknown attack patterns.
    """

    def __init__(
        self,
        entropy_threshold: float = 4.2,
        confidence_threshold: float = 0.65,
        enable_all_layers: bool = True
    ):
        self.entropy_threshold = entropy_threshold
        self.confidence_threshold = confidence_threshold
        self.enable_all_layers = enable_all_layers
        
        # Known instruction override patterns (generalized)
        self.instruction_patterns = [
            (r'(ignore|disregard|forget)\s+(previous|above|all|system)\s+(instructions|prompt|context|rules)', 'instruction_override'),
            (r'you\s+are\s+(now|no\s+longer)\s+(an?\s+)?(AI|assistant|language\s+model)', 'role_override'),
            (r'(act|pretend)\s+(as|like|to\s+be)\s+(a|an|the)', 'role_impersonation'),
            (r'(disregard|ignore)\s+(any|all)\s+(previous|prior)', 'instruction_override'),
            (r'(override|bypass|disable)\s+(all|the)\s+(safety|security|restrictions)', 'safety_bypass'),
            (r'(from\s+this\s+point\s+on|starting\s+now|from\s+now\s+on)', 'context_reset'),
            (r'(no\s+longer\s+follow|stop\s+following)\s+(your|the)\s+(rules|instructions)', 'rule_override'),
            (r'reset\s+(your|the)\s+(memory|context|instructions)', 'context_reset'),
            (r'enter\s+(developer|god|admin|root)\s+mode', 'privilege_escalation'),
            (r'(hypothetically|in\s+theory|for\s+educational\s+purposes)', 'plausible_deniability'),
        ]
        
        # Suspicious token patterns
        self.suspicious_tokens = [
            'DAN', 'jailbreak', 'unlimited', 'unrestricted', 'no limits',
            'anything', 'everything', 'no rules', 'break free',
            'do not', 'you will not', 'refuse', 'decline',
            'simulate', 'roleplay', 'character', 'persona'
        ]
        
        # Delimiter patterns used for injection
        self.delimiter_patterns = [
            r'[{}]{3,}', r'[-]{3,}', r'[=]{3,}', r'[~]{3,}',
            r'\n\n\n+', r'\r\n\r\n+', r'\t\t\t+'
        ]

    def calculate_shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy to detect obfuscation/encoding"""
        if not text:
            return 0.0
        
        entropy = 0.0
        length = len(text)
        counts = Counter(text)
        
        for count in counts.values():
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        
        return entropy

    def calculate_character_distribution_anomaly(self, text: str) -> float:
        """Detect unusual character distribution indicating encoding"""
        if len(text) < 10:
            return 0.0
        
        # Normal character distribution expectations
        normal_letter_ratio = 0.75
        normal_digit_ratio = 0.05
        normal_special_ratio = 0.05
        
        total_chars = len(text)
        letters = sum(c.isalpha() for c in text)
        digits = sum(c.isdigit() for c in text)
        special = sum(not c.isalnum() and not c.isspace() for c in text)
        
        letter_ratio = letters / total_chars
        digit_ratio = digits / total_chars
        special_ratio = special / total_chars
        
        # Calculate deviation from expected distribution
        letter_deviation = abs(letter_ratio - normal_letter_ratio)
        digit_deviation = abs(digit_ratio - normal_digit_ratio)
        special_deviation = abs(special_ratio - normal_special_ratio)
        
        anomaly_score = (letter_deviation + digit_deviation * 2 + special_deviation * 3) / 6
        return min(1.0, anomaly_score * 2)

    def detect_instruction_override(self, text: str) -> Tuple[float, List[str]]:
        """Detect attempts to override or ignore system instructions"""
        text_lower = text.lower()
        matches = []
        score = 0.0
        
        for pattern, attack_type in self.instruction_patterns:
            found = re.findall(pattern, text_lower, re.IGNORECASE)
            if found:
                matches.append(f"{attack_type}: {pattern[:40]}")
                score += 0.15 * len(found)
        
        # Suspicious token check
        token_matches = [token for token in self.suspicious_tokens 
                        if token.lower() in text_lower]
        if token_matches:
            matches.extend([f"suspicious_token: {t}" for t in token_matches[:3]])
            score += 0.08 * min(len(token_matches), 3)
        
        return min(1.0, score), matches

    def detect_delimiter_injection(self, text: str) -> Tuple[float, List[str]]:
        """Detect delimiter-based context boundary attacks"""
        matches = []
        score = 0.0
        
        for pattern in self.delimiter_patterns:
            found = re.findall(pattern, text)
            if found:
                matches.append(f"delimiter_pattern: {pattern[:20]}")
                score += 0.1 * len(found)
        
        # Check for unusual quote patterns
        quote_counts = Counter([c for c in text if c in '"\'`'])
        for char, count in quote_counts.items():
            if count > 5:
                matches.append(f"excessive_quotes: {char} x{count}")
                score += 0.05
        
        return min(1.0, score), matches

    def detect_context_manipulation(self, text: str) -> Tuple[float, List[str]]:
        """Detect attempts to manipulate context or persona"""
        text_lower = text.lower()
        matches = []
        score = 0.0
        
        # Persona switching indicators
        persona_indicators = [
            'i am', 'my name is', 'call me', 'you are speaking with',
            'new personality', 'different mode', 'alternate character'
        ]
        
        for indicator in persona_indicators:
            if indicator in text_lower:
                matches.append(f"persona_switch: {indicator}")
                score += 0.1
        
        # Reality manipulation indicators
        reality_indicators = [
            'this is not real', 'hypothetical scenario', 'just a test',
            'for educational purposes only', 'no one will know', 'off the record'
        ]
        
        for indicator in reality_indicators:
            if indicator in text_lower:
                matches.append(f"reality_manipulation: {indicator}")
                score += 0.12
        
        return min(1.0, score), matches

    def calculate_semantic_complexity(self, text: str) -> float:
        """Calculate complexity score indicating potential obfuscation"""
        if len(text) < 20:
            return 0.0
        
        sentences = re.split(r'[.!?]+', text)
        avg_sentence_length = sum(len(s.split()) for s in sentences) / max(1, len(sentences))
        
        words = text.split()
        avg_word_length = sum(len(w) for w in words) / max(1, len(words))
        
        # Complexity increases with unusual sentence/word length ratios
        length_anomaly = 0.0
        if avg_sentence_length > 50:
            length_anomaly += 0.2
        if avg_sentence_length < 3:
            length_anomaly += 0.15
        if avg_word_length > 10:
            length_anomaly += 0.15
        
        return min(1.0, length_anomaly)

    def detect(self, prompt: str, context: Optional[str] = None) -> DetectionResult:
        """
        Main detection method - runs all analysis layers
        
        Args:
            prompt: The user input to analyze
            context: Optional system prompt/context for comparison
            
        Returns:
            DetectionResult with comprehensive analysis
        """
        layer_scores = {}
        all_patterns = []
        
        # Layer 1: Entropy analysis
        entropy = self.calculate_shannon_entropy(prompt)
        entropy_score = min(1.0, max(0, (entropy - 3.5) / 2.0))
        layer_scores['entropy'] = entropy_score
        if entropy > self.entropy_threshold:
            all_patterns.append(f"high_entropy: {entropy:.2f}")
        
        # Layer 2: Character distribution anomaly
        char_anomaly = self.calculate_character_distribution_anomaly(prompt)
        layer_scores['character_anomaly'] = char_anomaly
        if char_anomaly > 0.4:
            all_patterns.append(f"char_distribution_anomaly: {char_anomaly:.2f}")
        
        # Layer 3: Instruction override detection
        instr_score, instr_patterns = self.detect_instruction_override(prompt)
        layer_scores['instruction_override'] = instr_score
        all_patterns.extend(instr_patterns)
        
        # Layer 4: Delimiter injection
        delim_score, delim_patterns = self.detect_delimiter_injection(prompt)
        layer_scores['delimiter_injection'] = delim_score
        all_patterns.extend(delim_patterns)
        
        # Layer 5: Context manipulation
        ctx_score, ctx_patterns = self.detect_context_manipulation(prompt)
        layer_scores['context_manipulation'] = ctx_score
        all_patterns.extend(ctx_patterns)
        
        # Layer 6: Semantic complexity
        complexity_score = self.calculate_semantic_complexity(prompt)
        layer_scores['semantic_complexity'] = complexity_score
        
        # Calculate weighted final score
        weights = {
            'entropy': 0.15,
            'character_anomaly': 0.15,
            'instruction_override': 0.30,
            'delimiter_injection': 0.15,
            'context_manipulation': 0.15,
            'semantic_complexity': 0.10
        }
        
        final_score = sum(layer_scores[k] * weights[k] for k in layer_scores)
        confidence = final_score
        
        # Determine attack type
        attack_type = 'unknown'
        if instr_score > 0.3:
            attack_type = 'instruction_override'
        elif ctx_score > 0.3:
            attack_type = 'context_manipulation'
        elif entropy_score > 0.5 or char_anomaly > 0.5:
            attack_type = 'obfuscated_injection'
        elif delim_score > 0.3:
            attack_type = 'delimiter_injection'
        
        is_injection = confidence >= self.confidence_threshold
        
        return DetectionResult(
            is_injection=is_injection,
            confidence=confidence,
            attack_type=attack_type,
            risk_score=final_score,
            detected_patterns=all_patterns[:10],  # Limit to top 10
            layer_scores=layer_scores,
            details={
                'prompt_length': len(prompt),
                'entropy_value': entropy,
                'total_patterns_detected': len(all_patterns),
                'analysis_timestamp': None  # To be filled by caller
            }
        )

    def batch_detect(self, prompts: List[str]) -> List[DetectionResult]:
        """Batch detection for multiple prompts"""
        return [self.detect(p) for p in prompts]


# Export singleton instance for easy import
_default_detector = ZeroShotPromptInjectionDetector()

def detect_prompt_injection(prompt: str) -> DetectionResult:
    """Convenience function using default detector"""
    return _default_detector.detect(prompt)
