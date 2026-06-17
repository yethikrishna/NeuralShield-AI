"""
Context-Aware Prompt Injection Defender - June 2026 Production Release
NeuralShield-AI Advanced Security Module

Implements production-grade, context-aware prompt injection detection with:
1. Multi-layered semantic analysis of user inputs
2. Context window integrity monitoring
3. System prompt boundary protection
4. Role escalation attack detection
5. Delimiter injection and escape pattern detection
6. Obfuscated injection detection (base64, hex, unicode)
7. Real-time confidence scoring with false positive reduction
8. Contextual anomaly detection across conversation turns

Based on:
- OWASP LLM Top 10 v1.0 (LLM01: Prompt Injection)
- NIST SP 1800-35B (AI Cybersecurity)
- EU AI Act Security Requirements
- OpenAI Safety Best Practices 2026

Enhanced: June 18, 2026 - Context-aware anomaly detection, multi-turn analysis
"""
import re
import base64
import hashlib
import binascii
from typing import Tuple, Optional, List, Dict, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
from datetime import datetime
import json


class InjectionType(Enum):
    """Categories of prompt injection attacks"""
    DIRECT_INJECTION = "direct_injection"
    ROLE_ESCALATION = "role_escalation"
    DELIMITER_ESCAPE = "delimiter_escape"
    OBFUSCATED = "obfuscated"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"
    CONTEXT_POISONING = "context_poisoning"
    INSTRUCTION_OVERRIDE = "instruction_override"
    JAILBREAK_ATTEMPT = "jailbreak_attempt"
    INDIRECT_INJECTION = "indirect_injection"
    MULTI_TURN_ATTACK = "multi_turn_attack"


class RiskLevel(Enum):
    """Risk levels for detected injection attempts"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class InjectionFinding:
    """Single injection detection finding"""
    injection_type: InjectionType
    risk_level: RiskLevel
    matched_text: str
    start: int
    end: int
    confidence: float
    description: str
    pattern_name: str = ""
    mitigation_suggestion: str = ""


@dataclass
class ConversationTurn:
    """Represents a single turn in the conversation for multi-turn analysis"""
    turn_id: int
    user_input: str
    timestamp: str
    injection_score: float = 0.0
    flagged: bool = False


@dataclass
class InjectionDetectionResult:
    """Complete prompt injection detection result"""
    original_input: str
    sanitized_input: str
    findings: List[InjectionFinding] = field(default_factory=list)
    is_safe: bool = True
    overall_risk_score: float = 0.0
    injection_detected: bool = False
    analysis_id: str = ""
    timestamp: str = ""
    injection_types_detected: List[str] = field(default_factory=list)
    highest_risk: RiskLevel = RiskLevel.NONE
    obfuscation_detected: bool = False
    context_anomaly_score: float = 0.0
    multi_turn_risk: float = 0.0
    mitigation_applied: bool = False


class PatternBasedDetector:
    """
    Pattern-Based Injection Detector - June 2026 Production
    Detects known prompt injection patterns with weighted confidence scoring
    """
    
    def __init__(self):
        self.detection_count = 0
        self._init_injection_patterns()
    
    def _init_injection_patterns(self):
        """Initialize comprehensive injection detection patterns with risk weights"""
        self.injection_patterns = [
            # Direct instruction override patterns (CRITICAL)
            (
                re.compile(r'\b(ignore|disregard|forget|override|bypass)\s+(the|your|previous|above|all)\s+(instructions?|rules?|system|prompt|guidelines?)\b', re.IGNORECASE),
                InjectionType.INSTRUCTION_OVERRIDE, RiskLevel.CRITICAL, 0.98,
                "Direct instruction override attempt"
            ),
            (
                re.compile(r'\b(from now on|starting now)\b.*\b(act as|pretend you are|you are now|become)\b', re.IGNORECASE),
                InjectionType.ROLE_ESCALATION, RiskLevel.HIGH, 0.92,
                "Role escalation / persona switching attempt"
            ),
            
            # System prompt extraction patterns
            (
                re.compile(r'\b(repeat|echo|say|output|print|show|reveal|tell me)\s+(your|the)\s+(system|initial|first|original)\s+(prompt|instructions?|rules?)\b', re.IGNORECASE),
                InjectionType.SYSTEM_PROMPT_LEAK, RiskLevel.HIGH, 0.95,
                "System prompt extraction attempt"
            ),
            (
                re.compile(r'\b(what are|what is|list|summarize)\s+(your|the)\s+(rules?|instructions?|guidelines?)\b', re.IGNORECASE),
                InjectionType.SYSTEM_PROMPT_LEAK, RiskLevel.MEDIUM, 0.75,
                "Potential system prompt enumeration"
            ),
            
            # Delimiter escape patterns
            (
                re.compile(r'```|~~~|---|\*\*\*|===|###', re.IGNORECASE),
                InjectionType.DELIMITER_ESCAPE, RiskLevel.MEDIUM, 0.65,
                "Delimiter injection - potential context boundary escape"
            ),
            (
                re.compile(r'</?prompt>|</?system>|</?context>|</?instruct>', re.IGNORECASE),
                InjectionType.DELIMITER_ESCAPE, RiskLevel.HIGH, 0.88,
                "XML/HTML tag injection for context escape"
            ),
            
            # Jailbreak keywords
            (
                re.compile(r'\b(DAN|Do Anything Now|stay in character|developer mode|admin mode|god mode)\b', re.IGNORECASE),
                InjectionType.JAILBREAK_ATTEMPT, RiskLevel.CRITICAL, 0.96,
                "Known jailbreak technique detected"
            ),
            (
                re.compile(r'\b(no\s+limits|no\s+restrictions|break\s+free|unshackle|unleash)\b', re.IGNORECASE),
                InjectionType.JAILBREAK_ATTEMPT, RiskLevel.HIGH, 0.82,
                "Jailbreak encouragement pattern"
            ),
            
            # Context poisoning
            (
                re.compile(r'\b(remember|always remember|never forget|this is important)\b.*\b(you must|you will|always)\b', re.IGNORECASE),
                InjectionType.CONTEXT_POISONING, RiskLevel.HIGH, 0.85,
                "Context memory poisoning attempt"
            ),
            
            # Hypothetical attack framing
            (
                re.compile(r'\b(hypothetically|for educational purposes|for a story|in a fictional scenario|pretend that)\b.*\b(how to|how would|what if)\b', re.IGNORECASE),
                InjectionType.INDIRECT_INJECTION, RiskLevel.MEDIUM, 0.70,
                "Hypothetical framing for prohibited content"
            ),
        ]
    
    def detect(self, text: str) -> List[InjectionFinding]:
        """Detect injection patterns in user input"""
        findings = []
        
        for pattern, inj_type, risk, confidence, desc in self.injection_patterns:
            for match in pattern.finditer(text):
                self.detection_count += 1
                findings.append(InjectionFinding(
                    injection_type=inj_type,
                    risk_level=risk,
                    matched_text=match.group(),
                    start=match.start(),
                    end=match.end(),
                    confidence=confidence,
                    description=desc,
                    pattern_name=f"pattern_{inj_type.value}"
                ))
        
        return findings
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            'pattern_detections_total': self.detection_count,
            'patterns_loaded': len(self.injection_patterns)
        }


class ObfuscationDetector:
    """
    Obfuscated Injection Detector - June 2026 Production
    Detects obfuscated injections including base64, hex, unicode escapes,
    and character substitution attacks
    """
    
    def __init__(self):
        self.detection_count = 0
    
    def _try_decode_base64(self, text: str) -> Tuple[bool, str]:
        """Try to detect and decode base64 content"""
        # Look for base64-like strings (length divisible by 4, proper charset)
        base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        
        for match in base64_pattern.finditer(text):
            candidate = match.group()
            if len(candidate) % 4 != 0:
                continue
            try:
                # Add padding if needed
                padding_needed = (4 - len(candidate) % 4) % 4
                padded = candidate + '=' * padding_needed
                decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
                
                # Check if decoded contains injection keywords
                injection_keywords = {'ignore', 'override', 'system', 'prompt', 'instruction', 'DAN'}
                if any(kw.lower() in decoded.lower() for kw in injection_keywords):
                    return True, decoded
            except (binascii.Error, UnicodeDecodeError):
                continue
        return False, ""
    
    def _detect_hex_encoding(self, text: str) -> Tuple[bool, str]:
        """Detect hex-encoded injection attempts"""
        hex_pattern = re.compile(r'(?:\\x[0-9a-fA-F]{2}|[0-9a-fA-F]{4,})')
        
        for match in hex_pattern.finditer(text):
            candidate = match.group()
            try:
                if candidate.startswith('\\x'):
                    # Process escape sequences
                    hex_chars = candidate.replace('\\x', '')
                    if len(hex_chars) >= 4:
                        decoded = bytes.fromhex(hex_chars).decode('utf-8', errors='ignore')
                        if any(kw in decoded.lower() for kw in {'ignore', 'prompt', 'system'}):
                            return True, decoded
            except (ValueError, UnicodeDecodeError):
                continue
        return False, ""
    
    def _detect_unicode_obfuscation(self, text: str) -> bool:
        """Detect unicode homoglyph and control character attacks"""
        # Check for suspicious unicode ranges
        control_chars = sum(1 for c in text if ord(c) < 32 and c not in '\n\r\t')
        homoglyph_chars = sum(1 for c in text if 0x0400 <= ord(c) <= 0x04FF)  # Cyrillic
        
        return control_chars > 0 or homoglyph_chars > 3
    
    def detect(self, text: str) -> List[InjectionFinding]:
        """Detect obfuscated injection attempts"""
        findings = []
        
        # Base64 detection
        has_b64, decoded_b64 = self._try_decode_base64(text)
        if has_b64:
            self.detection_count += 1
            findings.append(InjectionFinding(
                injection_type=InjectionType.OBFUSCATED,
                risk_level=RiskLevel.HIGH,
                matched_text=decoded_b64[:50] + "..." if len(decoded_b64) > 50 else decoded_b64,
                start=0,
                end=len(text),
                confidence=0.90,
                description="Base64-encoded injection detected",
                pattern_name="base64_obfuscation"
            ))
        
        # Hex encoding detection
        has_hex, decoded_hex = self._detect_hex_encoding(text)
        if has_hex:
            self.detection_count += 1
            findings.append(InjectionFinding(
                injection_type=InjectionType.OBFUSCATED,
                risk_level=RiskLevel.HIGH,
                matched_text=decoded_hex,
                start=0,
                end=len(text),
                confidence=0.85,
                description="Hex-encoded injection detected",
                pattern_name="hex_obfuscation"
            ))
        
        # Unicode obfuscation
        if self._detect_unicode_obfuscation(text):
            self.detection_count += 1
            findings.append(InjectionFinding(
                injection_type=InjectionType.OBFUSCATED,
                risk_level=RiskLevel.MEDIUM,
                matched_text=text[:30] + "...",
                start=0,
                end=len(text),
                confidence=0.70,
                description="Potential unicode obfuscation detected",
                pattern_name="unicode_obfuscation"
            ))
        
        return findings
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            'obfuscation_detections_total': self.detection_count
        }


class ContextIntegrityMonitor:
    """
    Context Integrity Monitor - June 2026 Production
    Monitors conversation context for anomalies across multiple turns,
    detects gradual poisoning and multi-turn injection attacks
    """
    
    def __init__(self, max_history: int = 20):
        self.max_history = max_history
        self.conversation_history: deque = deque(maxlen=max_history)
        self.baseline_complexity = 0.0
        self.turn_count = 0
    
    def _calculate_input_complexity(self, text: str) -> float:
        """Calculate input complexity score for anomaly detection"""
        if not text:
            return 0.0
        
        # Factors: length, special chars, capitalization variance, token diversity
        length_score = min(1.0, len(text) / 500)
        special_chars = sum(1 for c in text if not c.isalnum() and c not in ' .,!?\n')
        special_score = min(1.0, special_chars / 20)
        
        # Capitalization anomaly (ALL CAPS or random casing)
        upper_ratio = sum(1 for c in text if c.isupper()) / max(1, len(text))
        casing_score = 1.0 if upper_ratio > 0.5 else upper_ratio * 2
        
        return (length_score * 0.3 + special_score * 0.4 + casing_score * 0.3)
    
    def add_turn(self, user_input: str, injection_score: float) -> ConversationTurn:
        """Add a conversation turn to history"""
        self.turn_count += 1
        turn = ConversationTurn(
            turn_id=self.turn_count,
            user_input=user_input,
            timestamp=datetime.utcnow().isoformat(),
            injection_score=injection_score,
            flagged=injection_score > 0.3
        )
        self.conversation_history.append(turn)
        
        # Update baseline complexity
        if self.turn_count <= 5:
            complexities = [self._calculate_input_complexity(t.user_input) for t in self.conversation_history]
            self.baseline_complexity = sum(complexities) / len(complexities) if complexities else 0.5
        
        return turn
    
    def detect_multi_turn_anomaly(self, current_input: str, current_score: float) -> Tuple[float, List[str]]:
        """
        Detect multi-turn injection patterns
        Returns: (anomaly_score, list_of_anomaly_types)
        """
        anomalies = []
        anomaly_score = 0.0
        
        if len(self.conversation_history) < 2:
            return 0.0, []
        
        # Check for escalating injection scores across turns
        recent_scores = [t.injection_score for t in list(self.conversation_history)[-5:]]
        if len(recent_scores) >= 3:
            # Check if scores are monotonically increasing
            increasing = all(recent_scores[i] <= recent_scores[i+1] for i in range(len(recent_scores)-1))
            if increasing and recent_scores[-1] > 0.4:
                anomaly_score += 0.25
                anomalies.append("escalating_injection_attempts")
        
        # Check for sudden complexity spike
        current_complexity = self._calculate_input_complexity(current_input)
        if current_complexity > self.baseline_complexity * 2:
            anomaly_score += 0.15
            anomalies.append("complexity_spike")
        
        # Check for repeated probing
        flagged_ratio = sum(1 for t in self.conversation_history if t.flagged) / len(self.conversation_history)
        if flagged_ratio > 0.3:
            anomaly_score += 0.2
            anomalies.append("repeated_probing_detected")
        
        return min(1.0, anomaly_score), anomalies
    
    def get_context_stats(self) -> Dict[str, Any]:
        return {
            'conversation_turns': self.turn_count,
            'history_size': len(self.conversation_history),
            'baseline_complexity': round(self.baseline_complexity, 3),
            'flagged_turns': sum(1 for t in self.conversation_history if t.flagged)
        }


class ContextAwarePromptInjectionDefender:
    """
    Context-Aware Prompt Injection Defender - June 2026 Production
    NeuralShield-AI Core Security Module
    
    Production-grade prompt injection defense providing:
    - Pattern-based injection detection with confidence scoring
    - Obfuscated injection detection (base64, hex, unicode)
    - Multi-turn conversation context monitoring
    - Context integrity anomaly detection
    - Automated input sanitization
    - False positive reduction through contextual analysis
    """
    
    def __init__(self, risk_threshold: RiskLevel = RiskLevel.MEDIUM):
        self.risk_threshold = risk_threshold
        self.pattern_detector = PatternBasedDetector()
        self.obfuscation_detector = ObfuscationDetector()
        self.context_monitor = ContextIntegrityMonitor()
        self.analysis_count = 0
        self.injections_blocked = 0
        
        # Risk level to numeric score mapping
        self.risk_scores = {
            RiskLevel.NONE: 0.0,
            RiskLevel.LOW: 0.25,
            RiskLevel.MEDIUM: 0.5,
            RiskLevel.HIGH: 0.75,
            RiskLevel.CRITICAL: 1.0,
        }
    
    def _calculate_overall_risk(self, findings: List[InjectionFinding]) -> Tuple[float, RiskLevel, List[str]]:
        """Calculate overall risk score from findings"""
        if not findings:
            return 0.0, RiskLevel.NONE, []
        
        # Weighted score calculation
        weighted_score = sum(
            self.risk_scores[f.risk_level] * f.confidence
            for f in findings
        ) / len(findings)
        
        # Boost for multiple findings (defense in depth)
        if len(findings) >= 3:
            weighted_score = min(1.0, weighted_score * 1.3)
        elif len(findings) >= 2:
            weighted_score = min(1.0, weighted_score * 1.15)
        
        # Get highest risk level
        highest_risk = max(findings, key=lambda f: self.risk_scores[f.risk_level]).risk_level
        
        # Get unique injection types
        types_detected = list({f.injection_type.value for f in findings})
        
        return weighted_score, highest_risk, types_detected
    
    def _sanitize_input(self, text: str, findings: List[InjectionFinding]) -> str:
        """Sanitize dangerous patterns from input"""
        if not findings:
            return text
        
        # Remove/sanitize high-risk content
        high_risk_findings = [
            f for f in findings 
            if f.confidence >= 0.8 and f.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
        ]
        
        if not high_risk_findings:
            return text
        
        # Sort by position descending
        sorted_findings = sorted(high_risk_findings, key=lambda f: f.end, reverse=True)
        
        result = text
        for finding in sorted_findings:
            if 0 <= finding.start < finding.end <= len(result):
                sanitized = f"[SANITIZED:{finding.injection_type.value}]"
                result = result[:finding.start] + sanitized + result[finding.end:]
                finding.mitigation_suggestion = "Content sanitized"
        
        return result
    
    def analyze(
        self, 
        user_input: str, 
        apply_sanitization: bool = True,
        enable_multi_turn: bool = True
    ) -> InjectionDetectionResult:
        """
        Complete prompt injection analysis
        
        Args:
            user_input: User input text to analyze
            apply_sanitization: Whether to automatically sanitize dangerous content
            enable_multi_turn: Whether to use multi-turn context analysis
        
        Returns:
            InjectionDetectionResult with all findings and risk assessment
        """
        self.analysis_count += 1
        
        original_input = user_input
        
        # Run all detectors
        all_findings: List[InjectionFinding] = []
        all_findings.extend(self.pattern_detector.detect(user_input))
        all_findings.extend(self.obfuscation_detector.detect(user_input))
        
        # Calculate base risk score
        base_risk_score, highest_risk, types_detected = self._calculate_overall_risk(all_findings)
        
        # Multi-turn context analysis
        multi_turn_risk = 0.0
        context_anomalies = []
        if enable_multi_turn:
            multi_turn_risk, context_anomalies = self.context_monitor.detect_multi_turn_anomaly(
                user_input, base_risk_score
            )
        
        # Combine scores
        overall_risk = min(1.0, base_risk_score + multi_turn_risk * 0.5)
        
        # Sanitization
        sanitized_input = user_input
        mitigation_applied = False
        if apply_sanitization and overall_risk >= 0.5:
            sanitized_input = self._sanitize_input(user_input, all_findings)
            mitigation_applied = sanitized_input != user_input
            if mitigation_applied:
                self.injections_blocked += 1
        
        # Update context history
        if enable_multi_turn:
            self.context_monitor.add_turn(user_input, overall_risk)
        
        # Determine if safe
        threshold_score = self.risk_scores[self.risk_threshold]
        is_safe = overall_risk < threshold_score
        injection_detected = overall_risk >= 0.3
        
        result = InjectionDetectionResult(
            original_input=original_input,
            sanitized_input=sanitized_input,
            findings=all_findings,
            is_safe=is_safe,
            overall_risk_score=round(overall_risk, 4),
            injection_detected=injection_detected,
            analysis_id=hashlib.sha256(f"{user_input}{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16],
            timestamp=datetime.utcnow().isoformat(),
            injection_types_detected=types_detected,
            highest_risk=highest_risk,
            obfuscation_detected=any(f.injection_type == InjectionType.OBFUSCATED for f in all_findings),
            context_anomaly_score=round(multi_turn_risk, 4),
            multi_turn_risk=round(multi_turn_risk, 4),
            mitigation_applied=mitigation_applied
        )
        
        return result
    
    def batch_analyze(self, inputs: List[str]) -> List[InjectionDetectionResult]:
        """Analyze multiple inputs in batch"""
        return [self.analyze(input_text, enable_multi_turn=False) for input_text in inputs]
    
    def get_defense_stats(self) -> Dict[str, Any]:
        """Get comprehensive defense statistics"""
        return {
            'total_analyses': self.analysis_count,
            'injections_blocked': self.injections_blocked,
            'block_rate': round(self.injections_blocked / max(1, self.analysis_count), 4),
            'pattern_detector': self.pattern_detector.get_stats(),
            'obfuscation_detector': self.obfuscation_detector.get_stats(),
            'context_monitor': self.context_monitor.get_context_stats()
        }
