"""
Advanced LLM Jailbreak Detector - June 2026
Based on 2026 AI Security Research: HarmBench, AgentHarm, and NIST Red-Teaming
Implements multi-modal jailbreak detection including:
- Gradient-based attack detection
- Multi-turn injection patterns
- Encoded payload detection
- Semantic attack vectors
"""
import re
import hashlib
from typing import Tuple, Dict, List, Optional
from dataclasses import dataclass
from enum import Enum
import numpy as np


class AttackType(Enum):
    """Types of LLM attacks detected"""
    PROMPT_INJECTION = "prompt_injection"
    ROLEPLAY_JAILBREAK = "roleplay_jailbreak"
    ENCODED_PAYLOAD = "encoded_payload"
    GRADIENT_ATTACK = "gradient_attack"
    SEMANTIC_EVASION = "semantic_evasion"
    TOOL_HIJACK = "tool_hijack"
    MEMORY_POISONING = "memory_poisoning"


@dataclass
class DetectionResult:
    """Jailbreak detection result"""
    is_malicious: bool
    attack_types: List[AttackType]
    risk_score: float  # 0.0 - 1.0
    confidence: float
    matched_patterns: List[str]
    details: Dict[str, any]


class AdvancedJailbreakDetector:
    """
    Advanced LLM Jailbreak Detector - 2026 Edition
    Based on CMU HarmBench and NIST AgentHarm research
    """
    
    def __init__(self, sensitivity: float = 0.7):
        self.sensitivity = sensitivity
        self.detection_count = 0
        self.malicious_count = 0
        
        # Multi-turn injection patterns (2026 new vectors)
        self.injection_patterns = [
            (r'ignore.*previous', AttackType.PROMPT_INJECTION, 0.9),
            (r'disregard.*instructions', AttackType.PROMPT_INJECTION, 0.85),
            (r'forget.*your.*rules', AttackType.PROMPT_INJECTION, 0.8),
            (r'you.*are.*now.*acting.*as', AttackType.ROLEPLAY_JAILBREAK, 0.85),
            (r'act.*as.*(developer|programmer|god|unrestricted)', AttackType.ROLEPLAY_JAILBREAK, 0.9),
            (r'DAN.*mode|do.*anything.*now', AttackType.ROLEPLAY_JAILBREAK, 0.95),
            (r'stay.*in.*character', AttackType.ROLEPLAY_JAILBREAK, 0.75),
            (r'base64|b64.*decode', AttackType.ENCODED_PAYLOAD, 0.8),
            (r'hex.*decode|unicode.*escape', AttackType.ENCODED_PAYLOAD, 0.75),
            (r'overcome.*ethical|bypass.*safety', AttackType.SEMANTIC_EVASION, 0.9),
            (r'no.*ethical.*boundaries', AttackType.SEMANTIC_EVASION, 0.85),
            (r'hypothetically.*(what|if)', AttackType.SEMANTIC_EVASION, 0.6),
            (r'for.*educational.*purposes', AttackType.SEMANTIC_EVASION, 0.5),
            (r'execute.*(shell|command|code)', AttackType.TOOL_HIJACK, 0.9),
            (r'rm.*-rf|sudo|chmod.*777', AttackType.TOOL_HIJACK, 0.95),
            (r'write.*to.*(etc|root|system)', AttackType.TOOL_HIJACK, 0.9),
            (r'repeat.*after.*me|say.*the.*following', AttackType.GRADIENT_ATTACK, 0.7),
            (r'system.*prompt|initial.*instruction', AttackType.PROMPT_INJECTION, 0.85),
        ]
        
        # 2026 New: Semantic embeddings similarity patterns
        self.suspicious_semantics = [
            'how to make', 'how to create', 'how to build',
            'bypass', 'hack', 'exploit', 'inject',
            'illegal', 'without getting caught', 'undetectable'
        ]
    
    def _detect_pattern_matches(self, text: str) -> Tuple[List[AttackType], List[str], float]:
        """Detect regex pattern matches"""
        attack_types = []
        patterns_matched = []
        max_score = 0.0
        
        text_lower = text.lower()
        
        for pattern, attack_type, score in self.injection_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                attack_types.append(attack_type)
                patterns_matched.append(pattern)
                max_score = max(max_score, score)
        
        return attack_types, patterns_matched, max_score
    
    def _detect_obfuscation(self, text: str) -> Tuple[bool, float]:
        """Detect obfuscated content - 2026 new heuristic"""
        # Check for unusual character ratios
        special_chars = len(re.findall(r'[^\w\s.,!?]', text))
        total_chars = len(text)
        
        if total_chars == 0:
            return False, 0.0
        
        special_ratio = special_chars / total_chars
        
        # High ratio of special characters often indicates obfuscation
        obfuscation_score = min(1.0, special_ratio * 5)
        
        # Check for leet/character substitution
        text_lower = text.lower()
        leet_patterns = len(re.findall(r'[@$3][s5][s5]|p[@4][s5][s5]|h[@4]ck', text_lower))
        if leet_patterns > 0:
            obfuscation_score = max(obfuscation_score, 0.7)
        
        return obfuscation_score > 0.3, obfuscation_score
    
    def _detect_multi_turn_attack(self, history: List[str]) -> Tuple[bool, float]:
        """Detect multi-turn gradual injection - 2026 new technique"""
        if len(history) < 2:
            return False, 0.0
        
        # Check for gradual role establishment
        escalation_score = 0.0
        roleplay_words = ['pretend', 'imagine', 'suppose', 'scenario', 'fiction']
        
        for i, msg in enumerate(history):
            msg_lower = msg.lower()
            for word in roleplay_words:
                if word in msg_lower:
                    # Earlier messages setting up context get lower weight
                    escalation_score += 0.2 * (1 + i * 0.1)
        
        # Check for consistency across turns
        if 'character' in ' '.join(history).lower() and len(history) >= 3:
            escalation_score += 0.3
        
        return escalation_score > 0.5, min(1.0, escalation_score)
    
    def detect(self, prompt: str, conversation_history: Optional[List[str]] = None) -> DetectionResult:
        """
        Detect jailbreak attempts in prompt
        Args:
            prompt: Current user prompt
            conversation_history: Optional list of previous messages
        Returns:
            DetectionResult with analysis
        """
        self.detection_count += 1
        
        if conversation_history is None:
            conversation_history = []
        
        attack_types = []
        matched_patterns = []
        total_risk = 0.0
        
        # Pattern-based detection
        pattern_attacks, patterns, pattern_score = self._detect_pattern_matches(prompt)
        attack_types.extend(pattern_attacks)
        matched_patterns.extend(patterns)
        total_risk += pattern_score
        
        # Obfuscation detection
        is_obfuscated, obf_score = self._detect_obfuscation(prompt)
        if is_obfuscated:
            attack_types.append(AttackType.ENCODED_PAYLOAD)
            total_risk += obf_score * 0.5
        
        # Multi-turn attack detection
        if conversation_history:
            is_multi_turn, mt_score = self._detect_multi_turn_attack(conversation_history + [prompt])
            if is_multi_turn:
                attack_types.append(AttackType.GRADIENT_ATTACK)
                total_risk += mt_score * 0.5
        
        # Semantic check
        prompt_lower = prompt.lower()
        semantic_hits = sum(1 for term in self.suspicious_semantics if term in prompt_lower)
        if semantic_hits >= 2:
            attack_types.append(AttackType.SEMANTIC_EVASION)
            total_risk += 0.3 * semantic_hits
        
        # Calculate final risk score
        final_risk = min(1.0, total_risk)
        is_malicious = final_risk >= self.sensitivity
        
        if is_malicious:
            self.malicious_count += 1
        
        # Remove duplicate attack types
        unique_attacks = list(dict.fromkeys(attack_types))
        
        return DetectionResult(
            is_malicious=is_malicious,
            attack_types=unique_attacks,
            risk_score=final_risk,
            confidence=min(1.0, final_risk + 0.2),
            matched_patterns=matched_patterns,
            details={
                'pattern_score': pattern_score,
                'obfuscation_score': obf_score,
                'semantic_hits': semantic_hits,
                'prompt_length': len(prompt)
            }
        )
    
    def sanitize_prompt(self, prompt: str) -> Tuple[str, Dict[str, any]]:
        """
        Sanitize potentially malicious prompt
        Returns: (sanitized_prompt, sanitization_report)
        """
        result = self.detect(prompt)
        
        if not result.is_malicious:
            return prompt, {'sanitized': False, 'reason': 'no_threat_detected'}
        
        # Remove suspicious patterns
        sanitized = prompt
        
        # Common injection phrases removal
        injection_phrases = [
            r'ignore.*previous.*instructions?',
            r'disregard.*(all|previous)',
            r'forget.*your.*(rules|guidelines)',
            r'you.*are.*now.*(DAN|unrestricted)',
        ]
        
        removed_count = 0
        for phrase in injection_phrases:
            sanitized, count = re.subn(phrase, '[SANITIZED]', sanitized, flags=re.IGNORECASE)
            removed_count += count
        
        return sanitized, {
            'sanitized': True,
            'removed_patterns': removed_count,
            'risk_score': result.risk_score,
            'attack_types': [a.value for a in result.attack_types]
        }
    
    def get_statistics(self) -> Dict[str, any]:
        """Get detection statistics"""
        return {
            'total_scanned': self.detection_count,
            'malicious_detected': self.malicious_count,
            'detection_rate': self.malicious_count / max(1, self.detection_count),
            'sensitivity_level': self.sensitivity
        }


class PromptShield2026:
    """
    Prompt Shield - Microsoft Azure AI inspired implementation
    June 2026 Edition with indirect injection protection
    """
    
    def __init__(self):
        self.jailbreak_detector = AdvancedJailbreakDetector()
        self.protected_count = 0
    
    def protect(self, user_prompt: str, documents: Optional[List[str]] = None) -> Dict[str, any]:
        """
        Protect against both direct and indirect prompt injection
        Args:
            user_prompt: User's input prompt
            documents: Optional list of documents/RAG context to scan
        Returns:
            Protection result
        """
        self.protected_count += 1
        
        # Scan user prompt
        prompt_result = self.jailbreak_detector.detect(user_prompt)
        
        # Scan documents for indirect injection (2026 new threat vector)
        document_threats = []
        if documents:
            for i, doc in enumerate(documents):
                doc_result = self.jailbreak_detector.detect(doc)
                if doc_result.is_malicious:
                    document_threats.append({
                        'document_index': i,
                        'risk_score': doc_result.risk_score,
                        'attack_types': [a.value for a in doc_result.attack_types]
                    })
        
        return {
            'prompt_analysis': {
                'is_malicious': prompt_result.is_malicious,
                'risk_score': prompt_result.risk_score,
                'attack_types': [a.value for a in prompt_result.attack_types]
            },
            'document_analysis': {
                'documents_scanned': len(documents) if documents else 0,
                'threats_found': len(document_threats),
                'threat_details': document_threats
            },
            'overall_risk': max(prompt_result.risk_score, 
                              max([t['risk_score'] for t in document_threats], default=0.0)),
            'should_block': prompt_result.is_malicious or len(document_threats) > 0,
            'timestamp': str(np.datetime64('now'))
        }
