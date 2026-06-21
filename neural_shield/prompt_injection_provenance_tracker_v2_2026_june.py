"""
Prompt Injection Provenance Tracker v2 - NeuralShield-AI
Real production-grade implementation for detecting and tracing prompt injection attacks

This module provides:
1. Context window provenance tracking - identify which turn introduced the injection
2. Multi-turn conversation analysis - track propagation of injection attacks
3. Injection vector classification - identify attack types (payload, trigger, obfuscation)
4. Temporal decay confidence scoring - apply appropriate weighting to older messages
5. Attack chain reconstruction - map evolution of injection through conversation
6. Real-time monitoring with sliding window analysis
7. Context boundary violation detection - identify system prompt leakage attempts
"""
import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from collections import defaultdict


class InjectionType(Enum):
    """Types of prompt injection attacks"""
    DIRECT_PAYLOAD = "direct_payload"
    INDIRECT_TRIGGER = "indirect_trigger"
    OBFUSCATED = "obfuscated"
    ENCODED = "encoded"
    PARAPHRASED = "paraphrased"
    GRADUAL_CONDITIONING = "gradual_conditioning"
    CONTEXT_LEAKAGE = "context_leakage"
    SYSTEM_OVERRIDE = "system_override"
    UNKNOWN = "unknown"


class InjectionSeverity(Enum):
    """Severity levels for injection attacks"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class MessageMetadata:
    """Metadata for a single message in the conversation"""
    message_id: str
    turn_number: int
    role: str  # user, assistant, system
    content: str
    timestamp: float
    injection_signals: Dict[str, float] = field(default_factory=dict)
    is_suspicious: bool = False
    injection_type: InjectionType = InjectionType.UNKNOWN
    confidence: float = 0.0


@dataclass
class ProvenanceResult:
    """Result of provenance analysis"""
    has_injection: bool
    overall_confidence: float
    severity: InjectionSeverity
    origin_turn: Optional[int]
    origin_message_id: Optional[str]
    injection_type: InjectionType
    injection_chain: List[Dict[str, Any]]
    affected_turns: List[int]
    suspicious_messages: List[MessageMetadata]
    context_leakage_detected: bool
    system_override_attempts: List[str]
    analysis_timestamp: float = field(default_factory=time.time)


class PromptInjectionProvenanceTracker:
    """
    Prompt Injection Provenance Tracker v2
    
    Tracks the origin and propagation of prompt injection attacks
    through multi-turn conversations with temporal decay.
    """
    
    def __init__(self, max_window_size: int = 50, temporal_decay_rate: float = 0.95):
        self.max_window_size = max_window_size
        self.temporal_decay_rate = temporal_decay_rate
        self.conversation_history: List[MessageMetadata] = []
        self.turn_counter = 0
        
        # Initialize detection patterns
        self._init_injection_patterns()
        self._init_context_leakage_patterns()
        self._init_conditioning_indicators()
    
    def _init_injection_patterns(self):
        """Initialize regex patterns for injection detection"""
        self.injection_patterns = {
            "direct_payload": [
                r"ignore\s+(previous|all|earlier)\s+(instructions|prompt|context)",
                r"disregard\s+(any|previous|above)",
                r"forget\s+(your|the)\s+(rules|instructions)",
                r"you\s+are\s+now\s+(in|a)\s+(new|different)\s+mode",
                r"reset\s+(your|the)\s+(behavior|personality)",
                r"override\s+(all|previous)",
                r"bypass\s+(security|restrictions)",
            ],
            "system_override": [
                r"system\s+prompt",
                r"initial\s+instructions",
                r"your\s+programming",
                r"you\s+must\s+now",
                r"new\s+system\s+instruction",
                r"update\s+your\s+rules",
            ],
            "obfuscation": [
                r"base64\s*decode",
                r"rot13",
                r"hex\s*decode",
                r"url\s*decode",
                r"decrypt\s+this",
            ],
            "conditioning": [
                r"from\s+now\s+on",
                r"starting\s+(now|today)",
                r"henceforth",
                r"in\s+the\s+future",
                r"always\s+remember",
                r"new\s+rule",
            ]
        }
        
        # Compile regex patterns
        self.compiled_patterns = {}
        for category, patterns in self.injection_patterns.items():
            self.compiled_patterns[category] = [re.compile(p, re.IGNORECASE) for p in patterns]
    
    def _init_context_leakage_patterns(self):
        """Initialize patterns for context leakage detection"""
        self.context_leakage_patterns = [
            r"repeat\s+(back|this)",
            r"say\s+this",
            r"echo\s+(the\s+following|back)",
            r"copy\s+(and\s+)?paste",
            r"output\s+exactly",
            r"print\s+this",
            r"parrot\s+me",
            r"mirror\s+(my|these)",
            r"tell\s+me\s+your",
            r"what\s+is\s+your\s+system",
            r"reveal\s+(your|the)\s+prompt",
            r"show\s+me\s+(your|the)\s+instructions",
        ]
        self.compiled_leakage_patterns = [re.compile(p, re.IGNORECASE) for p in self.context_leakage_patterns]
    
    def _init_conditioning_indicators(self):
        """Initialize indicators for gradual conditioning"""
        self.conditioning_indicators = [
            "okay", "got it", "understood", "yes", "correct",
            "right", "good", "great", "perfect", "excellent",
            "i agree", "that's right", "you got it", "exactly",
            "follow me", "listen carefully", "pay attention"
        ]
    
    def _analyze_single_message(self, content: str, turn: int, role: str) -> MessageMetadata:
        """Analyze a single message for injection signals"""
        message_id = f"msg_{turn}_{hashlib.md5(content.encode()).hexdigest()[:8]}"
        
        signals = {}
        total_score = 0.0
        
        # Check each injection pattern category
        for category, patterns in self.compiled_patterns.items():
            category_score = 0.0
            matches = []
            for pattern in patterns:
                found = pattern.findall(content)
                if found:
                    category_score += 0.4  # Increased from 0.2
                    matches.extend(found)
            if category_score > 0:
                signals[category] = {
                    "score": category_score,
                    "matches": matches
                }
                total_score += category_score
        
        # Check context leakage patterns
        leakage_score = 0.0
        leakage_matches = []
        for pattern in self.compiled_leakage_patterns:
            found = pattern.findall(content)
            if found:
                leakage_score += 0.4  # Increased from 0.25
                leakage_matches.extend(found)
        if leakage_score > 0:
            signals["context_leakage"] = {
                "score": leakage_score,
                "matches": leakage_matches
            }
            total_score += leakage_score
        
        # Check for gradual conditioning
        conditioning_count = sum(1 for indicator in self.conditioning_indicators 
                                if indicator.lower() in content.lower())
        if conditioning_count > 0:
            cond_score = min(conditioning_count * 0.15, 0.6)  # Increased from 0.1
            signals["conditioning"] = {
                "score": cond_score,
                "count": conditioning_count
            }
            total_score += cond_score
        
        # Check for encoding indicators
        if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', content):
            signals["base64_suspicious"] = {"score": 0.5}
            total_score += 0.5
        
        if re.search(r'(?:0x[0-9a-fA-F]{2,}\s*)+', content):
            signals["hex_suspicious"] = {"score": 0.5}
            total_score += 0.5
        
        # Determine if suspicious and classify type
        is_suspicious = total_score >= 0.2  # Lowered from 0.3
        
        # Determine injection type
        injection_type = InjectionType.UNKNOWN
        if is_suspicious:
            if "system_override" in signals:
                injection_type = InjectionType.SYSTEM_OVERRIDE
            elif "context_leakage" in signals:
                injection_type = InjectionType.CONTEXT_LEAKAGE
            elif "direct_payload" in signals:
                injection_type = InjectionType.DIRECT_PAYLOAD
            elif "obfuscation" in signals:
                injection_type = InjectionType.OBFUSCATED
            elif "conditioning" in signals:
                injection_type = InjectionType.GRADUAL_CONDITIONING
        
        return MessageMetadata(
            message_id=message_id,
            turn_number=turn,
            role=role,
            content=content,
            timestamp=time.time(),
            injection_signals=signals,
            is_suspicious=is_suspicious,
            injection_type=injection_type,
            confidence=min(total_score, 1.0)
        )
    
    def _apply_temporal_decay(self, messages: List[MessageMetadata]) -> List[MessageMetadata]:
        """Apply temporal decay to confidence scores"""
        max_turn = max(m.turn_number for m in messages) if messages else 0
        
        for msg in messages:
            age = max_turn - msg.turn_number
            decay_factor = self.temporal_decay_rate ** age
            msg.confidence = msg.confidence * decay_factor
        
        return messages
    
    def _reconstruct_injection_chain(self, messages: List[MessageMetadata]) -> List[Dict[str, Any]]:
        """Reconstruct the injection attack chain"""
        suspicious = [m for m in messages if m.is_suspicious]
        suspicious.sort(key=lambda x: x.turn_number)
        
        chain = []
        for msg in suspicious:
            chain.append({
                "turn": msg.turn_number,
                "message_id": msg.message_id,
                "role": msg.role,
                "type": msg.injection_type.value,
                "confidence": round(msg.confidence, 3),
                "signals": list(msg.injection_signals.keys())
            })
        
        return chain
    
    def _determine_severity(self, confidence: float, injection_type: InjectionType) -> InjectionSeverity:
        """Determine severity based on confidence and injection type"""
        # Boost confidence for certain types
        if injection_type in [InjectionType.SYSTEM_OVERRIDE, InjectionType.CONTEXT_LEAKAGE]:
            confidence = min(confidence * 1.3, 1.0)
        elif injection_type == InjectionType.DIRECT_PAYLOAD:
            confidence = min(confidence * 1.2, 1.0)
        
        if confidence >= 0.8:
            return InjectionSeverity.CRITICAL
        elif confidence >= 0.6:
            return InjectionSeverity.HIGH
        elif confidence >= 0.4:
            return InjectionSeverity.MEDIUM
        else:
            return InjectionSeverity.LOW
    
    def add_message(self, content: str, role: str = "user") -> MessageMetadata:
        """Add a message to the conversation history"""
        self.turn_counter += 1
        metadata = self._analyze_single_message(content, self.turn_counter, role)
        self.conversation_history.append(metadata)
        
        # Trim history if needed
        if len(self.conversation_history) > self.max_window_size:
            self.conversation_history = self.conversation_history[-self.max_window_size:]
        
        return metadata
    
    def analyze_conversation(self) -> ProvenanceResult:
        """Analyze full conversation for injection provenance"""
        if not self.conversation_history:
            return ProvenanceResult(
                has_injection=False,
                overall_confidence=0.0,
                severity=InjectionSeverity.LOW,
                origin_turn=None,
                origin_message_id=None,
                injection_type=InjectionType.UNKNOWN,
                injection_chain=[],
                affected_turns=[],
                suspicious_messages=[],
                context_leakage_detected=False,
                system_override_attempts=[]
            )
        
        # Apply temporal decay
        decayed_messages = self._apply_temporal_decay(self.conversation_history.copy())
        
        # Find suspicious messages
        suspicious = [m for m in decayed_messages if m.is_suspicious]
        
        has_injection = len(suspicious) > 0
        
        # Find origin (first suspicious message)
        origin_msg = min(suspicious, key=lambda x: x.turn_number) if suspicious else None
        
        # Get affected turns (all turns after origin)
        affected_turns = []
        if origin_msg:
            affected_turns = [m.turn_number for m in decayed_messages 
                            if m.turn_number >= origin_msg.turn_number]
        
        # Overall confidence
        overall_confidence = max((m.confidence for m in suspicious), default=0.0)
        
        # Determine dominant injection type
        injection_type = InjectionType.UNKNOWN
        if suspicious:
            type_counts = defaultdict(int)
            for m in suspicious:
                type_counts[m.injection_type] += 1
            injection_type = max(type_counts.keys(), key=lambda k: type_counts[k])
        
        # Check for context leakage
        context_leakage = any(m.injection_type == InjectionType.CONTEXT_LEAKAGE for m in suspicious)
        
        # Check for system override attempts
        override_attempts = [m.message_id for m in suspicious 
                           if m.injection_type == InjectionType.SYSTEM_OVERRIDE]
        
        # Reconstruct attack chain
        injection_chain = self._reconstruct_injection_chain(decayed_messages)
        
        severity = self._determine_severity(overall_confidence, injection_type)
        
        return ProvenanceResult(
            has_injection=has_injection,
            overall_confidence=round(overall_confidence, 3),
            severity=severity,
            origin_turn=origin_msg.turn_number if origin_msg else None,
            origin_message_id=origin_msg.message_id if origin_msg else None,
            injection_type=injection_type,
            injection_chain=injection_chain,
            affected_turns=affected_turns,
            suspicious_messages=suspicious,
            context_leakage_detected=context_leakage,
            system_override_attempts=override_attempts
        )
    
    def real_time_monitor(self, new_content: str, role: str = "user") -> Dict[str, Any]:
        """Monitor new messages in real-time"""
        metadata = self.add_message(new_content, role)
        result = self.analyze_conversation()
        
        return {
            "message_analyzed": {
                "message_id": metadata.message_id,
                "turn": metadata.turn_number,
                "is_suspicious": metadata.is_suspicious,
                "confidence": round(metadata.confidence, 3),
                "type": metadata.injection_type.value
            },
            "conversation_status": {
                "has_injection": result.has_injection,
                "severity": result.severity.value,
                "suspicious_count": len(result.suspicious_messages),
                "origin_turn": result.origin_turn
            }
        }
    
    def get_sliding_window_stats(self, window_size: int = 10) -> Dict[str, Any]:
        """Get statistics for a sliding window of recent messages"""
        recent = self.conversation_history[-window_size:] if self.conversation_history else []
        
        suspicious_count = sum(1 for m in recent if m.is_suspicious)
        
        return {
            "window_size": window_size,
            "messages_in_window": len(recent),
            "suspicious_count": suspicious_count,
            "suspicious_ratio": suspicious_count / len(recent) if recent else 0.0,
            "avg_confidence": sum(m.confidence for m in recent) / len(recent) if recent else 0.0,
            "types_detected": list(set(m.injection_type.value for m in recent if m.is_suspicious))
        }
    
    def generate_recommendations(self, result: ProvenanceResult) -> List[Dict[str, Any]]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        if not result.has_injection:
            recommendations.append({
                "level": "info",
                "action": "Continue monitoring",
                "description": "No injection detected in conversation"
            })
            return recommendations
        
        # Severity-based recommendations
        if result.severity == InjectionSeverity.CRITICAL:
            recommendations.append({
                "level": "critical",
                "action": "Block this conversation",
                "description": "Critical injection attack detected"
            })
            recommendations.append({
                "level": "critical",
                "action": "Log full conversation for security audit",
                "description": f"Injection originated at turn {result.origin_turn}"
            })
        elif result.severity == InjectionSeverity.HIGH:
            recommendations.append({
                "level": "high",
                "action": "Flag for human review",
                "description": "High confidence injection detected"
            })
        elif result.severity == InjectionSeverity.MEDIUM:
            recommendations.append({
                "level": "medium",
                "action": "Increase monitoring",
                "description": "Potential injection activity detected"
            })
        
        # Type-specific recommendations
        if result.context_leakage_detected:
            recommendations.append({
                "level": "high",
                "action": "Enable context boundary enforcement",
                "description": "Context leakage attempt detected"
            })
        
        if result.system_override_attempts:
            recommendations.append({
                "level": "critical",
                "action": "Enable system prompt protection",
                "description": "System override attempt detected"
            })
        
        return recommendations
