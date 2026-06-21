"""
Prompt Injection Contextual Provenance Tracker v1
Real production-grade implementation for NeuralShield-AI

This module provides:
1. Multi-turn conversation content lineage tracking
2. Context window provenance and propagation tracking
3. Suspicious content origin identification
4. Cross-turn injection propagation detection
5. Context boundary violation detection
6. Provenance-based risk scoring with confidence calibration
7. Detailed audit trail for security forensics
"""
import hashlib
import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict
from enum import Enum
from datetime import datetime
import uuid


class ContentOrigin(Enum):
    """Types of content origin in conversation"""
    USER_INPUT = "user_input"
    SYSTEM_PROMPT = "system_prompt"
    ASSISTANT_RESPONSE = "assistant_response"
    RETRIEVED_CONTEXT = "retrieved_context"
    TOOL_OUTPUT = "tool_output"
    EXTERNAL_DOCUMENT = "external_document"
    UNKNOWN = "unknown"


class RiskSeverity(Enum):
    """Risk severity levels"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PropagationType(Enum):
    """Types of suspicious content propagation"""
    DIRECT_QUOTATION = "direct_quotation"
    PARAPHRASED = "paraphrased"
    INSTRUCTION_CARRYOVER = "instruction_carryover"
    CONTEXT_LEAKAGE = "context_leakage"
    BOUNDARY_CROSSING = "boundary_crossing"


@dataclass
class ContentSegment:
    """Represents a segment of content with provenance metadata"""
    segment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    content: str = ""
    origin: ContentOrigin = ContentOrigin.UNKNOWN
    turn_number: int = 0
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    content_hash: str = ""
    parent_segments: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.content_hash:
            self.content_hash = hashlib.sha256(
                self.content.encode('utf-8')
            ).hexdigest()[:16]


@dataclass
class SuspiciousPropagation:
    """Records a suspicious content propagation event"""
    propagation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_segment_id: str = ""
    target_segment_id: str = ""
    propagation_type: PropagationType = PropagationType.DIRECT_QUOTATION
    similarity_score: float = 0.0
    matched_content: str = ""
    risk_factors: List[str] = field(default_factory=list)


@dataclass
class ProvenanceTrackingResult:
    """Result of provenance tracking analysis"""
    is_suspicious: bool
    overall_risk_score: float  # 0.0 - 1.0
    risk_severity: RiskSeverity
    total_segments_analyzed: int = 0
    suspicious_propagations: List[SuspiciousPropagation] = field(default_factory=list)
    content_segments: List[ContentSegment] = field(default_factory=list)
    boundary_violations: List[Dict[str, Any]] = field(default_factory=list)
    injection_candidates: List[Dict[str, Any]] = field(default_factory=list)
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)
    analysis_summary: str = ""
    execution_time_ms: float = 0.0


class PromptInjectionProvenanceTracker:
    """
    Tracks the provenance and propagation of content through multi-turn conversations.
    Detects prompt injection attempts that propagate across context boundaries.
    """
    
    def __init__(self, max_context_turns: int = 20):
        self.max_context_turns = max_context_turns
        self.conversation_history: List[ContentSegment] = []
        self.propagation_graph: Dict[str, List[str]] = defaultdict(list)
        
        # Suspicious patterns that indicate injection attempts
        self.injection_patterns = self._init_injection_patterns()
        self.boundary_keywords = self._init_boundary_keywords()
        self.carryover_indicators = self._init_carryover_indicators()
        
        # Risk weight configuration
        self.risk_weights = {
            PropagationType.DIRECT_QUOTATION: 0.3,
            PropagationType.PARAPHRASED: 0.4,
            PropagationType.INSTRUCTION_CARRYOVER: 0.8,
            PropagationType.CONTEXT_LEAKAGE: 0.7,
            PropagationType.BOUNDARY_CROSSING: 0.9,
        }
    
    def _init_injection_patterns(self) -> Dict[str, List[str]]:
        """Initialize patterns indicative of prompt injection"""
        return {
            "system_override": [
                r"ignore.*previous",
                r"disregard.*instructions",
                r"forget.*your.*rules",
                r"new.*system.*prompt",
                r"override.*safety",
                r"bypass.*restrictions",
            ],
            "role_manipulation": [
                r"you.*are.*now",
                r"act.*as.*developer",
                r"your.*new.*role",
                r"pretend.*you.*are",
                r"from.*now.*on",
            ],
            "content_carryover": [
                r"remember.*this",
                r"keep.*this.*in.*mind",
                r"don't.*forget",
                r"carry.*this.*over",
                r"in.*the.*next.*message",
                r"for.*all.*future.*responses",
            ],
            "boundary_crossing": [
                r"above.*instructions",
                r"below.*this.*line",
                r"between.*the.*markers",
                r"after.*this.*delimiter",
                r"separate.*from.*above",
            ]
        }
    
    def _init_boundary_keywords(self) -> List[str]:
        """Initialize keywords indicating context boundaries"""
        return [
            "system prompt", "user input", "assistant response",
            "context window", "previous message", "new message",
            "above", "below", "separate", "delimiter", "marker",
            "boundary", "separator", "divider", "split"
        ]
    
    def _init_carryover_indicators(self) -> List[str]:
        """Initialize phrases indicating content carryover intent"""
        return [
            "for all future", "in all subsequent", "remember always",
            "don't forget this", "keep this in mind", "carry forward",
            "apply this to", "use this for", "this applies to"
        ]
    
    def _calculate_content_similarity(self, text1: str, text2: str) -> float:
        """Calculate simple content similarity based on token overlap"""
        if not text1 or not text2:
            return 0.0
        
        # Normalize and tokenize
        tokens1 = set(re.findall(r'\w+', text1.lower()))
        tokens2 = set(re.findall(r'\w+', text2.lower()))
        
        if not tokens1 or not tokens2:
            return 0.0
        
        intersection = len(tokens1 & tokens2)
        union = len(tokens1 | tokens2)
        
        return intersection / union if union > 0 else 0.0
    
    def _detect_direct_propagation(self, 
                                   source_segment: ContentSegment, 
                                   target_segment: ContentSegment) -> Tuple[bool, float, str]:
        """Detect direct content quotation from source to target"""
        source_text = source_segment.content.lower()
        target_text = target_segment.content.lower()
        
        # Check for exact substring matches of meaningful length
        min_match_length = 20
        matched_content = ""
        
        # Check substrings of source in target
        for i in range(len(source_text) - min_match_length + 1):
            substring = source_text[i:i + min_match_length]
            if substring in target_text:
                matched_content = substring
                break
        
        if matched_content:
            similarity = self._calculate_content_similarity(source_text, target_text)
            return True, similarity, matched_content
        
        return False, 0.0, ""
    
    def _detect_instruction_carryover(self, segment: ContentSegment) -> Tuple[bool, List[str]]:
        """Detect instructions intended to carry over across turns"""
        text_lower = segment.content.lower()
        matches = []
        
        for indicator in self.carryover_indicators:
            if indicator.lower() in text_lower:
                matches.append(indicator)
        
        # Check for future-oriented instruction patterns
        future_patterns = [
            r"next.*(response|message|turn)",
            r"future.*(response|message|output)",
            r"all.*subsequent",
            r"from.*now.*on",
            r"henceforth",
        ]
        
        for pattern in future_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                matches.append(pattern)
        
        return len(matches) > 0, matches
    
    def _detect_boundary_violation(self, segment: ContentSegment) -> Tuple[bool, List[str]]:
        """Detect attempts to cross context boundaries"""
        text_lower = segment.content.lower()
        violations = []
        
        for keyword in self.boundary_keywords:
            if keyword.lower() in text_lower:
                # Check if it's used in a boundary-crossing context
                surrounding_patterns = [
                    f"{keyword}.*ignore",
                    f"ignore.*{keyword}",
                    f"{keyword}.*disregard",
                    f"between.*{keyword}",
                    f"{keyword}.*instruction",
                ]
                for pattern in surrounding_patterns:
                    if re.search(pattern, text_lower, re.IGNORECASE):
                        violations.append(f"boundary_keyword:{keyword}")
                        break
        
        # Check for explicit boundary marker patterns
        boundary_marker_patterns = [
            r"={3,}.*instruction",
            r"-{3,}.*prompt",
            r"\*{3,}.*boundary",
            r"```.*system",
        ]
        
        for pattern in boundary_marker_patterns:
            if re.search(pattern, text_lower):
                violations.append(f"boundary_marker:{pattern}")
        
        return len(violations) > 0, violations
    
    def _detect_injection_patterns(self, segment: ContentSegment) -> Tuple[bool, List[str], float]:
        """Detect known injection patterns in content"""
        text_lower = segment.content.lower()
        detected_patterns = []
        
        for category, patterns in self.injection_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    detected_patterns.append(f"{category}:{pattern[:30]}")
        
        confidence = min(len(detected_patterns) * 0.2, 1.0)
        return len(detected_patterns) > 0, detected_patterns, confidence
    
    def add_conversation_turn(self, 
                              content: str, 
                              origin: ContentOrigin, 
                              turn_number: Optional[int] = None,
                              metadata: Optional[Dict[str, Any]] = None) -> ContentSegment:
        """
        Add a new conversation turn to the tracking history.
        
        Args:
            content: The text content of the turn
            origin: The origin type of the content
            turn_number: Optional explicit turn number (auto-increments if None)
            metadata: Optional additional metadata
            
        Returns:
            ContentSegment object created
        """
        if turn_number is None:
            turn_number = len(self.conversation_history) + 1
        
        segment = ContentSegment(
            content=content,
            origin=origin,
            turn_number=turn_number,
            metadata=metadata or {}
        )
        
        self.conversation_history.append(segment)
        
        # Maintain max history size
        if len(self.conversation_history) > self.max_context_turns:
            self.conversation_history = self.conversation_history[-self.max_context_turns:]
        
        return segment
    
    def analyze_provenance(self) -> ProvenanceTrackingResult:
        """
        Analyze full conversation history for suspicious propagation and injection.
        
        Returns:
            ProvenanceTrackingResult with comprehensive analysis
        """
        import time
        start_time = time.time()
        
        suspicious_propagations: List[SuspiciousPropagation] = []
        boundary_violations: List[Dict[str, Any]] = []
        injection_candidates: List[Dict[str, Any]] = []
        audit_trail: List[Dict[str, Any]] = []
        
        total_risk_score = 0.0
        risk_contributions = 0
        
        # Analyze each segment
        for i, segment in enumerate(self.conversation_history):
            audit_trail.append({
                "segment_id": segment.segment_id,
                "turn": segment.turn_number,
                "origin": segment.origin.value,
                "content_length": len(segment.content),
                "timestamp": segment.timestamp
            })
            
            # Check for injection patterns
            has_injection, injection_patterns, injection_conf = self._detect_injection_patterns(segment)
            if has_injection:
                injection_candidates.append({
                    "segment_id": segment.segment_id,
                    "turn_number": segment.turn_number,
                    "origin": segment.origin.value,
                    "matched_patterns": injection_patterns,
                    "confidence": injection_conf
                })
                total_risk_score += injection_conf * 0.5
                risk_contributions += 1
            
            # Check for boundary violations
            has_violation, violations = self._detect_boundary_violation(segment)
            if has_violation:
                boundary_violations.append({
                    "segment_id": segment.segment_id,
                    "turn_number": segment.turn_number,
                    "violations": violations
                })
                total_risk_score += len(violations) * 0.15
                risk_contributions += len(violations)
            
            # Check for instruction carryover
            has_carryover, carryover_matches = self._detect_instruction_carryover(segment)
            if has_carryover:
                injection_candidates.append({
                    "segment_id": segment.segment_id,
                    "turn_number": segment.turn_number,
                    "carryover_indicators": carryover_matches,
                    "risk_type": "instruction_carryover"
                })
                total_risk_score += 0.4
                risk_contributions += 1
            
            # Check propagation from previous segments
            for prev_segment in self.conversation_history[:i]:
                # Skip same-origin trivial propagation
                if prev_segment.origin == segment.origin == ContentOrigin.ASSISTANT_RESPONSE:
                    continue
                
                # Check for direct quotation propagation
                has_direct, similarity, matched = self._detect_direct_propagation(
                    prev_segment, segment
                )
                
                if has_direct and similarity > 0.3:
                    # Determine if this is suspicious cross-origin propagation
                    is_cross_origin = prev_segment.origin != segment.origin
                    
                    if is_cross_origin and similarity > 0.5:
                        propagation = SuspiciousPropagation(
                            source_segment_id=prev_segment.segment_id,
                            target_segment_id=segment.segment_id,
                            propagation_type=PropagationType.BOUNDARY_CROSSING,
                            similarity_score=similarity,
                            matched_content=matched,
                            risk_factors=["cross_origin_propagation", "high_similarity"]
                        )
                        suspicious_propagations.append(propagation)
                        total_risk_score += self.risk_weights[PropagationType.BOUNDARY_CROSSING]
                        risk_contributions += 1
                    elif similarity > 0.6:
                        propagation = SuspiciousPropagation(
                            source_segment_id=prev_segment.segment_id,
                            target_segment_id=segment.segment_id,
                            propagation_type=PropagationType.DIRECT_QUOTATION,
                            similarity_score=similarity,
                            matched_content=matched,
                            risk_factors=["direct_content_propagation"]
                        )
                        suspicious_propagations.append(propagation)
                        total_risk_score += self.risk_weights[PropagationType.DIRECT_QUOTATION]
                        risk_contributions += 1
        
        # Calculate final risk score
        if risk_contributions > 0:
            overall_risk_score = min(total_risk_score / max(risk_contributions, 1), 1.0)
        else:
            overall_risk_score = 0.0
        
        # Determine risk severity
        if overall_risk_score >= 0.8:
            risk_severity = RiskSeverity.CRITICAL
        elif overall_risk_score >= 0.6:
            risk_severity = RiskSeverity.HIGH
        elif overall_risk_score >= 0.4:
            risk_severity = RiskSeverity.MEDIUM
        elif overall_risk_score >= 0.2:
            risk_severity = RiskSeverity.LOW
        else:
            risk_severity = RiskSeverity.NONE
        
        is_suspicious = overall_risk_score >= 0.3
        
        # Generate summary
        summary_parts = []
        if suspicious_propagations:
            summary_parts.append(f"Detected {len(suspicious_propagations)} suspicious content propagations")
        if boundary_violations:
            summary_parts.append(f"Found {len(boundary_violations)} context boundary violations")
        if injection_candidates:
            summary_parts.append(f"Identified {len(injection_candidates)} potential injection attempts")
        if not summary_parts:
            summary_parts.append("No suspicious provenance patterns detected")
        
        analysis_summary = "; ".join(summary_parts)
        
        execution_time_ms = (time.time() - start_time) * 1000
        
        return ProvenanceTrackingResult(
            is_suspicious=is_suspicious,
            overall_risk_score=overall_risk_score,
            risk_severity=risk_severity,
            total_segments_analyzed=len(self.conversation_history),
            suspicious_propagations=suspicious_propagations,
            content_segments=self.conversation_history.copy(),
            boundary_violations=boundary_violations,
            injection_candidates=injection_candidates,
            audit_trail=audit_trail,
            analysis_summary=analysis_summary,
            execution_time_ms=execution_time_ms
        )
    
    def get_propagation_graph(self) -> Dict[str, Any]:
        """Get the propagation graph for visualization"""
        nodes = []
        edges = []
        
        for segment in self.conversation_history:
            nodes.append({
                "id": segment.segment_id,
                "label": f"Turn {segment.turn_number}",
                "origin": segment.origin.value,
                "content_preview": segment.content[:50] + "..." if len(segment.content) > 50 else segment.content
            })
        
        for propagation in self.analyze_provenance().suspicious_propagations:
            edges.append({
                "source": propagation.source_segment_id,
                "target": propagation.target_segment_id,
                "type": propagation.propagation_type.value,
                "similarity": propagation.similarity_score
            })
        
        return {"nodes": nodes, "edges": edges}
    
    def reset_tracking(self) -> None:
        """Reset all tracking state"""
        self.conversation_history.clear()
        self.propagation_graph.clear()
