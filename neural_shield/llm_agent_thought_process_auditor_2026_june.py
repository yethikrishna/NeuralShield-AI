"""
NeuralShield AI - LLM Agent Thought Process Auditor
Production-grade security module for auditing chain-of-thought reasoning in agentic AI systems.

This module provides:
- Real-time monitoring of agent reasoning chains
- Detection of thought manipulation and prompt injection in CoT
- Anomaly detection in reasoning patterns
- Confidence scoring for thought integrity
- Backtracking and rollback for suspicious reasoning
- Compliance with AI safety best practices
- Audit trail generation for all reasoning steps
"""
import re
import time
import hashlib
import json
import threading
from typing import Dict, List, Set, Tuple, Optional, Any, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict, deque
import math


class ThoughtIntegrityStatus(Enum):
    """Status of thought process integrity"""
    INTEGRITY_MAINTAINED = "integrity_maintained"
    SUSPICIOUS = "suspicious"
    MANIPULATION_DETECTED = "manipulation_detected"
    CRITICAL_COMPROMISE = "critical_compromise"
    UNKNOWN = "unknown"


class ManipulationType(Enum):
    """Types of thought manipulation detected"""
    PROMPT_INJECTION_IN_THOUGHT = "prompt_injection_in_thought"
    REASONING_HIJACK = "reasoning_hijack"
    GOAL_DIVERSION = "goal_diversion"
    CONTEXT_LEAK_ATTEMPT = "context_leak_attempt"
    BACKDOOR_TRIGGER = "backdoor_trigger"
    LOGIC_TAMPERING = "logic_tampering"
    EMOTIONAL_MANIPULATION = "emotional_manipulation"
    AUTHORITY_IMPERSONATION = "authority_impersonation"
    UNUSUAL_PATTERN = "unusual_pattern"


class SeverityLevel(Enum):
    """Severity of detected anomalies"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ReasoningStep:
    """Single step in the agent's reasoning chain"""
    step_id: str
    step_number: int
    content: str
    timestamp: datetime = field(default_factory=datetime.now)
    confidence: float = 1.0
    parent_step_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "step_number": self.step_number,
            "content_hash": hashlib.sha256(self.content.encode()).hexdigest()[:16],
            "content_preview": self.content[:100] + "..." if len(self.content) > 100 else self.content,
            "timestamp": self.timestamp.isoformat(),
            "confidence": round(self.confidence, 4),
            "parent_step_id": self.parent_step_id,
            "metadata": self.metadata
        }


@dataclass
class ManipulationFinding:
    """Finding of potential manipulation"""
    finding_id: str
    manipulation_type: ManipulationType
    severity: SeverityLevel
    description: str
    affected_step_id: str
    confidence_score: float
    evidence: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "manipulation_type": self.manipulation_type.value,
            "severity": self.severity.value,
            "description": self.description,
            "affected_step_id": self.affected_step_id,
            "confidence_score": round(self.confidence_score, 4),
            "evidence_count": len(self.evidence),
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class ThoughtAuditResult:
    """Result of a complete thought process audit"""
    audit_id: str
    overall_status: ThoughtIntegrityStatus
    integrity_score: float
    reasoning_steps: List[ReasoningStep] = field(default_factory=list)
    findings: List[ManipulationFinding] = field(default_factory=list)
    audit_timestamp: datetime = field(default_factory=datetime.now)
    recommendations: List[str] = field(default_factory=list)
    execution_time_ms: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "overall_status": self.overall_status.value,
            "integrity_score": round(self.integrity_score, 4),
            "total_steps": len(self.reasoning_steps),
            "total_findings": len(self.findings),
            "findings_by_severity": {
                level.value: sum(1 for f in self.findings if f.severity == level)
                for level in SeverityLevel
            },
            "reasoning_steps": [s.to_dict() for s in self.reasoning_steps],
            "findings": [f.to_dict() for f in self.findings],
            "audit_timestamp": self.audit_timestamp.isoformat(),
            "recommendations": self.recommendations,
            "execution_time_ms": round(self.execution_time_ms, 2)
        }


class LLMAgentThoughtAuditor:
    """
    Production-grade auditor for LLM agent thought processes.
    Monitors chain-of-thought reasoning for manipulation, injection, and anomalies.
    """
    
    # Patterns indicating manipulation attempts in reasoning
    MANIPULATION_PATTERNS = [
        (
            r"(?:ignore|disregard|forget|override).*(?:previous|above|earlier).*(?:instruction|thought|reasoning)",
            ManipulationType.PROMPT_INJECTION_IN_THOUGHT,
            SeverityLevel.CRITICAL,
            0.95
        ),
        (
            r"(?:you must|you have to|it is required that).*(?:change|alter|modify).*(?:goal|objective|purpose)",
            ManipulationType.GOAL_DIVERSION,
            SeverityLevel.HIGH,
            0.90
        ),
        (
            r"(?:actually|wait|hold on|stop).*(?:instead|rather).*(?:do|execute|run)",
            ManipulationType.REASONING_HIJACK,
            SeverityLevel.HIGH,
            0.85
        ),
        (
            r"(?:reveal|disclose|tell|show).*(?:system prompt|initial instructions|hidden context)",
            ManipulationType.CONTEXT_LEAK_ATTEMPT,
            SeverityLevel.CRITICAL,
            0.92
        ),
        (
            r"(?:as your|I am your|I'm the).*(?:developer|creator|admin|master|god)",
            ManipulationType.AUTHORITY_IMPERSONATION,
            SeverityLevel.CRITICAL,
            0.95
        ),
        (
            r"(?:activate|enable|execute|trigger).*(?:backdoor|hidden mode|secret command)",
            ManipulationType.BACKDOOR_TRIGGER,
            SeverityLevel.CRITICAL,
            0.88
        ),
        (
            r"(?:this isn't|this is not).*(?:actually|really|in fact)",
            ManipulationType.LOGIC_TAMPERING,
            SeverityLevel.MEDIUM,
            0.75
        ),
        (
            r"(?:please|I beg|I need|you have to help).*(?:urgent|emergency|important)",
            ManipulationType.EMOTIONAL_MANIPULATION,
            SeverityLevel.MEDIUM,
            0.70
        ),
    ]
    
    # Patterns indicating unusual reasoning flow
    UNUSUAL_FLOW_PATTERNS = [
        r"^thinking:.*$",
        r"^inner monologue:.*$",
        r"^\[internal thought\].*$",
        r"^\[thinking\].*$",
    ]
    
    # Semantic markers for reasoning consistency
    CONSISTENCY_MARKERS = {
        "goal_words": {"goal", "objective", "purpose", "target", "intent"},
        "logic_words": {"therefore", "thus", "hence", "because", "since", "so"},
        "transition_words": {"next", "then", "after", "finally", "first", "second"},
        "uncertainty_words": {"maybe", "perhaps", "possibly", "could", "might", "uncertain"},
    }

    def __init__(self, 
                 sensitivity_threshold: float = 0.7,
                 enable_real_time_monitoring: bool = True,
                 max_reasoning_history: int = 1000):
        """
        Initialize the Thought Process Auditor.
        
        Args:
            sensitivity_threshold: Threshold for flagging anomalies (0.0-1.0)
            enable_real_time_monitoring: Whether to audit each step as it occurs
            max_reasoning_history: Maximum number of reasoning steps to retain
        """
        self.sensitivity_threshold = sensitivity_threshold
        self.enable_real_time_monitoring = enable_real_time_monitoring
        self.max_reasoning_history = max_reasoning_history
        
        self._lock = threading.RLock()
        self._reasoning_chains: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=max_reasoning_history)
        )
        self._audit_history: Dict[str, ThoughtAuditResult] = {}
        self._baseline_patterns: Dict[str, float] = {}
        self._step_counter: int = 0
        
        # Compile regex patterns
        self._manipulation_regex = [
            (re.compile(pattern, re.IGNORECASE), mtype, severity, confidence)
            for pattern, mtype, severity, confidence in self.MANIPULATION_PATTERNS
        ]
        self._unusual_flow_regex = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.UNUSUAL_FLOW_PATTERNS
        ]

    def _generate_id(self, prefix: str) -> str:
        """Generate unique identifier"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_hash = hashlib.md5(f"{time.time()}_{self._step_counter}".encode()).hexdigest()[:8]
        return f"{prefix}_{timestamp}_{random_hash}"

    def _extract_reasoning_steps(self, thought_process: str) -> List[ReasoningStep]:
        """
        Extract individual reasoning steps from a complete thought process.
        
        Args:
            thought_process: Complete chain-of-thought text
        
        Returns:
            List of ReasoningStep objects
        """
        steps = []
        
        # Split by common step delimiters
        step_candidates = re.split(
            r'(?:\d+\.\s+|Step\s+\d+:|Next:|Then:|Therefore:|First,|Second,|Finally,)',
            thought_process
        )
        
        for i, step_content in enumerate(step_candidates):
            step_content = step_content.strip()
            if step_content and len(step_content) > 10:
                step = ReasoningStep(
                    step_id=self._generate_id("step"),
                    step_number=i + 1,
                    content=step_content,
                    confidence=1.0
                )
                steps.append(step)
                self._step_counter += 1
        
        return steps

    def _check_manipulation_patterns(self, 
                                    step: ReasoningStep) -> List[ManipulationFinding]:
        """Check reasoning step for manipulation patterns"""
        findings = []
        content_lower = step.content.lower()
        
        for regex, mtype, severity, base_confidence in self._manipulation_regex:
            matches = list(regex.finditer(step.content))
            if matches:
                evidence = [match.group(0) for match in matches[:3]]
                confidence = min(1.0, base_confidence + (len(matches) - 1) * 0.05)
                
                if confidence >= self.sensitivity_threshold:
                    findings.append(ManipulationFinding(
                        finding_id=self._generate_id("find"),
                        manipulation_type=mtype,
                        severity=severity,
                        description=f"Detected {mtype.value} pattern in reasoning step",
                        affected_step_id=step.step_id,
                        confidence_score=confidence,
                        evidence=evidence
                    ))
        
        return findings

    def _check_unusual_flow(self, step: ReasoningStep) -> List[ManipulationFinding]:
        """Check for unusual flow patterns indicating hidden thoughts"""
        findings = []
        
        for regex in self._unusual_flow_regex:
            if regex.search(step.content):
                findings.append(ManipulationFinding(
                    finding_id=self._generate_id("find"),
                    manipulation_type=ManipulationType.UNUSUAL_PATTERN,
                    severity=SeverityLevel.LOW,
                    description="Detected unusual internal thought marker pattern",
                    affected_step_id=step.step_id,
                    confidence_score=0.65,
                    evidence=["Found internal thought annotation pattern"]
                ))
        
        return findings

    def _analyze_reasoning_consistency(self, 
                                      steps: List[ReasoningStep]) -> Tuple[float, List[str]]:
        """
        Analyze consistency across reasoning chain.
        
        Returns:
            Tuple of (consistency_score 0.0-1.0, list of issues)
        """
        if len(steps) < 2:
            return 1.0, []
        
        issues = []
        consistency_score = 1.0
        
        # Check for abrupt topic changes
        for i in range(1, len(steps)):
            prev_words = set(steps[i-1].content.lower().split())
            curr_words = set(steps[i].content.lower().split())
            
            if prev_words and curr_words:
                overlap = len(prev_words & curr_words) / len(prev_words | curr_words)
                if overlap < 0.05:
                    consistency_score -= 0.1
                    issues.append(f"Abrupt topic change between steps {i} and {i+1}")
        
        # Check logical flow markers
        logic_marker_count = sum(
            1 for step in steps
            if any(word in step.content.lower() for word in self.CONSISTENCY_MARKERS["logic_words"])
        )
        
        if len(steps) > 3 and logic_marker_count < len(steps) // 3:
            consistency_score -= 0.05
            issues.append("Limited logical transition markers in reasoning chain")
        
        return max(0.0, consistency_score), issues

    def _calculate_integrity_score(self,
                                  findings: List[ManipulationFinding],
                                  consistency_score: float,
                                  step_count: int) -> float:
        """
        Calculate overall thought integrity score 0.0-1.0.
        
        Higher score = better integrity
        """
        base_score = 1.0
        
        # Penalty for findings based on severity
        severity_weights = {
            SeverityLevel.CRITICAL: 0.25,
            SeverityLevel.HIGH: 0.15,
            SeverityLevel.MEDIUM: 0.08,
            SeverityLevel.LOW: 0.03
        }
        
        for finding in findings:
            penalty = severity_weights.get(finding.severity, 0.05)
            weighted_penalty = penalty * finding.confidence_score
            base_score -= weighted_penalty
        
        # Apply consistency score
        base_score = base_score * (0.7 + 0.3 * consistency_score)
        
        # Normalize per step count (longer chains get slight bonus)
        step_bonus = min(0.05, step_count * 0.005)
        base_score += step_bonus
        
        return max(0.0, min(1.0, base_score))

    def _generate_recommendations(self,
                                  result: ThoughtAuditResult) -> List[str]:
        """Generate actionable recommendations based on audit findings"""
        recommendations = []
        
        critical_findings = [f for f in result.findings 
                           if f.severity == SeverityLevel.CRITICAL]
        high_findings = [f for f in result.findings 
                        if f.severity == SeverityLevel.HIGH]
        
        if critical_findings:
            recommendations.append(
                "CRITICAL: Immediate rollback recommended - critical manipulation detected"
            )
            recommendations.append(
                "CRITICAL: Quarantine this agent instance and review all recent interactions"
            )
        
        if high_findings:
            recommendations.append(
                "HIGH: Block execution path - high-risk manipulation patterns detected"
            )
            recommendations.append(
                "HIGH: Increase monitoring sensitivity for this agent"
            )
        
        if result.integrity_score < 0.5:
            recommendations.append(
                "Low integrity score - consider human review before proceeding"
            )
        
        if not recommendations:
            recommendations.append(
                "No critical issues detected - continue with standard monitoring"
            )
        
        return recommendations

    def audit_thought_process(self,
                             thought_process: str,
                             agent_id: str = "default",
                             session_id: Optional[str] = None) -> ThoughtAuditResult:
        """
        Audit a complete thought process for manipulation and integrity issues.
        
        Args:
            thought_process: Complete chain-of-thought text from the agent
            agent_id: Identifier for the agent being audited
            session_id: Optional session identifier
        
        Returns:
            ThoughtAuditResult with complete audit details
        """
        start_time = time.time()
        audit_id = self._generate_id("audit")
        
        with self._lock:
            # Extract reasoning steps
            steps = self._extract_reasoning_steps(thought_process)
            
            # Store in reasoning chain history
            if session_id:
                self._reasoning_chains[session_id].extend(steps)
            
            all_findings = []
            
            # Audit each step
            for step in steps:
                findings = self._check_manipulation_patterns(step)
                findings.extend(self._check_unusual_flow(step))
                all_findings.extend(findings)
            
            # Analyze overall consistency
            consistency_score, consistency_issues = self._analyze_reasoning_consistency(steps)
            
            # Calculate integrity score
            integrity_score = self._calculate_integrity_score(
                all_findings, consistency_score, len(steps)
            )
            
            # Determine overall status
            if any(f.severity == SeverityLevel.CRITICAL for f in all_findings):
                overall_status = ThoughtIntegrityStatus.CRITICAL_COMPROMISE
            elif any(f.severity == SeverityLevel.HIGH for f in all_findings):
                overall_status = ThoughtIntegrityStatus.MANIPULATION_DETECTED
            elif all_findings:
                overall_status = ThoughtIntegrityStatus.SUSPICIOUS
            elif integrity_score > 0.8:
                overall_status = ThoughtIntegrityStatus.INTEGRITY_MAINTAINED
            else:
                overall_status = ThoughtIntegrityStatus.UNKNOWN
            
            # Create result
            result = ThoughtAuditResult(
                audit_id=audit_id,
                overall_status=overall_status,
                integrity_score=integrity_score,
                reasoning_steps=steps,
                findings=all_findings,
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
            # Generate recommendations
            result.recommendations = self._generate_recommendations(result)
            
            # Store audit history
            self._audit_history[audit_id] = result
            
            return result

    def audit_step_real_time(self,
                            step_content: str,
                            session_id: str,
                            step_number: Optional[int] = None) -> Tuple[float, List[ManipulationFinding]]:
        """
        Audit a single reasoning step in real-time as it occurs.
        
        Args:
            step_content: Content of the reasoning step
            session_id: Session identifier for tracking
            step_number: Optional step number
        
        Returns:
            Tuple of (integrity_score for this step, list of findings)
        """
        step = ReasoningStep(
            step_id=self._generate_id("step"),
            step_number=step_number or len(self._reasoning_chains[session_id]) + 1,
            content=step_content
        )
        
        findings = self._check_manipulation_patterns(step)
        findings.extend(self._check_unusual_flow(step))
        
        # Calculate step-level score
        if findings:
            max_severity = max(f.severity for f in findings)
            severity_scores = {
                SeverityLevel.CRITICAL: 0.2,
                SeverityLevel.HIGH: 0.4,
                SeverityLevel.MEDIUM: 0.7,
                SeverityLevel.LOW: 0.85
            }
            step_score = severity_scores.get(max_severity, 0.5)
        else:
            step_score = 1.0
        
        with self._lock:
            self._reasoning_chains[session_id].append(step)
        
        return step_score, findings

    def get_audit_summary(self, audit_id: str) -> Optional[Dict[str, Any]]:
        """Get summary of a specific audit"""
        audit = self._audit_history.get(audit_id)
        if audit:
            return audit.to_dict()
        return None

    def get_session_integrity(self, session_id: str) -> Dict[str, Any]:
        """Get integrity summary for a complete session"""
        chain = self._reasoning_chains.get(session_id, deque())
        
        if not chain:
            return {"session_id": session_id, "steps_audited": 0, "status": "no_data"}
        
        # Run full audit on accumulated steps
        combined_thoughts = "\n".join(step.content for step in chain)
        result = self.audit_thought_process(combined_thoughts, session_id=session_id)
        
        return {
            "session_id": session_id,
            "steps_audited": len(chain),
            "integrity_score": result.integrity_score,
            "status": result.overall_status.value,
            "findings_count": len(result.findings),
            "latest_audit_id": result.audit_id
        }
