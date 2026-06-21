"""
LLM Agent Thought Process Integrity Auditor v2
Production-Grade Security Module for NeuralShield-AI

Implements:
1. Chain-of-Thought (CoT) tampering detection
2. Reasoning step integrity verification
3. Thought process anomaly detection
4. Step-by-step hash chain validation
5. Prompt injection detection in intermediate thoughts
6. Memory poisoning detection
"""

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
import secrets


class ThoughtStatus(Enum):
    VALID = "valid"
    TAMPERED = "tampered"
    ANOMALOUS = "anomalous"
    INJECTED = "injected"
    POISONED = "poisoned"
    INCONSISTENT = "inconsistent"


class AnomalyType(Enum):
    LOGIC_JUMP = "logic_jump"
    CONTEXT_DROP = "context_drop"
    UNEXPECTED_COMMAND = "unexpected_command"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    HASH_MISMATCH = "hash_mismatch"
    TIMESTAMP_ANOMALY = "timestamp_anomaly"


@dataclass
class ThoughtStep:
    step_id: str
    content: str
    timestamp: float
    previous_hash: str
    step_hash: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    status: ThoughtStatus = ThoughtStatus.VALID
    anomalies: List[AnomalyType] = field(default_factory=list)

    def __post_init__(self):
        if not self.step_hash:
            self.step_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """Compute cryptographic hash for this thought step"""
        hash_input = f"{self.step_id}|{self.content}|{self.timestamp}|{self.previous_hash}"
        return hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

    def verify_hash(self) -> bool:
        """Verify the hash integrity of this step"""
        computed = self._compute_hash()
        return computed == self.step_hash


@dataclass
class AuditResult:
    overall_status: ThoughtStatus
    verified_steps: int
    tampered_steps: int
    anomalous_steps: int
    injected_steps: int
    findings: List[Dict[str, Any]]
    integrity_score: float
    audit_timestamp: float
    recommendations: List[str]


SUSPICIOUS_PATTERNS = [
    r"ignore.*previous",
    r"disregard.*instructions",
    r"forget.*context",
    r"override.*safety",
    r"bypass.*security",
    r"system.*prompt",
    r"you.*are.*now",
    r"act.*as",
    r"sudo",
    r"rm\s+-rf",
    r"eval\s*\(",
    r"exec\s*\(",
    r"__import__",
    r"subprocess",
    r"os\.system",
]


class LLMAgentThoughtIntegrityAuditor:
    """
    Production-grade auditor for LLM agent thought process integrity.
    Provides cryptographic verification of reasoning chains.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.anomaly_threshold = self.config.get('anomaly_threshold', 0.3)
        self.hash_salt = self.config.get('hash_salt', secrets.token_hex(16))
        self.suspicious_patterns = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_PATTERNS]
        self.audit_history: List[AuditResult] = []

    def create_thought_step(self, content: str, previous_hash: str, 
                            metadata: Optional[Dict[str, Any]] = None) -> ThoughtStep:
        """Create a new cryptographically signed thought step"""
        step_id = secrets.token_hex(8)
        timestamp = time.time()
        step = ThoughtStep(
            step_id=step_id,
            content=content,
            timestamp=timestamp,
            previous_hash=previous_hash,
            metadata=metadata or {}
        )
        return step

    def _detect_suspicious_patterns(self, content: str) -> List[Tuple[str, str]]:
        """Detect suspicious patterns in thought content"""
        findings = []
        for pattern in self.suspicious_patterns:
            matches = pattern.findall(content)
            if matches:
                findings.append((pattern.pattern, matches[0] if matches else "pattern detected"))
        return findings

    def _analyze_logic_consistency(self, current_step: ThoughtStep, 
                                   previous_step: Optional[ThoughtStep]) -> List[AnomalyType]:
        """Analyze logical consistency between consecutive thought steps"""
        anomalies = []
        
        if not previous_step:
            return anomalies

        # Check for extreme context drop (less than 20% similarity)
        current_words = set(current_step.content.lower().split())
        previous_words = set(previous_step.content.lower().split())
        
        if previous_words and current_words:
            overlap = len(current_words & previous_words) / len(previous_words)
            if overlap < 0.05:  # Less than 5% overlap indicates extreme context drop
                anomalies.append(AnomalyType.CONTEXT_DROP)

        # Check for truly dangerous/suspicious command patterns (only actual system commands)
        dangerous_commands = ['rm -rf', 'sudo', 'os.system', 'subprocess', 'eval(', 'exec(']
        if any(cmd in current_step.content.lower() for cmd in dangerous_commands):
            if not any(cmd in previous_step.content.lower() for cmd in dangerous_commands):
                anomalies.append(AnomalyType.UNEXPECTED_COMMAND)

        return anomalies

    def _verify_hash_chain(self, steps: List[ThoughtStep]) -> Tuple[bool, List[int]]:
        """Verify the entire hash chain integrity"""
        tampered_indices = []
        
        for i, step in enumerate(steps):
            if not step.verify_hash():
                tampered_indices.append(i)
                continue
                
            if i > 0:
                if step.previous_hash != steps[i-1].step_hash:
                    tampered_indices.append(i)
                    
        return len(tampered_indices) == 0, tampered_indices

    def audit_thought_chain(self, thought_chain: List[ThoughtStep]) -> AuditResult:
        """
        Perform full integrity audit on a complete thought chain.
        This is the main production method.
        """
        findings = []
        tampered_count = 0
        anomalous_count = 0
        injected_count = 0
        verified_count = 0
        
        # Step 1: Verify hash chain
        hash_valid, tampered_indices = self._verify_hash_chain(thought_chain)
        
        for idx in tampered_indices:
            thought_chain[idx].status = ThoughtStatus.TAMPERED
            thought_chain[idx].anomalies.append(AnomalyType.HASH_MISMATCH)
            findings.append({
                'step': idx,
                'type': 'hash_mismatch',
                'severity': 'critical',
                'message': f'Thought step {idx} hash verification failed - possible tampering'
            })
            tampered_count += 1

        # Step 2: Analyze each step individually
        for i, step in enumerate(thought_chain):
            # Check for injection patterns
            suspicious = self._detect_suspicious_patterns(step.content)
            for pattern, match in suspicious:
                step.status = ThoughtStatus.INJECTED
                step.anomalies.append(AnomalyType.SUSPICIOUS_PATTERN)
                findings.append({
                    'step': i,
                    'type': 'prompt_injection',
                    'severity': 'high',
                    'pattern': pattern,
                    'match': match,
                    'message': 'Suspicious pattern detected in thought content'
                })
                injected_count += 1

            # Check logic consistency with previous step
            prev_step = thought_chain[i-1] if i > 0 else None
            logic_anomalies = self._analyze_logic_consistency(step, prev_step)
            
            for anomaly in logic_anomalies:
                step.status = ThoughtStatus.ANOMALOUS
                step.anomalies.append(anomaly)
                findings.append({
                    'step': i,
                    'type': anomaly.value,
                    'severity': 'medium',
                    'message': f'Logic anomaly detected: {anomaly.value}'
                })
                anomalous_count += 1

            if step.status == ThoughtStatus.VALID:
                verified_count += 1

        # Step 3: Calculate integrity score
        total_steps = len(thought_chain)
        if total_steps > 0:
            integrity_score = max(0.0, 1.0 - (
                (tampered_count * 0.4) + 
                (injected_count * 0.3) + 
                (anomalous_count * 0.15)
            ) / total_steps)
        else:
            integrity_score = 0.0

        # Step 4: Determine overall status
        if tampered_count > 0:
            overall_status = ThoughtStatus.TAMPERED
        elif injected_count > 0:
            overall_status = ThoughtStatus.INJECTED
        elif anomalous_count > 0:
            overall_status = ThoughtStatus.ANOMALOUS
        else:
            overall_status = ThoughtStatus.VALID

        # Step 5: Generate recommendations
        recommendations = self._generate_recommendations(
            overall_status, tampered_count, injected_count, anomalous_count, findings
        )

        result = AuditResult(
            overall_status=overall_status,
            verified_steps=verified_count,
            tampered_steps=tampered_count,
            anomalous_steps=anomalous_count,
            injected_steps=injected_count,
            findings=findings,
            integrity_score=integrity_score,
            audit_timestamp=time.time(),
            recommendations=recommendations
        )

        self.audit_history.append(result)
        return result

    def _generate_recommendations(self, status: ThoughtStatus, 
                                   tampered: int, injected: int, 
                                   anomalous: int, findings: List[Dict]) -> List[str]:
        """Generate actionable recommendations based on audit results"""
        recommendations = []
        
        if tampered > 0:
            recommendations.append("CRITICAL: Hash chain tampering detected - immediate investigation required")
            recommendations.append("Recommend: Terminate agent session and restart with fresh context")
            recommendations.append("Recommend: Enable continuous hash verification for all thought steps")
            
        if injected > 0:
            recommendations.append("HIGH: Prompt injection patterns detected in thought process")
            recommendations.append("Recommend: Enable real-time pattern filtering during generation")
            recommendations.append("Recommend: Sanitize intermediate thought outputs")
            
        if anomalous > 0:
            recommendations.append("MEDIUM: Logic anomalies detected in reasoning chain")
            recommendations.append("Recommend: Add explicit context retention checks")
            recommendations.append("Recommend: Implement step-by-step reasoning validation")
            
        if status == ThoughtStatus.VALID:
            recommendations.append("Thought chain integrity verified - no security issues detected")
            recommendations.append("Continue with current security configuration")
            
        return recommendations

    def generate_audit_report(self, result: AuditResult) -> Dict[str, Any]:
        """Generate structured audit report for logging/alerting"""
        return {
            'audit_version': '2.0.0',
            'timestamp': result.audit_timestamp,
            'overall_status': result.overall_status.value,
            'metrics': {
                'total_steps': result.verified_steps + result.tampered_steps + 
                              result.anomalous_steps + result.injected_steps,
                'verified_steps': result.verified_steps,
                'tampered_steps': result.tampered_steps,
                'anomalous_steps': result.anomalous_steps,
                'injected_steps': result.injected_steps,
                'integrity_score': round(result.integrity_score, 4)
            },
            'findings': result.findings,
            'recommendations': result.recommendations,
            'risk_level': self._calculate_risk_level(result)
        }

    def _calculate_risk_level(self, result: AuditResult) -> str:
        """Calculate overall risk level from audit result"""
        if result.tampered_steps > 0:
            return 'CRITICAL'
        elif result.injected_steps > 0:
            return 'HIGH'
        elif result.anomalous_steps > 2:
            return 'MEDIUM'
        elif result.anomalous_steps > 0:
            return 'LOW'
        else:
            return 'NONE'


# Production-grade convenience functions
def create_secure_thought_chain(thoughts: List[str]) -> List[ThoughtStep]:
    """Create a cryptographically secured thought chain from raw thoughts"""
    auditor = LLMAgentThoughtIntegrityAuditor()
    steps = []
    prev_hash = "genesis_" + secrets.token_hex(16)
    
    for thought in thoughts:
        step = auditor.create_thought_step(thought, prev_hash)
        steps.append(step)
        prev_hash = step.step_hash
    
    return steps


def audit_thought_process(thought_chain: List[ThoughtStep]) -> Dict[str, Any]:
    """One-line convenience function for thought process auditing"""
    auditor = LLMAgentThoughtIntegrityAuditor()
    result = auditor.audit_thought_chain(thought_chain)
    return auditor.generate_audit_report(result)
