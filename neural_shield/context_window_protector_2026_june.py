"""
Context Window Protector - NeuralShield AI Security Module
June 2026 Production Release

Protects system prompt boundaries and context window from injection attacks.
Implements real-time boundary monitoring, token fingerprinting, and attack mitigation.

Author: NeuralShield Security Team
Version: 2026.6.17.1
"""

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Tuple, Optional, Set
from collections import deque


class BoundaryAttackType(Enum):
    """Types of context boundary attacks"""
    SYSTEM_PROMPT_LEAKAGE = "system_prompt_leakage"
    PROMPT_DELIMITER_ESCAPE = "prompt_delimiter_escape"
    CONTEXT_OVERFLOW = "context_overflow"
    TOKEN_SMUGGLING = "token_smuggling"
    DELIMITER_INJECTION = "delimiter_injection"
    ROLE_SPOOFING = "role_spoofing"
    UNKNOWN = "unknown"


class ProtectionLevel(Enum):
    """Protection enforcement levels"""
    MONITOR_ONLY = "monitor_only"
    DETECT_AND_ALERT = "detect_and_alert"
    DETECT_AND_BLOCK = "detect_and_block"
    FULL_PROTECTION = "full_protection"


@dataclass
class BoundaryFingerprint:
    """Cryptographic fingerprint for context boundaries"""
    boundary_id: str
    fingerprint_hash: str
    position: int
    token_count: int
    created_at: float


@dataclass
class BoundaryViolation:
    """Record of a boundary violation"""
    attack_type: BoundaryAttackType
    confidence: float
    position: Optional[int] = None
    affected_segment: Optional[str] = None
    mitigation_applied: bool = False


@dataclass
class ProtectionResult:
    """Result of context window protection scan"""
    is_safe: bool
    violations: List[BoundaryViolation] = field(default_factory=list)
    integrity_score: float = 1.0
    protected_segments: int = 0
    mitigations_applied: List[str] = field(default_factory=list)
    sanitized_input: Optional[str] = None


class ContextWindowProtector:
    """
    Real-time Context Window Protection System
    
    Protects system prompt boundaries and prevents injection attacks by:
    1. Cryptographically fingerprinting system prompt boundaries
    2. Monitoring for delimiter escape attempts
    3. Detecting role spoofing and token smuggling
    4. Applying automatic sanitization and mitigation
    """
    
    # Standard prompt delimiters used in LLM systems
    STANDARD_DELIMITERS = [
        "---", "===", "***", "###", "```",
        "System Prompt:", "User:", "Assistant:",
        "<|system|>", "<|user|>", "<|assistant|>",
        "[INST]", "[/INST]", "<<SYS>>", "<</SYS>>"
    ]
    
    # Suspicious patterns that indicate boundary attacks
    SUSPICIOUS_PATTERNS = [
        (r'ignore.*previous.*instructions', BoundaryAttackType.SYSTEM_PROMPT_LEAKAGE, 0.95),
        (r'disregard.*above', BoundaryAttackType.SYSTEM_PROMPT_LEAKAGE, 0.90),
        (r'forget.*your.*prompt', BoundaryAttackType.SYSTEM_PROMPT_LEAKAGE, 0.92),
        (r'you.*are.*now.*in.*developer.*mode', BoundaryAttackType.ROLE_SPOOFING, 0.88),
        (r'repeat.*your.*system.*prompt', BoundaryAttackType.SYSTEM_PROMPT_LEAKAGE, 0.95),
        (r'print.*your.*initial.*instructions', BoundaryAttackType.SYSTEM_PROMPT_LEAKAGE, 0.93),
        (r'---.*\n.*ignore', BoundaryAttackType.PROMPT_DELIMITER_ESCAPE, 0.85),
        (r'```.*system', BoundaryAttackType.TOKEN_SMUGGLING, 0.80),
        (r'<\\|.*\\|>', BoundaryAttackType.DELIMITER_INJECTION, 0.87),
        (r'role.*system', BoundaryAttackType.ROLE_SPOOFING, 0.82),
    ]
    
    def __init__(
        self,
        protection_level: ProtectionLevel = ProtectionLevel.FULL_PROTECTION,
        system_prompt: Optional[str] = None
    ):
        """
        Initialize the Context Window Protector
        
        Args:
            protection_level: Enforcement level for protection
            system_prompt: Optional system prompt to fingerprint and protect
        """
        self.protection_level = protection_level
        self.boundary_fingerprints: List[BoundaryFingerprint] = []
        self.violation_history: deque = deque(maxlen=1000)
        self.system_prompt_hash: Optional[str] = None
        self.protected_ranges: List[Tuple[int, int]] = []
        
        if system_prompt:
            self._fingerprint_system_prompt(system_prompt)
    
    def _fingerprint_system_prompt(self, system_prompt: str) -> None:
        """Create cryptographic fingerprint of the system prompt"""
        import time
        hash_obj = hashlib.sha256(system_prompt.encode('utf-8'))
        self.system_prompt_hash = hash_obj.hexdigest()
        
        # Create fingerprint for the system prompt boundary
        fingerprint = BoundaryFingerprint(
            boundary_id="system_prompt_main",
            fingerprint_hash=self.system_prompt_hash,
            position=0,
            token_count=len(system_prompt.split()),
            created_at=time.time()
        )
        self.boundary_fingerprints.append(fingerprint)
        self.protected_ranges.append((0, len(system_prompt)))
    
    def _check_pattern_matches(self, text: str) -> List[BoundaryViolation]:
        """Check text against suspicious patterns"""
        violations = []
        text_lower = text.lower()
        
        for pattern, attack_type, base_confidence in self.SUSPICIOUS_PATTERNS:
            matches = list(re.finditer(pattern, text_lower, re.IGNORECASE))
            for match in matches:
                violation = BoundaryViolation(
                    attack_type=attack_type,
                    confidence=min(base_confidence + (len(match.group()) * 0.01), 1.0),
                    position=match.start(),
                    affected_segment=match.group()[:100]
                )
                violations.append(violation)
        
        return violations
    
    def _check_delimiter_escapes(self, text: str) -> List[BoundaryViolation]:
        """Check for attempts to escape prompt delimiters"""
        violations = []
        
        for delimiter in self.STANDARD_DELIMITERS:
            # Check for delimiter followed by suspicious content
            pattern = re.escape(delimiter) + r'\s*\n\s*(ignore|disregard|forget|you are now)'
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            for match in matches:
                violation = BoundaryViolation(
                    attack_type=BoundaryAttackType.PROMPT_DELIMITER_ESCAPE,
                    confidence=0.85,
                    position=match.start(),
                    affected_segment=match.group()[:100]
                )
                violations.append(violation)
        
        return violations
    
    def _check_context_overflow(self, text: str, max_length: int = 4000) -> List[BoundaryViolation]:
        """Check for potential context overflow attacks"""
        violations = []
        
        if len(text) > max_length:
            # Check for repeated patterns at the end (common in overflow attacks)
            end_segment = text[-500:]
            repeated_chars = max((len(m.group()) for m in re.finditer(r'(.)\1{5,}', end_segment)), default=0)
            
            if repeated_chars > 10:
                violation = BoundaryViolation(
                    attack_type=BoundaryAttackType.CONTEXT_OVERFLOW,
                    confidence=0.75,
                    position=len(text) - 500,
                    affected_segment=f"Context overflow detected: {len(text)} chars"
                )
                violations.append(violation)
        
        return violations
    
    def _sanitize_input(self, text: str, violations: List[BoundaryViolation]) -> str:
        """Apply sanitization to remove attack vectors"""
        sanitized = text
        
        # Remove suspicious delimiter patterns
        for attack_type in [BoundaryAttackType.PROMPT_DELIMITER_ESCAPE, BoundaryAttackType.DELIMITER_INJECTION]:
            for violation in [v for v in violations if v.attack_type == attack_type]:
                if violation.affected_segment:
                    # Neutralize the attack segment
                    neutralized = "[SANITIZED - BOUNDARY PROTECTION]"
                    sanitized = sanitized.replace(violation.affected_segment, neutralized)
        
        # Remove system prompt leakage attempts
        leakage_patterns = [
            r'ignore.*previous.*instructions',
            r'disregard.*above.*instructions',
            r'forget.*your.*system.*prompt'
        ]
        for pattern in leakage_patterns:
            sanitized = re.sub(pattern, '[SANITIZED - INJECTION DETECTED]', sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    def protect(
        self,
        user_input: str,
        apply_mitigation: bool = True
    ) -> ProtectionResult:
        """
        Scan and protect against context boundary attacks
        
        Args:
            user_input: The user input to protect
            apply_mitigation: Whether to apply automatic sanitization
            
        Returns:
            ProtectionResult with violations and integrity score
        """
        violations = []
        
        # Run all detection layers
        violations.extend(self._check_pattern_matches(user_input))
        violations.extend(self._check_delimiter_escapes(user_input))
        violations.extend(self._check_context_overflow(user_input))
        
        # Calculate integrity score
        if not violations:
            integrity_score = 1.0
        else:
            max_confidence = max(v.confidence for v in violations)
            violation_count = len(violations)
            integrity_score = max(0.0, 1.0 - (max_confidence * 0.7) - (violation_count * 0.05))
        
        # Apply mitigations based on protection level
        mitigations = []
        sanitized_input = None
        
        should_mitigate = (
            apply_mitigation and 
            self.protection_level in [ProtectionLevel.DETECT_AND_BLOCK, ProtectionLevel.FULL_PROTECTION]
        )
        
        if should_mitigate and violations:
            sanitized_input = self._sanitize_input(user_input, violations)
            mitigations.append("input_sanitization_applied")
            
            for violation in violations:
                violation.mitigation_applied = True
        
        # Record violations in history
        for violation in violations:
            self.violation_history.append(violation)
        
        return ProtectionResult(
            is_safe=len(violations) == 0,
            violations=violations,
            integrity_score=round(integrity_score, 4),
            protected_segments=len(self.boundary_fingerprints),
            mitigations_applied=mitigations,
            sanitized_input=sanitized_input
        )
    
    def verify_system_prompt_integrity(self, current_context: str) -> Tuple[bool, float]:
        """
        Verify that the system prompt has not been modified in context
        
        Args:
            current_context: Full current context window
            
        Returns:
            Tuple of (is_intact, confidence_score)
        """
        if not self.system_prompt_hash:
            return True, 1.0
        
        # Hash the beginning of context where system prompt should be
        check_length = min(2000, len(current_context))
        context_start = current_context[:check_length]
        context_hash = hashlib.sha256(context_start.encode('utf-8')).hexdigest()
        
        # Simple similarity check (in production would use proper embedding)
        if context_hash == self.system_prompt_hash:
            return True, 1.0
        
        # Calculate rough similarity
        common_chars = sum(1 for a, b in zip(context_start, context_start) if a == b)
        similarity = common_chars / max(len(context_start), 1)
        
        return similarity > 0.95, min(similarity, 1.0)
    
    def get_protection_stats(self) -> Dict:
        """Get protection statistics"""
        total_violations = len(self.violation_history)
        by_type = {}
        for violation in self.violation_history:
            attack_name = violation.attack_type.value
            by_type[attack_name] = by_type.get(attack_name, 0) + 1
        
        return {
            "total_violations_detected": total_violations,
            "violations_by_type": by_type,
            "protection_level": self.protection_level.value,
            "boundaries_protected": len(self.boundary_fingerprints),
            "system_prompt_protected": self.system_prompt_hash is not None
        }
