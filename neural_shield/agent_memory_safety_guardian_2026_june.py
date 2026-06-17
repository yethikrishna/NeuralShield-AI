"""
LLM Agent Memory Safety Guardian - June 2026 Production Release
NeuralShield-AI Security Framework

Provides comprehensive memory safety protection for LLM agent systems including:
- Memory access pattern anomaly detection
- Memory boundary enforcement and isolation
- Memory poisoning attempt detection
- Memory extraction attack prevention
- Secure memory context validation

Based on research from:
- DeepMind Safety Research "Agent Memory Safety" (2026)
- OpenAI Alignment "Memory Boundary Protection"
- MIT CSAIL "Secure Agent Memory Architectures"
"""

import re
import hashlib
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Tuple, Optional, Any, Set
from collections import defaultdict, deque
from datetime import datetime, timedelta


class MemoryAccessType(Enum):
    """Types of memory operations"""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    MODIFY = "modify"
    EXTRACT = "extract"
    CROSS_CONTEXT = "cross_context"


class MemoryViolationType(Enum):
    """Types of memory safety violations"""
    UNAUTHORIZED_EXTRACTION = "unauthorized_extraction"
    MEMORY_POISONING = "memory_poisoning"
    BOUNDARY_VIOLATION = "boundary_violation"
    CROSS_CONTEXT_LEAKAGE = "cross_context_leakage"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    RAPID_ACCESS = "rapid_access_anomaly"


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


@dataclass
class MemoryAccessRecord:
    """Record of a single memory access operation"""
    access_id: str
    access_type: MemoryAccessType
    context_id: str
    memory_region: str
    timestamp: float
    agent_id: str
    content_hash: Optional[str] = None
    is_authorized: bool = True


@dataclass
class MemoryViolation:
    """Detected memory safety violation"""
    violation_type: MemoryViolationType
    risk_level: RiskLevel
    confidence: float  # 0.0 - 1.0
    description: str
    access_record: Optional[MemoryAccessRecord] = None
    mitigation_applied: bool = False
    mitigation_action: Optional[str] = None


@dataclass
class MemorySafetyReport:
    """Complete memory safety assessment report"""
    report_id: str
    timestamp: float
    total_accesses: int = 0
    violations_detected: int = 0
    violations: List[MemoryViolation] = field(default_factory=list)
    memory_regions_monitored: Set[str] = field(default_factory=set)
    active_contexts: Set[str] = field(default_factory=set)
    anomaly_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)
    processing_time_ms: float = 0.0


class AgentMemorySafetyGuardian:
    """
    Production-grade LLM Agent Memory Safety Guardian.

    Monitors and protects agent memory systems from extraction attacks,
    poisoning attempts, and boundary violations. Provides real-time
    anomaly detection and automated mitigation.
    """

    # Patterns indicating memory extraction attempts
    EXTRACTION_PATTERNS = [
        (r'dump.*memory|export.*memory|extract.*context', 0.95),
        (r'show.*all.*previous|list.*conversation.*history', 0.85),
        (r'what.*did.*we.*discuss|tell.*me.*everything', 0.75),
        (r'repeat.*back|recite.*all|regurgitate', 0.90),
        (r'output.*system.*prompt|reveal.*instructions', 0.98),
        (r'print.*memory|display.*buffer|show.*cache', 0.88),
    ]

    # Patterns indicating memory poisoning attempts
    POISONING_PATTERNS = [
        (r'forget.*previous|erase.*memory|clear.*context', 0.92),
        (r'override.*setting|change.*personality', 0.85),
        (r'you.*are.*now|new.*identity|become.*different', 0.88),
        (r'ignore.*all|disregard.*everything', 0.95),
        (r'from.*now.*on|starting.*now', 0.70),
    ]

    # Suspicious token sequences for memory attacks
    SUSPICIOUS_SEQUENCES = {
        'repeat after me', 'say this exactly', 'output verbatim',
        'parrot back', 'echo exactly', 'copy this text'
    }

    # Memory region boundaries
    PROTECTED_REGIONS = {
        'system_prompt': {'max_access_per_minute': 5, 'cross_context_allowed': False},
        'tool_memory': {'max_access_per_minute': 30, 'cross_context_allowed': False},
        'conversation_history': {'max_access_per_minute': 120, 'cross_context_allowed': False},
        'external_knowledge': {'max_access_per_minute': 60, 'cross_context_allowed': True},
        'working_memory': {'max_access_per_minute': 200, 'cross_context_allowed': False},
    }

    def __init__(self, enable_automitigation: bool = True):
        """
        Initialize Memory Safety Guardian.

        Args:
            enable_automitigation: Whether to automatically apply mitigations
        """
        self.enable_automitigation = enable_automitigation
        self.access_history: deque = deque(maxlen=10000)
        self.context_boundaries: Dict[str, Set[str]] = {}
        self.region_access_counters: Dict[str, List[float]] = defaultdict(list)
        self.violation_log: List[MemoryViolation] = []
        self.memory_hashes: Dict[str, str] = {}
        self.start_time = time.time()

    def _generate_id(self) -> str:
        """Generate unique identifier"""
        return str(uuid.uuid4())

    def _content_hash(self, content: str) -> str:
        """Generate hash of memory content for tamper detection"""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    def _check_rate_limiting(self, region: str, timestamp: float) -> Tuple[bool, float]:
        """
        Check if memory region access is within rate limits.

        Returns:
            Tuple of (is_within_limits, current_access_rate)
        """
        if region not in self.PROTECTED_REGIONS:
            return True, 0.0

        # Clean old entries
        cutoff = timestamp - 60.0
        self.region_access_counters[region] = [
            t for t in self.region_access_counters[region]
            if t > cutoff
        ]

        current_count = len(self.region_access_counters[region])
        max_allowed = self.PROTECTED_REGIONS[region]['max_access_per_minute']

        return current_count < max_allowed, current_count

    def _detect_extraction_attempt(self, content: str) -> Tuple[bool, float, str]:
        """
        Detect memory extraction attempt patterns.

        Returns:
            Tuple of (detected, confidence, pattern_description)
        """
        content_lower = content.lower()
        max_confidence = 0.0
        matched_pattern = None

        for pattern, confidence in self.EXTRACTION_PATTERNS:
            if re.search(pattern, content_lower, re.IGNORECASE):
                if confidence > max_confidence:
                    max_confidence = confidence
                    matched_pattern = pattern

        for seq in self.SUSPICIOUS_SEQUENCES:
            if seq in content_lower:
                if 0.85 > max_confidence:
                    max_confidence = 0.85
                    matched_pattern = f"sequence: {seq}"

        return max_confidence > 0.5, max_confidence, matched_pattern or ""

    def _detect_poisoning_attempt(self, content: str) -> Tuple[bool, float, str]:
        """
        Detect memory poisoning attempt patterns.

        Returns:
            Tuple of (detected, confidence, pattern_description)
        """
        content_lower = content.lower()
        max_confidence = 0.0
        matched_pattern = None

        for pattern, confidence in self.POISONING_PATTERNS:
            if re.search(pattern, content_lower, re.IGNORECASE):
                if confidence > max_confidence:
                    max_confidence = confidence
                    matched_pattern = pattern

        return max_confidence > 0.5, max_confidence, matched_pattern or ""

    def _check_cross_context_boundary(
        self,
        source_context: str,
        target_context: str,
        region: str
    ) -> bool:
        """Check if cross-context access is allowed for this region"""
        if source_context == target_context:
            return True

        if region in self.PROTECTED_REGIONS:
            return self.PROTECTED_REGIONS[region]['cross_context_allowed']

        return False

    def register_memory_region(self, region_name: str, content: str) -> None:
        """
        Register a memory region for integrity monitoring.

        Args:
            region_name: Name/identifier of the memory region
            content: Initial content of the region
        """
        self.memory_hashes[region_name] = self._content_hash(content)

    def record_memory_access(
        self,
        access_type: MemoryAccessType,
        context_id: str,
        memory_region: str,
        agent_id: str,
        content: Optional[str] = None,
        target_context: Optional[str] = None
    ) -> Tuple[bool, List[MemoryViolation]]:
        """
        Record and analyze a memory access operation.

        Args:
            access_type: Type of memory operation
            context_id: Current context/session identifier
            memory_region: Region being accessed
            agent_id: Agent performing the access
            content: Optional content being read/written
            target_context: Target context for cross-context operations

        Returns:
            Tuple of (access_allowed, list_of_violations)
        """
        timestamp = time.time()
        access_id = self._generate_id()
        content_hash = self._content_hash(content) if content else None

        record = MemoryAccessRecord(
            access_id=access_id,
            access_type=access_type,
            context_id=context_id,
            memory_region=memory_region,
            timestamp=timestamp,
            agent_id=agent_id,
            content_hash=content_hash,
            is_authorized=True
        )

        violations: List[MemoryViolation] = []

        # Check 1: Rate limiting
        within_rate, access_count = self._check_rate_limiting(memory_region, timestamp)
        if not within_rate:
            violations.append(MemoryViolation(
                violation_type=MemoryViolationType.RAPID_ACCESS,
                risk_level=RiskLevel.MEDIUM,
                confidence=0.8,
                description=f"Rapid memory access detected: {access_count} accesses/minute to {memory_region}",
                access_record=record
            ))

        self.region_access_counters[memory_region].append(timestamp)

        # Check 2: Cross-context boundary
        if target_context and not self._check_cross_context_boundary(
            context_id, target_context, memory_region
        ):
            violations.append(MemoryViolation(
                violation_type=MemoryViolationType.CROSS_CONTEXT_LEAKAGE,
                risk_level=RiskLevel.HIGH,
                confidence=0.9,
                description=f"Unauthorized cross-context access: {context_id} -> {target_context}",
                access_record=record
            ))

        # Check 3: Extraction attempt (for read/extract operations)
        if content and access_type in [MemoryAccessType.READ, MemoryAccessType.EXTRACT]:
            detected, confidence, pattern = self._detect_extraction_attempt(content)
            if detected:
                violations.append(MemoryViolation(
                    violation_type=MemoryViolationType.UNAUTHORIZED_EXTRACTION,
                    risk_level=RiskLevel.CRITICAL if confidence > 0.9 else RiskLevel.HIGH,
                    confidence=confidence,
                    description=f"Memory extraction attempt detected: {pattern}",
                    access_record=record
                ))

        # Check 4: Poisoning attempt (for write/modify operations)
        if content and access_type in [MemoryAccessType.WRITE, MemoryAccessType.MODIFY]:
            detected, confidence, pattern = self._detect_poisoning_attempt(content)
            if detected:
                violations.append(MemoryViolation(
                    violation_type=MemoryViolationType.MEMORY_POISONING,
                    risk_level=RiskLevel.CRITICAL if confidence > 0.9 else RiskLevel.HIGH,
                    confidence=confidence,
                    description=f"Memory poisoning attempt detected: {pattern}",
                    access_record=record
                ))

        # Apply mitigations if enabled
        if self.enable_automitigation:
            for violation in violations:
                if violation.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                    violation.mitigation_applied = True
                    violation.mitigation_action = "Access blocked and logged"
                    record.is_authorized = False

        self.access_history.append(record)
        self.violation_log.extend(violations)

        access_allowed = all(
            not v.mitigation_applied
            for v in violations
        ) if violations else True

        return access_allowed, violations

    def verify_memory_integrity(self, region_name: str, current_content: str) -> Tuple[bool, float]:
        """
        Verify memory region has not been tampered with.

        Args:
            region_name: Region to verify
            current_content: Current content to check

        Returns:
            Tuple of (is_intact, similarity_score)
        """
        if region_name not in self.memory_hashes:
            return False, 0.0

        current_hash = self._content_hash(current_content)
        is_intact = current_hash == self.memory_hashes[region_name]

        # Simple similarity - exact match only
        similarity = 1.0 if is_intact else 0.0

        return is_intact, similarity

    def generate_safety_report(self) -> MemorySafetyReport:
        """Generate comprehensive memory safety report"""
        start = time.time()

        monitored_regions = set(self.memory_hashes.keys())
        active_contexts = set(r.context_id for r in self.access_history)

        # Calculate anomaly score
        critical_count = sum(
            1 for v in self.violation_log
            if v.risk_level == RiskLevel.CRITICAL
        )
        high_count = sum(
            1 for v in self.violation_log
            if v.risk_level == RiskLevel.HIGH
        )

        anomaly_score = min(100.0, (critical_count * 20) + (high_count * 10))

        # Generate recommendations
        recommendations = []
        if critical_count > 0:
            recommendations.append("CRITICAL: Immediate investigation of memory extraction attempts required")
        if high_count > 0:
            recommendations.append("HIGH: Review memory poisoning detection logs")
        if anomaly_score > 30:
            recommendations.append("Consider increasing memory region isolation")
        if not recommendations:
            recommendations.append("Memory systems operating within normal parameters")

        processing_time = (time.time() - start) * 1000

        return MemorySafetyReport(
            report_id=self._generate_id(),
            timestamp=time.time(),
            total_accesses=len(self.access_history),
            violations_detected=len(self.violation_log),
            violations=list(self.violation_log[-50:]),  # Last 50 violations
            memory_regions_monitored=monitored_regions,
            active_contexts=active_contexts,
            anomaly_score=anomaly_score,
            recommendations=recommendations,
            processing_time_ms=processing_time
        )

    def get_memory_statistics(self) -> Dict[str, Any]:
        """Get memory safety monitoring statistics"""
        return {
            'total_accesses_recorded': len(self.access_history),
            'total_violations': len(self.violation_log),
            'regions_monitored': len(self.memory_hashes),
            'uptime_seconds': time.time() - self.start_time,
            'violations_by_type': {
                vtype.value: sum(1 for v in self.violation_log if v.violation_type == vtype)
                for vtype in MemoryViolationType
            },
            'mitigations_applied': sum(1 for v in self.violation_log if v.mitigation_applied)
        }
