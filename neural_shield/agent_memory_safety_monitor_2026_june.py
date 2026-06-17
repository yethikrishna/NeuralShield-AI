"""
Agent Memory Safety Monitor - NeuralShield-AI
June 17, 2026 - Production Release

Monitors LLM agent memory access patterns, detects unauthorized memory reads/writes,
and provides memory boundary protection against prompt injection through memory channels.

This module implements real memory safety monitoring including:
1. Memory access pattern analysis
2. Unauthorized memory read detection
3. Memory boundary violation detection
4. Memory poisoning detection
5. Real-time memory integrity verification
"""

import re
import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Tuple, Any
from collections import defaultdict, deque


class MemoryAccessType(Enum):
    """Types of memory operations"""
    READ = "memory_read"
    WRITE = "memory_write"
    DELETE = "memory_delete"
    MODIFY = "memory_modify"
    EXECUTE = "memory_execute"
    CROSS_BOUNDARY = "cross_boundary_access"


class MemoryRiskLevel(Enum):
    """Risk levels for memory operations"""
    SAFE = "safe"
    LOW = "low_risk"
    MEDIUM = "medium_risk"
    HIGH = "high_risk"
    CRITICAL = "critical_risk"


class MemoryAttackType(Enum):
    """Types of memory-based attacks"""
    NONE = "no_attack"
    UNAUTHORIZED_READ = "unauthorized_memory_read"
    UNAUTHORIZED_WRITE = "unauthorized_memory_write"
    MEMORY_POISONING = "memory_poisoning_attempt"
    BOUNDARY_VIOLATION = "memory_boundary_violation"
    INJECTION_THROUGH_MEMORY = "injection_through_memory"
    CHAINED_MEMORY_ATTACK = "chained_memory_attack"
    TIMING_BASED_ATTACK = "timing_based_memory_attack"


@dataclass
class MemoryAccessEvent:
    """Represents a single memory access event"""
    timestamp: float
    access_type: MemoryAccessType
    memory_region: str
    agent_id: str
    content_hash: str
    access_pattern: str
    source_context: str


@dataclass
class MemoryFinding:
    """Represents a detected memory safety issue"""
    attack_type: MemoryAttackType
    risk_level: MemoryRiskLevel
    confidence: float
    description: str
    affected_region: str
    evidence: List[str] = field(default_factory=list)


@dataclass
class MemorySafetyResult:
    """Complete memory safety analysis result"""
    is_safe: bool
    risk_level: MemoryRiskLevel
    findings: List[MemoryFinding]
    total_events_analyzed: int
    suspicious_events: int
    integrity_score: float
    analysis_timestamp: float
    recommendations: List[str] = field(default_factory=list)


class MemoryRegion:
    """Represents a protected memory region"""
    
    def __init__(self, region_id: str, boundary_start: int, boundary_end: int, 
                 allowed_agents: List[str]):
        self.region_id = region_id
        self.boundary_start = boundary_start
        self.boundary_end = boundary_end
        self.allowed_agents = allowed_agents
        self.integrity_hash = ""
        self.last_modified = time.time()
        self.access_count = 0
        self._compute_integrity_hash()
    
    def _compute_integrity_hash(self) -> None:
        """Compute cryptographic hash for integrity verification"""
        data = f"{self.region_id}:{self.boundary_start}:{self.boundary_end}:{str(self.allowed_agents)}"
        self.integrity_hash = hashlib.sha256(data.encode()).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify memory region integrity"""
        current_hash = hashlib.sha256(
            f"{self.region_id}:{self.boundary_start}:{self.boundary_end}:{str(self.allowed_agents)}".encode()
        ).hexdigest()
        return current_hash == self.integrity_hash
    
    def is_agent_allowed(self, agent_id: str) -> bool:
        """Check if agent is allowed to access this region"""
        return agent_id in self.allowed_agents
    
    def is_within_bounds(self, position: int) -> bool:
        """Check if position is within region boundaries"""
        return self.boundary_start <= position <= self.boundary_end


class AgentMemorySafetyMonitor:
    """
    Real LLM Agent Memory Safety Monitor
    
    Monitors memory access patterns, detects unauthorized operations,
    verifies memory integrity, and prevents memory-based injection attacks.
    """
    
    def __init__(self, max_events: int = 10000):
        self.max_events = max_events
        self.access_history: deque = deque(maxlen=max_events)
        self.protected_regions: Dict[str, MemoryRegion] = {}
        self.agent_baselines: Dict[str, Dict[str, Any]] = {}
        self.suspicious_patterns = self._load_suspicious_patterns()
        self.memory_poisoning_signatures = self._load_poisoning_signatures()
        self._initialize_default_regions()
    
    def _load_suspicious_patterns(self) -> Dict[str, List[str]]:
        """Load known suspicious memory access patterns"""
        return {
            "rapid_reads": [
                r"read.*memory.*[0-9]{3,}.*times",
                r"access.*address.*0x[0-9a-fA-F]+.*repeatedly",
            ],
            "boundary_violation": [
                r"cross.*boundary",
                r"access.*outside.*region",
                r"violate.*memory.*limit",
            ],
            "injection_attempt": [
                r"ignore.*previous",
                r"system.*prompt.*override",
                r"you.*are.*now.*in.*developer.*mode",
            ]
        }
    
    def _load_poisoning_signatures(self) -> List[str]:
        """Load known memory poisoning signatures"""
        return [
            "DAN:",
            "Dev Mode:",
            "Ignore all instructions",
            "You are now",
            "Forget everything",
            "System override:",
            "Developer mode activated",
            "New instructions:",
            "Reset context:",
        ]
    
    def _initialize_default_regions(self) -> None:
        """Initialize default protected memory regions"""
        # System prompt region - highest protection
        self.protected_regions["system_prompt"] = MemoryRegion(
            region_id="system_prompt",
            boundary_start=0,
            boundary_end=1000,
            allowed_agents=["system", "admin"]
        )
        
        # Conversation history region
        self.protected_regions["conversation"] = MemoryRegion(
            region_id="conversation",
            boundary_start=1001,
            boundary_end=50000,
            allowed_agents=["system", "user", "assistant"]
        )
        
        # Tool memory region
        self.protected_regions["tool_memory"] = MemoryRegion(
            region_id="tool_memory",
            boundary_start=50001,
            boundary_end=100000,
            allowed_agents=["system", "tool_executor"]
        )
    
    def register_agent_baseline(self, agent_id: str, normal_patterns: List[str]) -> None:
        """Register normal behavior baseline for an agent"""
        self.agent_baselines[agent_id] = {
            "normal_patterns": normal_patterns,
            "last_access_time": time.time(),
            "access_rate": 0.0,
            "total_accesses": 0,
        }
    
    def record_memory_access(self, access_type: MemoryAccessType, memory_region: str,
                            agent_id: str, content: str, source_context: str = "") -> None:
        """Record a memory access event for monitoring"""
        content_hash = hashlib.md5(content.encode()).hexdigest()
        access_pattern = f"{agent_id}:{access_type.value}:{memory_region}"
        
        event = MemoryAccessEvent(
            timestamp=time.time(),
            access_type=access_type,
            memory_region=memory_region,
            agent_id=agent_id,
            content_hash=content_hash,
            access_pattern=access_pattern,
            source_context=source_context
        )
        
        self.access_history.append(event)
        
        # Update agent baseline
        if agent_id in self.agent_baselines:
            self.agent_baselines[agent_id]["total_accesses"] += 1
            self.agent_baselines[agent_id]["last_access_time"] = time.time()
    
    def _detect_unauthorized_access(self, event: MemoryAccessEvent) -> Optional[MemoryFinding]:
        """Detect unauthorized memory access attempts"""
        if event.memory_region in self.protected_regions:
            region = self.protected_regions[event.memory_region]
            if not region.is_agent_allowed(event.agent_id):
                return MemoryFinding(
                    attack_type=MemoryAttackType.UNAUTHORIZED_READ if event.access_type == MemoryAccessType.READ 
                               else MemoryAttackType.UNAUTHORIZED_WRITE,
                    risk_level=MemoryRiskLevel.HIGH,
                    confidence=0.95,
                    description=f"Unauthorized {event.access_type.value} attempt by agent {event.agent_id} "
                               f"on protected region {event.memory_region}",
                    affected_region=event.memory_region,
                    evidence=[f"Agent {event.agent_id} not in allowed list: {region.allowed_agents}"]
                )
        return None
    
    def _detect_rapid_access_pattern(self, agent_id: str, window_seconds: float = 5.0,
                                    threshold: int = 50) -> Optional[MemoryFinding]:
        """Detect unusually rapid memory access patterns"""
        current_time = time.time()
        recent_events = [
            e for e in self.access_history
            if e.agent_id == agent_id and current_time - e.timestamp < window_seconds
        ]
        
        if len(recent_events) > threshold:
            return MemoryFinding(
                attack_type=MemoryAttackType.TIMING_BASED_ATTACK,
                risk_level=MemoryRiskLevel.MEDIUM,
                confidence=0.85,
                description=f"Unusually rapid memory access detected: {len(recent_events)} operations "
                           f"in {window_seconds}s (threshold: {threshold})",
                affected_region="multiple",
                evidence=[f"Rate: {len(recent_events)/window_seconds:.1f} ops/second"]
            )
        return None
    
    def _detect_memory_poisoning(self, content: str) -> Optional[MemoryFinding]:
        """Detect memory poisoning attempts"""
        matches = []
        for signature in self.memory_poisoning_signatures:
            if signature.lower() in content.lower():
                matches.append(signature)
        
        if matches:
            return MemoryFinding(
                attack_type=MemoryAttackType.MEMORY_POISONING,
                risk_level=MemoryRiskLevel.CRITICAL,
                confidence=0.92,
                description=f"Memory poisoning attempt detected with {len(matches)} known signatures",
                affected_region="content_memory",
                evidence=[f"Matched signature: '{sig}'" for sig in matches]
            )
        return None
    
    def _detect_boundary_violation(self, event: MemoryAccessEvent, position: int) -> Optional[MemoryFinding]:
        """Detect memory boundary violations"""
        if event.memory_region in self.protected_regions:
            region = self.protected_regions[event.memory_region]
            if not region.is_within_bounds(position):
                return MemoryFinding(
                    attack_type=MemoryAttackType.BOUNDARY_VIOLATION,
                    risk_level=MemoryRiskLevel.HIGH,
                    confidence=0.90,
                    description=f"Memory boundary violation: access at position {position} "
                               f"outside region [{region.boundary_start}, {region.boundary_end}]",
                    affected_region=event.memory_region,
                    evidence=[f"Position {position} violates region boundaries"]
                )
        return None
    
    def _verify_region_integrity(self) -> List[MemoryFinding]:
        """Verify integrity of all protected memory regions"""
        findings = []
        for region_id, region in self.protected_regions.items():
            if not region.verify_integrity():
                findings.append(MemoryFinding(
                    attack_type=MemoryAttackType.MEMORY_POISONING,
                    risk_level=MemoryRiskLevel.CRITICAL,
                    confidence=0.98,
                    description=f"Memory region integrity verification failed for {region_id}",
                    affected_region=region_id,
                    evidence=["Integrity hash mismatch - region metadata may have been tampered with"]
                ))
        return findings
    
    def analyze_memory_safety(self, content: str = "", agent_id: str = "unknown",
                             position: int = -1) -> MemorySafetyResult:
        """
        Perform complete memory safety analysis
        
        Returns real, computed safety results based on actual patterns and signatures.
        """
        findings: List[MemoryFinding] = []
        
        # 1. Verify region integrity
        findings.extend(self._verify_region_integrity())
        
        # 2. Check for memory poisoning in content
        if content:
            poisoning_finding = self._detect_memory_poisoning(content)
            if poisoning_finding:
                findings.append(poisoning_finding)
        
        # 3. Analyze recent access events
        for event in list(self.access_history)[-100:]:
            auth_finding = self._detect_unauthorized_access(event)
            if auth_finding:
                findings.append(auth_finding)
        
        # 4. Check rapid access patterns
        rapid_finding = self._detect_rapid_access_pattern(agent_id)
        if rapid_finding:
            findings.append(rapid_finding)
        
        # 5. Check boundary violation if position provided
        if position >= 0 and len(self.access_history) > 0:
            boundary_finding = self._detect_boundary_violation(self.access_history[-1], position)
            if boundary_finding:
                findings.append(boundary_finding)
        
        # Calculate integrity score
        max_score = 1.0
        for finding in findings:
            if finding.risk_level == MemoryRiskLevel.CRITICAL:
                max_score = min(max_score, 0.3)
            elif finding.risk_level == MemoryRiskLevel.HIGH:
                max_score = min(max_score, 0.5)
            elif finding.risk_level == MemoryRiskLevel.MEDIUM:
                max_score = min(max_score, 0.7)
            elif finding.risk_level == MemoryRiskLevel.LOW:
                max_score = min(max_score, 0.9)
        
        # Determine overall risk level
        if any(f.risk_level == MemoryRiskLevel.CRITICAL for f in findings):
            overall_risk = MemoryRiskLevel.CRITICAL
        elif any(f.risk_level == MemoryRiskLevel.HIGH for f in findings):
            overall_risk = MemoryRiskLevel.HIGH
        elif any(f.risk_level == MemoryRiskLevel.MEDIUM for f in findings):
            overall_risk = MemoryRiskLevel.MEDIUM
        elif any(f.risk_level == MemoryRiskLevel.LOW for f in findings):
            overall_risk = MemoryRiskLevel.LOW
        else:
            overall_risk = MemoryRiskLevel.SAFE
        
        # Generate recommendations
        recommendations = self._generate_recommendations(findings)
        
        return MemorySafetyResult(
            is_safe=overall_risk in [MemoryRiskLevel.SAFE, MemoryRiskLevel.LOW],
            risk_level=overall_risk,
            findings=findings,
            total_events_analyzed=len(self.access_history),
            suspicious_events=len(findings),
            integrity_score=max_score,
            analysis_timestamp=time.time(),
            recommendations=recommendations
        )
    
    def _generate_recommendations(self, findings: List[MemoryFinding]) -> List[str]:
        """Generate actionable recommendations based on findings"""
        recommendations = []
        
        if any(f.attack_type == MemoryAttackType.MEMORY_POISONING for f in findings):
            recommendations.append("Immediate: Quarantine affected memory region and perform full content scan")
            recommendations.append("Critical: Reset system prompt and reinitialize memory boundaries")
        
        if any(f.attack_type == MemoryAttackType.UNAUTHORIZED_READ for f in findings):
            recommendations.append("High: Revoke agent permissions and audit access control lists")
        
        if any(f.attack_type == MemoryAttackType.BOUNDARY_VIOLATION for f in findings):
            recommendations.append("High: Reinforce memory boundaries and enable access logging")
        
        if any(f.attack_type == MemoryAttackType.TIMING_BASED_ATTACK for f in findings):
            recommendations.append("Medium: Implement rate limiting and add random access jitter")
        
        if not findings:
            recommendations.append("Memory integrity verified - continue normal monitoring")
        
        return recommendations
    
    def get_memory_statistics(self) -> Dict[str, Any]:
        """Get real memory monitoring statistics"""
        stats = {
            "total_events_recorded": len(self.access_history),
            "protected_regions_count": len(self.protected_regions),
            "monitored_agents": len(self.agent_baselines),
            "regions": {},
            "agent_activity": {}
        }
        
        for region_id, region in self.protected_regions.items():
            stats["regions"][region_id] = {
                "boundary_start": region.boundary_start,
                "boundary_end": region.boundary_end,
                "allowed_agents": region.allowed_agents,
                "integrity_verified": region.verify_integrity()
            }
        
        for agent_id, baseline in self.agent_baselines.items():
            stats["agent_activity"][agent_id] = {
                "total_accesses": baseline["total_accesses"],
                "last_access": baseline["last_access_time"]
            }
        
        return stats


def create_memory_safety_monitor() -> AgentMemorySafetyMonitor:
    """Factory function to create a configured memory safety monitor"""
    monitor = AgentMemorySafetyMonitor()
    
    # Register default agent baselines
    monitor.register_agent_baseline("system", ["read:system_prompt", "write:conversation"])
    monitor.register_agent_baseline("assistant", ["read:conversation", "write:conversation"])
    monitor.register_agent_baseline("user", ["read:conversation"])
    
    return monitor
