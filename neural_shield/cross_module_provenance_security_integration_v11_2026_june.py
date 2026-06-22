"""
Cross-Module Provenance Security Integration v11
NeuralShield-AI Feature Expansion (Dimension A)

Provides unified security context tracking across all detection modules.
Tracks decision provenance, confidence chains, and cross-module correlation.
ADD-ONLY implementation - no modifications to existing modules.

API Stability: STABLE
"""

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone


class SecurityDecisionType(Enum):
    """Types of security decisions from modules."""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    ADVERSARIAL = "adversarial"
    HALLUCINATION = "hallucination"
    PII_DETECTION = "pii_detection"
    TOXICITY = "toxicity"
    BACKDOOR = "backdoor"
    RAG_POISONING = "rag_poisoning"
    MEMORY_CORRUPTION = "memory_corruption"
    UNKNOWN = "unknown"


class ConfidenceLevel(Enum):
    """Confidence levels for security decisions."""
    VERY_LOW = 0.1
    LOW = 0.3
    MEDIUM = 0.5
    HIGH = 0.7
    VERY_HIGH = 0.9
    CERTAIN = 1.0


@dataclass
class SecurityDecision:
    """Represents a single security decision from a module."""
    module_name: str
    decision_type: SecurityDecisionType
    confidence: float
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    evidence: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "module_name": self.module_name,
            "decision_type": self.decision_type.value,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "evidence": self.evidence,
            "metadata": self.metadata
        }
    
    def get_provenance_hash(self) -> str:
        """Generate a hash for provenance tracking."""
        data = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()


@dataclass
class ProvenanceChain:
    """Chain of security decisions with correlation analysis."""
    chain_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    decisions: List[SecurityDecision] = field(default_factory=list)
    correlations: List[Tuple[str, str, float]] = field(default_factory=list)
    
    def add_decision(self, decision: SecurityDecision) -> None:
        """Add a security decision to the chain."""
        self.decisions.append(decision)
        self._update_correlations(decision)
    
    def _update_correlations(self, new_decision: SecurityDecision) -> None:
        """Update correlations with existing decisions."""
        for existing in self.decisions[:-1]:
            correlation = self._calculate_correlation(existing, new_decision)
            if correlation > 0.3:
                self.correlations.append(
                    (existing.decision_id, new_decision.decision_id, correlation)
                )
    
    def _calculate_correlation(self, d1: SecurityDecision, d2: SecurityDecision) -> float:
        """Calculate correlation between two decisions."""
        score = 0.0
        
        # Same decision type correlation
        if d1.decision_type == d2.decision_type:
            score += 0.4
        
        # Time proximity correlation
        time_diff = abs(d1.timestamp - d2.timestamp)
        if time_diff < 1.0:
            score += 0.3
        elif time_diff < 5.0:
            score += 0.15
        
        # Evidence overlap correlation
        d1_keys = set(d1.evidence.keys())
        d2_keys = set(d2.evidence.keys())
        if d1_keys & d2_keys:
            score += 0.3
        
        return min(score, 1.0)
    
    def get_aggregate_risk_score(self) -> float:
        """Calculate aggregate risk score across all decisions."""
        if not self.decisions:
            return 0.0
        
        weighted_sum = sum(d.confidence for d in self.decisions)
        correlation_bonus = sum(c[2] for c in self.correlations) * 0.1
        return min(weighted_sum / len(self.decisions) + correlation_bonus, 1.0)
    
    def get_decision_by_type(self, decision_type: SecurityDecisionType) -> List[SecurityDecision]:
        """Get all decisions of a specific type."""
        return [d for d in self.decisions if d.decision_type == decision_type]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "decisions": [d.to_dict() for d in self.decisions],
            "correlations": [
                {"from": c[0], "to": c[1], "score": c[2]}
                for c in self.correlations
            ],
            "aggregate_risk": self.get_aggregate_risk_score()
        }


class CrossModuleProvenanceTracker:
    """
    Main tracker for cross-module security provenance.
    
    Tracks security decisions across all NeuralShield modules,
    provides correlation analysis, and maintains audit trails.
    """
    
    def __init__(self, max_chains: int = 1000):
        self.max_chains = max_chains
        self.chains: Dict[str, ProvenanceChain] = {}
        self.active_chain: Optional[ProvenanceChain] = None
        self.module_registry: Dict[str, bool] = {}
        self.audit_log: List[Dict[str, Any]] = []
    
    def register_module(self, module_name: str) -> None:
        """Register a security module for tracking."""
        self.module_registry[module_name] = True
        self._log_audit("module_registered", {"module": module_name})
    
    def start_new_chain(self) -> str:
        """Start a new provenance chain for a request."""
        self._prune_old_chains()
        chain = ProvenanceChain()
        self.chains[chain.chain_id] = chain
        self.active_chain = chain
        self._log_audit("chain_started", {"chain_id": chain.chain_id})
        return chain.chain_id
    
    def track_decision(
        self,
        module_name: str,
        decision_type: SecurityDecisionType,
        confidence: float,
        evidence: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        chain_id: Optional[str] = None
    ) -> str:
        """
        Track a security decision from a module.
        
        Returns: decision_id
        """
        if chain_id and chain_id in self.chains:
            chain = self.chains[chain_id]
        elif self.active_chain:
            chain = self.active_chain
        else:
            chain_id = self.start_new_chain()
            chain = self.chains[chain_id]
        
        decision = SecurityDecision(
            module_name=module_name,
            decision_type=decision_type,
            confidence=max(0.0, min(1.0, confidence)),
            evidence=evidence or {},
            metadata=metadata or {}
        )
        
        chain.add_decision(decision)
        self._log_audit("decision_tracked", {
            "decision_id": decision.decision_id,
            "module": module_name,
            "chain_id": chain.chain_id
        })
        
        return decision.decision_id
    
    def get_chain(self, chain_id: str) -> Optional[ProvenanceChain]:
        """Get a provenance chain by ID."""
        return self.chains.get(chain_id)
    
    def get_chain_risk(self, chain_id: str) -> float:
        """Get aggregate risk score for a chain."""
        chain = self.chains.get(chain_id)
        return chain.get_aggregate_risk_score() if chain else 0.0
    
    def get_module_decisions(self, module_name: str) -> List[SecurityDecision]:
        """Get all decisions from a specific module."""
        decisions = []
        for chain in self.chains.values():
            decisions.extend([
                d for d in chain.decisions 
                if d.module_name == module_name
            ])
        return decisions
    
    def verify_provenance(self, decision_id: str) -> Optional[Dict[str, Any]]:
        """Verify a decision's provenance and return its context."""
        for chain in self.chains.values():
            for decision in chain.decisions:
                if decision.decision_id == decision_id:
                    return {
                        "valid": True,
                        "decision": decision.to_dict(),
                        "provenance_hash": decision.get_provenance_hash(),
                        "chain_id": chain.chain_id,
                        "chain_risk": chain.get_aggregate_risk_score()
                    }
        return {"valid": False, "reason": "decision_not_found"}
    
    def generate_audit_report(self) -> Dict[str, Any]:
        """Generate a comprehensive audit report."""
        total_decisions = sum(len(c.decisions) for c in self.chains.values())
        high_risk = sum(
            1 for c in self.chains.values() 
            if c.get_aggregate_risk_score() > 0.7
        )
        
        return {
            "report_time": datetime.now(timezone.utc).isoformat(),
            "active_chains": len(self.chains),
            "registered_modules": len(self.module_registry),
            "total_decisions_tracked": total_decisions,
            "high_risk_chains": high_risk,
            "audit_log_entries": len(self.audit_log),
            "module_list": list(self.module_registry.keys())
        }
    
    def _prune_old_chains(self) -> None:
        """Prune oldest chains if max limit reached."""
        if len(self.chains) >= self.max_chains:
            sorted_chains = sorted(
                self.chains.items(),
                key=lambda x: x[1].decisions[0].timestamp if x[1].decisions else 0
            )
            remove_count = len(self.chains) - self.max_chains + 1
            for chain_id, _ in sorted_chains[:remove_count]:
                del self.chains[chain_id]
    
    def _log_audit(self, event_type: str, data: Dict[str, Any]) -> None:
        """Log an audit event."""
        self.audit_log.append({
            "timestamp": time.time(),
            "event_type": event_type,
            "data": data
        })


# Global tracker instance
_global_tracker: Optional[CrossModuleProvenanceTracker] = None


def get_provenance_tracker() -> CrossModuleProvenanceTracker:
    """Get or create the global provenance tracker instance."""
    global _global_tracker
    if _global_tracker is None:
        _global_tracker = CrossModuleProvenanceTracker()
    return _global_tracker


def track_security_decision(
    module_name: str,
    decision_type: str,
    confidence: float,
    evidence: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> str:
    """
    Convenience function to track a security decision.
    
    Easy integration wrapper for existing modules.
    """
    tracker = get_provenance_tracker()
    
    try:
        decision_enum = SecurityDecisionType(decision_type)
    except ValueError:
        decision_enum = SecurityDecisionType.UNKNOWN
    
    return tracker.track_decision(
        module_name=module_name,
        decision_type=decision_enum,
        confidence=confidence,
        evidence=evidence,
        metadata=metadata
    )


# Export public API
__all__ = [
    "CrossModuleProvenanceTracker",
    "ProvenanceChain",
    "SecurityDecision",
    "SecurityDecisionType",
    "ConfidenceLevel",
    "get_provenance_tracker",
    "track_security_decision"
]
