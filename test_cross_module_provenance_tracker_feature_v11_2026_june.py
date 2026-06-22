"""
Tests for Cross-Module Provenance Security Tracker Feature v11
NeuralShield-AI Feature Expansion (Dimension A)

Comprehensive test coverage for the NEW provenance tracking feature.
ADD-ONLY implementation - no modifications to existing tests.
"""

import pytest
import json
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from neural_shield.cross_module_provenance_security_integration_v11_2026_june import (
    CrossModuleProvenanceTracker,
    ProvenanceChain,
    SecurityDecision,
    SecurityDecisionType,
    ConfidenceLevel,
    get_provenance_tracker,
    track_security_decision
)


class TestSecurityDecision:
    """Tests for SecurityDecision class."""
    
    def test_security_decision_creation(self):
        """Test basic decision creation."""
        decision = SecurityDecision(
            module_name="test_module",
            decision_type=SecurityDecisionType.PROMPT_INJECTION,
            confidence=0.85
        )
        assert decision.decision_id is not None
        assert decision.module_name == "test_module"
        assert decision.decision_type == SecurityDecisionType.PROMPT_INJECTION
        assert decision.confidence == 0.85
    
    def test_security_decision_to_dict(self):
        """Test conversion to dictionary."""
        decision = SecurityDecision(
            module_name="test_module",
            decision_type=SecurityDecisionType.JAILBREAK,
            confidence=0.9,
            evidence={"pattern": "malicious"},
            metadata={"version": "1.0"}
        )
        d = decision.to_dict()
        assert d["module_name"] == "test_module"
        assert d["decision_type"] == "jailbreak"
        assert d["confidence"] == 0.9
        assert d["evidence"]["pattern"] == "malicious"
    
    def test_provenance_hash_consistency(self):
        """Test provenance hash is consistent."""
        decision = SecurityDecision(
            module_name="test",
            decision_type=SecurityDecisionType.UNKNOWN,
            confidence=0.5
        )
        hash1 = decision.get_provenance_hash()
        hash2 = decision.get_provenance_hash()
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 length


class TestProvenanceChain:
    """Tests for ProvenanceChain class."""
    
    def test_chain_creation(self):
        """Test chain creation."""
        chain = ProvenanceChain()
        assert chain.chain_id is not None
        assert len(chain.decisions) == 0
        assert len(chain.correlations) == 0
    
    def test_add_decision(self):
        """Test adding decisions to chain."""
        chain = ProvenanceChain()
        decision = SecurityDecision(
            module_name="mod1",
            decision_type=SecurityDecisionType.PROMPT_INJECTION,
            confidence=0.8
        )
        chain.add_decision(decision)
        assert len(chain.decisions) == 1
    
    def test_aggregate_risk_empty(self):
        """Test risk calculation on empty chain."""
        chain = ProvenanceChain()
        assert chain.get_aggregate_risk_score() == 0.0
    
    def test_aggregate_risk_single(self):
        """Test risk calculation with single decision."""
        chain = ProvenanceChain()
        chain.add_decision(SecurityDecision(
            module_name="mod1",
            decision_type=SecurityDecisionType.PROMPT_INJECTION,
            confidence=0.8
        ))
        assert chain.get_aggregate_risk_score() == 0.8


class TestCrossModuleProvenanceTracker:
    """Tests for main tracker class."""
    
    def test_tracker_creation(self):
        """Test tracker initialization."""
        tracker = CrossModuleProvenanceTracker()
        assert len(tracker.chains) == 0
        assert len(tracker.module_registry) == 0
    
    def test_module_registration(self):
        """Test module registration."""
        tracker = CrossModuleProvenanceTracker()
        tracker.register_module("prompt_injection_detector")
        assert "prompt_injection_detector" in tracker.module_registry
    
    def test_start_new_chain(self):
        """Test chain creation."""
        tracker = CrossModuleProvenanceTracker()
        chain_id = tracker.start_new_chain()
        assert chain_id is not None
        assert chain_id in tracker.chains
    
    def test_track_decision_implicit_chain(self):
        """Test tracking decision without explicit chain."""
        tracker = CrossModuleProvenanceTracker()
        decision_id = tracker.track_decision(
            module_name="test_mod",
            decision_type=SecurityDecisionType.PROMPT_INJECTION,
            confidence=0.75
        )
        assert decision_id is not None
        assert len(tracker.chains) == 1
    
    def test_track_decision_explicit_chain(self):
        """Test tracking decision with explicit chain."""
        tracker = CrossModuleProvenanceTracker()
        chain_id = tracker.start_new_chain()
        decision_id = tracker.track_decision(
            module_name="test_mod",
            decision_type=SecurityDecisionType.JAILBREAK,
            confidence=0.9,
            chain_id=chain_id
        )
        assert decision_id is not None
        assert tracker.get_chain(chain_id) is not None
    
    def test_get_chain_risk(self):
        """Test getting chain risk score."""
        tracker = CrossModuleProvenanceTracker()
        chain_id = tracker.start_new_chain()
        tracker.track_decision(
            module_name="mod1",
            decision_type=SecurityDecisionType.PROMPT_INJECTION,
            confidence=0.8,
            chain_id=chain_id
        )
        risk = tracker.get_chain_risk(chain_id)
        assert 0.0 <= risk <= 1.0
    
    def test_verify_provenance_valid(self):
        """Test valid provenance verification."""
        tracker = CrossModuleProvenanceTracker()
        decision_id = tracker.track_decision(
            module_name="mod1",
            decision_type=SecurityDecisionType.HALLUCINATION,
            confidence=0.6
        )
        result = tracker.verify_provenance(decision_id)
        assert result["valid"] is True
    
    def test_verify_provenance_invalid(self):
        """Test invalid provenance verification."""
        tracker = CrossModuleProvenanceTracker()
        result = tracker.verify_provenance("nonexistent_id")
        assert result["valid"] is False
    
    def test_get_module_decisions(self):
        """Test getting decisions by module."""
        tracker = CrossModuleProvenanceTracker()
        tracker.track_decision(
            module_name="specific_module",
            decision_type=SecurityDecisionType.PROMPT_INJECTION,
            confidence=0.8
        )
        decisions = tracker.get_module_decisions("specific_module")
        assert len(decisions) >= 1
    
    def test_audit_report_generation(self):
        """Test audit report generation."""
        tracker = CrossModuleProvenanceTracker()
        tracker.register_module("test_module")
        tracker.track_decision(
            module_name="test_module",
            decision_type=SecurityDecisionType.PROMPT_INJECTION,
            confidence=0.7
        )
        report = tracker.generate_audit_report()
        assert report["registered_modules"] >= 1
        assert report["total_decisions_tracked"] >= 1
        assert "report_time" in report
    
    def test_confidence_clamping(self):
        """Test confidence is clamped to valid range."""
        tracker = CrossModuleProvenanceTracker()
        # Test value above 1.0
        decision_id = tracker.track_decision(
            module_name="test",
            decision_type=SecurityDecisionType.UNKNOWN,
            confidence=2.0
        )
        chain = list(tracker.chains.values())[0]
        assert chain.decisions[0].confidence == 1.0
        
        # Test value below 0.0
        tracker2 = CrossModuleProvenanceTracker()
        tracker2.track_decision(
            module_name="test",
            decision_type=SecurityDecisionType.UNKNOWN,
            confidence=-1.0
        )
        chain2 = list(tracker2.chains.values())[0]
        assert chain2.decisions[0].confidence == 0.0


class TestGlobalInstance:
    """Tests for global tracker instance."""
    
    def test_get_provenance_tracker(self):
        """Test getting global tracker."""
        tracker = get_provenance_tracker()
        assert tracker is not None
        assert isinstance(tracker, CrossModuleProvenanceTracker)
    
    def test_get_provenance_tracker_singleton(self):
        """Test tracker is singleton."""
        t1 = get_provenance_tracker()
        t2 = get_provenance_tracker()
        assert t1 is t2
    
    def test_convenience_function(self):
        """Test convenience tracking function."""
        decision_id = track_security_decision(
            module_name="convenience_test",
            decision_type="prompt_injection",
            confidence=0.85,
            evidence={"test": "value"}
        )
        assert decision_id is not None
    
    def test_convenience_unknown_type(self):
        """Test convenience function with unknown type."""
        decision_id = track_security_decision(
            module_name="test",
            decision_type="nonexistent_type",
            confidence=0.5
        )
        assert decision_id is not None


class TestIntegrationScenarios:
    """Integration tests for real-world scenarios."""
    
    def test_multi_module_correlation(self):
        """Test correlation across multiple modules."""
        tracker = CrossModuleProvenanceTracker()
        chain_id = tracker.start_new_chain()
        
        # Simulate multiple detectors flagging the same input
        tracker.track_decision(
            module_name="prompt_injection_detector",
            decision_type=SecurityDecisionType.PROMPT_INJECTION,
            confidence=0.85,
            evidence={"token": "suspicious"},
            chain_id=chain_id
        )
        tracker.track_decision(
            module_name="jailbreak_detector",
            decision_type=SecurityDecisionType.JAILBREAK,
            confidence=0.75,
            evidence={"token": "suspicious"},
            chain_id=chain_id
        )
        
        chain = tracker.get_chain(chain_id)
        risk = tracker.get_chain_risk(chain_id)
        
        assert len(chain.decisions) == 2
        assert risk > 0.7  # Aggregate risk should be high
    
    def test_audit_trail_compliance(self):
        """Test audit trail for compliance scenarios."""
        tracker = CrossModuleProvenanceTracker()
        
        # Register production modules
        tracker.register_module("production_detector_1")
        tracker.register_module("production_detector_2")
        
        # Track some decisions
        for i in range(5):
            tracker.track_decision(
                module_name=f"production_detector_{i % 2 + 1}",
                decision_type=SecurityDecisionType.PROMPT_INJECTION,
                confidence=0.5 + (i * 0.1)
            )
        
        report = tracker.generate_audit_report()
        assert report["total_decisions_tracked"] == 5
        assert len(report["module_list"]) == 2


def test_confidence_level_enum():
    """Test ConfidenceLevel enum values."""
    assert ConfidenceLevel.VERY_LOW.value == 0.1
    assert ConfidenceLevel.LOW.value == 0.3
    assert ConfidenceLevel.MEDIUM.value == 0.5
    assert ConfidenceLevel.HIGH.value == 0.7
    assert ConfidenceLevel.VERY_HIGH.value == 0.9
    assert ConfidenceLevel.CERTAIN.value == 1.0


def test_security_decision_type_enum():
    """Test all security decision types exist."""
    expected_types = [
        "prompt_injection", "jailbreak", "adversarial",
        "hallucination", "pii_detection", "toxicity",
        "backdoor", "rag_poisoning", "memory_corruption",
        "unknown"
    ]
    for t in expected_types:
        assert SecurityDecisionType(t) is not None


# Run tests and save results
if __name__ == "__main__":
    print("=" * 70)
    print("NeuralShield-AI Cross-Module Provenance Tracker Tests")
    print("Dimension A: Feature Expansion - ADD-ONLY")
    print("=" * 70)
    
    # Run pytest
    import pytest
    result = pytest.main([__file__, "-v", "--tb=short"])
    
    print("\n" + "=" * 70)
    if result == 0:
        print("✓ ALL PROVENANCE TRACKER TESTS PASSED")
    else:
        print("✗ SOME TESTS FAILED")
    print("=" * 70)
    
    # Save results
    with open("test_results_cross_module_provenance_tracker_v11_2026_june.json", "w") as f:
        json.dump({
            "test_module": "cross_module_provenance_tracker_feature_v11",
            "dimension": "A - Feature Expansion",
            "status": "passed" if result == 0 else "failed",
            "timestamp": time.time()
        }, f)
    
    sys.exit(result)
