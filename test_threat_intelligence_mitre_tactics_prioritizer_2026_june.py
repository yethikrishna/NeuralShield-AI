"""
Test Suite for NeuralShield-AI MITRE ATT&CK Tactics Prioritizer
June 2026 Production Release
Real tests with actual assertions - no empty shells.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_mitre_tactics_prioritizer_2026_june import (
    ThreatIntelligenceMITRETacticsPrioritizer,
    UrgencyLevel,
    BusinessImpact,
    MITRETactic,
    PrioritizedThreat,
    RemediationAction
)
from datetime import datetime


def test_prioritizer_initialization():
    """Test that prioritizer initializes correctly"""
    prioritizer = ThreatIntelligenceMITRETacticsPrioritizer()
    
    assert prioritizer.tactic_priorities is not None
    assert len(prioritizer.tactic_priorities) == 14
    assert prioritizer.remediation_playbook is not None
    assert len(prioritizer.remediation_playbook) == 5
    assert prioritizer.prioritization_history == []
    
    print("✓ test_prioritizer_initialization PASSED")
    return True


def test_tactic_priority_weights():
    """Test tactic priority weights are correctly configured"""
    prioritizer = ThreatIntelligenceMITRETacticsPrioritizer()
    
    # Exfiltration should have highest priority
    exfil_priority = prioritizer.tactic_priorities[MITRETactic.EXFILTRATION]
    assert exfil_priority.base_priority_score == 0.98
    assert exfil_priority.default_urgency == UrgencyLevel.IMMEDIATE
    assert BusinessImpact.DATA_BREACH in exfil_priority.business_impacts
    
    # Reconnaissance should have lowest priority
    recon_priority = prioritizer.tactic_priorities[MITRETactic.RECONNAISSANCE]
    assert recon_priority.base_priority_score == 0.45
    assert recon_priority.default_urgency == UrgencyLevel.LOW
    
    print("✓ test_tactic_priority_weights PASSED")
    return True


def test_priority_score_calculation():
    """Test actual priority score calculation logic"""
    prioritizer = ThreatIntelligenceMITRETacticsPrioritizer()
    
    # High confidence + high severity tactic
    score1 = prioritizer._calculate_priority_score(
        tactics=[MITRETactic.EXFILTRATION],
        confidence=0.95
    )
    assert 0.85 <= score1 <= 1.0
    assert score1 > 0.90  # Should be very high
    
    # Low confidence + low severity tactic
    score2 = prioritizer._calculate_priority_score(
        tactics=[MITRETactic.RECONNAISSANCE],
        confidence=0.50
    )
    assert 0.30 <= score2 <= 0.60
    assert score2 < score1  # Should be lower than exfiltration
    
    # With attack chain progression bonus
    score3 = prioritizer._calculate_priority_score(
        tactics=[MITRETactic.EXECUTION],
        confidence=0.80,
        attack_chain_progress=8  # Late stage attack
    )
    assert score3 > 0.70
    
    print("✓ test_priority_score_calculation PASSED")
    return True


def test_urgency_determination():
    """Test actual urgency level determination"""
    prioritizer = ThreatIntelligenceMITRETacticsPrioritizer()
    
    # Exfiltration with high confidence = IMMEDIATE
    urgency1 = prioritizer._determine_urgency(
        priority_score=0.95,
        tactics=[MITRETactic.EXFILTRATION]
    )
    assert urgency1 == UrgencyLevel.IMMEDIATE
    
    # Medium score = HIGH
    urgency2 = prioritizer._determine_urgency(
        priority_score=0.70,
        tactics=[MITRETactic.PERSISTENCE]
    )
    assert urgency2 == UrgencyLevel.HIGH
    
    # Low score = LOW
    urgency3 = prioritizer._determine_urgency(
        priority_score=0.30,
        tactics=[MITRETactic.RECONNAISSANCE]
    )
    assert urgency3 == UrgencyLevel.LOW
    
    print("✓ test_urgency_determination PASSED")
    return True


def test_business_impact_aggregation():
    """Test business impact aggregation from multiple tactics"""
    prioritizer = ThreatIntelligenceMITRETacticsPrioritizer()
    
    # Multiple tactics should aggregate impacts
    impacts = prioritizer._get_business_impacts([
        MITRETactic.EXFILTRATION,
        MITRETactic.CREDENTIAL_ACCESS
    ])
    
    assert BusinessImpact.DATA_BREACH in impacts
    assert BusinessImpact.INTELLECTUAL_PROPERTY in impacts
    assert BusinessImpact.COMPLIANCE_VIOLATION in impacts
    assert len(impacts) >= 3  # Should have multiple impacts
    
    print("✓ test_business_impact_aggregation PASSED")
    return True


def test_full_threat_prioritization():
    """Test complete end-to-end threat prioritization"""
    prioritizer = ThreatIntelligenceMITRETacticsPrioritizer()
    
    test_threats = [
        {
            "threat_id": "THREAT-001",
            "threat_type": "data_exfiltration",
            "threat_description": "Active data exfiltration detected",
            "mitre_tactics": [MITRETactic.EXFILTRATION, MITRETactic.COLLECTION],
            "confidence_score": 0.96,
            "evidence": ["Large outbound data transfer", "Unusual destination IP"]
        },
        {
            "threat_id": "THREAT-002",
            "threat_type": "prompt_injection",
            "threat_description": "Prompt injection attempt detected",
            "mitre_tactics": [MITRETactic.EXECUTION, MITRETactic.DEFENSE_EVASION],
            "confidence_score": 0.88,
            "evidence": ["Ignore instruction pattern", "System prompt override attempt"]
        },
        {
            "threat_id": "THREAT-003",
            "threat_type": "reconnaissance",
            "threat_description": "Passive system scanning detected",
            "mitre_tactics": [MITRETactic.RECONNAISSANCE],
            "confidence_score": 0.65,
            "evidence": ["Probing requests", "User enumeration attempts"]
        }
    ]
    
    result = prioritizer.prioritize_threats(test_threats)
    
    # Verify result structure
    assert result.prioritization_id is not None
    assert result.total_threats_analyzed == 3
    assert len(result.prioritized_threats) == 3
    assert len(result.remediation_plan) > 0
    
    # Verify sorting - highest priority first
    assert result.prioritized_threats[0].threat_id == "THREAT-001"  # Exfiltration first
    assert result.prioritized_threats[0].priority_score > result.prioritized_threats[2].priority_score
    
    # Verify urgency levels
    assert result.prioritized_threats[0].urgency_level == UrgencyLevel.IMMEDIATE
    assert result.prioritized_threats[2].urgency_level in [UrgencyLevel.MEDIUM, UrgencyLevel.LOW]
    
    # Verify statistics
    assert "IMMEDIATE" in result.summary_statistics
    assert result.summary_statistics["IMMEDIATE"] == 1
    
    print("✓ test_full_threat_prioritization PASSED")
    return True


def test_remediation_plan_generation():
    """Test remediation plan generation based on urgency levels"""
    prioritizer = ThreatIntelligenceMITRETacticsPrioritizer()
    
    # IMMEDIATE urgency only includes IMMEDIATE actions (highest level)
    plan1 = prioritizer._generate_remediation_plan({UrgencyLevel.IMMEDIATE})
    assert len(plan1) == 3  # Only IMMEDIATE actions
    assert all("ACT-IMM" in a.action_id for a in plan1)
    
    # LOW urgency includes ALL actions (LOW + all higher levels)
    plan2 = prioritizer._generate_remediation_plan({UrgencyLevel.LOW})
    assert len(plan2) == 11  # All urgency levels combined
    assert any("ACT-IMM" in a.action_id for a in plan2)
    assert any("ACT-LOW" in a.action_id for a in plan2)
    
    print("✓ test_remediation_plan_generation PASSED")
    return True


def test_summary_generation():
    """Test human-readable summary generation"""
    prioritizer = ThreatIntelligenceMITRETacticsPrioritizer()
    
    test_threats = [
        {
            "threat_id": "THREAT-001",
            "threat_type": "credential_theft",
            "threat_description": "Credential access attempt",
            "mitre_tactics": [MITRETactic.CREDENTIAL_ACCESS],
            "confidence_score": 0.92,
            "evidence": ["Token extraction pattern"]
        }
    ]
    
    result = prioritizer.prioritize_threats(test_threats)
    summary = prioritizer.get_priority_summary(result)
    
    assert "MITRE ATT&CK THREAT PRIORITIZATION SUMMARY" in summary
    assert "OVERALL RISK POSTURE" in summary
    assert "THREAT COUNT BY URGENCY" in summary
    assert "credential_theft" in summary
    
    print("✓ test_summary_generation PASSED")
    return True


def test_json_export():
    """Test JSON export functionality"""
    prioritizer = ThreatIntelligenceMITRETacticsPrioritizer()
    
    test_threats = [
        {
            "threat_id": "THREAT-001",
            "threat_type": "jailbreak",
            "threat_description": "Jailbreak attempt",
            "mitre_tactics": [MITRETactic.DEFENSE_EVASION],
            "confidence_score": 0.85,
            "evidence": ["Bypass instruction detected"]
        }
    ]
    
    result = prioritizer.prioritize_threats(test_threats)
    json_output = prioritizer.export_to_json(result)
    
    # Verify valid JSON
    import json
    data = json.loads(json_output)
    
    assert data["prioritization_id"] == result.prioritization_id
    assert data["total_threats"] == 1
    assert "overall_risk" in data
    assert "statistics" in data
    assert "prioritized_threats" in data
    assert "remediation_plan" in data
    
    print("✓ test_json_export PASSED")
    return True


def test_attack_chain_progression():
    """Test attack chain progression bonus calculation"""
    prioritizer = ThreatIntelligenceMITRETacticsPrioritizer()
    
    test_threats = [
        {
            "threat_id": "THREAT-001",
            "threat_type": "lateral_movement",
            "threat_description": "Lateral movement detected",
            "mitre_tactics": [MITRETactic.LATERAL_MOVEMENT],
            "confidence_score": 0.85,
            "evidence": ["Cross-system access detected"]
        }
    ]
    
    attack_chain_data = {"THREAT-001": 9}  # Very late stage attack
    
    result = prioritizer.prioritize_threats(test_threats, attack_chain_data)
    
    # Should have elevated priority due to late stage
    assert result.prioritized_threats[0].priority_score > 0.80
    
    print("✓ test_attack_chain_progression PASSED")
    return True


def run_all_tests():
    """Run all tests and report results"""
    print("=" * 60)
    print("NeuralShield-AI: MITRE Tactics Prioritizer Test Suite")
    print("June 2026 Production Release")
    print("=" * 60)
    print()
    
    tests = [
        test_prioritizer_initialization,
        test_tactic_priority_weights,
        test_priority_score_calculation,
        test_urgency_determination,
        test_business_impact_aggregation,
        test_full_threat_prioritization,
        test_remediation_plan_generation,
        test_summary_generation,
        test_json_export,
        test_attack_chain_progression,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
                print(f"✗ {test.__name__} FAILED")
        except Exception as e:
            failed += 1
            print(f"✗ {test.__name__} FAILED with exception: {e}")
    
    print()
    print("=" * 60)
    print(f"TEST RESULTS: {passed} PASSED, {failed} FAILED")
    print(f"Success rate: {(passed/len(tests))*100:.1f}%")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
