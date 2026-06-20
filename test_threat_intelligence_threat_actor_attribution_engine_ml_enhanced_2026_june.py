#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Threat Actor Attribution Engine (ML-Enhanced)
Production-grade testing with comprehensive coverage.
"""
import json
import sys
from datetime import datetime, timezone, timedelta
from typing import Dict, List

# Add neural_shield to path
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_threat_actor_attribution_engine_ml_enhanced_2026_june import (
    ThreatActorAttributionEngine,
    AttackObservation,
    MLAttributionResult,
    AttributionConfidenceLevel,
    AttributionMethod
)


def run_tests():
    """Run all attribution engine tests"""
    print("=" * 70)
    print("NeuralShield AI - Threat Actor Attribution Engine (ML-Enhanced) Tests")
    print("=" * 70)
    
    test_results = []
    
    # Test 1: Engine initialization
    print("\n[TEST 1] Engine Initialization")
    try:
        engine = ThreatActorAttributionEngine()
        model_state = engine.export_attribution_model()
        assert len(model_state["known_actors"]) == 5, "Should have 5 known actors"
        assert model_state["historical_attributions_count"] == 0
        print("  ✓ Engine initialized successfully")
        print(f"  ✓ Known actors: {model_state['known_actors']}")
        test_results.append(("Engine Initialization", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Engine Initialization", False, str(e)))
        return test_results
    
    # Test 2: APT29 (Cozy Bear) attribution
    print("\n[TEST 2] APT29 (Cozy Bear) Attribution")
    try:
        observation = AttackObservation(
            observation_id="TEST-001",
            observed_ttps=["spear_phishing", "credential_stuffing", "lateral_movement", "persistence"],
            observed_techniques=["T1566", "T1110", "T1021", "T1053"],
            observed_iocs={"ip": [], "domain": []},
            observed_tools=["CozyDuke", "PowerShell"],
            attack_timeline=[
                datetime(2026, 6, 20, 10, 30, tzinfo=timezone.utc),
                datetime(2026, 6, 20, 11, 15, tzinfo=timezone.utc),
                datetime(2026, 6, 20, 14, 45, tzinfo=timezone.utc)
            ],
            victim_sector="government"
        )
        
        result = engine.attribute_attack(observation)
        
        assert result.actor_id == "APT29", f"Expected APT29, got {result.actor_id}"
        assert result.confidence_score > 0.7, f"Confidence too low: {result.confidence_score}"
        assert result.behavioral_similarity_score > 0.5
        print(f"  ✓ Correctly attributed to: {result.actor_name} ({result.actor_id})")
        print(f"  ✓ Confidence score: {result.confidence_score:.2%}")
        print(f"  ✓ Confidence level: {result.confidence_level.value}")
        test_results.append(("APT29 Attribution", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("APT29 Attribution", False, str(e)))
    
    # Test 3: LAPSUS$ attribution
    print("\n[TEST 3] LAPSUS$ Attribution")
    try:
        observation = AttackObservation(
            observation_id="TEST-002",
            observed_ttps=["social_engineering", "initial_access", "data_exfiltration", "data_leak"],
            observed_techniques=["T1589", "T1078", "T1048"],
            observed_iocs={"ip": [], "domain": []},
            observed_tools=["Mimikatz", "RDP", "VPN"],
            attack_timeline=[datetime(2026, 6, 20, 15, 0, tzinfo=timezone.utc)],
            victim_sector="technology"
        )
        
        result = engine.attribute_attack(observation)
        
        assert result.actor_id == "LAPSUS$", f"Expected LAPSUS$, got {result.actor_id}"
        assert result.confidence_score > 0.6
        print(f"  ✓ Correctly attributed to: {result.actor_name}")
        print(f"  ✓ Confidence score: {result.confidence_score:.2%}")
        print(f"  ✓ Feature contributions: {[f'{k}: {v:.1%}' for k, v in result.feature_contributions.items()]}")
        test_results.append(("LAPSUS$ Attribution", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("LAPSUS$ Attribution", False, str(e)))
    
    # Test 4: CONTI ransomware attribution
    print("\n[TEST 4] CONTI Ransomware Attribution")
    try:
        observation = AttackObservation(
            observation_id="TEST-003",
            observed_ttps=["ransomware", "double_extortion", "lateral_movement"],
            observed_techniques=["T1486", "T1021", "T1003"],
            observed_iocs={"ip": [], "domain": []},
            observed_tools=["Cobalt Strike", "TrickBot"],
            attack_timeline=[datetime(2026, 6, 20, 9, 0, tzinfo=timezone.utc)],
            victim_sector="healthcare"
        )
        
        result = engine.attribute_attack(observation)
        
        assert result.actor_id == "CONTI", f"Expected CONTI, got {result.actor_id}"
        print(f"  ✓ Correctly attributed to: {result.actor_name}")
        print(f"  ✓ Confidence score: {result.confidence_score:.2%}")
        print(f"  ✓ Uncertainty estimate: {result.uncertainty_estimate:.2%}")
        test_results.append(("CONTI Attribution", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("CONTI Attribution", False, str(e)))
    
    # Test 5: Anonymous hacktivist attribution
    print("\n[TEST 5] Anonymous Hacktivist Attribution")
    try:
        observation = AttackObservation(
            observation_id="TEST-004",
            observed_ttps=["ddos", "defacement", "social_media", "public_claim"],
            observed_techniques=["T1498", "T1491"],
            observed_iocs={"ip": [], "domain": []},
            observed_tools=["LOIC"],
            attack_timeline=[datetime(2026, 6, 20, 12, 0, tzinfo=timezone.utc)],
            victim_sector="political"
        )
        
        result = engine.attribute_attack(observation)
        
        assert result.actor_id == "ANONYMOUS", f"Expected ANONYMOUS, got {result.actor_id}"
        print(f"  ✓ Correctly attributed to: {result.actor_name}")
        print(f"  ✓ Confidence score: {result.confidence_score:.2%}")
        test_results.append(("Anonymous Attribution", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Anonymous Attribution", False, str(e)))
    
    # Test 6: Batch attribution
    print("\n[TEST 6] Batch Attribution Processing")
    try:
        observations = [
            AttackObservation(
                observation_id=f"BATCH-{i}",
                observed_ttps=["spear_phishing", "lateral_movement"],
                observed_techniques=["T1566", "T1021"],
                observed_iocs={},
                observed_tools=["PowerShell"],
                attack_timeline=[datetime.now(timezone.utc)],
                victim_sector="government"
            )
            for i in range(5)
        ]
        
        batch_results = engine.batch_attribute(observations)
        
        assert len(batch_results) == 5
        print(f"  ✓ Successfully processed {len(batch_results)} observations in batch")
        test_results.append(("Batch Attribution", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Batch Attribution", False, str(e)))
    
    # Test 7: Statistics tracking
    print("\n[TEST 7] Attribution Statistics")
    try:
        stats = engine.get_attribution_statistics()
        
        assert stats["total_attributions"] > 0
        assert "actor_distribution" in stats
        assert "average_confidence" in stats
        print(f"  ✓ Total attributions: {stats['total_attributions']}")
        print(f"  ✓ Average confidence: {stats['average_confidence']:.2%}")
        print(f"  ✓ Actor distribution: {stats['actor_distribution']}")
        test_results.append(("Statistics Tracking", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Statistics Tracking", False, str(e)))
    
    # Test 8: Alternative candidates
    print("\n[TEST 8] Alternative Candidates Generation")
    try:
        # Ambiguous observation that could match multiple actors
        observation = AttackObservation(
            observation_id="TEST-AMBIGUOUS",
            observed_ttps=["spear_phishing"],
            observed_techniques=["T1566"],
            observed_iocs={},
            observed_tools=[],
            attack_timeline=[datetime.now(timezone.utc)]
        )
        
        result = engine.attribute_attack(observation)
        
        assert len(result.alternative_candidates) > 0
        assert len(result.probability_distribution) > 1
        print(f"  ✓ Primary: {result.actor_id} ({result.confidence_score:.2%})")
        print(f"  ✓ Alternatives: {[(aid, f'{score:.2%}') for aid, score in result.alternative_candidates]}")
        test_results.append(("Alternative Candidates", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Alternative Candidates", False, str(e)))
    
    # Test 9: Reasoning generation
    print("\n[TEST 9] Attribution Reasoning Generation")
    try:
        observation = AttackObservation(
            observation_id="TEST-REASONING",
            observed_ttps=["spear_phishing", "credential_stuffing"],
            observed_techniques=["T1566", "T1110"],
            observed_iocs={},
            observed_tools=["CozyDuke"],
            attack_timeline=[datetime.now(timezone.utc)]
        )
        
        result = engine.attribute_attack(observation)
        
        assert len(result.attribution_reasoning) > 0
        print("  ✓ Generated reasoning:")
        for reason in result.attribution_reasoning[:3]:
            print(f"    - {reason}")
        test_results.append(("Reasoning Generation", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Reasoning Generation", False, str(e)))
    
    # Test 10: Empty/edge case handling
    print("\n[TEST 10] Edge Case Handling")
    try:
        # Empty observation
        observation = AttackObservation(
            observation_id="TEST-EMPTY",
            observed_ttps=[],
            observed_techniques=[],
            observed_iocs={},
            observed_tools=[],
            attack_timeline=[]
        )
        
        result = engine.attribute_attack(observation)
        
        # Should not crash, should return some result
        assert result is not None
        print(f"  ✓ Empty observation handled gracefully")
        print(f"  ✓ Result confidence: {result.confidence_score:.2%}")
        test_results.append(("Edge Case Handling", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Edge Case Handling", False, str(e)))
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, success, _ in test_results if success)
    total = len(test_results)
    
    for test_name, success, error in test_results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"  {status} - {test_name}")
        if error:
            print(f"       Error: {error}")
    
    print(f"\n  Total: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    # Save results
    results_data = {
        "test_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_tests": total,
        "passed_tests": passed,
        "pass_rate": passed / total,
        "results": [
            {"test": name, "passed": success, "error": error}
            for name, success, error in test_results
        ]
    }
    
    with open("/home/user/autonomous-developer/NeuralShield-AI/test_results_threat_actor_attribution_engine_ml_enhanced.json", "w") as f:
        json.dump(results_data, f, indent=2)
    
    print(f"\n  Results saved to test_results_threat_actor_attribution_engine_ml_enhanced.json")
    
    return test_results


if __name__ == "__main__":
    results = run_tests()
    passed = sum(1 for _, success, _ in results if success)
    total = len(results)
    sys.exit(0 if passed == total else 1)
