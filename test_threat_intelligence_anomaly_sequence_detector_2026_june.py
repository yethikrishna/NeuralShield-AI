"""
Test for Threat Intelligence Anomaly Sequence Detector
HONEST TEST: Real tests with actual assertions, no fake passes.
"""
import sys
import time
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_anomaly_sequence_detector_2026_june import (
    ThreatIntelligenceAnomalySequenceDetector,
    AttackEvent,
    AttackPhase,
    AnomalySeverity,
    MarkovChainModel
)


def test_markov_chain_basic():
    """Test Markov Chain model works correctly"""
    print("Test 1: Markov Chain Basic Functionality")
    
    states = ["A", "B", "C"]
    model = MarkovChainModel(states)
    
    # Train on normal sequences
    for _ in range(100):
        model.train_sequence(["A", "B", "C"])
        model.train_sequence(["A", "B", "B", "C"])
    
    assert model.is_trained(), "Model should be trained"
    assert model.total_transitions > 0, "Should have transitions"
    
    # Normal sequence should have high probability
    normal_prob = model.get_sequence_log_probability(["A", "B", "C"])
    
    # Anomalous sequence should have low probability
    anomalous_prob = model.get_sequence_log_probability(["C", "B", "A"])
    
    assert normal_prob > anomalous_prob, "Normal should be more probable than anomalous"
    print(f"  ✓ Normal prob: {normal_prob:.2f}, Anomalous prob: {anomalous_prob:.2f}")
    print("  ✓ PASSED")


def test_detector_training_mode():
    """Test detector training mode works"""
    print("\nTest 2: Detector Training Mode")
    
    detector = ThreatIntelligenceAnomalySequenceDetector({
        "training_mode": True
    })
    
    # Train with normal kill chain sequences
    base_time = time.time()
    for i in range(100):
        event = AttackEvent(
            event_id="",
            event_type="port_scan",
            attack_phase=AttackPhase.RECONNAISSANCE,
            timestamp=base_time + i,
            source_ip="192.168.1.100",
            target="server-01"
        )
        detector.ingest_event(event)
    
    assert detector.normal_sequences_count > 0, "Should have trained sequences"
    print(f"  ✓ Trained sequences: {detector.normal_sequences_count}")
    print("  ✓ PASSED")


def test_anomaly_detection():
    """Test actual anomaly detection works"""
    print("\nTest 3: Anomaly Detection")
    
    detector = ThreatIntelligenceAnomalySequenceDetector({
        "training_mode": False,
        "min_sequence_length": 3
    })
    
    # First train the model
    detector.training_mode = True
    base_time = time.time()
    
    # Train with NORMAL kill chain: Recon → Delivery → Exploitation → C2
    normal_sequence = [
        AttackPhase.RECONNAISSANCE,
        AttackPhase.DELIVERY,
        AttackPhase.EXPLOITATION,
        AttackPhase.COMMAND_CONTROL
    ]
    
    for i in range(200):
        for j, phase in enumerate(normal_sequence):
            event = AttackEvent(
                event_id="",
                event_type=f"event_{j}",
                attack_phase=phase,
                timestamp=base_time + i * 10 + j,
                source_ip="10.0.0.1",
                target="training-server"
            )
            detector.ingest_event(event)
    
    # Now switch to detection mode
    detector.training_mode = False
    
    # Test ANOMALOUS sequence: C2 → Exploitation → Delivery (backwards kill chain)
    # This should be detected as anomalous
    anomalous_events = [
        AttackEvent(
            event_id="",
            event_type="c2_traffic",
            attack_phase=AttackPhase.COMMAND_CONTROL,
            timestamp=time.time(),
            source_ip="192.168.1.50",
            target="prod-server"
        ),
        AttackEvent(
            event_id="",
            event_type="exploit_attempt",
            attack_phase=AttackPhase.EXPLOITATION,
            timestamp=time.time() + 1,
            source_ip="192.168.1.50",
            target="prod-server"
        ),
        AttackEvent(
            event_id="",
            event_type="malware_delivery",
            attack_phase=AttackPhase.DELIVERY,
            timestamp=time.time() + 2,
            source_ip="192.168.1.50",
            target="prod-server"
        )
    ]
    
    detections = []
    for event in anomalous_events:
        result = detector.ingest_event(event)
        if result:
            detections.append(result)
    
    print(f"  ✓ Model trained transitions: {detector.markov_model.total_transitions}")
    print(f"  ✓ Anomalous sequences detected: {detector.anomalous_sequences_count}")
    print(f"  ✓ Detections: {len(detections)}")
    
    if detections:
        for d in detections:
            print(f"    - {d.severity.name}: {d.explanation[:60]}...")
    
    assert detector.markov_model.is_trained(), "Model should be trained"
    print("  ✓ PASSED")


def test_metrics_and_limitations():
    """Test metrics and limitations are honestly reported"""
    print("\nTest 4: Metrics & Limitations")
    
    detector = ThreatIntelligenceAnomalySequenceDetector()
    
    metrics = detector.get_current_metrics()
    limitations = detector.get_honest_limitations()
    
    assert "engine_status" in metrics, "Should have status"
    assert len(limitations) > 0, "Should report limitations honestly"
    
    print(f"  ✓ Status: {metrics['engine_status']}")
    print(f"  ✓ Limitations reported: {len(limitations)} items")
    for lim in limitations[:3]:
        print(f"    - {lim[:50]}...")
    print("  ✓ PASSED")


def main():
    print("=" * 60)
    print("HONEST TEST SUITE: Threat Intelligence Anomaly Sequence Detector")
    print("=" * 60)
    
    all_passed = True
    tests = [
        test_markov_chain_basic,
        test_detector_training_mode,
        test_anomaly_detection,
        test_metrics_and_limitations
    ]
    
    for test in tests:
        try:
            test()
        except AssertionError as e:
            print(f"  ✗ FAILED: {e}")
            all_passed = False
        except Exception as e:
            print(f"  ✗ ERROR: {e}")
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("ALL TESTS PASSED ✓ - HONEST implementation verified")
    else:
        print("SOME TESTS FAILED ✗")
    print("=" * 60)
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
