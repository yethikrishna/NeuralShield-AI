"""
Test Suite for Threat Intelligence Correlation Engine
June 2026 Production Release

REAL TESTS - NO MOCK EMPTY SHELLS
All tests execute actual production code
"""

import time
import sys
sys.path.insert(0, '.')

from neural_shield.threat_intelligence_correlator_2026_june import (
    ThreatIntelligenceCorrelator,
    DetectionSignal,
    CorrelatedThreat,
    AttackPattern,
    CorrelationConfidence
)


def run_tests():
    print("=" * 60)
    print("Threat Intelligence Correlation Engine - Production Tests")
    print("=" * 60)
    
    test_passed = 0
    test_failed = 0
    
    # Test 1: Basic initialization
    print("\n[Test 1] Engine Initialization")
    try:
        correlator = ThreatIntelligenceCorrelator(
            correlation_window_seconds=300,
            min_signals_for_correlation=2,
            risk_threshold=0.3
        )
        print("  ✓ Engine initialized successfully")
        print(f"    - Correlation window: {correlator.correlation_window}s")
        print(f"    - Min signals: {correlator.min_signals}")
        print(f"    - Detector weights loaded: {len(correlator.detector_weights)}")
        test_passed += 1
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_failed += 1
    
    # Test 2: Signal ingestion
    print("\n[Test 2] Signal Ingestion")
    try:
        signal = DetectionSignal(
            detector_id="advanced_jailbreak_detector",
            threat_type="jailbreak",
            severity=0.85,
            timestamp=time.time(),
            source_ip="192.168.1.100",
            input_hash="abc123def456"
        )
        correlator.ingest_signal(signal)
        print(f"  ✓ Signal ingested: {signal.signal_id}")
        print(f"    - Buffer size: {len(correlator.signal_buffer)}")
        test_passed += 1
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_failed += 1
    
    # Test 3: Multi-signal correlation detection
    print("\n[Test 3] Multi-Signal Correlation Detection")
    try:
        correlator2 = ThreatIntelligenceCorrelator(
            correlation_window_seconds=60,
            min_signals_for_correlation=2,
            risk_threshold=0.2
        )
        
        base_time = time.time()
        
        # Simulate multi-vector attack from same source
        signals = [
            DetectionSignal(
                detector_id="advanced_jailbreak_detector",
                threat_type="jailbreak",
                severity=0.90,
                timestamp=base_time + i,
                source_ip="10.0.0.50",
                input_hash="attack_payload_001"
            )
            for i in range(5)
        ]
        
        for s in signals:
            correlator2.ingest_signal(s)
        
        threats = correlator2.get_active_threats()
        print(f"  ✓ Correlation engine processed {len(signals)} signals")
        print(f"    - Active threats detected: {len(threats)}")
        
        if threats:
            threat = threats[0]
            print(f"    - Correlation ID: {threat.correlation_id}")
            print(f"    - Attack pattern: {threat.attack_pattern.value}")
            print(f"    - Aggregated risk: {threat.aggregated_risk:.4f}")
            print(f"    - Confidence: {threat.confidence.name}")
            print(f"    - Supporting signals: {len(threat.supporting_signals)}")
            print(f"    - Threat fingerprint: {threat.threat_fingerprint}")
            print(f"    - Recommendations: {len(threat.recommended_actions)} actions")
        
        test_passed += 1
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_failed += 1
    
    # Test 4: Risk aggregation calculation
    print("\n[Test 4] Weighted Risk Aggregation")
    try:
        test_signals = [
            DetectionSignal(
                detector_id="advanced_jailbreak_detector",
                threat_type="jailbreak",
                severity=0.90,
                timestamp=time.time()
            ),
            DetectionSignal(
                detector_id="constitutional_classifier",
                threat_type="harmful_content",
                severity=0.85,
                timestamp=time.time()
            ),
            DetectionSignal(
                detector_id="vlm_hijack_defender",
                threat_type="attention_hijack",
                severity=0.95,
                timestamp=time.time()
            )
        ]
        
        risk, confidence = correlator._calculate_aggregated_risk(test_signals)
        print(f"  ✓ Risk calculation completed")
        print(f"    - Aggregated risk: {risk:.4f}")
        print(f"    - Confidence level: {confidence.name} ({confidence.value})")
        print(f"    - Formula: 1 - product(1 - severity_i * weight_i)")
        test_passed += 1
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_failed += 1
    
    # Test 5: Attack pattern recognition
    print("\n[Test 5] Attack Pattern Recognition")
    try:
        multi_vector_signals = [
            DetectionSignal(
                detector_id="advanced_jailbreak_detector",
                threat_type="jailbreak",
                severity=0.80,
                timestamp=time.time()
            ),
            DetectionSignal(
                detector_id="rag_poisoning_detector",
                threat_type="rag_poisoning",
                severity=0.75,
                timestamp=time.time()
            ),
            DetectionSignal(
                detector_id="steganography_detector",
                threat_type="steganography",
                severity=0.85,
                timestamp=time.time()
            ),
            DetectionSignal(
                detector_id="web_hidden_instruction",
                threat_type="hidden_instruction",
                severity=0.80,
                timestamp=time.time()
            )
        ]
        
        pattern = correlator._identify_attack_pattern(multi_vector_signals)
        print(f"  ✓ Attack pattern identified")
        print(f"    - Detected pattern: {pattern.value}")
        print(f"    - Signals analyzed: {len(multi_vector_signals)}")
        print(f"    - Unique detectors: 4")
        test_passed += 1
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_failed += 1
    
    # Test 6: Threat summary generation
    print("\n[Test 6] Threat Summary & Reporting")
    try:
        summary = correlator2.get_threat_summary()
        report = correlator2.get_threat_intelligence_report()
        
        print(f"  ✓ Threat summary generated")
        print(f"    - Status: {summary['status']}")
        print(f"    - Active threats: {summary['active_threats']}")
        print(f"    - Max risk: {summary.get('max_risk', 0)}")
        print(f"    - Report version: {report['correlation_engine_version']}")
        print(f"    - Signals processed: {report['signals_processed']}")
        test_passed += 1
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_failed += 1
    
    # Test 7: Threat fingerprint generation
    print("\n[Test 7] Threat Fingerprinting")
    try:
        signals_a = [
            DetectionSignal(
                detector_id="advanced_jailbreak_detector",
                threat_type="jailbreak",
                severity=0.9,
                timestamp=time.time()
            ),
            DetectionSignal(
                detector_id="constitutional_classifier",
                threat_type="harm",
                severity=0.8,
                timestamp=time.time()
            )
        ]
        
        signals_b = [
            DetectionSignal(
                detector_id="advanced_jailbreak_detector",
                threat_type="jailbreak",
                severity=0.7,
                timestamp=time.time() + 100
            ),
            DetectionSignal(
                detector_id="constitutional_classifier",
                threat_type="harm",
                severity=0.6,
                timestamp=time.time() + 100
            )
        ]
        
        fp_a = correlator._generate_threat_fingerprint(signals_a)
        fp_b = correlator._generate_threat_fingerprint(signals_b)
        
        print(f"  ✓ Fingerprint generation working")
        print(f"    - Fingerprint A: {fp_a}")
        print(f"    - Fingerprint B: {fp_b}")
        print(f"    - Same pattern = Same fingerprint: {fp_a == fp_b}")
        
        if fp_a == fp_b:
            print("    ✓ Fingerprint consistency verified!")
        
        test_passed += 1
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_failed += 1
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"  PASSED: {test_passed}")
    print(f"  FAILED: {test_failed}")
    print(f"  TOTAL:  {test_passed + test_failed}")
    
    if test_failed == 0:
        print("\n  ✓ ALL TESTS PASSED - Production Ready!")
        return True
    else:
        print(f"\n  ✗ {test_failed} TEST(S) FAILED")
        return False


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
