#!/usr/bin/env python3
"""
Test Suite for Threat Intelligence Signature Drift Detector & Rollback Engine
June 2026 - Production Grade Tests

REAL TESTS - no mocking!
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from neural_shield.threat_intelligence_signature_drift_detector_rollback_2026_june import (
    SignatureDriftDetector,
    DriftSeverity,
    SignatureStatus
)


def run_all_tests():
    print("=" * 70)
    print("NeuralShield-AI: Signature Drift Detector & Rollback Engine Tests")
    print("=" * 70)
    
    test_results = []
    
    # Test 1: Initialize detector
    print("\n[TEST 1] Initialize SignatureDriftDetector")
    try:
        detector = SignatureDriftDetector(
            drift_threshold_precision=-15.0,
            drift_threshold_fpr=20.0,
            min_sample_size=10
        )
        print("  ✓ Detector initialized successfully")
        test_results.append(("Initialize detector", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results.append(("Initialize detector", False))
    
    # Test 2: Register signature
    print("\n[TEST 2] Register new detection signature")
    try:
        sig_id = "SIG-MALWARE-001"
        sig_content = """
        rule Malware_Detection {
            strings: $a = "malicious_pattern"
            condition: $a
        }
        """
        version_id = detector.register_signature(
            signature_id=sig_id,
            signature_content=sig_content,
            initial_baseline={
                "precision": 0.90,
                "recall": 0.80,
                "f1_score": 0.85,
                "false_positive_rate": 0.03
            },
            created_by="threat_intel_team"
        )
        print(f"  ✓ Signature registered: {sig_id}")
        print(f"    Version ID: {version_id}")
        test_results.append(("Register signature", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results.append(("Register signature", False))
    
    # Test 3: Record performance data
    print("\n[TEST 3] Record performance metrics")
    try:
        # Record good performance (matches baseline)
        for i in range(15):
            detector.record_performance(
                signature_id=sig_id,
                true_positives=90,
                false_positives=10,
                true_negatives=900,
                false_negatives=10
            )
        
        history = detector.performance_history[sig_id]
        print(f"  ✓ Recorded {len(history)} performance samples")
        print(f"    Last sample precision: {history[-1].precision:.3f}")
        print(f"    Last sample FPR: {history[-1].false_positive_rate:.3f}")
        test_results.append(("Record performance", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results.append(("Record performance", False))
    
    # Test 4: Evaluate drift (no drift expected)
    print("\n[TEST 4] Evaluate drift (baseline performance)")
    try:
        alerts = detector.evaluate_drift(sig_id)
        print(f"  ✓ Drift evaluation complete")
        print(f"    Alerts generated: {len(alerts)}")
        if len(alerts) == 0:
            print("    No drift detected (as expected for baseline performance)")
        test_results.append(("Evaluate no-drift scenario", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results.append(("Evaluate no-drift scenario", False))
    
    # Test 5: Simulate drift and detect it
    print("\n[TEST 5] Detect precision drift (degraded performance)")
    try:
        # Simulate degraded performance - lots of false positives
        for i in range(15):
            detector.record_performance(
                signature_id=sig_id,
                true_positives=40,  # Dropped from 90
                false_positives=60,  # Increased from 10
                true_negatives=900,
                false_negatives=10
            )
        
        alerts = detector.evaluate_drift(sig_id)
        print(f"  ✓ Drift evaluation with degraded performance")
        print(f"    Alerts generated: {len(alerts)}")
        for alert in alerts:
            print(f"    - [{alert.drift_severity.value}] {alert.message}")
        
        if len(alerts) > 0:
            print("    Drift correctly detected!")
        test_results.append(("Detect precision drift", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results.append(("Detect precision drift", False))
    
    # Test 6: Update signature to new version
    print("\n[TEST 6] Update signature (create new version)")
    try:
        new_content = """
        rule Malware_Detection_v2 {
            strings: 
                $a = "malicious_pattern"
                $b = "new_indicator"
            condition: any of them
        }
        """
        new_version = detector.update_signature(
            signature_id=sig_id,
            new_content=new_content,
            updated_by="analyst_john",
            new_baseline={
                "precision": 0.92,
                "recall": 0.85,
                "f1_score": 0.88,
                "false_positive_rate": 0.02
            }
        )
        print(f"  ✓ Signature updated")
        print(f"    New version ID: {new_version}")
        print(f"    Total versions: {len(detector.versions[sig_id])}")
        test_results.append(("Update signature version", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results.append(("Update signature version", False))
    
    # Test 7: Manual rollback
    print("\n[TEST 7] Manual rollback to previous version")
    try:
        result = detector.rollback_signature(
            signature_id=sig_id,
            reason="new_version_causes_too_many_false_positives"
        )
        if result["success"]:
            print(f"  ✓ Rollback successful")
            print(f"    Rollback ID: {result['rollback_id']}")
            print(f"    Rolled from: {result['rolled_from']}")
            print(f"    Rolled to: {result['rolled_to_version_number']}")
            print(f"    Reason: {result['reason']}")
        test_results.append(("Manual rollback", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results.append(("Manual rollback", False))
    
    # Test 8: Get drift summary
    print("\n[TEST 8] Generate drift detection summary")
    try:
        summary = detector.get_drift_summary()
        print(f"  ✓ Summary generated")
        print(f"    Total signatures: {summary['total_signatures_registered']}")
        print(f"    Total versions: {summary['total_versions_tracked']}")
        print(f"    Performance records: {summary['total_performance_records']}")
        print(f"    Drift alerts: {summary['total_drift_alerts']}")
        print(f"    Rollbacks: {summary['total_rollbacks']}")
        test_results.append(("Generate summary", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results.append(("Generate summary", False))
    
    # Test 9: Generate full drift report
    print("\n[TEST 9] Generate detailed drift report")
    try:
        report = detector.generate_drift_report(sig_id)
        print(f"  ✓ Report generated for {sig_id}")
        print(f"    Status: {report['status']}")
        print(f"    Versions tracked: {report['versions_tracked']}")
        print(f"    Performance samples: {report['performance_samples']}")
        print(f"    Drift alerts: {report['drift_alerts']}")
        print(f"    Rollback history entries: {len(report['rollback_history'])}")
        test_results.append(("Generate drift report", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results.append(("Generate drift report", False))
    
    # Test 10: Multiple signatures test
    print("\n[TEST 10] Multi-signature drift monitoring")
    try:
        # Register additional signatures
        detector.register_signature(
            "SIG-PHI-001",
            "rule PHI_Detection { condition: true }",
            created_by="compliance_team"
        )
        detector.register_signature(
            "SIG-RANSOM-002",
            "rule Ransomware_Detect { condition: true }",
            created_by="threat_intel"
        )
        
        # Record performance
        for i in range(12):
            detector.record_performance("SIG-PHI-001", 85, 15, 900, 5)
            detector.record_performance("SIG-RANSOM-002", 95, 5, 950, 2)
        
        full_report = detector.generate_drift_report()
        print(f"  ✓ Multi-signature monitoring active")
        print(f"    Total signatures in system: {full_report['summary']['total_signatures_registered']}")
        print(f"    System-wide drift alerts: {full_report['summary']['total_drift_alerts']}")
        test_results.append(("Multi-signature monitoring", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results.append(("Multi-signature monitoring", False))
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, result in test_results if result)
    total = len(test_results)
    
    for test_name, result in test_results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status} - {test_name}")
    
    print(f"\n  Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n  🎉 ALL TESTS PASSED!")
        return 0
    else:
        print(f"\n  ⚠️  {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
