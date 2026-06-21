#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Alert Correlation & Context Enrichment Engine v65
Production-grade testing for NeuralShield-AI
"""
import json
import time
import sys

sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_alert_correlation_context_enricher_v65_2026_june import (
    AlertCorrelationContextEnricherV65,
    Alert,
    AlertSeverity,
    KillChainPhase
)


def run_tests():
    """Run all tests for v65 engine"""
    print("=" * 70)
    print("NeuralShield-AI: Alert Correlation v65 - Production Test Suite")
    print("=" * 70)
    
    # Initialize engine
    engine = AlertCorrelationContextEnricherV65(
        correlation_window_seconds=7200,
        min_correlation_score=0.35,
        enable_bloom_filter=True,
        enable_geolocation=True,
        enable_asset_context=True,
        enable_anomaly_detection=True,
        batch_size=50
    )
    
    results = {
        "tests_passed": 0,
        "tests_failed": 0,
        "test_details": []
    }
    
    # Test 1: Basic alert processing
    print("\n[Test 1] Basic alert processing and enrichment")
    try:
        alert1 = Alert(
            alert_id="alert-001",
            timestamp=time.time(),
            source="firewall",
            title="Suspicious Network Connection",
            description="Outbound connection to known malicious IP",
            severity=AlertSeverity.HIGH,
            iocs=["45.33.32.156", "malware.exe"],
            mitre_techniques=["T1071", "T1046"],
            source_ip="45.33.32.156",
            destination_ip="192.168.1.1",
            asset_id="asset-001"
        )
        
        result = engine.process_alert(alert1)
        
        assert result["enriched"] == True, "Alert should be enriched"
        assert result["confidence_score"] > 0, "Confidence score should be > 0"
        assert "geolocation" in result["enrichment_data"], "Should have geolocation data"
        assert result["processing_time_ms"] > 0, "Should have processing time"
        
        print(f"  ✓ Alert processed successfully")
        print(f"  ✓ Confidence score: {result['confidence_score']}")
        print(f"  ✓ Kill chain phase: {result['kill_chain_phase']}")
        print(f"  ✓ Processing time: {result['processing_time_ms']}ms")
        results["tests_passed"] += 1
        results["test_details"].append({"test": "basic_processing", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "basic_processing", "status": "failed", "error": str(e)})
    
    # Test 2: Kill chain phase classification
    print("\n[Test 2] Kill chain phase classification")
    try:
        # Initial Access phase
        alert_phish = Alert(
            alert_id="alert-phish",
            timestamp=time.time(),
            source="email",
            title="Phishing Email Detected",
            description="Malicious attachment detected",
            severity=AlertSeverity.CRITICAL,
            iocs=["phish.docm"],
            mitre_techniques=["T1566"]
        )
        result_phish = engine.process_alert(alert_phish)
        assert result_phish["kill_chain_phase"] == KillChainPhase.DELIVERY.value, "Phishing should map to DELIVERY phase"
        
        # Execution phase
        alert_exec = Alert(
            alert_id="alert-exec",
            timestamp=time.time(),
            source="edr",
            title="Malicious Command Execution",
            description="Suspicious powershell command",
            severity=AlertSeverity.HIGH,
            iocs=["powershell.exe"],
            mitre_techniques=["T1059"]
        )
        result_exec = engine.process_alert(alert_exec)
        assert result_exec["kill_chain_phase"] == KillChainPhase.EXPLOITATION.value, "Execution should map to EXPLOITATION phase"
        
        print(f"  ✓ Phishing mapped to: {result_phish['kill_chain_phase']}")
        print(f"  ✓ Execution mapped to: {result_exec['kill_chain_phase']}")
        results["tests_passed"] += 1
        results["test_details"].append({"test": "kill_chain_classification", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "kill_chain_classification", "status": "failed", "error": str(e)})
    
    # Test 3: Alert correlation and grouping
    print("\n[Test 3] Alert correlation and grouping")
    try:
        base_time = time.time()
        
        # Create related alerts with same IOCs
        alert_a = Alert(
            alert_id="alert-cor-a",
            timestamp=base_time,
            source="ids",
            title="Suspicious Activity A",
            description="IDS alert for suspicious traffic",
            severity=AlertSeverity.HIGH,
            iocs=["shared-ioc-123", "unique-a"],
            mitre_techniques=["T1071"],
            source_ip="45.33.32.156"
        )
        result_a = engine.process_alert(alert_a)
        group_id = result_a["correlation"]["group_id"]
        
        alert_b = Alert(
            alert_id="alert-cor-b",
            timestamp=base_time + 60,
            source="firewall",
            title="Suspicious Activity B",
            description="Firewall alert for same traffic",
            severity=AlertSeverity.MEDIUM,
            iocs=["shared-ioc-123", "unique-b"],
            mitre_techniques=["T1071"],
            source_ip="45.33.32.156"
        )
        result_b = engine.process_alert(alert_b)
        
        # Should be in same group
        assert result_b["correlation"]["group_id"] == group_id, "Related alerts should be in same group"
        assert result_b["correlation"]["matched_alerts"] >= 2, "Group should have multiple alerts"
        
        print(f"  ✓ Alerts correlated into same group")
        print(f"  ✓ Group ID: {group_id}")
        print(f"  ✓ Alerts in group: {result_b['correlation']['matched_alerts']}")
        print(f"  ✓ Correlation score: {result_b['correlation']['correlation_score']}")
        results["tests_passed"] += 1
        results["test_details"].append({"test": "alert_correlation", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "alert_correlation", "status": "failed", "error": str(e)})
    
    # Test 4: Attack hypothesis generation
    print("\n[Test 4] Attack chain hypothesis generation")
    try:
        base_time = time.time()
        
        # Create multi-phase attack scenario
        for i, (tech, phase_name) in enumerate([
            ("T1566", "delivery"),
            ("T1059", "exploitation"), 
            ("T1003", "credential_access"),
            ("T1071", "c2")
        ]):
            alert = Alert(
                alert_id=f"attack-chain-{i}",
                timestamp=base_time + (i * 300),
                source="sensor",
                title=f"Attack Stage {i}",
                description=f"Attack activity detected at stage {i}",
                severity=AlertSeverity.HIGH,
                iocs=["attack-common-ioc"],
                mitre_techniques=[tech],
                source_ip="45.33.32.156"
            )
            result = engine.process_alert(alert)
        
        # Check hypothesis exists
        metrics = engine.get_metrics()
        assert metrics["correlation_groups"] > 0, "Should have correlation groups"
        assert "attack_hypothesis" in result["correlation"], "Should have attack hypothesis"
        
        print(f"  ✓ Attack hypothesis generated")
        print(f"  ✓ Hypothesis: {result['correlation']['attack_hypothesis'][:80]}...")
        print(f"  ✓ Kill chain progression: {result['correlation'].get('kill_chain_progression', [])}")
        results["tests_passed"] += 1
        results["test_details"].append({"test": "attack_hypothesis", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "attack_hypothesis", "status": "failed", "error": str(e)})
    
    # Test 5: IOC deduplication with bloom filter
    print("\n[Test 5] IOC deduplication with bloom filter")
    try:
        # Reset bloom filter
        engine.ioc_bloom_filter = engine.ioc_bloom_filter.__class__()
        
        # Same IOC multiple times
        for i in range(5):
            alert = Alert(
                alert_id=f"dedup-test-{i}",
                timestamp=time.time(),
                source="test",
                title="Deduplication Test",
                description="Testing IOC deduplication",
                severity=AlertSeverity.LOW,
                iocs=["duplicate-ioc-test"]
            )
            engine.process_alert(alert)
        
        metrics = engine.get_metrics()
        assert metrics["metrics"]["iocs_deduplicated"] > 0, "Should have deduplicated IOCs"
        
        print(f"  ✓ IOC deduplication working")
        print(f"  ✓ IOCs deduplicated: {metrics['metrics']['iocs_deduplicated']}")
        print(f"  ✓ Bloom filter FP rate: {metrics['bloom_filter_fp_rate']}%")
        results["tests_passed"] += 1
        results["test_details"].append({"test": "ioc_deduplication", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "ioc_deduplication", "status": "failed", "error": str(e)})
    
    # Test 6: Asset context enrichment
    print("\n[Test 6] Asset context enrichment")
    try:
        alert = Alert(
            alert_id="asset-test",
            timestamp=time.time(),
            source="test",
            title="Asset Context Test",
            description="Testing asset enrichment",
            severity=AlertSeverity.HIGH,
            iocs=["test-ioc"],
            asset_id="asset-001"
        )
        result = engine.process_alert(alert)
        
        assert "asset_context" in result["enrichment_data"], "Should have asset context"
        assert result["enrichment_data"]["asset_context"]["name"] == "Primary Database", "Should get correct asset name"
        assert result["enrichment_data"]["asset_context"]["criticality"] == "critical", "Should have correct criticality"
        
        print(f"  ✓ Asset context retrieved")
        print(f"  ✓ Asset name: {result['enrichment_data']['asset_context']['name']}")
        print(f"  ✓ Asset criticality: {result['enrichment_data']['asset_context']['criticality']}")
        results["tests_passed"] += 1
        results["test_details"].append({"test": "asset_enrichment", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "asset_enrichment", "status": "failed", "error": str(e)})
    
    # Test 7: Performance metrics
    print("\n[Test 7] Performance metrics tracking")
    try:
        metrics = engine.get_metrics()
        
        assert metrics["version"] == "v65", "Should be v65"
        assert metrics["metrics"]["total_alerts_processed"] > 0, "Should have processed alerts"
        assert metrics["metrics"]["alerts_enriched"] > 0, "Should have enriched alerts"
        assert metrics["metrics"]["avg_processing_time_ms"] > 0, "Should have avg processing time"
        assert "enhancements" in metrics, "Should list v65 enhancements"
        
        print(f"  ✓ Version: {metrics['version']}")
        print(f"  ✓ Alerts processed: {metrics['metrics']['total_alerts_processed']}")
        print(f"  ✓ Alerts enriched: {metrics['metrics']['alerts_enriched']}")
        print(f"  ✓ Avg processing time: {metrics['metrics']['avg_processing_time_ms']:.2f}ms")
        print(f"  ✓ Enhancements: {len(metrics['enhancements'])} features")
        results["tests_passed"] += 1
        results["test_details"].append({"test": "performance_metrics", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "performance_metrics", "status": "failed", "error": str(e)})
    
    # Test 8: Geolocation enrichment
    print("\n[Test 8] IP geolocation enrichment")
    try:
        alert = Alert(
            alert_id="geo-test",
            timestamp=time.time(),
            source="firewall",
            title="Geolocation Test",
            description="Testing IP geolocation enrichment",
            severity=AlertSeverity.MEDIUM,
            iocs=["test"],
            source_ip="45.33.32.156",
            destination_ip="8.8.8.8"
        )
        result = engine.process_alert(alert)
        
        geo = result["enrichment_data"]["geolocation"]
        assert "source_ip" in geo, "Should have source IP geolocation"
        assert geo["source_ip"]["country"] == "NL", "Should map to correct country"
        assert geo["source_ip"]["threat_score"] > 0, "Should have threat score"
        
        print(f"  ✓ Source IP country: {geo['source_ip']['country']}")
        print(f"  ✓ Source IP threat score: {geo['source_ip']['threat_score']}")
        print(f"  ✓ Destination IP country: {geo['destination_ip']['country']}")
        results["tests_passed"] += 1
        results["test_details"].append({"test": "geolocation", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "geolocation", "status": "failed", "error": str(e)})
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Tests Passed: {results['tests_passed']}")
    print(f"Tests Failed: {results['tests_failed']}")
    print(f"Success Rate: {(results['tests_passed'] / (results['tests_passed'] + results['tests_failed']) * 100):.1f}%")
    print("=" * 70)
    
    # Save results
    output = {
        "engine_version": "v65",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "results": results,
        "final_metrics": engine.get_metrics(),
        "status": "success" if results["tests_failed"] == 0 else "partial_success"
    }
    
    with open("/home/user/autonomous-developer/NeuralShield-AI/test_results_alert_correlation_context_enricher_v65_2026_june.json", "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"\nTest results saved to test_results_alert_correlation_context_enricher_v65_2026_june.json")
    
    return output


if __name__ == "__main__":
    run_tests()
