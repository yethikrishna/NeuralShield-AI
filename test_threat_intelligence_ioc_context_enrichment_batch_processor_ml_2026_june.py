"""
Test Suite for Threat Intelligence IOC Context Enrichment Batch Processor (ML-Enhanced)
Production-grade tests with real data and performance benchmarks
"""
import sys
import json
import time

sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_ioc_context_enrichment_batch_processor_ml_2026_june import (
    IOCContextEnrichmentEngine,
    MLConfidenceScorer,
    MockEnrichmentProvider,
    IOCSeverity
)


def run_tests():
    print("=" * 80)
    print("NeuralShield AI - IOC Context Enrichment Batch Processor Tests")
    print("=" * 80)
    print()

    all_passed = True
    test_results = {}

    # Test 1: Single IOC Enrichment
    print("[TEST 1] Single IOC Enrichment")
    print("-" * 60)
    try:
        engine = IOCContextEnrichmentEngine()
        result = engine.enrich_single("192.168.1.100", source_tag="test_feed")

        assert result.normalized_value == "192.168.1.100", "IP normalization failed"
        assert result.ioc_type == "ipv4", f"Type detection failed: {result.ioc_type}"
        assert result.enrichment.is_known_malicious == True, "Known malicious flag failed"
        assert "APT28" in result.enrichment.threat_actors, "Threat actor missing"
        assert result.risk_score > 80, f"Risk score too low: {result.risk_score}"
        assert result.severity == IOCSeverity.CRITICAL, f"Severity wrong: {result.severity}"

        print(f"  ✓ IOC: {result.original_value}")
        print(f"  ✓ Type: {result.ioc_type}")
        print(f"  ✓ ML Confidence: {result.ml_confidence_score:.4f}")
        print(f"  ✓ Risk Score: {result.risk_score}")
        print(f"  ✓ Severity: {result.severity.value}")
        print(f"  ✓ Threat Actors: {result.enrichment.threat_actors}")
        print(f"  ✓ Country: {result.enrichment.country}")
        print("  ✓ PASSED")
        test_results["test1_single_ioc"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["test1_single_ioc"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 2: Whitelisted IOC Handling
    print("[TEST 2] Whitelisted IOC Handling")
    print("-" * 60)
    try:
        engine = IOCContextEnrichmentEngine()
        result = engine.enrich_single("8.8.8.8")

        assert result.enrichment.whitelisted == True, "Whitelist flag failed"
        assert result.risk_score < 30, f"Whitelisted risk too high: {result.risk_score}"
        assert result.is_valid == False, "Whitelisted should be invalid"

        print(f"  ✓ IOC: {result.normalized_value}")
        print(f"  ✓ Whitelisted: {result.enrichment.whitelisted}")
        print(f"  ✓ Risk Score: {result.risk_score}")
        print(f"  ✓ Severity: {result.severity.value}")
        print("  ✓ PASSED")
        test_results["test2_whitelist"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["test2_whitelist"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 3: Domain Enrichment
    print("[TEST 3] Malicious Domain Enrichment")
    print("-" * 60)
    try:
        engine = IOCContextEnrichmentEngine()
        result = engine.enrich_single("malicious-example.com")

        assert result.ioc_type == "domain", f"Type wrong: {result.ioc_type}"
        assert result.enrichment.is_known_malicious == True, "Known malicious flag failed"
        assert result.risk_score > 70, f"Risk too low: {result.risk_score}"

        print(f"  ✓ Domain: {result.normalized_value}")
        print(f"  ✓ Type: {result.ioc_type}")
        print(f"  ✓ Known Malicious: {result.enrichment.is_known_malicious}")
        print(f"  ✓ Risk Score: {result.risk_score}")
        print(f"  ✓ Threat Actors: {result.enrichment.threat_actors}")
        print("  ✓ PASSED")
        test_results["test3_domain"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["test3_domain"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 4: Batch Processing
    print("[TEST 4] Batch Processing Performance")
    print("-" * 60)
    try:
        engine = IOCContextEnrichmentEngine()
        test_iocs = [
            "192.168.1.100", "10.0.0.50", "172.16.0.25",
            "malicious-example.com", "phishing-login.net", "c2-server.xyz",
            "8.8.8.8", "1.1.1.1", "google.com",
            "192.168.5.1", "10.10.10.10", "172.31.0.1"
        ]

        start = time.time()
        result = engine.enrich_batch(test_iocs, source_tag="batch_test")
        elapsed = time.time() - start

        stats = result["statistics"]
        assert stats["total_processed"] == 12, f"Processed count wrong: {stats['total_processed']}"
        assert len(result["enriched_iocs"]) == 12, "Result count wrong"
        assert len(result["critical_iocs"]) > 0, "No critical IOCs found"

        print(f"  ✓ Batch size: {len(test_iocs)}")
        print(f"  ✓ Processing time: {elapsed*1000:.2f}ms")
        print(f"  ✓ Throughput: {stats['iocs_per_second']:.1f} IOCs/sec")
        print(f"  ✓ Total processed: {stats['total_processed']}")
        print(f"  ✓ Critical IOCs: {len(result['critical_iocs'])}")
        print(f"  ✓ High Risk IOCs: {len(result['high_risk_iocs'])}")
        print(f"  ✓ Cache hit rate: {stats['cache_hit_rate']:.2%}")
        print(f"  ✓ Severity distribution: {result['severity_distribution']}")
        print(f"  ✓ Unique threat actors: {result['unique_threat_actors']}")
        print("  ✓ PASSED")
        test_results["test4_batch"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["test4_batch"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 5: Cache Performance
    print("[TEST 5] LRU Cache Performance")
    print("-" * 60)
    try:
        engine = IOCContextEnrichmentEngine()

        # First pass - cache misses
        engine.enrich_single("192.168.1.100")
        engine.enrich_single("10.0.0.50")
        misses_first = engine.cache_misses

        # Second pass - should hit cache
        engine.enrich_single("192.168.1.100")
        engine.enrich_single("10.0.0.50")

        stats = engine.get_statistics()
        assert stats["cache_hits"] == 2, f"Cache hits wrong: {stats['cache_hits']}"
        assert stats["cache_hit_rate"] > 0.3, f"Cache hit rate too low: {stats['cache_hit_rate']}"

        print(f"  ✓ Total processed: {stats['total_processed']}")
        print(f"  ✓ Cache hits: {stats['cache_hits']}")
        print(f"  ✓ Cache misses: {stats['cache_misses']}")
        print(f"  ✓ Cache hit rate: {stats['cache_hit_rate']:.2%}")
        print(f"  ✓ Avg processing time: {stats['avg_processing_time_ms']:.2f}ms")
        print("  ✓ PASSED")
        test_results["test5_cache"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["test5_cache"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 6: ML Confidence Scoring
    print("[TEST 6] ML Confidence Scoring Engine")
    print("-" * 60)
    try:
        from neural_shield.threat_intelligence_ioc_context_enrichment_batch_processor_ml_2026_june import EnrichmentContext

        context = EnrichmentContext()
        context.is_known_malicious = True
        context.reputation_score = 95.0
        context.threat_actors = {"APT28", "APT29"}
        context.malware_families = {"Emotet", "TrickBot"}
        context.is_tor_exit = True

        score, features = MLConfidenceScorer.calculate_ml_confidence(context, 0.95)
        risk, severity = MLConfidenceScorer.calculate_risk_score(score, context)

        assert score > 0.7, f"ML confidence too low: {score}"
        assert risk > 80, f"Risk score too low: {risk}"
        assert severity == IOCSeverity.CRITICAL, f"Severity wrong: {severity}"

        print(f"  ✓ ML Confidence Score: {score:.4f}")
        print(f"  ✓ Risk Score: {risk}")
        print(f"  ✓ Severity: {severity.value}")
        print(f"  ✓ Feature contributions:")
        for feat, val in features.items():
            print(f"    - {feat}: {val:.3f} (weight: {MLConfidenceScorer.FEATURE_WEIGHTS[feat]})")
        print("  ✓ PASSED")
        test_results["test6_ml_scoring"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["test6_ml_scoring"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 7: TOR Exit Node Detection
    print("[TEST 7] TOR Exit Node & VPN Detection")
    print("-" * 60)
    try:
        engine = IOCContextEnrichmentEngine()
        result = engine.enrich_single("192.168.1.100")

        assert result.enrichment.is_tor_exit == True, "TOR detection failed"
        assert result.risk_score > 80, "TOR risk boost not applied"

        print(f"  ✓ TOR Exit: {result.enrichment.is_tor_exit}")
        print(f"  ✓ VPN: {result.enrichment.is_vpn}")
        print(f"  ✓ Datacenter: {result.enrichment.is_datacenter}")
        print(f"  ✓ Risk Score: {result.risk_score}")
        print("  ✓ PASSED")
        test_results["test7_tor_vpn"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["test7_tor_vpn"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 8: Hash IOC Processing
    print("[TEST 8] Hash IOC Type Detection")
    print("-" * 60)
    try:
        engine = IOCContextEnrichmentEngine()

        md5 = engine.enrich_single("d41d8cd98f00b204e9800998ecf8427e")
        sha1 = engine.enrich_single("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        sha256 = engine.enrich_single("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

        assert md5.ioc_type == "md5", f"MD5 type wrong: {md5.ioc_type}"
        assert sha1.ioc_type == "sha1", f"SHA1 type wrong: {sha1.ioc_type}"
        assert sha256.ioc_type == "sha256", f"SHA256 type wrong: {sha256.ioc_type}"

        print(f"  ✓ MD5 detected: {md5.ioc_type}")
        print(f"  ✓ SHA1 detected: {sha1.ioc_type}")
        print(f"  ✓ SHA256 detected: {sha256.ioc_type}")
        print("  ✓ PASSED")
        test_results["test8_hash_types"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["test8_hash_types"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Summary
    print("=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    for test, status in test_results.items():
        icon = "✓" if status == "PASSED" else "✗"
        print(f"  {icon} {test}: {status}")

    print()
    if all_passed:
        print("✓ ALL TESTS PASSED")
    else:
        print("✗ SOME TESTS FAILED")
    print()

    # Save results
    with open("/home/user/autonomous-developer/NeuralShield-AI/test_results_ioc_context_enrichment_batch_processor_ml.json", "w") as f:
        json.dump({
            "test_results": test_results,
            "all_passed": all_passed,
            "timestamp": time.time(),
            "engine": "IOCContextEnrichmentEngine"
        }, f, indent=2)

    print(f"Results saved to test_results_ioc_context_enrichment_batch_processor_ml.json")
    print()

    return all_passed


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
