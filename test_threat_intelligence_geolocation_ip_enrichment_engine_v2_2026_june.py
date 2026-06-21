#!/usr/bin/env python3
"""
Test for NeuralShield-AI: Threat Intelligence Geolocation IP Enrichment Engine v2
June 21, 2026 - Production Grade Tests

REAL TESTS - actually runs and verifies functionality
"""

import sys
import os
import json
import time

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from neural_shield.threat_intelligence_geolocation_ip_enrichment_engine_v2_2026_june import (
    GeolocationIPEnrichmentEngine,
    create_geolocation_enrichment_engine,
    verify_geolocation_enrichment_engine,
    IPType,
    IPReputation,
    ThreatLevel
)


def run_comprehensive_tests():
    """Run comprehensive real tests"""
    print("=" * 70)
    print("NeuralShield-AI: Geolocation IP Enrichment Engine v2 - TEST SUITE")
    print("June 21, 2026 - Production Grade")
    print("=" * 70)
    
    engine = create_geolocation_enrichment_engine(cache_capacity=1000)
    
    test_results = {
        "test_suite": "Geolocation IP Enrichment Engine v2",
        "date": "2026-06-21",
        "tests_passed": 0,
        "tests_failed": 0,
        "test_cases": [],
        "final_verification": None
    }
    
    # Test 1: IP Validation
    print("\n[TEST 1] IP Validation")
    test_ips = [
        ("8.8.8.8", True, IPType.IPV4),
        ("2001:4860:4860::8888", True, IPType.IPV6),
        ("192.168.1.1", True, IPType.IPV4),
        ("invalid", False, IPType.INVALID),
        ("256.256.256.256", False, IPType.INVALID),
        ("", False, IPType.INVALID),
    ]
    
    for ip, expected_valid, expected_type in test_ips:
        is_valid, ip_type, _ = engine.validate_ip(ip)
        passed = is_valid == expected_valid and ip_type == expected_type
        status = "PASS" if passed else "FAIL"
        print(f"  {ip}: {status} (valid={is_valid}, type={ip_type.value})")
        
        if passed:
            test_results["tests_passed"] += 1
        else:
            test_results["tests_failed"] += 1
        
        test_results["test_cases"].append({
            "test": f"validation_{ip}",
            "passed": passed,
            "expected": {"valid": expected_valid, "type": expected_type.value},
            "actual": {"valid": is_valid, "type": ip_type.value}
        })
    
    # Test 2: Private IP Detection
    print("\n[TEST 2] Private IP Detection")
    private_ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1"]
    public_ips = ["8.8.8.8", "1.1.1.1"]
    
    for ip in private_ips:
        result = engine.enrich_ip(ip)
        passed = result.is_private == True
        status = "PASS" if passed else "FAIL"
        print(f"  {ip}: {status} (private={result.is_private})")
        
        if passed:
            test_results["tests_passed"] += 1
        else:
            test_results["tests_failed"] += 1
        
        test_results["test_cases"].append({
            "test": f"private_{ip}",
            "passed": passed,
            "expected": True,
            "actual": result.is_private
        })
    
    for ip in public_ips:
        result = engine.enrich_ip(ip)
        passed = result.is_private == False
        status = "PASS" if passed else "FAIL"
        print(f"  {ip}: {status} (private={result.is_private})")
        
        if passed:
            test_results["tests_passed"] += 1
        else:
            test_results["tests_failed"] += 1
    
    # Test 3: Threat Scoring
    print("\n[TEST 3] Threat Scoring")
    score_ips = ["8.8.8.8", "192.168.1.1", "109.70.100.10"]
    
    for ip in score_ips:
        result = engine.enrich_ip(ip)
        passed = 0 <= result.threat_score <= 100
        status = "PASS" if passed else "FAIL"
        print(f"  {ip}: {status} (score={result.threat_score:.1f}, level={result.threat_level.value})")
        
        if passed:
            test_results["tests_passed"] += 1
        else:
            test_results["tests_failed"] += 1
        
        test_results["test_cases"].append({
            "test": f"threat_score_{ip}",
            "passed": passed,
            "expected": "0-100",
            "actual": result.threat_score
        })
    
    # Test 4: CIDR Matching
    print("\n[TEST 4] CIDR Matching")
    cidr_tests = [
        ("192.168.1.100", "192.168.1.0/24", True),
        ("192.168.2.100", "192.168.1.0/24", False),
        ("10.0.0.5", "10.0.0.0/8", True),
        ("8.8.8.8", "0.0.0.0/0", True),
    ]
    
    for ip, cidr, expected in cidr_tests:
        result = engine.match_cidr(ip, cidr)
        passed = result == expected
        status = "PASS" if passed else "FAIL"
        print(f"  {ip} in {cidr}: {status} (result={result})")
        
        if passed:
            test_results["tests_passed"] += 1
        else:
            test_results["tests_failed"] += 1
        
        test_results["test_cases"].append({
            "test": f"cidr_{ip}_{cidr}",
            "passed": passed,
            "expected": expected,
            "actual": result
        })
    
    # Test 5: Bulk Enrichment
    print("\n[TEST 5] Bulk Enrichment")
    bulk_ips = ["8.8.8.8", "1.1.1.1", "192.168.1.1", "10.0.0.1"]
    results = engine.bulk_enrich(bulk_ips)
    passed = len(results) == len(bulk_ips)
    status = "PASS" if passed else "FAIL"
    print(f"  Bulk enrich {len(bulk_ips)} IPs: {status} (count={len(results)})")
    
    if passed:
        test_results["tests_passed"] += 1
    else:
        test_results["tests_failed"] += 1
    
    # Test 6: Caching
    print("\n[TEST 6] Caching")
    initial_hits = engine.cache_hits
    # Enrich same IP twice
    _ = engine.enrich_ip("8.8.8.8", use_cache=True)
    _ = engine.enrich_ip("8.8.8.8", use_cache=True)
    final_hits = engine.cache_hits
    passed = final_hits > initial_hits
    status = "PASS" if passed else "FAIL"
    print(f"  Cache hit detection: {status} (hits={final_hits - initial_hits})")
    
    if passed:
        test_results["tests_passed"] += 1
    else:
        test_results["tests_failed"] += 1
    
    # Test 7: Geolocation Data
    print("\n[TEST 7] Geolocation Data")
    result = engine.enrich_ip("8.8.8.8")
    geo = result.geolocation
    passed = geo.country_code != "ZZ" and geo.asn > 0
    status = "PASS" if passed else "FAIL"
    print(f"  Geolocation data present: {status}")
    print(f"    Country: {geo.country_name} ({geo.country_code})")
    print(f"    ASN: {geo.asn} - {geo.asn_org}")
    print(f"    ISP: {geo.isp}")
    
    if passed:
        test_results["tests_passed"] += 1
    else:
        test_results["tests_failed"] += 1
    
    # Final verification
    print("\n" + "=" * 70)
    print("FINAL VERIFICATION")
    print("=" * 70)
    verification = verify_geolocation_enrichment_engine()
    test_results["final_verification"] = verification
    
    print(f"Verification: {'PASSED' if verification['verified'] else 'FAILED'}")
    print(f"Message: {verification['message']}")
    print(f"Stats: {json.dumps(verification['stats'], indent=2)}")
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    total = test_results["tests_passed"] + test_results["tests_failed"]
    print(f"Total Tests: {total}")
    print(f"Passed: {test_results['tests_passed']}")
    print(f"Failed: {test_results['tests_failed']}")
    print(f"Success Rate: {(test_results['tests_passed']/total*100):.1f}%")
    
    # Save results
    output_file = "test_results_geolocation_ip_enrichment_v2_2026_june.json"
    with open(output_file, 'w') as f:
        json.dump(test_results, f, indent=2)
    print(f"\nResults saved to: {output_file}")
    
    return test_results


if __name__ == "__main__":
    results = run_comprehensive_tests()
    sys.exit(0 if results["tests_failed"] == 0 else 1)
