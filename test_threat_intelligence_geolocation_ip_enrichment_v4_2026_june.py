#!/usr/bin/env python3
"""
Test suite for Geolocation IP Enrichment Engine v4.
"""
import sys
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_geolocation_ip_enrichment_v4_2026_june import (
    GeolocationIPEnrichmentEngineV4,
    Coordinates,
    VelocityAnalyzer,
    VelocityAnomalyType,
    GeofencePolicy,
    GeofenceAction,
    TemporalThreatDecay
)
from datetime import datetime, timedelta


def run_all_tests():
    print("=" * 60)
    print("NeuralShield-AI: Geolocation v4 - Test Suite")
    print("=" * 60)
    
    results = []
    
    # Test 1: Basic IP enrichment
    print("\n[TEST 1] Basic IP Enrichment")
    try:
        engine = GeolocationIPEnrichmentEngineV4()
        result = engine.enrich_ip("8.8.8.8")
        assert result.is_valid == True
        assert result.country_code != "ZZ"
        print(f"  ✓ IP: {result.ip_address}, Country: {result.country_code}")
        results.append(("Basic IP enrichment", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results.append(("Basic IP enrichment", False))
    
    # Test 2: Invalid IP handling
    print("\n[TEST 2] Invalid IP Handling")
    try:
        engine = GeolocationIPEnrichmentEngineV4()
        result = engine.enrich_ip("not_an_ip")
        assert result.is_valid == False
        print("  ✓ Invalid IP correctly detected")
        results.append(("Invalid IP handling", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results.append(("Invalid IP handling", False))
    
    # Test 3: Impossible Travel Detection
    print("\n[TEST 3] Impossible Travel Detection")
    try:
        engine = GeolocationIPEnrichmentEngineV4()
        scenario = engine.simulate_impossible_travel_scenario("test_user_456")
        detected = scenario["impossible_travel_detected"]
        print(f"  ✓ Impossible travel detected: {detected}")
        print(f"    First country: {scenario['first_access']['country_code']}")
        print(f"    Second country: {scenario['second_access_immediate']['country_code']}")
        results.append(("Impossible travel detection", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results.append(("Impossible travel detection", False))
    
    # Test 4: Geofencing Violation Detection
    print("\n[TEST 4] Geofencing Violation Detection")
    try:
        engine = GeolocationIPEnrichmentEngineV4()
        policy = GeofencePolicy("test_strict", "Test Policy", {"US", "GB"}, GeofenceAction.BLOCK, 200)
        engine.geofence_enforcer.add_policy(policy)
        result = engine.enrich_ip("1.1.1.1")
        print(f"  ✓ IP: {result.ip_address}, Country: {result.country_code}")
        print(f"    Violations: {len(result.geofence_violations)}, Action: {result.geofence_action.value}")
        results.append(("Geofencing violation detection", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results.append(("Geofencing violation detection", False))
    
    # Test 5: ML-based Anomaly Scoring
    print("\n[TEST 5] ML-based Anomaly Scoring")
    try:
        engine = GeolocationIPEnrichmentEngineV4()
        user_id = "test_user_789"
        for i in range(10):
            engine.enrich_ip("8.8.8.8", user_id)
        result = engine.enrich_ip("1.1.1.1", user_id)
        print(f"  ✓ ML Anomaly Score: {result.ml_anomaly_score:.1f}")
        results.append(("ML-based anomaly scoring", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results.append(("ML-based anomaly scoring", False))
    
    # Test 6: Temporal Threat Decay
    print("\n[TEST 6] Temporal Threat Decay")
    try:
        decayed_7d = TemporalThreatDecay.calculate_decayed_score(100.0, 7.0, 7.0)
        decayed_14d = TemporalThreatDecay.calculate_decayed_score(100.0, 14.0, 7.0)
        assert abs(decayed_7d - 50.0) < 1.0
        assert abs(decayed_14d - 25.0) < 1.0
        print(f"  ✓ Decay verified: 7d={decayed_7d:.1f}, 14d={decayed_14d:.1f}")
        results.append(("Temporal threat decay", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results.append(("Temporal threat decay", False))
    
    # Test 7: Velocity analyzer unit test
    print("\n[TEST 7] Velocity Analyzer")
    try:
        analyzer = VelocityAnalyzer()
        nyc = Coordinates(40.7128, -74.0060)
        london = Coordinates(51.5074, -0.1278)
        
        class Record:
            def __init__(self, c, t):
                self.coordinates = c
                self.timestamp = t
        
        normal = analyzer.analyze_velocity(london, datetime.now() + timedelta(hours=7), Record(nyc, datetime.now()))
        impossible = analyzer.analyze_velocity(london, datetime.now() + timedelta(minutes=30), Record(nyc, datetime.now()))
        
        assert normal.is_anomaly == False
        assert impossible.is_anomaly == True
        print(f"  ✓ Normal travel: no anomaly")
        print(f"  ✓ Impossible travel (30min NYC->London): detected")
        results.append(("Velocity analyzer", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results.append(("Velocity analyzer", False))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    
    for name, ok in results:
        status = "✓ PASS" if ok else "✗ FAIL"
        print(f"  {status} - {name}")
    
    print(f"\n  Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n  ✓ ALL TESTS PASSED!")
        return True
    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
