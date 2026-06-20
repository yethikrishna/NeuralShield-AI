"""
Test Suite for MITRE ATT&CK Heatmap Dashboard Generator v3
June 21, 2026

Production-grade tests with real assertions
"""

import json
import os
import sys
from datetime import datetime

# Add path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_mitre_heatmap_dashboard_generator_v3_2026_june import (
    MITREHeatmapGeneratorV3,
    MITRETactic,
    SeverityLevel,
    verify_heatmap_generator_v3
)


def run_all_tests():
    """Run all test cases"""
    results = {
        "test_basic_functionality": False,
        "test_heatmap_generation": False,
        "test_html_export": False,
        "test_json_export": False,
        "test_csv_export": False,
        "test_threat_actor_mapping": False,
        "test_trend_calculation": False
    }
    
    print("=" * 60)
    print("Testing MITRE Heatmap Generator v3")
    print("=" * 60)
    
    # Test 1: Basic functionality
    print("\n[TEST 1] Basic functionality...")
    try:
        generator = MITREHeatmapGeneratorV3()
        generator.add_observation(
            "T1566", "Phishing", MITRETactic.INITIAL_ACCESS,
            10, SeverityLevel.CRITICAL, "APT29"
        )
        assert len(generator.observations) == 1
        results["test_basic_functionality"] = True
        print("  ✓ PASSED")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
    
    # Test 2: Heatmap generation
    print("\n[TEST 2] Heatmap data generation...")
    try:
        generator = MITREHeatmapGeneratorV3()
        generator.add_observation("T1566", "Phishing", MITRETactic.INITIAL_ACCESS, 5)
        generator.add_observation("T1059", "Command Interpreter", MITRETactic.EXECUTION, 3)
        
        heatmap = generator.generate_heatmap_data()
        assert len(heatmap) == 14  # 14 tactics
        assert "Initial Access" in heatmap
        assert "Execution" in heatmap
        results["test_heatmap_generation"] = True
        print("  ✓ PASSED")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
    
    # Test 3: HTML export
    print("\n[TEST 3] HTML dashboard export...")
    try:
        generator = MITREHeatmapGeneratorV3()
        generator.add_observation("T1566", "Phishing", MITRETactic.INITIAL_ACCESS, 15, SeverityLevel.CRITICAL)
        html_path = "/tmp/test_heatmap_v3.html"
        success = generator.generate_html_dashboard(html_path)
        
        assert success
        assert os.path.exists(html_path)
        assert os.path.getsize(html_path) > 1000
        
        with open(html_path) as f:
            content = f.read()
            assert "MITRE ATT&CK" in content
            assert "Phishing" in content
            assert "T1566" in content
        
        results["test_html_export"] = True
        print("  ✓ PASSED")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
    
    # Test 4: JSON export
    print("\n[TEST 4] JSON export...")
    try:
        generator = MITREHeatmapGeneratorV3()
        generator.add_observation("T1566", "Phishing", MITRETactic.INITIAL_ACCESS, 10)
        json_path = "/tmp/test_heatmap_v3.json"
        success = generator.export_json(json_path)
        
        assert success
        assert os.path.exists(json_path)
        
        with open(json_path) as f:
            data = json.load(f)
            assert "version" in data
            assert data["version"] == "v3"
            assert "summary" in data
            assert "heatmap_data" in data
        
        results["test_json_export"] = True
        print("  ✓ PASSED")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
    
    # Test 5: CSV export
    print("\n[TEST 5] CSV export...")
    try:
        generator = MITREHeatmapGeneratorV3()
        generator.add_observation("T1566", "Phishing", MITRETactic.INITIAL_ACCESS, 10)
        csv_path = "/tmp/test_heatmap_v3.csv"
        success = generator.export_csv(csv_path)
        
        assert success
        assert os.path.exists(csv_path)
        assert os.path.getsize(csv_path) > 100
        
        results["test_csv_export"] = True
        print("  ✓ PASSED")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
    
    # Test 6: Threat actor mapping
    print("\n[TEST 6] Threat actor mapping...")
    try:
        generator = MITREHeatmapGeneratorV3()
        generator.add_observation("T1566", "Phishing", MITRETactic.INITIAL_ACCESS, 5, threat_actor="APT29")
        generator.add_observation("T1059", "Execution", MITRETactic.EXECUTION, 3, threat_actor="APT29")
        generator.add_observation("T1027", "Evasion", MITRETactic.DEFENSE_EVASION, 8, threat_actor="APT28")
        
        actor_matrix = generator.get_threat_actor_matrix()
        assert "APT29" in actor_matrix
        assert "APT28" in actor_matrix
        assert len(actor_matrix["APT29"]) == 2
        
        results["test_threat_actor_mapping"] = True
        print("  ✓ PASSED")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
    
    # Test 7: Trend calculation
    print("\n[TEST 7] Trend calculation...")
    try:
        generator = MITREHeatmapGeneratorV3()
        generator.set_previous_period_baseline({
            "Initial Access:T1566": 10
        })
        generator.add_observation("T1566", "Phishing", MITRETactic.INITIAL_ACCESS, 15)
        
        trend = generator.calculate_trend("Initial Access:T1566", 15)
        assert trend == 50.0  # 50% increase
        
        results["test_trend_calculation"] = True
        print("  ✓ PASSED")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
    
    # Run built-in verification
    print("\n[VERIFICATION] Running built-in verification...")
    verify_result = verify_heatmap_generator_v3()
    print(f"  Status: {verify_result['status']}")
    print(f"  Observations: {verify_result['observations_added']}")
    print(f"  Tactics: {verify_result['tactics_covered']}")
    print(f"  Detections: {verify_result['total_detections']}")
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    # Save results
    test_results = {
        "test_timestamp": datetime.now().isoformat(),
        "module": "MITRE Heatmap Generator v3",
        "passed": passed,
        "total": total,
        "results": results,
        "verification": verify_result
    }
    
    with open("/home/user/.super_doubao/super-doubao-runtime/workspace/NeuralShield-AI/test_results_mitre_heatmap_v3.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    return test_results


if __name__ == "__main__":
    run_all_tests()
