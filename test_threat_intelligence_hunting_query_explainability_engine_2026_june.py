#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Hunting Query Explainability Engine
Production-grade tests with real assertions and edge cases.
"""
import sys
import json
sys.path.insert(0, 'neural_shield')
from threat_intelligence_hunting_query_explainability_engine_2026_june import (
    HuntingQueryExplainabilityEngine,
    QueryPlatform,
    QueryCategory,
    MITRECategory
)
def run_tests():
    print("=" * 70)
    print("NeuralShield AI - Hunting Query Explainability Engine - Test Suite")
    print("=" * 70)
    
    engine = HuntingQueryExplainabilityEngine()
    passed = 0
    failed = 0
    
    # Test 1: Basic Splunk query explanation
    print("\n[TEST 1] Basic Splunk Query Explanation")
    try:
        query = 'search index=security sourcetype=windows process_name=powershell.exe | stats count'
        result = engine.explain_query(query)
        assert result.platform == QueryPlatform.SPLUNK, "Should detect Splunk platform"
        assert result.query_id is not None, "Should generate query ID"
        assert len(result.components) > 0, "Should parse components"
        print("  ✓ PASSED - Basic Splunk query explained correctly")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 2: Platform detection accuracy
    print("\n[TEST 2] Platform Detection Accuracy")
    try:
        splunk_query = 'search index=* | stats count by host'
        sql_query = 'SELECT * FROM events WHERE src_ip = "10.0.0.1"'
        sigma_query = 'title: Test Detection\ndetection:\n  selection:\n    EventID: 4688'
        
        assert engine._detect_platform(splunk_query) == QueryPlatform.SPLUNK
        assert engine._detect_platform(sql_query) == QueryPlatform.SQL
        assert engine._detect_platform(sigma_query) == QueryPlatform.SIGMA
        print("  ✓ PASSED - Platform detection working correctly")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 3: Query categorization
    print("\n[TEST 3] Query Categorization")
    try:
        process_query = 'cmd.exe powershell.exe wmic.exe'
        network_query = 'src_ip dst_port http dns tcp'
        malware_query = 'mimikatz invoke- base64'
        
        cat1 = engine._categorize_query(process_query, QueryPlatform.SPLUNK)
        cat2 = engine._categorize_query(network_query, QueryPlatform.SPLUNK)
        cat3 = engine._categorize_query(malware_query, QueryPlatform.SPLUNK)
        
        assert cat1 == QueryCategory.PROCESS_ANALYSIS
        assert cat2 == QueryCategory.NETWORK_TRAFFIC
        assert cat3 == QueryCategory.MALWARE_DETECTION
        print("  ✓ PASSED - Query categorization working correctly")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 4: MITRE ATT&CK mapping
    print("\n[TEST 4] MITRE ATT&CK Mapping")
    try:
        query_with_mitre = 'powershell registry token auth lateral exfil c2'
        techniques = engine._map_to_mitre(query_with_mitre)
        assert len(techniques) >= 3, "Should map to multiple MITRE techniques"
        assert MITRECategory.EXECUTION in techniques
        assert MITRECategory.PERSISTENCE in techniques
        print(f"  ✓ PASSED - Mapped to {len(techniques)} MITRE techniques")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 5: Performance analysis
    print("\n[TEST 5] Performance Analysis")
    try:
        simple_query = 'search index=security'
        complex_query = 'search index=* | regex .* | regex .* | regex .* | stats count | where count>1 | table *'
        
        perf_simple = engine._analyze_performance(simple_query, QueryPlatform.SPLUNK)
        perf_complex = engine._analyze_performance(complex_query, QueryPlatform.SPLUNK)
        
        assert perf_simple.complexity_score < perf_complex.complexity_score
        assert perf_simple.estimated_complexity == "low"
        print("  ✓ PASSED - Performance analysis differentiates complexity")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 6: False positive risk assessment
    print("\n[TEST 6] False Positive Risk Assessment")
    try:
        specific_query = 'process_name=mimikatz.exe cve-2026-1234'
        broad_query = 'process=* network=* file=* user=*'
        
        risk1, _ = engine._assess_false_positive_risk(specific_query)
        risk2, _ = engine._assess_false_positive_risk(broad_query)
        
        assert risk1 in ["low", "medium"]
        assert risk2 in ["medium", "high"]
        print("  ✓ PASSED - False positive risk assessment working")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 7: Report generation
    print("\n[TEST 7] Report Generation")
    try:
        query = 'search index=security process_name=powershell.exe | stats count'
        explained = engine.explain_query(query)
        report = engine.generate_explanation_report(explained)
        
        assert 'query_id' in report
        assert 'summary' in report
        assert 'performance_analysis' in report
        assert 'mitre_coverage' in report
        assert isinstance(report['components'], list)
        print("  ✓ PASSED - Report generation complete")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 8: Markdown export
    print("\n[TEST 8] Markdown Export")
    try:
        query = 'search index=security sourcetype=auth failed=true'
        explained = engine.explain_query(query)
        md = engine.export_to_markdown(explained)
        
        assert '# Threat Hunting Query Explanation Report' in md
        assert '## Query Summary' in md
        assert '## Performance Analysis' in md
        assert len(md) > 500
        print("  ✓ PASSED - Markdown export generated correctly")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 9: Batch processing
    print("\n[TEST 9] Batch Query Processing")
    try:
        queries = [
            'search index=sec process=cmd.exe',
            'search index=net dst_port=443',
            'search index=auth failed=true'
        ]
        results = engine.batch_explain_queries(queries)
        assert len(results) == 3
        assert all(r.query_id is not None for r in results)
        print("  ✓ PASSED - Batch processing completed successfully")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 10: Query comparison
    print("\n[TEST 10] Query Comparison")
    try:
        q1 = engine.explain_query('search process=powershell.exe registry')
        q2 = engine.explain_query('search process=powershell.exe network')
        comparison = engine.compare_queries(q1, q2)
        
        assert 'common_mitre_techniques' in comparison
        assert 'complexity_difference' in comparison
        assert comparison['platform_match'] == True
        print("  ✓ PASSED - Query comparison working correctly")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 11: Caching mechanism
    print("\n[TEST 11] Caching Mechanism")
    try:
        query = 'search index=test caching=enabled'
        result1 = engine.explain_query(query)
        result2 = engine.explain_query(query)
        
        assert result1.query_id == result2.query_id
        assert result1 is result2  # Same object from cache
        print("  ✓ PASSED - Caching mechanism working correctly")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Summary
    print("\n" + "=" * 70)
    print(f"TEST SUMMARY: {passed} PASSED | {failed} FAILED")
    print("=" * 70)
    
    # Save test results
    test_results = {
        "test_timestamp": __import__('datetime').datetime.now().isoformat(),
        "total_tests": passed + failed,
        "passed": passed,
        "failed": failed,
        "success_rate": f"{(passed/(passed+failed))*100:.1f}%"
    }
    
    with open('test_results_hunting_query_explainability_engine.json', 'w') as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nTest results saved to test_results_hunting_query_explainability_engine.json")
    
    return failed == 0
if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
