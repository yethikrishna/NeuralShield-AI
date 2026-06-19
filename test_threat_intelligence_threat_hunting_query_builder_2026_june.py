#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Threat Hunting Query Builder
June 2026 Production Release

REAL TESTS - NO EMPTY SHELLS
"""

import sys
import json
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_threat_hunting_query_builder_2026_june import (
    ThreatHuntingQueryBuilder,
    QueryTemplateType,
    ExportFormat,
    ValidationSeverity
)


def run_tests():
    print("=" * 70)
    print("NeuralShield-AI: Threat Hunting Query Builder Tests")
    print("=" * 70)
    
    builder = ThreatHuntingQueryBuilder()
    passed = 0
    failed = 0
    
    # Test 1: Template building
    print("\n[TEST 1] Build query from template")
    try:
        query = builder.build_from_template(QueryTemplateType.RANSOMWARE_ACTIVITY)
        assert query.is_valid == True
        assert query.template_used == QueryTemplateType.RANSOMWARE_ACTIVITY
        assert len(query.query_dict["conditions"]) == 2
        print(f"  ✓ PASS: Built query from template - {query.query_id}")
        print(f"    Query: {query.query_string}")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 2: Manual condition building
    print("\n[TEST 2] Build query from manual conditions")
    try:
        conditions = [
            {"field": "severity", "operator": "=", "value": "CRITICAL"},
            {"field": "confidence", "operator": ">", "value": 0.8}
        ]
        query = builder.build_from_conditions(conditions)
        assert query.is_valid == True
        assert "CRITICAL" in query.query_string
        print(f"  ✓ PASS: Built manual query - {query.query_id}")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 3: Natural language query
    print("\n[TEST 3] Build query from natural language")
    try:
        query = builder.build_from_natural_language("find all high severity threats")
        assert query.is_valid == True
        print(f"  ✓ PASS: Built NL query - {query.query_string}")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 4: Query validation - valid query
    print("\n[TEST 4] Query validation - valid query")
    try:
        query_dict = {
            "conditions": [
                {"field": "severity", "operator": "in", "value": ["HIGH", "CRITICAL"]}
            ],
            "operator": "AND"
        }
        result = builder.validate_query(query_dict)
        assert result["is_valid"] == True
        print(f"  ✓ PASS: Valid query validated correctly")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 5: Query validation - invalid operator
    print("\n[TEST 5] Query validation - catch invalid operator")
    try:
        query_dict = {
            "conditions": [
                {"field": "severity", "operator": "INVALID_OP", "value": "HIGH"}
            ],
            "operator": "AND"
        }
        result = builder.validate_query(query_dict)
        has_error = any(m.severity == ValidationSeverity.ERROR for m in result["messages"])
        assert has_error == True
        print(f"  ✓ PASS: Correctly detected invalid operator")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 6: Query validation - missing required field
    print("\n[TEST 6] Query validation - catch missing fields")
    try:
        query_dict = {
            "conditions": [
                {"operator": "=", "value": "HIGH"}  # Missing 'field'
            ],
            "operator": "AND"
        }
        result = builder.validate_query(query_dict)
        has_error = any(m.severity == ValidationSeverity.ERROR for m in result["messages"])
        assert has_error == True
        print(f"  ✓ PASS: Correctly detected missing 'field' in condition")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 7: Auto-completion suggestions
    print("\n[TEST 7] Get auto-completion suggestions")
    try:
        suggestions = builder.get_suggestions("sever")
        assert len(suggestions) > 0
        severity_suggestions = [s for s in suggestions if s.category == "Severity"]
        assert len(severity_suggestions) > 0
        print(f"  ✓ PASS: Got {len(suggestions)} suggestions")
        for s in suggestions[:3]:
            print(f"    - {s.value}: {s.description}")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 8: Get available templates
    print("\n[TEST 8] Get available templates")
    try:
        templates = builder.get_available_templates()
        assert len(templates) >= 5
        print(f"  ✓ PASS: Found {len(templates)} available templates")
        for t in templates[:3]:
            print(f"    - {t['name']}: {t['description'][:40]}...")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 9: Export to JSON
    print("\n[TEST 9] Export query to JSON")
    try:
        query = builder.build_from_template(QueryTemplateType.DATA_EXFILTRATION)
        json_output = builder.export_query(query, ExportFormat.JSON)
        parsed = json.loads(json_output)
        assert "conditions" in parsed
        print(f"  ✓ PASS: JSON export successful")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 10: Export to Splunk SPL
    print("\n[TEST 10] Export query to Splunk SPL")
    try:
        query = builder.build_from_template(QueryTemplateType.COMMAND_AND_CONTROL)
        spl_output = builder.export_query(query, ExportFormat.SPLUNK_SPL)
        assert "search" in spl_output.lower()
        print(f"  ✓ PASS: Splunk SPL export successful")
        print(f"    SPL: {spl_output[:80]}...")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 11: Query history tracking
    print("\n[TEST 11] Query history tracking")
    try:
        history = builder.get_query_history()
        assert len(history) >= 3
        print(f"  ✓ PASS: Query history has {len(history)} entries")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 12: Optimization recommendations
    print("\n[TEST 12] Optimization recommendations")
    try:
        conditions = [
            {"field": "description", "operator": "contains", "value": "test"},
            {"field": "patterns", "operator": "contains", "value": "pattern"}
        ]
        query = builder.build_from_conditions(conditions)
        assert len(query.optimization_recommendations) >= 1
        print(f"  ✓ PASS: Got {len(query.optimization_recommendations)} optimization recommendations")
        for rec in query.optimization_recommendations:
            print(f"    - {rec}")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 13: Template with customizations
    print("\n[TEST 13] Template with customizations")
    try:
        customizations = {
            "conditions": [
                {"field": "source", "operator": "=", "value": "external_feed"}
            ]
        }
        query = builder.build_from_template(
            QueryTemplateType.PRIVILEGE_ESCALATION,
            customizations=customizations
        )
        assert len(query.query_dict["conditions"]) == 3  # 2 from template + 1 custom
        print(f"  ✓ PASS: Template customization successful - {len(query.query_dict['conditions'])} conditions")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 14: Export to Elasticsearch DSL
    print("\n[TEST 14] Export query to Elasticsearch DSL")
    try:
        query = builder.build_from_template(QueryTemplateType.LATERAL_MOVEMENT)
        dsl_output = builder.export_query(query, ExportFormat.ELASTICSEARCH_DSL)
        parsed = json.loads(dsl_output)
        assert "query" in parsed
        print(f"  ✓ PASS: Elasticsearch DSL export successful")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Summary
    print("\n" + "=" * 70)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 70)
    
    # Save test results
    results = {
        "test_module": "threat_intelligence_threat_hunting_query_builder_2026_june",
        "passed": passed,
        "failed": failed,
        "total": passed + failed,
        "success_rate": passed / (passed + failed) * 100 if (passed + failed) > 0 else 0,
        "timestamp": __import__("time").time()
    }
    
    with open("/home/user/autonomous-developer/NeuralShield-AI/test_results_threat_hunting_query_builder.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nTest results saved to test_results_threat_hunting_query_builder.json")
    print(f"Success rate: {results['success_rate']:.1f}%")
    
    return results


if __name__ == "__main__":
    results = run_tests()
    sys.exit(0 if results["failed"] == 0 else 1)
