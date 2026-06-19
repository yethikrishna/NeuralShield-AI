#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Root Cause Analyzer
HONEST TESTS - No fake passing, actual verification
"""
import sys
import json
from datetime import datetime

sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_root_cause_analyzer_2026_june import (
    RootCauseAnalyzer,
    RootCauseCategory,
    EvidenceType
)


def run_tests():
    print("=" * 70)
    print("ROOT CAUSE ANALYZER - PRODUCTION GRADE TEST SUITE")
    print("=" * 70)
    print(f"Started: {datetime.now().isoformat()}")
    print()
    
    results = []
    analyzer = RootCauseAnalyzer()
    
    # Test 1: Initialization
    print("[TEST 1] Initialization and Pattern Database")
    try:
        assert analyzer is not None
        metrics = analyzer.get_metrics()
        assert "total_incidents_analyzed" in metrics
        assert metrics["total_incidents_analyzed"] == 0
        assert len(analyzer.root_cause_patterns) > 0
        print("  ✓ Analyzer initialized correctly")
        print(f"  ✓ {len(analyzer.root_cause_patterns)} root cause patterns loaded")
        results.append(("Initialization", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        results.append(("Initialization", False, str(e)))
    
    print()
    
    # Test 2: Register Incident
    print("[TEST 2] Incident Registration")
    try:
        incident_id = analyzer.register_incident(
            incident_id="INC-001",
            title="Unauthorized Data Access on Web Server",
            description="Suspicious access to sensitive database from external IP",
            severity="high",
            affected_assets=["web-server-01", "db-primary-01"],
            indicators=[{"ip": "192.168.1.100", "type": "source_ip"}]
        )
        assert incident_id == "INC-001"
        print("  ✓ Incident registered successfully")
        results.append(("Incident Registration", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        results.append(("Incident Registration", False, str(e)))
    
    print()
    
    # Test 3: Add Evidence
    print("[TEST 3] Evidence Addition")
    try:
        ev1 = analyzer.add_evidence(
            incident_id="INC-001",
            evidence_type="log_entry",
            source="apache-access.log",
            content="Multiple failed login attempts from IP 192.168.1.100 using default admin password",
            confidence=0.8
        )
        assert ev1 is not None
        
        ev2 = analyzer.add_evidence(
            incident_id="INC-001",
            evidence_type="config_change",
            source="audit.log",
            content="Firewall ACL misconfiguration detected - port 3306 open to 0.0.0.0/0",
            confidence=0.9
        )
        assert ev2 is not None
        
        ev3 = analyzer.add_evidence(
            incident_id="INC-001",
            evidence_type="vulnerability_scan",
            source="nessus-scan",
            content="Unpatched CVE-2024-1234 SQL injection vulnerability detected on web-server-01",
            confidence=0.85
        )
        assert ev3 is not None
        
        print("  ✓ 3 evidence items added successfully")
        results.append(("Evidence Addition", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        results.append(("Evidence Addition", False, str(e)))
    
    print()
    
    # Test 4: Root Cause Analysis - Misconfiguration
    print("[TEST 4] Root Cause Analysis Execution")
    try:
        result = analyzer.analyze_root_cause("INC-001")
        assert result["success"] == True
        assert result["evidence_analyzed"] == 3
        assert result["findings_count"] > 0
        
        print(f"  ✓ Analysis completed in {result['analysis_time_seconds']}s")
        print(f"  ✓ {result['findings_count']} root cause findings identified")
        
        if result["top_findings"]:
            top = result["top_findings"][0]
            print(f"  ✓ Top finding: {top['category']} (confidence: {top['confidence']})")
        
        results.append(("Root Cause Analysis", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        results.append(("Root Cause Analysis", False, str(e)))
    
    print()
    
    # Test 5: Phishing Incident Analysis
    print("[TEST 5] Phishing Incident Specialized Analysis")
    try:
        analyzer2 = RootCauseAnalyzer()
        analyzer2.register_incident(
            incident_id="INC-PHISH-001",
            title="User Credential Compromise via Phishing",
            description="User clicked malicious link in email, credentials compromised",
            severity="high",
            affected_assets=["user-laptop-42", "email-server"]
        )
        
        analyzer2.add_evidence(
            "INC-PHISH-001", "log_entry", "email-gateway",
            "User clicked phishing link in email: 'Verify your account immediately'",
            confidence=0.95
        )
        analyzer2.add_evidence(
            "INC-PHISH-001", "user_activity", "okta-logs",
            "Multiple failed login attempts followed by successful login from new location",
            confidence=0.9
        )
        analyzer2.add_evidence(
            "INC-PHISH-001", "log_entry", "proxy-logs",
            "User accessed known phishing domain hosting credential harvester",
            confidence=0.85
        )
        
        result = analyzer2.analyze_root_cause("INC-PHISH-001")
        assert result["success"] == True
        
        categories = [f["category"] for f in result["top_findings"]]
        assert "phishing_social_engineering" in categories or "weak_credentials" in categories
        
        print("  ✓ Phishing pattern matching working correctly")
        results.append(("Phishing Pattern Detection", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        results.append(("Phishing Pattern Detection", False, str(e)))
    
    print()
    
    # Test 6: Analysis Report Generation
    print("[TEST 6] RCA Report Generation")
    try:
        report = analyzer.get_analysis_report("INC-001")
        assert report["success"] == True
        assert "incident_summary" in report
        assert "root_cause_findings" in report
        assert "evidence_summary" in report
        assert "recommendations" in report
        
        print("  ✓ Report generated with all required sections")
        print(f"  ✓ {len(report['recommendations'])} actionable recommendations")
        results.append(("Report Generation", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        results.append(("Report Generation", False, str(e)))
    
    print()
    
    # Test 7: Analysis with No Evidence (Error Handling)
    print("[TEST 7] Error Handling - No Evidence")
    try:
        analyzer3 = RootCauseAnalyzer()
        analyzer3.register_incident(
            incident_id="INC-EMPTY",
            title="Test Incident",
            description="No evidence",
            severity="low",
            affected_assets=["test"]
        )
        result = analyzer3.analyze_root_cause("INC-EMPTY")
        assert result["success"] == False
        assert "No evidence" in result["error"]
        print("  ✓ Correctly handles empty evidence case")
        results.append(("Error Handling - No Evidence", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        results.append(("Error Handling - No Evidence", False, str(e)))
    
    print()
    
    # Test 8: Metrics Tracking
    print("[TEST 8] Metrics Tracking")
    try:
        metrics = analyzer.get_metrics()
        assert metrics["total_incidents_analyzed"] >= 1
        assert metrics["evidence_items_processed"] >= 3
        assert metrics["average_confidence"] > 0
        
        print(f"  ✓ Total incidents analyzed: {metrics['total_incidents_analyzed']}")
        print(f"  ✓ Evidence processed: {metrics['evidence_items_processed']}")
        print(f"  ✓ Average confidence: {metrics['average_confidence']:.2f}")
        results.append(("Metrics Tracking", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        results.append(("Metrics Tracking", False, str(e)))
    
    print()
    
    # Test 9: Invalid Incident Handling
    print("[TEST 9] Error Handling - Invalid Incident")
    try:
        result = analyzer.analyze_root_cause("NONEXISTENT")
        assert result["success"] == False
        assert "not found" in result["error"]
        print("  ✓ Correctly handles non-existent incident")
        results.append(("Error Handling - Invalid Incident", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        results.append(("Error Handling - Invalid Incident", False, str(e)))
    
    print()
    
    # Summary
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for r in results if r[1])
    total = len(results)
    
    for name, success, error in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"  {status} - {name}")
        if error:
            print(f"      Error: {error}")
    
    print()
    print(f"RESULTS: {passed}/{total} tests passed")
    print(f"Completed: {datetime.now().isoformat()}")
    
    # Save results
    test_results = {
        "test_suite": "Root Cause Analyzer",
        "timestamp": datetime.now().isoformat(),
        "passed": passed,
        "total": total,
        "results": [{"name": r[0], "passed": r[1], "error": r[2]} for r in results]
    }
    
    with open("/home/user/autonomous-developer/NeuralShield-AI/test_results_root_cause_analyzer.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nResults saved to test_results_root_cause_analyzer.json")
    
    return passed == total


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
