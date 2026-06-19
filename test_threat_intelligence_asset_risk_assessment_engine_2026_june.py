#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Asset Risk Assessment Engine
June 19, 2026 - Production Grade Tests

Tests cover:
- Single asset risk assessment
- Batch assessment with risk sorting
- CVSS score adjustment calculations
- Vulnerability prioritization
- Risk level determination
- Remediation effort estimation
- Threat intelligence scoring
"""

import sys
import json
import importlib.util
from datetime import datetime, timedelta

# Import directly from module file to avoid __init__.py issues
spec = importlib.util.spec_from_file_location(
    "asset_risk_module",
    "/home/user/autonomous-developer/NeuralShield-AI/neural_shield/threat_intelligence_asset_risk_assessment_engine_2026_june.py"
)
asset_risk_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(asset_risk_module)

AssetRiskAssessmentEngine = asset_risk_module.AssetRiskAssessmentEngine
CVSSRiskCalculator = asset_risk_module.CVSSRiskCalculator
ThreatIntelligenceScorer = asset_risk_module.ThreatIntelligenceScorer
Asset = asset_risk_module.Asset
Vulnerability = asset_risk_module.Vulnerability
AssetType = asset_risk_module.AssetType
RiskLevel = asset_risk_module.RiskLevel


def run_tests():
    print("=" * 70)
    print("TEST SUITE: Threat Intelligence Asset Risk Assessment Engine")
    print("=" * 70)
    print(f"Test Time: {datetime.utcnow().isoformat()}")
    print()
    
    all_passed = True
    test_results = []
    
    # Test 1: CVSS Risk Calculator - Basic adjustment
    print("[TEST 1] CVSS Risk Calculator - Basic Score Adjustment")
    try:
        calculator = CVSSRiskCalculator()
        vuln = Vulnerability(
            cve_id="CVE-2026-1234",
            cvss_score=9.8,
            severity="critical",
            description="Test critical vulnerability",
            exploit_available=True,
            exploit_maturity="weaponized"
        )
        adjusted = calculator.calculate_adjusted_cvss(vuln)
        assert 9.0 <= adjusted <= 10.0, f"Expected ~9.8, got {adjusted}"
        print(f"  ✓ Passed: Weaponized exploit score = {adjusted}")
        test_results.append({"test": "cvss_basic", "status": "PASS", "score": adjusted})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "cvss_basic", "status": "FAIL", "error": str(e)})
        all_passed = False
    
    # Test 2: CVSS Risk Calculator - Exploit maturity weighting
    print("\n[TEST 2] CVSS Risk Calculator - Exploit Maturity Weighting")
    try:
        calculator = CVSSRiskCalculator()
        vuln_unproven = Vulnerability(
            cve_id="CVE-2026-TEST",
            cvss_score=10.0,
            severity="critical",
            description="Test",
            exploit_available=False,
            exploit_maturity="unproven"
        )
        vuln_weaponized = Vulnerability(
            cve_id="CVE-2026-TEST2",
            cvss_score=10.0,
            severity="critical",
            description="Test",
            exploit_available=True,
            exploit_maturity="weaponized"
        )
        score_unproven = calculator.calculate_adjusted_cvss(vuln_unproven)
        score_weaponized = calculator.calculate_adjusted_cvss(vuln_weaponized)
        assert score_weaponized > score_unproven, "Weaponized should score higher"
        print(f"  ✓ Passed: Weaponized ({score_weaponized}) > Unproven ({score_unproven})")
        test_results.append({"test": "cvss_maturity", "status": "PASS"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "cvss_maturity", "status": "FAIL", "error": str(e)})
        all_passed = False
    
    # Test 3: Threat Intelligence Scorer
    print("\n[TEST 3] Threat Intelligence Scorer")
    try:
        scorer = ThreatIntelligenceScorer()
        asset = Asset(
            asset_id="ASSET-001",
            asset_name="Web Server Test",
            asset_type=AssetType.WEB_SERVER,
            ip_address="192.168.1.1",
            operating_system="Ubuntu 22.04",
            business_impact=8,
            network_exposure="internet"
        )
        score, techniques = scorer.calculate_threat_score(asset)
        assert 0 <= score <= 10, f"Score out of range: {score}"
        assert len(techniques) > 0, "Should have MITRE techniques"
        print(f"  ✓ Passed: Threat score = {score}, Techniques: {techniques}")
        test_results.append({"test": "threat_scorer", "status": "PASS", "score": score})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "threat_scorer", "status": "FAIL", "error": str(e)})
        all_passed = False
    
    # Test 4: Full Risk Assessment - Critical Asset
    print("\n[TEST 4] Full Risk Assessment - Critical Internet-Exposed Server")
    try:
        engine = AssetRiskAssessmentEngine()
        
        # Create high-risk asset
        critical_vulns = [
            Vulnerability(
                cve_id="CVE-2026-1001",
                cvss_score=10.0,
                severity="critical",
                description="Remote code execution",
                exploit_available=True,
                exploit_maturity="weaponized",
                threat_feed_match="CISA Known Exploited"
            ),
            Vulnerability(
                cve_id="CVE-2026-1002",
                cvss_score=9.1,
                severity="critical",
                description="SQL injection",
                exploit_available=True,
                exploit_maturity="proof-of-concept"
            )
        ]
        
        asset = Asset(
            asset_id="PROD-WEB-001",
            asset_name="Production E-Commerce Web Server",
            asset_type=AssetType.WEB_SERVER,
            ip_address="203.0.113.10",
            operating_system="Ubuntu 22.04 LTS",
            business_impact=10,
            network_exposure="internet",
            vulnerabilities=critical_vulns,
            department="E-Commerce"
        )
        
        result = engine.assess_asset_risk(asset)
        
        assert result.overall_risk_score >= 7.0, f"Expected high risk, got {result.overall_risk_score}"
        assert result.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH], f"Unexpected risk level: {result.risk_level}"
        assert len(result.prioritized_vulnerabilities) == 2, "Should have 2 prioritized vulns"
        assert result.estimated_remediation_effort_hours > 0, "Should have remediation effort"
        
        print(f"  ✓ Passed:")
        print(f"    Asset: {result.asset_name}")
        print(f"    Overall Risk Score: {result.overall_risk_score}")
        print(f"    Risk Level: {result.risk_level.value.upper()}")
        print(f"    Remediation Priority: {result.remediation_priority}")
        print(f"    Key Risk Factors: {result.key_risk_factors}")
        
        test_results.append({
            "test": "full_assessment_critical", 
            "status": "PASS",
            "risk_score": result.overall_risk_score,
            "risk_level": result.risk_level.value
        })
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        test_results.append({"test": "full_assessment_critical", "status": "FAIL", "error": str(e)})
        all_passed = False
    
    # Test 5: Batch Assessment with Sorting
    print("\n[TEST 5] Batch Assessment - Risk Sorting")
    try:
        engine = AssetRiskAssessmentEngine()
        
        assets = [
            Asset(
                asset_id=f"ASSET-{i:03d}",
                asset_name=f"Server {i}",
                asset_type=AssetType.WEB_SERVER if i % 2 == 0 else AssetType.DATABASE,
                ip_address=f"192.168.1.{i}",
                operating_system="Linux",
                business_impact=5 + i,
                network_exposure="internet" if i < 2 else "internal",
                vulnerabilities=[
                    Vulnerability(
                        cve_id=f"CVE-2026-{1000+i}",
                        cvss_score=9.0 - (i * 0.5),
                        severity="high" if i < 2 else "medium",
                        description=f"Test vuln {i}"
                    )
                ]
            )
            for i in range(5)
        ]
        
        results = engine.batch_assess(assets)
        
        # Verify sorted descending
        scores = [r.overall_risk_score for r in results]
        assert scores == sorted(scores, reverse=True), "Results should be sorted by risk descending"
        assert len(results) == 5, f"Expected 5 results, got {len(results)}"
        
        print(f"  ✓ Passed: Batch processed {len(results)} assets, correctly sorted")
        for i, r in enumerate(results[:3]):
            print(f"    #{i+1}: {r.asset_name} - Score: {r.overall_risk_score} - {r.risk_level.value}")
        
        test_results.append({"test": "batch_assessment", "status": "PASS", "count": len(results)})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "batch_assessment", "status": "FAIL", "error": str(e)})
        all_passed = False
    
    # Test 6: Risk Summary Statistics
    print("\n[TEST 6] Risk Summary Statistics")
    try:
        summary = engine.get_risk_summary()
        assert summary["total_assets_assessed"] == 5, f"Expected 5, got {summary['total_assets_assessed']}"
        assert "average_risk_score" in summary
        assert "risk_distribution" in summary
        
        print(f"  ✓ Passed:")
        print(f"    Total Assessed: {summary['total_assets_assessed']}")
        print(f"    Average Score: {summary['average_risk_score']}")
        print(f"    Risk Distribution: {summary['risk_distribution']}")
        
        test_results.append({"test": "risk_summary", "status": "PASS"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "risk_summary", "status": "FAIL", "error": str(e)})
        all_passed = False
    
    # Test 7: Low Risk Asset (Internal, no vulnerabilities)
    print("\n[TEST 7] Low Risk Asset Assessment")
    try:
        engine = AssetRiskAssessmentEngine()
        asset = Asset(
            asset_id="LOW-RISK-001",
            asset_name="Internal Workstation",
            asset_type=AssetType.ENDPOINT,
            ip_address="10.0.0.50",
            operating_system="Windows 11",
            business_impact=3,
            network_exposure="restricted",
            vulnerabilities=[]
        )
        
        result = engine.assess_asset_risk(asset)
        assert result.overall_risk_score < 5.0, f"Expected low risk, got {result.overall_risk_score}"
        assert result.vulnerability_risk_score == 0.0, "No vulnerabilities should score 0"
        
        print(f"  ✓ Passed: Low risk asset score = {result.overall_risk_score}")
        print(f"    Risk Level: {result.risk_level.value}")
        test_results.append({"test": "low_risk_asset", "status": "PASS", "score": result.overall_risk_score})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "low_risk_asset", "status": "FAIL", "error": str(e)})
        all_passed = False
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for r in test_results if r["status"] == "PASS")
    total = len(test_results)
    print(f"Passed: {passed}/{total}")
    
    if all_passed:
        print("✓ ALL TESTS PASSED")
    else:
        print("✗ SOME TESTS FAILED")
        failed = [r for r in test_results if r["status"] == "FAIL"]
        for f in failed:
            print(f"  - {f['test']}: {f.get('error', 'Unknown error')}")
    
    print()
    
    # Save results
    with open('/home/user/autonomous-developer/NeuralShield-AI/test_results_asset_risk_assessment.json', 'w') as f:
        json.dump({
            "test_suite": "Threat Intelligence Asset Risk Assessment Engine",
            "timestamp": datetime.utcnow().isoformat(),
            "passed": passed,
            "total": total,
            "all_passed": all_passed,
            "results": test_results
        }, f, indent=2)
    
    print(f"Results saved to test_results_asset_risk_assessment.json")
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(run_tests())
