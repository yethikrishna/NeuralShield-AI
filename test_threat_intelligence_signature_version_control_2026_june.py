#!/usr/bin/env python3
"""
Test Suite for Threat Intelligence Signature Version Control
June 2026 - Production Grade Tests

Tests versioning, rollback, deployment validation, and integrity checking.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_signature_version_control_2026_june import (
    ThreatIntelSignatureVersionControl,
    SignatureType,
    DeploymentStatus
)


def run_tests():
    print("=" * 70)
    print("THREAT INTELLIGENCE SIGNATURE VERSION CONTROL TESTS")
    print("June 2026 - Production Grade")
    print("=" * 70)
    
    passed = 0
    failed = 0
    
    try:
        # Test 1: Initialize version control
        print("\n[TEST 1] Initialization")
        try:
            vc = ThreatIntelSignatureVersionControl()
            stats = vc.get_statistics()
            assert stats["total_versions"] == 0
            print(f"  ✓ Version control initialized successfully")
            passed += 1
        except Exception as e:
            print(f"  ✗ Failed: {e}")
            failed += 1

        # Test 2: Create new signature version
        print("\n[TEST 2] Create New Signature Version")
        try:
            yara_rule = """
rule Malicious_EXE_Detection {
    meta:
        description = "Detects malicious EXE patterns"
        author = "Security Team"
        severity = "high"
    strings:
        $mz = { 4D 5A }
        $pattern1 = "malicious_code"
    condition:
        $mz at 0 and any of them
}
"""
            v1 = vc.create_new_version(
                signature_name="Malicious EXE Detection",
                signature_type=SignatureType.YARA,
                content=yara_rule,
                author="security-admin",
                change_description="Initial YARA rule for EXE malware detection"
            )
            assert v1.version_number == "1.0.0"
            assert v1.deployment_status == DeploymentStatus.PENDING
            assert len(v1.content_hash) == 64
            print(f"  ✓ Created version {v1.version_number} (ID: {v1.version_id[:12]}...)")
            passed += 1
        except Exception as e:
            print(f"  ✗ Failed: {e}")
            failed += 1

        # Test 3: Integrity validation
        print("\n[TEST 3] Signature Integrity Validation")
        try:
            valid, msg = vc.validate_integrity(v1.version_id)
            assert valid == True
            assert msg == "Integrity verified"
            print(f"  ✓ Integrity validation passed")
            passed += 1
        except Exception as e:
            print(f"  ✗ Failed: {e}")
            failed += 1

        # Test 4: Deployment validation gates
        print("\n[TEST 4] Deployment Validation Gates")
        try:
            can_deploy, gates = vc.validate_deployment_gates(v1.version_id)
            assert can_deploy == True
            assert gates["integrity_check"] == True
            assert gates["risk_threshold"] == True
            print(f"  ✓ Deployment validation passed - Risk score: {v1.risk_score:.3f}")
            passed += 1
        except Exception as e:
            print(f"  ✗ Failed: {e}")
            failed += 1

        # Test 5: Mark version as deployed
        print("\n[TEST 5] Mark Version as Deployed")
        try:
            success, msg = vc.mark_deployed(v1.version_id)
            assert success == True
            assert v1.deployment_status == DeploymentStatus.DEPLOYED
            print(f"  ✓ Marked version as deployed successfully")
            passed += 1
        except Exception as e:
            print(f"  ✗ Failed: {e}")
            failed += 1

        # Test 6: Create updated version
        print("\n[TEST 6] Create Updated Signature Version")
        try:
            yara_rule_v2 = """
rule Malicious_EXE_Detection {
    meta:
        description = "Detects malicious EXE patterns"
        author = "Security Team"
        severity = "critical"
        tlp = "amber"
    strings:
        $mz = { 4D 5A }
        $pattern1 = "malicious_code"
        $pattern2 = "suspicious_api_call"
        $pattern3 = "anti_debug"
    condition:
        $mz at 0 and 2 of them
}
"""
            v2 = vc.create_new_version(
                signature_name="Malicious EXE Detection v2",
                signature_type=SignatureType.YARA,
                content=yara_rule_v2,
                author="security-admin",
                change_description="Added additional pattern matching and improved conditions",
                previous_version_id=v1.version_id
            )
            assert v2.version_number != "1.0.0"
            assert v2.previous_version_id == v1.version_id
            print(f"  ✓ Created version {v2.version_number} with auto-bump")
            passed += 1
        except Exception as e:
            print(f"  ✗ Failed: {e}")
            failed += 1

        # Test 7: Version comparison & diff
        print("\n[TEST 7] Version Comparison & Diff")
        try:
            diff = vc.compare_versions(v1.version_id, v2.version_id)
            assert diff.similarity_score > 0.5
            assert diff.lines_added > 0
            print(f"  ✓ Version diff computed - Similarity: {diff.similarity_score:.2%}")
            print(f"    Impact: {diff.impact_assessment}")
            print(f"    Added: {diff.lines_added} lines, Removed: {diff.lines_removed} lines")
            passed += 1
        except Exception as e:
            print(f"  ✗ Failed: {e}")
            failed += 1

        # Test 8: Version history tracking
        print("\n[TEST 8] Version History Tracking")
        try:
            history = vc.get_version_history()
            assert len(history) == 2
            print(f"  ✓ Retrieved version history: {len(history)} versions")
            for entry in history:
                print(f"    - {entry['version_number']}: {entry['description']}")
            passed += 1
        except Exception as e:
            print(f"  ✗ Failed: {e}")
            failed += 1

        # Test 9: Rollback operation
        print("\n[TEST 9] Rollback Operation")
        try:
            result = vc.rollback_to_version(v1.version_id, "admin-rollback")
            assert result.success == True
            assert result.rollback_from_version == v1.version_number
            assert result.rollback_to_version == v1.version_number
            print(f"  ✓ Rollback completed successfully")
            print(f"    Message: {result.message}")
            passed += 1
        except Exception as e:
            print(f"  ✗ Failed: {e}")
            failed += 1

        # Test 10: System statistics
        print("\n[TEST 10] System Statistics")
        try:
            stats = vc.get_statistics()
            assert stats["total_versions"] >= 3
            assert stats["deployed_count"] >= 1
            assert stats["rolled_back_count"] >= 0
            print(f"  ✓ System statistics:")
            print(f"    Total versions: {stats['total_versions']}")
            print(f"    Deployed: {stats['deployed_count']}")
            print(f"    Rolled back: {stats['rolled_back_count']}")
            print(f"    Rollback rate: {stats['rollback_rate']:.1%}")
            passed += 1
        except Exception as e:
            print(f"  ✗ Failed: {e}")
            failed += 1

        # Test 11: Snort/Suricata signature support
        print("\n[TEST 11] Snort/Suricata Signature Support")
        try:
            snort_rule = 'alert tcp any any -> any 80 (msg:"SQL Injection attempt"; content:"UNION SELECT"; sid:1000001; rev:1;)'
            snort_v = vc.create_new_version(
                signature_name="SQL Injection Detection",
                signature_type=SignatureType.SNORT,
                content=snort_rule,
                author="ids-admin",
                change_description="Snort rule for SQL injection detection"
            )
            assert snort_v.version_number == "1.0.0"
            vc.mark_deployed(snort_v.version_id)
            print(f"  ✓ Snort rule created and validated: {snort_v.version_number}")
            passed += 1
        except Exception as e:
            print(f"  ✗ Failed: {e}")
            failed += 1

        # Test 12: Sigma signature support
        print("\n[TEST 12] Sigma Signature Support")
        try:
            sigma_rule = """
title: Suspicious PowerShell Execution
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Detects suspicious PowerShell commands
author: Threat Intel Team
logsource:
    product: windows
    service: powershell
detection:
    selection:
        CommandLine|contains:
            - 'Invoke-Expression'
            - 'DownloadString'
    condition: selection
falsepositives:
    - Legitimate administration
level: high
"""
            sigma_v = vc.create_new_version(
                signature_name="Suspicious PowerShell",
                signature_type=SignatureType.SIGMA,
                content=sigma_rule,
                author="soc-analyst",
                change_description="Sigma rule for PowerShell detection"
            )
            assert sigma_v.version_number == "1.0.0"
            vc.mark_deployed(sigma_v.version_id)
            print(f"  ✓ Sigma rule created and validated: {sigma_v.version_number}")
            passed += 1
        except Exception as e:
            print(f"  ✗ Failed: {e}")
            failed += 1

    except Exception as e:
        print(f"\nFATAL ERROR IN TEST SUITE: {e}")
        import traceback
        traceback.print_exc()
        failed += 1

    print("\n" + "=" * 70)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    total = passed + failed
    if failed == 0:
        print(f"SUCCESS: All {total} tests passed! ✓")
        print("=" * 70)
        return True
    else:
        print(f"FAILURE: {failed} test(s) failed! ✗")
        print("=" * 70)
        return False


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
