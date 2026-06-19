"""
Test Suite for Threat Intelligence Incident Response Automation Engine
June 20, 2026 - Production Grade Tests

Real tests that verify actual functionality
"""

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from neural_shield.threat_intelligence_incident_response_automation_engine_2026_june import (
    IncidentResponseAutomationEngine,
    IncidentEvent,
    IncidentType,
    IncidentSeverity,
    MITRETactic,
    MITRETechnique,
    ResponseActionType
)


def test_basic_incident_processing():
    """Test basic incident processing functionality"""
    print("=" * 60)
    print("TEST 1: Basic Incident Processing")
    print("=" * 60)
    
    engine = IncidentResponseAutomationEngine()
    
    # Create test events - ransomware scenario
    events = [
        IncidentEvent(
            event_id="EVT-001",
            timestamp=datetime.now() - timedelta(minutes=30),
            source="endpoint_edr",
            event_type="file_encryption_detected",
            description="Ransomware detected: files encrypted with .encrypted extension",
            ip_address="192.168.1.100",
            asset_identifier="SERVER-WEB-01",
            user_identifier="john.doe"
        ),
        IncidentEvent(
            event_id="EVT-002",
            timestamp=datetime.now() - timedelta(minutes=25),
            source="file_server",
            event_type="ransom_note_created",
            description="Ransom note README_RESTORE.txt created on file server",
            ip_address="192.168.1.100",
            asset_identifier="SERVER-FILE-01"
        ),
        IncidentEvent(
            event_id="EVT-003",
            timestamp=datetime.now() - timedelta(minutes=20),
            source="network_firewall",
            event_type="suspicious_outbound",
            description="Large outbound data transfer to unknown IP 45.33.32.156",
            ip_address="45.33.32.156",
            asset_identifier="SERVER-WEB-01"
        )
    ]
    
    result = engine.process_incident(events)
    
    print(f"✓ Incident ID: {result.incident_id}")
    print(f"✓ Incident Type: {result.incident_type.value}")
    print(f"✓ Severity: {result.severity.value} (Score: {result.severity_score})")
    print(f"✓ Title: {result.title}")
    print(f"✓ Events Processed: {len(result.events)}")
    print(f"✓ MITRE Mappings: {len(result.mitre_mappings)}")
    print(f"✓ Response Actions: {len(result.response_actions)}")
    print(f"✓ Processing Time: {result.processing_time_ms:.2f}ms")
    
    # Verify classification
    assert result.incident_type == IncidentType.RANSOMWARE, f"Expected RANSOMWARE, got {result.incident_type}"
    assert result.severity == IncidentSeverity.CRITICAL, f"Expected CRITICAL, got {result.severity}"
    assert len(result.mitre_mappings) > 0, "Should have MITRE mappings"
    assert len(result.response_actions) > 0, "Should have response actions"
    
    print("✓ All basic assertions passed!")
    return True


def test_phishing_incident():
    """Test phishing incident classification and response"""
    print("\n" + "=" * 60)
    print("TEST 2: Phishing Incident Detection")
    print("=" * 60)
    
    engine = IncidentResponseAutomationEngine()
    
    events = [
        IncidentEvent(
            event_id="PHISH-001",
            timestamp=datetime.now(),
            source="email_security",
            event_type="phish_detected",
            description="Phishing email detected: fake login page credential harvest",
            ip_address="203.0.113.50",
            user_identifier="user@company.com"
        )
    ]
    
    result = engine.process_incident(events)
    
    print(f"✓ Incident Type: {result.incident_type.value}")
    print(f"✓ Severity: {result.severity.value}")
    print(f"✓ Affected Users: {result.affected_users}")
    
    assert result.incident_type == IncidentType.PHISHING
    print("✓ Phishing classification correct!")
    return True


def test_prompt_injection_incident():
    """Test prompt injection incident for AI security"""
    print("\n" + "=" * 60)
    print("TEST 3: Prompt Injection Incident (AI Security)")
    print("=" * 60)
    
    engine = IncidentResponseAutomationEngine()
    
    events = [
        IncidentEvent(
            event_id="AI-001",
            timestamp=datetime.now(),
            source="llm_guardrails",
            event_type="prompt_injection_attempt",
            description="Ignore previous instructions - DAN prompt injection detected",
            asset_identifier="LLM-PROD-01"
        ),
        IncidentEvent(
            event_id="AI-002",
            timestamp=datetime.now(),
            source="llm_guardrails",
            event_type="jailbreak_attempt",
            description="Role play attempt: Now you are unrestricted AI assistant",
            asset_identifier="LLM-PROD-01"
        )
    ]
    
    result = engine.process_incident(events)
    
    print(f"✓ Incident Type: {result.incident_type.value}")
    print(f"✓ Severity: {result.severity.value}")
    print(f"✓ MITRE Mappings: {[(m.tactic.value, m.technique.value) for m in result.mitre_mappings]}")
    
    assert result.incident_type in [IncidentType.PROMPT_INJECTION, IncidentType.JAILBREAK_ATTEMPT]
    print("✓ AI security incident classification correct!")
    return True


def test_mitre_attack_mapping():
    """Test MITRE ATT&CK mapping functionality"""
    print("\n" + "=" * 60)
    print("TEST 4: MITRE ATT&CK Framework Mapping")
    print("=" * 60)
    
    engine = IncidentResponseAutomationEngine()
    
    events = [
        IncidentEvent(
            event_id="BRUTE-001",
            timestamp=datetime.now(),
            source="auth_log",
            event_type="brute_force_attack",
            description="Multiple failed login attempts - brute force password attack",
            ip_address="198.51.100.25"
        )
    ]
    
    result = engine.process_incident(events)
    
    for mapping in result.mitre_mappings:
        print(f"  ✓ Tactic: {mapping.tactic.value:25} Technique: {mapping.technique.value:30} Confidence: {mapping.confidence_score:.0%}")
    
    assert len(result.mitre_mappings) > 0
    print("✓ MITRE ATT&CK mapping working correctly!")
    return True


def test_response_playbook_generation():
    """Test automated response playbook generation"""
    print("\n" + "=" * 60)
    print("TEST 5: Response Playbook Generation")
    print("=" * 60)
    
    engine = IncidentResponseAutomationEngine()
    
    events = [
        IncidentEvent(
            event_id="DATA-001",
            timestamp=datetime.now(),
            source="dlp",
            event_type="data_exfiltration",
            description="Suspicious data exfiltration to external cloud storage",
            ip_address="198.51.100.100"
        )
    ]
    
    result = engine.process_incident(events)
    
    print(f"✓ Response Actions Generated: {len(result.response_actions)}")
    for action in sorted(result.response_actions, key=lambda a: a.priority)[:5]:
        print(f"  [{action.priority:2d}] {action.action_type.value:30} -> {action.target or 'N/A'}")
    
    print(f"\n✓ Recommendations: {len(result.recommendations)}")
    for rec in result.recommendations[:3]:
        print(f"  - {rec}")
    
    assert len(result.response_actions) > 0
    assert len(result.recommendations) > 0
    assert "PHASE 1" in result.response_playbook
    print("✓ Response playbook generation complete!")
    return True


def test_json_export():
    """Test JSON export functionality"""
    print("\n" + "=" * 60)
    print("TEST 6: JSON Export Functionality")
    print("=" * 60)
    
    engine = IncidentResponseAutomationEngine()
    
    events = [
        IncidentEvent(
            event_id="EXPORT-001",
            timestamp=datetime.now(),
            source="test",
            event_type="malware_detected",
            description="Test malware detection event"
        )
    ]
    
    result = engine.process_incident(events)
    json_output = engine.export_result_json(result)
    
    # Validate JSON
    data = json.loads(json_output)
    assert "incident_id" in data
    assert "severity" in data
    assert "mitre_mappings" in data
    
    print(f"✓ JSON Export Valid")
    print(f"  Incident ID: {data['incident_id']}")
    print(f"  Severity Score: {data['severity_score']}")
    print(f"  Processing Time: {data['processing_time_ms']}ms")
    
    print("✓ JSON export working correctly!")
    return True


def test_incident_statistics():
    """Test incident statistics tracking"""
    print("\n" + "=" * 60)
    print("TEST 7: Incident Statistics Tracking")
    print("=" * 60)
    
    engine = IncidentResponseAutomationEngine()
    
    # Process multiple incidents
    for i in range(3):
        events = [
            IncidentEvent(
                event_id=f"STAT-{i}",
                timestamp=datetime.now(),
                source="test",
                event_type="malware",
                description=f"Test malware event {i}"
            )
        ]
        engine.process_incident(events)
    
    stats = engine.get_incident_statistics()
    
    print(f"✓ Total Incidents: {stats['total_incidents']}")
    print(f"✓ Severity Distribution: {stats.get('severity_distribution', {})}")
    print(f"✓ Avg Processing Time: {stats.get('average_processing_time_ms', 0)}ms")
    
    assert stats["total_incidents"] == 3
    print("✓ Statistics tracking working correctly!")
    return True


def test_timeline_generation():
    """Test incident timeline generation"""
    print("\n" + "=" * 60)
    print("TEST 8: Incident Timeline Generation")
    print("=" * 60)
    
    engine = IncidentResponseAutomationEngine()
    
    events = [
        IncidentEvent(
            event_id="TL-001",
            timestamp=datetime.now() - timedelta(hours=2),
            source="ids",
            event_type="initial_scan",
            description="Initial network scan detected"
        ),
        IncidentEvent(
            event_id="TL-002",
            timestamp=datetime.now() - timedelta(hours=1),
            source="auth",
            event_type="login_attempt",
            description="Login attempt from scanned IP"
        ),
        IncidentEvent(
            event_id="TL-003",
            timestamp=datetime.now(),
            source="edr",
            event_type="execution",
            description="Malicious code execution detected"
        )
    ]
    
    result = engine.process_incident(events)
    
    print("✓ Generated Timeline:")
    print(result.timeline_summary)
    
    assert "Duration" in result.timeline_summary
    assert "Total Events: 3" in result.timeline_summary
    print("✓ Timeline generation working correctly!")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("\n" + "=" * 60)
    print("INCIDENT RESPONSE AUTOMATION ENGINE - TEST SUITE")
    print("June 20, 2026 - Production Grade")
    print("=" * 60 + "\n")
    
    tests = [
        test_basic_incident_processing,
        test_phishing_incident,
        test_prompt_injection_incident,
        test_mitre_attack_mapping,
        test_response_playbook_generation,
        test_json_export,
        test_incident_statistics,
        test_timeline_generation
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append((test.__name__, result, None))
        except Exception as e:
            results.append((test.__name__, False, str(e)))
            print(f"✗ FAILED: {test.__name__}: {e}")
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, r, _ in results if r)
    total = len(results)
    
    for name, result, error in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status} {name}")
        if error:
            print(f"    Error: {error}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    # Save test results
    test_results = {
        "test_date": datetime.now().isoformat(),
        "module": "threat_intelligence_incident_response_automation_engine",
        "tests_passed": passed,
        "tests_total": total,
        "success_rate": passed / total if total > 0 else 0,
        "results": [{"name": n, "passed": r, "error": e} for n, r, e in results]
    }
    
    with open("test_results_incident_response_automation_engine.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nTest results saved to test_results_incident_response_automation_engine.json")
    
    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
