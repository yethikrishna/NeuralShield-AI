#!/usr/bin/env python3
"""
Test Suite for NeuralShield-AI Threat Intelligence Port Scanner Engine
June 2026 - Production-grade testing
"""

import sys
import os
import json
import time

# Add the neural_shield directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_port_scanner_engine_2026_june import (
    ThreatIntelligencePortScanner,
    PortStatus,
    Protocol,
    COMMON_PORTS,
    TOP_100_PORTS,
    run_port_scanner_demo
)


def test_port_scanner_initialization():
    """Test scanner initialization with various parameters."""
    print("[TEST 1] Testing Port Scanner Initialization...")
    
    scanner = ThreatIntelligencePortScanner(
        timeout_seconds=1.5,
        max_threads=30,
        delay_ms=10,
        grab_banners=True
    )
    
    assert scanner.timeout == 1.5
    assert scanner.max_threads == 30
    assert scanner.delay_ms == 10
    assert scanner.grab_banners == True
    print("  ✓ Initialization successful")
    return True


def test_host_resolution():
    """Test hostname to IP resolution."""
    print("[TEST 2] Testing Host Resolution...")
    
    scanner = ThreatIntelligencePortScanner()
    ip = scanner._resolve_host("localhost")
    
    # Should resolve to 127.0.0.1 or ::1
    assert ip in ["127.0.0.1", "::1"] or ip.startswith("127.")
    print(f"  ✓ localhost resolved to {ip}")
    return True


def test_single_port_scan():
    """Test scanning a single port."""
    print("[TEST 3] Testing Single Port Scan...")
    
    scanner = ThreatIntelligencePortScanner(timeout_seconds=0.5)
    result = scanner._scan_single_port("127.0.0.1", 65535)  # High port, likely closed
    
    assert result.port == 65535
    assert result.host == "127.0.0.1"
    assert result.protocol == Protocol.TCP
    assert result.status in [PortStatus.CLOSED, PortStatus.FILTERED]
    assert result.response_time_ms >= 0
    
    print(f"  ✓ Port 65535: {result.status.value}")
    print(f"  ✓ Response time: {result.response_time_ms}ms")
    return True


def test_localhost_scan():
    """Test scanning localhost."""
    print("[TEST 4] Testing Localhost Scan...")
    
    scanner = ThreatIntelligencePortScanner(timeout_seconds=0.5, max_threads=10)
    result = scanner.scan_host("127.0.0.1", ports=[22, 80, 443, 8080])
    
    assert result.host == "127.0.0.1"
    assert result.ip_address == "127.0.0.1"
    assert result.total_ports_scanned == 4
    assert result.scan_duration_seconds >= 0
    
    print(f"  ✓ Scanned {result.total_ports_scanned} ports")
    print(f"  ✓ Open ports: {result.open_ports}")
    print(f"  ✓ Duration: {result.scan_duration_seconds}s")
    return True


def test_json_export():
    """Test JSON export functionality."""
    print("[TEST 5] Testing JSON Export...")
    
    scanner = ThreatIntelligencePortScanner(timeout_seconds=0.3)
    result = scanner.scan_host("127.0.0.1", ports=[80, 443])
    
    json_output = scanner.export_results_json(result)
    data = json.loads(json_output)
    
    assert "scan_summary" in data
    assert "detailed_results" in data
    assert data["scan_summary"]["host"] == "127.0.0.1"
    assert len(data["detailed_results"]) == 2
    
    print("  ✓ JSON export successful")
    print(f"  ✓ Contains scan_summary and detailed_results")
    return True


def test_threat_intel_report():
    """Test threat intelligence report generation."""
    print("[TEST 6] Testing Threat Intelligence Report...")
    
    scanner = ThreatIntelligencePortScanner(timeout_seconds=0.3)
    result = scanner.scan_host("127.0.0.1", ports=[21, 22, 23, 80, 443, 3389])
    
    report = scanner.generate_threat_intel_report(result)
    
    assert "target" in report
    assert "attack_surface_score" in report
    assert "open_ports_count" in report
    assert "risky_services_exposed" in report
    assert "recommendations" in report
    assert 0 <= report["attack_surface_score"] <= 100
    
    print(f"  ✓ Attack Surface Score: {report['attack_surface_score']}/100")
    print(f"  ✓ Report contains all required fields")
    return True


def test_port_lists():
    """Test port list constants."""
    print("[TEST 7] Testing Port List Constants...")
    
    assert len(COMMON_PORTS) > 20
    assert len(TOP_100_PORTS) >= 90  # Allow for slight variations
    assert 80 in COMMON_PORTS
    assert COMMON_PORTS[80] == "HTTP"
    assert 443 in COMMON_PORTS
    assert COMMON_PORTS[443] == "HTTPS"
    
    print(f"  ✓ {len(COMMON_PORTS)} common ports defined")
    print(f"  ✓ {len(TOP_100_PORTS)} top ports defined")
    return True


def test_enum_values():
    """Test enum values are correct."""
    print("[TEST 8] Testing Enum Values...")
    
    assert PortStatus.OPEN.value == "open"
    assert PortStatus.CLOSED.value == "closed"
    assert PortStatus.FILTERED.value == "filtered"
    assert Protocol.TCP.value == "tcp"
    assert Protocol.UDP.value == "udp"
    
    print("  ✓ All enum values correct")
    return True


def run_all_tests():
    """Run all test cases and generate report."""
    print("=" * 70)
    print("NeuralShield-AI Threat Intelligence Port Scanner - Test Suite")
    print("=" * 70)
    print(f"Test Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    tests = [
        test_port_scanner_initialization,
        test_host_resolution,
        test_single_port_scan,
        test_localhost_scan,
        test_json_export,
        test_threat_intel_report,
        test_port_lists,
        test_enum_values,
    ]
    
    passed = 0
    failed = 0
    failures = []
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
                failures.append(test.__name__)
        except Exception as e:
            failed += 1
            failures.append(f"{test.__name__}: {str(e)}")
            print(f"  ✗ FAILED: {e}")
    
    print()
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Total Tests: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success Rate: {(passed/len(tests)*100):.1f}%")
    
    if failures:
        print("\nFailed Tests:")
        for f in failures:
            print(f"  - {f}")
    
    print()
    
    # Run demo
    print("=" * 70)
    print("RUNNING DEMO SCAN")
    print("=" * 70)
    try:
        run_port_scanner_demo()
    except Exception as e:
        print(f"Demo completed with: {e}")
    
    # Save test results
    results = {
        "test_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": f"{(passed/len(tests)*100):.1f}%",
        "failures": failures,
        "module": "threat_intelligence_port_scanner_engine_2026_june"
    }
    
    with open("test_results_port_scanner.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print()
    print(f"Results saved to test_results_port_scanner.json")
    
    return passed == len(tests)


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
