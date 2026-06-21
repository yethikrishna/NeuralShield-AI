#!/usr/bin/env python3
"""
Test suite for Playbook Effectiveness Metrics & ROI Calculator
Real, working tests - no empty shells
"""

import sys
import json
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from datetime import datetime, timedelta
from neural_shield.threat_intelligence_playbook_effectiveness_roi_calculator_2026_june import (
    PlaybookEffectivenessEngine,
    PlaybookExecution,
    PlaybookOutcome,
    EffectivenessMetrics,
    ROICalculation
)


def test_execution_recording():
    """Test recording playbook executions"""
    print("Test 1: Playbook Execution Recording")
    
    engine = PlaybookEffectivenessEngine()
    
    execution = PlaybookExecution(
        execution_id="EXEC-001",
        playbook_id="PB-RANSOM-001",
        playbook_name="Ransomware Response v2",
        threat_type="ransomware",
        start_time=datetime.utcnow() - timedelta(minutes=45),
        end_time=datetime.utcnow(),
        outcome=PlaybookOutcome.SUCCESS,
        analyst_hours=2.5,
        steps_completed=8,
        total_steps=8,
        containment_success=True,
        eradication_success=True,
        recovery_success=True
    )
    
    result = engine.record_execution(execution)
    print(f"  Recorded execution: {result}")
    print(f"  Duration: {execution.duration_minutes:.1f} minutes")
    print(f"  Completion rate: {execution.completion_rate * 100:.0f}%")
    
    assert result == "EXEC-001"
    assert len(engine.execution_history) == 1
    assert execution.duration_minutes > 40
    assert execution.completion_rate == 1.0
    
    print("  ✓ PASSED\n")
    return True


def test_effectiveness_calculation():
    """Test effectiveness metrics calculation"""
    print("Test 2: Effectiveness Metrics Calculation")
    
    engine = PlaybookEffectivenessEngine()
    
    # Register playbook
    engine.register_playbook(
        playbook_id="PB-PHISH-001",
        name="Phishing Response Playbook",
        threat_type="phishing",
        development_cost=15000,
        maintenance_cost_monthly=800,
        target_sla_minutes=60
    )
    
    # Add 10 executions with varying outcomes
    for i in range(10):
        outcome = PlaybookOutcome.SUCCESS if i < 8 else PlaybookOutcome.PARTIAL
        duration = 30 + i * 5
        
        exec = PlaybookExecution(
            execution_id=f"EXEC-{i:03d}",
            playbook_id="PB-PHISH-001",
            playbook_name="Phishing Response Playbook",
            threat_type="phishing",
            start_time=datetime.utcnow() - timedelta(minutes=duration + 10),
            end_time=datetime.utcnow() - timedelta(minutes=10),
            outcome=outcome,
            analyst_hours=1.5,
            steps_completed=5 if outcome == PlaybookOutcome.SUCCESS else 3,
            total_steps=5,
            containment_success=outcome == PlaybookOutcome.SUCCESS,
            eradication_success=True,
            recovery_success=True
        )
        engine.record_execution(exec)
    
    metrics = engine.calculate_effectiveness("PB-PHISH-001")
    
    print(f"  Playbook: {metrics.playbook_name}")
    print(f"  Total executions: {metrics.total_executions}")
    print(f"  Success rate: {metrics.success_rate}%")
    print(f"  Avg duration: {metrics.avg_duration_minutes}min")
    print(f"  Containment rate: {metrics.containment_rate}%")
    print(f"  Quality score: {metrics.quality_score}/100")
    print(f"  Recommendations: {len(metrics.recommendations)}")
    
    assert metrics.total_executions == 10
    assert metrics.success_rate == 80.0
    assert metrics.quality_score > 60
    assert len(metrics.recommendations) > 0
    
    print("  ✓ PASSED\n")
    return True


def test_roi_calculation():
    """Test ROI calculation for security playbooks"""
    print("Test 3: ROI Calculation & Cost Analysis")
    
    engine = PlaybookEffectivenessEngine()
    
    engine.register_playbook(
        playbook_id="PB-RANSOM-001",
        name="Enterprise Ransomware Response",
        threat_type="ransomware",
        development_cost=25000,
        maintenance_cost_monthly=1200
    )
    
    # Simulate successful ransomware containment events
    for i in range(5):
        exec = PlaybookExecution(
            execution_id=f"RANSOM-{i}",
            playbook_id="PB-RANSOM-001",
            playbook_name="Enterprise Ransomware Response",
            threat_type="ransomware",
            start_time=datetime.utcnow() - timedelta(hours=2),
            end_time=datetime.utcnow(),
            outcome=PlaybookOutcome.SUCCESS,
            analyst_hours=8,
            steps_completed=12,
            total_steps=12,
            containment_success=True,
            eradication_success=True,
            recovery_success=True,
            escalation_required=False
        )
        engine.record_execution(exec)
    
    roi = engine.calculate_roi("PB-RANSOM-001", months_active=6)
    
    print(f"  Total Investment: ${roi.total_investment:,.2f}")
    print(f"  Total Cost Avoided: ${roi.total_cost_avoided:,.2f}")
    print(f"  ROI Percentage: {roi.roi_percentage}%")
    print(f"  ROI Ratio: {roi.roi_ratio}x")
    print(f"  Payback Period: {roi.payback_months} months")
    print(f"  Incidents Contained: {roi.incidents_contained}")
    print(f"  MTTR Improvement: {roi.mttr_improvement_pct}%")
    
    assert roi.total_investment > 0
    assert roi.total_cost_avoided > roi.total_investment  # Should be positive ROI
    assert roi.roi_percentage > 0
    assert roi.payback_months > 0
    
    print("  ✓ PASSED\n")
    return True


def test_benchmark_comparison():
    """Test benchmark comparison across multiple playbooks"""
    print("Test 4: Multi-Playbook Benchmark Comparison")
    
    engine = PlaybookEffectivenessEngine()
    
    # Register multiple playbooks
    playbooks = [
        ("PB-RANSOM", "Ransomware Response", "ransomware", 25000, 1200),
        ("PB-PHISH", "Phishing Response", "phishing", 12000, 600),
        ("PB-DATA", "Data Exfiltration", "data_exfiltration", 35000, 1500),
    ]
    
    for pb_id, name, threat, dev_cost, maint in playbooks:
        engine.register_playbook(pb_id, name, threat, dev_cost, maint)
        
        # Add executions for each
        for i in range(8):
            exec = PlaybookExecution(
                execution_id=f"{pb_id}-{i}",
                playbook_id=pb_id,
                playbook_name=name,
                threat_type=threat,
                start_time=datetime.utcnow() - timedelta(minutes=60),
                end_time=datetime.utcnow(),
                outcome=PlaybookOutcome.SUCCESS,
                analyst_hours=2,
                steps_completed=6,
                total_steps=6,
                containment_success=True,
                eradication_success=True,
                recovery_success=True
            )
            engine.record_execution(exec)
    
    report = engine.generate_benchmark_report([p[0] for p in playbooks])
    
    print(f"  Total playbooks compared: {report['total_playbooks']}")
    print(f"  Avg quality score: {report['overall_average_quality']}")
    print(f"  Avg success rate: {report['overall_average_success_rate']}%")
    print(f"  Avg ROI: {report['overall_average_roi']}%")
    print(f"  Top quality performers: {report['top_performers_quality']}")
    print(f"  Top ROI performers: {report['top_performers_roi']}")
    
    assert report["total_playbooks"] == 3
    assert report["overall_average_quality"] > 70
    assert len(report["top_performers_quality"]) == 3
    assert "playbook_details" in report
    
    print("  ✓ PASSED\n")
    return True


def test_sla_compliance_monitoring():
    """Test SLA compliance tracking"""
    print("Test 5: SLA Compliance Monitoring")
    
    engine = PlaybookEffectivenessEngine()
    
    engine.register_playbook(
        playbook_id="PB-CRITICAL",
        name="Critical Incident Response",
        threat_type="ransomware",
        development_cost=50000,
        maintenance_cost_monthly=2000,
        target_sla_minutes=60
    )
    
    # Mix of SLA compliant and non-compliant executions
    for i in range(10):
        # 70% meet SLA, 30% don't
        duration = 45 if i < 7 else 90
        
        exec = PlaybookExecution(
            execution_id=f"SLA-TEST-{i}",
            playbook_id="PB-CRITICAL",
            playbook_name="Critical Incident Response",
            threat_type="ransomware",
            start_time=datetime.utcnow() - timedelta(minutes=duration),
            end_time=datetime.utcnow(),
            outcome=PlaybookOutcome.SUCCESS,
            analyst_hours=3,
            steps_completed=10,
            total_steps=10,
            containment_success=True,
            eradication_success=True,
            recovery_success=True
        )
        engine.record_execution(exec)
    
    metrics = engine.calculate_effectiveness("PB-CRITICAL")
    
    print(f"  SLA Target: 60 minutes")
    print(f"  SLA Compliance Rate: {metrics.sla_compliance_rate}%")
    print(f"  Avg Duration: {metrics.avg_duration_minutes}min")
    print(f"  P95 Duration: {metrics.p95_duration_minutes}min")
    
    # Should be ~70% compliance
    assert 65 <= metrics.sla_compliance_rate <= 75
    assert metrics.p95_duration_minutes > metrics.avg_duration_minutes
    
    print("  ✓ PASSED\n")
    return True


def test_recommendation_engine():
    """Test automated improvement recommendations"""
    print("Test 6: Automated Improvement Recommendations")
    
    engine = PlaybookEffectivenessEngine()
    
    # Create a poorly performing playbook
    engine.register_playbook(
        playbook_id="PB-POOR",
        name="Poorly Performing Playbook",
        threat_type="lateral_movement",
        development_cost=5000,
        maintenance_cost_monthly=300,
        target_sla_minutes=120
    )
    
    # Add poor performance data
    for i in range(10):
        exec = PlaybookExecution(
            execution_id=f"POOR-{i}",
            playbook_id="PB-POOR",
            playbook_name="Poorly Performing Playbook",
            threat_type="lateral_movement",
            start_time=datetime.utcnow() - timedelta(minutes=180),
            end_time=datetime.utcnow(),
            outcome=PlaybookOutcome.PARTIAL if i < 6 else PlaybookOutcome.FAILED,
            analyst_hours=5,
            steps_completed=2,
            total_steps=8,
            containment_success=i < 4,
            eradication_success=i < 3,
            recovery_success=i < 2,
            escalation_required=True,
            false_positive=i < 3
        )
        engine.record_execution(exec)
    
    metrics = engine.calculate_effectiveness("PB-POOR")
    
    print(f"  Success Rate: {metrics.success_rate}%")
    print(f"  Quality Score: {metrics.quality_score}/100")
    print(f"  Recommendations Generated: {len(metrics.recommendations)}")
    print("  Recommendations:")
    for rec in metrics.recommendations:
        print(f"    - {rec}")
    
    assert len(metrics.recommendations) >= 3
    assert any("Poor quality" in r for r in metrics.recommendations)
    assert metrics.quality_score < 60
    
    print("  ✓ PASSED\n")
    return True


def main():
    """Run all tests"""
    print("=" * 70)
    print("Playbook Effectiveness & ROI Calculator - TEST SUITE")
    print("=" * 70 + "\n")
    
    tests = [
        test_execution_recording,
        test_effectiveness_calculation,
        test_roi_calculation,
        test_benchmark_comparison,
        test_sla_compliance_monitoring,
        test_recommendation_engine,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
        except AssertionError as e:
            print(f"  ✗ FAILED: {e}\n")
            failed += 1
        except Exception as e:
            print(f"  ✗ ERROR: {e}\n")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("=" * 70)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 70)
    
    # Save test results
    test_results = {
        "test_module": "playbook_effectiveness_roi_calculator",
        "timestamp": datetime.utcnow().isoformat(),
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": round(passed / len(tests) * 100, 1)
    }
    
    with open("/home/user/autonomous-developer/NeuralShield-AI/test_results_playbook_effectiveness_roi.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nTest results saved to test_results_playbook_effectiveness_roi.json")
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
