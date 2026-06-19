#!/usr/bin/env python3
"""
Test Suite for Threat Intelligence Feed Health & Quality Monitor
June 19, 2026 - Production Grade Tests

Verifies all core functionality:
- Feed registration
- Poll result recording
- All scoring calculations (freshness, availability, quality, coverage, performance)
- Health assessment generation
- Summary dashboard
- Edge cases and error handling
"""
import json
import sys
from datetime import datetime, timedelta
import sys
sys.path.insert(0, 'neural_shield')
from threat_intelligence_feed_health_quality_monitor_2026_june import (
    ThreatFeedHealthMonitor,
    FeedHealthStatus,
    FeedQualityTier
)


def run_tests():
    """Execute all tests and return results."""
    test_results = {
        'tests_passed': 0,
        'tests_failed': 0,
        'test_details': [],
        'timestamp': datetime.now().isoformat()
    }

    monitor = ThreatFeedHealthMonitor()

    # Test 1: Feed Registration
    print("Test 1: Feed Registration")
    try:
        result1 = monitor.register_feed("AbuseIPDB", "https://api.abuseipdb.com/api/v2")
        result2 = monitor.register_feed("VirusTotal", "https://www.virustotal.com/api/v3")
        result3 = monitor.register_feed("AbuseIPDB", "https://api.abuseipdb.com/api/v2")  # Duplicate
        
        assert result1 == True, "First feed should register successfully"
        assert result2 == True, "Second feed should register successfully"
        assert result3 == False, "Duplicate feed registration should fail"
        assert len(monitor.feed_metrics_store) == 2, "Should have 2 feeds registered"
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'Feed Registration',
            'status': 'PASSED',
            'message': 'Successfully registered feeds and rejected duplicate'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'Feed Registration',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Test 2: Record Poll Result - Success
    print("\nTest 2: Record Poll Result - Success")
    try:
        sample_records = [
            {'ioc_type': 'ipv4', 'threat_category': 'botnet', 'value': '192.168.1.1', 'timestamp': datetime.now().isoformat()},
            {'ioc_type': 'domain', 'threat_category': 'phishing', 'value': 'evil.com', 'timestamp': datetime.now().isoformat()},
            {'ioc_type': 'sha256', 'threat_category': 'malware', 'value': 'abc123', 'timestamp': datetime.now().isoformat()},
            {'ioc_type': 'ipv4', 'threat_category': 'botnet', 'value': '192.168.1.1', 'timestamp': datetime.now().isoformat()},  # Duplicate
        ]
        
        result = monitor.record_poll_result(
            feed_name="AbuseIPDB",
            records=sample_records,
            latency_ms=450.5,
            success=True
        )
        
        assert result['success'] == True
        assert result['records_processed'] == 4
        assert result['duplicates_found'] == 1
        
        metrics = monitor.feed_metrics_store["AbuseIPDB"]
        assert metrics.total_records == 4
        assert metrics.duplicate_records == 1
        assert metrics.success_count == 1
        assert metrics.average_latency_ms == 450.5
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'Record Poll Result - Success',
            'status': 'PASSED',
            'message': 'Successfully recorded poll with duplicate detection'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'Record Poll Result - Success',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Test 3: Record Poll Result - Failure
    print("\nTest 3: Record Poll Result - Failure")
    try:
        result = monitor.record_poll_result(
            feed_name="AbuseIPDB",
            records=[],
            latency_ms=5000,
            success=False,
            error_message="Connection timeout"
        )
        
        assert result['success'] == False
        
        metrics = monitor.feed_metrics_store["AbuseIPDB"]
        assert metrics.error_count == 1
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'Record Poll Result - Failure',
            'status': 'PASSED',
            'message': 'Successfully recorded failure with error tracking'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'Record Poll Result - Failure',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Test 4: Freshness Score Calculation
    print("\nTest 4: Freshness Score Calculation")
    try:
        score, issues = monitor.calculate_freshness_score("AbuseIPDB")
        assert 0 <= score <= 100, "Score should be between 0 and 100"
        assert isinstance(issues, list), "Issues should be a list"
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'Freshness Score Calculation',
            'status': 'PASSED',
            'message': f'Score: {score:.1f}, Issues: {len(issues)}'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'Freshness Score Calculation',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Test 5: Availability Score Calculation
    print("\nTest 5: Availability Score Calculation")
    try:
        score, issues = monitor.calculate_availability_score("AbuseIPDB")
        assert 0 <= score <= 100, "Score should be between 0 and 100"
        assert isinstance(issues, list), "Issues should be a list"
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'Availability Score Calculation',
            'status': 'PASSED',
            'message': f'Score: {score:.1f}, Issues: {len(issues)}'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'Availability Score Calculation',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Test 6: Quality Score Calculation
    print("\nTest 6: Quality Score Calculation")
    try:
        score, issues = monitor.calculate_quality_score("AbuseIPDB")
        assert 0 <= score <= 100, "Score should be between 0 and 100"
        assert isinstance(issues, list), "Issues should be a list"
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'Quality Score Calculation',
            'status': 'PASSED',
            'message': f'Score: {score:.1f}, Issues: {len(issues)}'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'Quality Score Calculation',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Test 7: Coverage Score Calculation
    print("\nTest 7: Coverage Score Calculation")
    try:
        score, issues = monitor.calculate_coverage_score("AbuseIPDB")
        assert 0 <= score <= 100, "Score should be between 0 and 100"
        assert isinstance(issues, list), "Issues should be a list"
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'Coverage Score Calculation',
            'status': 'PASSED',
            'message': f'Score: {score:.1f}, Issues: {len(issues)}'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'Coverage Score Calculation',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Test 8: Performance Score Calculation
    print("\nTest 8: Performance Score Calculation")
    try:
        score, issues = monitor.calculate_performance_score("AbuseIPDB")
        assert 0 <= score <= 100, "Score should be between 0 and 100"
        assert isinstance(issues, list), "Issues should be a list"
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'Performance Score Calculation',
            'status': 'PASSED',
            'message': f'Score: {score:.1f}, Issues: {len(issues)}'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'Performance Score Calculation',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Test 9: Comprehensive Health Assessment
    print("\nTest 9: Comprehensive Health Assessment")
    try:
        assessment = monitor.assess_feed_health("AbuseIPDB")
        
        assert 0 <= assessment.overall_score <= 100
        assert isinstance(assessment.health_status, FeedHealthStatus)
        assert isinstance(assessment.quality_tier, FeedQualityTier)
        assert isinstance(assessment.recommendations, list)
        assert isinstance(assessment.assessment_timestamp, datetime)
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'Comprehensive Health Assessment',
            'status': 'PASSED',
            'message': f'Overall: {assessment.overall_score}, Status: {assessment.health_status.value}, Tier: {assessment.quality_tier.value}'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'Comprehensive Health Assessment',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Test 10: All Feeds Summary Dashboard
    print("\nTest 10: All Feeds Summary Dashboard")
    try:
        summary = monitor.get_all_feeds_summary()
        
        assert summary['total_feeds_monitored'] == 2
        assert 'health_status_distribution' in summary
        assert 'quality_tier_distribution' in summary
        assert 'average_overall_score' in summary
        assert 'feed_assessments' in summary
        assert len(summary['feed_assessments']) == 2
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'All Feeds Summary Dashboard',
            'status': 'PASSED',
            'message': f'Summary generated for {summary["total_feeds_monitored"]} feeds'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'All Feeds Summary Dashboard',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Test 11: Unregistered Feed Error Handling
    print("\nTest 11: Unregistered Feed Error Handling")
    try:
        try:
            monitor.record_poll_result("NonExistentFeed", [], 100, True)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "not registered" in str(e)
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'Unregistered Feed Error Handling',
            'status': 'PASSED',
            'message': 'Correctly raised ValueError for unregistered feed'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'Unregistered Feed Error Handling',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Test 12: Historical Data Storage
    print("\nTest 12: Historical Data Storage")
    try:
        # Add multiple poll results
        for i in range(5):
            monitor.record_poll_result(
                "VirusTotal",
                [{'ioc_type': 'ipv4', 'threat_category': 'malware', 'value': f'10.0.0.{i}'}],
                latency_ms=200 + i * 50,
                success=True
            )
        
        history = monitor.historical_data["VirusTotal"]
        assert len(history) >= 5, "Should have at least 5 historical records"
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'Historical Data Storage',
            'status': 'PASSED',
            'message': f'Stored {len(history)} historical data points'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'Historical Data Storage',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Print final summary
    print("\n" + "="*60)
    print(f"TEST SUMMARY: {test_results['tests_passed']} PASSED, {test_results['tests_failed']} FAILED")
    print("="*60)

    return test_results


if __name__ == "__main__":
    results = run_tests()
    
    # Save results to JSON
    with open('test_results_feed_health_quality_monitor.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to test_results_feed_health_quality_monitor.json")
    
    # Exit with appropriate code
    sys.exit(0 if results['tests_failed'] == 0 else 1)
