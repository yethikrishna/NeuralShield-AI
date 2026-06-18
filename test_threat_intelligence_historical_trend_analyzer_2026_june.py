#!/usr/bin/env python3
"""
Test suite for NeuralShield-AI Threat Intelligence Historical Trend Analyzer
June 2026 - Production Grade Tests
Tests all real functionality of the HistoricalTrendAnalyzer
"""
import sys
import time
import json
from datetime import datetime, timedelta

# Add neural_shield to path
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_historical_trend_analyzer_2026_june import (
    HistoricalTrendAnalyzer,
    ThreatDataPoint,
    TrendDirection,
    AnomalySeverity
)


def generate_test_data(num_points: int = 100) -> list:
    """Generate realistic test data with patterns and anomalies"""
    base_time = time.time() - (num_points * 3600)  # 1 hour intervals
    points = []
    
    for i in range(num_points):
        timestamp = base_time + (i * 3600)
        
        # Base threat count with upward trend
        base_count = 10 + (i * 0.2)
        
        # Add some noise
        import random
        noise = random.randint(-3, 5)
        
        # Add a deliberate spike at point 50 for anomaly testing
        if i == 50:
            threat_count = int(base_count + 30)  # Big spike
        elif i == 75:
            threat_count = int(base_count + 20)  # Medium spike
        else:
            threat_count = max(1, int(base_count + noise))
        
        severity = 0.3 + (i * 0.005) + (random.random() * 0.2)
        unique_types = random.randint(2, 8)
        source_ips = random.randint(1, 15)
        
        points.append(ThreatDataPoint(
            timestamp=timestamp,
            threat_count=threat_count,
            threat_severity_avg=min(1.0, severity),
            unique_threat_types=unique_types,
            source_ip_count=source_ips,
            metadata={"hour": i, "source": "test_generator"}
        ))
    
    return points


def test_basic_initialization():
    """Test basic analyzer initialization"""
    print("=" * 60)
    print("TEST 1: Basic Initialization")
    print("=" * 60)
    
    analyzer = HistoricalTrendAnalyzer(
        max_data_points=5000,
        anomaly_sensitivity=2.5,
        moving_average_window=5
    )
    
    assert len(analyzer) == 0, "Analyzer should start empty"
    print("✓ Analyzer initialized correctly")
    print("✓ Empty state verified")
    return True


def test_add_data_points():
    """Test adding data points individually and in batch"""
    print("\n" + "=" * 60)
    print("TEST 2: Adding Data Points")
    print("=" * 60)
    
    analyzer = HistoricalTrendAnalyzer()
    test_points = generate_test_data(20)
    
    # Test individual adds
    for point in test_points[:10]:
        analyzer.add_data_point(point)
    
    assert len(analyzer) == 10, f"Expected 10 points, got {len(analyzer)}"
    print(f"✓ Added 10 individual points, total: {len(analyzer)}")
    
    # Test batch add
    analyzer.add_data_points_batch(test_points[10:])
    assert len(analyzer) == 20, f"Expected 20 points, got {len(analyzer)}"
    print(f"✓ Added 10 points in batch, total: {len(analyzer)}")
    
    return True


def test_moving_averages():
    """Test SMA and EMA calculations"""
    print("\n" + "=" * 60)
    print("TEST 3: Moving Averages (SMA & EMA)")
    print("=" * 60)
    
    analyzer = HistoricalTrendAnalyzer(moving_average_window=5)
    test_points = generate_test_data(50)
    analyzer.add_data_points_batch(test_points)
    
    sma = analyzer.calculate_sma(field="threat_count", window=7)
    print(f"✓ SMA calculated: {len(sma)} values")
    print(f"  First 5 SMA values: {[round(v, 2) for v in sma[:5]]}")
    
    ema = analyzer.calculate_ema(field="threat_count", window=7)
    print(f"✓ EMA calculated: {len(ema)} values")
    print(f"  First 5 EMA values: {[round(v, 2) for v in ema[:5]]}")
    
    assert len(sma) > 0, "SMA should return values with enough data"
    assert len(ema) > 0, "EMA should return values with enough data"
    assert len(sma) == 50 - 7 + 1, "SMA length should be n - window + 1"
    
    return True


def test_trend_detection():
    """Test trend detection functionality"""
    print("\n" + "=" * 60)
    print("TEST 4: Trend Detection")
    print("=" * 60)
    
    analyzer = HistoricalTrendAnalyzer()
    test_points = generate_test_data(60)
    analyzer.add_data_points_batch(test_points)
    
    trend = analyzer.detect_trend(field="threat_count", lookback=30)
    
    print(f"✓ Trend detected: {trend.trend_direction.value}")
    print(f"  Slope: {trend.trend_slope:.6f}")
    print(f"  Avg threat count: {trend.avg_threat_count:.2f}")
    print(f"  Volatility score: {trend.volatility_score:.4f}")
    print(f"  Peak threat count: {trend.peak_threat_count}")
    print(f"  Data points analyzed: {trend.data_points_count}")
    
    # Since we have an upward trend in test data
    assert trend.trend_direction in [TrendDirection.INCREASING, TrendDirection.VOLATILE], \
        f"Expected increasing/volatile trend, got {trend.trend_direction}"
    assert trend.data_points_count == 30, "Should analyze 30 points"
    
    trend_dict = trend.to_dict()
    assert "trend_direction" in trend_dict
    assert "trend_slope" in trend_dict
    print("✓ Trend result serialization verified")
    
    return True


def test_anomaly_detection():
    """Test anomaly detection with statistical methods"""
    print("\n" + "=" * 60)
    print("TEST 5: Anomaly Detection")
    print("=" * 60)
    
    analyzer = HistoricalTrendAnalyzer(anomaly_sensitivity=2.0)
    test_points = generate_test_data(100)  # Contains spikes at 50 and 75
    analyzer.add_data_points_batch(test_points)
    
    anomalies = analyzer.detect_anomalies(field="threat_count")
    print(f"✓ Full anomaly detection complete: {len(anomalies)} anomalies found")
    
    # Check realtime anomalies
    realtime_anomalies = analyzer.get_anomalies()
    print(f"✓ Realtime anomalies detected: {len(realtime_anomalies)}")
    
    if anomalies:
        for a in anomalies[:3]:
            print(f"  - {a.anomaly_type}: {a.severity.value}, deviation: {a.deviation_percent:.1f}%")
    
    # Verify anomaly structure
    for anomaly in anomalies:
        assert hasattr(anomaly, 'timestamp')
        assert hasattr(anomaly, 'severity')
        assert hasattr(anomaly, 'deviation_percent')
        a_dict = anomaly.to_dict()
        assert "severity" in a_dict
        assert "deviation_percent" in a_dict
    
    print("✓ Anomaly structure and serialization verified")
    return True


def test_forecasting():
    """Test linear forecasting functionality"""
    print("\n" + "=" * 60)
    print("TEST 6: Forecasting")
    print("=" * 60)
    
    analyzer = HistoricalTrendAnalyzer(enable_forecasting=True)
    test_points = generate_test_data(50)
    analyzer.add_data_points_batch(test_points)
    
    forecasts = analyzer.forecast(field="threat_count", steps=5)
    
    print(f"✓ Forecast generated: {len(forecasts)} steps ahead")
    
    for fc in forecasts:
        print(f"  Step {fc['step']}: {fc['forecast_value']} "
              f"[{fc['lower_bound']} - {fc['upper_bound']}] "
              f"@ {fc['forecast_datetime']}")
    
    assert len(forecasts) == 5, "Should forecast 5 steps"
    for fc in forecasts:
        assert "forecast_value" in fc
        assert "lower_bound" in fc
        assert "upper_bound" in fc
        assert fc["forecast_value"] >= 0, "Forecast can't be negative"
        assert fc["lower_bound"] <= fc["forecast_value"] <= fc["upper_bound"]
    
    print("✓ Forecast structure and bounds verified")
    return True


def test_time_window_aggregation():
    """Test time window aggregation"""
    print("\n" + "=" * 60)
    print("TEST 7: Time Window Aggregation")
    print("=" * 60)
    
    analyzer = HistoricalTrendAnalyzer()
    test_points = generate_test_data(48)  # 48 hours
    analyzer.add_data_points_batch(test_points)
    
    # Aggregate by 6-hour windows
    aggregated = analyzer.aggregate_by_time_window(window_seconds=6 * 3600)
    
    print(f"✓ Time aggregation complete: {len(aggregated)} windows")
    
    for window in aggregated[:3]:
        print(f"  Window {window['window_start_iso']}: "
              f"{window['points_in_window']} points, "
              f"{window['total_threats']} total threats")
    
    assert len(aggregated) > 0, "Should have aggregated windows"
    for window in aggregated:
        assert "points_in_window" in window
        assert "total_threats" in window
        assert "avg_threats_per_point" in window
        assert window["points_in_window"] > 0
    
    print("✓ Aggregation structure verified")
    return True


def test_summary_report():
    """Test comprehensive summary generation"""
    print("\n" + "=" * 60)
    print("TEST 8: Summary Report")
    print("=" * 60)
    
    analyzer = HistoricalTrendAnalyzer()
    test_points = generate_test_data(100)
    analyzer.add_data_points_batch(test_points)
    
    summary = analyzer.get_summary()
    
    print("✓ Summary generated:")
    print(f"  Total data points: {summary['total_data_points']}")
    print(f"  Time coverage: {summary['time_coverage']['duration_hours']} hours")
    print(f"  Total threats: {summary['threat_statistics']['total_threats']}")
    print(f"  Avg threats/point: {summary['threat_statistics']['avg_threats_per_point']}")
    print(f"  Current trend: {summary['current_trend']['trend_direction']}")
    print(f"  Total anomalies: {summary['total_anomalies_detected']}")
    
    assert "total_data_points" in summary
    assert "time_coverage" in summary
    assert "threat_statistics" in summary
    assert "current_trend" in summary
    assert "anomalies_by_severity" in summary
    
    print("✓ Summary structure verified")
    return True


def test_empty_edge_cases():
    """Test edge cases with empty or minimal data"""
    print("\n" + "=" * 60)
    print("TEST 9: Edge Cases (Empty/Minimal Data)")
    print("=" * 60)
    
    analyzer = HistoricalTrendAnalyzer()
    
    # Empty analyzer
    summary = analyzer.get_summary()
    assert summary["status"] == "no_data", "Empty analyzer should return no_data status"
    print("✓ Empty analyzer handled correctly")
    
    sma = analyzer.calculate_sma()
    assert sma == [], "SMA on empty should return empty list"
    print("✓ SMA on empty handled correctly")
    
    anomalies = analyzer.detect_anomalies()
    assert anomalies == [], "Anomaly detection on empty should return empty"
    print("✓ Anomaly detection on empty handled correctly")
    
    forecasts = analyzer.forecast()
    assert forecasts == [], "Forecast on empty should return empty"
    print("✓ Forecasting on minimal data handled correctly")
    
    # Add just 2 points
    analyzer.add_data_points_batch(generate_test_data(2))
    trend = analyzer.detect_trend()
    assert trend.trend_direction == TrendDirection.UNKNOWN, "Minimal data should return UNKNOWN trend"
    print("✓ Minimal data trend detection handled correctly")
    
    return True


def test_serialization():
    """Test that all objects serialize to JSON correctly"""
    print("\n" + "=" * 60)
    print("TEST 10: JSON Serialization")
    print("=" * 60)
    
    analyzer = HistoricalTrendAnalyzer()
    test_points = generate_test_data(50)
    analyzer.add_data_points_batch(test_points)
    
    # Test ThreatDataPoint serialization
    point_dict = test_points[0].to_dict()
    json.dumps(point_dict)  # Should not raise
    print("✓ ThreatDataPoint JSON serialization")
    
    # Test TrendAnalysisResult serialization
    trend = analyzer.detect_trend()
    trend_dict = trend.to_dict()
    json.dumps(trend_dict)
    print("✓ TrendAnalysisResult JSON serialization")
    
    # Test DetectedAnomaly serialization
    anomalies = analyzer.detect_anomalies()
    if anomalies:
        a_dict = anomalies[0].to_dict()
        json.dumps(a_dict)
        print("✓ DetectedAnomaly JSON serialization")
    
    # Test full summary
    summary = analyzer.get_summary()
    json.dumps(summary, indent=2)
    print("✓ Full summary JSON serialization")
    
    print("✓ All objects serialize to JSON correctly")
    return True


def run_all_tests():
    """Run all tests and report results"""
    print("\n" + "=" * 60)
    print("NeuralShield-AI: Historical Trend Analyzer - Test Suite")
    print("June 2026 - Production Grade")
    print("=" * 60 + "\n")
    
    tests = [
        test_basic_initialization,
        test_add_data_points,
        test_moving_averages,
        test_trend_detection,
        test_anomaly_detection,
        test_forecasting,
        test_time_window_aggregation,
        test_summary_report,
        test_empty_edge_cases,
        test_serialization
    ]
    
    passed = 0
    failed = 0
    failures = []
    
    for test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
                failures.append(test_func.__name__)
        except Exception as e:
            failed += 1
            failures.append(f"{test_func.__name__}: {str(e)}")
            print(f"\n✗ EXCEPTION in {test_func.__name__}: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Passed: {passed}/{len(tests)}")
    print(f"Failed: {failed}")
    
    if failures:
        print("\nFailed tests:")
        for f in failures:
            print(f"  - {f}")
    else:
        print("\n✓ ALL TESTS PASSED! Feature is fully functional.")
    
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
