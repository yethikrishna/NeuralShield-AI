"""
Test Suite for Security Metrics & Analytics Dashboard - NeuralShield-AI
June 2026 Production Release
Comprehensive tests for metric aggregation, security scoring, and reporting.
"""
import pytest
import json
import os
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

from neural_shield.security_metrics_analytics_dashboard_2026_june import (
    SecurityLevel,
    MetricType,
    AlertSeverity,
    MetricDataPoint,
    DashboardAlert,
    SecurityScore,
    MetricsAggregator,
    SecurityScorer,
    TrendAnalyzer,
    SecurityAnalyticsDashboard,
    create_security_dashboard,
    AlertThreshold
)


class TestMetricDataPoint:
    """Tests for MetricDataPoint dataclass"""
    
    def test_metric_creation(self):
        """Test basic metric creation"""
        metric = MetricDataPoint(
            metric_type=MetricType.THREAT_DETECTION_RATE,
            value=0.95,
            source="test_detector"
        )
        assert metric.metric_type == MetricType.THREAT_DETECTION_RATE
        assert metric.value == 0.95
        assert metric.source == "test_detector"
        assert isinstance(metric.timestamp, datetime)


class TestAlertThreshold:
    """Tests for AlertThreshold class"""
    
    def test_threshold_breach(self):
        """Test threshold breach detection"""
        threshold = AlertThreshold()
        metric = MetricDataPoint(
            metric_type=MetricType.JAILBREAK_ATTEMPTS,
            value=15.0  # Above threshold of 10
        )
        alert = threshold.check_threshold(metric)
        assert alert is not None
        assert alert.severity == AlertSeverity.CRITICAL


class TestMetricsAggregator:
    """Tests for MetricsAggregator class"""
    
    def test_record_metric(self):
        """Test recording a metric"""
        aggregator = MetricsAggregator()
        metric = MetricDataPoint(
            metric_type=MetricType.THREAT_DETECTION_RATE,
            value=0.90
        )
        alert = aggregator.record_metric(metric)
        assert len(aggregator.metrics_history) == 1
    
    def test_metric_average(self):
        """Test metric average calculation"""
        aggregator = MetricsAggregator()
        for i in range(5):
            aggregator.record_metric(MetricDataPoint(
                metric_type=MetricType.THREAT_DETECTION_RATE,
                value=0.80 + (i * 0.05)
            ))
        avg = aggregator.get_metric_average(MetricType.THREAT_DETECTION_RATE)
        assert 0.85 <= avg <= 0.95


class TestSecurityScorer:
    """Tests for SecurityScorer class"""
    
    def test_score_calculation(self):
        """Test security score calculation"""
        metrics = {
            MetricType.THREAT_DETECTION_RATE.value: {"average": 0.92},
            MetricType.RESPONSE_TIME.value: {"average": 50.0},
            MetricType.SESSIONS_MONITORED.value: {"sum": 1000},
            MetricType.BLOCKED_ATTACKS.value: {"sum": 50},
            MetricType.FALSE_POSITIVE_RATE.value: {"average": 0.03},
        }
        score = SecurityScorer.calculate_score(metrics)
        assert 0 <= score.overall_score <= 100
        assert isinstance(score.security_level, SecurityLevel)


class TestSecurityAnalyticsDashboard:
    """Tests for main SecurityAnalyticsDashboard class"""
    
    def test_dashboard_creation(self):
        """Test dashboard creation"""
        with tempfile.TemporaryDirectory() as tmpdir:
            dashboard = SecurityAnalyticsDashboard(reports_directory=tmpdir)
            assert dashboard.aggregator is not None
    
    def test_factory_function(self):
        """Test factory function"""
        dashboard = create_security_dashboard()
        assert isinstance(dashboard, SecurityAnalyticsDashboard)
    
    def test_get_security_score(self):
        """Test getting security score"""
        with tempfile.TemporaryDirectory() as tmpdir:
            dashboard = SecurityAnalyticsDashboard(reports_directory=tmpdir)
            for _ in range(10):
                dashboard.record_threat_detection(0.90)
                dashboard.record_blocked_attack(1)
            
            score = dashboard.get_current_security_score()
            assert isinstance(score, SecurityScore)
            assert 0 <= score.overall_score <= 100
    
    def test_generate_report(self):
        """Test report generation"""
        with tempfile.TemporaryDirectory() as tmpdir:
            dashboard = SecurityAnalyticsDashboard(reports_directory=tmpdir)
            for i in range(20):
                dashboard.record_threat_detection(0.85 + (i % 10) * 0.01)
                dashboard.record_blocked_attack(1)
            
            report = dashboard.generate_report(report_type="test", hours_back=1)
            assert report.report_type == "test"
            assert len(report.recommendations) > 0


class TestIntegration:
    """Integration tests for complete workflow"""
    
    def test_complete_dashboard_workflow(self):
        """Test complete dashboard workflow"""
        with tempfile.TemporaryDirectory() as tmpdir:
            dashboard = SecurityAnalyticsDashboard(reports_directory=tmpdir)
            
            # Simulate production traffic
            for i in range(50):
                dashboard.record_threat_detection(0.85 + (i % 10) * 0.01)
                if i % 5 == 0:
                    dashboard.record_jailbreak_attempt(1)
                if i % 7 == 0:
                    dashboard.record_prompt_injection(1)
                dashboard.record_blocked_attack(1)
            
            # Get summary
            summary = dashboard.get_dashboard_summary()
            assert summary["security_score"]["overall"] > 0
            
            # Generate report
            report = dashboard.generate_report("integration_test", 1)
            assert report.generated_at is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
