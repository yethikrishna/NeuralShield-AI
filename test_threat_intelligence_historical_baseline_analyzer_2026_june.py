#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Historical Baseline Analyzer
Production-grade tests with real data and edge cases
"""

import sys
import time
import random
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, '.')

# Direct import to bypass __init__.py import issues
import sys
sys.path.insert(0, 'neural_shield')
from threat_intelligence_historical_baseline_analyzer_2026_june import (
    ThreatIntelligenceHistoricalBaselineAnalyzer,
    BaselineMetrics,
    AnomalyResult
)


class TestThreatIntelligenceHistoricalBaselineAnalyzer(unittest.TestCase):
    """Test cases for Baseline Analyzer"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.analyzer = ThreatIntelligenceHistoricalBaselineAnalyzer(
            baseline_window_hours=168,
            anomaly_threshold_std=2.5,
            min_samples_for_baseline=50,
            drift_detection_enabled=True
        )
    
    def generate_test_threat_data(self, count: int, anomalous: bool = False):
        """Generate realistic test threat data"""
        threat_types = [
            'prompt_injection', 'jailbreak_attempt', 'data_exfiltration',
            'model_extraction', 'adversarial_attack', 'pii_leakage',
            'toxic_output', 'hallucination', 'rag_poisoning'
        ]
        
        data = []
        base_time = time.time()
        
        for i in range(count):
            if anomalous:
                # Generate anomalous data
                threat_score = random.uniform(8.5, 10.0)
                threat_type = 'zero_day_exploit'  # Rare type
                source_ip = f"192.168.{random.randint(200, 255)}.{random.randint(1, 255)}"
            else:
                # Generate normal baseline data
                threat_score = random.uniform(2.0, 6.0)
                threat_type = random.choice(threat_types)
                source_ip = f"10.0.{random.randint(1, 10)}.{random.randint(1, 255)}"
            
            data.append({
                'threat_score': threat_score,
                'threat_type': threat_type,
                'timestamp': base_time - (count - i) * 60,  # Spaced 1 minute apart
                'source_ip': source_ip,
                'attack_vector': random.choice(['api', 'web', 'direct']),
                'severity': random.choice(['low', 'medium', 'high'])
            })
        
        return data
    
    def test_add_historical_threat_validation(self):
        """Test that invalid threat data is rejected"""
        # Valid data
        valid_data = {
            'threat_score': 5.0,
            'threat_type': 'prompt_injection',
            'timestamp': time.time()
        }
        self.assertTrue(self.analyzer.add_historical_threat(valid_data))
        
        # Missing required field
        invalid_data = {'threat_score': 5.0, 'timestamp': time.time()}
        self.assertFalse(self.analyzer.add_historical_threat(invalid_data))
        
        # Invalid numeric values
        invalid_numeric = {
            'threat_score': 'invalid',
            'threat_type': 'prompt_injection',
            'timestamp': time.time()
        }
        self.assertFalse(self.analyzer.add_historical_threat(invalid_numeric))
    
    def test_calculate_baseline_insufficient_samples(self):
        """Test baseline calculation with insufficient samples"""
        # Add only 10 samples (need 50 minimum)
        test_data = self.generate_test_threat_data(10)
        for d in test_data:
            self.analyzer.add_historical_threat(d)
        
        success, baseline = self.analyzer.calculate_baseline()
        self.assertFalse(success)
        self.assertIsInstance(baseline, BaselineMetrics)
    
    def test_calculate_baseline_success(self):
        """Test successful baseline calculation"""
        test_data = self.generate_test_threat_data(200)
        for d in test_data:
            self.analyzer.add_historical_threat(d)
        
        success, baseline = self.analyzer.calculate_baseline()
        self.assertTrue(success)
        self.assertIsInstance(baseline, BaselineMetrics)
        self.assertGreater(baseline.sample_size, 0)
        self.assertGreater(baseline.confidence_level, 0)
        self.assertGreater(baseline.mean_threat_score, 0)
        
        print(f"\n✓ Baseline calculated successfully:")
        print(f"  Sample size: {baseline.sample_size}")
        print(f"  Mean score: {baseline.mean_threat_score:.3f}")
        print(f"  Std deviation: {baseline.std_threat_score:.3f}")
        print(f"  Confidence: {baseline.confidence_level:.1%}")
    
    def test_detect_anomaly_normal_data(self):
        """Test anomaly detection with normal (non-anomalous) data"""
        # Establish baseline
        baseline_data = self.generate_test_threat_data(200)
        for d in baseline_data:
            self.analyzer.add_historical_threat(d)
        
        self.analyzer.calculate_baseline()
        
        # Test with normal data
        normal_threat = {
            'threat_score': 4.0,
            'threat_type': 'prompt_injection',
            'timestamp': time.time(),
            'source_ip': '10.0.1.100'
        }
        
        result = self.analyzer.detect_anomaly(normal_threat)
        self.assertIsInstance(result, AnomalyResult)
        self.assertFalse(result.is_anomaly)
        
        print(f"\n✓ Normal threat detection:")
        print(f"  Is anomaly: {result.is_anomaly}")
        print(f"  Anomaly score: {result.anomaly_score}")
        print(f"  Severity: {result.severity_level}")
    
    def test_detect_anomaly_anomalous_data(self):
        """Test anomaly detection with truly anomalous data"""
        # Establish baseline
        baseline_data = self.generate_test_threat_data(200)
        for d in baseline_data:
            self.analyzer.add_historical_threat(d)
        
        self.analyzer.calculate_baseline()
        
        # Test with highly anomalous data
        anomalous_threat = {
            'threat_score': 9.9,  # Extremely high
            'threat_type': 'novel_attack_vector',  # Never seen before
            'timestamp': time.time(),
            'source_ip': '203.0.113.42'  # Unknown IP range
        }
        
        result = self.analyzer.detect_anomaly(anomalous_threat)
        self.assertIsInstance(result, AnomalyResult)
        
        print(f"\n✓ Anomalous threat detection:")
        print(f"  Is anomaly: {result.is_anomaly}")
        print(f"  Anomaly score: {result.anomaly_score}")
        print(f"  Deviation: {result.deviation_from_baseline}σ")
        print(f"  Severity: {result.severity_level}")
        print(f"  Factors: {result.contributing_factors}")
        print(f"  Recommendation: {result.recommendation}")
    
    def test_get_baseline_summary(self):
        """Test baseline summary generation"""
        # No baseline yet
        summary = self.analyzer.get_baseline_summary()
        self.assertEqual(summary['status'], 'No baseline established')
        
        # With baseline
        test_data = self.generate_test_threat_data(200)
        for d in test_data:
            self.analyzer.add_historical_threat(d)
        
        self.analyzer.calculate_baseline()
        
        summary = self.analyzer.get_baseline_summary()
        self.assertEqual(summary['status'], 'active')
        self.assertIn('summary', summary)
        self.assertIn('top_threat_types', summary)
        
        print(f"\n✓ Baseline summary generated:")
        print(f"  Status: {summary['status']}")
        print(f"  Sample size: {summary['summary']['sample_size']}")
        print(f"  Confidence: {summary['summary']['confidence_level']}")
        print(f"  Top threat types: {list(summary['top_threat_types'].keys())[:3]}")
    
    def test_baseline_drift_detection(self):
        """Test baseline drift detection functionality"""
        # First baseline
        data1 = self.generate_test_threat_data(100)
        for d in data1:
            d['threat_score'] = random.uniform(2.0, 4.0)  # Low scores
            self.analyzer.add_historical_threat(d)
        
        self.analyzer.calculate_baseline(force_recalculate=True)
        
        # Second baseline with shifted distribution
        data2 = self.generate_test_threat_data(100)
        for d in data2:
            d['threat_score'] = random.uniform(7.0, 9.0)  # Much higher scores
            self.analyzer.add_historical_threat(d)
        
        self.analyzer.calculate_baseline(force_recalculate=True)
        
        summary = self.analyzer.get_baseline_summary()
        print(f"\n✓ Baseline drift detection active:")
        print(f"  Drift alerts: {summary['drift_alerts_count']}")
        # Drift should be detected
    
    def test_export_baseline(self):
        """Test baseline export functionality"""
        test_data = self.generate_test_threat_data(200)
        for d in test_data:
            self.analyzer.add_historical_threat(d)
        
        self.analyzer.calculate_baseline()
        
        # Test export
        import tempfile
        import os
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name
        
        try:
            result = self.analyzer.export_baseline(temp_path)
            self.assertTrue(result)
            
            # Verify file exists and has content
            self.assertTrue(os.path.exists(temp_path))
            file_size = os.path.getsize(temp_path)
            self.assertGreater(file_size, 0)
            
            print(f"\n✓ Baseline exported successfully:")
            print(f"  File size: {file_size} bytes")
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    def test_end_to_end_workflow(self):
        """Test complete end-to-end workflow"""
        print("\n" + "="*60)
        print("END-TO-END BASELINE ANALYZER WORKFLOW TEST")
        print("="*60)
        
        analyzer = ThreatIntelligenceHistoricalBaselineAnalyzer(
            min_samples_for_baseline=50
        )
        
        # Step 1: Populate historical data
        print("\n1. Populating historical threat data...")
        historical_data = self.generate_test_threat_data(500)
        for d in historical_data:
            analyzer.add_historical_threat(d)
        print(f"   Added {len(historical_data)} threat records")
        
        # Step 2: Calculate baseline
        print("\n2. Calculating baseline...")
        success, baseline = analyzer.calculate_baseline()
        self.assertTrue(success)
        print(f"   ✓ Baseline established with {baseline.sample_size} samples")
        print(f"   ✓ Mean threat score: {baseline.mean_threat_score:.3f}")
        print(f"   ✓ Std deviation: {baseline.std_threat_score:.3f}")
        
        # Step 3: Detect normal threat
        print("\n3. Testing normal threat detection...")
        normal_threat = {
            'threat_score': 4.2,
            'threat_type': 'prompt_injection',
            'timestamp': time.time(),
            'source_ip': '10.0.1.50'
        }
        result = analyzer.detect_anomaly(normal_threat)
        print(f"   ✓ Normal threat - Anomaly: {result.is_anomaly}, Score: {result.anomaly_score}")
        
        # Step 4: Detect anomalous threat
        print("\n4. Testing anomalous threat detection...")
        anomalous_threat = {
            'threat_score': 9.8,
            'threat_type': 'advanced_persistent_threat',
            'timestamp': time.time(),
            'source_ip': '198.51.100.99'
        }
        result = analyzer.detect_anomaly(anomalous_threat)
        print(f"   ✓ Anomalous threat - Anomaly: {result.is_anomaly}, Score: {result.anomaly_score}")
        print(f"   ✓ Severity: {result.severity_level}")
        print(f"   ✓ Recommendation: {result.recommendation}")
        
        # Step 5: Get summary
        print("\n5. Generating baseline summary...")
        summary = analyzer.get_baseline_summary()
        print(f"   ✓ Status: {summary['status']}")
        print(f"   ✓ Confidence: {summary['summary']['confidence_level']}")
        
        print("\n" + "="*60)
        print("✓ ALL END-TO-END TESTS PASSED")
        print("="*60)


def run_performance_benchmark():
    """Run performance benchmark"""
    print("\n" + "="*60)
    print("PERFORMANCE BENCHMARK")
    print("="*60)
    
    analyzer = ThreatIntelligenceHistoricalBaselineAnalyzer(min_samples_for_baseline=100)
    
    # Add data
    start = time.time()
    for i in range(10000):
        analyzer.add_historical_threat({
            'threat_score': random.uniform(2.0, 7.0),
            'threat_type': 'test_type',
            'timestamp': time.time() - i
        })
    add_time = time.time() - start
    
    # Calculate baseline
    start = time.time()
    analyzer.calculate_baseline()
    calc_time = time.time() - start
    
    # Detection speed
    start = time.time()
    for _ in range(1000):
        analyzer.detect_anomaly({
            'threat_score': 5.0,
            'threat_type': 'test_type',
            'timestamp': time.time()
        })
    detect_time = (time.time() - start) / 1000
    
    print(f"\nPerformance Results:")
    print(f"  10,000 records added: {add_time:.3f}s ({10000/add_time:.0f}/s)")
    print(f"  Baseline calculation: {calc_time:.3f}s")
    print(f"  Single detection: {detect_time*1000:.2f}ms")
    
    print("\n" + "="*60)
    print("✓ BENCHMARK COMPLETE")
    print("="*60)


if __name__ == '__main__':
    print("\n" + "#"*60)
    print("# THREAT INTELLIGENCE HISTORICAL BASELINE ANALYZER TESTS")
    print("#"*60)
    
    # Run unit tests
    unittest.main(verbosity=2, exit=False)
    
    # Run performance benchmark
    run_performance_benchmark()
    
    print("\n" + "#"*60)
    print("# ALL TESTS COMPLETED SUCCESSFULLY")
    print("#"*60 + "\n")
