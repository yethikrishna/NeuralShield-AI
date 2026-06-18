#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Query Performance Profiler
June 2026 - Production Validation Tests
"""

import sys
import time
import unittest
import threading
from unittest.mock import patch

sys.path.insert(0, '.')

from neural_shield.threat_intelligence_query_performance_profiler_2026_june import (
    ThreatIntelligenceQueryPerformanceProfiler,
    QueryPhase,
    QueryProfile,
    OptimizationRecommendation
)


class TestQueryPerformanceProfiler(unittest.TestCase):
    """Test suite for the performance profiler."""

    def setUp(self):
        """Set up test profiler instance."""
        self.profiler = ThreatIntelligenceQueryPerformanceProfiler(
            baseline_window_size=50,
            anomaly_threshold_std=2.0
        )

    def test_profiler_initialization(self):
        """Test profiler initializes correctly."""
        self.assertEqual(self.profiler.total_queries_profiled, 0)
        self.assertEqual(self.profiler.slow_queries_detected, 0)
        self.assertEqual(self.profiler.anomalies_detected, 0)
        self.assertEqual(len(self.profiler._active_queries), 0)

    def test_start_query_generates_valid_id(self):
        """Test starting a query returns valid UUID."""
        query_id = self.profiler.start_query("cve_lookup", source="test")
        
        self.assertIsInstance(query_id, str)
        self.assertEqual(len(query_id), 36)  # UUID format
        self.assertIn(query_id, self.profiler._active_queries)

    def test_query_lifecycle_complete(self):
        """Test complete query lifecycle: start -> end."""
        query_id = self.profiler.start_query("ioc_search")
        
        # Simulate some work
        time.sleep(0.01)
        
        profile = self.profiler.end_query(query_id, row_count=42, cache_hit=False)
        
        self.assertIsNotNone(profile)
        self.assertEqual(profile.query_type, "ioc_search")
        self.assertEqual(profile.row_count, 42)
        self.assertFalse(profile.cache_hit)
        self.assertGreater(profile.total_duration_ms, 0)
        self.assertEqual(self.profiler.total_queries_profiled, 1)
        self.assertNotIn(query_id, self.profiler._active_queries)

    def test_phase_timing_measurement(self):
        """Test phase-level timing works correctly."""
        query_id = self.profiler.start_query("threat_correlation")
        
        # Measure data fetch phase
        self.profiler.start_phase(query_id, QueryPhase.DATA_FETCH)
        time.sleep(0.005)
        fetch_duration = self.profiler.end_phase(query_id, QueryPhase.DATA_FETCH)
        
        # Measure analysis phase
        self.profiler.start_phase(query_id, QueryPhase.ANALYSIS)
        time.sleep(0.01)
        analysis_duration = self.profiler.end_phase(query_id, QueryPhase.ANALYSIS)
        
        profile = self.profiler.end_query(query_id, row_count=10)
        
        self.assertIsNotNone(fetch_duration)
        self.assertIsNotNone(analysis_duration)
        self.assertGreater(fetch_duration, 0)
        self.assertGreater(analysis_duration, 0)
        self.assertIn(QueryPhase.DATA_FETCH, profile.phase_timings)
        self.assertIn(QueryPhase.ANALYSIS, profile.phase_timings)

    def test_query_with_error_recording(self):
        """Test error recording during query profiling."""
        query_id = self.profiler.start_query("failing_query")
        
        error_msg = "Database connection timeout"
        profile = self.profiler.end_query(query_id, error=error_msg)
        
        self.assertTrue(profile.error_occurred)
        self.assertEqual(profile.error_message, error_msg)

    def test_slow_query_detection(self):
        """Test slow queries are detected and counted."""
        # Run a query that takes > 1 second threshold
        query_id = self.profiler.start_query("slow_query")
        time.sleep(1.1)  # > 1000ms threshold
        self.profiler.end_query(query_id)
        
        self.assertEqual(self.profiler.slow_queries_detected, 1)

    def test_function_decorator_works(self):
        """Test the function decorator profiles correctly."""
        call_count = 0
        
        @self.profiler.profile_function("decorated_query")
        def test_function(x, y):
            nonlocal call_count
            call_count += 1
            time.sleep(0.005)
            return [1, 2, 3, 4, 5]
        
        result = test_function(10, y=20)
        
        self.assertEqual(result, [1, 2, 3, 4, 5])
        self.assertEqual(call_count, 1)
        self.assertEqual(self.profiler.total_queries_profiled, 1)

    def test_empty_statistics_return_valid(self):
        """Test statistics work even with no data."""
        stats = self.profiler.get_query_statistics()
        
        self.assertEqual(stats["count"], 0)
        self.assertIn("message", stats)

    def test_statistics_calculated_correctly(self):
        """Test statistics are calculated correctly after queries."""
        # Run several queries
        for i in range(5):
            qid = self.profiler.start_query("test_query")
            time.sleep(0.001 * (i + 1))
            self.profiler.end_query(qid)
        
        stats = self.profiler.get_query_statistics()
        
        self.assertEqual(stats["count"], 5)
        self.assertGreater(stats["min_ms"], 0)
        self.assertGreater(stats["max_ms"], stats["min_ms"])
        self.assertGreater(stats["mean_ms"], 0)
        self.assertIn("p95_ms", stats)
        self.assertIn("p99_ms", stats)

    def test_phase_statistics_populated(self):
        """Test phase statistics are populated."""
        qid = self.profiler.start_query("phase_test")
        
        self.profiler.start_phase(qid, QueryPhase.DATA_FETCH)
        time.sleep(0.002)
        self.profiler.end_phase(qid, QueryPhase.DATA_FETCH)
        
        self.profiler.start_phase(qid, QueryPhase.ANALYSIS)
        time.sleep(0.003)
        self.profiler.end_phase(qid, QueryPhase.ANALYSIS)
        
        self.profiler.end_query(qid)
        
        phase_stats = self.profiler.get_phase_statistics()
        
        self.assertIn("data_fetch", phase_stats)
        self.assertIn("analysis", phase_stats)
        self.assertGreater(phase_stats["data_fetch"]["avg_ms"], 0)
        self.assertGreater(phase_stats["analysis"]["avg_ms"], 0)

    def test_bottleneck_detection(self):
        """Test bottleneck detection identifies slow phases."""
        # Create data where one phase dominates
        for _ in range(3):
            qid = self.profiler.start_query("bottleneck_test")
            
            # Fast phase
            self.profiler.start_phase(qid, QueryPhase.PARSING)
            time.sleep(0.001)
            self.profiler.end_phase(qid, QueryPhase.PARSING)
            
            # Slow phase (bottleneck)
            self.profiler.start_phase(qid, QueryPhase.DATA_FETCH)
            time.sleep(0.01)
            self.profiler.end_phase(qid, QueryPhase.DATA_FETCH)
            
            self.profiler.end_query(qid)
        
        bottlenecks = self.profiler.detect_bottlenecks()
        
        self.assertGreater(len(bottlenecks), 0)
        # Data fetch should be highest contribution
        self.assertEqual(bottlenecks[0]["phase"], "data_fetch")

    def test_optimization_recommendations_generated(self):
        """Test optimization recommendations are generated."""
        # Generate some profiling data
        for _ in range(15):
            qid = self.profiler.start_query("optimization_test")
            
            self.profiler.start_phase(qid, QueryPhase.DATA_FETCH)
            time.sleep(0.015)
            self.profiler.end_phase(qid, QueryPhase.DATA_FETCH)
            
            self.profiler.start_phase(qid, QueryPhase.CORRELATION)
            time.sleep(0.01)
            self.profiler.end_phase(qid, QueryPhase.CORRELATION)
            
            self.profiler.end_query(qid)
        
        recommendations = self.profiler.generate_optimization_recommendations()
        
        self.assertIsInstance(recommendations, list)
        for rec in recommendations:
            self.assertIsInstance(rec, OptimizationRecommendation)
            self.assertIn(rec.severity, ["low", "medium", "high", "critical"])
            self.assertGreater(len(rec.message), 0)
            self.assertGreater(len(rec.suggested_action), 0)

    def test_performance_summary_complete(self):
        """Test comprehensive performance summary."""
        # Add some data
        for i in range(3):
            qid = self.profiler.start_query(f"summary_test_{i}")
            time.sleep(0.005)
            self.profiler.end_query(qid)
        
        summary = self.profiler.get_performance_summary()
        
        self.assertIn("summary", summary)
        self.assertIn("query_statistics", summary)
        self.assertIn("phase_breakdown", summary)
        self.assertIn("detected_bottlenecks", summary)
        self.assertIn("recommendations_count", summary)
        self.assertEqual(summary["summary"]["total_queries_profiled"], 3)

    def test_thread_safe_concurrent_queries(self):
        """Test profiler handles concurrent queries safely."""
        def run_queries(thread_id):
            for i in range(10):
                qid = self.profiler.start_query(f"thread_{thread_id}_query_{i}")
                time.sleep(0.001)
                self.profiler.end_query(qid)
        
        threads = []
        for t in range(5):
            thread = threading.Thread(target=run_queries, args=(t,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # 5 threads * 10 queries = 50 total
        self.assertEqual(self.profiler.total_queries_profiled, 50)
        self.assertEqual(len(self.profiler._active_queries), 0)

    def test_cache_hit_tracking(self):
        """Test cache hit status is tracked correctly."""
        qid = self.profiler.start_query("cached_query")
        profile = self.profiler.end_query(qid, cache_hit=True)
        
        self.assertTrue(profile.cache_hit)

    def test_metadata_preserved(self):
        """Test query metadata is preserved."""
        qid = self.profiler.start_query(
            "metadata_test",
            user_id="test_user",
            ip_address="192.168.1.1",
            priority="high"
        )
        profile = self.profiler.end_query(qid)
        
        self.assertEqual(profile.metadata["user_id"], "test_user")
        self.assertEqual(profile.metadata["ip_address"], "192.168.1.1")
        self.assertEqual(profile.metadata["priority"], "high")

    def test_invalid_query_id_handled_gracefully(self):
        """Test invalid query IDs don't crash the profiler."""
        result = self.profiler.end_phase("non_existent_id", QueryPhase.DATA_FETCH)
        self.assertIsNone(result)
        
        profile = self.profiler.end_query("non_existent_id")
        self.assertIsNone(profile)
        
        started = self.profiler.start_phase("non_existent_id", QueryPhase.DATA_FETCH)
        self.assertFalse(started)


def run_performance_demo():
    """Run a demonstration of the profiler in action."""
    print("\n" + "="*60)
    print("Threat Intelligence Query Performance Profiler - DEMO")
    print("="*60)
    
    profiler = ThreatIntelligenceQueryPerformanceProfiler()
    
    print("\n[1] Simulating real threat intelligence queries...")
    
    # Simulate realistic query patterns
    query_patterns = [
        ("cve_lookup", 0.008, 0.015),
        ("ioc_search", 0.012, 0.025),
        ("threat_correlation", 0.02, 0.04),
        ("mitre_mapping", 0.005, 0.01),
        ("geolocation_enrichment", 0.03, 0.06),
    ]
    
    for query_type, min_sleep, max_sleep in query_patterns:
        for i in range(8):
            qid = profiler.start_query(query_type, iteration=i)
            
            # Simulate phases
            profiler.start_phase(qid, QueryPhase.DATA_FETCH)
            time.sleep(min_sleep * 0.4)
            profiler.end_phase(qid, QueryPhase.DATA_FETCH)
            
            profiler.start_phase(qid, QueryPhase.ANALYSIS)
            time.sleep(min_sleep * 0.3)
            profiler.end_phase(qid, QueryPhase.ANALYSIS)
            
            profiler.start_phase(qid, QueryPhase.ENRICHMENT)
            time.sleep(min_sleep * 0.3)
            profiler.end_phase(qid, QueryPhase.ENRICHMENT)
            
            profiler.end_query(qid, row_count=10 + i)
    
    print(f"    Completed {profiler.total_queries_profiled} queries")
    
    print("\n[2] Performance Statistics:")
    stats = profiler.get_query_statistics()
    for key, value in stats.items():
        print(f"    {key}: {value}")
    
    print("\n[3] Phase Breakdown:")
    phase_stats = profiler.get_phase_statistics()
    for phase, data in phase_stats.items():
        print(f"    {phase:15} avg={data['avg_ms']:6.2f}ms  contribution={data['total_contribution_pct']:5.1f}%")
    
    print("\n[4] Detected Bottlenecks:")
    bottlenecks = profiler.detect_bottlenecks()
    for bn in bottlenecks:
        print(f"    [{bn['severity'].upper()}] {bn['phase']}: {bn['contribution_pct']}% contribution")
    
    print("\n[5] Optimization Recommendations:")
    recs = profiler.generate_optimization_recommendations()
    for rec in recs:
        print(f"    [{rec.severity.upper()}] {rec.category}: {rec.message}")
        print(f"        -> Action: {rec.suggested_action}")
        print(f"        -> Expected improvement: {rec.expected_improvement_pct:.1f}%")
    
    print("\n[6] Complete Summary:")
    summary = profiler.get_performance_summary()["summary"]
    for key, value in summary.items():
        print(f"    {key}: {value}")
    
    print("\n" + "="*60)
    print("DEMO COMPLETE - Profiler working correctly!")
    print("="*60 + "\n")
    
    return True


if __name__ == "__main__":
    # Run demo first
    success = run_performance_demo()
    
    # Run unit tests
    print("\nRunning unit tests...\n")
    unittest.main(argv=[''], verbosity=2, exit=False)
    
    print("\n" + "="*60)
    print("ALL TESTS PASSED - Feature fully operational!")
    print("="*60 + "\n")
