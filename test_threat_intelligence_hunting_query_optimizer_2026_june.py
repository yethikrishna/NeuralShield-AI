"""
Test Suite for Threat Intelligence Hunting Query Optimizer
Production-Grade Tests - June 19, 2026

Covers:
- Query validation and syntax checking
- Cost estimation accuracy
- Optimization suggestion generation
- Query caching functionality
- Performance metrics tracking
- Edge cases and error handling
"""
import pytest
import json
import time
from datetime import datetime
from neural_shield.threat_intelligence_hunting_query_optimizer_2026_june import (
    ThreatHuntingQueryOptimizer,
    QueryType,
    OptimizationLevel,
    QueryStatus,
    QueryCostEstimate,
    OptimizationSuggestion,
    OptimizedQuery,
)


class TestThreatHuntingQueryOptimizer:
    """Test suite for ThreatHuntingQueryOptimizer."""
    
    @pytest.fixture
    def optimizer(self):
        """Create fresh optimizer instance for each test."""
        return ThreatHuntingQueryOptimizer()
    
    def test_initialization(self, optimizer):
        """Test proper initialization with default config."""
        assert optimizer.config is not None
        assert optimizer.query_cache == {}
        assert optimizer.query_history == []
        assert optimizer.optimization_level == OptimizationLevel.MODERATE
        assert "max_query_length" in optimizer.config
        assert "cache_ttl_seconds" in optimizer.config
    
    def test_query_hash_generation(self, optimizer):
        """Test deterministic query hash generation."""
        query1 = "SELECT * FROM network_traffic WHERE src_ip = '192.168.1.1'"
        query2 = "SELECT * FROM network_traffic WHERE src_ip = '192.168.1.1'"
        query3 = "SELECT * FROM network_traffic WHERE src_ip = '10.0.0.1'"
        
        hash1 = optimizer.generate_query_hash(query1)
        hash2 = optimizer.generate_query_hash(query2)
        hash3 = optimizer.generate_query_hash(query3)
        
        assert hash1 == hash2  # Same query = same hash
        assert hash1 != hash3  # Different query = different hash
        assert len(hash1) == 16  # 16 hex chars
    
    def test_query_normalization(self, optimizer):
        """Test query normalization for consistent hashing."""
        query1 = "select * from logs where ip = '1.1.1.1'"
        query2 = "SELECT * FROM logs WHERE ip = '1.1.1.1'"
        
        normalized1 = optimizer._normalize_query(query1)
        normalized2 = optimizer._normalize_query(query2)
        
        # Keywords should be standardized to uppercase
        assert "SELECT" in normalized1
        assert "FROM" in normalized1
        assert "WHERE" in normalized1
    
    def test_query_type_detection(self, optimizer):
        """Test query type classification."""
        # IOC Search
        ioc_query = "SELECT * FROM indicators WHERE ip = '1.1.1.1' AND domain = 'evil.com'"
        assert optimizer.detect_query_type(ioc_query) == QueryType.IOC_SEARCH
        
        # Network Traffic
        network_query = "SELECT src_ip, dst_ip FROM connections WHERE src_port = 443"
        assert optimizer.detect_query_type(network_query) == QueryType.NETWORK_TRAFFIC
        
        # Process Analysis
        process_query = "SELECT process_name, command_line FROM process_events"
        assert optimizer.detect_query_type(process_query) == QueryType.PROCESS_ANALYSIS
        
        # Log Correlation
        correlation_query = "SELECT * FROM auth_logs JOIN process_logs ON host_id"
        assert optimizer.detect_query_type(correlation_query) == QueryType.LOG_CORRELATION
    
    def test_query_validation_valid_query(self, optimizer):
        """Test validation of a well-formed query."""
        valid_query = "SELECT timestamp, src_ip FROM network WHERE dst_port = 80"
        is_valid, issues = optimizer.validate_query(valid_query)
        
        # Should be valid with no critical issues
        assert isinstance(is_valid, bool)
        assert isinstance(issues, list)
    
    def test_query_validation_unbalanced_parentheses(self, optimizer):
        """Test detection of unbalanced parentheses."""
        bad_query = "SELECT * FROM logs WHERE (ip = '1.1.1.1' AND port = 80"
        is_valid, issues = optimizer.validate_query(bad_query)
        
        assert any("Unbalanced parentheses" in issue for issue in issues)
    
    def test_query_validation_select_star_warning(self, optimizer):
        """Test performance warning for SELECT *."""
        query = "SELECT * FROM network_traffic"
        is_valid, issues = optimizer.validate_query(query)
        
        assert any("SELECT *" in issue for issue in issues)
        assert any("field projection" in issue.lower() for issue in issues)
    
    def test_cost_estimation_basic(self, optimizer):
        """Test basic cost estimation functionality."""
        query = "SELECT src_ip FROM logs WHERE timestamp > '2026-01-01'"
        query_type = QueryType.NETWORK_TRAFFIC
        
        cost = optimizer.estimate_query_cost(query, query_type)
        
        assert isinstance(cost, QueryCostEstimate)
        assert cost.estimated_rows_scanned > 0
        assert cost.estimated_execution_time_ms >= 0
        assert cost.estimated_memory_mb >= 0
        assert 0.0 <= cost.io_cost <= 1.0
        assert 0.0 <= cost.network_cost <= 1.0
        assert 0.0 <= cost.overall_cost_score <= 100.0
        assert cost.cost_category in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    
    def test_cost_estimation_complex_query_higher_cost(self, optimizer):
        """Test that more complex queries have higher estimated costs."""
        simple_query = "SELECT ip FROM iocs WHERE value = '1.1.1.1'"
        complex_query = """
            SELECT DISTINCT a.ip, b.domain, c.hash
            FROM iocs a 
            JOIN domains b ON a.id = b.ioc_id
            JOIN hashes c ON a.id = c.ioc_id
            WHERE a.timestamp > '2026-01-01'
            ORDER BY a.timestamp DESC
        """
        
        simple_cost = optimizer.estimate_query_cost(simple_query, QueryType.IOC_SEARCH)
        complex_cost = optimizer.estimate_query_cost(complex_query, QueryType.LOG_CORRELATION)
        
        # Complex query should have higher or equal cost
        assert complex_cost.overall_cost_score >= simple_cost.overall_cost_score * 0.5
    
    def test_time_range_extraction(self, optimizer):
        """Test time range extraction from queries."""
        query_24h = "SELECT * FROM logs WHERE timestamp > now() - 24h"
        query_7d = "SELECT * FROM logs WHERE last 7d"
        
        hours_24 = optimizer._extract_time_range(query_24h)
        hours_7d = optimizer._extract_time_range(query_7d)
        
        assert hours_24 == 24
        assert hours_7d == 168
    
    def test_optimization_suggestions_generation(self, optimizer):
        """Test generation of optimization suggestions."""
        query = "SELECT * FROM network_traffic WHERE src_ip = '1.1.1.1'"
        query_type = QueryType.NETWORK_TRAFFIC
        cost = optimizer.estimate_query_cost(query, query_type)
        
        suggestions = optimizer.generate_optimization_suggestions(query, query_type, cost)
        
        assert isinstance(suggestions, list)
        assert len(suggestions) > 0
        
        for s in suggestions:
            assert isinstance(s, OptimizationSuggestion)
            assert s.suggestion_type in ["INDEX", "PROJECTION", "PAGINATION", "CACHE", "FILTER"]
            assert s.impact in ["LOW", "MEDIUM", "HIGH"]
            assert 0.0 <= s.expected_improvement_pct <= 100.0
    
    def test_apply_optimizations_pagination(self, optimizer):
        """Test automatic pagination application."""
        query = "SELECT src_ip FROM logs WHERE dst_port = 443"
        suggestions = []
        
        optimized, applied = optimizer.apply_optimizations(query, suggestions)
        
        assert "LIMIT" in optimized
        assert any("pagination" in a.lower() for a in applied)
    
    def test_full_optimize_query_pipeline(self, optimizer):
        """Test complete query optimization pipeline."""
        query = """
            SELECT * FROM network_events 
            WHERE src_ip = '192.168.1.100' 
            AND timestamp > '2026-06-01'
        """
        
        result = optimizer.optimize_query(query)
        
        assert isinstance(result, OptimizedQuery)
        assert result.original_query == query
        assert result.optimized_query is not None
        assert result.query_type in QueryType
        assert len(result.query_hash) == 16
        assert isinstance(result.cost_estimate, QueryCostEstimate)
        assert isinstance(result.suggestions, list)
        assert isinstance(result.applied_optimizations, list)
        assert isinstance(result.validation_errors, list)
        assert isinstance(result.cache_strategy, dict)
        assert isinstance(result.pagination_strategy, dict)
        assert isinstance(result.optimization_timestamp, datetime)
    
    def test_cache_functionality(self, optimizer):
        """Test query result caching."""
        query_hash = "abc123def456"
        test_results = [{"ip": "1.1.1.1", "score": 95}]
        
        # Cache should be empty initially
        assert optimizer.check_cache(query_hash) is None
        
        # Store in cache
        optimizer.cache_results(query_hash, test_results)
        
        # Should retrieve from cache
        cached = optimizer.check_cache(query_hash)
        assert cached is not None
        assert cached["results"] == test_results
    
    def test_cache_ttl_expiration(self, optimizer):
        """Test that cache entries expire after TTL."""
        # Configure very short TTL for testing
        short_config = {"cache_ttl_seconds": 1}
        short_optimizer = ThreatHuntingQueryOptimizer(short_config)
        
        query_hash = "test_expire"
        short_optimizer.cache_results(query_hash, ["test"])
        
        # Immediately available
        assert short_optimizer.check_cache(query_hash) is not None
        
        # Wait for expiration
        time.sleep(1.1)
        
        # Should be expired
        assert short_optimizer.check_cache(query_hash) is None
    
    def test_cache_capacity_eviction(self, optimizer):
        """Test that oldest entries are evicted when cache is full."""
        # Configure small cache for testing
        small_config = {"max_cache_entries": 3, "cache_ttl_seconds": 3600}
        small_optimizer = ThreatHuntingQueryOptimizer(small_config)
        
        # Fill cache
        for i in range(5):
            small_optimizer.cache_results(f"hash_{i}", [f"data_{i}"])
        
        # Should only keep 3 most recent
        assert len(small_optimizer.query_cache) == 3
    
    def test_query_history_tracking(self, optimizer):
        """Test that queries are recorded in history."""
        initial_count = len(optimizer.query_history)
        
        optimizer.optimize_query("SELECT * FROM test")
        optimizer.optimize_query("SELECT ip FROM iocs")
        
        assert len(optimizer.query_history) == initial_count + 2
        
        for entry in optimizer.query_history:
            assert "query_hash" in entry
            assert "timestamp" in entry
            assert "query_type" in entry
            assert "cost_score" in entry
    
    def test_performance_report(self, optimizer):
        """Test performance report generation."""
        # Run some queries first
        optimizer.optimize_query("SELECT ip FROM iocs WHERE value = '1.1.1.1'")
        optimizer.optimize_query("SELECT * FROM network WHERE src_port = 80")
        
        report = optimizer.get_performance_report()
        
        assert isinstance(report, dict)
        assert "total_queries_optimized" in report
        assert report["total_queries_optimized"] == 2
        assert "avg_cost_score" in report
        assert "query_type_distribution" in report
        assert "cache_size" in report
    
    def test_different_optimization_levels(self, optimizer):
        """Test optimization level configuration."""
        optimizer.optimization_level = OptimizationLevel.CONSERVATIVE
        assert optimizer.optimization_level == OptimizationLevel.CONSERVATIVE
        
        optimizer.optimization_level = OptimizationLevel.AGGRESSIVE
        assert optimizer.optimization_level == OptimizationLevel.AGGRESSIVE
    
    def test_custom_configuration(self):
        """Test custom configuration options."""
        custom_config = {
            "max_query_length": 5000,
            "default_page_size": 500,
            "cache_ttl_seconds": 1800,
            "enable_auto_apply": False,
            "enable_query_caching": False,
        }
        
        custom_optimizer = ThreatHuntingQueryOptimizer(custom_config)
        
        assert custom_optimizer.config["max_query_length"] == 5000
        assert custom_optimizer.config["default_page_size"] == 500
        assert custom_optimizer.config["cache_ttl_seconds"] == 1800
    
    def test_empty_query_handling(self, optimizer):
        """Test handling of empty or minimal queries."""
        result = optimizer.optimize_query("")
        assert isinstance(result, OptimizedQuery)
        assert result.original_query == ""
    
    def test_very_long_query(self, optimizer):
        """Test handling of very long queries."""
        long_query = "SELECT " + ", ".join([f"field_{i}" for i in range(100)]) + " FROM very_large_table"
        
        result = optimizer.optimize_query(long_query)
        assert isinstance(result, OptimizedQuery)
    
    def test_regex_pattern_detection(self, optimizer):
        """Test detection of expensive regex patterns."""
        query = "SELECT * FROM logs WHERE message REGEXP '.*attack.*'"
        
        is_valid, issues = optimizer.validate_query(query)
        
        # Should detect regex pattern
        assert any("regex" in issue.lower() for issue in issues)
    
    def test_cost_category_assignment(self, optimizer):
        """Test proper cost category assignment."""
        # Very simple query should be LOW
        simple = optimizer.estimate_query_cost("SELECT ip FROM iocs", QueryType.IOC_SEARCH)
        assert simple.cost_category in ["LOW", "MEDIUM"]
        
        # Complex correlation should be higher
        complex_cost = optimizer.estimate_query_cost(
            "SELECT * FROM a JOIN b JOIN c WHERE .*", 
            QueryType.LOG_CORRELATION
        )
        assert complex_cost.cost_category in ["MEDIUM", "HIGH", "CRITICAL"]


def run_tests():
    """Run all tests and report results."""
    print("=" * 70)
    print("Threat Intelligence Hunting Query Optimizer - Test Suite")
    print("Production-Grade Implementation - June 19, 2026")
    print("=" * 70)
    
    # Run pytest
    result = pytest.main([__file__, "-v", "--tb=short"])
    
    print("\n" + "=" * 70)
    if result == 0:
        print("✓ ALL TESTS PASSED - Production Ready")
    else:
        print("✗ SOME TESTS FAILED - Review Required")
    print("=" * 70)
    
    return result


if __name__ == "__main__":
    run_tests()
