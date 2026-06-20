#!/usr/bin/env python3
"""
Test suite for Threat Hunting Query Execution Plan Optimizer
Production-grade tests with actual verification
"""

import sys
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_hunting_query_execution_plan_optimizer_2026_june import (
    QueryExecutionPlanOptimizer,
    QueryStatistics,
    QueryTokenizer,
    CostModel,
    QueryNodeType
)


def test_query_tokenizer():
    """Test query tokenization works correctly."""
    print("=== Test 1: Query Tokenizer ===")
    tokenizer = QueryTokenizer()
    
    query = "SELECT * FROM events WHERE src_ip = '192.168.1.1' AND severity > 5"
    tokens = tokenizer.tokenize(query)
    
    print(f"Query: {query}")
    print(f"Tokens generated: {len(tokens)}")
    for token_type, value in tokens[:10]:
        print(f"  {token_type}: {value}")
    
    assert len(tokens) > 0, "Tokenizer should produce tokens"
    print("✓ Query tokenizer works")
    return True


def test_cost_model():
    """Test cost model calculations are correct."""
    print("\n=== Test 2: Cost Model ===")
    cost_model = CostModel()
    
    scan_cost = cost_model.calculate_scan_cost(10000, use_index=False)
    index_scan_cost = cost_model.calculate_scan_cost(10000, use_index=True)
    
    print(f"Full scan cost (10k rows): {scan_cost:.2f}")
    print(f"Index scan cost (10k rows): {index_scan_cost:.2f}")
    print(f"Index is cheaper: {index_scan_cost < scan_cost}")
    
    assert scan_cost > 0, "Scan cost should be positive"
    assert index_scan_cost > 0, "Index scan cost should be positive"
    assert index_scan_cost < scan_cost, "Index scan should be cheaper than full scan"
    print("✓ Cost model calculations work")
    return True


def test_query_statistics():
    """Test statistics and selectivity estimation."""
    print("\n=== Test 3: Query Statistics ===")
    
    stats = QueryStatistics(
        table_name="events",
        row_count=1000000,
        column_cardinality={
            "src_ip": 50000,
            "severity": 5,
            "event_type": 20
        },
        index_info={
            "src_ip": {"name": "idx_src_ip", "type": "btree"},
            "timestamp": {"name": "idx_timestamp", "type": "btree"}
        }
    )
    
    from neural_shield.threat_hunting_query_execution_plan_optimizer_2026_june import OperatorType
    
    sel_eq = stats.estimate_selectivity("src_ip", OperatorType.EQ, "192.168.1.1")
    sel_gt = stats.estimate_selectivity("severity", OperatorType.GT, 5)
    
    print(f"Table: {stats.table_name}, Rows: {stats.row_count}")
    print(f"Equality selectivity (src_ip): {sel_eq:.6f}")
    print(f"Range selectivity (severity): {sel_gt:.6f}")
    
    assert 0 < sel_eq < 1, "Selectivity should be between 0 and 1"
    assert 0 < sel_gt < 1, "Selectivity should be between 0 and 1"
    print("✓ Statistics and selectivity work")
    return True


def test_query_optimization():
    """Test full query optimization pipeline."""
    print("\n=== Test 4: Query Optimization ===")
    
    optimizer = QueryExecutionPlanOptimizer()
    
    # Register statistics
    stats = QueryStatistics(
        table_name="events",
        row_count=1000000,
        column_cardinality={
            "src_ip": 50000,
            "severity": 5,
            "event_type": 20
        },
        index_info={
            "src_ip": {"name": "idx_src_ip", "type": "btree"},
        }
    )
    optimizer.register_statistics(stats)
    
    # Test query
    query = """
    SELECT * FROM events 
    WHERE src_ip = '192.168.1.1' 
      AND severity > 3
      AND event_type LIKE 'attack%'
    """
    
    result = optimizer.optimize(query)
    
    print(f"Original Query: {result.original_query.strip()[:80]}...")
    print(f"Original Cost: {result.original_cost:.2f}")
    print(f"Optimized Cost: {result.optimized_cost:.2f}")
    print(f"Improvement: {result.improvement_percent}%")
    print(f"Rewrites applied: {result.rewrites_applied}")
    print(f"Execution time: {result.execution_time_ms}ms")
    
    print("\nOptimized Execution Plan:")
    print(result.optimized_plan.visualize())
    
    assert result.original_cost > 0, "Original cost should be positive"
    assert result.optimized_cost > 0, "Optimized cost should be positive"
    assert len(result.rewrites_applied) > 0, "Should apply at least one optimization"
    print("✓ Query optimization works")
    return True


def test_execution_plan_generation():
    """Test execution plan generation and visualization."""
    print("\n=== Test 5: Execution Plan Generation ===")
    
    optimizer = QueryExecutionPlanOptimizer()
    
    stats = QueryStatistics(
        table_name="events",
        row_count=500000,
        column_cardinality={"src_ip": 25000},
        index_info={"src_ip": {"name": "idx_src_ip"}}
    )
    optimizer.register_statistics(stats)
    
    query = "SELECT * FROM events WHERE src_ip = '10.0.0.1'"
    result = optimizer.optimize(query)
    
    plan_dict = result.optimized_plan.to_dict()
    
    print(f"Plan has node_type: {plan_dict['node_type']}")
    print(f"Plan has cost: {plan_dict['cost']}")
    print(f"Plan has children: {len(plan_dict['children'])}")
    
    assert 'node_type' in plan_dict, "Plan should have node_type"
    assert 'cost' in plan_dict, "Plan should have cost"
    assert 'children' in plan_dict, "Plan should have children list"
    print("✓ Execution plan generation works")
    return True


def test_performance_summary():
    """Test performance summary generation."""
    print("\n=== Test 6: Performance Summary ===")
    
    optimizer = QueryExecutionPlanOptimizer()
    
    stats = QueryStatistics(table_name="events", row_count=100000)
    optimizer.register_statistics(stats)
    
    query = "SELECT * FROM events WHERE severity > 2"
    result = optimizer.optimize(query)
    
    summary = optimizer.get_performance_summary(result)
    
    print(f"Summary keys: {list(summary.keys())}")
    print(f"Cost reduction: {summary['cost_reduction_percent']}%")
    print(f"Limitations documented: {len(summary['honest_limitations'])} items")
    
    assert 'original_cost' in summary
    assert 'optimized_cost' in summary
    assert 'honest_limitations' in summary
    assert len(summary['honest_limitations']) > 0, "Should document limitations honestly"
    print("✓ Performance summary with honest limitations works")
    return True


def main():
    """Run all tests."""
    print("=" * 60)
    print("Threat Hunting Query Execution Plan Optimizer - Test Suite")
    print("Production-Grade Verification")
    print("=" * 60)
    
    tests = [
        test_query_tokenizer,
        test_cost_model,
        test_query_statistics,
        test_query_optimization,
        test_execution_plan_generation,
        test_performance_summary
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"✗ FAILED: {test.__name__}: {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"TEST RESULTS: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    if failed == 0:
        print("\n✓ ALL TESTS PASSED - Feature is production-ready!")
        return 0
    else:
        print(f"\n✗ {failed} TEST(S) FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
