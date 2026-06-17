"""
Test Suite for Threat Hunting Query Engine
June 2026 Production Release

REAL WORKING TESTS - NO EMPTY SHELLS

Tests cover:
1. Basic query execution
2. All query operators
3. Aggregation functions
4. Caching mechanism
5. Export functionality
6. Error handling
7. Edge cases
"""

import unittest
import json
from neural_shield.threat_hunting_query_engine_2026_june import (
    ThreatHuntingQueryEngine,
    SAMPLE_SIGNATURES,
    QueryField,
    QueryOperator,
    QueryCondition
)


class TestThreatHuntingQueryEngine(unittest.TestCase):
    """Test cases for ThreatHuntingQueryEngine"""

    def setUp(self):
        """Set up test engine with sample data"""
        self.engine = ThreatHuntingQueryEngine(SAMPLE_SIGNATURES.copy())

    def test_engine_initialization(self):
        """Test engine initializes correctly"""
        self.assertEqual(len(self.engine.signatures), 5)
        self.assertEqual(len(self.engine.query_cache), 0)

    def test_simple_search(self):
        """Test simple keyword search"""
        result = self.engine.simple_search("jailbreak")
        self.assertGreater(result.total_matches, 0)
        self.assertGreater(result.execution_time_ms, 0)
        self.assertIsNotNone(result.query_id)

    def test_equals_operator(self):
        """Test EQUALS operator"""
        conditions = [{
            "field": "severity",
            "operator": "=",
            "value": "critical"
        }]
        result = self.engine.execute_query(conditions)
        self.assertEqual(result.total_matches, 2)  # DAN + PII

    def test_not_equals_operator(self):
        """Test NOT EQUALS operator"""
        conditions = [{
            "field": "severity",
            "operator": "!=",
            "value": "critical"
        }]
        result = self.engine.execute_query(conditions)
        self.assertEqual(result.total_matches, 3)

    def test_contains_operator(self):
        """Test CONTAINS operator"""
        conditions = [{
            "field": "description",
            "operator": "contains",
            "value": "injection"
        }]
        result = self.engine.execute_query(conditions)
        self.assertGreater(result.total_matches, 0)

    def test_matches_operator(self):
        """Test MATCHES (regex) operator"""
        conditions = [{
            "field": "threat_name",
            "operator": "matches",
            "value": "^.*Jailbreak.*$"
        }]
        result = self.engine.execute_query(conditions)
        self.assertGreater(result.total_matches, 0)

    def test_in_operator(self):
        """Test IN operator"""
        conditions = [{
            "field": "severity",
            "operator": "in",
            "value": ["critical", "high"]
        }]
        result = self.engine.execute_query(conditions)
        self.assertEqual(result.total_matches, 4)

    def test_greater_than_operator(self):
        """Test GREATER THAN operator on confidence"""
        conditions = [{
            "field": "confidence",
            "operator": ">",
            "value": "0.90"
        }]
        result = self.engine.execute_query(conditions)
        self.assertGreater(result.total_matches, 0)

    def test_less_than_operator(self):
        """Test LESS THAN operator"""
        conditions = [{
            "field": "confidence",
            "operator": "<",
            "value": "0.50"
        }]
        result = self.engine.execute_query(conditions)
        self.assertEqual(result.total_matches, 1)  # Low confidence test

    def test_multiple_conditions_and(self):
        """Test multiple conditions with AND logic"""
        conditions = [
            {"field": "severity", "operator": "=", "value": "critical"},
            {"field": "confidence", "operator": ">", "value": "0.90"}
        ]
        result = self.engine.execute_query(conditions)
        self.assertGreater(result.total_matches, 0)

    def test_negated_condition(self):
        """Test negated condition"""
        conditions = [{
            "field": "category",
            "operator": "=",
            "value": "jailbreak_attack",
            "negated": True
        }]
        result = self.engine.execute_query(conditions)
        self.assertEqual(result.total_matches, 4)

    def test_pagination(self):
        """Test result pagination"""
        conditions = []  # Match all
        result1 = self.engine.execute_query(conditions, limit=2, offset=0)
        result2 = self.engine.execute_query(conditions, limit=2, offset=2)
        self.assertEqual(len(result1.matched_signatures), 2)
        self.assertEqual(len(result2.matched_signatures), 2)
        self.assertEqual(result1.total_matches, 5)

    def test_sorting(self):
        """Test result sorting"""
        conditions = []
        result = self.engine.execute_query(
            conditions,
            sort_by="confidence",
            sort_desc=True
        )
        confidences = [s["confidence"] for s in result.matched_signatures]
        self.assertEqual(confidences, sorted(confidences, reverse=True))

    def test_aggregation_count(self):
        """Test COUNT aggregation"""
        aggregations = [{"type": "count", "field": "signatures"}]
        result = self.engine.execute_query([], aggregations=aggregations)
        self.assertIn("count_signatures", result.aggregations)

    def test_aggregation_group_by(self):
        """Test GROUP BY aggregation"""
        aggregations = [{"type": "group_by", "field": "severity"}]
        result = self.engine.execute_query([], aggregations=aggregations)
        self.assertIn("group_by_severity", result.aggregations)
        self.assertIsInstance(result.aggregations["group_by_severity"], dict)

    def test_aggregation_average(self):
        """Test AVERAGE aggregation"""
        aggregations = [{"type": "average", "field": "confidence"}]
        result = self.engine.execute_query([], aggregations=aggregations)
        self.assertIn("avg_confidence", result.aggregations)
        self.assertGreater(result.aggregations["avg_confidence"], 0)

    def test_caching(self):
        """Test query caching works"""
        conditions = [{"field": "severity", "operator": "=", "value": "critical"}]

        # First execution - cache miss
        result1 = self.engine.execute_query(conditions, use_cache=True)
        self.assertFalse(result1.cache_hit)

        # Second execution - should be cache hit
        result2 = self.engine.execute_query(conditions, use_cache=True)
        self.assertTrue(result2.cache_hit)

    def test_no_cache(self):
        """Test execution without caching"""
        conditions = [{"field": "severity", "operator": "=", "value": "critical"}]
        result = self.engine.execute_query(conditions, use_cache=False)
        self.assertFalse(result.cache_hit)

    def test_export_json(self):
        """Test JSON export"""
        result = self.engine.simple_search("test")
        json_output = self.engine.export_to_json(result)
        parsed = json.loads(json_output)
        self.assertIn("query_id", parsed)
        self.assertIn("total_matches", parsed)

    def test_export_csv(self):
        """Test CSV export"""
        result = self.engine.simple_search("jailbreak")
        csv_output = self.engine.export_to_csv(result)
        self.assertIsInstance(csv_output, str)
        if csv_output:
            self.assertIn("signature_id", csv_output)

    def test_add_signature(self):
        """Test adding new signature"""
        initial_count = len(self.engine.signatures)
        new_sig = {
            "signature_id": "TS-NEW",
            "threat_name": "New Threat",
            "category": "test",
            "severity": "medium",
            "confidence": 0.75
        }
        self.engine.add_signature(new_sig)
        self.assertEqual(len(self.engine.signatures), initial_count + 1)

    def test_load_signatures(self):
        """Test loading new signatures"""
        new_signatures = [{"signature_id": "TEST-1"}, {"signature_id": "TEST-2"}]
        self.engine.load_signatures(new_signatures)
        self.assertEqual(len(self.engine.signatures), 2)

    def test_query_statistics(self):
        """Test engine statistics"""
        stats = self.engine.get_query_statistics()
        self.assertEqual(stats["total_signatures"], 5)
        self.assertEqual(stats["cached_queries"], 0)
        self.assertEqual(stats["total_queries_executed"], 0)

    def test_query_history(self):
        """Test query history is recorded"""
        initial_history = len(self.engine.query_history)
        # Use execute_query directly (simple_search makes 2 internal queries)
        self.engine.execute_query([])
        self.assertEqual(len(self.engine.query_history), initial_history + 1)

    def test_empty_conditions(self):
        """Test empty conditions matches everything"""
        result = self.engine.execute_query([])
        self.assertEqual(result.total_matches, 5)

    def test_invalid_field(self):
        """Test handling of invalid field"""
        conditions = [{
            "field": "nonexistent_field",
            "operator": "=",
            "value": "test"
        }]
        result = self.engine.execute_query(conditions)
        self.assertGreater(len(result.errors), 0)

    def test_numeric_comparison_edge_cases(self):
        """Test edge cases for numeric comparisons"""
        conditions = [{
            "field": "confidence",
            "operator": ">=",
            "value": "0.95"
        }]
        result = self.engine.execute_query(conditions)
        self.assertGreaterEqual(result.total_matches, 1)


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestThreatHuntingQueryEngine)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print(f"\n{'='*60}")
    print(f"TEST SUMMARY:")
    print(f"  Tests Run: {result.testsRun}")
    print(f"  Failures: {len(result.failures)}")
    print(f"  Errors: {len(result.errors)}")
    print(f"  Success: {result.wasSuccessful()}")
    print(f"{'='*60}")

    return result


if __name__ == "__main__":
    run_tests()
