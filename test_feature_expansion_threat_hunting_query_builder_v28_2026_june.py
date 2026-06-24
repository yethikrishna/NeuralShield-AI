#!/usr/bin/env python3
"""
Test suite for Threat Hunting Query Builder v28
Dimension A - Feature Expansion
ADD-ONLY TESTS - no production code modified
All existing tests continue to pass
"""
import sys
import os
import json
import unittest
from typing import Dict, List

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from feature_expansion_threat_hunting_query_builder_v28_2026_june import (
    ThreatHuntingQueryBuilder,
    SIEMPlatform,
    HuntingCategory,
    QueryTuningLevel,
    HuntingQuery,
    create_hunting_query_builder,
    quick_hunt_query
)


class TestThreatHuntingQueryBuilder(unittest.TestCase):
    """Test cases for ThreatHuntingQueryBuilder"""

    def setUp(self):
        """Set up test fixtures"""
        self.builder = ThreatHuntingQueryBuilder()

    def test_builder_initialization(self):
        """Test builder initializes with correct defaults"""
        self.assertIsNotNone(self.builder)
        self.assertEqual(self.builder.default_time_range, "-24h")
        self.assertEqual(self.builder.tuning_level, QueryTuningLevel.OPTIMIZED)
        self.assertIsInstance(self.builder._templates, dict)
        self.assertGreater(len(self.builder._templates), 0)

    def test_build_splunk_lateral_movement_query(self):
        """Test building Splunk query for lateral movement"""
        query = self.builder.build_query(
            HuntingCategory.LATERAL_MOVEMENT,
            SIEMPlatform.SPLUNK
        )
        
        self.assertIsNotNone(query)
        self.assertIsInstance(query, HuntingQuery)
        self.assertEqual(query.category, HuntingCategory.LATERAL_MOVEMENT)
        self.assertEqual(query.platform, SIEMPlatform.SPLUNK)
        self.assertIn("index=windows", query.query_text)
        self.assertIn("EventCode=4624", query.query_text)
        self.assertGreater(len(query.query_id), 0)

    def test_build_sentinel_c2_query(self):
        """Test building Microsoft Sentinel query for C2 detection"""
        query = self.builder.build_query(
            HuntingCategory.COMMAND_AND_CONTROL,
            SIEMPlatform.MICROSOFT_SENTINEL
        )
        
        self.assertIsNotNone(query)
        self.assertEqual(query.severity, "CRITICAL")
        self.assertIn("CommonSecurityLog", query.query_text)
        self.assertIn("has_any", query.query_text)

    def test_build_splunk_persistence_query(self):
        """Test building Splunk query for persistence detection"""
        query = self.builder.build_query(
            HuntingCategory.PERSISTENCE,
            SIEMPlatform.SPLUNK
        )
        
        self.assertIsNotNone(query)
        self.assertIn("index=windows", query.query_text)
        self.assertIn("EventCode=13", query.query_text)

    def test_build_data_exfiltration_query(self):
        """Test building data exfiltration hunting query"""
        query = self.builder.build_query(
            HuntingCategory.DATA_EXFILTRATION,
            SIEMPlatform.SPLUNK
        )
        
        self.assertIsNotNone(query)
        self.assertEqual(query.severity, "HIGH")
        self.assertIn("bytes_out", query.query_text)

    def test_build_privilege_escalation_query(self):
        """Test building privilege escalation query"""
        query = self.builder.build_query(
            HuntingCategory.PRIVILEGE_ESCALATION,
            SIEMPlatform.MICROSOFT_SENTINEL
        )
        
        self.assertIsNotNone(query)
        self.assertIn("4672", query.query_text)

    def test_build_execution_query(self):
        """Test building execution detection query"""
        query = self.builder.build_query(
            HuntingCategory.EXECUTION,
            SIEMPlatform.SPLUNK
        )
        
        self.assertIsNotNone(query)
        self.assertIn("powershell", query.query_text.lower())

    def test_custom_parameters(self):
        """Test query building with custom parameters"""
        custom_params = {
            "threshold": 10,
            "unique_threshold": 20
        }
        
        query = self.builder.build_query(
            HuntingCategory.LATERAL_MOVEMENT,
            SIEMPlatform.SPLUNK,
            custom_params=custom_params
        )
        
        self.assertIsNotNone(query)
        self.assertTrue(query.metadata["custom_params_provided"])

    def test_build_all_for_platform(self):
        """Test building all queries for a specific platform"""
        queries = self.builder.build_all_for_platform(SIEMPlatform.SPLUNK)
        
        self.assertIsInstance(queries, list)
        self.assertGreater(len(queries), 0)
        for q in queries:
            self.assertEqual(q.platform, SIEMPlatform.SPLUNK)

    def test_query_to_dict(self):
        """Test query serialization to dictionary"""
        query = self.builder.build_query(
            HuntingCategory.LATERAL_MOVEMENT,
            SIEMPlatform.SPLUNK
        )
        
        q_dict = query.to_dict()
        self.assertIsInstance(q_dict, dict)
        self.assertIn("query_id", q_dict)
        self.assertIn("query_text", q_dict)
        self.assertIn("mitre_technique", q_dict)
        self.assertIn("severity", q_dict)

    def test_export_queries_json(self):
        """Test JSON export functionality"""
        queries = self.builder.build_all_for_platform(SIEMPlatform.SPLUNK)
        json_output = self.builder.export_queries(queries, "json")
        
        parsed = json.loads(json_output)
        self.assertIsInstance(parsed, list)
        self.assertEqual(len(parsed), len(queries))

    def test_validate_query_syntax(self):
        """Test query syntax validation"""
        query = self.builder.build_query(
            HuntingCategory.LATERAL_MOVEMENT,
            SIEMPlatform.SPLUNK
        )
        
        is_valid, errors = self.builder.validate_query_syntax(query)
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)

    def test_get_available_categories(self):
        """Test getting available hunting categories"""
        categories = self.builder.get_available_categories()
        
        self.assertIsInstance(categories, list)
        self.assertGreater(len(categories), 0)
        for cat in categories:
            self.assertIn("category", cat)
            self.assertIn("description", cat)
            self.assertIn("mitre_techniques", cat)
            self.assertIn("severity", cat)

    def test_performance_notes_added(self):
        """Test performance notes are added based on tuning level"""
        query = self.builder.build_query(
            HuntingCategory.LATERAL_MOVEMENT,
            SIEMPlatform.SPLUNK
        )
        
        self.assertGreater(len(query.performance_notes), 0)

    def test_high_performance_tuning(self):
        """Test high performance tuning configuration"""
        hp_builder = ThreatHuntingQueryBuilder({
            "tuning_level": "high_performance"
        })
        
        self.assertEqual(hp_builder.tuning_level, QueryTuningLevel.HIGH_PERFORMANCE)
        
        query = hp_builder.build_query(
            HuntingCategory.LATERAL_MOVEMENT,
            SIEMPlatform.SPLUNK
        )
        
        self.assertGreater(len(query.performance_notes), 1)

    def test_ioc_provider_registration(self):
        """Test IOC provider registration"""
        def mock_ioc_provider():
            return {"ips": ["1.2.3.4", "5.6.7.8"], "domains": ["evil.com"]}
        
        self.builder.register_ioc_provider("test", mock_ioc_provider)
        self.assertIn("test", self.builder._ioc_providers)

    def test_factory_function(self):
        """Test factory function creates valid instance"""
        instance = create_hunting_query_builder()
        self.assertIsInstance(instance, ThreatHuntingQueryBuilder)

    def test_quick_hunt_query_function(self):
        """Test convenience quick hunt query function"""
        result = quick_hunt_query(
            "lateral_movement",
            "splunk"
        )
        
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)
        self.assertIn("query_text", result)

    def test_quick_hunt_query_invalid_input(self):
        """Test quick hunt query handles invalid inputs gracefully"""
        result = quick_hunt_query("invalid_category", "invalid_platform")
        self.assertIsNone(result)

    def test_query_id_uniqueness(self):
        """Test generated query IDs are unique"""
        q1 = self.builder.build_query(HuntingCategory.LATERAL_MOVEMENT, SIEMPlatform.SPLUNK)
        q2 = self.builder.build_query(HuntingCategory.COMMAND_AND_CONTROL, SIEMPlatform.SPLUNK)
        
        self.assertNotEqual(q1.query_id, q2.query_id)

    def test_generated_queries_tracking(self):
        """Test builder tracks generated queries"""
        initial_count = len(self.builder.generated_queries)
        
        self.builder.build_query(HuntingCategory.LATERAL_MOVEMENT, SIEMPlatform.SPLUNK)
        self.builder.build_query(HuntingCategory.COMMAND_AND_CONTROL, SIEMPlatform.SPLUNK)
        
        self.assertEqual(len(self.builder.generated_queries), initial_count + 2)


class TestEdgeCases(unittest.TestCase):
    """Edge case tests for Query Builder"""

    def setUp(self):
        self.builder = ThreatHuntingQueryBuilder()

    def test_empty_custom_params(self):
        """Test with empty custom parameters dict"""
        query = self.builder.build_query(
            HuntingCategory.LATERAL_MOVEMENT,
            SIEMPlatform.SPLUNK,
            custom_params={}
        )
        self.assertIsNotNone(query)

    def test_ioc_injection_disabled(self):
        """Test with IOC injection disabled"""
        query = self.builder.build_query(
            HuntingCategory.LATERAL_MOVEMENT,
            SIEMPlatform.SPLUNK,
            inject_iocs=False
        )
        self.assertIsNotNone(query)
        self.assertFalse(query.metadata["ioc_injected"])

    def test_all_platforms_all_categories(self):
        """Test matrix of supported platforms and categories"""
        platforms = [SIEMPlatform.SPLUNK, SIEMPlatform.MICROSOFT_SENTINEL]
        categories = list(HuntingCategory)
        
        success_count = 0
        for platform in platforms:
            for category in categories:
                query = self.builder.build_query(category, platform)
                if query:
                    success_count += 1
        
        # Should have successful queries for most combinations
        self.assertGreater(success_count, 5)


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestThreatHuntingQueryBuilder))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result


if __name__ == "__main__":
    print("=" * 60)
    print("Threat Hunting Query Builder v28 - Test Suite")
    print("Dimension A: Feature Expansion")
    print("=" * 60)
    
    result = run_tests()
    
    print("\n" + "=" * 60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("=" * 60)
    
    sys.exit(0 if result.wasSuccessful() else 1)
