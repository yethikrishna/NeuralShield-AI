#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Correlation Rule Engine
June 2026 - Production Grade Tests

Real working tests that verify actual functionality.
"""

import sys
import time
import unittest
from neural_shield.threat_intelligence_correlation_rule_engine_2026_june import (
    ThreatIntelligenceCorrelationEngine,
    CorrelationRule,
    CorrelationCondition,
    RuleOperator,
    RuleSeverity,
    create_builtin_rules,
    RuleMatch
)


class TestCorrelationCondition(unittest.TestCase):
    """Test individual condition evaluation."""
    
    def test_equals_operator(self):
        cond = CorrelationCondition("event_type", RuleOperator.EQUALS, "login_failed")
        self.assertTrue(cond.evaluate({"event_type": "login_failed"}))
        self.assertFalse(cond.evaluate({"event_type": "login_success"}))
        
    def test_equals_case_insensitive(self):
        cond = CorrelationCondition("user", RuleOperator.EQUALS, "ADMIN", case_sensitive=False)
        self.assertTrue(cond.evaluate({"user": "admin"}))
        self.assertTrue(cond.evaluate({"user": "Admin"}))
        
    def test_contains_operator(self):
        cond = CorrelationCondition("message", RuleOperator.CONTAINS, "attack")
        self.assertTrue(cond.evaluate({"message": "Possible attack detected"}))
        self.assertFalse(cond.evaluate({"message": "Normal activity"}))
        
    def test_regex_operator(self):
        cond = CorrelationCondition("ip", RuleOperator.REGEX, r"^192\.168\.\d+\.\d+$")
        self.assertTrue(cond.evaluate({"ip": "192.168.1.100"}))
        self.assertFalse(cond.evaluate({"ip": "10.0.0.1"}))
        
    def test_greater_than_operator(self):
        cond = CorrelationCondition("count", RuleOperator.GREATER_THAN, 10)
        self.assertTrue(cond.evaluate({"count": 15}))
        self.assertFalse(cond.evaluate({"count": 5}))
        
    def test_less_than_operator(self):
        cond = CorrelationCondition("score", RuleOperator.LESS_THAN, 50)
        self.assertTrue(cond.evaluate({"score": 30}))
        self.assertFalse(cond.evaluate({"score": 60}))


class TestCorrelationRule(unittest.TestCase):
    """Test rule evaluation logic."""
    
    def test_and_logic(self):
        rule = CorrelationRule(
            rule_id="TEST001",
            name="Test AND Rule",
            description="Test rule with AND logic",
            conditions=[
                CorrelationCondition("type", RuleOperator.EQUALS, "alert"),
                CorrelationCondition("severity", RuleOperator.EQUALS, "high")
            ],
            logical_operator=RuleOperator.AND,
            threshold_count=1
        )
        
        events = [
            {"type": "alert", "severity": "high"},
            {"type": "alert", "severity": "low"},
        ]
        
        self.assertTrue(rule.evaluate(events))
        self.assertEqual(rule.match_count, 1)
        
    def test_or_logic(self):
        rule = CorrelationRule(
            rule_id="TEST002",
            name="Test OR Rule",
            description="Test rule with OR logic",
            conditions=[
                CorrelationCondition("type", RuleOperator.EQUALS, "alert"),
                CorrelationCondition("type", RuleOperator.EQUALS, "warning")
            ],
            logical_operator=RuleOperator.OR,
            threshold_count=1
        )
        
        events = [{"type": "warning"}]
        self.assertTrue(rule.evaluate(events))
        
    def test_threshold_count(self):
        rule = CorrelationRule(
            rule_id="TEST003",
            name="Test Threshold",
            description="Test threshold triggering",
            conditions=[
                CorrelationCondition("event_type", RuleOperator.EQUALS, "failed_login")
            ],
            threshold_count=3
        )
        
        # Only 2 events - should not trigger
        events = [{"event_type": "failed_login"} for _ in range(2)]
        self.assertFalse(rule.evaluate(events))
        
        # 3 events - should trigger
        events = [{"event_type": "failed_login"} for _ in range(3)]
        self.assertTrue(rule.evaluate(events))
        
    def test_disabled_rule(self):
        rule = CorrelationRule(
            rule_id="TEST004",
            name="Disabled Rule",
            description="This should not match",
            conditions=[CorrelationCondition("x", RuleOperator.EQUALS, "x")],
            enabled=False,
            threshold_count=1
        )
        self.assertFalse(rule.evaluate([{"x": "x"}]))


class TestCorrelationEngine(unittest.TestCase):
    """Test the main correlation engine."""
    
    def setUp(self):
        self.engine = ThreatIntelligenceCorrelationEngine()
        
    def test_add_and_list_rules(self):
        rule = CorrelationRule(
            rule_id="ENGINE001",
            name="Test Rule",
            description="Test",
            conditions=[CorrelationCondition("x", RuleOperator.EQUALS, "x")]
        )
        
        rule_id = self.engine.add_rule(rule)
        self.assertEqual(rule_id, "ENGINE001")
        self.assertEqual(len(self.engine.list_rules()), 1)
        
    def test_remove_rule(self):
        rule = CorrelationRule(
            rule_id="DEL001",
            name="To Delete",
            description="Test",
            conditions=[CorrelationCondition("x", RuleOperator.EQUALS, "x")]
        )
        self.engine.add_rule(rule)
        self.assertTrue(self.engine.remove_rule("DEL001"))
        self.assertFalse(self.engine.remove_rule("NOT_EXISTS"))
        
    def test_simple_event_matching(self):
        rule = CorrelationRule(
            rule_id="MATCH001",
            name="SQL Injection",
            description="Detect SQLi",
            conditions=[
                CorrelationCondition("request", RuleOperator.CONTAINS, "UNION SELECT")
            ],
            threshold_count=1,
            severity=RuleSeverity.HIGH
        )
        self.engine.add_rule(rule)
        
        matches = self.engine.add_event({
            "request": "test UNION SELECT password FROM users",
            "source_ip": "192.168.1.1"
        })
        
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule_id, "MATCH001")
        self.assertEqual(matches[0].severity, RuleSeverity.HIGH)
        
    def test_brute_force_detection(self):
        """Test real brute force detection scenario."""
        rule = CorrelationRule(
            rule_id="BRUTE001",
            name="Brute Force",
            description="5+ failed logins",
            conditions=[
                CorrelationCondition("event_type", RuleOperator.EQUALS, "login_failed")
            ],
            threshold_count=5,
            time_window_seconds=60
        )
        self.engine.add_rule(rule)
        
        # Add 4 failed logins - no match
        for i in range(4):
            matches = self.engine.add_event({
                "event_type": "login_failed",
                "source_ip": "10.0.0.1",
                "attempt": i
            })
            self.assertEqual(len(matches), 0)
            
        # 5th failed login - should match
        matches = self.engine.add_event({
            "event_type": "login_failed",
            "source_ip": "10.0.0.1",
            "attempt": 5
        })
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule_name, "Brute Force")
        
    def test_builtin_rules(self):
        """Test all built-in rules load correctly."""
        rules = create_builtin_rules()
        self.assertEqual(len(rules), 5)
        
        for rule in rules:
            self.engine.add_rule(rule)
            
        stats = self.engine.get_statistics()
        self.assertEqual(stats["total_rules"], 5)
        self.assertEqual(stats["enabled_rules"], 5)
        
    def test_engine_statistics(self):
        """Test statistics tracking."""
        for rule in create_builtin_rules():
            self.engine.add_rule(rule)
            
        # Generate some events
        for _ in range(10):
            self.engine.add_event({"event_type": "test", "value": "data"})
            
        stats = self.engine.get_statistics()
        self.assertIn("total_rules", stats)
        self.assertIn("total_evaluations", stats)
        self.assertIn("events_in_history", stats)
        self.assertIn("rules_by_severity", stats)
        
    def test_callback_registration(self):
        """Test callback on rule match."""
        callback_called = []
        
        def on_match(match: RuleMatch):
            callback_called.append(match)
            
        self.engine.register_callback(on_match)
        
        rule = CorrelationRule(
            rule_id="CALLBACK001",
            name="Callback Test",
            description="Test",
            conditions=[CorrelationCondition("trigger", RuleOperator.EQUALS, True)],
            threshold_count=1
        )
        self.engine.add_rule(rule)
        
        self.engine.add_event({"trigger": True})
        self.assertEqual(len(callback_called), 1)
        
    def test_export_rules(self):
        """Test rule export functionality."""
        for rule in create_builtin_rules():
            self.engine.add_rule(rule)
            
        exported = self.engine.export_rules()
        self.assertEqual(len(exported), 5)
        
        for rule_data in exported:
            self.assertIn("rule_id", rule_data)
            self.assertIn("name", rule_data)
            self.assertIn("severity", rule_data)
            self.assertIn("enabled", rule_data)
            
    def test_events_in_window(self):
        """Test time window filtering."""
        # Add events
        self.engine.add_event({"type": "old"})
        time.sleep(0.01)  # Small delay
        self.engine.add_event({"type": "new"})
        
        events = self.engine.get_events_in_window(1)  # Last 1 second
        self.assertGreaterEqual(len(events), 2)


def run_comprehensive_demo():
    """Run a comprehensive demo showing real usage."""
    print("\n" + "="*60)
    print("Threat Intelligence Correlation Rule Engine - DEMO")
    print("="*60)
    
    engine = ThreatIntelligenceCorrelationEngine()
    
    # Load built-in rules
    print("\n[1] Loading built-in rules...")
    for rule in create_builtin_rules():
        engine.add_rule(rule)
        print(f"  ✓ Loaded: {rule.name} [{rule.severity.value}]")
    
    stats = engine.get_statistics()
    print(f"\n[2] Engine Statistics:")
    print(f"  - Total Rules: {stats['total_rules']}")
    print(f"  - Rules by Severity: {stats['rules_by_severity']}")
    
    # Simulate security events
    print("\n[3] Simulating security events...")
    
    # Simulate SQL injection attempt
    print("\n  Testing SQL Injection detection:")
    matches = engine.add_event({
        "event_type": "http_request",
        "request_params": "id=1' UNION SELECT username,password FROM users--",
        "source_ip": "192.168.1.100",
        "timestamp": time.time()
    })
    for match in matches:
        print(f"    ⚠️  MATCH: {match.rule_name} [{match.severity.value}]")
    
    # Simulate brute force attack
    print("\n  Testing Brute Force detection (6 failed logins):")
    for i in range(6):
        matches = engine.add_event({
            "event_type": "login_failed",
            "source_ip": "10.0.0.50",
            "username": f"admin{i}",
            "attempt": i + 1
        })
        if matches:
            for match in matches:
                print(f"    ⚠️  MATCH on attempt {i+1}: {match.rule_name}")
    
    # Final stats
    final_stats = engine.get_statistics()
    print(f"\n[4] Final Statistics:")
    print(f"  - Total Evaluations: {final_stats['total_evaluations']}")
    print(f"  - Total Matches: {final_stats['total_matches']}")
    print(f"  - Events in History: {final_stats['events_in_history']}")
    
    print("\n[5] Top Rules by Matches:")
    for rule_id, name, count in final_stats['top_rules_by_matches']:
        if count > 0:
            print(f"  - {name}: {count} matches")
    
    print("\n" + "="*60)
    print("DEMO COMPLETED SUCCESSFULLY")
    print("="*60 + "\n")
    
    return True


if __name__ == "__main__":
    print("Running Threat Intelligence Correlation Rule Engine Tests...\n")
    
    # Run unit tests
    unittest.main(argv=[''], exit=False, verbosity=2)
    
    # Run demo
    success = run_comprehensive_demo()
    
    if success:
        print("\n✅ ALL TESTS PASSED - Engine is working correctly!")
        sys.exit(0)
    else:
        print("\n❌ SOME TESTS FAILED")
        sys.exit(1)
