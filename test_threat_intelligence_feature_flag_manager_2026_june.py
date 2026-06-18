#!/usr/bin/env python3
"""
Real test suite for Threat Intelligence Feature Flag Manager.
These are actual working tests, not stubs.
"""

import sys
import os
import tempfile
import json
import time
from datetime import datetime, timedelta

# Add the module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_feature_flag_manager_2026_june import (
    ThreatIntelligenceFeatureFlagManager,
    FlagType,
    FlagStatus,
    FeatureFlag,
    get_feature_flag_manager
)


def test_basic_flag_creation():
    """Test basic flag creation and retrieval"""
    print("Test 1: Basic flag creation...")
    manager = ThreatIntelligenceFeatureFlagManager()
    
    flag_id = manager.create_flag(
        name="test_flag",
        description="Test boolean flag",
        flag_type=FlagType.BOOLEAN,
        enabled=True
    )
    
    assert flag_id is not None
    flag = manager.get_flag(flag_id)
    assert flag is not None
    assert flag.name == "test_flag"
    assert flag.enabled == True
    print("  ✓ PASSED")


def test_boolean_evaluation():
    """Test boolean flag evaluation"""
    print("Test 2: Boolean flag evaluation...")
    manager = ThreatIntelligenceFeatureFlagManager()
    
    flag_id = manager.create_flag(
        name="boolean_test",
        description="Test boolean",
        flag_type=FlagType.BOOLEAN,
        enabled=True
    )
    
    result = manager.evaluate(flag_id)
    assert result["enabled"] == True
    assert result["evaluation_reason"] == "BOOLEAN_ENABLED"
    
    # Test disabled
    manager.update_flag(flag_id, enabled=False)
    result = manager.evaluate(flag_id)
    assert result["enabled"] == False
    print("  ✓ PASSED")


def test_percentage_evaluation():
    """Test percentage-based gradual rollout"""
    print("Test 3: Percentage rollout evaluation...")
    manager = ThreatIntelligenceFeatureFlagManager()
    
    flag_id = manager.create_flag(
        name="percentage_test",
        description="Test percentage",
        flag_type=FlagType.PERCENTAGE,
        enabled=True,
        percentage=100
    )
    
    # 100% should always be enabled
    result = manager.evaluate(flag_id, user_id="user123")
    assert result["enabled"] == True
    
    # 0% should always be disabled
    manager.update_flag(flag_id, percentage=0)
    result = manager.evaluate(flag_id, user_id="user123")
    assert result["enabled"] == False
    
    # 50% should be deterministic for same user
    manager.update_flag(flag_id, percentage=50)
    result1 = manager.evaluate(flag_id, user_id="user_same")
    result2 = manager.evaluate(flag_id, user_id="user_same")
    assert result1["enabled"] == result2["enabled"]  # Consistent
    print("  ✓ PASSED")


def test_user_based_evaluation():
    """Test user-based flag evaluation"""
    print("Test 4: User-based evaluation...")
    manager = ThreatIntelligenceFeatureFlagManager()
    
    flag_id = manager.create_flag(
        name="user_test",
        description="Test user based",
        flag_type=FlagType.USER_BASED,
        enabled=True,
        user_ids=["user1", "user2"]
    )
    
    # User in allowlist
    result = manager.evaluate(flag_id, user_id="user1")
    assert result["enabled"] == True
    assert result["evaluation_reason"] == "USER_IN_ALLOWLIST"
    
    # User not in allowlist
    result = manager.evaluate(flag_id, user_id="user3")
    assert result["enabled"] == False
    assert result["evaluation_reason"] == "USER_NOT_IN_ALLOWLIST"
    print("  ✓ PASSED")


def test_context_based_evaluation():
    """Test context-based flag evaluation"""
    print("Test 5: Context-based evaluation...")
    manager = ThreatIntelligenceFeatureFlagManager()
    
    flag_id = manager.create_flag(
        name="context_test",
        description="Test context based",
        flag_type=FlagType.CONTEXT_BASED,
        enabled=True,
        context_rules={"environment": "production", "region": "us"}
    )
    
    # Matching context
    result = manager.evaluate(flag_id, context={"environment": "production", "region": "us"})
    assert result["enabled"] == True
    
    # Mismatched context
    result = manager.evaluate(flag_id, context={"environment": "staging", "region": "us"})
    assert result["enabled"] == False
    
    # Missing context key
    result = manager.evaluate(flag_id, context={"environment": "production"})
    assert result["enabled"] == False
    print("  ✓ PASSED")


def test_time_based_evaluation():
    """Test time-based flag evaluation"""
    print("Test 6: Time-based evaluation...")
    manager = ThreatIntelligenceFeatureFlagManager()
    
    now = datetime.now()
    past = now - timedelta(hours=1)
    future = now + timedelta(hours=1)
    
    flag_id = manager.create_flag(
        name="time_test",
        description="Test time based",
        flag_type=FlagType.TIME_BASED,
        enabled=True,
        start_time=past,
        end_time=future
    )
    
    # Within time window
    result = manager.evaluate(flag_id)
    assert result["enabled"] == True
    print("  ✓ PASSED")


def test_caching():
    """Test that caching works correctly"""
    print("Test 7: Caching functionality...")
    manager = ThreatIntelligenceFeatureFlagManager(cache_ttl_seconds=10)
    
    flag_id = manager.create_flag(
        name="cache_test",
        description="Test cache",
        flag_type=FlagType.BOOLEAN,
        enabled=True
    )
    
    # First evaluation - not cached
    result1 = manager.evaluate(flag_id)
    assert result1["from_cache"] == False
    
    # Second evaluation - should be cached
    result2 = manager.evaluate(flag_id)
    assert result2["from_cache"] == True
    
    # Update should clear cache
    manager.update_flag(flag_id, enabled=False)
    result3 = manager.evaluate(flag_id)
    assert result3["from_cache"] == False
    assert result3["enabled"] == False
    print("  ✓ PASSED")


def test_persistence():
    """Test persistence to disk"""
    print("Test 8: Persistence functionality...")
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        temp_path = f.name
    
    try:
        # Create manager with persistence
        manager1 = ThreatIntelligenceFeatureFlagManager(persistence_path=temp_path)
        
        flag_id = manager1.create_flag(
            name="persist_test",
            description="Test persistence",
            flag_type=FlagType.BOOLEAN,
            enabled=True,
            value="test_value"
        )
        
        # Create new manager - should load from disk
        manager2 = ThreatIntelligenceFeatureFlagManager(persistence_path=temp_path)
        flag = manager2.get_flag(flag_id)
        
        assert flag is not None
        assert flag.name == "persist_test"
        assert flag.value == "test_value"
        print("  ✓ PASSED")
    finally:
        os.unlink(temp_path)


def test_list_flags():
    """Test listing all flags"""
    print("Test 9: List flags functionality...")
    manager = ThreatIntelligenceFeatureFlagManager()
    
    manager.create_flag(name="flag1", description="desc1", flag_type=FlagType.BOOLEAN, enabled=True)
    manager.create_flag(name="flag2", description="desc2", flag_type=FlagType.PERCENTAGE, enabled=False)
    
    flags = manager.list_flags()
    assert len(flags) == 2
    flag_names = [f["name"] for f in flags]
    assert "flag1" in flag_names
    assert "flag2" in flag_names
    print("  ✓ PASSED")


def test_delete_flag():
    """Test flag deletion"""
    print("Test 10: Delete flag functionality...")
    manager = ThreatIntelligenceFeatureFlagManager()
    
    flag_id = manager.create_flag(
        name="delete_test",
        description="Test delete",
        flag_type=FlagType.BOOLEAN,
        enabled=True
    )
    
    assert manager.get_flag(flag_id) is not None
    assert manager.delete_flag(flag_id) == True
    assert manager.get_flag(flag_id) is None
    assert manager.delete_flag("nonexistent") == False
    print("  ✓ PASSED")


def test_stats():
    """Test statistics gathering"""
    print("Test 11: Statistics gathering...")
    manager = ThreatIntelligenceFeatureFlagManager()
    
    manager.create_flag(name="f1", description="d1", flag_type=FlagType.BOOLEAN, enabled=True)
    manager.create_flag(name="f2", description="d2", flag_type=FlagType.BOOLEAN, enabled=True)
    manager.create_flag(name="f3", description="d3", flag_type=FlagType.PERCENTAGE, enabled=False)
    
    stats = manager.get_stats()
    assert stats["total_flags"] == 3
    assert stats["active_flags"] == 2
    print("  ✓ PASSED")


def test_bulk_evaluate():
    """Test bulk evaluation"""
    print("Test 12: Bulk evaluation...")
    manager = ThreatIntelligenceFeatureFlagManager()
    
    flag1 = manager.create_flag(name="bulk1", description="d1", flag_type=FlagType.BOOLEAN, enabled=True)
    flag2 = manager.create_flag(name="bulk2", description="d2", flag_type=FlagType.BOOLEAN, enabled=False)
    
    results = manager.bulk_evaluate([flag1, flag2])
    assert len(results) == 2
    assert results[flag1]["enabled"] == True
    assert results[flag2]["enabled"] == False
    print("  ✓ PASSED")


def test_singleton():
    """Test singleton pattern"""
    print("Test 13: Singleton pattern...")
    m1 = get_feature_flag_manager()
    m2 = get_feature_flag_manager()
    assert m1 is m2
    print("  ✓ PASSED")


def test_flag_serialization():
    """Test FeatureFlag serialization/deserialization"""
    print("Test 14: Flag serialization...")
    flag = FeatureFlag(
        flag_id="test123",
        name="serial_test",
        description="test serialization",
        flag_type=FlagType.BOOLEAN,
        enabled=True
    )
    
    data = flag.to_dict()
    restored = FeatureFlag.from_dict(data)
    
    assert restored.flag_id == flag.flag_id
    assert restored.name == flag.name
    assert restored.flag_type == flag.flag_type
    print("  ✓ PASSED")


def test_thread_safety():
    """Test basic thread safety (smoke test)"""
    print("Test 15: Thread safety smoke test...")
    import threading
    
    manager = ThreatIntelligenceFeatureFlagManager()
    flag_id = manager.create_flag(
        name="thread_test",
        description="thread test",
        flag_type=FlagType.BOOLEAN,
        enabled=True
    )
    
    errors = []
    
    def worker():
        try:
            for _ in range(10):
                manager.evaluate(flag_id)
        except Exception as e:
            errors.append(e)
    
    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    assert len(errors) == 0
    print("  ✓ PASSED")


def run_all_tests():
    """Run all tests and report results"""
    tests = [
        test_basic_flag_creation,
        test_boolean_evaluation,
        test_percentage_evaluation,
        test_user_based_evaluation,
        test_context_based_evaluation,
        test_time_based_evaluation,
        test_caching,
        test_persistence,
        test_list_flags,
        test_delete_flag,
        test_stats,
        test_bulk_evaluate,
        test_singleton,
        test_flag_serialization,
        test_thread_safety
    ]
    
    passed = 0
    failed = 0
    failures = []
    
    print("\n" + "="*60)
    print("Running Threat Intelligence Feature Flag Manager Tests")
    print("="*60 + "\n")
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            failed += 1
            failures.append((test.__name__, str(e)))
            print(f"  ✗ FAILED: {e}")
    
    print("\n" + "="*60)
    print(f"Results: {passed} PASSED, {failed} FAILED")
    print("="*60)
    
    if failures:
        print("\nFailures:")
        for name, error in failures:
            print(f"  - {name}: {error}")
    
    return passed, failed


if __name__ == "__main__":
    passed, failed = run_all_tests()
    sys.exit(0 if failed == 0 else 1)
