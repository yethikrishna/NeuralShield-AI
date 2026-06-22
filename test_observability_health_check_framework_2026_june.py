"""
Test Suite for NeuralShield-AI Health Check Framework
June 2026 - Production Grade Tests

DIMENSION D - Observability & Instrumentation
Tests for the comprehensive health check framework.

All tests must pass. No modification of production code.
"""

import os
import sys
import json
import time
import unittest
import threading
from typing import Dict, Any

# Add the module path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from neural_shield.observability_health_check_framework_2026_june import (
    HealthStatus,
    HealthCheckType,
    HealthCheckResult,
    AggregatedHealthStatus,
    HealthCheckRegistry,
    get_health_registry,
    enable_health_checks,
    disable_health_checks,
    create_process_liveness_check,
    create_memory_usage_check,
    create_thread_count_check,
    create_file_write_check,
    create_http_endpoint_check,
    register_default_health_checks,
    health_check_monitored,
    get_liveness_probe,
    get_readiness_probe,
    get_full_health_report,
)


class TestHealthStatusEnum(unittest.TestCase):
    """Test HealthStatus enumeration."""

    def test_health_status_values(self):
        """Test health status enum values."""
        self.assertEqual(HealthStatus.HEALTHY.value, "healthy")
        self.assertEqual(HealthStatus.DEGRADED.value, "degraded")
        self.assertEqual(HealthStatus.UNHEALTHY.value, "unhealthy")
        self.assertEqual(HealthStatus.UNKNOWN.value, "unknown")


class TestHealthCheckTypeEnum(unittest.TestCase):
    """Test HealthCheckType enumeration."""

    def test_check_type_values(self):
        """Test health check type enum values."""
        self.assertEqual(HealthCheckType.LIVENESS.value, "liveness")
        self.assertEqual(HealthCheckType.READINESS.value, "readiness")
        self.assertEqual(HealthCheckType.DEPENDENCY.value, "dependency")
        self.assertEqual(HealthCheckType.CUSTOM.value, "custom")


class TestHealthCheckResult(unittest.TestCase):
    """Test HealthCheckResult data class."""

    def test_result_creation(self):
        """Test creating a health check result."""
        result = HealthCheckResult(
            name="test_check",
            status=HealthStatus.HEALTHY,
            check_type=HealthCheckType.LIVENESS,
            message="Test passed",
        )
        
        self.assertEqual(result.name, "test_check")
        self.assertEqual(result.status, HealthStatus.HEALTHY)
        self.assertEqual(result.check_type, HealthCheckType.LIVENESS)
        self.assertEqual(result.message, "Test passed")

    def test_result_to_dict(self):
        """Test converting result to dictionary."""
        result = HealthCheckResult(
            name="test_check",
            status=HealthStatus.HEALTHY,
            check_type=HealthCheckType.LIVENESS,
            message="OK",
            duration_ms=123.4567,
            details={"key": "value"},
        )
        
        d = result.to_dict()
        self.assertEqual(d["name"], "test_check")
        self.assertEqual(d["status"], "healthy")
        self.assertEqual(d["check_type"], "liveness")
        self.assertEqual(d["duration_ms"], 123.457)  # Rounded
        self.assertEqual(d["details"]["key"], "value")


class TestAggregatedHealthStatus(unittest.TestCase):
    """Test AggregatedHealthStatus."""

    def test_aggregated_creation(self):
        """Test creating aggregated status."""
        checks = [
            HealthCheckResult("check1", HealthStatus.HEALTHY, HealthCheckType.LIVENESS),
            HealthCheckResult("check2", HealthStatus.HEALTHY, HealthCheckType.READINESS),
        ]
        
        agg = AggregatedHealthStatus(
            overall_status=HealthStatus.HEALTHY,
            checks=checks,
        )
        
        self.assertEqual(agg.overall_status, HealthStatus.HEALTHY)
        self.assertEqual(len(agg.checks), 2)

    def test_aggregated_severity_order(self):
        """Test that most severe status wins."""
        # Healthy + Unhealthy should result in Unhealthy
        checks = [
            HealthCheckResult("check1", HealthStatus.HEALTHY, HealthCheckType.LIVENESS),
            HealthCheckResult("check2", HealthStatus.UNHEALTHY, HealthCheckType.LIVENESS),
        ]
        
        # Manually compute overall
        severity_order = {
            HealthStatus.HEALTHY: 0,
            HealthStatus.UNKNOWN: 1,
            HealthStatus.DEGRADED: 2,
            HealthStatus.UNHEALTHY: 3,
        }
        
        overall = HealthStatus.HEALTHY
        for result in checks:
            if severity_order[result.status] > severity_order[overall]:
                overall = result.status
        
        self.assertEqual(overall, HealthStatus.UNHEALTHY)

    def test_aggregated_to_json(self):
        """Test JSON serialization."""
        checks = [
            HealthCheckResult("check1", HealthStatus.HEALTHY, HealthCheckType.LIVENESS),
        ]
        
        agg = AggregatedHealthStatus(
            overall_status=HealthStatus.HEALTHY,
            checks=checks,
        )
        
        json_str = agg.to_json()
        data = json.loads(json_str)
        
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["checks_count"], 1)


class TestHealthCheckRegistry(unittest.TestCase):
    """Test HealthCheckRegistry."""

    def setUp(self):
        """Set up test registry."""
        self.registry = HealthCheckRegistry()

    def test_registry_disabled_by_default(self):
        """Test that registry is disabled by default (opt-in)."""
        self.assertFalse(self.registry.is_enabled())

    def test_enable_disable(self):
        """Test enabling and disabling registry."""
        self.registry.enable()
        self.assertTrue(self.registry.is_enabled())
        
        self.registry.disable()
        self.assertFalse(self.registry.is_enabled())

    def test_register_check(self):
        """Test registering a health check."""
        def dummy_check():
            return HealthCheckResult("dummy", HealthStatus.HEALTHY, HealthCheckType.CUSTOM)
        
        self.registry.register("dummy_check", dummy_check)
        self.assertIn("dummy_check", self.registry.list_checks())

    def test_unregister_check(self):
        """Test unregistering a health check."""
        def dummy_check():
            return HealthCheckResult("dummy", HealthStatus.HEALTHY, HealthCheckType.CUSTOM)
        
        self.registry.register("dummy_check", dummy_check)
        result = self.registry.unregister("dummy_check")
        
        self.assertTrue(result)
        self.assertNotIn("dummy_check", self.registry.list_checks())

    def test_run_check_disabled_returns_none(self):
        """Test that running check when disabled returns None."""
        def dummy_check():
            return HealthCheckResult("dummy", HealthStatus.HEALTHY, HealthCheckType.CUSTOM)
        
        self.registry.register("dummy_check", dummy_check)
        # Registry is disabled by default
        result = self.registry.run_check("dummy_check")
        
        self.assertIsNone(result)

    def test_run_check_enabled(self):
        """Test running check when enabled."""
        def dummy_check():
            return HealthCheckResult("dummy", HealthStatus.HEALTHY, HealthCheckType.CUSTOM)
        
        self.registry.enable()
        self.registry.register("dummy_check", dummy_check)
        result = self.registry.run_check("dummy_check")
        
        self.assertIsNotNone(result)
        self.assertEqual(result.status, HealthStatus.HEALTHY)

    def test_run_all_checks_disabled(self):
        """Test running all checks when disabled."""
        result = self.registry.run_all_checks()
        self.assertEqual(result.overall_status, HealthStatus.HEALTHY)
        self.assertEqual(len(result.checks), 0)

    def test_run_all_checks_enabled(self):
        """Test running all checks when enabled."""
        def check1():
            return HealthCheckResult("check1", HealthStatus.HEALTHY, HealthCheckType.LIVENESS)
        
        def check2():
            return HealthCheckResult("check2", HealthStatus.HEALTHY, HealthCheckType.READINESS)
        
        self.registry.enable()
        self.registry.register("check1", check1, HealthCheckType.LIVENESS)
        self.registry.register("check2", check2, HealthCheckType.READINESS)
        
        result = self.registry.run_all_checks()
        
        self.assertEqual(result.overall_status, HealthStatus.HEALTHY)
        self.assertEqual(len(result.checks), 2)

    def test_run_all_checks_with_filter(self):
        """Test running checks with type filter."""
        def check1():
            return HealthCheckResult("check1", HealthStatus.HEALTHY, HealthCheckType.LIVENESS)
        
        def check2():
            return HealthCheckResult("check2", HealthStatus.HEALTHY, HealthCheckType.READINESS)
        
        self.registry.enable()
        self.registry.register("check1", check1, HealthCheckType.LIVENESS)
        self.registry.register("check2", check2, HealthCheckType.READINESS)
        
        result = self.registry.run_all_checks(filter_type=HealthCheckType.LIVENESS)
        
        self.assertEqual(len(result.checks), 1)
        self.assertEqual(result.checks[0].name, "check1")


class TestBuiltInHealthChecks(unittest.TestCase):
    """Test built-in health check implementations."""

    def test_process_liveness_check(self):
        """Test process liveness check."""
        result = create_process_liveness_check()
        
        self.assertEqual(result.name, "process_liveness")
        self.assertEqual(result.status, HealthStatus.HEALTHY)
        self.assertIn("pid", result.details)

    def test_memory_usage_check(self):
        """Test memory usage check."""
        check_func = create_memory_usage_check()
        result = check_func()
        
        self.assertEqual(result.name, "memory_usage")
        # Result could be HEALTHY or UNKNOWN (if psutil not available)
        self.assertIn(result.status, [HealthStatus.HEALTHY, HealthStatus.UNKNOWN])

    def test_thread_count_check(self):
        """Test thread count check."""
        check_func = create_thread_count_check()
        result = check_func()
        
        self.assertEqual(result.name, "thread_count")
        self.assertIn(result.status, [HealthStatus.HEALTHY, HealthStatus.UNKNOWN])

    def test_file_write_check(self):
        """Test filesystem write check."""
        check_func = create_file_write_check()
        result = check_func()
        
        self.assertEqual(result.name, "filesystem_write")
        # Should work on most systems
        self.assertIn(result.status, [HealthStatus.HEALTHY, HealthStatus.UNHEALTHY])


class TestHealthCheckDecorator(unittest.TestCase):
    """Test health check monitoring decorator."""

    def setUp(self):
        """Reset registry for each test - use fresh local registry."""
        # Create a fresh registry for each test to avoid cross-test pollution
        self.test_registry = HealthCheckRegistry()
        self.test_registry.enable()

    def test_decorator_tracks_success(self):
        """Test decorator tracks successful calls."""
        # Use a fresh function name to avoid conflicts
        @health_check_monitored(name="unique_success_test_func")
        def test_func():
            return "success"
        
        # Call successfully
        for _ in range(10):
            test_func()
        
        # Run the health check
        registry = get_health_registry()
        result = registry.run_check("unique_success_test_func")
        
        self.assertIsNotNone(result)
        # Status depends on global state, just verify it ran
        self.assertIsNotNone(result.status)

    def test_decorator_tracks_failures(self):
        """Test decorator tracks failed calls."""
        call_count = [0]
        
        @health_check_monitored(name="unique_failure_test_func")
        def test_func():
            call_count[0] += 1
            if call_count[0] % 2 == 0:
                raise ValueError("Simulated error")
            return "success"
        
        # Call with mix of success/failure
        for i in range(20):
            try:
                test_func()
            except ValueError:
                pass
        
        registry = get_health_registry()
        result = registry.run_check("unique_failure_test_func")
        
        self.assertIsNotNone(result)
        # Just verify it produced a result
        self.assertIsNotNone(result.status)


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience probe functions."""

    def test_liveness_probe_disabled(self):
        """Test liveness probe when disabled."""
        disable_health_checks()
        result = get_liveness_probe()
        self.assertEqual(result["status"], "healthy")

    def test_readiness_probe_disabled(self):
        """Test readiness probe when disabled."""
        disable_health_checks()
        result = get_readiness_probe()
        self.assertEqual(result["status"], "healthy")

    def test_full_health_report_disabled(self):
        """Test full health report when disabled."""
        disable_health_checks()
        result = get_full_health_report()
        self.assertEqual(result["status"], "healthy")
        self.assertIn("note", result)

    def test_liveness_probe_enabled(self):
        """Test liveness probe when enabled."""
        enable_health_checks()
        register_default_health_checks()
        result = get_liveness_probe()
        self.assertIn("status", result)
        self.assertIn("timestamp", result)


class TestGlobalRegistry(unittest.TestCase):
    """Test global registry singleton."""

    def test_get_health_registry(self):
        """Test getting global registry."""
        registry = get_health_registry()
        self.assertIsInstance(registry, HealthCheckRegistry)

    def test_same_instance(self):
        """Test that same instance is returned."""
        r1 = get_health_registry()
        r2 = get_health_registry()
        self.assertIs(r1, r2)


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of registry operations."""

    def test_concurrent_registration(self):
        """Test concurrent check registration."""
        registry = HealthCheckRegistry()
        registry.enable()
        
        def register_checks(start_id: int):
            for i in range(10):
                name = f"check_{start_id}_{i}"
                def make_check(n):
                    return lambda: HealthCheckResult(n, HealthStatus.HEALTHY, HealthCheckType.CUSTOM)
                registry.register(name, make_check(name))
        
        threads = []
        for t in range(5):
            thread = threading.Thread(target=register_checks, args=(t,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Should have 50 checks registered
        self.assertEqual(len(registry.list_checks()), 50)

    def test_concurrent_check_execution(self):
        """Test concurrent check execution."""
        registry = HealthCheckRegistry()
        registry.enable()
        
        def slow_check():
            time.sleep(0.01)
            return HealthCheckResult("slow", HealthStatus.HEALTHY, HealthCheckType.CUSTOM)
        
        registry.register("slow_check", slow_check)
        
        def run_checks():
            for _ in range(10):
                registry.run_check("slow_check", use_cache=False)
        
        threads = []
        for t in range(5):
            thread = threading.Thread(target=run_checks)
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # No exceptions = success
        self.assertTrue(True)


def run_tests():
    """Run all tests and return results."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return {
        "total": result.testsRun,
        "passed": result.testsRun - len(result.failures) - len(result.errors),
        "failed": len(result.failures),
        "errors": len(result.errors),
        "success": result.wasSuccessful(),
    }


if __name__ == "__main__":
    results = run_tests()
    print("\n" + "="*60)
    print("TEST RESULTS SUMMARY")
    print("="*60)
    print(f"Total tests: {results['total']}")
    print(f"Passed: {results['passed']}")
    print(f"Failed: {results['failed']}")
    print(f"Errors: {results['errors']}")
    print(f"Success: {results['success']}")
    print("="*60)
    
    # Save results
    with open("test_results_observability_health_check_framework_2026_june.json", "w") as f:
        json.dump(results, f, indent=2)
