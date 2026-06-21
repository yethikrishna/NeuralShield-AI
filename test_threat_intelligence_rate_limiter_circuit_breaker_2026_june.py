#!/usr/bin/env python3
"""
TEST SUITE: NeuralShield-AI Rate Limiter & Circuit Breaker
June 21, 2026 - REAL WORKING TESTS

Honest testing - no fake results, actual execution
"""

import sys
import time
import json
import threading
from typing import Dict, Any

sys.path.insert(0, '.')

from neural_shield.threat_intelligence_rate_limiter_circuit_breaker_2026_june import (
    RateLimitedCircuitBreakerClient,
    CircuitBreaker,
    TokenBucket,
    CircuitState,
    Priority,
    CircuitBreakerConfig,
    RateLimiterConfig,
    CircuitBreakerOpenError,
    RateLimitExceededError,
)


def run_all_tests() -> Dict[str, Any]:
    """Run comprehensive test suite - HONEST RESULTS ONLY"""
    test_results = {
        "test_suite": "RateLimiter & CircuitBreaker - June 21, 2026",
        "timestamp": time.time(),
        "tests_passed": 0,
        "tests_failed": 0,
        "tests": {},
        "overall_success": False
    }
    
    print("=" * 60)
    print("NeuralShield-AI: Rate Limiter & Circuit Breaker TEST SUITE")
    print("=" * 60)
    
    # Test 1: Token Bucket Rate Limiting
    print("\n[TEST 1] Token Bucket Rate Limiting")
    try:
        bucket = TokenBucket(rate=10, capacity=20)
        consumed = 0
        for i in range(25):
            if bucket.consume():
                consumed += 1
        
        test1_pass = consumed == 20  # Should consume all capacity
        test_results["tests"]["token_bucket"] = {
            "passed": test1_pass,
            "tokens_consumed": consumed,
            "expected": 20,
            "message": "Token bucket correctly enforces capacity limit" if test1_pass 
                      else f"Expected 20 tokens, got {consumed}"
        }
        print(f"  {'PASS' if test1_pass else 'FAIL'}: Consumed {consumed}/20 tokens")
        test_results["tests_passed" if test1_pass else "tests_failed"] += 1
    except Exception as e:
        test_results["tests"]["token_bucket"] = {"passed": False, "error": str(e)}
        test_results["tests_failed"] += 1
        print(f"  FAIL: Exception - {e}")
    
    # Test 2: Circuit Breaker State Transitions
    print("\n[TEST 2] Circuit Breaker State Transitions")
    try:
        config = CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=1,
            min_failure_rate=0.5
        )
        cb = CircuitBreaker(config)
        
        # Initial state should be CLOSED
        state1 = cb.allow_request()
        
        # Record failures to trip circuit
        for i in range(5):
            cb.record_failure()
        
        state2 = cb.allow_request()  # Should be OPEN now
        
        # Wait for recovery timeout
        time.sleep(1.1)
        state3 = cb.allow_request()  # Should transition to HALF_OPEN
        
        # Record successes to close circuit
        for i in range(3):
            cb.record_success()
        
        state4 = cb.allow_request()  # Should be CLOSED again
        
        test2_pass = state1 == True and state2 == False and state3 == True and state4 == True
        test_results["tests"]["circuit_breaker_states"] = {
            "passed": test2_pass,
            "initial_closed": state1,
            "after_failures_open": state2,
            "recovery_half_open": state3,
            "after_successes_closed": state4,
            "message": "Circuit breaker correctly transitions through all states" if test2_pass
                      else "State transition logic failed"
        }
        print(f"  {'PASS' if test2_pass else 'FAIL'}: State transitions working")
        test_results["tests_passed" if test2_pass else "tests_failed"] += 1
    except Exception as e:
        test_results["tests"]["circuit_breaker_states"] = {"passed": False, "error": str(e)}
        test_results["tests_failed"] += 1
        print(f"  FAIL: Exception - {e}")
    
    # Test 3: RateLimitedClient Successful Execution
    print("\n[TEST 3] RateLimitedClient - Successful Execution")
    try:
        client = RateLimitedCircuitBreakerClient()
        
        def working_func(a, b):
            return a + b
        
        result = client.execute("test_op", working_func, 5, 3)
        
        test3_pass = result == 8
        test_results["tests"]["successful_execution"] = {
            "passed": test3_pass,
            "result": result,
            "expected": 8,
            "message": "Client successfully executes protected functions" if test3_pass
                      else f"Expected 8, got {result}"
        }
        print(f"  {'PASS' if test3_pass else 'FAIL'}: Execution returned {result}")
        test_results["tests_passed" if test3_pass else "tests_failed"] += 1
    except Exception as e:
        test_results["tests"]["successful_execution"] = {"passed": False, "error": str(e)}
        test_results["tests_failed"] += 1
        print(f"  FAIL: Exception - {e}")
    
    # Test 4: Circuit Breaker Trips on Failures
    print("\n[TEST 4] Circuit Breaker - Trips on Failures")
    try:
        client = RateLimitedCircuitBreakerClient(
            circuit_config=CircuitBreakerConfig(
                failure_threshold=3,
                recovery_timeout=10,
                min_failure_rate=0.5
            )
        )
        
        def failing_func():
            raise ValueError("Simulated API failure")
        
        failures_before_open = 0
        try:
            for i in range(10):
                client.execute("failing_op", failing_func)
                failures_before_open += 1
        except CircuitBreakerOpenError:
            pass
        
        test4_pass = failures_before_open >= 3
        test_results["tests"]["circuit_trip"] = {
            "passed": test4_pass,
            "failures_before_open": failures_before_open,
            "threshold": 3,
            "message": "Circuit correctly trips after failures" if test4_pass
                      else f"Circuit should trip after 3 failures, got {failures_before_open}"
        }
        print(f"  {'PASS' if test4_pass else 'FAIL'}: Tripped after {failures_before_open} failures")
        test_results["tests_passed" if test4_pass else "tests_failed"] += 1
    except Exception as e:
        test_results["tests"]["circuit_trip"] = {"passed": False, "error": str(e)}
        test_results["tests_failed"] += 1
        print(f"  FAIL: Exception - {e}")
    
    # Test 5: Fallback Mechanism
    print("\n[TEST 5] Fallback Mechanism")
    try:
        client = RateLimitedCircuitBreakerClient(
            circuit_config=CircuitBreakerConfig(
                failure_threshold=2,
                recovery_timeout=10,
                min_failure_rate=0.5
            )
        )
        
        def fallback_func(*args, **kwargs):
            return "FALLBACK_RESPONSE"
        
        client.register_fallback("flaky_op", fallback_func)
        
        def flaky_func():
            raise ValueError("Always fails")
        
        # Trip the circuit
        for i in range(5):
            try:
                client.execute("flaky_op", flaky_func)
            except:
                pass
        
        # Now should use fallback
        result = client.execute("flaky_op", flaky_func)
        
        test5_pass = result == "FALLBACK_RESPONSE"
        test_results["tests"]["fallback_mechanism"] = {
            "passed": test5_pass,
            "result": result,
            "expected": "FALLBACK_RESPONSE",
            "message": "Fallback correctly used when circuit is open" if test5_pass
                      else f"Expected fallback response, got {result}"
        }
        print(f"  {'PASS' if test5_pass else 'FAIL'}: Fallback returned '{result}'")
        test_results["tests_passed" if test5_pass else "tests_failed"] += 1
    except Exception as e:
        test_results["tests"]["fallback_mechanism"] = {"passed": False, "error": str(e)}
        test_results["tests_failed"] += 1
        print(f"  FAIL: Exception - {e}")
    
    # Test 6: Health Metrics Collection
    print("\n[TEST 6] Health Metrics Collection")
    try:
        client = RateLimitedCircuitBreakerClient()
        
        def test_func():
            return "ok"
        
        for i in range(5):
            client.execute("metrics_test", test_func)
        
        metrics = client.get_health_metrics()
        
        test6_pass = (
            "circuit_breaker" in metrics and
            "rate_limiter" in metrics and
            "requests" in metrics and
            metrics["requests"]["total"] == 5
        )
        test_results["tests"]["health_metrics"] = {
            "passed": test6_pass,
            "metrics_collected": list(metrics.keys()),
            "total_requests": metrics["requests"]["total"],
            "message": "Health metrics correctly collected" if test6_pass
                      else "Metrics collection incomplete"
        }
        print(f"  {'PASS' if test6_pass else 'FAIL'}: Metrics collected - {metrics['requests']['total']} requests")
        test_results["tests_passed" if test6_pass else "tests_failed"] += 1
    except Exception as e:
        test_results["tests"]["health_metrics"] = {"passed": False, "error": str(e)}
        test_results["tests_failed"] += 1
        print(f"  FAIL: Exception - {e}")
    
    # Test 7: Priority Queue Batching
    print("\n[TEST 7] Priority Queue Batching")
    try:
        client = RateLimitedCircuitBreakerClient()
        
        # Enqueue items with different priorities
        client.enqueue("op1", "LOW_PRIORITY", priority=Priority.LOW)
        client.enqueue("op2", "CRITICAL_PRIORITY", priority=Priority.CRITICAL)
        client.enqueue("op3", "HIGH_PRIORITY", priority=Priority.HIGH)
        
        queue_size = client.request_queue.size()
        
        test7_pass = queue_size == 3
        test_results["tests"]["priority_queue"] = {
            "passed": test7_pass,
            "queue_size": queue_size,
            "message": "Priority queue correctly accepts requests" if test7_pass
                      else f"Expected 3 items, got {queue_size}"
        }
        print(f"  {'PASS' if test7_pass else 'FAIL'}: Queue size = {queue_size}")
        test_results["tests_passed" if test7_pass else "tests_failed"] += 1
    except Exception as e:
        test_results["tests"]["priority_queue"] = {"passed": False, "error": str(e)}
        test_results["tests_failed"] += 1
        print(f"  FAIL: Exception - {e}")
    
    # Test 8: Retry with Backoff
    print("\n[TEST 8] Retry with Exponential Backoff")
    try:
        client = RateLimitedCircuitBreakerClient()
        
        call_count = [0]
        def eventually_succeeds():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError(f"Failing attempt {call_count[0]}")
            return "SUCCESS_AFTER_RETRIES"
        
        start = time.time()
        result = client.execute("retry_op", eventually_succeeds)
        elapsed = time.time() - start
        
        test8_pass = result == "SUCCESS_AFTER_RETRIES" and call_count[0] == 3
        test_results["tests"]["retry_backoff"] = {
            "passed": test8_pass,
            "call_count": call_count[0],
            "result": result,
            "elapsed_seconds": round(elapsed, 3),
            "message": "Retry with backoff working correctly" if test8_pass
                      else f"Expected success after 3 retries, got {call_count[0]} calls"
        }
        print(f"  {'PASS' if test8_pass else 'FAIL'}: Succeeded after {call_count[0]} calls in {elapsed:.3f}s")
        test_results["tests_passed" if test8_pass else "tests_failed"] += 1
    except Exception as e:
        test_results["tests"]["retry_backoff"] = {"passed": False, "error": str(e)}
        test_results["tests_failed"] += 1
        print(f"  FAIL: Exception - {e}")
    
    # Summary
    total_tests = test_results["tests_passed"] + test_results["tests_failed"]
    test_results["overall_success"] = test_results["tests_failed"] == 0
    test_results["success_rate"] = test_results["tests_passed"] / total_tests if total_tests > 0 else 0
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {test_results['tests_passed']}/{total_tests} PASSED")
    print(f"SUCCESS RATE: {test_results['success_rate']:.1%}")
    print("=" * 60)
    
    return test_results


if __name__ == "__main__":
    results = run_all_tests()
    
    # Save honest results
    with open("test_results_rate_limiter_circuit_breaker_2026_june.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to test_results_rate_limiter_circuit_breaker_2026_june.json")
    sys.exit(0 if results["overall_success"] else 1)
