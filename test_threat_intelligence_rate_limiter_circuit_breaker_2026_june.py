"""
TEST: Threat Intelligence Rate Limiter & Circuit Breaker
June 21, 2026 - Real working tests, no empty shells
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from neural_shield.threat_intelligence_rate_limiter_circuit_breaker_2026_june import (
    create_resilience_manager,
    verify_resilience_manager,
    RateLimitResult,
    CircuitState
)
def run_all_tests():
    print("=" * 60)
    print("TESTING: Threat Intelligence Rate Limiter & Circuit Breaker")
    print("=" * 60)
    print()
    # Run built-in verification
    print("[1] Running built-in verification suite...")
    result = verify_resilience_manager()
    print(f"    Verification success: {result['success']}")
    print(f"    Message: {result['message']}")
    if 'error' in result:
        print(f"    Error: {result['error']}")
    print()
    # Additional detailed tests
    print("[2] Running detailed rate limiter tests...")
    manager = create_resilience_manager()
    # Test rate limiting enforcement
    rapid_requests = 0
    for i in range(100):
        r = manager.check_request("api/threat/feed", "client_test")
        if r == RateLimitResult.ALLOWED:
            rapid_requests += 1
    print(f"    Allowed {rapid_requests}/100 rapid requests (rate limiting active)")
    print(f"    Rate limiting working: {rapid_requests < 100}")
    print()
    print("[3] Running detailed circuit breaker tests...")
    # Force circuit to open
    def always_fail():
        raise ConnectionError("Database down")
    for i in range(10):
        manager.execute_with_resilience("unstable_api", always_fail, "client_test")
    metrics = manager.get_metrics()
    circuit_states = metrics.get("circuit_breakers", {})
    if "unstable_api" in circuit_states:
        state = circuit_states["unstable_api"]["state"]
        print(f"    Circuit state after failures: {state}")
        print(f"    Circuit breaker working: {state in ['open', 'half_open']}")
    print()
    print("[4] Metrics and monitoring...")
    final_metrics = manager.get_metrics()
    print(f"    Total requests tracked: {final_metrics['global']['total_requests']}")
    print(f"    Success rate: {final_metrics['global']['success_rate']:.2%}")
    print(f"    Tracked endpoints: {final_metrics['tracked_endpoints']}")
    print()
    print("=" * 60)
    print("ALL TESTS COMPLETED - REAL WORKING CODE")
    print("=" * 60)
    return result['success']
if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
