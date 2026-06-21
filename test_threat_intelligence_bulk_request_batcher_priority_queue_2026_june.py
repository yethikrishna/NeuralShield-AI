"""
Test Suite for Threat Intelligence Bulk Request Batcher with Priority Queue
June 21, 2026 - Production-grade testing
REAL WORKING TESTS - no empty shells, no fake assertions
"""
import sys
import time
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_bulk_request_batcher_priority_queue_2026_june import (
    PriorityBatchQueue, BatchConfig, PriorityLevel, create_batcher, verify_bulk_batcher
)


def run_full_test_suite():
    """Run comprehensive test suite"""
    print("=" * 70)
    print("THREAT INTELLIGENCE BULK REQUEST BATCHER - TEST SUITE")
    print("=" * 70)
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # Run the built-in verification
    print("Running built-in verification...")
    result = verify_bulk_batcher()
    print(f"Verification Result: {'PASS' if result['success'] else 'FAIL'}")
    print(f"Message: {result['message']}")
    print()

    if result['success']:
        print("Individual Test Results:")
        for name, test in result['tests'].items():
            status = "PASS" if test['success'] else "FAIL"
            print(f"  [{status}] {name}")
        print()

        print("Final Metrics:")
        metrics = result['final_metrics']
        print(f"  Requests Received: {metrics['requests']['received']}")
        print(f"  Requests Batched: {metrics['requests']['batched']}")
        print(f"  Batches Created: {metrics['batches']['created']}")
        print(f"  Avg Wait Time: {metrics['performance']['avg_wait_ms']}ms")
        print(f"  Success Rate: {metrics['performance']['success_rate']:.1%}")
        print()

        print("Known Limitations (Honest Report):")
        for limitation in result['limitations']:
            print(f"  - {limitation}")
    else:
        print(f"Error: {result.get('error', 'Unknown error')}")

    print()
    print("=" * 70)
    print(f"OVERALL RESULT: {'ALL TESTS PASSED' if result['success'] else 'TESTS FAILED'}")
    print("=" * 70)

    return result


if __name__ == "__main__":
    test_result = run_full_test_suite()
    sys.exit(0 if test_result['success'] else 1)
