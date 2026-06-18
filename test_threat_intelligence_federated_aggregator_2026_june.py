"""
Test suite for Threat Intelligence Federated Learning Aggregator
Production-grade tests for NeuralShield-AI
"""

import sys
import os
import time
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_federated_aggregator_2026_june import (
    ThreatIntelligenceFederatedAggregator,
    ClientUpdate,
    DifferentialPrivacyEngine,
    SecureWeightAggregator,
    ModelDriftDetector
)


def generate_client_signature(client_id: str, sample_count: int, timestamp: float) -> str:
    """Generate test client signature"""
    message = f"{client_id}:{sample_count}:{timestamp}"
    return hashlib.sha256(message.encode()).hexdigest()


def test_differential_privacy_engine():
    """Test Differential Privacy Engine"""
    print("=== Testing Differential Privacy Engine ===")
    
    dp_engine = DifferentialPrivacyEngine(epsilon=1.0, delta=1e-5)
    
    # Test noise addition
    original = [1.0, 2.0, 3.0, 4.0, 5.0]
    noisy = dp_engine.add_gaussian_noise(original)
    
    assert len(noisy) == len(original), "Noise should preserve length"
    assert dp_engine.privacy_budget_used > 0, "Privacy budget should be consumed"
    
    # Test gradient clipping
    large_gradients = [10.0, 20.0, 30.0]
    clipped = dp_engine.clip_gradients(large_gradients, clip_norm=5.0)
    
    import math
    norm = math.sqrt(sum(g * g for g in clipped))
    assert norm <= 5.01, f"Gradients should be clipped, got norm {norm}"
    
    # Test privacy budget check
    status = dp_engine.get_privacy_status()
    assert "epsilon_used" in status
    assert "remaining_budget" in status
    
    print("✓ Differential Privacy Engine tests passed")
    return True


def test_secure_weight_aggregator():
    """Test Secure Weight Aggregator"""
    print("\n=== Testing Secure Weight Aggregator ===")
    
    aggregator = SecureWeightAggregator()
    
    # Test secret sharing
    secret = [1.5, 2.5, 3.5]
    shares = aggregator.generate_shares(secret, num_shares=3)
    
    assert len(shares) == 3, "Should generate 3 shares"
    
    reconstructed = aggregator.reconstruct_secret(shares)
    
    for i in range(len(secret)):
        assert abs(reconstructed[i] - secret[i]) < 0.001, \
            f"Reconstruction failed at index {i}: {reconstructed[i]} != {secret[i]}"
    
    print("✓ Secure Weight Aggregator tests passed")
    return True


def test_model_drift_detector():
    """Test Model Drift Detector"""
    print("\n=== Testing Model Drift Detector ===")
    
    detector = ModelDriftDetector()
    
    # Test cosine similarity
    vec1 = [1.0, 0.0, 0.0]
    vec2 = [1.0, 0.0, 0.0]
    sim = detector.calculate_cosine_similarity(vec1, vec2)
    assert abs(sim - 1.0) < 0.001, "Identical vectors should have similarity 1"
    
    vec3 = [0.0, 1.0, 0.0]
    sim_ortho = detector.calculate_cosine_similarity(vec1, vec3)
    assert abs(sim_ortho) < 0.001, "Orthogonal vectors should have similarity 0"
    
    # Test weight distance
    weights1 = {"layer1": [1.0, 2.0], "layer2": [3.0, 4.0]}
    weights2 = {"layer1": [1.0, 2.0], "layer2": [3.0, 4.0]}
    distance = detector.calculate_weight_distance(weights1, weights2)
    assert distance < 0.001, "Identical weights should have 0 distance"
    
    print("✓ Model Drift Detector tests passed")
    return True


def test_federated_aggregator_registration():
    """Test client registration"""
    print("\n=== Testing Federated Aggregator - Registration ===")
    
    aggregator = ThreatIntelligenceFederatedAggregator(min_clients=2)
    
    # Test client registration
    result = aggregator.register_client("client_001")
    assert result["success"] == True, "First registration should succeed"
    
    # Test duplicate registration
    result_dup = aggregator.register_client("client_001")
    assert result_dup["success"] == False, "Duplicate registration should fail"
    
    metrics = aggregator.get_metrics()
    assert metrics["registered_clients"] == 1, "Should have 1 registered client"
    
    print("✓ Client registration tests passed")
    return True


def test_federated_aggregator_update_submission():
    """Test update submission flow"""
    print("\n=== Testing Federated Aggregator - Update Submission ===")
    
    aggregator = ThreatIntelligenceFederatedAggregator(min_clients=2)
    
    # Register clients
    aggregator.register_client("client_001")
    aggregator.register_client("client_002")
    
    # Create test update
    timestamp = time.time()
    weights = {
        "dense_1": [0.1, 0.2, 0.3, 0.4],
        "dense_2": [0.5, 0.6, 0.7]
    }
    
    update = ClientUpdate(
        client_id="client_001",
        model_weights=weights,
        sample_count=100,
        timestamp=timestamp,
        signature=generate_client_signature("client_001", 100, timestamp)
    )
    
    result = aggregator.submit_update(update)
    assert result["success"] == True, "Valid update should be accepted"
    
    # Test unregistered client
    update_bad = ClientUpdate(
        client_id="unregistered",
        model_weights=weights,
        sample_count=100,
        timestamp=timestamp,
        signature="bad_signature"
    )
    result_bad = aggregator.submit_update(update_bad)
    assert result_bad["success"] == False, "Unregistered client should be rejected"
    
    print("✓ Update submission tests passed")
    return True


def test_federated_aggregation():
    """Test full federated aggregation flow"""
    print("\n=== Testing Federated Aggregation ===")
    
    aggregator = ThreatIntelligenceFederatedAggregator(min_clients=2, aggregation_interval=0)
    
    # Register clients
    aggregator.register_client("client_001")
    aggregator.register_client("client_002")
    
    # Submit updates from both clients
    timestamp = time.time()
    
    weights1 = {
        "layer1": [0.1, 0.2, 0.3],
        "layer2": [0.4, 0.5]
    }
    update1 = ClientUpdate(
        client_id="client_001",
        model_weights=weights1,
        sample_count=100,
        timestamp=timestamp,
        signature=generate_client_signature("client_001", 100, timestamp)
    )
    
    weights2 = {
        "layer1": [0.2, 0.3, 0.4],
        "layer2": [0.5, 0.6]
    }
    update2 = ClientUpdate(
        client_id="client_002",
        model_weights=weights2,
        sample_count=200,
        timestamp=timestamp,
        signature=generate_client_signature("client_002", 200, timestamp)
    )
    
    aggregator.submit_update(update1)
    aggregator.submit_update(update2)
    
    # Perform aggregation
    result = aggregator.aggregate()
    
    assert result.participating_clients == 2, "Should have 2 participating clients"
    assert result.total_samples == 300, "Should have 300 total samples"
    assert len(result.aggregated_weights) == 2, "Should have aggregated weights for 2 layers"
    
    # Verify weights are averaged correctly (weighted by sample count)
    # Expected: (100*0.1 + 200*0.2) / 300 = 0.166... for first weight
    expected_first = (100 * 0.1 + 200 * 0.2) / 300
    actual_first = result.aggregated_weights["layer1"][0]
    
    # Allow for DP noise difference
    assert abs(actual_first - expected_first) < 0.1, "Weighted averaging should work correctly"
    
    metrics = aggregator.get_metrics()
    assert metrics["aggregations_performed"] == 1, "Should have performed 1 aggregation"
    
    print("✓ Federated aggregation tests passed")
    return True


def test_full_integration():
    """Test full integration flow"""
    print("\n=== Testing Full Integration ===")
    
    aggregator = ThreatIntelligenceFederatedAggregator(
        epsilon=0.1,  # Smaller epsilon per aggregation
        min_clients=2,
        aggregation_interval=0
    )
    
    # Simulate multi-round federated learning
    num_rounds = 3
    num_clients = 3
    
    for i in range(num_clients):
        aggregator.register_client(f"client_{i:03d}")
    
    for round_num in range(num_rounds):
        timestamp = time.time()
        
        # Submit updates for this round
        for i in range(num_clients):
            client_id = f"client_{i:03d}"
            weights = {
                "layer1": [0.1 + round_num * 0.01 + i * 0.001] * 4,
                "layer2": [0.5 + round_num * 0.01 + i * 0.001] * 3
            }
            update = ClientUpdate(
                client_id=client_id,
                model_weights=weights,
                sample_count=50 + i * 25,
                timestamp=timestamp,
                signature=generate_client_signature(client_id, 50 + i * 25, timestamp)
            )
            aggregator.submit_update(update)
        
        result = aggregator.aggregate()
        print(f"  Round {round_num + 1}: {result.participating_clients} clients, "
              f"{result.total_samples} samples, privacy budget: {result.privacy_budget_used:.2f}")
    
    final_metrics = aggregator.get_metrics()
    assert final_metrics["aggregations_performed"] == num_rounds
    
    print("✓ Full integration tests passed")
    return True


def main():
    """Run all tests"""
    print("=" * 60)
    print("Threat Intelligence Federated Learning Aggregator - Test Suite")
    print("=" * 60)
    
    tests = [
        test_differential_privacy_engine,
        test_secure_weight_aggregator,
        test_model_drift_detector,
        test_federated_aggregator_registration,
        test_federated_aggregator_update_submission,
        test_federated_aggregation,
        test_full_integration
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ {test.__name__} failed with exception: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
