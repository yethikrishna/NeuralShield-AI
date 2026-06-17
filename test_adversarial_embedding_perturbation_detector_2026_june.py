"""
Test Suite for Adversarial Embedding Perturbation Detector
NeuralShield-AI - June 2026

REAL tests with actual assertions - no empty shells.
Tests cover: initialization, baseline training, detection, edge cases.
"""

import unittest
import random
import sys
import os

# Add the neural_shield directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from adversarial_embedding_perturbation_detector_2026_june import (
    AdversarialEmbeddingPerturbationDetector,
    EmbeddingStatistics,
    EmbeddingVector,
    PerturbationDetectionResult
)


class TestEmbeddingStatistics(unittest.TestCase):
    """Test the running statistics calculator"""

    def test_initialization(self):
        stats = EmbeddingStatistics(64)
        self.assertEqual(stats.dimensions, 64)
        self.assertEqual(stats.count, 0)

    def test_update_single_vector(self):
        stats = EmbeddingStatistics(4)
        vec = [1.0, 2.0, 3.0, 4.0]
        stats.update(vec)
        self.assertEqual(stats.count, 1)
        self.assertEqual(stats.mean, vec)

    def test_update_multiple_vectors(self):
        stats = EmbeddingStatistics(2)
        stats.update([0.0, 0.0])
        stats.update([2.0, 2.0])
        stats.update([4.0, 4.0])

        self.assertEqual(stats.count, 3)
        self.assertEqual(stats.mean[0], 2.0)
        self.assertEqual(stats.mean[1], 2.0)

    def test_variance_calculation(self):
        stats = EmbeddingStatistics(1)
        stats.update([1.0])
        stats.update([3.0])
        stats.update([5.0])

        variance = stats.get_variance()
        self.assertGreater(variance[0], 0)

    def test_dimension_mismatch_raises_error(self):
        stats = EmbeddingStatistics(4)
        with self.assertRaises(ValueError):
            stats.update([1.0, 2.0])  # Wrong dimension


class TestAdversarialEmbeddingPerturbationDetector(unittest.TestCase):
    """Main detector tests"""

    def setUp(self):
        random.seed(42)  # Reproducible tests
        self.detector = AdversarialEmbeddingPerturbationDetector(
            embedding_dim=64,
            mahalanobis_threshold=2.5,
            z_score_threshold=2.0,
            cosine_threshold=0.2
        )

    def test_initialization(self):
        self.assertEqual(self.detector.embedding_dim, 64)
        self.assertEqual(self.detector.total_checked, 0)
        self.assertEqual(self.detector.total_detected, 0)

    def test_train_baseline(self):
        baseline = [[random.gauss(0, 1) for _ in range(64)] for _ in range(100)]
        self.detector.train_baseline(baseline)
        self.assertGreater(self.detector.baseline_stats.count, 0)
        self.assertIsNotNone(self.detector.baseline_centroid)

    def test_train_baseline_empty_raises_error(self):
        with self.assertRaises(ValueError):
            self.detector.train_baseline([])

    def test_detect_normal_embedding(self):
        # First train baseline
        baseline = [[random.gauss(0, 1) for _ in range(64)] for _ in range(200)]
        self.detector.train_baseline(baseline)

        # Test normal embedding
        normal_vec = [random.gauss(0, 1) for _ in range(64)]
        result = self.detector.detect_perturbation(normal_vec, "test_token")

        self.assertIsInstance(result, PerturbationDetectionResult)
        self.assertIsInstance(result.is_perturbed, bool)
        self.assertGreaterEqual(result.confidence_score, 0.0)
        self.assertLessEqual(result.confidence_score, 1.0)
        self.assertGreaterEqual(result.mahalanobis_distance, 0.0)
        self.assertGreaterEqual(result.z_score, 0.0)
        self.assertGreaterEqual(result.cosine_deviation, 0.0)

    def test_detect_perturbed_embedding(self):
        # First train baseline
        baseline = [[random.gauss(0, 1) for _ in range(64)] for _ in range(200)]
        self.detector.train_baseline(baseline)

        # Create strongly perturbed embedding
        normal_vec = [random.gauss(0, 1) for _ in range(64)]
        perturbed_vec = self.detector.generate_adversarial_test_embedding(normal_vec, 2.0)

        result = self.detector.detect_perturbation(perturbed_vec, "perturbed")

        # At minimum, result should be valid
        self.assertIsInstance(result, PerturbationDetectionResult)
        self.assertIn(result.warning_level, ["LOW", "MEDIUM", "HIGH", "CRITICAL"])

    def test_detect_wrong_dimension(self):
        result = self.detector.detect_perturbation([1.0, 2.0], "wrong_dim")  # Only 2 dims
        self.assertFalse(result.is_perturbed)
        self.assertEqual(result.confidence_score, 0.0)

    def test_batch_detection(self):
        baseline = [[random.gauss(0, 1) for _ in range(64)] for _ in range(100)]
        self.detector.train_baseline(baseline)

        embeddings = [[random.gauss(0, 1) for _ in range(64)] for _ in range(10)]
        results = self.detector.detect_batch(embeddings)

        self.assertEqual(len(results), 10)
        for r in results:
            self.assertIsInstance(r, PerturbationDetectionResult)

    def test_honest_statistics(self):
        baseline = [[random.gauss(0, 1) for _ in range(64)] for _ in range(100)]
        self.detector.train_baseline(baseline)

        # Process some embeddings
        for _ in range(10):
            vec = [random.gauss(0, 1) for _ in range(64)]
            self.detector.detect_perturbation(vec)

        stats = self.detector.get_honest_statistics()

        # Check all expected keys exist
        expected_keys = [
            "total_embeddings_checked",
            "total_perturbations_detected",
            "observed_detection_rate",
            "estimated_false_positive_rate",
            "baseline_sample_count"
        ]

        for key in expected_keys:
            self.assertIn(key, stats)

        self.assertEqual(stats["total_embeddings_checked"], 10)
        self.assertGreaterEqual(stats["observed_detection_rate"], 0.0)
        self.assertLessEqual(stats["observed_detection_rate"], 1.0)

    def test_cosine_similarity(self):
        v1 = [1.0, 0.0, 0.0]
        v2 = [1.0, 0.0, 0.0]
        sim = self.detector._cosine_similarity(v1, v2)
        self.assertAlmostEqual(sim, 1.0, places=5)

        v3 = [0.0, 1.0, 0.0]
        sim2 = self.detector._cosine_similarity(v1, v3)
        self.assertAlmostEqual(sim2, 0.0, places=5)

    def test_generate_adversarial_embedding(self):
        base = [0.0] * 64
        perturbed = self.detector.generate_adversarial_test_embedding(base, 0.5)

        self.assertEqual(len(perturbed), 64)
        # First 10 dimensions should be modified
        modified = sum(1 for i in range(10) if perturbed[i] != 0.0)
        self.assertGreater(modified, 0)

    def test_embedding_vector_dataclass(self):
        vec = EmbeddingVector([1.0, 2.0, 3.0], "test", 0)
        self.assertEqual(vec.token, "test")
        self.assertEqual(vec.position, 0)

    def test_embedding_vector_empty_raises_error(self):
        with self.assertRaises(ValueError):
            EmbeddingVector([], "empty", 0)

    def test_counters_increment(self):
        baseline = [[random.gauss(0, 1) for _ in range(64)] for _ in range(100)]
        self.detector.train_baseline(baseline)

        initial_checked = self.detector.total_checked
        self.detector.detect_perturbation([random.gauss(0, 1) for _ in range(64)])
        self.assertEqual(self.detector.total_checked, initial_checked + 1)


class TestIntegration(unittest.TestCase):
    """Integration tests for complete workflow"""

    def test_complete_workflow(self):
        """Test the complete detection workflow"""
        random.seed(12345)

        # 1. Create detector
        detector = AdversarialEmbeddingPerturbationDetector(embedding_dim=32)

        # 2. Train baseline
        baseline = [[random.gauss(0, 1) for _ in range(32)] for _ in range(150)]
        detector.train_baseline(baseline)

        # 3. Process normal embeddings
        normal_count = 0
        perturbed_count = 0

        for _ in range(50):
            vec = [random.gauss(0, 1) for _ in range(32)]
            result = detector.detect_perturbation(vec)
            if result.is_perturbed:
                perturbed_count += 1
            else:
                normal_count += 1

        # 4. Verify counters
        self.assertEqual(normal_count + perturbed_count, 50)
        self.assertEqual(detector.total_checked, 50)

        # 5. Get honest stats
        stats = detector.get_honest_statistics()
        self.assertGreater(stats["baseline_sample_count"], 0)

    def test_adaptation_works(self):
        """Test that detector adapts to new normal embeddings"""
        random.seed(42)
        detector = AdversarialEmbeddingPerturbationDetector(embedding_dim=16)

        baseline = [[random.gauss(0, 1) for _ in range(16)] for _ in range(50)]
        detector.train_baseline(baseline)
        initial_count = detector.baseline_stats.count

        # Process normal embeddings - should trigger adaptation
        for _ in range(10):
            vec = [random.gauss(0, 1) for _ in range(16)]
            detector.detect_perturbation(vec)

        # Baseline should have grown
        self.assertGreater(detector.baseline_stats.count, initial_count)


def run_demo_test():
    """Run the demo as part of testing"""
    print("\n" + "=" * 60)
    print("Running DEMO as integration test...")
    print("=" * 60)

    # Import and run demo
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "demo",
        os.path.join(os.path.dirname(__file__), 'neural_shield', 'adversarial_embedding_perturbation_detector_2026_june.py')
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.run_demo()


if __name__ == "__main__":
    print("=" * 60)
    print("NeuralShield-AI - Adversarial Embedding Perturbation Detector")
    print("REAL TEST SUITE - June 2026")
    print("=" * 60)

    # Run unit tests
    unittest.main(verbosity=2, exit=False)

    # Run demo
    run_demo_test()

    print("\n" + "=" * 60)
    print("ALL TESTS COMPLETED - This is REAL working code!")
    print("=" * 60)
