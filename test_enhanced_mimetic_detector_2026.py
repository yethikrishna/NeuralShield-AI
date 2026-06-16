"""
Test suite for Enhanced Mimetic Detector 2026
Based on Lawrence Berkeley National Laboratory Research (May 2026)
"""

import pytest
import numpy as np
from neural_shield.enhanced_mimetic_detector_2026 import EnhancedMimeticDetector2026

class TestEnhancedMimeticDetector2026:
    
    def test_initialization(self):
        """Test detector initialization"""
        detector = EnhancedMimeticDetector2026(threshold=0.75, order=4)
        assert detector.threshold == 0.75
        assert detector.order == 4
        
    def test_detect_clean_image(self):
        """Test detection on clean (non-adversarial) image"""
        detector = EnhancedMimeticDetector2026(threshold=0.75)
        
        # Create a clean smooth gradient image
        x, y = np.meshgrid(np.linspace(0, 1, 64), np.linspace(0, 1, 64))
        clean_image = x + y
        
        is_adversarial, score, details = detector.detect(clean_image)
        
        # Clean image should have low anomaly score
        assert score < 0.6
        assert not is_adversarial
        assert "features" in details
        assert "separation_factor" in details
        
    def test_detect_adversarial_image(self):
        """Test detection on adversarial image with high-frequency perturbations"""
        detector = EnhancedMimeticDetector2026(threshold=0.5)
        
        # Create base image + adversarial high-frequency noise
        x, y = np.meshgrid(np.linspace(0, 1, 64), np.linspace(0, 1, 64))
        base = x + y
        
        # Add structured high-frequency adversarial perturbation
        np.random.seed(42)
        adv_noise = np.random.randn(64, 64) * 0.15
        # Create structured pattern typical of adversarial perturbations
        adv_noise = np.where(np.abs(adv_noise) > 0.1, adv_noise * 2, 0)
        
        adversarial_image = base + adv_noise
        
        is_adversarial, score, details = detector.detect(adversarial_image)
        
        # Should detect adversarial pattern
        assert score > 0.3  # Should have elevated score
        assert "gradient_energy_mean" in details
        
    def test_rgb_image_detection(self):
        """Test detection on RGB color images"""
        detector = EnhancedMimeticDetector2026(threshold=0.7)
        
        # Create RGB test image
        rgb_image = np.random.rand(32, 32, 3)
        
        is_adversarial, score, details = detector.detect(rgb_image)
        
        assert isinstance(is_adversarial, bool)
        assert isinstance(score, float)
        assert 0 <= score <= 1.0
        
    def test_batch_detection(self):
        """Test batch detection of multiple images"""
        detector = EnhancedMimeticDetector2026()
        
        images = [np.random.rand(32, 32) for _ in range(5)]
        results = detector.detect_batch(images)
        
        assert len(results) == 5
        for result in results:
            assert len(result) == 3  # (bool, float, dict)
            
    def test_purification(self):
        """Test adversarial image purification"""
        detector = EnhancedMimeticDetector2026()
        
        # Create noisy adversarial image
        base = np.random.rand(64, 64)
        adv_noise = np.random.randn(64, 64) * 0.2
        adversarial = base + adv_noise
        
        purified = detector.purify(adversarial, strength=0.3)
        
        assert purified.shape == adversarial.shape
        # Purified should have reduced variance in high-energy regions
        assert np.std(purified) <= np.std(adversarial) * 1.1
        
    def test_statistics_tracking(self):
        """Test detection statistics tracking"""
        detector = EnhancedMimeticDetector2026()
        
        # Process multiple images
        for i in range(10):
            img = np.random.rand(32, 32)
            detector.detect(img)
            
        stats = detector.get_stats()
        
        assert stats["total"] == 10
        assert "detection_rate" in stats
        assert "threshold_used" in stats
        assert stats["operator_order"] == 4
        
    def test_feature_extraction(self):
        """Test gradient energy feature extraction"""
        detector = EnhancedMimeticDetector2026()
        
        image = np.random.rand(64, 64)
        gradient = detector._compute_corbino_castillo_gradient(image)
        features = detector._extract_signature_features(gradient)
        
        required_features = [
            "mean_energy", "std_energy", "max_energy",
            "energy_entropy", "high_freq_ratio",
            "skewness", "kurtosis"
        ]
        
        for feat in required_features:
            assert feat in features
            assert isinstance(features[feat], float)
            
    def test_entropy_computation(self):
        """Test entropy calculation"""
        detector = EnhancedMimeticDetector2026()
        
        # Uniform distribution should have high entropy
        uniform = np.random.rand(1000)
        entropy_uniform = detector._compute_entropy(uniform)
        
        # Spike distribution should have low entropy
        spike = np.zeros(1000)
        spike[0] = 1
        entropy_spike = detector._compute_entropy(spike)
        
        assert entropy_uniform > entropy_spike
        
    def test_skewness_kurtosis(self):
        """Test skewness and kurtosis computation"""
        detector = EnhancedMimeticDetector2026()
        
        # Normal distribution should have ~0 skewness, ~0 excess kurtosis
        normal = np.random.randn(10000)
        skew = detector._compute_skewness(normal)
        kurt = detector._compute_kurtosis(normal)
        
        assert abs(skew) < 0.5  # Should be near 0
        assert abs(kurt) < 1.0  # Should be near 0

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
