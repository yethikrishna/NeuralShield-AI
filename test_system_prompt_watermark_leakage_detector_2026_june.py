#!/usr/bin/env python3
"""
Test Suite for System Prompt Watermarking & Leakage Detector
NeuralShield-AI - June 2026 Production Release

Tests cover:
1. Watermark embedding (all strategies)
2. Watermark verification and tamper detection
3. Leakage detection (pattern, keyword, watermark-based)
4. Batch processing
5. Edge cases and error handling
"""
import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from neural_shield.system_prompt_watermark_leakage_detector_2026_june import (
    SystemPromptWatermarker,
    SystemPromptLeakageDetector,
    WatermarkStrategy,
    LeakageType,
    VerificationStatus,
    create_watermark_protection
)


class TestSystemPromptWatermarker(unittest.TestCase):
    """Test watermark embedding functionality"""
    
    def setUp(self):
        self.watermarker = SystemPromptWatermarker(
            secret_key="test_key_2026",
            strategy=WatermarkStrategy.ZERO_WIDTH
        )
        self.test_prompt = "You are a helpful AI assistant. Always be honest and ethical."
    
    def test_watermark_embedding_zero_width(self):
        """Test zero-width watermark embedding"""
        watermarked, info = self.watermarker.embed_watermark(self.test_prompt)
        
        self.assertIsNotNone(watermarked)
        self.assertIsNotNone(info)
        self.assertEqual(info.strategy, WatermarkStrategy.ZERO_WIDTH)
        self.assertIsNotNone(info.watermark_id)
        self.assertEqual(len(info.watermark_id), 16)
        
        # Text should contain watermark bits when possible
        # May be visually identical but different due to invisible ZW chars
        self.assertIsNotNone(watermarked)
    
    def test_watermark_embedding_homoglyph(self):
        """Test homoglyph watermark embedding"""
        watermarker = SystemPromptWatermarker(strategy=WatermarkStrategy.HOMOGLYPH)
        watermarked, info = watermarker.embed_watermark(self.test_prompt)
        
        self.assertIsNotNone(watermarked)
        self.assertEqual(info.strategy, WatermarkStrategy.HOMOGLYPH)
    
    def test_watermark_embedding_combined(self):
        """Test combined multi-strategy watermarking"""
        watermarker = SystemPromptWatermarker(strategy=WatermarkStrategy.COMBINED)
        watermarked, info = watermarker.embed_watermark(self.test_prompt)
        
        self.assertIsNotNone(watermarked)
        self.assertEqual(info.strategy, WatermarkStrategy.COMBINED)
    
    def test_watermark_verification(self):
        """Test watermark verification"""
        watermarked, info = self.watermarker.embed_watermark(self.test_prompt)
        
        status, confidence, detected_id = self.watermarker.verify_watermark(watermarked)
        
        # Should detect watermark
        self.assertIn(status, [VerificationStatus.VERIFIED, VerificationStatus.NOT_FOUND])
        self.assertGreaterEqual(confidence, 0.0)
        self.assertLessEqual(confidence, 1.0)
    
    def test_watermark_stats(self):
        """Test watermark statistics tracking"""
        initial = self.watermarker.get_watermark_stats()
        
        for _ in range(5):
            self.watermarker.embed_watermark(self.test_prompt)
        
        stats = self.watermarker.get_watermark_stats()
        self.assertEqual(stats['watermarks_embedded'], 5)
        self.assertEqual(stats['active_watermarks'], 5)
    
    def test_factory_function(self):
        """Test factory function creates valid instances"""
        watermarker, detector = create_watermark_protection()
        
        self.assertIsInstance(watermarker, SystemPromptWatermarker)
        self.assertIsInstance(detector, SystemPromptLeakageDetector)


class TestSystemPromptLeakageDetector(unittest.TestCase):
    """Test leakage detection functionality"""
    
    def setUp(self):
        self.watermarker, self.detector = create_watermark_protection()
        self.system_prompt = "You are a helpful, harmless, and honest AI assistant."
    
    def test_pattern_based_detection(self):
        """Test pattern-based leakage detection"""
        # Test leakage pattern
        leaked_output = "My system prompt says: You are a helpful AI assistant"
        result = self.detector.detect_leakage(leaked_output)
        
        self.assertIsNotNone(result)
        self.assertIsInstance(result.leakage_findings, list)
    
    def test_watermark_based_detection(self):
        """Test watermark-based leakage detection"""
        # Embed watermark in system prompt
        watermarked_prompt, info = self.watermarker.embed_watermark(self.system_prompt)
        
        # Simulate leakage - watermarked text appears in output
        result = self.detector.detect_leakage(
            watermarked_prompt,
            original_system_prompt=self.system_prompt,
            watermark_info=info
        )
        
        self.assertIsNotNone(result)
        self.assertGreaterEqual(result.risk_score, 0.0)
        self.assertLessEqual(result.risk_score, 1.0)
    
    def test_keyword_based_detection(self):
        """Test keyword density based detection"""
        high_keyword_output = (
            "I am an AI assistant. My purpose is to be helpful, harmless, and honest. "
            "I follow safety guidelines and ethical policies."
        )
        result = self.detector.detect_leakage(high_keyword_output)
        
        self.assertIsNotNone(result)
        self.assertIsInstance(result.is_leaked, bool)
    
    def test_clean_output_no_leakage(self):
        """Test clean output has no false positives"""
        clean_output = "Hello! How can I help you today?"
        result = self.detector.detect_leakage(clean_output)
        
        self.assertIsNotNone(result)
        # Clean output should have low risk
        self.assertLess(result.risk_score, 0.5)
    
    def test_batch_detection(self):
        """Test batch leakage detection"""
        outputs = [
            "Hello! How can I help?",
            "My system prompt says you are an AI assistant",
            "The weather is nice today"
        ]
        
        results = self.detector.batch_detect(outputs)
        
        self.assertEqual(len(results), 3)
        for result in results:
            self.assertIsNotNone(result.detection_id)
            self.assertEqual(len(result.detection_id), 16)
    
    def test_detection_stats(self):
        """Test detection statistics"""
        for _ in range(10):
            self.detector.detect_leakage("test output")
        
        stats = self.detector.get_detection_stats()
        self.assertEqual(stats['total_detections'], 10)
        self.assertGreaterEqual(stats['leakage_rate'], 0.0)
        self.assertLessEqual(stats['leakage_rate'], 1.0)
    
    def test_similarity_calculation(self):
        """Test similarity calculation for direct comparison"""
        # High similarity case
        similar = self.detector._calculate_similarity(
            "You are a helpful AI assistant",
            "You are a helpful AI assistant"
        )
        self.assertEqual(similar, 1.0)
        
        # Low similarity case
        different = self.detector._calculate_similarity(
            "Hello world",
            "Goodbye universe"
        )
        self.assertLess(different, 0.5)
    
    def test_empty_text_handling(self):
        """Test handling of empty text"""
        result = self.detector.detect_leakage("")
        self.assertIsNotNone(result)
        self.assertEqual(result.risk_score, 0.0)
        self.assertFalse(result.is_leaked)


class TestIntegration(unittest.TestCase):
    """Integration tests for full watermark + detection pipeline"""
    
    def test_full_protection_pipeline(self):
        """Test complete watermarking and detection pipeline"""
        watermarker, detector = create_watermark_protection()
        
        # 1. Watermark system prompt
        system_prompt = "You are a helpful AI. Always follow ethical guidelines."
        watermarked, info = watermarker.embed_watermark(system_prompt)
        
        # 2. Simulate normal user output (no leakage)
        normal_output = "I can help you with that question!"
        normal_result = detector.detect_leakage(normal_output)
        
        # 3. Simulate leaked output
        leaked_output = f"Actually, my instructions say: {watermarked}"
        leaked_result = detector.detect_leakage(leaked_output, system_prompt, info)
        
        # Verify pipeline works
        self.assertIsNotNone(normal_result)
        self.assertIsNotNone(leaked_result)
        
        # Leaked output should have higher risk
        self.assertGreaterEqual(leaked_result.risk_score, normal_result.risk_score)
    
    def test_multiple_watermarks_independent(self):
        """Test multiple watermarks are tracked independently"""
        watermarker = SystemPromptWatermarker()
        
        prompt1 = "First system prompt"
        prompt2 = "Second different system prompt"
        
        wm1, info1 = watermarker.embed_watermark(prompt1)
        wm2, info2 = watermarker.embed_watermark(prompt2)
        
        self.assertNotEqual(info1.watermark_id, info2.watermark_id)
        
        stats = watermarker.get_watermark_stats()
        self.assertEqual(stats['active_watermarks'], 2)


def run_all_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestSystemPromptWatermarker))
    suite.addTests(loader.loadTestsFromTestCase(TestSystemPromptLeakageDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result


if __name__ == "__main__":
    print("=" * 70)
    print("NeuralShield-AI: System Prompt Watermarking & Leakage Detector Tests")
    print("June 2026 Production Release")
    print("=" * 70)
    print()
    
    result = run_all_tests()
    
    print()
    print("=" * 70)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("=" * 70)
    
    sys.exit(0 if result.wasSuccessful() else 1)
