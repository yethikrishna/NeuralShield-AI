"""
Test Suite for Threat Intelligence False Positive Classifier v84
DIMENSION A - Feature Expansion Tests
June 2026

ADD-ONLY TESTS - No modifications to existing tests
All existing tests must continue to pass
"""

import unittest
import sys
import os

# Add neural_shield to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from feature_expansion_fp_classifier_v84 import (
    EnsembleFalsePositiveClassifier,
    ClassificationResult,
    IOCContext,
    FalsePositiveCategory,
)


class TestFalsePositiveClassifierBasic(unittest.TestCase):
    """Basic functionality tests"""
    
    def setUp(self):
        self.classifier = EnsembleFalsePositiveClassifier(risk_appetite=0.5)
    
    def test_classifier_initialization(self):
        """Test classifier initializes correctly"""
        self.assertEqual(self.classifier.VERSION, "v84_2026_june")
        self.assertEqual(self.classifier.risk_appetite, 0.5)
        self.assertEqual(len(self.classifier.classification_cache), 0)
    
    def test_private_ip_classification(self):
        """Test private IP addresses are correctly identified as false positives"""
        result = self.classifier.classify_ioc("192.168.1.1", "ip")
        
        self.assertEqual(result.ioc_value, "192.168.1.1")
        self.assertEqual(result.ioc_type, "ip")
        self.assertTrue(result.confidence_score > 0.8)
        self.assertTrue(result.is_likely_false_positive())
        self.assertEqual(result.category, FalsePositiveCategory.INTERNAL_SERVICE)
    
    def test_localhost_classification(self):
        """Test localhost is highest confidence false positive"""
        result = self.classifier.classify_ioc("127.0.0.1", "ip")
        self.assertTrue(result.confidence_score > 0.9)
        self.assertTrue(result.is_likely_false_positive())


class TestUserAgentClassification(unittest.TestCase):
    """User agent based classification tests"""
    
    def setUp(self):
        self.classifier = EnsembleFalsePositiveClassifier()
    
    def test_googlebot_user_agent(self):
        """Test known good search engine crawlers"""
        context = IOCContext(
            user_agent="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        )
        result = self.classifier.classify_ioc("8.8.8.8", "ip", context)
        self.assertTrue(result.confidence_score > 0.7)
    
    def test_shodan_scanner_user_agent(self):
        """Test research scanner user agents"""
        context = IOCContext(
            user_agent="Mozilla/5.0 (compatible; Shodan/1.0; +https://www.shodan.io)"
        )
        result = self.classifier.classify_ioc("104.131.12.45", "ip", context)
        self.assertTrue(result.confidence_score > 0.7)


class TestBatchProcessing(unittest.TestCase):
    """Batch processing tests"""
    
    def setUp(self):
        self.classifier = EnsembleFalsePositiveClassifier()
    
    def test_batch_classification(self):
        """Test batch processing works correctly"""
        iocs = [
            ("192.168.1.1", "ip"),
            ("10.0.0.1", "ip"),
            ("127.0.0.1", "ip"),
        ]
        
        results = self.classifier.classify_batch(iocs)
        self.assertEqual(len(results), 3)
        for result in results:
            self.assertIsInstance(result, ClassificationResult)
    
    def test_caching_works(self):
        """Test caching reduces processing time on repeated calls"""
        result1 = self.classifier.classify_ioc("192.168.1.1", "ip")
        stats1 = self.classifier.get_statistics()
        
        result2 = self.classifier.classify_ioc("192.168.1.1", "ip")
        stats2 = self.classifier.get_statistics()
        
        self.assertEqual(stats2["cache_hits"], 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
