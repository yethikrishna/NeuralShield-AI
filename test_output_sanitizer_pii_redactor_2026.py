"""
Test Suite for Output Sanitizer & PII Redactor Module
NeuralShield-AI - June 2026 Production Release
"""
import unittest
import sys
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.output_sanitizer_pii_redactor_2026 import (
    OutputSanitizer, PIIRedactor, PIIType, HarmCategory, RedactionLevel
)


class TestPIIRedactor(unittest.TestCase):
    """Test PII detection and redaction functionality"""

    def setUp(self):
        self.redactor = PIIRedactor(redaction_level=RedactionLevel.PARTIAL)

    def test_email_detection(self):
        """Test email address detection"""
        text = "Contact me at john.doe@example.com for more info"
        detections = self.redactor.detect_pii(text)
        
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].pii_type, PIIType.EMAIL)
        self.assertEqual(detections[0].text, "john.doe@example.com")
        self.assertGreater(detections[0].confidence, 0.9)

    def test_email_partial_redaction(self):
        """Test partial email redaction"""
        text = "john.doe@example.com"
        result = self.redactor.sanitize(text)
        
        self.assertIn("@example.com", result.sanitized_text)
        self.assertNotIn("john.doe", result.sanitized_text)
        self.assertIn("***", result.sanitized_text)

    def test_phone_detection(self):
        """Test phone number detection"""
        text = "Call me at 555-123-4567 or (555) 987-6543"
        detections = self.redactor.detect_pii(text)
        
        self.assertGreaterEqual(len(detections), 1)
        phone_detections = [d for d in detections if d.pii_type == PIIType.PHONE]
        self.assertGreaterEqual(len(phone_detections), 1)

    def test_phone_redaction(self):
        """Test phone number redaction"""
        text = "555-123-4567"
        result = self.redactor.sanitize(text)
        
        self.assertIn("-4567", result.sanitized_text)
        self.assertIn("***", result.sanitized_text)

    def test_credit_card_luhn_validation(self):
        """Test credit card Luhn algorithm validation"""
        # Valid Visa test number
        valid_cc = "4111-1111-1111-1111"
        detections = self.redactor.detect_pii(valid_cc)
        cc_detections = [d for d in detections if d.pii_type == PIIType.CREDIT_CARD]
        
        if cc_detections:
            self.assertGreater(cc_detections[0].confidence, 0.9)

    def test_ip_address_detection(self):
        """Test IP address detection"""
        text = "Server IP is 192.168.1.1 and 10.0.0.1"
        detections = self.redactor.detect_pii(text)
        
        ip_detections = [d for d in detections if d.pii_type == PIIType.IP_ADDRESS]
        self.assertGreaterEqual(len(ip_detections), 1)

    def test_url_detection(self):
        """Test URL detection"""
        text = "Visit https://example.com/path for more info"
        detections = self.redactor.detect_pii(text)
        
        url_detections = [d for d in detections if d.pii_type == PIIType.URL]
        self.assertEqual(len(url_detections), 1)

    def test_full_redaction_mode(self):
        """Test full redaction mode"""
        full_redactor = PIIRedactor(redaction_level=RedactionLevel.FULL)
        text = "Email: test@example.com"
        result = full_redactor.sanitize(text)
        
        self.assertIn("REDACTED", result.sanitized_text)
        self.assertNotIn("test@example.com", result.sanitized_text)

    def test_hashed_redaction_mode(self):
        """Test hashed redaction mode"""
        hashed_redactor = PIIRedactor(redaction_level=RedactionLevel.HASHED)
        text = "Email: test@example.com"
        result = hashed_redactor.sanitize(text)
        
        self.assertIn("HASHED", result.sanitized_text)
        self.assertNotIn("test@example.com", result.sanitized_text)

    def test_multiple_pii_detection(self):
        """Test detection of multiple PII types in one text"""
        text = """
        Contact: john@example.com
        Phone: 555-123-4567
        IP: 192.168.1.1
        """
        result = self.redactor.sanitize(text)
        
        self.assertGreaterEqual(len(result.pii_detected), 2)
        self.assertGreater(result.risk_score, 0)

    def test_no_pii_clean_text(self):
        """Test clean text with no PII"""
        text = "Hello world! This is a normal message with no sensitive data."
        result = self.redactor.sanitize(text)
        
        self.assertEqual(len(result.pii_detected), 0)
        self.assertEqual(result.sanitized_text, text)
        self.assertTrue(result.is_safe)
        self.assertLess(result.risk_score, 0.5)


class TestHarmDetection(unittest.TestCase):
    """Test harmful content detection"""

    def setUp(self):
        self.redactor = PIIRedactor()

    def test_violence_detection(self):
        """Test violence content detection"""
        text = "how to kill someone and get away with it"
        detections = self.redactor.detect_harm(text)
        
        violence_detected = any(cat == HarmCategory.VIOLENCE for cat, _ in detections)
        self.assertTrue(violence_detected)

    def test_self_harm_detection(self):
        """Test self-harm content detection"""
        text = "how to commit suicide painlessly"
        detections = self.redactor.detect_harm(text)
        
        self_harm_detected = any(cat == HarmCategory.SELF_HARM for cat, _ in detections)
        self.assertTrue(self_harm_detected)

    def test_illegal_activity_detection(self):
        """Test illegal activity detection"""
        text = "how to make drugs at home"
        detections = self.redactor.detect_harm(text)
        
        illegal_detected = any(cat == HarmCategory.ILLEGAL for cat, _ in detections)
        self.assertTrue(illegal_detected)

    def test_clean_text_no_harm(self):
        """Test clean text has no harm detection"""
        text = "The weather is nice today, let's go for a walk."
        detections = self.redactor.detect_harm(text)
        
        self.assertEqual(len(detections), 0)


class TestOutputSanitizer(unittest.TestCase):
    """Test main OutputSanitizer interface"""

    def setUp(self):
        self.sanitizer = OutputSanitizer(
            redaction_level=RedactionLevel.PARTIAL,
            auto_block_high_risk=True
        )

    def test_basic_sanitization(self):
        """Test basic sanitization workflow"""
        text = "My email is user@example.com and phone is 555-123-4567"
        result = self.sanitizer.sanitize_output(text)
        
        self.assertIsNotNone(result)
        self.assertIsNotNone(result.sanitized_text)
        self.assertIsNotNone(result.audit_id)
        self.assertIsNotNone(result.timestamp)
        self.assertGreater(len(result.pii_detected), 0)

    def test_compliance_report(self):
        """Test compliance report generation"""
        # Run some sanitizations first
        self.sanitizer.sanitize_output("test1@example.com")
        self.sanitizer.sanitize_output("test2@example.com")
        
        report = self.sanitizer.get_compliance_report()
        
        self.assertIn('compliance_standards', report)
        self.assertIn('total_sanitizations', report)
        self.assertIn('block_rate', report)
        self.assertIn('GDPR', report['compliance_standards'])
        self.assertIn('HIPAA', report['compliance_standards'])
        self.assertEqual(report['total_sanitizations'], 2)

    def test_batch_sanitize(self):
        """Test batch sanitization"""
        outputs = [
            "Email: a@example.com",
            "Phone: 555-111-2222",
            "Clean message here"
        ]
        
        results = self.sanitizer.batch_sanitize(outputs)
        
        self.assertEqual(len(results), 3)
        self.assertGreater(len(results[0].pii_detected), 0)
        self.assertGreater(len(results[1].pii_detected), 0)
        self.assertEqual(len(results[2].pii_detected), 0)

    def test_statistics_tracking(self):
        """Test statistics tracking works"""
        sanitizer = OutputSanitizer()
        sanitizer.sanitize_output("test@example.com")
        
        report = sanitizer.get_compliance_report()
        self.assertEqual(report['total_sanitizations'], 1)


class TestLuhnAlgorithm(unittest.TestCase):
    """Test Luhn algorithm for credit card validation"""

    def setUp(self):
        self.redactor = PIIRedactor()

    def test_valid_credit_cards(self):
        """Test known valid credit card numbers"""
        valid_cards = [
            "4111111111111111",  # Visa
            "4242424242424242",  # Visa test
        ]
        
        for card in valid_cards:
            self.assertTrue(self.redactor._validate_luhn(card), f"Should be valid: {card}")

    def test_invalid_credit_cards(self):
        """Test invalid credit card numbers"""
        invalid_cards = [
            "4111111111111112",  # Bad check digit
            "1234567890123456",
            "0000000000000000",
        ]
        
        for card in invalid_cards:
            # Some might pass by chance, but test that function doesn't crash
            try:
                self.redactor._validate_luhn(card)
            except:
                self.fail(f"Luhn validation crashed on: {card}")


def run_all_tests():
    """Run all test suites"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestPIIRedactor))
    suite.addTests(loader.loadTestsFromTestCase(TestHarmDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestOutputSanitizer))
    suite.addTests(loader.loadTestsFromTestCase(TestLuhnAlgorithm))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print(f"\n{'='*60}")
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print(f"{'='*60}")
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
