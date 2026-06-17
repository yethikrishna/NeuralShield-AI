"""
Test suite for Threat Intelligence Whitelist Validator
Production-grade tests covering all functionality
"""

import unittest
import time
from neural_shield.threat_intelligence_whitelist_validator_2026_june import (
    ThreatIntelligenceWhitelistValidator,
    ValidationResult,
    WhitelistType
)


class TestThreatIntelligenceWhitelistValidator(unittest.TestCase):
    """Test cases for Whitelist Validator"""

    def setUp(self):
        """Set up test validator"""
        self.validator = ThreatIntelligenceWhitelistValidator(
            cache_ttl=60,
            enable_caching=True
        )

    def test_ip_validation_exact_match(self):
        """Test exact IP address matching"""
        self.validator.add_ip("192.168.1.1", "test", 1.0, "Test IP")
        
        result = self.validator.validate_ip("192.168.1.1")
        self.assertEqual(result.result, ValidationResult.WHITELISTED)
        self.assertEqual(result.match_type, "exact_ip")
        self.assertEqual(result.confidence, 1.0)

    def test_ip_validation_cidr_match(self):
        """Test CIDR range matching"""
        self.validator.add_cidr("192.168.0.0/16", "test", 0.95)
        
        result = self.validator.validate_ip("192.168.5.100")
        self.assertEqual(result.result, ValidationResult.WHITELISTED)
        self.assertEqual(result.match_type, "cidr_match")
        self.assertAlmostEqual(result.confidence, 0.95)

    def test_ip_validation_not_whitelisted(self):
        """Test IP not in whitelist"""
        result = self.validator.validate_ip("10.0.0.1")
        self.assertEqual(result.result, ValidationResult.NOT_WHITELISTED)
        self.assertEqual(result.confidence, 0.0)

    def test_ip_validation_invalid(self):
        """Test invalid IP address"""
        result = self.validator.validate_ip("not-an-ip")
        self.assertEqual(result.result, ValidationResult.INVALID_INPUT)

    def test_domain_validation_exact(self):
        """Test exact domain matching"""
        self.validator.add_domain("example.com", "test", 1.0)
        
        result = self.validator.validate_domain("example.com")
        self.assertEqual(result.result, ValidationResult.WHITELISTED)
        self.assertEqual(result.match_type, "exact_domain")

    def test_domain_validation_subdomain(self):
        """Test subdomain matching"""
        self.validator.add_domain("example.com", "test", 1.0)
        
        result = self.validator.validate_domain("sub.example.com")
        self.assertEqual(result.result, ValidationResult.WHITELISTED)
        self.assertEqual(result.match_type, "subdomain")
        self.assertLess(result.confidence, 1.0)

    def test_domain_validation_strict_mode(self):
        """Test strict domain matching mode"""
        strict_validator = ThreatIntelligenceWhitelistValidator(
            strict_domain_matching=True
        )
        strict_validator.add_domain("example.com", "test", 1.0)
        
        result = strict_validator.validate_domain("sub.example.com")
        self.assertEqual(result.result, ValidationResult.NOT_WHITELISTED)

    def test_domain_validation_invalid(self):
        """Test invalid domain format"""
        result = self.validator.validate_domain("not-a-domain!!!")
        self.assertEqual(result.result, ValidationResult.INVALID_INPUT)

    def test_url_validation_exact(self):
        """Test exact URL matching"""
        self.validator.add_url("https://example.com/page", "test", 1.0)
        
        result = self.validator.validate_url("https://example.com/page")
        self.assertEqual(result.result, ValidationResult.WHITELISTED)
        self.assertEqual(result.match_type, "exact_url")

    def test_url_validation_pattern(self):
        """Test URL pattern matching"""
        self.validator.add_url_pattern(r"https://.*\.example\.com/.*")
        
        result = self.validator.validate_url("https://sub.example.com/test")
        self.assertEqual(result.result, ValidationResult.WHITELISTED)
        self.assertEqual(result.match_type, "pattern")

    def test_url_validation_domain_in_url(self):
        """Test URL with whitelisted domain"""
        self.validator.add_domain("example.com", "test", 1.0)
        
        result = self.validator.validate_url("https://example.com/some/path")
        self.assertEqual(result.result, ValidationResult.PARTIAL_MATCH)
        self.assertEqual(result.match_type, "domain_in_url")

    def test_validate_auto_detection(self):
        """Test automatic type detection"""
        self.validator.add_ip("8.8.8.8")
        self.validator.add_domain("github.com")
        
        ip_result = self.validator.validate_auto("8.8.8.8")
        self.assertEqual(ip_result.result, ValidationResult.WHITELISTED)
        
        domain_result = self.validator.validate_auto("github.com")
        self.assertEqual(domain_result.result, ValidationResult.WHITELISTED)

    def test_bulk_validation(self):
        """Test bulk validation"""
        self.validator.add_ip("1.1.1.1")
        self.validator.add_domain("python.org")
        
        values = ["1.1.1.1", "python.org", "unknown.xyz", "8.8.8.8"]
        results = self.validator.bulk_validate(values)
        
        self.assertEqual(len(results), 4)
        self.assertEqual(results[0].result, ValidationResult.WHITELISTED)
        self.assertEqual(results[1].result, ValidationResult.WHITELISTED)

    def test_caching_works(self):
        """Test that caching stores results"""
        self.validator.add_ip("10.0.0.1")
        
        # First call
        result1 = self.validator.validate_ip("10.0.0.1")
        cache_size_before = self.validator.get_statistics()["cache_size"]
        
        # Second call should use cache
        result2 = self.validator.validate_ip("10.0.0.1")
        cache_size_after = self.validator.get_statistics()["cache_size"]
        
        self.assertEqual(result1.result, result2.result)
        self.assertGreater(cache_size_after, 0)

    def test_clear_cache(self):
        """Test cache clearing"""
        self.validator.add_ip("10.0.0.1")
        self.validator.validate_ip("10.0.0.1")
        
        self.assertGreater(self.validator.get_statistics()["cache_size"], 0)
        self.validator.clear_cache()
        self.assertEqual(self.validator.get_statistics()["cache_size"], 0)

    def test_load_default_whitelists(self):
        """Test loading default whitelists"""
        self.validator.load_default_whitelists()
        stats = self.validator.get_statistics()
        
        self.assertGreater(stats["ip_count"], 0)
        self.assertGreater(stats["domain_count"], 0)
        self.assertGreater(stats["cidr_count"], 0)
        
        # Verify Google DNS is whitelisted
        result = self.validator.validate_ip("8.8.8.8")
        self.assertEqual(result.result, ValidationResult.WHITELISTED)
        
        # Verify GitHub is whitelisted
        result = self.validator.validate_domain("github.com")
        self.assertEqual(result.result, ValidationResult.WHITELISTED)

    def test_is_whitelisted_helper(self):
        """Test is_whitelisted helper method"""
        self.validator.add_ip("192.168.1.1", confidence=0.8)
        
        self.assertTrue(self.validator.is_whitelisted("192.168.1.1", min_confidence=0.5))
        self.assertFalse(self.validator.is_whitelisted("192.168.1.1", min_confidence=0.9))
        self.assertFalse(self.validator.is_whitelisted("10.0.0.1"))

    def test_get_statistics(self):
        """Test statistics reporting"""
        self.validator.add_ip("1.1.1.1")
        self.validator.add_domain("test.com")
        
        stats = self.validator.get_statistics()
        
        self.assertIn("total_entries", stats)
        self.assertIn("ip_count", stats)
        self.assertIn("domain_count", stats)
        self.assertIn("sources", stats)
        self.assertGreater(stats["total_entries"], 0)

    def test_add_invalid_entries_rejected(self):
        """Test that invalid entries are rejected"""
        result = self.validator.add_ip("not-an-ip")
        self.assertFalse(result)
        
        result = self.validator.add_domain("not-a-domain")
        self.assertFalse(result)
        
        result = self.validator.add_url("not-a-url")
        self.assertFalse(result)

    def test_case_insensitive_domain(self):
        """Test domain matching is case-insensitive"""
        self.validator.add_domain("Example.COM")
        
        result = self.validator.validate_domain("EXAMPLE.COM")
        self.assertEqual(result.result, ValidationResult.WHITELISTED)
        
        result = self.validator.validate_domain("example.com")
        self.assertEqual(result.result, ValidationResult.WHITELISTED)

    def test_ipv6_support(self):
        """Test IPv6 address support"""
        self.validator.add_ip("2001:4860:4860::8888", "google", 1.0)
        
        result = self.validator.validate_ip("2001:4860:4860::8888")
        self.assertEqual(result.result, ValidationResult.WHITELISTED)

    def test_validation_report_details(self):
        """Test validation report contains details"""
        self.validator.add_cidr("172.16.0.0/12", "private")
        
        result = self.validator.validate_ip("172.16.5.5")
        self.assertIn("network", result.details)
        self.assertIsNotNone(result.validation_time)
        self.assertEqual(result.input_value, "172.16.5.5")


if __name__ == "__main__":
    print("Running Threat Intelligence Whitelist Validator tests...")
    unittest.main(verbosity=2)
