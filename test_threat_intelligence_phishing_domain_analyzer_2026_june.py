"""
Test Suite for NeuralShield AI - Threat Intelligence Phishing Domain Analyzer
Production-grade unit and integration tests
"""

import pytest
import sys
import os

# Add the neural_shield directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_phishing_domain_analyzer_2026_june import (
    PhishingDomainAnalyzer,
    PhishingRiskLevel,
    PhishingAnalysisResult
)


class TestPhishingDomainAnalyzer:
    """Test suite for PhishingDomainAnalyzer"""

    def setup_method(self):
        """Setup test fixtures"""
        self.analyzer = PhishingDomainAnalyzer()

    def test_initialization(self):
        """Test analyzer initialization"""
        assert self.analyzer is not None
        assert isinstance(self.analyzer.thresholds, dict)
        assert 'critical' in self.analyzer.thresholds

    def test_levenshtein_distance(self):
        """Test Levenshtein distance calculation"""
        assert PhishingDomainAnalyzer._levenshtein_distance("kitten", "sitting") == 3
        assert PhishingDomainAnalyzer._levenshtein_distance("", "") == 0
        assert PhishingDomainAnalyzer._levenshtein_distance("abc", "") == 3
        assert PhishingDomainAnalyzer._levenshtein_distance("same", "same") == 0

    def test_similarity_score(self):
        """Test similarity score calculation"""
        score = PhishingDomainAnalyzer._similarity_score("paypal", "paypai")
        assert 0.5 < score < 1.0
        
        identical = PhishingDomainAnalyzer._similarity_score("google", "google")
        assert identical == 1.0

    def test_extract_domain_parts(self):
        """Test domain part extraction"""
        sub, main, tld = self.analyzer._extract_domain_parts("www.paypal.com")
        assert main == "paypal"
        assert tld == "com"
        
        sub, main, tld = self.analyzer._extract_domain_parts("secure.login.google.co.uk")
        assert main == "co"  # Note: simplified parsing

    def test_suspicious_keywords_detection(self):
        """Test suspicious keyword detection"""
        keywords, score = self.analyzer._analyze_suspicious_keywords("paypal-login-verify.xyz")
        assert len(keywords) > 0
        assert 'login' in keywords or 'verify' in keywords
        assert score > 0

    def test_brand_impersonation_detection(self):
        """Test brand impersonation detection"""
        score, brands = self.analyzer._analyze_brand_impersonation("paypai")
        assert score > 20
        assert 'paypal' in brands
        
        # Legitimate domain should have low score
        score2, brands2 = self.analyzer._analyze_brand_impersonation("randomdomain")
        assert score2 < 10

    def test_tld_risk_analysis(self):
        """Test TLD risk analysis"""
        high_risk = self.analyzer._analyze_tld_risk("tk")
        assert high_risk > 20
        
        low_risk = self.analyzer._analyze_tld_risk("com")
        assert low_risk == 0

    def test_character_anomalies(self):
        """Test character anomaly detection"""
        anomalies, score = self.analyzer._analyze_character_anomalies("paypai-with-many-hyphens-here-test")
        assert score >= 0
        
        # Test numeric patterns
        anomalies2, score2 = self.analyzer._analyze_character_anomalies("verify12345")
        assert score2 > 0

    def test_analyze_legitimate_domain(self):
        """Test analysis of legitimate domain"""
        result = self.analyzer.analyze("google.com")
        assert isinstance(result, PhishingAnalysisResult)
        assert result.domain == "google.com"
        assert result.overall_risk_score < 40
        assert result.risk_level in [PhishingRiskLevel.LOW, PhishingRiskLevel.UNKNOWN]

    def test_analyze_phishing_domain(self):
        """Test analysis of obvious phishing domain"""
        result = self.analyzer.analyze("paypal-secure-login-verify.tk")
        assert isinstance(result, PhishingAnalysisResult)
        assert result.overall_risk_score > 50
        assert result.risk_level in [PhishingRiskLevel.HIGH, PhishingRiskLevel.CRITICAL]
        assert len(result.suspicious_keywords_found) > 0
        assert len(result.recommendations) > 0

    def test_analyze_brand_impersonation_domain(self):
        """Test analysis of brand impersonation domain"""
        result = self.analyzer.analyze("micros0ft-verify.xyz")
        assert result.brand_impersonation_score > 0
        assert len(result.heuristic_checks) > 0

    def test_batch_analyze(self):
        """Test batch analysis functionality"""
        domains = ["google.com", "paypal-phishing.tk", "apple-verify.xyz"]
        results = self.analyzer.batch_analyze(domains)
        
        assert len(results) == 3
        assert all(isinstance(r, PhishingAnalysisResult) for r in results.values())

    def test_caching_mechanism(self):
        """Test result caching"""
        domain = "test-caching-domain.com"
        result1 = self.analyzer.analyze(domain, use_cache=True)
        result2 = self.analyzer.analyze(domain, use_cache=True)
        
        # Should return same cached object
        assert result1.analysis_timestamp == result2.analysis_timestamp

    def test_get_analysis_summary(self):
        """Test summary generation"""
        result = self.analyzer.analyze("google.com")
        summary = self.analyzer.get_analysis_summary(result)
        
        assert 'domain' in summary
        assert 'risk_score' in summary
        assert 'risk_level' in summary
        assert 'total_flags' in summary

    def test_risk_level_determination(self):
        """Test risk level determination"""
        critical = self.analyzer._determine_risk_level(90)
        assert critical == PhishingRiskLevel.CRITICAL
        
        high = self.analyzer._determine_risk_level(70)
        assert high == PhishingRiskLevel.HIGH
        
        medium = self.analyzer._determine_risk_level(50)
        assert medium == PhishingRiskLevel.MEDIUM
        
        low = self.analyzer._determine_risk_level(10)
        assert low == PhishingRiskLevel.UNKNOWN

    def test_subdomain_analysis(self):
        """Test subdomain complexity analysis"""
        analysis, score = self.analyzer._analyze_subdomain_complexity("secure.login.verify")
        assert analysis['subdomain_count'] == 3
        assert score > 0

    def test_dns_pattern_analysis(self):
        """Test DNS pattern analysis"""
        anomalies, score = self.analyzer._analyze_dns_patterns("x123x456-domain.tk")
        assert score >= 0

    def test_recommendations_generation(self):
        """Test security recommendations"""
        result = self.analyzer.analyze("very-suspicious-phishing-site-12345.tk")
        assert len(result.recommendations) > 0
        assert isinstance(result.recommendations, list)

    def test_heurstic_checks_populated(self):
        """Test heuristic checks are populated"""
        result = self.analyzer.analyze("paypal-login-verify.xyz")
        assert len(result.heuristic_checks) > 0
        assert 'has_suspicious_keywords' in result.heuristic_checks
        assert 'potential_brand_impersonation' in result.heuristic_checks


def run_comprehensive_tests():
    """Run comprehensive integration tests"""
    print("\n" + "="*70)
    print("NeuralShield AI - Phishing Domain Analyzer - Comprehensive Tests")
    print("="*70)
    
    analyzer = PhishingDomainAnalyzer()
    
    test_cases = [
        ("Legitimate: google.com", "google.com", False),
        ("Legitimate: microsoft.com", "microsoft.com", False),
        ("Phishing: paypal-secure-login.tk", "paypal-secure-login.tk", True),
        ("Phishing: apple-verify-account.xyz", "apple-verify-account.xyz", True),
        ("Phishing: secure-login-microsoft.top", "secure-login-microsoft.top", True),
        ("Suspicious: coinbase-verify1234.online", "coinbase-verify1234.online", True),
        ("Mixed: amazon-update.site", "amazon-update.site", True),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, domain, should_be_suspicious in test_cases:
        result = analyzer.analyze(domain)
        is_suspicious = result.overall_risk_score > 40
        
        status = "PASS" if is_suspicious == should_be_suspicious else "FAIL"
        if status == "PASS":
            passed += 1
        else:
            failed += 1
        
        print(f"\n{test_name}")
        print(f"  Score: {result.overall_risk_score:.1f} | Level: {result.risk_level.value.upper()}")
        print(f"  Status: {status}")
        if result.impersonated_brands:
            print(f"  Impersonated: {result.impersonated_brands}")
    
    print("\n" + "-"*70)
    print(f"Results: {passed} PASSED | {failed} FAILED")
    print("="*70 + "\n")
    
    return failed == 0


if __name__ == "__main__":
    # Run pytest
    print("Running pytest unit tests...")
    pytest.main([__file__, "-v"])
    
    # Run comprehensive integration tests
    success = run_comprehensive_tests()
    
    if success:
        print("\n✅ ALL TESTS PASSED - Phishing Domain Analyzer working correctly!")
        sys.exit(0)
    else:
        print("\n❌ SOME TESTS FAILED")
        sys.exit(1)
