#!/usr/bin/env python3
"""
Test suite for Phishing URL Classifier - June 2026
Tests all classification features with real-world phishing and legitimate URLs
"""
import sys
import json
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_phishing_url_classifier_2026_june import (
    PhishingURLClassifier,
    PhishingRiskLevel
)


def run_tests():
    print("=" * 70)
    print("Phishing URL Classifier - Test Suite - June 2026")
    print("=" * 70)
    
    classifier = PhishingURLClassifier(threshold=0.5)
    
    # Test URLs - mix of phishing and legitimate
    test_urls = [
        # Legitimate URLs
        ("https://google.com", False, "Legitimate search engine"),
        ("https://github.com/login", False, "Legitimate login page"),
        ("https://amazon.com/gp/product", False, "Legitimate e-commerce"),
        
        # Phishing URLs
        ("http://192.168.1.100/login-verification.php", True, "IP address domain"),
        ("https://login-google-verification.xyz/secure", True, "Suspicious TLD + keywords"),
        ("https://paypal-login-verify-secure.com@evil.ru", True, "@ redirect + phish"),
        ("https://accounts.googIe.com/login", True, "Typosquatting (I instead of l)"),
        ("https://login.verify.update.secure.bad-site.xyz/login.php", True, "Excessive subdomains"),
        ("http://evil.com:8080/payment/invoice.pdf.exe", True, "Non-standard port + double extension"),
    ]
    
    passed = 0
    failed = 0
    results = []
    
    print("\nRunning classification tests...")
    print("-" * 70)
    
    for url, expected_phish, description in test_urls:
        result = classifier.classify_url(url)
        is_correct = result.is_phishing == expected_phish
        
        status = "✓ PASS" if is_correct else "✗ FAIL"
        if is_correct:
            passed += 1
        else:
            failed += 1
        
        print(f"{status} | {result.risk_level.value.upper():15} | Score: {result.risk_score:.3f} | {description}")
        print(f"       URL: {url[:60]}...")
        
        results.append({
            "url": url,
            "description": description,
            "expected_phishing": expected_phish,
            "actual_phishing": result.is_phishing,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level.value,
            "confidence": result.confidence,
            "suspicious_features": result.suspicious_features,
            "passed": is_correct
        })
    
    print("\n" + "=" * 70)
    accuracy = passed / len(test_urls) * 100
    print(f"TEST SUMMARY: {passed} passed, {failed} failed | Accuracy: {accuracy:.1f}%")
    print("=" * 70)
    
    # Print classifier metrics
    print("\nClassifier Metrics:")
    metrics = classifier.get_classifier_metrics()
    for key, value in metrics.items():
        print(f"  {key}: {value}")
    
    # Save test results
    with open('/home/user/autonomous-developer/NeuralShield-AI/test_results_phishing_url_classifier.json', 'w') as f:
        json.dump({
            "test_timestamp": "2026-06-20",
            "passed": passed,
            "failed": failed,
            "accuracy": accuracy,
            "results": results,
            "classifier_metrics": metrics
        }, f, indent=2)
    
    print(f"\nTest results saved to test_results_phishing_url_classifier.json")
    
    return passed, failed, accuracy


if __name__ == "__main__":
    passed, failed, accuracy = run_tests()
    sys.exit(0 if failed == 0 else 1)
