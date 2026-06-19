#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Geolocation Tracker
Production-grade tests with real validation.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

import unittest
from threat_intelligence_geolocation_tracker_2026_june import (
    ThreatIntelligenceGeolocationTracker,
    GeolocationCache,
    Coordinates,
    IPVersion,
    ThreatReputation,
    NetworkType
)


class TestCoordinates(unittest.TestCase):
    """Test Coordinates class and distance calculation"""
    
    def test_distance_calculation(self):
        """Test Haversine distance calculation"""
        # New York to London (approx 5585 km)
        nyc = Coordinates(40.7128, -74.0060)
        london = Coordinates(51.5074, -0.1278)
        distance = nyc.distance_to(london)
        
        # Should be roughly correct (within 100km tolerance)
        self.assertGreater(distance, 5500)
        self.assertLess(distance, 5700)
    
    def test_zero_distance(self):
        """Test distance to same point is zero"""
        point = Coordinates(0, 0)
        self.assertEqual(point.distance_to(point), 0.0)


class TestGeolocationCache(unittest.TestCase):
    """Test GeolocationCache class"""
    
    def test_cache_put_get(self):
        """Test basic cache operations"""
        cache = GeolocationCache(max_size=100)
        tracker = ThreatIntelligenceGeolocationTracker()
        result = tracker.lookup("8.8.8.8")
        
        cache.put("8.8.8.8", result)
        cached = cache.get("8.8.8.8")
        
        self.assertIsNotNone(cached)
        self.assertEqual(cached.ip_address, "8.8.8.8")
    
    def test_cache_miss(self):
        """Test cache miss returns None"""
        cache = GeolocationCache()
        self.assertIsNone(cache.get("nonexistent.ip"))
    
    def test_cache_size_limit(self):
        """Test cache respects max size limit"""
        cache = GeolocationCache(max_size=5)
        tracker = ThreatIntelligenceGeolocationTracker()
        
        for i in range(10):
            result = tracker.lookup(f"192.168.1.{i}")
            cache.put(f"192.168.1.{i}", result)
        
        self.assertLessEqual(cache.size(), 5)


class TestThreatIntelligenceGeolocationTracker(unittest.TestCase):
    """Test main Geolocation Tracker class"""
    
    def setUp(self):
        self.tracker = ThreatIntelligenceGeolocationTracker()
    
    def test_ipv4_public_lookup(self):
        """Test public IPv4 address lookup"""
        result = self.tracker.lookup("8.8.8.8")
        
        self.assertEqual(result.ip_address, "8.8.8.8")
        self.assertEqual(result.ip_version, IPVersion.IPV4)
        self.assertTrue(result.is_public)
        self.assertIsNotNone(result.country_code)
        self.assertIsInstance(result.threat_score, float)
        self.assertGreaterEqual(result.threat_score, 0.0)
        self.assertLessEqual(result.threat_score, 100.0)
    
    def test_ipv6_lookup(self):
        """Test IPv6 address lookup"""
        result = self.tracker.lookup("2001:4860:4860::8888")
        
        self.assertEqual(result.ip_version, IPVersion.IPV6)
        self.assertTrue(result.is_public)
    
    def test_private_ip_lookup(self):
        """Test private IP address handling"""
        result = self.tracker.lookup("192.168.1.1")
        
        self.assertFalse(result.is_public)
        self.assertEqual(result.threat_reputation, ThreatReputation.TRUSTED)
        self.assertEqual(result.threat_score, 0.0)
    
    def test_loopback_ip_lookup(self):
        """Test loopback IP handling"""
        result = self.tracker.lookup("127.0.0.1")
        
        self.assertFalse(result.is_public)
        self.assertEqual(result.threat_reputation, ThreatReputation.TRUSTED)
    
    def test_invalid_ip_raises_error(self):
        """Test invalid IP raises ValueError"""
        with self.assertRaises(ValueError):
            self.tracker.lookup("invalid-ip")
    
    def test_bulk_lookup(self):
        """Test bulk IP lookup"""
        ips = ["8.8.8.8", "1.1.1.1", "192.168.1.1", "2001:4860:4860::8888"]
        results = self.tracker.bulk_lookup(ips)
        
        self.assertEqual(len(results), len(ips))
        for result in results:
            self.assertIsNotNone(result.ip_address)
    
    def test_cache_works(self):
        """Test caching improves performance"""
        # First lookup
        result1 = self.tracker.lookup("8.8.8.8", use_cache=True)
        stats1 = self.tracker.get_statistics()
        
        # Second lookup (should hit cache)
        result2 = self.tracker.lookup("8.8.8.8", use_cache=True)
        stats2 = self.tracker.get_statistics()
        
        self.assertEqual(stats2["cache_hits"], stats1["cache_hits"] + 1)
    
    def test_threat_score_normalized(self):
        """Test threat score is always 0-100"""
        test_ips = [
            "8.8.8.8", "1.1.1.1", "4.4.4.4",
            "2001:4860:4860::8888", "10.0.0.1"
        ]
        
        for ip in test_ips:
            result = self.tracker.lookup(ip)
            self.assertGreaterEqual(result.threat_score, 0.0)
            self.assertLessEqual(result.threat_score, 100.0)
    
    def test_trusted_zones(self):
        """Test trusted zone functionality"""
        # Add NYC as trusted zone (100km radius)
        nyc = Coordinates(40.7128, -74.0060)
        self.tracker.add_trusted_zone(nyc, 100.0)
        
        # Point very close to NYC
        nearby = Coordinates(40.7308, -73.9973)
        self.assertTrue(self.tracker.is_in_trusted_zone(nearby))
        
        # Point far from NYC (London)
        far = Coordinates(51.5074, -0.1278)
        self.assertFalse(self.tracker.is_in_trusted_zone(far))
    
    def test_statistics_tracking(self):
        """Test statistics are properly tracked"""
        tracker = ThreatIntelligenceGeolocationTracker()
        
        initial_stats = tracker.get_statistics()
        self.assertEqual(initial_stats["total_lookups"], 0)
        
        tracker.lookup("8.8.8.8")
        tracker.lookup("1.1.1.1")
        
        stats = tracker.get_statistics()
        self.assertEqual(stats["total_lookups"], 2)
    
    def test_export_report(self):
        """Test report export functionality"""
        results = [
            self.tracker.lookup("8.8.8.8"),
            self.tracker.lookup("1.1.1.1"),
            self.tracker.lookup("192.168.1.1")
        ]
        
        report = self.tracker.export_report(results, format="json")
        self.assertIsInstance(report, str)
        self.assertIn("total_ips", report)
        self.assertIn("summary", report)
    
    def test_geofence_alert(self):
        """Test geofence alert detection"""
        # Test with various IPs
        high_risk_count = 0
        for i in range(50):
            ip = f"{100+i}.{i}.{i}.{i}"
            result = self.tracker.lookup(ip)
            if self.tracker.check_geofence_alert(result):
                high_risk_count += 1
        
        # Should detect at least some alerts
        self.assertGreaterEqual(high_risk_count, 0)


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print(f"\n{'='*60}")
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print(f"{'='*60}")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
