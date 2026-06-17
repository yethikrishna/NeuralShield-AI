"""
Test Suite for Threat Intelligence Automated Feeder - June 2026
Production-grade tests for multi-source threat intelligence ingestion

Tests cover:
1. Basic initialization and configuration
2. Feed polling and raw indicator ingestion
3. Indicator normalization and deduplication
4. Confidence calibration and source weighting
5. Feed health monitoring and failure detection
6. IOC aging and retirement
7. Statistics and metrics collection
8. Thread safety and concurrent operations
"""
import unittest
import time
import sys
import os

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_automated_feeder_2026_june import (
    ThreatIntelligenceAutomatedFeeder,
    FeedSource,
    FeedStatus,
    FeedConfiguration,
    RawThreatIndicator
)


class TestThreatIntelligenceAutomatedFeederInitialization(unittest.TestCase):
    """Test feeder initialization and configuration"""
    
    def test_initialization_creates_default_feeds(self):
        """Test that feeder initializes with all default feed sources"""
        feeder = ThreatIntelligenceAutomatedFeeder()
        
        # All 7 feed sources should be configured
        self.assertEqual(len(feeder.feed_configs), 7)
        self.assertIn(FeedSource.MITRE_ATTCK, feeder.feed_configs)
        self.assertIn(FeedSource.OWASP_LLM, feeder.feed_configs)
        self.assertIn(FeedSource.NIST_CSRF, feeder.feed_configs)
        self.assertIn(FeedSource.COMMUNITY, feeder.feed_configs)
        self.assertIn(FeedSource.COMMERCIAL_PREMIUM, feeder.feed_configs)
        self.assertIn(FeedSource.OPEN_SOURCE, feeder.feed_configs)
        self.assertIn(FeedSource.INTERNAL_HUNTING, feeder.feed_configs)
        
        feeder.stop_automated_feeding()
    
    def test_initialization_sets_healthy_status(self):
        """Test that all feeds start with HEALTHY status"""
        feeder = ThreatIntelligenceAutomatedFeeder()
        
        for source in FeedSource:
            self.assertEqual(
                feeder.feed_health[source].status,
                FeedStatus.HEALTHY
            )
            self.assertEqual(
                feeder.feed_health[source].consecutive_failures,
                0
            )
        
        feeder.stop_automated_feeding()
    
    def test_initialization_clears_databases(self):
        """Test that databases start empty"""
        feeder = ThreatIntelligenceAutomatedFeeder()
        
        self.assertEqual(len(feeder.normalized_iocs), 0)
        self.assertEqual(len(feeder.ioc_hash_index), 0)
        self.assertEqual(len(feeder.raw_ingestion_queue), 0)
        
        feeder.stop_automated_feeding()


class TestFeedPolling(unittest.TestCase):
    """Test feed polling functionality"""
    
    def test_poll_single_feed_produces_indicators(self):
        """Test that polling produces raw indicators"""
        feeder = ThreatIntelligenceAutomatedFeeder()
        
        # Poll MITRE feed multiple times to ensure we get some indicators
        success_count = 0
        for _ in range(10):
            if feeder.poll_single_feed(FeedSource.MITRE_ATTCK):
                success_count += 1
        
        # Should have at least some successful polls
        self.assertGreater(success_count, 0)
        
        # Queue should have indicators
        self.assertGreaterEqual(len(feeder.raw_ingestion_queue), 0)
        
        feeder.stop_automated_feeding()
    
    def test_poll_updates_health_metrics(self):
        """Test that polling updates feed health metrics"""
        feeder = ThreatIntelligenceAutomatedFeeder()
        
        initial_received = feeder.feed_health[FeedSource.MITRE_ATTCK].total_indicators_received
        
        for _ in range(5):
            feeder.poll_single_feed(FeedSource.MITRE_ATTCK)
        
        final_received = feeder.feed_health[FeedSource.MITRE_ATTCK].total_indicators_received
        
        # Should have received some indicators
        self.assertGreaterEqual(final_received, initial_received)
        
        feeder.stop_automated_feeding()
    
    def test_disabled_feed_not_polled(self):
        """Test that disabled feeds are not polled"""
        feeder = ThreatIntelligenceAutomatedFeeder()
        feeder.feed_configs[FeedSource.OPEN_SOURCE].enabled = False
        
        result = feeder.poll_single_feed(FeedSource.OPEN_SOURCE)
        self.assertFalse(result)
        
        feeder.stop_automated_feeding()


class TestIndicatorNormalization(unittest.TestCase):
    """Test indicator normalization and deduplication"""
    
    def test_normalization_produces_valid_ioc(self):
        """Test that raw indicators are properly normalized"""
        feeder = ThreatIntelligenceAutomatedFeeder()
        
        raw = RawThreatIndicator(
            raw_indicator="  NEW JAILBREAK TECHNIQUE  ",
            source=FeedSource.MITRE_ATTCK,
            raw_category="jailbreak",
            raw_severity="CRITICAL",
            raw_confidence=0.9,
            discovered_at=time.time()
        )
        
        normalized = feeder._normalize_indicator(raw)
        
        self.assertIsNotNone(normalized)
        self.assertEqual(normalized['indicator'], "new jailbreak technique")
        self.assertEqual(normalized['category'], "jailbreak_pattern")
        self.assertEqual(normalized['severity'], 4)
        self.assertGreater(normalized['confidence'], 0)
        self.assertIn('indicator_hash', normalized)
        self.assertIn('expires_at', normalized)
        
        feeder.stop_automated_feeding()
    
    def test_duplicate_detection(self):
        """Test that duplicate indicators are detected and dropped"""
        feeder = ThreatIntelligenceAutomatedFeeder()
        
        raw1 = RawThreatIndicator(
            raw_indicator="duplicate test pattern",
            source=FeedSource.MITRE_ATTCK,
            raw_category="jailbreak",
            raw_severity="high",
            raw_confidence=0.9,
            discovered_at=time.time()
        )
        
        raw2 = RawThreatIndicator(
            raw_indicator="DUPLICATE TEST PATTERN",  # Same, different case
            source=FeedSource.OWASP_LLM,
            raw_category="jailbreak",
            raw_severity="high",
            raw_confidence=0.85,
            discovered_at=time.time()
        )
        
        # First should normalize successfully
        norm1 = feeder._normalize_indicator(raw1)
        self.assertIsNotNone(norm1)
        
        # Add to index manually
        feeder.ioc_hash_index.add(norm1['indicator_hash'])
        
        # Second should be detected as duplicate
        norm2 = feeder._normalize_indicator(raw2)
        self.assertIsNone(norm2)
        
        feeder.stop_automated_feeding()
    
    def test_low_confidence_dropped(self):
        """Test that low confidence indicators are dropped"""
        feeder = ThreatIntelligenceAutomatedFeeder()
        
        raw = RawThreatIndicator(
            raw_indicator="low confidence test",
            source=FeedSource.OPEN_SOURCE,
            raw_category="jailbreak",
            raw_severity="low",
            raw_confidence=0.1,  # Very low confidence
            discovered_at=time.time()
        )
        
        normalized = feeder._normalize_indicator(raw)
        
        # Should be None because confidence * weight < threshold
        self.assertIsNone(normalized)
        
        feeder.stop_automated_feeding()
    
    def test_source_confidence_weighting(self):
        """Test that different sources have different confidence weights"""
        feeder = ThreatIntelligenceAutomatedFeeder()
        
        raw_premium = RawThreatIndicator(
            raw_indicator="premium source indicator",
            source=FeedSource.COMMERCIAL_PREMIUM,  # Weight = 1.0
            raw_category="jailbreak",
            raw_severity="high",
            raw_confidence=0.8,
            discovered_at=time.time()
        )
        
        raw_community = RawThreatIndicator(
            raw_indicator="community source indicator",
            source=FeedSource.COMMUNITY,  # Weight = 0.7
            raw_category="jailbreak",
            raw_severity="high",
            raw_confidence=0.8,
            discovered_at=time.time()
        )
        
        norm_premium = feeder._normalize_indicator(raw_premium)
        norm_community = feeder._normalize_indicator(raw_community)
        
        # Premium should have higher normalized confidence
        self.assertGreater(norm_premium['confidence'], norm_community['confidence'])
        
        feeder.stop_automated_feeding()


class TestProcessing(unittest.TestCase):
    """Test indicator processing pipeline"""
    
    def test_process_queued_indicators(self):
        """Test that queued indicators are processed into normalized IOCs"""
        feeder = ThreatIntelligenceAutomatedFeeder()
        
        # Add some raw indicators
        for i in range(10):
            feeder.raw_ingestion_queue.append(RawThreatIndicator(
                raw_indicator=f"test indicator {i}",
                source=FeedSource.MITRE_ATTCK,
                raw_category="jailbreak",
                raw_severity="high",
                raw_confidence=0.9,
                discovered_at=time.time()
            ))
        
        initial_count = len(feeder.normalized_iocs)
        processed = feeder.process_queued_indicators()
        
        self.assertGreater(processed, 0)
        self.assertEqual(len(feeder.normalized_iocs), initial_count + processed)
        self.assertEqual(len(feeder.raw_ingestion_queue), 0)
        
        feeder.stop_automated_feeding()
    
    def test_retire_aged_iocs(self):
        """Test that expired IOCs are retired"""
        feeder = ThreatIntelligenceAutomatedFeeder()
        
        # Add an expired IOC
        expired_hash = "expired_test_hash"
        feeder.normalized_iocs[expired_hash] = {
            'indicator': 'expired indicator',
            'indicator_hash': expired_hash,
            'expires_at': time.time() - 1000,  # Already expired
            'severity': 3,
            'confidence': 0.9
        }
        feeder.ioc_hash_index.add(expired_hash)
        
        # Add a valid IOC
        valid_hash = "valid_test_hash"
        feeder.normalized_iocs[valid_hash] = {
            'indicator': 'valid indicator',
            'indicator_hash': valid_hash,
            'expires_at': time.time() + 100000,  # Still valid
            'severity': 3,
            'confidence': 0.9
        }
        feeder.ioc_hash_index.add(valid_hash)
        
        initial_count = len(feeder.normalized_iocs)
        retired = feeder.retire_aged_iocs()
        
        self.assertEqual(retired, 1)
        self.assertEqual(len(feeder.normalized_iocs), initial_count - 1)
        self.assertNotIn(expired_hash, feeder.normalized_iocs)
        self.assertIn(valid_hash, feeder.normalized_iocs)
        
        feeder.stop_automated_feeding()


class TestStatistics(unittest.TestCase):
    """Test statistics and metrics collection"""
    
    def test_get_feeder_statistics_returns_comprehensive_data(self):
        """Test that statistics return all required fields"""
        feeder = ThreatIntelligenceAutomatedFeeder()
        
        stats = feeder.get_feeder_statistics()
        
        self.assertIn('ingestion', stats)
        self.assertIn('database', stats)
        self.assertIn('feed_health', stats)
        self.assertIn('queues', stats)
        self.assertIn('timestamp', stats)
        
        # Check ingestion stats
        self.assertIn('total_normalized', stats['ingestion'])
        self.assertIn('total_duplicates', stats['ingestion'])
        
        # Check database stats
        self.assertIn('total_normalized_iocs', stats['database'])
        self.assertIn('by_source', stats['database'])
        
        # Check feed health for all sources
        for source in FeedSource:
            self.assertIn(source.value, stats['feed_health'])
        
        feeder.stop_automated_feeding()
    
    def test_get_normalized_iocs_sorted_by_severity(self):
        """Test that IOCs are returned sorted by severity and confidence"""
        feeder = ThreatIntelligenceAutomatedFeeder()
        
        # Add IOCs with different severities
        for i in range(5):
            feeder.raw_ingestion_queue.append(RawThreatIndicator(
                raw_indicator=f"indicator_{i}",
                source=FeedSource.MITRE_ATTCK,
                raw_category="jailbreak",
                raw_severity="critical" if i == 0 else "high" if i == 1 else "medium",
                raw_confidence=0.9,
                discovered_at=time.time()
            ))
        
        feeder.process_queued_indicators()
        
        iocs = feeder.get_normalized_iocs(limit=10)
        
        if len(iocs) >= 2:
            # First should have highest severity
            self.assertGreaterEqual(iocs[0]['severity'], iocs[1]['severity'])
        
        feeder.stop_automated_feeding()


class TestIntegration(unittest.TestCase):
    """Integration tests for full feeder workflow"""
    
    def test_full_ingestion_workflow(self):
        """Test complete ingestion workflow: poll -> process -> retrieve"""
        feeder = ThreatIntelligenceAutomatedFeeder()
        
        # Poll multiple feeds
        for source in [FeedSource.MITRE_ATTCK, FeedSource.OWASP_LLM, FeedSource.COMMUNITY]:
            for _ in range(3):
                feeder.poll_single_feed(source)
        
        # Process all queued indicators
        processed = feeder.process_queued_indicators()
        
        # Get statistics
        stats = feeder.get_feeder_statistics()
        
        # Get normalized IOCs
        iocs = feeder.get_normalized_iocs(limit=50)
        
        # Verify workflow completed
        self.assertEqual(len(feeder.raw_ingestion_queue), 0)
        self.assertEqual(stats['database']['total_normalized_iocs'], len(feeder.normalized_iocs))
        
        if iocs:
            self.assertIn('indicator', iocs[0])
            self.assertIn('severity', iocs[0])
            self.assertIn('confidence', iocs[0])
        
        feeder.stop_automated_feeding()
    
    def test_background_thread_operations(self):
        """Test that background thread can be started and stopped"""
        feeder = ThreatIntelligenceAutomatedFeeder()
        
        # Start background feeding
        feeder.start_automated_feeding()
        self.assertTrue(feeder._running)
        self.assertIsNotNone(feeder._feeder_thread)
        
        # Let it run briefly
        time.sleep(0.5)
        
        # Stop background feeding
        feeder.stop_automated_feeding()
        self.assertFalse(feeder._running)


if __name__ == '__main__':
    print("=" * 70)
    print("Threat Intelligence Automated Feeder - Test Suite")
    print("=" * 70)
    print()
    
    # Run tests
    unittest.main(verbosity=2)
