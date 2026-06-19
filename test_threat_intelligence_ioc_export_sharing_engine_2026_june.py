"""
Test Suite for Threat Intelligence IOC Export & Sharing Engine
REAL TESTS - No mocks, actual working code
"""

import unittest
import json
import csv
import io
from datetime import datetime, timezone

from neural_shield.threat_intelligence_ioc_export_sharing_engine_2026_june import (
    IOCExportEngine,
    IndicatorOfCompromise,
    IOType,
    TLP,
    Severity,
    ExportFormat
)


class TestIndicatorOfCompromise(unittest.TestCase):
    """Test IOC dataclass functionality"""

    def test_ioc_creation_basic(self):
        """Test basic IOC creation works"""
        ioc = IndicatorOfCompromise(
            value="192.168.1.1",
            ioc_type=IOType.IPV4
        )
        self.assertEqual(ioc.value, "192.168.1.1")
        self.assertEqual(ioc.ioc_type, IOType.IPV4)
        self.assertEqual(ioc.tlp, TLP.AMBER)
        self.assertEqual(ioc.severity, Severity.MEDIUM)

    def test_ioc_creation_full_metadata(self):
        """Test IOC creation with full metadata"""
        ioc = IndicatorOfCompromise(
            value="malicious.com",
            ioc_type=IOType.DOMAIN,
            tlp=TLP.RED,
            severity=Severity.CRITICAL,
            description="C2 domain for APT28",
            threat_actor="APT28",
            malware_family="Emotet",
            mitre_technique="T1071",
            confidence=0.95,
            tags=["c2", "apt", "malware"]
        )
        self.assertEqual(ioc.description, "C2 domain for APT28")
        self.assertEqual(ioc.threat_actor, "APT28")
        self.assertEqual(ioc.confidence, 0.95)
        self.assertEqual(len(ioc.tags), 3)

    def test_ioc_confidence_validation(self):
        """Test confidence validation rejects invalid values"""
        with self.assertRaises(ValueError):
            IndicatorOfCompromise(
                value="1.1.1.1",
                ioc_type=IOType.IPV4,
                confidence=1.5  # Invalid
            )
        with self.assertRaises(ValueError):
            IndicatorOfCompromise(
                value="1.1.1.1",
                ioc_type=IOType.IPV4,
                confidence=-0.1  # Invalid
            )

    def test_ioc_hash_computation(self):
        """Test hash computation for deduplication"""
        ioc1 = IndicatorOfCompromise(value="192.168.1.1", ioc_type=IOType.IPV4)
        ioc2 = IndicatorOfCompromise(value="192.168.1.1", ioc_type=IOType.IPV4)
        ioc3 = IndicatorOfCompromise(value="10.0.0.1", ioc_type=IOType.IPV4)

        self.assertEqual(ioc1.compute_hash(), ioc2.compute_hash())
        self.assertNotEqual(ioc1.compute_hash(), ioc3.compute_hash())


class TestIOCExportEngineBasic(unittest.TestCase):
    """Test basic engine functionality"""

    def test_engine_initialization(self):
        """Test engine initializes correctly"""
        engine = IOCExportEngine("Test Org")
        self.assertEqual(engine.organization_name, "Test Org")
        self.assertEqual(len(engine._iocs), 0)

    def test_add_single_ioc(self):
        """Test adding single IOC"""
        engine = IOCExportEngine()
        ioc = IndicatorOfCompromise(value="1.1.1.1", ioc_type=IOType.IPV4)
        engine.add_ioc(ioc)
        self.assertEqual(len(engine._iocs), 1)

    def test_add_multiple_iocs(self):
        """Test adding multiple IOCs"""
        engine = IOCExportEngine()
        iocs = [
            IndicatorOfCompromise(value="1.1.1.1", ioc_type=IOType.IPV4),
            IndicatorOfCompromise(value="2.2.2.2", ioc_type=IOType.IPV4),
            IndicatorOfCompromise(value="evil.com", ioc_type=IOType.DOMAIN)
        ]
        engine.add_iocs(iocs)
        self.assertEqual(len(engine._iocs), 3)

    def test_clear_iocs(self):
        """Test clearing IOCs"""
        engine = IOCExportEngine()
        engine.add_ioc(IndicatorOfCompromise(value="1.1.1.1", ioc_type=IOType.IPV4))
        engine.clear()
        self.assertEqual(len(engine._iocs), 0)

    def test_deduplication(self):
        """Test IOC deduplication works"""
        engine = IOCExportEngine()
        # Add duplicates
        engine.add_ioc(IndicatorOfCompromise(value="1.1.1.1", ioc_type=IOType.IPV4))
        engine.add_ioc(IndicatorOfCompromise(value="1.1.1.1", ioc_type=IOType.IPV4))
        engine.add_ioc(IndicatorOfCompromise(value="2.2.2.2", ioc_type=IOType.IPV4))

        removed = engine.deduplicate()
        self.assertEqual(removed, 1)
        self.assertEqual(len(engine._iocs), 2)


class TestIOCFiltering(unittest.TestCase):
    """Test IOC filtering functionality"""

    def setUp(self):
        self.engine = IOCExportEngine()
        self.engine.add_iocs([
            IndicatorOfCompromise(value="1.1.1.1", ioc_type=IOType.IPV4, tlp=TLP.WHITE, severity=Severity.LOW),
            IndicatorOfCompromise(value="evil.com", ioc_type=IOType.DOMAIN, tlp=TLP.RED, severity=Severity.CRITICAL),
            IndicatorOfCompromise(value="bad.exe", ioc_type=IOType.FILE_HASH_SHA256, tlp=TLP.AMBER, severity=Severity.HIGH),
        ])

    def test_filter_by_type(self):
        """Test filtering by IOC type"""
        ipv4 = self.engine.filter_by_type(IOType.IPV4)
        domain = self.engine.filter_by_type(IOType.DOMAIN)
        self.assertEqual(len(ipv4), 1)
        self.assertEqual(len(domain), 1)
        self.assertEqual(ipv4[0].value, "1.1.1.1")

    def test_filter_by_tlp(self):
        """Test filtering by TLP"""
        red = self.engine.filter_by_tlp(TLP.RED)
        white = self.engine.filter_by_tlp(TLP.WHITE)
        self.assertEqual(len(red), 1)
        self.assertEqual(len(white), 1)
        self.assertEqual(red[0].value, "evil.com")

    def test_filter_by_severity(self):
        """Test filtering by minimum severity"""
        high_and_above = self.engine.filter_by_severity(Severity.HIGH)
        self.assertEqual(len(high_and_above), 2)  # HIGH + CRITICAL
        critical_only = self.engine.filter_by_severity(Severity.CRITICAL)
        self.assertEqual(len(critical_only), 1)


class TestExportFormats(unittest.TestCase):
    """Test all export formats"""

    def setUp(self):
        self.engine = IOCExportEngine("Test Security")
        self.engine.add_iocs([
            IndicatorOfCompromise(
                value="192.168.1.100",
                ioc_type=IOType.IPV4,
                tlp=TLP.AMBER,
                severity=Severity.HIGH,
                description="C2 Server",
                mitre_technique="T1071.001"
            ),
            IndicatorOfCompromise(
                value="malicious-domain.net",
                ioc_type=IOType.DOMAIN,
                tlp=TLP.RED,
                severity=Severity.CRITICAL,
                description="Phishing domain"
            ),
            IndicatorOfCompromise(
                value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                ioc_type=IOType.FILE_HASH_SHA256,
                tlp=TLP.GREEN,
                severity=Severity.MEDIUM
            )
        ])

    def test_export_stix21(self):
        """Test STIX 2.1 export - REAL WORKING"""
        result = self.engine.export_stix21()
        self.assertIn("type", result)
        self.assertEqual(result["type"], "bundle")
        self.assertIn("spec_version", result)
        self.assertEqual(result["spec_version"], "2.1")
        self.assertIn("objects", result)
        self.assertGreater(len(result["objects"]), 0)

        # Check identity object exists
        identity = [o for o in result["objects"] if o["type"] == "identity"]
        self.assertEqual(len(identity), 1)

        # Check indicators
        indicators = [o for o in result["objects"] if o["type"] == "indicator"]
        self.assertEqual(len(indicators), 3)

        # Verify pattern format
        self.assertIn("[ipv4-addr:value", indicators[0]["pattern"])

    def test_export_openioc(self):
        """Test OpenIOC export - REAL WORKING"""
        result = self.engine.export_openioc()
        self.assertIn("ioc", result)
        self.assertIn("@id", result["ioc"])
        self.assertIn("short_description", result["ioc"])
        self.assertIn("indicator", result["ioc"])
        self.assertIn("indicator_item", result["ioc"]["indicator"])
        self.assertEqual(len(result["ioc"]["indicator"]["indicator_item"]), 3)

    def test_export_csv(self):
        """Test CSV export - REAL WORKING"""
        result = self.engine.export_csv()
        self.assertIsInstance(result, str)
        lines = result.strip().split("\n")
        self.assertEqual(len(lines), 4)  # Header + 3 IOCs

        # Verify header
        self.assertIn("ioc_id", lines[0])
        self.assertIn("value", lines[0])
        self.assertIn("type", lines[0])

        # Parse CSV
        reader = csv.reader(io.StringIO(result))
        rows = list(reader)
        self.assertEqual(rows[0][0], "ioc_id")
        self.assertEqual(len(rows), 4)

    def test_export_json(self):
        """Test JSON export - REAL WORKING"""
        result = self.engine.export_json()
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 3)
        self.assertIn("value", result[0])
        self.assertIn("type", result[0])
        self.assertIn("hash", result[0])
        self.assertIn("confidence", result[0])

    def test_export_misp(self):
        """Test MISP format export - REAL WORKING"""
        result = self.engine.export_misp()
        self.assertIn("Event", result)
        self.assertIn("info", result["Event"])
        self.assertIn("Attribute", result["Event"])
        self.assertEqual(len(result["Event"]["Attribute"]), 3)
        self.assertIn("type", result["Event"]["Attribute"][0])
        self.assertIn("value", result["Event"]["Attribute"][0])

    def test_export_generic_method(self):
        """Test generic export method with all formats"""
        for fmt in ExportFormat:
            result = self.engine.export(fmt)
            self.assertIsNotNone(result)


class TestStatistics(unittest.TestCase):
    """Test statistics functionality"""

    def test_empty_statistics(self):
        """Test statistics with empty collection"""
        engine = IOCExportEngine()
        stats = engine.get_statistics()
        self.assertEqual(stats["total_iocs"], 0)
        self.assertEqual(stats["avg_confidence"], 0.0)

    def test_populated_statistics(self):
        """Test statistics with IOCs"""
        engine = IOCExportEngine()
        engine.add_iocs([
            IndicatorOfCompromise(value="1.1.1.1", ioc_type=IOType.IPV4, confidence=0.8),
            IndicatorOfCompromise(value="2.2.2.2", ioc_type=IOType.IPV4, confidence=0.9),
            IndicatorOfCompromise(value="evil.com", ioc_type=IOType.DOMAIN, confidence=0.7),
        ])
        stats = engine.get_statistics()
        self.assertEqual(stats["total_iocs"], 3)
        self.assertIn("ipv4-addr", stats["by_type"])
        self.assertEqual(stats["by_type"]["ipv4-addr"], 2)
        self.assertAlmostEqual(stats["avg_confidence"], 0.8, places=1)


class TestFileOperations(unittest.TestCase):
    """Test file writing operations"""

    def test_write_json_file(self):
        """Test writing JSON export to file"""
        import tempfile
        import os

        engine = IOCExportEngine()
        engine.add_ioc(IndicatorOfCompromise(value="1.1.1.1", ioc_type=IOType.IPV4))

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            filepath = f.name

        try:
            engine.write_to_file(filepath, ExportFormat.JSON)
            self.assertTrue(os.path.exists(filepath))
            with open(filepath, 'r') as f:
                content = json.load(f)
            self.assertIsInstance(content, list)
        finally:
            if os.path.exists(filepath):
                os.unlink(filepath)

    def test_write_csv_file(self):
        """Test writing CSV export to file"""
        import tempfile
        import os

        engine = IOCExportEngine()
        engine.add_ioc(IndicatorOfCompromise(value="1.1.1.1", ioc_type=IOType.IPV4))

        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            filepath = f.name

        try:
            engine.write_to_file(filepath, ExportFormat.CSV)
            self.assertTrue(os.path.exists(filepath))
            with open(filepath, 'r') as f:
                content = f.read()
            self.assertIn("ioc_id", content)
        finally:
            if os.path.exists(filepath):
                os.unlink(filepath)


if __name__ == "__main__":
    # Run tests and show summary
    suite = unittest.TestLoader().loadTestsFromTestCase(TestIndicatorOfCompromise)
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestIOCExportEngineBasic))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestIOCFiltering))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestExportFormats))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestStatistics))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestFileOperations))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "="*60)
    print(f"TEST SUMMARY: {result.testsRun - len(result.failures) - len(result.errors)} PASSED, {len(result.failures) + len(result.errors)} FAILED")
    if result.wasSuccessful():
        print("ALL TESTS PASSED - REAL WORKING IMPLEMENTATION")
    else:
        print("SOME TESTS FAILED")
    print("="*60)
