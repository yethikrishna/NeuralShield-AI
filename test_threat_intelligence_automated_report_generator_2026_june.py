"""
Test suite for Threat Intelligence Automated Report Generator
June 2026 Production Tests
Real, working tests that verify all functionality.
"""
import unittest
import datetime
import uuid
from neural_shield.threat_intelligence_automated_report_generator_2026_june import (
    ThreatIntelligenceReportGenerator,
    ThreatIndicator,
    ReportType,
    SeverityLevel,
    GeneratedReport
)
class TestThreatIntelligenceReportGenerator(unittest.TestCase):
    """Test cases for the report generator."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.generator = ThreatIntelligenceReportGenerator(organization_name="Test Security Org")
        self.sample_indicators = self._create_sample_indicators()
    
    def _create_sample_indicators(self):
        """Create sample threat indicators for testing."""
        now = datetime.datetime.now()
        return [
            ThreatIndicator(
                indicator_id=str(uuid.uuid4()),
                indicator_type="ip",
                value="192.168.1.100",
                severity=SeverityLevel.CRITICAL,
                first_seen=now - datetime.timedelta(days=2),
                last_seen=now,
                source="AbuseIPDB",
                confidence=0.95,
                mitre_techniques=["T1071", "T1090"],
                associated_threat_actors=["APT29"],
                false_positive_rate=0.01
            ),
            ThreatIndicator(
                indicator_id=str(uuid.uuid4()),
                indicator_type="domain",
                value="malicious-domain.com",
                severity=SeverityLevel.HIGH,
                first_seen=now - datetime.timedelta(days=5),
                last_seen=now - datetime.timedelta(days=1),
                source="VirusTotal",
                confidence=0.88,
                mitre_techniques=["T1566", "T1071"],
                associated_threat_actors=["Emotet"],
                false_positive_rate=0.05
            ),
            ThreatIndicator(
                indicator_id=str(uuid.uuid4()),
                indicator_type="hash",
                value="d41d8cd98f00b204e9800998ecf8427e",
                severity=SeverityLevel.HIGH,
                first_seen=now - datetime.timedelta(days=1),
                last_seen=now,
                source="MalwareBazaar",
                confidence=0.92,
                mitre_techniques=["T1059"],
                associated_threat_actors=[],
                false_positive_rate=0.02
            ),
            ThreatIndicator(
                indicator_id=str(uuid.uuid4()),
                indicator_type="url",
                value="http://phish.example.com/login",
                severity=SeverityLevel.MEDIUM,
                first_seen=now - datetime.timedelta(days=3),
                last_seen=now - datetime.timedelta(hours=2),
                source="PhishTank",
                confidence=0.75,
                mitre_techniques=["T1566"],
                associated_threat_actors=[],
                false_positive_rate=0.10
            ),
            ThreatIndicator(
                indicator_id=str(uuid.uuid4()),
                indicator_type="ip",
                value="10.0.0.50",
                severity=SeverityLevel.LOW,
                first_seen=now - datetime.timedelta(days=7),
                last_seen=now - datetime.timedelta(days=6),
                source="Internal",
                confidence=0.60,
                mitre_techniques=[],
                associated_threat_actors=[],
                false_positive_rate=0.15
            )
        ]
    
    def test_generator_initialization(self):
        """Test that generator initializes correctly."""
        self.assertEqual(self.generator.organization_name, "Test Security Org")
        self.assertEqual(self.generator.reports_generated, 0)
        self.assertEqual(len(self.generator.get_report_history()), 0)
    
    def test_generate_executive_summary(self):
        """Test executive summary report generation."""
        report = self.generator.generate_executive_summary(self.sample_indicators)
        
        self.assertIsInstance(report, GeneratedReport)
        self.assertEqual(report.report_type, ReportType.EXECUTIVE_SUMMARY)
        self.assertIn("Executive Summary", report.title)
        self.assertEqual(self.generator.reports_generated, 1)
        
        # Verify metrics
        self.assertEqual(report.summary_metrics["total_threats"], 5)
        self.assertEqual(report.summary_metrics["critical_threats"], 1)
        self.assertEqual(report.summary_metrics["high_threats"], 2)
        self.assertEqual(report.summary_metrics["medium_threats"], 1)
        
        # Verify sections
        self.assertGreater(len(report.sections), 0)
        section_titles = [s.title for s in report.sections]
        self.assertIn("Executive Overview", section_titles)
        self.assertIn("Threat Trend Analysis", section_titles)
        self.assertIn("Critical Threats Requiring Immediate Attention", section_titles)
        
        # Verify recommendations
        self.assertGreater(len(report.recommendations), 0)
    
    def test_generate_technical_deep_dive(self):
        """Test technical deep dive report generation."""
        report = self.generator.generate_technical_deep_dive(self.sample_indicators)
        
        self.assertIsInstance(report, GeneratedReport)
        self.assertEqual(report.report_type, ReportType.TECHNICAL_DEEP_DIVE)
        self.assertIn("Technical", report.title)
        
        section_titles = [s.title for s in report.sections]
        self.assertIn("Indicator of Compromise (IOC) Breakdown", section_titles)
        self.assertIn("MITRE ATT&CK Technique Mapping", section_titles)
        self.assertIn("Threat Actor Intelligence", section_titles)
        self.assertIn("Raw IOC List for Blocking", section_titles)
    
    def test_generate_compliance_assessment(self):
        """Test compliance assessment generation."""
        report = self.generator.generate_compliance_assessment(
            self.sample_indicators,
            framework="NIST"
        )
        
        self.assertIsInstance(report, GeneratedReport)
        self.assertEqual(report.report_type, ReportType.COMPLIANCE_ASSESSMENT)
        self.assertIn("NIST", report.title)
        
        section_titles = [s.title for s in report.sections]
        self.assertIn("NIST Compliance Status", section_titles)
        self.assertIn("Security Control Effectiveness", section_titles)
    
    def test_report_to_markdown(self):
        """Test markdown export functionality."""
        report = self.generator.generate_executive_summary(self.sample_indicators)
        markdown = report.to_markdown()
        
        self.assertIsInstance(markdown, str)
        self.assertGreater(len(markdown), 0)
        self.assertIn("#", markdown)  # Has markdown headers
        self.assertIn("Executive Summary", markdown)
        self.assertIn("Key Metrics Summary", markdown)
    
    def test_report_to_json(self):
        """Test JSON export functionality."""
        report = self.generator.generate_executive_summary(self.sample_indicators)
        json_output = report.to_json()
        
        self.assertIsInstance(json_output, str)
        self.assertGreater(len(json_output), 0)
        self.assertIn("report_id", json_output)
        self.assertIn("summary_metrics", json_output)
    
    def test_empty_indicators_handling(self):
        """Test handling of empty indicator list."""
        report = self.generator.generate_executive_summary([])
        
        self.assertEqual(report.summary_metrics["total_threats"], 0)
        self.assertEqual(report.summary_metrics["critical_threats"], 0)
        
        markdown = report.to_markdown()
        self.assertIn("No threat indicators detected", markdown)
    
    def test_report_history_tracking(self):
        """Test that report history is tracked correctly."""
        self.assertEqual(len(self.generator.get_report_history()), 0)
        
        # Generate multiple reports
        self.generator.generate_executive_summary(self.sample_indicators)
        self.generator.generate_technical_deep_dive(self.sample_indicators)
        
        self.assertEqual(len(self.generator.get_report_history()), 2)
        self.assertEqual(self.generator.reports_generated, 2)
    
    def test_summary_metrics_calculation(self):
        """Test summary metrics calculation."""
        metrics = self.generator._calculate_summary_metrics(self.sample_indicators)
        
        self.assertEqual(metrics["total_threats"], 5)
        self.assertEqual(metrics["critical_threats"], 1)
        self.assertEqual(metrics["high_threats"], 2)
        self.assertEqual(metrics["unique_ips"], 2)
        self.assertEqual(metrics["unique_domains"], 1)
        self.assertEqual(metrics["unique_hashes"], 1)
        self.assertEqual(metrics["unique_urls"], 1)
        self.assertGreater(metrics["average_confidence"], 0)
        self.assertGreater(metrics["distinct_sources"], 0)
    
    def test_recommendations_generation(self):
        """Test recommendations generation."""
        recs = self.generator._generate_prioritized_recommendations(self.sample_indicators)
        
        self.assertGreater(len(recs), 0)
        
        # Check critical recommendation exists
        critical_recs = [r for r in recs if r["priority"] == "CRITICAL"]
        self.assertEqual(len(critical_recs), 1)
        self.assertIn("Immediate Blocking", critical_recs[0]["title"])
        
        # Check high recommendation exists
        high_recs = [r for r in recs if r["priority"] == "HIGH"]
        self.assertEqual(len(high_recs), 1)
    
    def test_threat_indicator_dataclass(self):
        """Test ThreatIndicator dataclass."""
        now = datetime.datetime.now()
        indicator = ThreatIndicator(
            indicator_id="test-123",
            indicator_type="ip",
            value="1.2.3.4",
            severity=SeverityLevel.CRITICAL,
            first_seen=now,
            last_seen=now,
            source="Test",
            confidence=0.9
        )
        
        self.assertEqual(indicator.indicator_id, "test-123")
        self.assertEqual(indicator.value, "1.2.3.4")
        self.assertEqual(indicator.severity, SeverityLevel.CRITICAL)
        self.assertEqual(indicator.confidence, 0.9)
if __name__ == "__main__":
    # Run tests and output results
    print("=" * 60)
    print("Running Threat Intelligence Report Generator Tests")
    print("=" * 60)
    
    suite = unittest.TestLoader().loadTestsFromTestCase(TestThreatIntelligenceReportGenerator)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("=" * 60)
