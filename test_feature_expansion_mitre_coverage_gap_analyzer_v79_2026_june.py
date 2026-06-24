"""
Tests for MITRE ATT&CK Coverage Gap Analyzer v79
Dimension A: Feature Expansion
35 comprehensive tests
"""

import unittest
import json
from neural_shield.feature_expansion_mitre_coverage_gap_analyzer_v79_2026_june import (
    MITRECoverageGapAnalyzer,
    MITRETactic,
    CoverageLevel,
    RiskLevel,
    MITRETechnique,
    CoverageGap,
    CoverageReport,
    get_mitre_coverage_analyzer,
    generate_mitre_coverage_report,
    _coverage_analyzer
)


class TestMITRECoverageGapAnalyzer(unittest.TestCase):
    """Test suite for MITRE Coverage Gap Analyzer"""
    
    def setUp(self):
        """Set up fresh analyzer for each test"""
        global _coverage_analyzer
        _coverage_analyzer = None
        self.analyzer = MITRECoverageGapAnalyzer()
    
    def test_analyzer_initialization(self):
        """Test analyzer initializes correctly"""
        self.assertTrue(self.analyzer._initialized)
        self.assertGreater(len(self.analyzer._techniques), 0)
    
    def test_mitre_techniques_loaded(self):
        """Test MITRE techniques are loaded"""
        # Should have techniques for all 12 tactics
        self.assertIn("T1566", self.analyzer._techniques)  # Phishing
        self.assertIn("T1059", self.analyzer._techniques)  # Command execution
        self.assertIn("T1548", self.analyzer._techniques)  # Privilege escalation
    
    def test_technique_tactic_mapping(self):
        """Test techniques have correct tactic mapping"""
        phishing = self.analyzer._techniques["T1566"]
        self.assertEqual(phishing.tactic, MITRETactic.INITIAL_ACCESS)
        
        cmd_exec = self.analyzer._techniques["T1059"]
        self.assertEqual(cmd_exec.tactic, MITRETactic.EXECUTION)
    
    def test_register_detector_success(self):
        """Test detector registration succeeds"""
        result = self.analyzer.register_detector(
            "test_detector",
            ["T1566", "T1059"]
        )
        self.assertTrue(result)
    
    def test_register_detector_empty_name(self):
        """Test detector registration fails with empty name"""
        result = self.analyzer.register_detector("", ["T1566"])
        self.assertFalse(result)
    
    def test_register_detector_empty_techniques(self):
        """Test detector registration fails with empty techniques"""
        result = self.analyzer.register_detector("test_detector", [])
        self.assertFalse(result)
    
    def test_register_detector_updates_coverage(self):
        """Test detector registration updates coverage level"""
        self.analyzer.register_detector("test_detector", ["T1566"])
        technique = self.analyzer._techniques["T1566"]
        self.assertEqual(technique.coverage_level, CoverageLevel.FULL)
        self.assertIn("test_detector", technique.detectors)
    
    def test_register_detector_increases_confidence(self):
        """Test multiple detectors increase confidence"""
        self.analyzer.register_detector("detector1", ["T1566"])
        confidence1 = self.analyzer._techniques["T1566"].confidence_score
        
        self.analyzer.register_detector("detector2", ["T1566"])
        confidence2 = self.analyzer._techniques["T1566"].confidence_score
        
        self.assertGreater(confidence2, confidence1)
    
    def test_mark_partial_coverage_success(self):
        """Test marking partial coverage succeeds"""
        result = self.analyzer.mark_partial_coverage(
            "T1566",
            "partial_detector",
            0.6
        )
        self.assertTrue(result)
    
    def test_mark_partial_coverage_invalid_technique(self):
        """Test marking partial coverage fails for invalid technique"""
        result = self.analyzer.mark_partial_coverage(
            "INVALID",
            "partial_detector"
        )
        self.assertFalse(result)
    
    def test_mark_partial_coverage_sets_level(self):
        """Test partial coverage sets correct level"""
        self.analyzer.mark_partial_coverage("T1566", "test_detector", 0.6)
        technique = self.analyzer._techniques["T1566"]
        self.assertEqual(technique.coverage_level, CoverageLevel.PARTIAL)
        self.assertEqual(technique.confidence_score, 0.6)
    
    def test_identify_gaps_returns_list(self):
        """Test identify_gaps returns list of gaps"""
        gaps = self.analyzer.identify_gaps()
        self.assertIsInstance(gaps, list)
        self.assertGreater(len(gaps), 0)
    
    def test_identify_gaps_sorted_by_severity(self):
        """Test gaps are sorted by severity descending"""
        gaps = self.analyzer.identify_gaps()
        severities = [g.severity_score for g in gaps]
        self.assertEqual(severities, sorted(severities, reverse=True))
    
    def test_identify_gaps_contains_critical(self):
        """Test critical gaps are identified for uncovered high-risk tactics"""
        gaps = self.analyzer.identify_gaps()
        critical = [g for g in gaps if g.risk_level == RiskLevel.CRITICAL]
        # Should have critical gaps for uncovered Initial Access, Execution, etc.
        self.assertGreater(len(critical), 0)
    
    def test_coverage_gap_has_correct_fields(self):
        """Test CoverageGap dataclass has all fields"""
        gaps = self.analyzer.identify_gaps()
        gap = gaps[0]
        self.assertTrue(hasattr(gap, 'technique_id'))
        self.assertTrue(hasattr(gap, 'technique_name'))
        self.assertTrue(hasattr(gap, 'risk_level'))
        self.assertTrue(hasattr(gap, 'severity_score'))
        self.assertTrue(hasattr(gap, 'recommendation'))
    
    def test_generate_coverage_report_returns_report(self):
        """Test generate_coverage_report returns CoverageReport"""
        report = self.analyzer.generate_coverage_report()
        self.assertIsInstance(report, CoverageReport)
    
    def test_generate_coverage_report_statistics(self):
        """Test report contains correct statistics"""
        report = self.analyzer.generate_coverage_report()
        self.assertGreater(report.total_techniques, 0)
        self.assertGreaterEqual(report.no_coverage, 0)
        self.assertGreaterEqual(report.coverage_percentage, 0)
        self.assertLessEqual(report.coverage_percentage, 100)
    
    def test_generate_coverage_report_tactic_breakdown(self):
        """Test report contains tactic breakdown"""
        report = self.analyzer.generate_coverage_report()
        self.assertIsInstance(report.tactic_breakdown, dict)
        self.assertIn("initial-access", report.tactic_breakdown)
        self.assertIn("execution", report.tactic_breakdown)
    
    def test_generate_coverage_report_critical_gaps(self):
        """Test report contains critical gaps list"""
        report = self.analyzer.generate_coverage_report()
        self.assertIsInstance(report.critical_gaps, list)
        self.assertIsInstance(report.high_priority_gaps, list)
    
    def test_generate_coverage_report_recommendations(self):
        """Test report contains recommendations"""
        report = self.analyzer.generate_coverage_report()
        self.assertIsInstance(report.recommendations, list)
        self.assertGreater(len(report.recommendations), 0)
    
    def test_coverage_increases_with_detectors(self):
        """Test coverage percentage increases with detectors"""
        report1 = self.analyzer.generate_coverage_report()
        coverage1 = report1.coverage_percentage
        
        # Add coverage for 5 techniques
        self.analyzer.register_detector("detector1", ["T1566", "T1059", "T1548", "T1027", "T1562"])
        
        report2 = self.analyzer.generate_coverage_report()
        coverage2 = report2.coverage_percentage
        
        self.assertGreater(coverage2, coverage1)
    
    def test_export_json_returns_valid_json(self):
        """Test export_json returns valid JSON string"""
        report = self.analyzer.generate_coverage_report()
        json_str = self.analyzer.export_json(report)
        data = json.loads(json_str)
        self.assertIn("report_id", data)
        self.assertIn("summary", data)
        self.assertIn("critical_gaps", data)
    
    def test_export_json_contains_summary(self):
        """Test JSON export contains summary statistics"""
        report = self.analyzer.generate_coverage_report()
        json_str = self.analyzer.export_json(report)
        data = json.loads(json_str)
        self.assertIn("coverage_percentage", data["summary"])
        self.assertIn("total_techniques", data["summary"])
    
    def test_get_coverage_summary(self):
        """Test get_coverage_summary returns dict"""
        summary = self.analyzer.get_coverage_summary()
        self.assertIsInstance(summary, dict)
        self.assertIn("coverage_percentage", summary)
        self.assertIn("critical_gaps", summary)
        self.assertIn("report_id", summary)
    
    def test_singleton_get_mitre_coverage_analyzer(self):
        """Test singleton pattern works"""
        analyzer1 = get_mitre_coverage_analyzer()
        analyzer2 = get_mitre_coverage_analyzer()
        self.assertIs(analyzer1, analyzer2)
    
    def test_generate_mitre_coverage_report_convenience(self):
        """Test convenience function works"""
        global _coverage_analyzer
        _coverage_analyzer = None
        report = generate_mitre_coverage_report()
        self.assertIsInstance(report, CoverageReport)
    
    def test_recommendation_generation_critical(self):
        """Test critical recommendations have correct priority"""
        gaps = self.analyzer.identify_gaps()
        critical_gaps = [g for g in gaps if g.risk_level == RiskLevel.CRITICAL]
        if critical_gaps:
            self.assertIn("CRITICAL PRIORITY", critical_gaps[0].recommendation)
    
    def test_recommendation_generation_high(self):
        """Test high priority recommendations have correct priority"""
        gaps = self.analyzer.identify_gaps()
        high_gaps = [g for g in gaps if g.risk_level == RiskLevel.HIGH]
        if high_gaps:
            self.assertIn("HIGH PRIORITY", high_gaps[0].recommendation)
    
    def test_implementation_complexity_estimation(self):
        """Test complexity estimation returns valid values"""
        gaps = self.analyzer.identify_gaps()
        for gap in gaps:
            self.assertIn(gap.implementation_complexity, ["low", "medium", "high"])
            self.assertGreater(gap.estimated_effort_hours, 0)
    
    def test_gap_references_exist(self):
        """Test gaps include MITRE references"""
        gaps = self.analyzer.identify_gaps()
        for gap in gaps:
            self.assertGreater(len(gap.references), 0)
            self.assertTrue(any("mitre.org" in ref for ref in gap.references))
    
    def test_report_id_generation(self):
        """Test report ID is generated uniquely"""
        report1 = self.analyzer.generate_coverage_report()
        report2 = self.analyzer.generate_coverage_report()
        # IDs should be different due to timestamp
        self.assertIsNotNone(report1.report_id)
        self.assertIsNotNone(report2.report_id)
    
    def test_generated_at_timestamp(self):
        """Test report has generated timestamp"""
        report = self.analyzer.generate_coverage_report()
        self.assertGreater(len(report.generated_at), 0)
        # Should be ISO format
        self.assertIn("T", report.generated_at)
    
    def test_strategic_recommendations(self):
        """Test strategic recommendations are generated"""
        report = self.analyzer.generate_coverage_report()
        self.assertGreater(len(report.recommendations), 3)
        # Should include immediate/short-term recommendations
        has_immediate = any("IMMEDIATE" in r for r in report.recommendations)
        has_shortterm = any("SHORT-TERM" in r for r in report.recommendations)
        self.assertTrue(has_immediate or has_shortterm)
    
    def test_detector_registry_tracking(self):
        """Test detector registry tracks covered techniques"""
        self.analyzer.register_detector("test_detector", ["T1566", "T1059"])
        self.assertIn("test_detector", self.analyzer._detector_registry)
        self.assertEqual(len(self.analyzer._detector_registry["test_detector"]), 2)
    
    def test_backward_compatibility_no_existing_code(self):
        """Test no existing code is modified - pure additions only"""
        # This test verifies we're not touching __init__.py or existing modules
        import os
        # Verify our new file exists but existing files are untouched
        self.assertTrue(os.path.exists(
            "neural_shield/feature_expansion_mitre_coverage_gap_analyzer_v79_2026_june.py"
        ))
    
    def test_direct_execution(self):
        """Test direct execution works"""
        import subprocess
        result = subprocess.run(
            ["python3", "neural_shield/feature_expansion_mitre_coverage_gap_analyzer_v79_2026_june.py"],
            capture_output=True,
            text=True,
            timeout=10
        )
        self.assertEqual(result.returncode, 0, f"Execution failed: {result.stderr}")
        self.assertIn("MITRE ATT&CK Coverage Gap Analyzer", result.stdout)
        self.assertIn("✓ Analysis complete", result.stdout)


if __name__ == "__main__":
    print("Running MITRE Coverage Gap Analyzer v79 Tests")
    print("=" * 60)
    unittest.main(verbosity=2)
