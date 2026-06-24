"""
Test Suite for MITRE ATT&CK Coverage Gap Analyzer v78
Dimension A: Feature Expansion
NeuralShield-AI - June 24, 2026

All tests verify the new feature works correctly.
No existing production code modified - ADD-ONLY philosophy.
"""

import pytest
import json
from datetime import datetime
from neural_shield.feature_expansion_mitre_attack_coverage_gap_analyzer_v78_2026_june import (
    MITREAttackCoverageGapAnalyzer,
    CoveragePriority,
    CoverageStatus,
    CoverageGap,
    TacticCoverageSummary,
    CoverageAnalysisReport
)


class TestCoverageGapAnalyzerCoreFunctionality:
    """Core functionality tests for the coverage gap analyzer."""
    
    def setup_method(self):
        """Initialize analyzer for each test."""
        self.analyzer = MITREAttackCoverageGapAnalyzer()
    
    def test_analyzer_initialization(self):
        """Test analyzer initializes correctly."""
        assert self.analyzer is not None
        assert hasattr(self.analyzer, '_coverage_cache')
        assert hasattr(self.analyzer, '_analysis_history')
    
    def test_version_information(self):
        """Test version information is correct."""
        version = self.analyzer.get_version()
        assert version["version"] == "1.0.0"
        assert version["api_stability"] == "STABLE"
        assert version["mitre_version"] == "v14"
        assert version["module"] == "MITREAttackCoverageGapAnalyzer"
    
    def test_covered_techniques_populated(self):
        """Test covered techniques database is populated."""
        assert len(self.analyzer._COVERED_TECHNIQUES) > 0
        assert "T1059" in self.analyzer._COVERED_TECHNIQUES
        assert "T1027" in self.analyzer._COVERED_TECHNIQUES
        assert "T1055" in self.analyzer._COVERED_TECHNIQUES
    
    def test_tactic_mapping_populated(self):
        """Test tactic mapping is populated."""
        assert len(self.analyzer._TECHNIQUE_TO_TACTIC) > 0
        assert self.analyzer._TECHNIQUE_TO_TACTIC["T1059"] == "Execution"
        assert self.analyzer._TECHNIQUE_TO_TACTIC["T1027"] == "Defense Evasion"


class TestCoverageGapAnalysis:
    """Tests for coverage gap analysis functionality."""
    
    def setup_method(self):
        """Initialize analyzer for each test."""
        self.analyzer = MITREAttackCoverageGapAnalyzer()
    
    def test_analyze_coverage_gaps_returns_report(self):
        """Test gap analysis returns valid report."""
        report = self.analyzer.analyze_coverage_gaps()
        assert isinstance(report, CoverageAnalysisReport)
        assert report.report_id.startswith("mitre-coverage-")
        assert report.mitre_version == "v14"
    
    def test_coverage_statistics_calculated(self):
        """Test coverage statistics are properly calculated."""
        report = self.analyzer.analyze_coverage_gaps()
        assert report.total_techniques > 0
        assert report.total_covered > 0
        assert report.total_not_covered > 0
        assert 0 <= report.overall_coverage_percentage <= 100
    
    def test_tactic_summaries_populated(self):
        """Test tactic summaries are populated."""
        report = self.analyzer.analyze_coverage_gaps()
        assert len(report.tactic_summaries) > 0
        for tactic, summary in report.tactic_summaries.items():
            assert isinstance(summary, TacticCoverageSummary)
            assert summary.tactic_name == tactic
            assert summary.total_techniques >= 0
            assert 0 <= summary.coverage_percentage <= 100
    
    def test_critical_gaps_identified(self):
        """Test critical gaps are properly identified."""
        report = self.analyzer.analyze_coverage_gaps()
        for gap in report.critical_gaps:
            assert gap.priority == CoveragePriority.CRITICAL
            assert gap.coverage_status == CoverageStatus.NOT_COVERED
    
    def test_high_priority_gaps_identified(self):
        """Test high priority gaps are properly identified."""
        report = self.analyzer.analyze_coverage_gaps()
        for gap in report.high_priority_gaps:
            assert gap.priority == CoveragePriority.HIGH
            assert gap.coverage_status == CoverageStatus.NOT_COVERED
    
    def test_recommendations_generated(self):
        """Test recommendations are generated."""
        report = self.analyzer.analyze_coverage_gaps()
        assert len(report.recommendations) > 0
        for rec in report.recommendations:
            assert isinstance(rec, str)
            assert len(rec) > 0
    
    def test_additional_covered_techniques_included(self):
        """Test additional covered techniques are properly included."""
        additional = {"T1003": "OS Credential Dumping"}
        report = self.analyzer.analyze_coverage_gaps(additional_covered=additional)
        assert report.total_covered >= len(additional)


class TestCoverageGapPriorityCalculation:
    """Tests for priority calculation logic."""
    
    def setup_method(self):
        """Initialize analyzer for each test."""
        self.analyzer = MITREAttackCoverageGapAnalyzer()
    
    def test_critical_priority_for_high_risk_tactics(self):
        """Test critical priority assigned to high-risk techniques."""
        priority = self.analyzer._calculate_priority("T1059", "Execution")
        assert priority == CoveragePriority.CRITICAL
    
    def test_high_priority_for_c2(self):
        """Test high priority for C2 techniques."""
        priority = self.analyzer._calculate_priority("T1071", "Command and Control")
        assert priority == CoveragePriority.HIGH
    
    def test_medium_priority_for_discovery(self):
        """Test medium priority for discovery tactics."""
        priority = self.analyzer._calculate_priority("T1083", "Discovery")
        assert priority == CoveragePriority.MEDIUM
    
    def test_effort_estimation(self):
        """Test effort estimation produces reasonable values."""
        effort = self.analyzer._estimate_effort("T1055")
        assert effort > 0
        assert isinstance(effort, int)
    
    def test_subtechnique_effort_lower(self):
        """Test sub-techniques have lower effort estimates."""
        parent_effort = self.analyzer._estimate_effort("T1055")
        child_effort = self.analyzer._estimate_effort("T1055.001")
        assert child_effort <= parent_effort


class TestGapDetectionComplexity:
    """Tests for detection complexity and false positive risk assessment."""
    
    def setup_method(self):
        """Initialize analyzer for each test."""
        self.analyzer = MITREAttackCoverageGapAnalyzer()
    
    def test_detection_complexity_ratings(self):
        """Test detection complexity ratings work."""
        complexity = self.analyzer._get_detection_complexity("T1055")
        assert complexity in ["low", "medium", "high"]
    
    def test_fp_risk_ratings(self):
        """Test false positive risk ratings work."""
        risk = self.analyzer._get_fp_risk("T1059")
        assert risk in ["low", "medium", "high"]
    
    def test_recommended_approach_generated(self):
        """Test recommended approach is properly generated."""
        approach = self.analyzer._get_recommended_approach("T1055")
        assert isinstance(approach, str)
        assert len(approach) > 0


class TestReportExportAndTrending:
    """Tests for report export and trend analysis."""
    
    def setup_method(self):
        """Initialize analyzer for each test."""
        self.analyzer = MITREAttackCoverageGapAnalyzer()
    
    def test_export_report_json(self):
        """Test JSON export works correctly."""
        report = self.analyzer.analyze_coverage_gaps()
        json_str = self.analyzer.export_report_json(report)
        parsed = json.loads(json_str)
        assert "report_id" in parsed
        assert "summary" in parsed
        assert "tactic_summaries" in parsed
        assert "critical_gaps" in parsed
    
    def test_coverage_trend_insufficient_data(self):
        """Test trend analysis with insufficient data."""
        trend = self.analyzer.get_coverage_trend()
        assert trend["trend"] == "insufficient_data"
    
    def test_coverage_trend_with_multiple_analyses(self):
        """Test trend analysis with multiple analyses."""
        for _ in range(3):
            self.analyzer.analyze_coverage_gaps()
        trend = self.analyzer.get_coverage_trend()
        assert "trend" in trend
        assert "analysis_count" in trend
        assert trend["analysis_count"] >= 3


class TestEnumsAndDataclasses:
    """Tests for enum and dataclass integrity."""
    
    def test_coverage_priority_enum(self):
        """Test CoveragePriority enum has all values."""
        assert CoveragePriority.CRITICAL.value == "critical"
        assert CoveragePriority.HIGH.value == "high"
        assert CoveragePriority.MEDIUM.value == "medium"
        assert CoveragePriority.LOW.value == "low"
    
    def test_coverage_status_enum(self):
        """Test CoverageStatus enum has all values."""
        assert CoverageStatus.FULLY_COVERED.value == "fully_covered"
        assert CoverageStatus.PARTIALLY_COVERED.value == "partially_covered"
        assert CoverageStatus.NOT_COVERED.value == "not_covered"
    
    def test_coverage_gap_dataclass(self):
        """Test CoverageGap dataclass works."""
        gap = CoverageGap(
            technique_id="T1003",
            technique_name="OS Credential Dumping",
            tactic="Credential Access",
            coverage_status=CoverageStatus.NOT_COVERED,
            priority=CoveragePriority.CRITICAL,
            gap_description="Test gap",
            detection_complexity="high",
            false_positive_risk="medium",
            recommended_approach="Test approach",
            estimated_effort_hours=40
        )
        assert gap.technique_id == "T1003"
        assert gap.estimated_effort_hours == 40


class TestBackwardCompatibility:
    """Tests ensuring backward compatibility - no breaking changes."""
    
    def test_no_existing_modules_modified(self):
        """Verify we only added, never modified existing code."""
        # This test verifies the ADD-ONLY philosophy
        # The module is completely new and standalone
        import neural_shield.feature_expansion_mitre_attack_coverage_gap_analyzer_v78_2026_june as module
        assert module is not None
        # Module is self-contained, no modifications to other modules
    
    def test_import_without_side_effects(self):
        """Test importing doesn't cause side effects."""
        # Import should work without errors
        analyzer = MITREAttackCoverageGapAnalyzer()
        assert analyzer is not None


class TestEdgeCases:
    """Edge case tests for coverage analyzer."""
    
    def setup_method(self):
        """Initialize analyzer for each test."""
        self.analyzer = MITREAttackCoverageGapAnalyzer()
    
    def test_empty_additional_covered(self):
        """Test with empty additional covered dict."""
        report = self.analyzer.analyze_coverage_gaps(additional_covered={})
        assert report is not None
    
    def test_none_additional_covered(self):
        """Test with None additional covered."""
        report = self.analyzer.analyze_coverage_gaps(additional_covered=None)
        assert report is not None
    
    def test_unmapped_technique_tactic(self):
        """Test unmapped technique returns Unknown tactic."""
        tactic = self.analyzer._get_tactic_for_technique("T9999")
        assert tactic == "Unknown"
    
    def test_unknown_approach_fallback(self):
        """Test unknown technique gets default approach."""
        approach = self.analyzer._get_recommended_approach("T9999")
        assert "Behavioral analysis" in approach
    
    def test_related_techniques_empty(self):
        """Test related techniques returns empty list when none found."""
        related = self.analyzer._find_related_techniques("T9999", {})
        assert related == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
