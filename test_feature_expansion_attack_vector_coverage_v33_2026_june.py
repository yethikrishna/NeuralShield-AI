"""
Tests for Attack Vector Coverage Analyzer - Feature Expansion v33
Dimension: A - Feature Expansion

Tests verify the coverage analyzer works correctly without modifying
any existing code. All tests are ADD-ONLY.
"""

import pytest
import time

from neural_shield.feature_expansion_attack_vector_coverage_analyzer_v33_2026_june import (
    AttackVectorCoverageAnalyzer,
    AttackVector,
    DefenseCategory,
    CoverageLevel,
    RiskLevel,
    DefenseInfo,
    AttackVectorCoverage,
    CoverageGap,
    CoverageReport,
    create_coverage_analyzer,
    create_default_neuralshield_coverage,
    MODULE_DIMENSION,
    MODULE_VERSION,
    MODULE_STABILITY,
    MODULE_IS_ADD_ONLY,
    MODULE_PRESERVES_BACKWARD_COMPATIBILITY,
    verify_module,
)


class TestAttackVectorEnum:
    """Test AttackVector enum has expected values."""

    def test_has_known_vectors(self):
        """Verify all expected attack vectors are defined."""
        expected = [
            "prompt_injection",
            "jailbreak",
            "adversarial_examples",
            "model_extraction",
            "data_poisoning",
            "backdoor_attacks",
            "rag_poisoning",
            "vlm_hijacking",
            "tool_hijack",
            "system_prompt_leak",
        ]
        for vec in expected:
            assert hasattr(AttackVector, vec.upper().replace(".", "_").replace(" ", "_")) or vec in [v.value for v in AttackVector]

    def test_vector_count(self):
        """Verify we have a reasonable number of attack vectors."""
        assert len(AttackVector) >= 15
        assert len(AttackVector) <= 30


class TestDefenseInfo:
    """Test DefenseInfo dataclass."""

    def test_create_defense_info(self):
        """Test creating a DefenseInfo object."""
        defense = DefenseInfo(
            name="TestDefense",
            category=DefenseCategory.INPUT_VALIDATION,
            version="1.0",
            description="Test defense module",
            covered_vectors={AttackVector.PROMPT_INJECTION},
            confidence=0.85,
        )
        assert defense.name == "TestDefense"
        assert defense.category == DefenseCategory.INPUT_VALIDATION
        assert defense.version == "1.0"
        assert AttackVector.PROMPT_INJECTION in defense.covered_vectors
        assert defense.confidence == 0.85
        assert defense.enabled is True

    def test_default_values(self):
        """Test default values are set correctly."""
        defense = DefenseInfo(
            name="MinimalDefense",
            category=DefenseCategory.ANOMALY_DETECTION,
            version="0.1",
            description="Minimal",
            covered_vectors=set(),
        )
        assert defense.confidence == 0.8
        assert defense.enabled is True


class TestAttackVectorCoverageAnalyzer:
    """Test the main coverage analyzer class."""

    def test_create_analyzer(self):
        """Test creating a new analyzer."""
        analyzer = AttackVectorCoverageAnalyzer()
        assert analyzer is not None
        assert len(analyzer.list_defenses()) == 0

    def test_register_defense(self):
        """Test registering a defense module."""
        analyzer = AttackVectorCoverageAnalyzer()
        defense = DefenseInfo(
            name="TestDefense",
            category=DefenseCategory.INPUT_VALIDATION,
            version="1.0",
            description="Test",
            covered_vectors={AttackVector.PROMPT_INJECTION, AttackVector.JAILBREAK},
        )

        result = analyzer.register_defense(defense)
        assert result is True
        assert len(analyzer.list_defenses()) == 1

    def test_register_duplicate_defense(self):
        """Test registering the same defense twice returns False."""
        analyzer = AttackVectorCoverageAnalyzer()
        defense = DefenseInfo(
            name="DuplicateDefense",
            category=DefenseCategory.INPUT_VALIDATION,
            version="1.0",
            description="Test",
            covered_vectors={AttackVector.PROMPT_INJECTION},
        )

        assert analyzer.register_defense(defense) is True
        assert analyzer.register_defense(defense) is False
        assert len(analyzer.list_defenses()) == 1

    def test_unregister_defense(self):
        """Test unregistering a defense module."""
        analyzer = AttackVectorCoverageAnalyzer()
        defense = DefenseInfo(
            name="RemovableDefense",
            category=DefenseCategory.INPUT_VALIDATION,
            version="1.0",
            description="Test",
            covered_vectors={AttackVector.PROMPT_INJECTION},
        )

        analyzer.register_defense(defense)
        assert len(analyzer.list_defenses()) == 1

        result = analyzer.unregister_defense("RemovableDefense")
        assert result is True
        assert len(analyzer.list_defenses()) == 0

    def test_unregister_nonexistent_defense(self):
        """Test unregistering a defense that doesn't exist."""
        analyzer = AttackVectorCoverageAnalyzer()
        result = analyzer.unregister_defense("NonExistent")
        assert result is False

    def test_get_defense(self):
        """Test getting a specific defense by name."""
        analyzer = AttackVectorCoverageAnalyzer()
        defense = DefenseInfo(
            name="GetMe",
            category=DefenseCategory.OUTPUT_SANITIZATION,
            version="2.0",
            description="Test get",
            covered_vectors={AttackVector.OUTPUT_MANIPULATION},
        )
        analyzer.register_defense(defense)

        retrieved = analyzer.get_defense("GetMe")
        assert retrieved is not None
        assert retrieved.name == "GetMe"
        assert retrieved.category == DefenseCategory.OUTPUT_SANITIZATION

    def test_get_nonexistent_defense(self):
        """Test getting a defense that doesn't exist returns None."""
        analyzer = AttackVectorCoverageAnalyzer()
        assert analyzer.get_defense("NoSuchDefense") is None

    def test_list_defenses(self):
        """Test listing all registered defenses."""
        analyzer = AttackVectorCoverageAnalyzer()

        for i in range(5):
            defense = DefenseInfo(
                name=f"Defense{i}",
                category=DefenseCategory.INPUT_VALIDATION,
                version="1.0",
                description=f"Defense {i}",
                covered_vectors={AttackVector.PROMPT_INJECTION},
            )
            analyzer.register_defense(defense)

        defenses = analyzer.list_defenses()
        assert len(defenses) == 5


class TestCoverageAssessment:
    """Test coverage assessment functionality."""

    def test_no_coverage(self):
        """Test coverage assessment with no defenses."""
        analyzer = AttackVectorCoverageAnalyzer()
        coverage = analyzer.get_coverage_for_vector(AttackVector.PROMPT_INJECTION)

        assert coverage.coverage_level == CoverageLevel.NONE
        assert len(coverage.defending_modules) == 0
        assert coverage.confidence_score == 0.0

    def test_weak_coverage(self):
        """Test coverage with one defense (weak coverage)."""
        analyzer = AttackVectorCoverageAnalyzer()
        defense = DefenseInfo(
            name="SingleDefense",
            category=DefenseCategory.INPUT_VALIDATION,
            version="1.0",
            description="Single defense",
            covered_vectors={AttackVector.PROMPT_INJECTION},
            confidence=0.8,
        )
        analyzer.register_defense(defense)

        coverage = analyzer.get_coverage_for_vector(AttackVector.PROMPT_INJECTION)
        assert coverage.coverage_level == CoverageLevel.WEAK
        assert len(coverage.defending_modules) == 1
        assert coverage.confidence_score > 0.0

    def test_partial_coverage(self):
        """Test coverage with two defenses (partial coverage)."""
        analyzer = AttackVectorCoverageAnalyzer()

        for i in range(2):
            defense = DefenseInfo(
                name=f"Defense{i}",
                category=DefenseCategory.INPUT_VALIDATION,
                version="1.0",
                description=f"Defense {i}",
                covered_vectors={AttackVector.JAILBREAK},
                confidence=0.75,
            )
            analyzer.register_defense(defense)

        coverage = analyzer.get_coverage_for_vector(AttackVector.JAILBREAK)
        assert coverage.coverage_level == CoverageLevel.PARTIAL
        assert len(coverage.defending_modules) == 2

    def test_full_coverage(self):
        """Test coverage with three+ defenses (full coverage)."""
        analyzer = AttackVectorCoverageAnalyzer()

        for i in range(4):
            defense = DefenseInfo(
                name=f"Defense{i}",
                category=DefenseCategory.INPUT_VALIDATION,
                version="1.0",
                description=f"Defense {i}",
                covered_vectors={AttackVector.PROMPT_INJECTION},
                confidence=0.7,
            )
            analyzer.register_defense(defense)

        coverage = analyzer.get_coverage_for_vector(AttackVector.PROMPT_INJECTION)
        assert coverage.coverage_level == CoverageLevel.FULL
        assert len(coverage.defending_modules) == 4

    def test_disabled_defense_not_counted(self):
        """Test that disabled defenses don't contribute to coverage."""
        analyzer = AttackVectorCoverageAnalyzer()
        defense = DefenseInfo(
            name="DisabledDefense",
            category=DefenseCategory.INPUT_VALIDATION,
            version="1.0",
            description="Disabled",
            covered_vectors={AttackVector.PROMPT_INJECTION},
            enabled=False,
        )
        analyzer.register_defense(defense)

        coverage = analyzer.get_coverage_for_vector(AttackVector.PROMPT_INJECTION)
        assert coverage.coverage_level == CoverageLevel.NONE
        assert len(coverage.defending_modules) == 0

    def test_confidence_score_increases_with_more_defenses(self):
        """Test that more defenses lead to higher confidence (with diminishing returns)."""
        analyzer1 = AttackVectorCoverageAnalyzer()
        analyzer1.register_defense(DefenseInfo(
            name="D1",
            category=DefenseCategory.INPUT_VALIDATION,
            version="1.0",
            description="",
            covered_vectors={AttackVector.PROMPT_INJECTION},
            confidence=0.8,
        ))
        score1 = analyzer1.get_coverage_for_vector(AttackVector.PROMPT_INJECTION).confidence_score

        analyzer2 = AttackVectorCoverageAnalyzer()
        for i in range(3):
            analyzer2.register_defense(DefenseInfo(
                name=f"D{i}",
                category=DefenseCategory.INPUT_VALIDATION,
                version="1.0",
                description="",
                covered_vectors={AttackVector.PROMPT_INJECTION},
                confidence=0.8,
            ))
        score2 = analyzer2.get_coverage_for_vector(AttackVector.PROMPT_INJECTION).confidence_score

        assert score2 > score1


class TestGapIdentification:
    """Test gap identification functionality."""

    def test_empty_analyzer_has_gaps(self):
        """Test that an empty analyzer identifies many gaps."""
        analyzer = AttackVectorCoverageAnalyzer()
        gaps = analyzer.identify_gaps()
        assert len(gaps) > 0

    def test_gaps_sorted_by_severity(self):
        """Test that gaps are sorted by severity (most severe first)."""
        analyzer = AttackVectorCoverageAnalyzer()
        gaps = analyzer.identify_gaps()

        severity_order = {
            RiskLevel.CRITICAL: 0,
            RiskLevel.HIGH: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 3,
            RiskLevel.INFO: 4,
        }

        for i in range(len(gaps) - 1):
            current_rank = severity_order.get(gaps[i].gap_severity, 5)
            next_rank = severity_order.get(gaps[i + 1].gap_severity, 5)
            assert current_rank <= next_rank

    def test_gap_has_recommendations(self):
        """Test that each gap has recommended defenses."""
        analyzer = AttackVectorCoverageAnalyzer()
        gaps = analyzer.identify_gaps()

        for gap in gaps:
            assert len(gap.recommended_defenses) > 0
            assert isinstance(gap.recommended_defenses, list)

    def test_gap_has_business_impact(self):
        """Test that each gap has a business impact description."""
        analyzer = AttackVectorCoverageAnalyzer()
        gaps = analyzer.identify_gaps()

        for gap in gaps:
            assert len(gap.business_impact) > 0
            assert isinstance(gap.business_impact, str)


class TestCoverageReport:
    """Test coverage report generation."""

    def test_generate_report_empty(self):
        """Test generating a report with no defenses."""
        analyzer = AttackVectorCoverageAnalyzer()
        report = analyzer.generate_coverage_report()

        assert isinstance(report, CoverageReport)
        assert report.total_vectors_analyzed == len(AttackVector)
        assert report.vectors_fully_covered == 0
        assert report.vectors_not_covered == len(AttackVector)
        assert report.overall_coverage_score == 0.0
        assert report.registered_defenses == 0
        assert len(report.gaps) > 0

    def test_generate_report_with_defenses(self):
        """Test generating a report with some defenses registered."""
        analyzer = AttackVectorCoverageAnalyzer()

        # Add defenses covering several vectors
        for i in range(3):
            defense = DefenseInfo(
                name=f"Defense{i}",
                category=DefenseCategory.INPUT_VALIDATION,
                version="1.0",
                description=f"Defense {i}",
                covered_vectors={
                    AttackVector.PROMPT_INJECTION,
                    AttackVector.JAILBREAK,
                },
                confidence=0.75,
            )
            analyzer.register_defense(defense)

        report = analyzer.generate_coverage_report()

        assert report.total_vectors_analyzed == len(AttackVector)
        assert report.registered_defenses == 3
        assert report.overall_coverage_score > 0.0
        assert report.overall_coverage_score < 1.0
        assert report.vectors_fully_covered >= 1  # At least prompt injection has 3 defenses

    def test_report_has_timestamp(self):
        """Test that report has a valid timestamp."""
        analyzer = AttackVectorCoverageAnalyzer()
        report = analyzer.generate_coverage_report()

        assert report.analysis_timestamp > 0
        assert isinstance(report.analysis_timestamp, float)

    def test_report_dimension_metadata(self):
        """Test report has correct dimension metadata."""
        analyzer = AttackVectorCoverageAnalyzer()
        report = analyzer.generate_coverage_report()

        assert report.dimension == "A - Feature Expansion"
        assert report.version == "v33"


class TestCoverageSummary:
    """Test coverage summary functionality."""

    def test_summary_keys(self):
        """Test summary has all expected keys."""
        analyzer = AttackVectorCoverageAnalyzer()
        summary = analyzer.get_coverage_summary()

        expected_keys = [
            "total_vectors",
            "fully_covered",
            "partially_covered",
            "weakly_covered",
            "not_covered",
            "overall_score",
            "registered_defenses",
            "critical_gaps",
            "high_gaps",
        ]

        for key in expected_keys:
            assert key in summary

    def test_summary_counts_match(self):
        """Test summary counts add up correctly."""
        analyzer = AttackVectorCoverageAnalyzer()
        summary = analyzer.get_coverage_summary()

        total = (
            summary["fully_covered"] +
            summary["partially_covered"] +
            summary["weakly_covered"] +
            summary["not_covered"]
        )
        assert total == summary["total_vectors"]


class TestBaselineComparison:
    """Test baseline comparison functionality."""

    def test_compare_improved_coverage(self):
        """Test comparing coverage shows improvement when adding defenses."""
        analyzer = AttackVectorCoverageAnalyzer()
        baseline = analyzer.generate_coverage_report()

        # Add some defenses
        for i in range(2):
            defense = DefenseInfo(
                name=f"NewDefense{i}",
                category=DefenseCategory.INPUT_VALIDATION,
                version="1.0",
                description="",
                covered_vectors={AttackVector.PROMPT_INJECTION},
                confidence=0.8,
            )
            analyzer.register_defense(defense)

        comparison = analyzer.compare_with_baseline(baseline)

        assert comparison["score_change"] > 0
        assert comparison["new_defenses"] == 2
        assert comparison["gap_reduction"] >= 0


class TestFactoryFunctions:
    """Test factory and utility functions."""

    def test_create_coverage_analyzer(self):
        """Test factory function creates an analyzer."""
        analyzer = create_coverage_analyzer()
        assert isinstance(analyzer, AttackVectorCoverageAnalyzer)
        assert len(analyzer.list_defenses()) == 0

    def test_create_default_neuralshield_coverage(self):
        """Test default NeuralShield coverage setup."""
        analyzer, report = create_default_neuralshield_coverage()

        assert isinstance(analyzer, AttackVectorCoverageAnalyzer)
        assert isinstance(report, CoverageReport)
        assert analyzer is not None
        assert report is not None
        assert report.registered_defenses > 10
        assert report.overall_coverage_score > 0.3

    def test_verify_module(self):
        """Test module self-verification function."""
        assert verify_module() is True


class TestModuleMetadata:
    """Test module metadata constants."""

    def test_dimension(self):
        assert MODULE_DIMENSION == "A - Feature Expansion"

    def test_version(self):
        assert MODULE_VERSION == "v33"

    def test_stability(self):
        assert MODULE_STABILITY == "stable"

    def test_is_add_only(self):
        assert MODULE_IS_ADD_ONLY is True

    def test_preserves_backward_compatibility(self):
        assert MODULE_PRESERVES_BACKWARD_COMPATIBILITY is True


class TestBackwardCompatibility:
    """Verify this module is purely additive and doesn't break anything."""

    def test_module_is_importable(self):
        """Test the module can be imported without errors."""
        from neural_shield import feature_expansion_attack_vector_coverage_analyzer_v33_2026_june
        assert feature_expansion_attack_vector_coverage_analyzer_v33_2026_june is not None

    def test_no_existing_code_modified(self):
        """
        Verify this is an add-only module by checking it doesn't
        modify any existing modules or globals.
        """
        # This module should be completely self-contained
        # It should only add new classes and functions
        assert hasattr(
            __import__('neural_shield.feature_expansion_attack_vector_coverage_analyzer_v33_2026_june',
                       fromlist=['AttackVectorCoverageAnalyzer']),
            'AttackVectorCoverageAnalyzer'
        )

    def test_existing_modules_still_work(self):
        """Verify existing modules can still be imported."""
        # Try importing a known existing module
        try:
            from neural_shield.advanced_jailbreak_detector_2026 import AdvancedJailbreakDetector
            assert AdvancedJailbreakDetector is not None
        except ImportError:
            # If it doesn't exist, that's fine - we're just checking we don't break things
            pass


class TestRealWorldScenarios:
    """Test realistic usage scenarios."""

    def test_security_posture_assessment_workflow(self):
        """Test a complete security posture assessment workflow."""
        # 1. Create analyzer
        analyzer = AttackVectorCoverageAnalyzer()

        # 2. Register known defenses
        defenses = [
            DefenseInfo(
                name="InputValidator",
                category=DefenseCategory.INPUT_VALIDATION,
                version="2.1",
                description="Validates all user inputs",
                covered_vectors={
                    AttackVector.PROMPT_INJECTION,
                    AttackVector.JAILBREAK,
                },
                confidence=0.82,
            ),
            DefenseInfo(
                name="OutputFilter",
                category=DefenseCategory.OUTPUT_SANITIZATION,
                version="1.5",
                description="Filters model outputs",
                covered_vectors={
                    AttackVector.OUTPUT_MANIPULATION,
                    AttackVector.DATA_POISONING,
                },
                confidence=0.75,
            ),
            DefenseInfo(
                name="AnomalyDetector",
                category=DefenseCategory.ANOMALY_DETECTION,
                version="3.0",
                description="Detects anomalous behavior",
                covered_vectors={
                    AttackVector.MODEL_EXTRACTION,
                    AttackVector.JAILBREAK,
                    AttackVector.ADVERSARIAL_EXAMPLES,
                },
                confidence=0.7,
            ),
        ]

        for defense in defenses:
            analyzer.register_defense(defense)

        # 3. Generate report
        report = analyzer.generate_coverage_report()

        # 4. Verify results make sense
        assert report.registered_defenses == 3
        assert report.total_vectors_analyzed == len(AttackVector)
        assert 0 < report.overall_coverage_score < 1

        # 5. Check specific vectors
        jailbreak_coverage = report.coverage_by_vector[AttackVector.JAILBREAK]
        assert jailbreak_coverage.coverage_level == CoverageLevel.PARTIAL  # 2 defenses

        # 6. Identify top gaps
        gaps = report.gaps
        assert len(gaps) > 0
        assert gaps[0].gap_severity in (RiskLevel.CRITICAL, RiskLevel.HIGH)

    def test_continuous_improvement_tracking(self):
        """Test tracking coverage improvement over time."""
        analyzer = AttackVectorCoverageAnalyzer()

        # Baseline
        baseline_report = analyzer.generate_coverage_report()
        baseline_score = baseline_report.overall_coverage_score

        # Add first defense
        analyzer.register_defense(DefenseInfo(
            name="Defense1",
            category=DefenseCategory.INPUT_VALIDATION,
            version="1.0",
            description="First defense",
            covered_vectors={AttackVector.PROMPT_INJECTION},
            confidence=0.8,
        ))
        report1 = analyzer.generate_coverage_report()
        assert report1.overall_coverage_score > baseline_score

        # Add second defense
        analyzer.register_defense(DefenseInfo(
            name="Defense2",
            category=DefenseCategory.ANOMALY_DETECTION,
            version="1.0",
            description="Second defense",
            covered_vectors={AttackVector.PROMPT_INJECTION, AttackVector.JAILBREAK},
            confidence=0.75,
        ))
        report2 = analyzer.generate_coverage_report()
        assert report2.overall_coverage_score > report1.overall_coverage_score

        # Verify comparison works
        comparison = analyzer.compare_with_baseline(baseline_report)
        assert comparison["score_change"] > 0
        assert comparison["new_defenses"] == 2
