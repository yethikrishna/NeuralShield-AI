"""
Attack Vector Coverage Analyzer - NeuralShield-AI Feature Expansion
Version: v33
Date: June 2026
Dimension: A - Feature Expansion

Analyzes which attack vectors are covered by existing security defenses
and identifies coverage gaps. Maps defenses to MITRE ATLAS (Adversarial
Threat Landscape for AI Systems) attack techniques.

ADD-ONLY: This module is purely additive. It does not modify any existing
code or break backward compatibility.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
import time


class AttackVector(str, Enum):
    """Known AI attack vectors based on MITRE ATLAS and industry research."""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    ADVERSARIAL_EXAMPLES = "adversarial_examples"
    MODEL_EXTRACTION = "model_extraction"
    DATA_POISONING = "data_poisoning"
    BACKDOOR_ATTACKS = "backdoor_attacks"
    MEMBERSHIP_INFERENCE = "membership_inference"
    MODEL_INVERSION = "model_inversion"
    VLM_HIJACKING = "vlm_hijacking"
    MULTIMODAL_INJECTION = "multimodal_injection"
    TOOL_HIJACK = "tool_hijack"
    MEMORY_POISONING = "memory_poisoning"
    RAG_POISONING = "rag_poisoning"
    CONVERSATION_HIJACK = "conversation_hijack"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"
    OUTPUT_MANIPULATION = "output_manipulation"
    HALLUCINATION_EXPLOITATION = "hallucination_exploitation"
    SUPPLY_CHAIN = "supply_chain"
    FINE_TUNING_ATTACK = "fine_tuning_attack"
    PROMPT_LEAKAGE = "prompt_leakage"


class DefenseCategory(str, Enum):
    """Categories of security defenses."""
    INPUT_VALIDATION = "input_validation"
    OUTPUT_SANITIZATION = "output_sanitization"
    ANOMALY_DETECTION = "anomaly_detection"
    ADVERSARIAL_TRAINING = "adversarial_training"
    ACCESS_CONTROL = "access_control"
    MEMORY_PROTECTION = "memory_protection"
    CONTENT_MODERATION = "content_moderation"
    RATE_LIMITING = "rate_limiting"
    AUDIT_LOGGING = "audit_logging"
    INTEGRITY_VERIFICATION = "integrity_verification"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    CONTEXTUAL_AWARENESS = "contextual_awareness"


class CoverageLevel(str, Enum):
    """Levels of defense coverage for an attack vector."""
    FULL = "full"           # Multiple overlapping defenses
    PARTIAL = "partial"     # Some defense coverage
    WEAK = "weak"           # Minimal defense coverage
    NONE = "none"           # No defense coverage
    UNKNOWN = "unknown"     # Coverage not assessed


class RiskLevel(str, Enum):
    """Risk levels based on coverage gaps and attack prevalence."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DefenseInfo:
    """Information about a security defense module."""
    name: str
    category: DefenseCategory
    version: str
    description: str
    covered_vectors: Set[AttackVector]
    confidence: float = 0.8  # How confident we are in this defense's effectiveness
    enabled: bool = True


@dataclass
class AttackVectorCoverage:
    """Coverage assessment for a single attack vector."""
    vector: AttackVector
    coverage_level: CoverageLevel
    defending_modules: List[str]
    confidence_score: float
    risk_if_uncovered: RiskLevel
    notes: str = ""


@dataclass
class CoverageGap:
    """Identified coverage gap in the security posture."""
    vector: AttackVector
    gap_severity: RiskLevel
    current_coverage: CoverageLevel
    recommended_defenses: List[str]
    estimated_effort: str  # "low", "medium", "high"
    business_impact: str


@dataclass
class CoverageReport:
    """Comprehensive coverage analysis report."""
    total_vectors_analyzed: int
    vectors_fully_covered: int
    vectors_partially_covered: int
    vectors_weakly_covered: int
    vectors_not_covered: int
    overall_coverage_score: float  # 0.0 - 1.0
    coverage_by_vector: Dict[AttackVector, AttackVectorCoverage]
    gaps: List[CoverageGap]
    registered_defenses: int
    analysis_timestamp: float
    dimension: str = "A - Feature Expansion"
    version: str = "v33"


class AttackVectorCoverageAnalyzer:
    """
    Analyzes attack vector coverage across all registered security defenses.

    This module provides:
    - Attack vector to defense mapping
    - Coverage gap identification
    - Risk assessment for uncovered vectors
    - Coverage scoring and recommendations

    Usage:
        analyzer = AttackVectorCoverageAnalyzer()
        analyzer.register_defense(defense_info)
        report = analyzer.generate_coverage_report()
    """

    def __init__(self):
        self._defenses: Dict[str, DefenseInfo] = {}
        self._vector_mappings: Dict[AttackVector, List[str]] = {}
        self._analysis_count = 0

    def register_defense(self, defense: DefenseInfo) -> bool:
        """
        Register a defense module for coverage analysis.

        Args:
            defense: DefenseInfo describing the defense module

        Returns:
            True if registered successfully, False if already registered
        """
        if defense.name in self._defenses:
            return False

        self._defenses[defense.name] = defense

        # Update vector mappings
        for vector in defense.covered_vectors:
            if vector not in self._vector_mappings:
                self._vector_mappings[vector] = []
            if defense.name not in self._vector_mappings[vector]:
                self._vector_mappings[vector].append(defense.name)

        return True

    def unregister_defense(self, defense_name: str) -> bool:
        """
        Unregister a defense module.

        Args:
            defense_name: Name of the defense to remove

        Returns:
            True if removed, False if not found
        """
        if defense_name not in self._defenses:
            return False

        defense = self._defenses[defense_name]
        del self._defenses[defense_name]

        # Update vector mappings
        for vector in defense.covered_vectors:
            if vector in self._vector_mappings:
                if defense_name in self._vector_mappings[vector]:
                    self._vector_mappings[vector].remove(defense_name)
                if not self._vector_mappings[vector]:
                    del self._vector_mappings[vector]

        return True

    def get_defense(self, defense_name: str) -> Optional[DefenseInfo]:
        """Get information about a registered defense."""
        return self._defenses.get(defense_name)

    def list_defenses(self) -> List[DefenseInfo]:
        """List all registered defenses."""
        return list(self._defenses.values())

    def get_coverage_for_vector(self, vector: AttackVector) -> AttackVectorCoverage:
        """
        Get coverage assessment for a specific attack vector.

        Args:
            vector: The attack vector to assess

        Returns:
            AttackVectorCoverage with detailed assessment
        """
        defending_modules = self._vector_mappings.get(vector, [])
        enabled_defenses = [
            name for name in defending_modules
            if self._defenses[name].enabled
        ]

        num_defenses = len(enabled_defenses)

        # Calculate coverage level
        if num_defenses == 0:
            coverage_level = CoverageLevel.NONE
        elif num_defenses == 1:
            coverage_level = CoverageLevel.WEAK
        elif num_defenses == 2:
            coverage_level = CoverageLevel.PARTIAL
        else:
            coverage_level = CoverageLevel.FULL

        # Calculate confidence score (weighted average of defense confidences)
        if enabled_defenses:
            confidences = [self._defenses[name].confidence for name in enabled_defenses]
            # Higher confidence with more overlapping defenses (diminishing returns)
            avg_confidence = sum(confidences) / len(confidences)
            overlap_bonus = min(0.15, (num_defenses - 1) * 0.05)
            confidence_score = min(1.0, avg_confidence + overlap_bonus)
        else:
            confidence_score = 0.0

        # Determine risk if uncovered
        risk_if_uncovered = self._get_vector_risk(vector)

        return AttackVectorCoverage(
            vector=vector,
            coverage_level=coverage_level,
            defending_modules=enabled_defenses,
            confidence_score=round(confidence_score, 3),
            risk_if_uncovered=risk_if_uncovered,
            notes=f"{num_defenses} defense(s) covering this vector"
        )

    def _get_vector_risk(self, vector: AttackVector) -> RiskLevel:
        """Get the inherent risk level of an attack vector if left uncovered."""
        high_risk_vectors = {
            AttackVector.PROMPT_INJECTION,
            AttackVector.JAILBREAK,
            AttackVector.DATA_POISONING,
            AttackVector.BACKDOOR_ATTACKS,
            AttackVector.RAG_POISONING,
            AttackVector.SYSTEM_PROMPT_LEAK,
        }

        medium_risk_vectors = {
            AttackVector.ADVERSARIAL_EXAMPLES,
            AttackVector.MODEL_EXTRACTION,
            AttackVector.VLM_HIJACKING,
            AttackVector.MULTIMODAL_INJECTION,
            AttackVector.TOOL_HIJACK,
            AttackVector.MEMORY_POISONING,
            AttackVector.CONVERSATION_HIJACK,
            AttackVector.OUTPUT_MANIPULATION,
            AttackVector.MEMBERSHIP_INFERENCE,
        }

        if vector in high_risk_vectors:
            return RiskLevel.CRITICAL
        elif vector in medium_risk_vectors:
            return RiskLevel.HIGH
        else:
            return RiskLevel.MEDIUM

    def identify_gaps(self) -> List[CoverageGap]:
        """
        Identify all coverage gaps in the current security posture.

        Returns:
            List of CoverageGap objects, sorted by severity
        """
        gaps = []

        for vector in AttackVector:
            coverage = self.get_coverage_for_vector(vector)

            # Consider it a gap if coverage is weak or none
            if coverage.coverage_level in (CoverageLevel.NONE, CoverageLevel.WEAK):
                gap_severity = self._calculate_gap_severity(coverage)
                recommendations = self._get_recommendations(vector)
                effort = self._estimate_implementation_effort(vector)
                impact = self._get_business_impact(vector)

                gaps.append(CoverageGap(
                    vector=vector,
                    gap_severity=gap_severity,
                    current_coverage=coverage.coverage_level,
                    recommended_defenses=recommendations,
                    estimated_effort=effort,
                    business_impact=impact
                ))

        # Sort by severity
        severity_order = {
            RiskLevel.CRITICAL: 0,
            RiskLevel.HIGH: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 3,
            RiskLevel.INFO: 4,
        }
        gaps.sort(key=lambda g: severity_order.get(g.gap_severity, 5))

        return gaps

    def _calculate_gap_severity(self, coverage: AttackVectorCoverage) -> RiskLevel:
        """Calculate the severity of a coverage gap."""
        if coverage.coverage_level == CoverageLevel.NONE:
            # No coverage at all - severity depends on vector risk
            return coverage.risk_if_uncovered
        else:
            # Weak coverage - downgrade one level
            risk_map = {
                RiskLevel.CRITICAL: RiskLevel.HIGH,
                RiskLevel.HIGH: RiskLevel.MEDIUM,
                RiskLevel.MEDIUM: RiskLevel.LOW,
                RiskLevel.LOW: RiskLevel.INFO,
            }
            return risk_map.get(coverage.risk_if_uncovered, RiskLevel.LOW)

    def _get_recommendations(self, vector: AttackVector) -> List[str]:
        """Get recommended defense types for a given attack vector."""
        recommendations = {
            AttackVector.PROMPT_INJECTION: [
                "Input validation with pattern matching",
                "Semantic analysis of prompts",
                "Context-aware injection detection",
                "Adversarial prompt fuzzing for testing",
            ],
            AttackVector.JAILBREAK: [
                "Multi-layer jailbreak detection",
                "Graph-based attack pattern recognition",
                "Conversation context monitoring",
                "Behavioral anomaly detection",
            ],
            AttackVector.ADVERSARIAL_EXAMPLES: [
                "Adversarial robustness scorer",
                "Input perturbation detection",
                "Gradient-based anomaly detection",
            ],
            AttackVector.MODEL_EXTRACTION: [
                "Query pattern analysis",
                "Rate limiting per API key",
                "Output perturbation",
                "Membership inference detection",
            ],
            AttackVector.DATA_POISONING: [
                "Training data validation",
                "Data integrity verification",
                "Supply chain verification",
            ],
            AttackVector.BACKDOOR_ATTACKS: [
                "Backdoor detection scanning",
                "Watermark verification",
                "Model integrity checks",
            ],
            AttackVector.VLM_HIJACKING: [
                "Visual prompt injection detection",
                "Attention pattern analysis",
                "Image integrity verification",
            ],
            AttackVector.TOOL_HIJACK: [
                "Tool call validation",
                "Parameter sanitization",
                "Access control enforcement",
            ],
            AttackVector.MEMORY_POISONING: [
                "Memory access monitoring",
                "Memory integrity verification",
                "Input validation for memory writes",
            ],
            AttackVector.RAG_POISONING: [
                "RAG context integrity verification",
                "Source attribution checking",
                "Document provenance verification",
            ],
        }
        return recommendations.get(vector, ["General security hardening", "Defense-in-depth layering"])

    def _estimate_implementation_effort(self, vector: AttackVector) -> str:
        """Estimate implementation effort for covering a vector."""
        low_effort = {
            AttackVector.RATE_LIMITING if hasattr(AttackVector, 'RATE_LIMITING') else None,
        }

        high_effort = {
            AttackVector.ADVERSARIAL_EXAMPLES,
            AttackVector.MODEL_EXTRACTION,
            AttackVector.FINE_TUNING_ATTACK,
            AttackVector.SUPPLY_CHAIN,
        }

        if vector in high_effort:
            return "high"
        elif vector in low_effort:
            return "low"
        else:
            return "medium"

    def _get_business_impact(self, vector: AttackVector) -> str:
        """Describe the business impact of an attack vector being exploited."""
        impacts = {
            AttackVector.PROMPT_INJECTION: "Unauthorized access, data exfiltration, compliance violations",
            AttackVector.JAILBREAK: "Security policy bypass, harmful content generation, brand damage",
            AttackVector.DATA_POISONING: "Model corruption, incorrect outputs, erosion of trust",
            AttackVector.BACKDOOR_ATTACKS: "Complete system compromise, unauthorized control",
            AttackVector.RAG_POISONING: "Misinformation, incorrect decisions, data integrity loss",
            AttackVector.SYSTEM_PROMPT_LEAK: "Intellectual property loss, security architecture exposure",
            AttackVector.MODEL_EXTRACTION: "IP theft, competitive disadvantage, model replication",
        }
        return impacts.get(vector, "Security degradation, potential data exposure")

    def generate_coverage_report(self) -> CoverageReport:
        """
        Generate a comprehensive coverage analysis report.

        Returns:
            CoverageReport with full analysis
        """
        self._analysis_count += 1

        all_vectors = list(AttackVector)
        coverage_by_vector = {}
        fully_covered = 0
        partially_covered = 0
        weakly_covered = 0
        not_covered = 0

        for vector in all_vectors:
            coverage = self.get_coverage_for_vector(vector)
            coverage_by_vector[vector] = coverage

            if coverage.coverage_level == CoverageLevel.FULL:
                fully_covered += 1
            elif coverage.coverage_level == CoverageLevel.PARTIAL:
                partially_covered += 1
            elif coverage.coverage_level == CoverageLevel.WEAK:
                weakly_covered += 1
            else:
                not_covered += 1

        # Calculate overall coverage score
        # Weighted: full=1.0, partial=0.6, weak=0.25, none=0.0
        total_weighted = (
            fully_covered * 1.0 +
            partially_covered * 0.6 +
            weakly_covered * 0.25 +
            not_covered * 0.0
        )
        overall_score = total_weighted / len(all_vectors) if all_vectors else 0.0

        gaps = self.identify_gaps()

        return CoverageReport(
            total_vectors_analyzed=len(all_vectors),
            vectors_fully_covered=fully_covered,
            vectors_partially_covered=partially_covered,
            vectors_weakly_covered=weakly_covered,
            vectors_not_covered=not_covered,
            overall_coverage_score=round(overall_score, 3),
            coverage_by_vector=coverage_by_vector,
            gaps=gaps,
            registered_defenses=len(self._defenses),
            analysis_timestamp=time.time(),
        )

    def get_coverage_summary(self) -> Dict[str, int]:
        """Get a quick summary of coverage counts."""
        report = self.generate_coverage_report()
        return {
            "total_vectors": report.total_vectors_analyzed,
            "fully_covered": report.vectors_fully_covered,
            "partially_covered": report.vectors_partially_covered,
            "weakly_covered": report.vectors_weakly_covered,
            "not_covered": report.vectors_not_covered,
            "overall_score": report.overall_coverage_score,
            "registered_defenses": report.registered_defenses,
            "critical_gaps": sum(1 for g in report.gaps if g.gap_severity == RiskLevel.CRITICAL),
            "high_gaps": sum(1 for g in report.gaps if g.gap_severity == RiskLevel.HIGH),
        }

    def compare_with_baseline(self, baseline: CoverageReport) -> Dict[str, float]:
        """
        Compare current coverage with a baseline report.

        Args:
            baseline: Previous coverage report to compare against

        Returns:
            Dictionary of comparison metrics
        """
        current = self.generate_coverage_report()

        return {
            "score_change": round(current.overall_coverage_score - baseline.overall_coverage_score, 3),
            "new_defenses": current.registered_defenses - baseline.registered_defenses,
            "gap_reduction": len(baseline.gaps) - len(current.gaps),
            "vectors_gained_full": (
                current.vectors_fully_covered - baseline.vectors_fully_covered
            ),
        }


def create_coverage_analyzer() -> AttackVectorCoverageAnalyzer:
    """Factory function to create a new coverage analyzer."""
    return AttackVectorCoverageAnalyzer()


def create_default_neuralshield_coverage() -> Tuple[AttackVectorCoverageAnalyzer, CoverageReport]:
    """
    Create a coverage analyzer pre-loaded with NeuralShield-AI's standard defenses.

    Returns:
        Tuple of (analyzer, initial_coverage_report)
    """
    analyzer = AttackVectorCoverageAnalyzer()

    # Register NeuralShield-AI's core defenses
    core_defenses = [
        DefenseInfo(
            name="AdvancedJailbreakDetector",
            category=DefenseCategory.ANOMALY_DETECTION,
            version="2026",
            description="Multi-layer jailbreak detection with pattern matching",
            covered_vectors={
                AttackVector.JAILBREAK,
                AttackVector.PROMPT_INJECTION,
                AttackVector.CONVERSATION_HIJACK,
            },
            confidence=0.85,
        ),
        DefenseInfo(
            name="ConstitutionalClassifier",
            category=DefenseCategory.CONTENT_MODERATION,
            version="2026",
            description="Constitutional AI-based content classification",
            covered_vectors={
                AttackVector.OUTPUT_MANIPULATION,
                AttackVector.JAILBREAK,
            },
            confidence=0.75,
        ),
        DefenseInfo(
            name="InputPurifier",
            category=DefenseCategory.INPUT_VALIDATION,
            version="2026",
            description="Input purification and sanitization",
            covered_vectors={
                AttackVector.PROMPT_INJECTION,
                AttackVector.ADVERSARIAL_EXAMPLES,
            },
            confidence=0.7,
        ),
        DefenseInfo(
            name="MemoryPoisoningDetector",
            category=DefenseCategory.MEMORY_PROTECTION,
            version="2026",
            description="Memory poisoning detection",
            covered_vectors={
                AttackVector.MEMORY_POISONING,
                AttackVector.DATA_POISONING,
            },
            confidence=0.8,
        ),
        DefenseInfo(
            name="RAGPoisoningDetector",
            category=DefenseCategory.INTEGRITY_VERIFICATION,
            version="2026",
            description="RAG context poisoning detection",
            covered_vectors={
                AttackVector.RAG_POISONING,
                AttackVector.DATA_POISONING,
            },
            confidence=0.78,
        ),
        DefenseInfo(
            name="SystemPromptLeakageDetector",
            category=DefenseCategory.ACCESS_CONTROL,
            version="2026",
            description="System prompt leakage detection",
            covered_vectors={
                AttackVector.SYSTEM_PROMPT_LEAK,
                AttackVector.PROMPT_LEAKAGE,
            },
            confidence=0.82,
        ),
        DefenseInfo(
            name="VLMAttentionHijackDefender",
            category=DefenseCategory.ANOMALY_DETECTION,
            version="2026",
            description="VLM attention hijacking defense",
            covered_vectors={
                AttackVector.VLM_HIJACKING,
                AttackVector.MULTIMODAL_INJECTION,
            },
            confidence=0.72,
        ),
        DefenseInfo(
            name="ModelExtractionDetector",
            category=DefenseCategory.BEHAVIORAL_ANALYSIS,
            version="2026",
            description="Model extraction attack detection",
            covered_vectors={
                AttackVector.MODEL_EXTRACTION,
                AttackVector.MEMBERSHIP_INFERENCE,
            },
            confidence=0.68,
        ),
        DefenseInfo(
            name="LLMBackdoorDetector",
            category=DefenseCategory.INTEGRITY_VERIFICATION,
            version="2026",
            description="Backdoor and watermark detection",
            covered_vectors={
                AttackVector.BACKDOOR_ATTACKS,
                AttackVector.DATA_POISONING,
            },
            confidence=0.7,
        ),
        DefenseInfo(
            name="AgentToolCallValidator",
            category=DefenseCategory.ACCESS_CONTROL,
            version="2026",
            description="Agent tool call security validation",
            covered_vectors={
                AttackVector.TOOL_HIJACK,
                AttackVector.PROMPT_INJECTION,
            },
            confidence=0.8,
        ),
        DefenseInfo(
            name="SemanticPromptInjectionDetector",
            category=DefenseCategory.CONTEXTUAL_AWARENESS,
            version="2026",
            description="Semantic prompt injection detection",
            covered_vectors={
                AttackVector.PROMPT_INJECTION,
                AttackVector.JAILBREAK,
            },
            confidence=0.75,
        ),
        DefenseInfo(
            name="ContextWindowProtector",
            category=DefenseCategory.ACCESS_CONTROL,
            version="2026",
            description="Context window boundary protection",
            covered_vectors={
                AttackVector.PROMPT_INJECTION,
                AttackVector.SYSTEM_PROMPT_LEAK,
                AttackVector.CONVERSATION_HIJACK,
            },
            confidence=0.77,
        ),
        DefenseInfo(
            name="MultimodalPromptInjectionDetector",
            category=DefenseCategory.ANOMALY_DETECTION,
            version="2026",
            description="Multimodal prompt injection detection",
            covered_vectors={
                AttackVector.MULTIMODAL_INJECTION,
                AttackVector.VLM_HIJACKING,
            },
            confidence=0.73,
        ),
        DefenseInfo(
            name="OutputSanitizer",
            category=DefenseCategory.OUTPUT_SANITIZATION,
            version="2026",
            description="Output sanitization and PII redaction",
            covered_vectors={
                AttackVector.OUTPUT_MANIPULATION,
                AttackVector.DATA_POISONING,
            },
            confidence=0.8,
        ),
        DefenseInfo(
            name="BehavioralBiometricsAnomalyDetector",
            category=DefenseCategory.BEHAVIORAL_ANALYSIS,
            version="2026",
            description="Behavioral biometrics anomaly detection",
            covered_vectors={
                AttackVector.MODEL_EXTRACTION,
                AttackVector.JAILBREAK,
            },
            confidence=0.65,
        ),
    ]

    for defense in core_defenses:
        analyzer.register_defense(defense)

    report = analyzer.generate_coverage_report()
    return analyzer, report


# Module metadata for backward compatibility and dimension tracking
MODULE_DIMENSION = "A - Feature Expansion"
MODULE_VERSION = "v33"
MODULE_STABILITY = "stable"
MODULE_IS_ADD_ONLY = True
MODULE_PRESERVES_BACKWARD_COMPATIBILITY = True


def verify_module() -> bool:
    """Self-verification function to ensure module loads correctly."""
    try:
        analyzer = create_coverage_analyzer()
        assert analyzer is not None
        assert len(analyzer.list_defenses()) == 0

        defense = DefenseInfo(
            name="TestDefense",
            category=DefenseCategory.INPUT_VALIDATION,
            version="test",
            description="Test defense",
            covered_vectors={AttackVector.PROMPT_INJECTION},
        )
        assert analyzer.register_defense(defense) is True
        assert len(analyzer.list_defenses()) == 1

        report = analyzer.generate_coverage_report()
        assert report.total_vectors_analyzed > 0
        assert report.registered_defenses == 1
        assert 0.0 <= report.overall_coverage_score <= 1.0

        summary = analyzer.get_coverage_summary()
        assert "overall_score" in summary
        assert "total_vectors" in summary

        return True
    except Exception:
        return False
