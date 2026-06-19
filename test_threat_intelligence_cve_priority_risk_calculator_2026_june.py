"""
Test Suite for NeuralShield-AI CVE Priority Risk Calculator
June 2026 - Production Grade Tests

This test suite validates the CVE Priority Risk Calculator module
with comprehensive unit tests, integration tests, and edge cases.
"""
import json
import os
import tempfile
import pytest
from datetime import datetime

from neural_shield.threat_intelligence_cve_priority_risk_calculator_2026_june import (
    CVEPriorityRiskCalculator,
    CVSSVector,
    AttackVector,
    AttackComplexity,
    PrivilegesRequired,
    UserInteraction,
    Scope,
    ConfidentialityImpact,
    IntegrityImpact,
    AvailabilityImpact,
    ExploitCodeMaturity,
    RemediationLevel,
    ReportConfidence,
    PriorityLevel,
    BusinessCriticality,
)


class TestCVSSVector:
    """Test CVSS vector parsing and serialization"""
    
    def test_vector_creation_default(self):
        """Test default CVSS vector creation"""
        vector = CVSSVector()
        assert vector.av == AttackVector.NETWORK
        assert vector.ac == AttackComplexity.LOW
        assert vector.pr == PrivilegesRequired.NONE
        assert vector.ui == UserInteraction.NONE
        assert vector.s == Scope.UNCHANGED
        assert vector.c == ConfidentialityImpact.NONE
        assert vector.i == IntegrityImpact.NONE
        assert vector.a == AvailabilityImpact.NONE
    
    def test_vector_to_string(self):
        """Test vector to string conversion"""
        vector = CVSSVector()
        vec_str = vector.to_vector_string()
        assert "CVSS:3.1" in vec_str
        assert "AV:N" in vec_str
        assert "AC:L" in vec_str
        assert "PR:N" in vec_str
        assert "UI:N" in vec_str
        assert "S:U" in vec_str
    
    def test_vector_from_string(self):
        """Test parsing CVSS vector string"""
        vec_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        vector = CVSSVector.from_vector_string(vec_str)
        assert vector.av == AttackVector.NETWORK
        assert vector.ac == AttackComplexity.LOW
        assert vector.pr == PrivilegesRequired.NONE
        assert vector.ui == UserInteraction.NONE
        assert vector.s == Scope.UNCHANGED
        assert vector.c == ConfidentialityImpact.HIGH
        assert vector.i == IntegrityImpact.HIGH
        assert vector.a == AvailabilityImpact.HIGH
    
    def test_vector_roundtrip(self):
        """Test vector string roundtrip"""
        original = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        vector = CVSSVector.from_vector_string(original)
        result = vector.to_vector_string()
        assert result == original


class TestCVSSScoring:
    """Test CVSS v3.1 scoring calculations"""
    
    def setup_method(self):
        self.calculator = CVEPriorityRiskCalculator()
    
    def test_critical_rce_score(self):
        """Test critical RCE vulnerability scoring"""
        # Log4j style: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
        vector = CVSSVector(
            av=AttackVector.NETWORK,
            ac=AttackComplexity.LOW,
            pr=PrivilegesRequired.NONE,
            ui=UserInteraction.NONE,
            s=Scope.CHANGED,
            c=ConfidentialityImpact.HIGH,
            i=IntegrityImpact.HIGH,
            a=AvailabilityImpact.HIGH
        )
        scores = self.calculator.calculate_cvss_scores(vector)
        assert scores.base_score >= 9.0
        assert scores.severity == PriorityLevel.CRITICAL
        assert scores.exploitability_score > 0
        assert scores.impact_score > 0
    
    def test_high_severity_score(self):
        """Test high severity vulnerability scoring"""
        vector = CVSSVector(
            av=AttackVector.NETWORK,
            ac=AttackComplexity.LOW,
            pr=PrivilegesRequired.LOW,
            ui=UserInteraction.NONE,
            s=Scope.UNCHANGED,
            c=ConfidentialityImpact.HIGH,
            i=IntegrityImpact.HIGH,
            a=AvailabilityImpact.HIGH
        )
        scores = self.calculator.calculate_cvss_scores(vector)
        assert 7.0 <= scores.base_score < 10.0
        assert scores.severity in [PriorityLevel.HIGH, PriorityLevel.CRITICAL]
    
    def test_medium_severity_score(self):
        """Test medium severity vulnerability scoring"""
        vector = CVSSVector(
            av=AttackVector.NETWORK,
            ac=AttackComplexity.LOW,
            pr=PrivilegesRequired.NONE,
            ui=UserInteraction.NONE,
            s=Scope.UNCHANGED,
            c=ConfidentialityImpact.LOW,
            i=IntegrityImpact.LOW,
            a=AvailabilityImpact.LOW
        )
        scores = self.calculator.calculate_cvss_scores(vector)
        assert 4.0 <= scores.base_score < 7.0
        assert scores.severity == PriorityLevel.MEDIUM
    
    def test_low_severity_score(self):
        """Test low severity vulnerability scoring"""
        vector = CVSSVector(
            av=AttackVector.LOCAL,
            ac=AttackComplexity.HIGH,
            pr=PrivilegesRequired.HIGH,
            ui=UserInteraction.REQUIRED,
            s=Scope.UNCHANGED,
            c=ConfidentialityImpact.LOW,
            i=IntegrityImpact.LOW,
            a=AvailabilityImpact.LOW
        )
        scores = self.calculator.calculate_cvss_scores(vector)
        assert scores.base_score < 4.0 or scores.severity == PriorityLevel.LOW
    
    def test_zero_impact_score(self):
        """Test vulnerability with no impact"""
        vector = CVSSVector(
            c=ConfidentialityImpact.NONE,
            i=IntegrityImpact.NONE,
            a=AvailabilityImpact.NONE
        )
        scores = self.calculator.calculate_cvss_scores(vector)
        assert scores.base_score == 0.0
        assert scores.severity == PriorityLevel.INFORMATIONAL
    
    def test_temporal_score_reduction(self):
        """Test temporal score reduces base score"""
        vector_base = CVSSVector(
            av=AttackVector.NETWORK,
            ac=AttackComplexity.LOW,
            pr=PrivilegesRequired.NONE,
            ui=UserInteraction.NONE,
            s=Scope.UNCHANGED,
            c=ConfidentialityImpact.HIGH,
            i=IntegrityImpact.HIGH,
            a=AvailabilityImpact.HIGH
        )
        scores_base = self.calculator.calculate_cvss_scores(vector_base)
        
        # With official fix available
        vector_fixed = CVSSVector(
            av=AttackVector.NETWORK,
            ac=AttackComplexity.LOW,
            pr=PrivilegesRequired.NONE,
            ui=UserInteraction.NONE,
            s=Scope.UNCHANGED,
            c=ConfidentialityImpact.HIGH,
            i=IntegrityImpact.HIGH,
            a=AvailabilityImpact.HIGH,
            rl=RemediationLevel.OFFICIAL_FIX
        )
        scores_fixed = self.calculator.calculate_cvss_scores(vector_fixed)
        
        assert scores_fixed.temporal_score <= scores_base.base_score


class TestExploitabilityPrediction:
    """Test exploitability likelihood prediction"""
    
    def setup_method(self):
        self.calculator = CVEPriorityRiskCalculator()
    
    def test_network_exploit_higher_likelihood(self):
        """Test network vectors have higher exploit likelihood"""
        vector_network = CVSSVector(
            av=AttackVector.NETWORK,
            c=ConfidentialityImpact.HIGH,
            i=IntegrityImpact.HIGH,
            a=AvailabilityImpact.HIGH
        )
        vector_local = CVSSVector(
            av=AttackVector.LOCAL,
            c=ConfidentialityImpact.HIGH,
            i=IntegrityImpact.HIGH,
            a=AvailabilityImpact.HIGH
        )
        
        scores = self.calculator.calculate_cvss_scores(vector_network)
        likelihood_network = self.calculator.predict_exploitability_likelihood(
            scores, vector_network
        )
        
        scores_local = self.calculator.calculate_cvss_scores(vector_local)
        likelihood_local = self.calculator.predict_exploitability_likelihood(
            scores_local, vector_local
        )
        
        assert likelihood_network > likelihood_local
    
    def test_low_complexity_higher_likelihood(self):
        """Test low complexity increases exploit likelihood"""
        vector_low = CVSSVector(
            ac=AttackComplexity.LOW,
            c=ConfidentialityImpact.HIGH,
            i=IntegrityImpact.HIGH,
            a=AvailabilityImpact.HIGH
        )
        vector_high = CVSSVector(
            ac=AttackComplexity.HIGH,
            c=ConfidentialityImpact.HIGH,
            i=IntegrityImpact.HIGH,
            a=AvailabilityImpact.HIGH
        )
        
        scores = self.calculator.calculate_cvss_scores(vector_low)
        likelihood_low = self.calculator.predict_exploitability_likelihood(
            scores, vector_low
        )
        
        scores_high = self.calculator.calculate_cvss_scores(vector_high)
        likelihood_high = self.calculator.predict_exploitability_likelihood(
            scores_high, vector_high
        )
        
        assert likelihood_low > likelihood_high
    
    def test_exploit_code_maturity_impact(self):
        """Test exploit code maturity impacts likelihood"""
        vector_high = CVSSVector(
            e=ExploitCodeMaturity.HIGH,
            c=ConfidentialityImpact.HIGH,
            i=IntegrityImpact.HIGH,
            a=AvailabilityImpact.HIGH
        )
        vector_none = CVSSVector(
            e=ExploitCodeMaturity.NOT_DEFINED,
            c=ConfidentialityImpact.HIGH,
            i=IntegrityImpact.HIGH,
            a=AvailabilityImpact.HIGH
        )
        
        scores = self.calculator.calculate_cvss_scores(vector_high)
        likelihood_high = self.calculator.predict_exploitability_likelihood(
            scores, vector_high
        )
        
        scores_none = self.calculator.calculate_cvss_scores(vector_none)
        likelihood_none = self.calculator.predict_exploitability_likelihood(
            scores_none, vector_none
        )
        
        assert likelihood_high > likelihood_none
    
    def test_likelihood_bounds(self):
        """Test likelihood stays within 0-100 range"""
        vector = CVSSVector(
            c=ConfidentialityImpact.HIGH,
            i=IntegrityImpact.HIGH,
            a=AvailabilityImpact.HIGH
        )
        scores = self.calculator.calculate_cvss_scores(vector)
        likelihood = self.calculator.predict_exploitability_likelihood(
            scores, vector, days_since_published=1000
        )
        assert 0 <= likelihood <= 100


class TestBusinessImpact:
    """Test business impact calculation"""
    
    def setup_method(self):
        self.calculator = CVEPriorityRiskCalculator()
    
    def test_mission_critical_higher_impact(self):
        """Test mission critical assets have higher impact"""
        vector = CVSSVector(
            c=ConfidentialityImpact.HIGH,
            i=IntegrityImpact.HIGH,
            a=AvailabilityImpact.HIGH
        )
        scores = self.calculator.calculate_cvss_scores(vector)
        
        impact_mission = self.calculator.calculate_business_impact(
            scores, BusinessCriticality.MISSION_CRITICAL
        )
        impact_standard = self.calculator.calculate_business_impact(
            scores, BusinessCriticality.STANDARD
        )
        
        assert impact_mission > impact_standard
    
    def test_high_sensitivity_higher_impact(self):
        """Test high data sensitivity increases impact"""
        vector = CVSSVector(
            c=ConfidentialityImpact.HIGH,
            i=IntegrityImpact.HIGH,
            a=AvailabilityImpact.HIGH
        )
        scores = self.calculator.calculate_cvss_scores(vector)
        
        impact_high = self.calculator.calculate_business_impact(
            scores, BusinessCriticality.STANDARD, data_sensitivity=1.0
        )
        impact_low = self.calculator.calculate_business_impact(
            scores, BusinessCriticality.STANDARD, data_sensitivity=0.2
        )
        
        assert impact_high > impact_low
    
    def test_many_users_higher_impact(self):
        """Test more users affected increases impact"""
        vector = CVSSVector(
            c=ConfidentialityImpact.HIGH,
            i=IntegrityImpact.HIGH,
            a=AvailabilityImpact.HIGH
        )
        scores = self.calculator.calculate_cvss_scores(vector)
        
        impact_many = self.calculator.calculate_business_impact(
            scores, BusinessCriticality.STANDARD, user_count=10000
        )
        impact_few = self.calculator.calculate_business_impact(
            scores, BusinessCriticality.STANDARD, user_count=1
        )
        
        assert impact_many >= impact_few
    
    def test_impact_bounds(self):
        """Test impact score stays within 0-100 range"""
        vector = CVSSVector(
            c=ConfidentialityImpact.HIGH,
            i=IntegrityImpact.HIGH,
            a=AvailabilityImpact.HIGH
        )
        scores = self.calculator.calculate_cvss_scores(vector)
        impact = self.calculator.calculate_business_impact(
            scores, BusinessCriticality.MISSION_CRITICAL, 
            data_sensitivity=1.0, user_count=1000000
        )
        assert 0 <= impact <= 100


class TestPriorityScoring:
    """Test final priority scoring"""
    
    def setup_method(self):
        self.calculator = CVEPriorityRiskCalculator()
    
    def test_priority_level_mapping(self):
        """Test priority score to level mapping"""
        # Critical
        assert self.calculator.determine_priority_level(90) == PriorityLevel.CRITICAL
        assert self.calculator.determine_priority_level(80) == PriorityLevel.CRITICAL
        
        # High
        assert self.calculator.determine_priority_level(70) == PriorityLevel.HIGH
        assert self.calculator.determine_priority_level(60) == PriorityLevel.HIGH
        
        # Medium
        assert self.calculator.determine_priority_level(50) == PriorityLevel.MEDIUM
        assert self.calculator.determine_priority_level(35) == PriorityLevel.MEDIUM
        
        # Low
        assert self.calculator.determine_priority_level(20) == PriorityLevel.LOW
        assert self.calculator.determine_priority_level(1) == PriorityLevel.LOW
        
        # Informational
        assert self.calculator.determine_priority_level(0) == PriorityLevel.INFORMATIONAL
    
    def test_priority_score_components(self):
        """Test priority score combines all components"""
        vector = CVSSVector(
            c=ConfidentialityImpact.HIGH,
            i=IntegrityImpact.HIGH,
            a=AvailabilityImpact.HIGH
        )
        scores = self.calculator.calculate_cvss_scores(vector)
        exploit = 80.0
        impact = 70.0
        
        priority = self.calculator.calculate_priority_score(scores, exploit, impact)
        
        # Should be weighted: 40% CVSS + 30% exploit + 30% impact
        expected = (scores.overall_score * 10 * 0.4) + (exploit * 0.3) + (impact * 0.3)
        assert abs(priority - expected) < 0.1


class TestVulnerabilityAssessment:
    """Test complete vulnerability assessment"""
    
    def setup_method(self):
        self.calculator = CVEPriorityRiskCalculator()
    
    def test_single_assessment(self):
        """Test single vulnerability assessment"""
        assessment = self.calculator.assess_vulnerability(
            cve_id="CVE-2026-1234",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            asset_criticality=BusinessCriticality.MISSION_CRITICAL,
            affected_asset="prod-db-server-01",
            vendor="Example Corp",
            product="Database Server",
            description="Critical remote code execution vulnerability"
        )
        
        assert assessment.cve_id == "CVE-2026-1234"
        assert assessment.affected_asset == "prod-db-server-01"
        assert assessment.priority_score > 0
        assert assessment.priority_level in [PriorityLevel.HIGH, PriorityLevel.CRITICAL]
        assert assessment.remediation_timeline
        assert len(assessment.remediation_steps) > 0
        assert assessment.assessment_timestamp
    
    def test_assessment_caching(self):
        """Test assessments are cached"""
        cve_id = "CVE-2026-9999"
        self.calculator.assess_vulnerability(
            cve_id=cve_id,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            asset_criticality=BusinessCriticality.STANDARD
        )
        
        assert cve_id in self.calculator.cve_cache
    
    def test_remediation_steps_generated(self):
        """Test remediation steps are generated based on vulnerability type"""
        # Network vulnerability
        assessment = self.calculator.assess_vulnerability(
            cve_id="CVE-2026-TEST",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            asset_criticality=BusinessCriticality.STANDARD
        )
        
        steps = assessment.remediation_steps
        assert any("network" in step.lower() or "firewall" in step.lower() for step in steps)


class TestBatchProcessing:
    """Test batch vulnerability processing"""
    
    def setup_method(self):
        self.calculator = CVEPriorityRiskCalculator()
    
    def test_batch_assessment(self):
        """Test batch vulnerability assessment"""
        vulns = [
            {
                "cve_id": "CVE-2026-0001",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "asset_criticality": "mission_critical",
                "affected_asset": "server-01"
            },
            {
                "cve_id": "CVE-2026-0002",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
                "asset_criticality": "standard",
                "affected_asset": "server-02"
            }
        ]
        
        result = self.calculator.batch_assess_vulnerabilities(vulns)
        
        assert result.total_vulnerabilities == 2
        assert len(result.assessments) == 2
        assert result.scan_id
        assert result.generated_at
        assert "CRITICAL" in result.by_priority or "HIGH" in result.by_priority
        assert result.risk_summary
        assert result.average_priority_score > 0
    
    def test_sample_data_generation(self):
        """Test sample vulnerability data generation"""
        samples = self.calculator.generate_sample_vulnerabilities(10)
        assert len(samples) == 10
        assert all("cve_id" in s for s in samples)
        assert all("cvss_vector" in s for s in samples)
    
    def test_large_batch_processing(self):
        """Test processing large batch of vulnerabilities"""
        vulns = self.calculator.generate_sample_vulnerabilities(50)
        result = self.calculator.batch_assess_vulnerabilities(vulns)
        
        assert result.total_vulnerabilities == 50
        assert len(result.assessments) == 50
        assert len(result.scan_history) == 1


class TestExportFunctions:
    """Test JSON and CSV export functionality"""
    
    def setup_method(self):
        self.calculator = CVEPriorityRiskCalculator()
        vulns = self.calculator.generate_sample_vulnerabilities(10)
        self.result = self.calculator.batch_assess_vulnerabilities(vulns)
    
    def test_json_export(self):
        """Test JSON export"""
        json_output = self.calculator.export_to_json(self.result)
        data = json.loads(json_output)
        
        assert "scan_metadata" in data
        assert "top_critical_vulnerabilities" in data
        assert "all_assessments" in data
        assert len(data["all_assessments"]) == 10
        assert data["scan_metadata"]["total_vulnerabilities"] == 10
    
    def test_json_export_to_file(self):
        """Test JSON export to file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            filepath = f.name
        
        try:
            self.calculator.export_to_json(self.result, filepath)
            assert os.path.exists(filepath)
            
            with open(filepath, 'r') as f:
                data = json.load(f)
            assert "scan_metadata" in data
        finally:
            os.unlink(filepath)
    
    def test_csv_export(self):
        """Test CSV export"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            filepath = f.name
        
        try:
            self.calculator.export_to_csv(self.result, filepath)
            assert os.path.exists(filepath)
            
            with open(filepath, 'r') as f:
                lines = f.readlines()
            # Header + 10 data rows
            assert len(lines) == 11
        finally:
            os.unlink(filepath)


class TestIntegration:
    """Integration tests for complete workflow"""
    
    def test_complete_workflow(self):
        """Test complete CVE priority scanning workflow"""
        calculator = CVEPriorityRiskCalculator()
        
        # 1. Generate sample vulnerability data
        vulns = calculator.generate_sample_vulnerabilities(20)
        assert len(vulns) == 20
        
        # 2. Batch process all vulnerabilities
        result = calculator.batch_assess_vulnerabilities(vulns)
        assert result.total_vulnerabilities == 20
        
        # 3. Verify top critical vulnerabilities identified
        assert isinstance(result.top_critical, list)
        
        # 4. Export results
        json_output = calculator.export_to_json(result)
        assert len(json_output) > 0
        
        # 5. Verify scan history maintained
        assert len(calculator.scan_history) == 1


def run_tests():
    """Run all tests and return results"""
    import pytest
    import sys
    
    # Run pytest on this file
    result = pytest.main([__file__, "-v", "--tb=short"])
    return result


if __name__ == "__main__":
    print("Running CVE Priority Risk Calculator Tests...")
    exit_code = run_tests()
    print(f"\nTest exit code: {exit_code}")
    
    # Also run a quick demo
    print("\n" + "="*60)
    print("DEMO: CVE Priority Risk Calculator")
    print("="*60)
    
    calculator = CVEPriorityRiskCalculator()
    
    # Generate and process sample data
    vulns = calculator.generate_sample_vulnerabilities(15)
    result = calculator.batch_assess_vulnerabilities(vulns)
    
    print(f"\nScan ID: {result.scan_id}")
    print(f"Generated: {result.generated_at}")
    print(f"Total Vulnerabilities: {result.total_vulnerabilities}")
    print(f"Average Priority Score: {result.average_priority_score}")
    print(f"\nBy Priority:")
    for level, count in result.by_priority.items():
        print(f"  {level}: {count}")
    
    print(f"\nRisk Summary: {result.risk_summary}")
    
    if result.top_critical:
        print(f"\nTop Critical Vulnerabilities ({len(result.top_critical)}):")
        for vuln in result.top_critical[:3]:
            print(f"  - {vuln.cve_id}: Score={vuln.priority_score}, "
                  f"Asset={vuln.affected_asset}")
    
    # Save results
    calculator.export_to_json(result, "test_results_cve_priority_calculator.json")
    print("\nResults saved to test_results_cve_priority_calculator.json")
