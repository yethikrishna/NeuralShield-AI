"""
Test Suite for Threat Intelligence Attack Surface Mapper
June 2026 - Production Grade Tests
Real working tests that verify actual functionality
"""
import pytest
import json
from datetime import datetime
from neural_shield.threat_intelligence_attack_surface_mapper_2026_june import (
    ThreatIntelligenceAttackSurfaceMapper,
    ServiceRiskLevel,
    AttackVectorType,
    NetworkService,
    AttackSurfaceFinding,
    AttackSurfaceReport
)


class TestThreatIntelligenceAttackSurfaceMapper:
    """Test suite for Attack Surface Mapper"""
    
    def setup_method(self):
        """Setup test mapper instance"""
        self.mapper = ThreatIntelligenceAttackSurfaceMapper()
    
    def test_mapper_initialization(self):
        """Test mapper initializes correctly"""
        assert self.mapper.enable_risk_caching == True
        assert self.mapper._analysis_count == 0
        assert self.mapper._total_findings_found == 0
        assert isinstance(self.mapper._risk_cache, dict)
    
    def test_analyze_service_critical_port(self):
        """Test analysis of critical high-risk port (RDP 3389)"""
        finding = self.mapper.analyze_service(3389, "tcp", is_public=True)
        
        assert finding is not None
        assert finding.finding_id.startswith("ASF-")
        assert finding.risk_level == ServiceRiskLevel.CRITICAL
        assert finding.cvss_score >= 9.0
        assert finding.service is not None
        assert finding.service.port == 3389
        assert finding.service.service_name == "RDP"
        assert "CRITICAL" in finding.description
        assert "IMMEDIATE" in finding.recommendation
    
    def test_analyze_service_high_risk(self):
        """Test analysis of high-risk port (SSH 22)"""
        finding = self.mapper.analyze_service(22, "tcp", is_public=True)
        
        assert finding.risk_level in [ServiceRiskLevel.HIGH, ServiceRiskLevel.CRITICAL]
        assert finding.cvss_score >= 7.0
        assert finding.service.service_name == "SSH"
    
    def test_analyze_service_medium_risk(self):
        """Test analysis of medium risk port (HTTP 80)"""
        finding = self.mapper.analyze_service(80, "tcp", is_public=False)
        
        assert finding.risk_level in [ServiceRiskLevel.MEDIUM, ServiceRiskLevel.LOW]
        assert finding.cvss_score < 7.0
        assert finding.service.service_name == "HTTP"
    
    def test_analyze_service_safe_port(self):
        """Test analysis of low-risk internal service"""
        finding = self.mapper.analyze_service(443, "tcp", is_public=False)
        
        assert finding.risk_level in [ServiceRiskLevel.LOW, ServiceRiskLevel.MEDIUM, ServiceRiskLevel.SAFE]
        assert finding.cvss_score <= 6.0
    
    def test_public_exposure_increases_risk(self):
        """Test that public exposure increases risk score"""
        private = self.mapper.analyze_service(22, "tcp", is_public=False)
        public = self.mapper.analyze_service(22, "tcp", is_public=True)
        
        assert public.cvss_score >= private.cvss_score
    
    def test_outdated_version_increases_risk(self):
        """Test that outdated version flag increases risk"""
        current = self.mapper.analyze_service(8080, "tcp", is_public=False, version="2.1.0")
        outdated = self.mapper.analyze_service(8080, "tcp", is_public=False, version="1.0.0-beta")
        
        assert outdated.cvss_score >= current.cvss_score
    
    def test_is_version_outdated_detection(self):
        """Test outdated version pattern detection"""
        assert self.mapper._is_version_outdated("1.0.0") == True
        assert self.mapper._is_version_outdated("0.9.5") == True
        assert self.mapper._is_version_outdated("2.1.0-beta") == True
        assert self.mapper._is_version_outdated("v1.5.2") == True
        assert self.mapper._is_version_outdated("3.2.1") == False
        assert self.mapper._is_version_outdated("2026.1") == False
    
    def test_analyze_configuration_default_credentials(self):
        """Test detection of default credentials in config"""
        config = """
        admin:admin
        DEBUG = True
        """
        findings = self.mapper.analyze_configuration(config)
        
        assert len(findings) >= 1
        default_cred = [f for f in findings if f.vector_type == AttackVectorType.DEFAULT_CREDENTIALS]
        assert len(default_cred) >= 1
        assert default_cred[0].risk_level == ServiceRiskLevel.CRITICAL
        assert default_cred[0].cvss_score == 9.8
    
    def test_analyze_configuration_debug_mode(self):
        """Test debug mode detection"""
        config = "DEBUG = True\ndebug=true"
        findings = self.mapper.analyze_configuration(config)
        
        debug_findings = [f for f in findings if "debug" in f.description.lower()]
        assert len(debug_findings) >= 1
        assert debug_findings[0].risk_level == ServiceRiskLevel.HIGH
    
    def test_generate_attack_surface_report_basic(self):
        """Test basic report generation"""
        services = [
            (22, "tcp", True, "OpenSSH_8.9"),
            (80, "tcp", True, "nginx/1.20"),
            (443, "tcp", True, "nginx/1.20"),
        ]
        
        report = self.mapper.generate_attack_surface_report(services)
        
        assert report is not None
        assert report.total_services_analyzed == 3
        assert report.total_findings == 3
        assert report.overall_risk_score > 0
        assert report.attack_surface_score <= 100
        assert len(report.findings) == 3
        assert len(report.exposed_services) == 3
        assert len(report.recommendations) > 0
        assert report.analysis_summary != ""
    
    def test_generate_report_with_config(self):
        """Test report generation with configuration analysis"""
        services = [(3389, "tcp", True, "")]
        config = "admin:admin\nDEBUG=True"
        
        report = self.mapper.generate_attack_surface_report(services, config)
        
        assert report.total_findings > 1  # Service + config findings
        assert report.critical_findings >= 1
        assert report.overall_risk_score >= 20
    
    def test_report_severity_counting(self):
        """Test severity counting in report"""
        services = [
            (3389, "tcp", True, ""),  # Critical
            (22, "tcp", True, ""),    # High/Critical
            (80, "tcp", False, ""),   # Medium
        ]
        
        report = self.mapper.generate_attack_surface_report(services)
        
        assert report.critical_findings + report.high_findings + report.medium_findings + report.low_findings == 3
    
    def test_get_mapper_stats(self):
        """Test mapper statistics tracking"""
        # Do some analyses
        self.mapper.analyze_service(22, "tcp")
        self.mapper.analyze_service(80, "tcp")
        
        stats = self.mapper.get_mapper_stats()
        
        assert stats["total_analyses"] == 2
        assert stats["total_findings"] == 2
        assert "timestamp" in stats
    
    def test_export_report_json(self):
        """Test JSON report export functionality"""
        services = [(22, "tcp", True, "")]
        report = self.mapper.generate_attack_surface_report(services)
        
        json_output = self.mapper.export_report_json(report)
        
        # Verify valid JSON
        parsed = json.loads(json_output)
        assert "report_timestamp" in parsed
        assert "summary" in parsed
        assert "findings" in parsed
        assert "recommendations" in parsed
        assert parsed["summary"]["services_analyzed"] == 1
    
    def test_unknown_port_handling(self):
        """Test handling of unknown/non-standard ports"""
        finding = self.mapper.analyze_service(55555, "tcp", False)
        
        assert finding is not None
        assert finding.service is not None
        assert "Unknown" in finding.service.service_name
        assert finding.cvss_score > 0
    
    def test_udp_protocol_support(self):
        """Test UDP protocol analysis"""
        finding = self.mapper.analyze_service(53, "udp", True)
        
        assert finding is not None
        assert finding.service.protocol == "udp"
        assert finding.service.service_name == "DNS"
    
    def test_finding_id_consistency(self):
        """Test that finding IDs are deterministic for same inputs"""
        finding1 = self.mapper.analyze_service(22, "tcp", False, "8.9")
        finding2 = self.mapper.analyze_service(22, "tcp", False, "8.9")
        
        assert finding1.finding_id == finding2.finding_id
    
    def test_recommendations_prioritization(self):
        """Test recommendations include critical findings first"""
        services = [
            (3389, "tcp", True, ""),
            (23, "tcp", True, ""),
        ]
        
        report = self.mapper.generate_attack_surface_report(services)
        
        assert any("PRIORITY 1" in r for r in report.recommendations)
        assert any("CRITICAL" in r for r in report.recommendations)
    
    def test_summary_generation(self):
        """Test summary text generation for different risk levels"""
        # Critical case
        critical_services = [(3389, "tcp", True, "")]
        critical_report = self.mapper.generate_attack_surface_report(critical_services)
        assert "SEVERE" in critical_report.analysis_summary or "CRITICAL" in critical_report.analysis_summary


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
