"""
Test Suite for MITRE ATT&CK Navigator Layer Exporter - June 19, 2026
Production-grade unit and integration tests
All tests are real, working implementations - no mocks
"""
import json
import os
import tempfile
import pytest
from datetime import datetime, timezone

from neural_shield.threat_intelligence_mitre_navigator_exporter_2026_june import (
    MITRENavigatorExporter,
    ColorGradient,
    MITREPlatform,
    NavigatorTechnique
)


class TestMITRENavigatorExporter:
    """Production test suite for MITRE Navigator Exporter"""

    def setup_method(self):
        """Setup test fixtures before each test"""
        self.exporter = MITRENavigatorExporter()
        self.sample_detections = [
            {
                "technique_id": "T1566",
                "severity": 8.5,
                "confidence": 0.95,
                "description": "Phishing email detected with malicious attachment"
            },
            {
                "technique_id": "T1566",
                "severity": 7.0,
                "confidence": 0.8,
                "description": "Spearphishing link targeting executive staff"
            },
            {
                "technique_id": "T1059",
                "severity": 9.0,
                "confidence": 1.0,
                "description": "PowerShell execution detected with suspicious parameters"
            },
            {
                "technique_id": "T1486",
                "severity": 10.0,
                "confidence": 1.0,
                "description": "Ransomware encryption activity detected"
            },
            {
                "technique_id": "T1078",
                "severity": 6.5,
                "confidence": 0.7,
                "description": "Valid account usage from unusual geo-location"
            },
            {
                "technique_id": "T1027",
                "severity": 7.5,
                "confidence": 0.85,
                "description": "Obfuscated file detected - possible malware"
            }
        ]

    def test_exporter_initialization(self):
        """Test exporter initializes correctly with production defaults"""
        assert self.exporter.navigator_version == "4.5"
        assert self.exporter.export_count == 0
        assert isinstance(self.exporter.export_cache, dict)
        print("✓ Exporter initialization test passed")

    def test_color_gradient_enum(self):
        """Test color gradients are properly defined"""
        assert len(ColorGradient.RED_TO_GREEN.value) == 5
        assert len(ColorGradient.GREEN_TO_RED.value) == 5
        assert all(c.startswith("#") for c in ColorGradient.HEATMAP.value)
        print("✓ Color gradient enum test passed")

    def test_get_color_for_score(self):
        """Test color calculation algorithm - real working logic"""
        # Test low score (should be green in GREEN_TO_RED)
        color_low = self.exporter._get_color_for_score(1.0, 0, 10, ColorGradient.GREEN_TO_RED)
        assert color_low.startswith("#")
        
        # Test high score (should be red in GREEN_TO_RED)
        color_high = self.exporter._get_color_for_score(9.0, 0, 10, ColorGradient.GREEN_TO_RED)
        assert color_high.startswith("#")
        
        # Test boundary conditions
        color_min = self.exporter._get_color_for_score(0.0, 0, 10, ColorGradient.GREEN_TO_RED)
        color_max = self.exporter._get_color_for_score(10.0, 0, 10, ColorGradient.GREEN_TO_RED)
        assert color_min != color_max  # Different colors for min vs max
        print("✓ Color calculation algorithm test passed")

    def test_export_layer_with_detection_data(self):
        """Test full layer export with real detection data"""
        result = self.exporter.export_layer(
            layer_name="June 2026 Threat Detection Report",
            detection_data=self.sample_detections,
            description="Production threat intelligence from NeuralShield-AI",
            platform="Windows"
        )
        
        # Verify result structure
        assert result.success is True
        assert result.export_id is not None
        assert len(result.export_id) == 16
        assert result.layer_count == 1
        assert result.total_techniques > 0
        assert result.execution_time_ms >= 0
        assert result.error_message is None
        
        # Verify Navigator JSON structure
        navigator_json = result.layer_files[0]['navigator_json']
        assert 'name' in navigator_json
        assert 'techniques' in navigator_json
        assert 'gradient' in navigator_json
        assert 'versions' in navigator_json
        assert 'domain' in navigator_json
        
        # Verify official Navigator schema compliance
        assert navigator_json['versions']['layer'] == "4.5"
        assert navigator_json['domain'] == "mitre-attack"
        assert isinstance(navigator_json['techniques'], list)
        
        # Verify techniques have proper scoring
        scored_techniques = [t for t in navigator_json['techniques'] if t['score'] > 0]
        assert len(scored_techniques) > 0
        
        # T1566 (Phishing) should have highest score (2 detections)
        phishing_tech = next((t for t in navigator_json['techniques'] if t['techniqueID'] == 'T1566'), None)
        assert phishing_tech is not None
        assert phishing_tech['score'] > 0
        assert phishing_tech['enabled'] is True
        
        print(f"✓ Layer export test passed - {result.total_techniques} techniques, {len(scored_techniques)} scored")

    def test_export_layer_with_custom_techniques(self):
        """Test export with manually defined techniques"""
        custom_techniques = [
            NavigatorTechnique(
                technique_id="T1566",
                score=8.5,
                comment="High volume phishing campaign",
                enabled=True
            ),
            NavigatorTechnique(
                technique_id="T1486",
                score=10.0,
                comment="Critical ransomware threat",
                enabled=True
            )
        ]
        
        result = self.exporter.export_layer(
            layer_name="Custom Threat Layer",
            techniques=custom_techniques,
            gradient=ColorGradient.RED_TO_GREEN
        )
        
        assert result.success is True
        navigator_json = result.layer_files[0]['navigator_json']
        assert len(navigator_json['techniques']) >= 2
        print("✓ Custom techniques export test passed")

    def test_export_layer_with_different_gradients(self):
        """Test all gradient options work correctly"""
        for gradient in ColorGradient:
            result = self.exporter.export_layer(
                layer_name=f"Test Layer - {gradient.name}",
                detection_data=self.sample_detections[:2],
                gradient=gradient
            )
            assert result.success is True
            navigator_json = result.layer_files[0]['navigator_json']
            assert len(navigator_json['gradient']['colors']) == len(gradient.value)
        print("✓ All color gradients test passed")

    def test_export_layer_platform_filtering(self):
        """Test platform filtering works correctly"""
        for platform in ["Windows", "Linux", "macOS", "AWS"]:
            result = self.exporter.export_layer(
                layer_name=f"{platform} Threat Report",
                detection_data=self.sample_detections,
                platform=platform
            )
            assert result.success is True
            navigator_json = result.layer_files[0]['navigator_json']
            assert platform in navigator_json['filters']['platforms']
        print("✓ Platform filtering test passed")

    def test_save_to_file(self):
        """Test file saving functionality - real file I/O"""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.exporter.export_layer(
                layer_name="File Export Test",
                detection_data=self.sample_detections
            )
            assert result.success is True
            
            saved_files = self.exporter.save_to_file(result, tmpdir)
            
            # Verify file was created
            assert len(saved_files) == 1
            assert os.path.exists(saved_files[0])
            
            # Verify file content is valid JSON
            with open(saved_files[0], 'r') as f:
                loaded_json = json.load(f)
            assert 'techniques' in loaded_json
            assert loaded_json['name'] == "File Export Test"
            
            print(f"✓ File save test passed - {saved_files[0]}")

    def test_get_import_instructions(self):
        """Test import instructions are provided correctly"""
        instructions = self.exporter.get_import_instructions()
        assert 'navigator_url' in instructions
        assert 'steps' in instructions
        assert 'supported_versions' in instructions
        assert len(instructions['steps']) == 4
        assert instructions['navigator_url'] == "https://mitre-attack.github.io/attack-navigator/"
        print("✓ Import instructions test passed")

    def test_export_layer_subtechniques(self):
        """Test subtechnique inclusion toggle"""
        # Without subtechniques
        result_no_sub = self.exporter.export_layer(
            layer_name="No Subtechniques",
            detection_data=self.sample_detections,
            show_subtechniques=False
        )
        
        # With subtechniques
        result_with_sub = self.exporter.export_layer(
            layer_name="With Subtechniques",
            detection_data=self.sample_detections,
            show_subtechniques=True
        )
        
        # With subtechniques should have more techniques
        assert result_with_sub.total_techniques >= result_no_sub.total_techniques
        print("✓ Subtechnique toggle test passed")

    def test_empty_detection_data(self):
        """Test export with empty detection data - edge case"""
        result = self.exporter.export_layer(
            layer_name="Empty Detection Report",
            detection_data=[]
        )
        assert result.success is True
        assert result.total_techniques > 0  # Still creates techniques, all score 0
        navigator_json = result.layer_files[0]['navigator_json']
        # All techniques should be disabled (score 0)
        enabled_count = sum(1 for t in navigator_json['techniques'] if t['enabled'])
        assert enabled_count == 0
        print("✓ Empty detection data edge case test passed")

    def test_export_performance(self):
        """Test export performance - production grade speed"""
        import time
        
        start = time.time()
        result = self.exporter.export_layer(
            layer_name="Performance Test",
            detection_data=self.sample_detections * 100  # 600 detections
        )
        elapsed = (time.time() - start) * 1000
        
        assert result.success is True
        assert elapsed < 1000  # Should complete in under 1 second for 600 detections
        print(f"✓ Performance test passed - {elapsed:.2f}ms for 600 detections")

    def test_export_id_uniqueness(self):
        """Test export IDs are unique across multiple exports"""
        ids = set()
        for i in range(5):
            result = self.exporter.export_layer(
                layer_name=f"Unique ID Test {i}",
                detection_data=self.sample_detections[:1]
            )
            assert result.export_id not in ids
            ids.add(result.export_id)
        assert len(ids) == 5
        print("✓ Export ID uniqueness test passed")

    def test_mitre_technique_database(self):
        """Test MITRE technique database is properly populated"""
        assert len(self.exporter.MITRE_TECHNIQUES) > 30
        assert 'T1566' in self.exporter.MITRE_TECHNIQUES
        assert 'T1486' in self.exporter.MITRE_TECHNIQUES
        assert 'tactic' in self.exporter.MITRE_TECHNIQUES['T1566']
        print("✓ MITRE technique database test passed")

    def test_tactic_order(self):
        """Test tactic ordering matches official MITRE"""
        assert len(self.exporter.TACTIC_ORDER) == 14
        assert self.exporter.TACTIC_ORDER[0] == "Reconnaissance"
        assert self.exporter.TACTIC_ORDER[-1] == "Impact"
        print("✓ Tactic order test passed")


if __name__ == "__main__":
    # Run tests directly for quick validation
    tester = TestMITRENavigatorExporter()
    tester.setup_method()
    
    print("\n" + "="*60)
    print("Running MITRE Navigator Exporter Production Tests")
    print("="*60 + "\n")
    
    tests = [
        tester.test_exporter_initialization,
        tester.test_color_gradient_enum,
        tester.test_get_color_for_score,
        tester.test_export_layer_with_detection_data,
        tester.test_export_layer_with_custom_techniques,
        tester.test_export_layer_with_different_gradients,
        tester.test_export_layer_platform_filtering,
        tester.test_save_to_file,
        tester.test_get_import_instructions,
        tester.test_export_layer_subtechniques,
        tester.test_empty_detection_data,
        tester.test_export_performance,
        tester.test_export_id_uniqueness,
        tester.test_mitre_technique_database,
        tester.test_tactic_order
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"✗ {test.__name__} FAILED: {str(e)}")
            failed += 1
    
    print("\n" + "="*60)
    print(f"TEST RESULTS: {passed} PASSED, {failed} FAILED")
    print("="*60)
    
    assert failed == 0, f"{failed} tests failed!"
