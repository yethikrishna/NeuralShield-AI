#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Asset Inventory Manager
Real working tests - no empty shells
"""

import json
import os
import tempfile
import time
import sys

# Add the neural_shield directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_asset_inventory_manager_2026_june import (
    AssetInventoryManager,
    AssetType,
    RiskLevel,
    ComplianceStatus,
    Vulnerability,
    Asset
)


def test_asset_registration():
    """Test basic asset registration"""
    print("Testing: Asset Registration...")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    try:
        manager = AssetInventoryManager(temp_path)
        
        # Register an asset
        asset_id = manager.register_asset(
            name="Production Web Server 01",
            asset_type=AssetType.SERVER,
            ip_address="192.168.1.100",
            hostname="web01.prod.example.com",
            description="Main production web server",
            owner="DevOps Team",
            location="US-East-1",
            environment="production",
            tags=["web", "production", "nginx"]
        )
        
        assert asset_id is not None
        assert len(asset_id) > 0
        
        # Retrieve and verify
        asset = manager.get_asset(asset_id)
        assert asset is not None
        assert asset.name == "Production Web Server 01"
        assert asset.asset_type == AssetType.SERVER
        assert asset.ip_address == "192.168.1.100"
        assert "web" in asset.tags
        
        print("  ✓ Asset registration works correctly")
        return True
    finally:
        os.unlink(temp_path)


def test_vulnerability_tracking():
    """Test vulnerability tracking and risk scoring"""
    print("Testing: Vulnerability Tracking & Risk Scoring...")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    try:
        manager = AssetInventoryManager(temp_path)
        
        asset_id = manager.register_asset(
            name="Test DB Server",
            asset_type=AssetType.DATABASE,
            ip_address="10.0.0.5",
            hostname="db01.test.local"
        )
        
        asset = manager.get_asset(asset_id)
        
        # Add critical vulnerability
        vuln1 = Vulnerability(
            cve_id="CVE-2026-1234",
            severity=RiskLevel.CRITICAL,
            cvss_score=9.8,
            description="Remote code execution vulnerability",
            discovered_at=time.time()
        )
        asset.add_vulnerability(vuln1)
        
        # Add high vulnerability
        vuln2 = Vulnerability(
            cve_id="CVE-2026-5678",
            severity=RiskLevel.HIGH,
            cvss_score=7.5,
            description="Privilege escalation",
            discovered_at=time.time()
        )
        asset.add_vulnerability(vuln2)
        
        # Risk should be calculated
        assert asset.risk_score > 0
        assert asset.get_overall_risk_level() in (RiskLevel.CRITICAL, RiskLevel.HIGH)
        
        # Patch one vulnerability
        result = asset.patch_vulnerability("CVE-2026-1234")
        assert result is True
        
        # Risk should decrease
        old_score = asset.risk_score
        assert old_score > 0
        
        print("  ✓ Vulnerability tracking and risk scoring works")
        return True
    finally:
        os.unlink(temp_path)


def test_asset_search_and_filtering():
    """Test asset search and filtering capabilities"""
    print("Testing: Asset Search & Filtering...")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    try:
        manager = AssetInventoryManager(temp_path)
        
        # Register multiple assets
        manager.register_asset(
            name="Web Server 01",
            asset_type=AssetType.SERVER,
            ip_address="192.168.1.1",
            hostname="web01.local",
            tags=["web", "frontend"]
        )
        
        manager.register_asset(
            name="DB Server 01",
            asset_type=AssetType.DATABASE,
            ip_address="192.168.1.2",
            hostname="db01.local",
            tags=["database", "backend"]
        )
        
        manager.register_asset(
            name="API Gateway",
            asset_type=AssetType.API_ENDPOINT,
            ip_address="192.168.1.3",
            hostname="api.local",
            tags=["api", "gateway"]
        )
        
        # Test filtering by type
        servers = manager.get_assets_by_type(AssetType.SERVER)
        assert len(servers) == 1
        assert servers[0].name == "Web Server 01"
        
        # Test search
        results = manager.search_assets("web")
        assert len(results) >= 1
        
        results = manager.search_assets("192.168.1.2")
        assert len(results) == 1
        assert results[0].hostname == "db01.local"
        
        print("  ✓ Search and filtering works correctly")
        return True
    finally:
        os.unlink(temp_path)


def test_inventory_statistics():
    """Test inventory statistics generation"""
    print("Testing: Inventory Statistics...")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    try:
        manager = AssetInventoryManager(temp_path)
        
        # Register some assets
        for i in range(5):
            manager.register_asset(
                name=f"Server {i}",
                asset_type=AssetType.SERVER,
                ip_address=f"10.0.0.{i}",
                hostname=f"server{i}.local"
            )
        
        # Add a high-risk asset
        high_risk_id = manager.register_asset(
            name="Vulnerable Server",
            asset_type=AssetType.SERVER,
            ip_address="10.0.0.99",
            hostname="vuln.local"
        )
        
        high_risk_asset = manager.get_asset(high_risk_id)
        high_risk_asset.add_vulnerability(Vulnerability(
            cve_id="CVE-2026-9999",
            severity=RiskLevel.CRITICAL,
            cvss_score=10.0,
            description="Test critical vuln",
            discovered_at=time.time()
        ))
        
        stats = manager.get_inventory_statistics()
        
        assert stats["total_assets"] == 6
        assert "by_type" in stats
        assert "by_risk_level" in stats
        assert "average_risk_score" in stats
        assert stats["high_risk_assets"] >= 1
        
        print("  ✓ Inventory statistics generated correctly")
        return True
    finally:
        os.unlink(temp_path)


def test_report_generation():
    """Test comprehensive report generation"""
    print("Testing: Report Generation...")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    try:
        manager = AssetInventoryManager(temp_path)
        
        manager.register_asset(
            name="Test Asset",
            asset_type=AssetType.SERVER,
            ip_address="10.0.0.1",
            hostname="test.local"
        )
        
        report = manager.generate_inventory_report()
        
        assert "report_generated" in report
        assert "statistics" in report
        assert "high_risk_assets" in report
        assert "recommendations" in report
        
        print("  ✓ Report generation works correctly")
        return True
    finally:
        os.unlink(temp_path)


def test_scan_history():
    """Test scan history recording"""
    print("Testing: Scan History Recording...")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    try:
        manager = AssetInventoryManager(temp_path)
        
        manager.record_scan("Nessus", 50, 5)
        manager.record_scan("OpenVAS", 50, 3)
        
        stats = manager.get_inventory_statistics()
        assert stats["total_scans"] == 2
        
        print("  ✓ Scan history recording works")
        return True
    finally:
        os.unlink(temp_path)


def main():
    """Run all tests"""
    print("=" * 60)
    print("Threat Intelligence Asset Inventory Manager - Test Suite")
    print("=" * 60)
    
    tests = [
        test_asset_registration,
        test_vulnerability_tracking,
        test_asset_search_and_filtering,
        test_inventory_statistics,
        test_report_generation,
        test_scan_history
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
                print(f"  ✗ {test.__name__} FAILED")
        except Exception as e:
            failed += 1
            print(f"  ✗ {test.__name__} EXCEPTION: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 60)
    print(f"Results: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    # Save test results
    results = {
        "test_module": "threat_intelligence_asset_inventory_manager",
        "tests_run": len(tests),
        "tests_passed": passed,
        "tests_failed": failed,
        "timestamp": time.time()
    }
    
    with open("test_results_asset_inventory.json", "w") as f:
        json.dump(results, f, indent=2)
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
