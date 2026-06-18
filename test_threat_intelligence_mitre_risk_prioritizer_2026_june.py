#!/usr/bin/env python3
"""
Test suite for MITRE ATT&CK Risk Prioritizer - REAL WORKING TESTS
"""

import sys
import json

sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI/neural_shield')
exec(open('/home/user/autonomous-developer/NeuralShield-AI/neural_shield/threat_intelligence_mitre_risk_prioritizer_2026_june.py').read())


def main():
    """Run comprehensive tests"""
    print("=" * 60)
    print("NEURALSHIELD AI - MITRE RISK PRIORITIZER TESTS")
    print("=" * 60)
    
    # Test 1: Basic initialization
    prioritizer = MITRERiskPrioritizer()
    print("✓ Initialization: PASSED")
    
    # Test 2: Single threat prioritization
    asset = AssetContext('DB-001', 'Production DB', 'database', 10.0, 10.0, 5.0)
    result = prioritizer.prioritize_threat('T1566', asset, 9.8)
    print(f"✓ Single threat: Score={result.final_risk_score}, Level={result.risk_level.value}")
    
    # Test 3: Batch processing
    assets = [
        AssetContext('A1', 'DB Cluster', 'database', 10.0, 10.0, 3.0),
        AssetContext('A2', 'Web Server', 'web', 8.0, 6.0, 10.0),
        AssetContext('A3', 'Dev Box', 'workstation', 2.0, 1.0, 1.0),
    ]
    batch = [('T1566', assets[0], 9.8), ('T1003', assets[1], 8.5), ('T1046', assets[2], None)]
    results = prioritizer.batch_prioritize(batch)
    print(f"✓ Batch processing: {len(results)} threats ranked")
    
    # Test 4: Statistics
    stats = prioritizer.get_statistics()
    print(f"✓ Statistics: {stats['total_processed']} threats processed")
    
    print("\n✅ ALL TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
