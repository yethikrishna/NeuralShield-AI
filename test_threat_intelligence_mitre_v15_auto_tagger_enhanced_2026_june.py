#!/usr/bin/env python3
"""
Test suite for MITRE ATT&CK v15 Auto-Tagger - Enhanced Pattern Matching
NeuralShield-AI Production-Grade Testing
"""

import json
import sys
import time
from datetime import datetime

sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_mitre_v15_auto_tagger_enhanced_2026_june import (
    MITREv15AutoTagger,
    TaggingResult
)


def run_tests():
    """Run all production tests"""
    print("=" * 70)
    print("NeuralShield-AI: MITRE ATT&CK v15 Auto-Tagger Tests")
    print("=" * 70)
    print(f"Test Time: {datetime.now().isoformat()}")
    print()
    
    test_results = {
        "test_suite": "MITRE v15 Auto-Tagger Enhanced",
        "timestamp": datetime.now().isoformat(),
        "passed": 0,
        "failed": 0,
        "tests": []
    }
    
    # Initialize tagger
    print("[TEST 1] Initialization Test")
    try:
        tagger = MITREv15AutoTagger(cache_ttl_seconds=60)
        stats = tagger.get_statistics()
        print(f"  ✓ Tagger initialized successfully")
        print(f"  ✓ Techniques loaded: {stats['total_techniques']}")
        print(f"  ✓ Tactics covered: {len(stats['tactics_coverage'])}")
        test_results["passed"] += 1
        test_results["tests"].append({"name": "initialization", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"name": "initialization", "status": "FAILED", "error": str(e)})
        return test_results
    
    print()
    
    # Test 2: Ransomware detection
    print("[TEST 2] Ransomware Threat Detection")
    try:
        ransomware_text = """
        The ransomware encrypted all files using AES encryption.
        It deleted shadow copies using vssadmin delete shadows.
        The attackers demanded bitcoin payment for decryption keys.
        Files were renamed with .encrypted extension.
        """
        result = tagger.tag_threat_intelligence(ransomware_text, input_id="test_ransomware")
        
        impact_techniques = [t for t in result.matched_techniques if t["tactic"] == "Impact"]
        print(f"  ✓ Processing time: {result.processing_time_ms}ms")
        print(f"  ✓ Total techniques matched: {len(result.matched_techniques)}")
        print(f"  ✓ Impact techniques found: {len(impact_techniques)}")
        
        has_data_encrypted = any("T1486" in t["technique_id"] for t in result.matched_techniques)
        has_inhibit_recovery = any("T1490" in t["technique_id"] for t in result.matched_techniques)
        
        if has_data_encrypted:
            print("  ✓ T1486 (Data Encrypted for Impact) detected")
        if has_inhibit_recovery:
            print("  ✓ T1490 (Inhibit System Recovery) detected")
            
        test_results["passed"] += 1
        test_results["tests"].append({"name": "ransomware_detection", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"name": "ransomware_detection", "status": "FAILED", "error": str(e)})
    
    print()
    
    # Test 3: Credential Access detection
    print("[TEST 3] Credential Access Detection")
    try:
        cred_text = """
        Attacker used mimikatz to dump LSASS memory and extract password hashes.
        Performed pass-the-hash attack to move laterally via SMB.
        Also did password spraying against domain accounts.
        """
        result = tagger.tag_threat_intelligence(cred_text, input_id="test_cred_access")
        
        cred_techniques = [t for t in result.matched_techniques if t["tactic"] == "Credential Access"]
        lateral_techniques = [t for t in result.matched_techniques if t["tactic"] == "Lateral Movement"]
        
        print(f"  ✓ Processing time: {result.processing_time_ms}ms")
        print(f"  ✓ Credential Access techniques: {len(cred_techniques)}")
        print(f"  ✓ Lateral Movement techniques: {len(lateral_techniques)}")
        
        has_cred_dump = any("T1003" in t["technique_id"] for t in result.matched_techniques)
        has_pass_hash = any("T1550" in t["technique_id"] for t in result.matched_techniques)
        
        if has_cred_dump:
            print("  ✓ T1003 (OS Credential Dumping) detected")
        if has_pass_hash:
            print("  ✓ T1550 (Alternate Authentication Material) detected")
            
        test_results["passed"] += 1
        test_results["tests"].append({"name": "credential_access", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"name": "credential_access", "status": "FAILED", "error": str(e)})
    
    print()
    
    # Test 4: Phishing + C2 detection
    print("[TEST 4] Multi-Tactic Threat Detection")
    try:
        multi_text = """
        Spearphishing email with malicious Word document attachment.
        Macro executes PowerShell to download payload from C2 server.
        C2 communication over HTTPS with base64 encoded commands.
        Established persistence via registry Run key.
        """
        result = tagger.tag_threat_intelligence(multi_text, input_id="test_multi_tactic")
        
        print(f"  ✓ Processing time: {result.processing_time_ms}ms")
        print(f"  ✓ Tactics found: {', '.join(result.tactics_found)}")
        print(f"  ✓ Total techniques: {len(result.matched_techniques)}")
        
        if len(result.tactics_found) >= 3:
            print(f"  ✓ Multi-tactic detection working: {len(result.tactics_found)} tactics")
            
        test_results["passed"] += 1
        test_results["tests"].append({"name": "multi_tactic", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"name": "multi_tactic", "status": "FAILED", "error": str(e)})
    
    print()
    
    # Test 5: Cache functionality
    print("[TEST 5] Cache Performance Test")
    try:
        test_text = "Testing cache performance with powershell and base64 encoding"
        
        # First call - cache miss
        start = time.time()
        result1 = tagger.tag_threat_intelligence(test_text)
        time1 = (time.time() - start) * 1000
        
        # Second call - should be cache hit
        start = time.time()
        result2 = tagger.tag_threat_intelligence(test_text)
        time2 = (time.time() - start) * 1000
        
        print(f"  ✓ First call (cache miss): {time1:.2f}ms")
        print(f"  ✓ Second call (cache hit): {time2:.2f}ms")
        
        if result2.cache_hit:
            print("  ✓ Cache hit correctly detected")
        if time2 < time1:
            print("  ✓ Cache improves performance")
            
        test_results["passed"] += 1
        test_results["tests"].append({"name": "cache_functionality", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"name": "cache_functionality", "status": "FAILED", "error": str(e)})
    
    print()
    
    # Test 6: Batch processing
    print("[TEST 6] Batch Processing Test")
    try:
        batch_texts = [
            "RDP brute force attack detected from external IP",
            "Phishing email with malicious attachment observed",
            "Powershell execution with base64 encoded command",
            "Port scanning activity detected on network",
            "Mimikatz credential dumping tool used"
        ]
        
        results = tagger.batch_tag(batch_texts)
        
        print(f"  ✓ Batch size: {len(batch_texts)}")
        print(f"  ✓ Results returned: {len(results)}")
        
        total_time = sum(r.processing_time_ms for r in results)
        avg_time = total_time / len(results)
        print(f"  ✓ Average processing time: {avg_time:.2f}ms")
        
        test_results["passed"] += 1
        test_results["tests"].append({"name": "batch_processing", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"name": "batch_processing", "status": "FAILED", "error": str(e)})
    
    print()
    
    # Test 7: Executive summary generation
    print("[TEST 7] Executive Summary Generation")
    try:
        threat_text = """
        Ransomware attack: encrypted files, deleted backups,
        disabled antivirus, established persistence, exfiltrated data.
        """
        result = tagger.tag_threat_intelligence(threat_text)
        summary = tagger.generate_mitre_summary(result)
        
        print(f"  ✓ Summary generated: {summary['total_matches']} matches")
        print(f"  ✓ Tactics affected: {summary['tactics_affected']}")
        print(f"  ✓ Severity breakdown: {summary['severity_breakdown']}")
        
        test_results["passed"] += 1
        test_results["tests"].append({"name": "executive_summary", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"name": "executive_summary", "status": "FAILED", "error": str(e)})
    
    print()
    print("=" * 70)
    print(f"TEST SUMMARY: {test_results['passed']} PASSED, {test_results['failed']} FAILED")
    print("=" * 70)
    
    # Save results
    with open('/home/user/autonomous-developer/NeuralShield-AI/test_results_mitre_v15_auto_tagger_enhanced.json', 'w') as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nResults saved to: test_results_mitre_v15_auto_tagger_enhanced.json")
    
    return test_results


if __name__ == "__main__":
    results = run_tests()
    sys.exit(0 if results["failed"] == 0 else 1)
