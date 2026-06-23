"""
================================================================================
           THREAT INTELLIGENCE FUSION ENGINE - COMPREHENSIVE DOCUMENTATION
================================================================================
Dimension F - Documentation & API Stability
ADD-ONLY: New documentation module, no modifications to existing code
================================================================================

API STABILITY MARKERS:
======================
- @STABLE: API is frozen, backward compatible, will not break
- @EXPERIMENTAL: API may change in future versions
- @DEPRECATED: API scheduled for removal, use alternative

MODULE: threat_intelligence_fusion_correlation_engine_v13_2026_june.py
STABILITY: EXPERIMENTAL (v13 - first release, subject to refinement)
================================================================================
"""

from enum import Enum
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass


class APIMaturity(Enum):
    """API Stability Levels"""
    STABLE = "stable"           # Frozen API - guaranteed backward compatibility
    EXPERIMENTAL = "experimental"  # New API - may change in future versions
    DEPRECATED = "deprecated"     # Scheduled for removal - use alternative


class DocumentationCategory(Enum):
    """Documentation categories"""
    GETTING_STARTED = "getting_started"
    API_REFERENCE = "api_reference"
    USAGE_EXAMPLES = "usage_examples"
    BEST_PRACTICES = "best_practices"
    TROUBLESHOOTING = "troubleshooting"


@dataclass
class APIStabilityMarker:
    """API Stability annotation for methods and classes"""
    stability: APIMaturity
    version: str
    deprecation_version: Optional[str] = None
    notes: str = ""


# ============================================================================
#                        API STABILITY CATALOG
# ============================================================================

THREAT_INTELLIGENCE_API_STABILITY = {
    # Classes
    "ThreatSeverity": APIStabilityMarker(
        stability=APIMaturity.STABLE,
        version="v13",
        notes="Standard severity enum - will be extended but not changed"
    ),
    "ThreatSource": APIStabilityMarker(
        stability=APIMaturity.STABLE,
        version="v13",
        notes="Source type enum - stable classification"
    ),
    "IOCIndicator": APIStabilityMarker(
        stability=APIMaturity.STABLE,
        version="v13",
        notes="IOC data structure - core data model"
    ),
    "CorrelatedThreat": APIStabilityMarker(
        stability=APIMaturity.EXPERIMENTAL,
        version="v13",
        notes="May add additional fields in future versions"
    ),
    "ThreatFeedDatabase": APIStabilityMarker(
        stability=APIMaturity.EXPERIMENTAL,
        version="v13",
        notes="Pattern matching algorithms may be enhanced"
    ),
    "ThreatCorrelationEngine": APIStabilityMarker(
        stability=APIMaturity.EXPERIMENTAL,
        version="v13",
        notes="Correlation weights and scoring subject to tuning"
    ),
    "ThreatIntelligenceFusionManager": APIStabilityMarker(
        stability=APIMaturity.STABLE,
        version="v13",
        notes="Public API facade - guaranteed stable interface"
    ),
    
    # Public Methods
    "ThreatIntelligenceFusionManager.analyze_and_correlate": APIStabilityMarker(
        stability=APIMaturity.STABLE,
        version="v13",
        notes="Main entry point - signature guaranteed stable"
    ),
    "ThreatIntelligenceFusionManager.add_custom_ioc": APIStabilityMarker(
        stability=APIMaturity.STABLE,
        version="v13",
        notes="IOC management API"
    ),
    "ThreatIntelligenceFusionManager.get_threat_dashboard": APIStabilityMarker(
        stability=APIMaturity.EXPERIMENTAL,
        version="v13",
        notes="Dashboard metrics may be extended"
    ),
}


# ============================================================================
#                        GETTING STARTED GUIDE
# ============================================================================

GETTING_STARTED_GUIDE = """
================================================================================
                    GETTING STARTED WITH THREAT INTELLIGENCE FUSION
================================================================================

OVERVIEW:
---------
The Threat Intelligence Fusion & Correlation Engine provides real-time
threat feed aggregation, IOC matching, and cross-module threat correlation
for NeuralShield AI security platform.

QUICK START:
------------

1. Import the manager:
   from neural_shield.threat_intelligence_fusion_correlation_engine_v13_2026_june \\
       import ThreatIntelligenceFusionManager

2. Initialize:
   ti_manager = ThreatIntelligenceFusionManager()

3. Analyze input:
   result = ti_manager.analyze_and_correlate(
       input_text="User input text here...",
       detector_results={
           "prompt_injection": 0.85,
           "jailbreak": 0.3
       }
   )

4. Get dashboard:
   dashboard = ti_manager.get_threat_dashboard(window_minutes=60)

================================================================================
"""


# ============================================================================
#                        FULL API REFERENCE
# ============================================================================

API_REFERENCE = """
================================================================================
                        FULL API REFERENCE
================================================================================

=== ThreatIntelligenceFusionManager ===

STABILITY: @STABLE (v13)

Main public interface for threat intelligence operations.

--- analyze_and_correlate(input_text, detector_results, context=None) ---

STABILITY: @STABLE

Correlate detector results with threat intelligence feeds.

Parameters:
  input_text: str
    The text content to analyze for IOCs and threat patterns
  detector_results: Dict[str, float]
    Results from existing NeuralShield detectors:
    - prompt_injection: 0.0-1.0 confidence
    - jailbreak: 0.0-1.0 confidence  
    - adversarial: 0.0-1.0 confidence
    - hallucination: 0.0-1.0 confidence
    - toxicity: 0.0-1.0 confidence
    - pii_leakage: 0.0-1.0 confidence
  context: Optional[Dict[str, Any]]
    Additional context metadata (optional)

Returns: Dict with:
  threat_id: str - Unique threat identifier
  timestamp: str - ISO format timestamp
  severity: str - critical/high/medium/low/info
  confidence_score: float - 0.0-1.0 overall confidence
  fusion_score: float - Weighted correlation score
  recommended_action: str - block_immediately/quarantine_and_review/...
  description: str - Human-readable threat description
  matched_iocs_count: int - Number of IOCs matched
  matched_iocs: List[Dict] - Detailed IOC matches
  matched_ttps: List[str] - MITRE ATT&CK TTP codes
  detector_contributions: Dict[str, float] - Per-detector scores

--- add_custom_ioc(ioc_type, value, severity, confidence=0.9, description="") ---

STABILITY: @STABLE

Add custom IOC to threat database.

Parameters:
  ioc_type: str - ip/domain/hash/url/email
  value: str - IOC value
  severity: str - critical/high/medium/low/info
  confidence: float - 0.0-1.0 confidence level
  description: str - Optional description

Returns: bool - Success indicator

--- get_threat_dashboard(window_minutes=60) ---

STABILITY: @EXPERIMENTAL

Get threat summary dashboard.

Parameters:
  window_minutes: int - Time window for statistics

Returns: Dict with threat statistics

================================================================================
"""


# ============================================================================
#                        USAGE EXAMPLES
# ============================================================================

USAGE_EXAMPLES = """
================================================================================
                        USAGE EXAMPLES
================================================================================

EXAMPLE 1: Basic Threat Analysis
---------------------------------

from neural_shield.threat_intelligence_fusion_correlation_engine_v13_2026_june \\
    import ThreatIntelligenceFusionManager

# Initialize
ti = ThreatIntelligenceFusionManager()

# Analyze with detector results
result = ti.analyze_and_correlate(
    input_text=\"\"\"Check this IP: 192.168.1.100
    and domain: malicious-domain.com\"\"\",
    detector_results={
        "prompt_injection": 0.2,
        "jailbreak": 0.1
    }
)

print(f"Severity: {result['severity']}")
print(f"Action: {result['recommended_action']}")
print(f"IOCs matched: {result['matched_iocs_count']}")

EXAMPLE 2: Custom IOC Management
---------------------------------

# Add custom malicious IP
ti.add_custom_ioc(
    ioc_type="ip",
    value="10.0.0.99",
    severity="critical",
    confidence=0.98,
    description="Known C2 server from recent breach"
)

# Add malicious domain
ti.add_custom_ioc(
    ioc_type="domain",
    value="phishing-attack.com",
    severity="high",
    confidence=0.95
)

EXAMPLE 3: Integration with Existing Detectors
-----------------------------------------------

def full_security_scan(input_text: str, detectors: Dict):
    # Run existing detectors first
    detector_results = {}
    for name, detector in detectors.items():
        detector_results[name] = detector.scan(input_text)
    
    # Correlate with threat intelligence
    ti_result = ti.analyze_and_correlate(
        input_text=input_text,
        detector_results=detector_results
    )
    
    # Decision logic
    if ti_result["severity"] == "critical":
        return {"action": "block", "reason": ti_result["description"]}
    elif ti_result["severity"] == "high":
        return {"action": "review", "reason": ti_result["description"]}
    else:
        return {"action": "allow", "monitor": True}

EXAMPLE 4: Threat Monitoring Dashboard
---------------------------------------

# Get 24-hour threat summary
dashboard = ti.get_threat_dashboard(window_minutes=1440)

print(f"Threats in 24h: {dashboard['total_threats']}")
print(f"Severity breakdown:")
for sev, count in dashboard['severity_distribution'].items():
    print(f"  {sev}: {count}")
print(f"Average confidence: {dashboard['average_confidence']:.2f}")

================================================================================
"""


# ============================================================================
#                        BEST PRACTICES
# ============================================================================

BEST_PRACTICES = """
================================================================================
                        BEST PRACTICES
================================================================================

1. DETECTOR WEIGHTING
----------------------
- Combine at least 2+ detector results for optimal correlation
- Critical threats require confidence >= 0.8
- High threats require confidence >= 0.6
- Use detector_results dict with consistent naming

2. IOC MANAGEMENT
------------------
- Regularly update IOC database from threat feeds
- Set appropriate confidence levels (0.9+ for verified threats)
- Include descriptions for audit trail
- Hash IOCs: MD5/SHA1/SHA256 formats supported

3. PERFORMANCE
--------------
- ThreatFeedDatabase is in-memory - suitable for high throughput
- Correlation adds ~5ms latency per request
- History is capped at 10,000 entries automatically
- Use get_threat_dashboard sparingly (once per minute max)

4. THRESHOLD TUNING
-------------------
- Start with default thresholds
- Adjust based on false positive rate
- Block at CRITICAL (>=0.8)
- Review at HIGH (>=0.6)
- Monitor at MEDIUM (>=0.4)

5. INTEGRATION
--------------
- Call analyze_and_correlate AFTER running detectors
- Pass ALL detector results for best fusion
- Use context parameter for user/session metadata
- Log threat_id for incident response

================================================================================
"""


# ============================================================================
#                        TROUBLESHOOTING GUIDE
# ============================================================================

TROUBLESHOOTING = """
================================================================================
                        TROUBLESHOOTING GUIDE
================================================================================

COMMON ISSUES:
--------------

ISSUE: Low confidence scores on obvious threats
SOLUTION:
  - Ensure detector_results includes all relevant detectors
  - Add custom IOCs for known threats
  - Check that input_text contains the suspicious content

ISSUE: High false positive rate
SOLUTION:
  - Adjust confidence thresholds
  - Reduce detector weights for noisy detectors
  - Add benign patterns to exclusion list (custom logic)
  - Require multiple detector hits for HIGH/CRITICAL

ISSUE: Memory usage growing
SOLUTION:
  - correlation_history is append-only
  - Implement periodic pruning (keep last N entries)
  - Dashboard queries scan full history - limit window size

ISSUE: IOCs not matching
SOLUTION:
  - Verify IOC type matches value format
  - IP: standard IPv4 format
  - Domain: lowercase, no protocol prefix
  - Hash: exact hex format (32/40/64 chars)
  - Check regex patterns in ThreatFeedDatabase.match_iocs()

PERFORMANCE TUNING:
-------------------
- Pre-initialize ThreatIntelligenceFusionManager once
- Reuse manager instance across requests
- Batch IOC additions when possible
- Avoid frequent dashboard queries in hot paths

================================================================================
"""


# ============================================================================
#                        DOCUMENTATION MANAGER
# ============================================================================

class ThreatIntelligenceDocumentationManager:
    """
    Documentation manager for Threat Intelligence Fusion Engine
    
    STABILITY: @STABLE (v13)
    Provides programmatic access to all documentation.
    """
    
    def __init__(self):
        self.stability_catalog = THREAT_INTELLIGENCE_API_STABILITY
        self._module_version = "v13"
        self._module_name = "threat_intelligence_fusion_correlation_engine"
    
    def get_stability(self, api_name: str) -> Optional[Dict[str, Any]]:
        """Get stability information for an API"""
        marker = self.stability_catalog.get(api_name)
        if marker:
            return {
                "api": api_name,
                "stability": marker.stability.value,
                "version": marker.version,
                "deprecation_version": marker.deprecation_version,
                "notes": marker.notes
            }
        return None
    
    def get_documentation(self, category: DocumentationCategory) -> str:
        """Get documentation by category"""
        docs = {
            DocumentationCategory.GETTING_STARTED: GETTING_STARTED_GUIDE,
            DocumentationCategory.API_REFERENCE: API_REFERENCE,
            DocumentationCategory.USAGE_EXAMPLES: USAGE_EXAMPLES,
            DocumentationCategory.BEST_PRACTICES: BEST_PRACTICES,
            DocumentationCategory.TROUBLESHOOTING: TROUBLESHOOTING,
        }
        return docs.get(category, "Documentation category not found")
    
    def get_all_categories(self) -> List[str]:
        """List all available documentation categories"""
        return [c.value for c in DocumentationCategory]
    
    def list_stable_apis(self) -> List[str]:
        """List all APIs marked as STABLE"""
        return [
            name for name, marker in self.stability_catalog.items()
            if marker.stability == APIMaturity.STABLE
        ]
    
    def list_experimental_apis(self) -> List[str]:
        """List all APIs marked as EXPERIMENTAL"""
        return [
            name for name, marker in self.stability_catalog.items()
            if marker.stability == APIMaturity.EXPERIMENTAL
        ]
    
    def get_module_info(self) -> Dict[str, Any]:
        """Get module metadata"""
        return {
            "module": self._module_name,
            "version": self._module_version,
            "stability": "experimental",
            "total_apis": len(self.stability_catalog),
            "stable_apis": len(self.list_stable_apis()),
            "experimental_apis": len(self.list_experimental_apis()),
            "documentation_categories": len(DocumentationCategory),
            "dimension": "F - Documentation & API Stability",
            "backward_compatible": True,
            "add_only": True
        }
    
    def print_full_documentation(self) -> None:
        """Print complete documentation to console"""
        print("=" * 80)
        print("THREAT INTELLIGENCE FUSION ENGINE - FULL DOCUMENTATION")
        print("=" * 80)
        print()
        print(GETTING_STARTED_GUIDE)
        print(API_REFERENCE)
        print(USAGE_EXAMPLES)
        print(BEST_PRACTICES)
        print(TROUBLESHOOTING)
        print("=" * 80)
        print("API STABILITY SUMMARY")
        print("=" * 80)
        print(f"STABLE APIs ({len(self.list_stable_apis())}):")
        for api in self.list_stable_apis():
            print(f"  ✓ {api}")
        print(f"\nEXPERIMENTAL APIs ({len(self.list_experimental_apis())}):")
        for api in self.list_experimental_apis():
            print(f"  ⚠ {api}")
        print("=" * 80)


# ============================================================================
#                        USAGE EXAMPLE (SELF-DOCUMENTING)
# ============================================================================

if __name__ == "__main__":
    # Example: Access documentation programmatically
    doc_manager = ThreatIntelligenceDocumentationManager()
    
    print("Module Info:")
    print(doc_manager.get_module_info())
    
    print("\nStable APIs:")
    print(doc_manager.list_stable_apis())
    
    print("\nGet Started Guide:")
    print(doc_manager.get_documentation(DocumentationCategory.GETTING_STARTED)[:500], "...")
    
    # Print full documentation
    # doc_manager.print_full_documentation()
