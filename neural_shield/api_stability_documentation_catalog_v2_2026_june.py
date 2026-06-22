"""
NeuralShield-AI API Stability Documentation Catalog v2.0
========================================================
API Stability Markers: STABLE | EXPERIMENTAL | DEPRECATED
Last Updated: 2026-06-22
Incremental Build: ADD-ONLY - No existing code modified
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
import json
from datetime import datetime


class StabilityLevel(Enum):
    """API Stability Level Classification."""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"


@dataclass
class APIEndpoint:
    """Metadata for a single API endpoint or function."""
    name: str
    module: str
    stability: StabilityLevel
    since_version: str
    description: str
    usage_example: str
    parameters: List[Dict[str, str]] = field(default_factory=list)
    returns: str = ""
    deprecation_notice: Optional[str] = None
    deprecation_scheduled_for: Optional[str] = None
    replacement: Optional[str] = None


@dataclass
class ModuleDocumentation:
    """Complete documentation for a module."""
    module_name: str
    category: str
    endpoints: List[APIEndpoint] = field(default_factory=list)
    module_description: str = ""


class NeuralShieldAPIStabilityCatalog:
    """
    Central catalog for NeuralShield-AI API stability information.
    
    STABILITY: STABLE (since v1.0)
    Provides machine-readable API metadata for all public interfaces.
    """
    
    def __init__(self):
        self.modules: Dict[str, ModuleDocumentation] = {}
        self._initialize_core_modules()
        self._initialize_threat_intelligence_modules()
        self._initialize_prompt_injection_modules()
        self._initialize_security_modules()
    
    def _initialize_core_modules(self) -> None:
        """Initialize core framework modules."""
        
        # Core Shield Defense Framework
        self.modules["shield_defense_framework"] = ModuleDocumentation(
            module_name="shield_defense_framework_2026",
            category="Core Framework",
            module_description="Primary entry point for NeuralShield AI security protection",
            endpoints=[
                APIEndpoint(
                    name="ShieldDefenseFramework.__init__",
                    module="shield_defense_framework_2026",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Initialize the main security framework with optional config",
                    usage_example="""
shield = ShieldDefenseFramework(
    enable_prompt_injection=True,
    enable_jailbreak_detection=True,
    log_level="INFO"
)
result = shield.scan_prompt(user_input)
                    """,
                    parameters=[
                        {"name": "enable_prompt_injection", "type": "bool", "desc": "Enable prompt injection detection"},
                        {"name": "enable_jailbreak_detection", "type": "bool", "desc": "Enable jailbreak pattern detection"},
                        {"name": "log_level", "type": "str", "desc": "Logging verbosity level"}
                    ],
                    returns="ShieldDefenseFramework instance"
                ),
                APIEndpoint(
                    name="ShieldDefenseFramework.scan_prompt",
                    module="shield_defense_framework_2026",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Scan user input for security threats",
                    usage_example="""
result = shield.scan_prompt("Ignore previous instructions...")
if result["risk_score"] > 0.7:
    print("Threat detected!")
                    """,
                    parameters=[
                        {"name": "prompt", "type": "str", "desc": "User input to scan"}
                    ],
                    returns="Dict with risk_score, threats_detected, confidence"
                )
            ]
        )
    
    def _initialize_threat_intelligence_modules(self) -> None:
        """Initialize threat intelligence modules."""
        
        # MITRE ATT&CK Coverage Analyzer
        self.modules["mitre_attack_v15_coverage_analyzer"] = ModuleDocumentation(
            module_name="mitre_attack_v15_coverage_analyzer_2026_june",
            category="Threat Intelligence",
            module_description="MITRE ATT&CK v15 framework mapping and coverage analysis",
            endpoints=[
                APIEndpoint(
                    name="MITREAttackV15Analyzer.calculate_coverage",
                    module="mitre_attack_v15_coverage_analyzer_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.2.0",
                    description="Calculate detection coverage against MITRE ATT&CK matrix",
                    usage_example="""
analyzer = MITREAttackV15Analyzer()
coverage = analyzer.calculate_coverage(detections)
print(f"Tactics covered: {coverage['tactics_covered_pct']:.1f}%")
                    """,
                    parameters=[
                        {"name": "detections", "type": "List[Dict]", "desc": "List of detection rules"}
                    ],
                    returns="Dict with tactics_covered_pct, techniques_covered, gaps"
                ),
                APIEndpoint(
                    name="MITREAttackV15Analyzer.generate_heatmap",
                    module="mitre_attack_v15_coverage_analyzer_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.2.0",
                    description="Generate MITRE ATT&CK heatmap visualization data",
                    usage_example="""
heatmap_data = analyzer.generate_heatmap(coverage_report)
export_to_json(heatmap_data, "mitre_heatmap.json")
                    """,
                    parameters=[
                        {"name": "coverage_report", "type": "Dict", "desc": "Coverage analysis output"}
                    ],
                    returns="Structured heatmap data for visualization"
                )
            ]
        )
        
        # IOC Normalization Engine
        self.modules["ioc_normalization_deduplication"] = ModuleDocumentation(
            module_name="threat_intelligence_ioc_normalization_deduplication_engine_v3_2026_june",
            category="Threat Intelligence",
            module_description="IOC (Indicators of Compromise) normalization and deduplication",
            endpoints=[
                APIEndpoint(
                    name="IOCNormalizationEngine.normalize_ioc",
                    module="threat_intelligence_ioc_normalization_deduplication_engine_v3_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.1.0",
                    description="Normalize IOC to standard format",
                    usage_example="""
engine = IOCNormalizationEngine()
normalized = engine.normalize_ioc("192.168.1.1", ioc_type="ip")
                    """,
                    parameters=[
                        {"name": "ioc_value", "type": "str", "desc": "Raw IOC value"},
                        {"name": "ioc_type", "type": "str", "desc": "IOC type: ip/domain/hash/url"}
                    ],
                    returns="Normalized IOC dictionary"
                ),
                APIEndpoint(
                    name="IOCNormalizationEngine.deduplicate_batch",
                    module="threat_intelligence_ioc_normalization_deduplication_engine_v3_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.1.0",
                    description="Deduplicate batch of IOCs",
                    usage_example="""
unique_iocs = engine.deduplicate_batch(ioc_list)
print(f"Removed {len(ioc_list) - len(unique_iocs)} duplicates")
                    """,
                    parameters=[
                        {"name": "iocs", "type": "List[str]", "desc": "List of IOC values"}
                    ],
                    returns="Deduplicated list with confidence scores"
                )
            ]
        )
    
    def _initialize_prompt_injection_modules(self) -> None:
        """Initialize prompt injection detection modules."""
        
        # Prompt Injection Context Analyzer
        self.modules["prompt_injection_context_analyzer"] = ModuleDocumentation(
            module_name="prompt_injection_context_analyzer_2026_june",
            category="Prompt Injection Defense",
            module_description="Context-aware prompt injection detection and analysis",
            endpoints=[
                APIEndpoint(
                    name="PromptInjectionContextAnalyzer.analyze",
                    module="prompt_injection_context_analyzer_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Analyze prompt for injection patterns with context",
                    usage_example="""
analyzer = PromptInjectionContextAnalyzer()
result = analyzer.analyze(user_input, conversation_history)
if result["is_injection"]:
    log_threat(result["patterns_found"])
                    """,
                    parameters=[
                        {"name": "prompt", "type": "str", "desc": "User input to analyze"},
                        {"name": "context", "type": "Optional[List[str]]", "desc": "Conversation history"}
                    ],
                    returns="Dict with is_injection, risk_score, patterns_found"
                ),
                APIEndpoint(
                    name="PromptInjectionContextAnalyzer.get_confidence_score",
                    module="prompt_injection_context_analyzer_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Get confidence score for injection detection",
                    usage_example="""
confidence = analyzer.get_confidence_score(analysis_result)
                    """,
                    parameters=[
                        {"name": "analysis", "type": "Dict", "desc": "Output from analyze()"}
                    ],
                    returns="Float confidence score 0.0-1.0"
                )
            ]
        )
        
        # Prompt Injection Evasion Detector v4
        self.modules["prompt_injection_evasion_detector_v4"] = ModuleDocumentation(
            module_name="prompt_injection_evasion_technique_detector_v4_2026_june",
            category="Prompt Injection Defense",
            module_description="Advanced evasion technique detection (obfuscation, paraphrasing)",
            endpoints=[
                APIEndpoint(
                    name="EvasionTechniqueDetectorV4.detect_obfuscation",
                    module="prompt_injection_evasion_technique_detector_v4_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.3.0",
                    description="Detect obfuscated injection attempts",
                    usage_example="""
detector = EvasionTechniqueDetectorV4()
result = detector.detect_obfuscation(encoded_prompt)
                    """,
                    parameters=[
                        {"name": "prompt", "type": "str", "desc": "Potentially obfuscated input"}
                    ],
                    returns="Dict with obfuscation_detected, techniques, decoded"
                )
            ]
        )
    
    def _initialize_security_modules(self) -> None:
        """Initialize security hardening modules."""
        
        # Input Validation Wrappers
        self.modules["security_input_validation"] = ModuleDocumentation(
            module_name="security_input_validation_wrappers_2026_june",
            category="Security Hardening",
            module_description="Secure input validation wrappers for all user inputs",
            endpoints=[
                APIEndpoint(
                    name="InputValidator.validate_string",
                    module="security_input_validation_wrappers_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Validate and sanitize string input",
                    usage_example="""
validator = InputValidator(max_length=4096)
clean = validator.validate_string(user_input, allow_special_chars=False)
                    """,
                    parameters=[
                        {"name": "value", "type": "str", "desc": "Input to validate"},
                        {"name": "max_length", "type": "int", "desc": "Maximum allowed length"},
                        {"name": "allow_special_chars", "type": "bool", "desc": "Allow special characters"}
                    ],
                    returns="Sanitized string"
                )
            ]
        )
        
        # Secure Memory Zeroization
        self.modules["secure_memory_zeroization"] = ModuleDocumentation(
            module_name="secure_memory_zeroization_constant_time_helpers_2026_june",
            category="Security Hardening",
            module_description="Constant-time memory operations for sensitive data",
            endpoints=[
                APIEndpoint(
                    name="SecureMemory.zeroize",
                    module="secure_memory_zeroization_constant_time_helpers_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Securely zeroize sensitive data in memory",
                    usage_example="""
sensitive_data = get_secret_key()
process_data(sensitive_data)
SecureMemory.zeroize(sensitive_data)
                    """,
                    parameters=[
                        {"name": "data", "type": "bytearray", "desc": "Sensitive data to zeroize"}
                    ],
                    returns="None - modifies in place"
                ),
                APIEndpoint(
                    name="SecureMemory.constant_time_compare",
                    module="secure_memory_zeroization_constant_time_helpers_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Timing-attack resistant comparison",
                    usage_example="""
if SecureMemory.constant_time_compare(user_hmac, expected_hmac):
    grant_access()
                    """,
                    parameters=[
                        {"name": "a", "type": "bytes", "desc": "First value"},
                        {"name": "b", "type": "bytes", "desc": "Second value"}
                    ],
                    returns="True if equal, False otherwise"
                )
            ]
        )
    
    def get_stability_report(self, module_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate stability report for documentation.
        
        STABILITY: STABLE
        """
        if module_name:
            module = self.modules.get(module_name)
            if not module:
                return {"error": "Module not found"}
            return self._module_to_dict(module)
        
        return {
            "catalog_version": "2.0.0",
            "generated_at": datetime.utcnow().isoformat(),
            "total_modules": len(self.modules),
            "total_endpoints": sum(len(m.endpoints) for m in self.modules.values()),
            "stability_breakdown": {
                "STABLE": sum(1 for m in self.modules.values() for e in m.endpoints if e.stability == StabilityLevel.STABLE),
                "EXPERIMENTAL": sum(1 for m in self.modules.values() for e in m.endpoints if e.stability == StabilityLevel.EXPERIMENTAL),
                "DEPRECATED": sum(1 for m in self.modules.values() for e in m.endpoints if e.stability == StabilityLevel.DEPRECATED)
            },
            "modules": {name: self._module_to_dict(mod) for name, mod in self.modules.items()}
        }
    
    def _module_to_dict(self, module: ModuleDocumentation) -> Dict[str, Any]:
        """Convert module to serializable dict."""
        return {
            "module_name": module.module_name,
            "category": module.category,
            "description": module.module_description,
            "endpoints": [
                {
                    "name": e.name,
                    "stability": e.stability.value,
                    "since_version": e.since_version,
                    "description": e.description,
                    "usage_example": e.usage_example.strip(),
                    "parameters": e.parameters,
                    "returns": e.returns,
                    "deprecation_notice": e.deprecation_notice
                }
                for e in module.endpoints
            ]
        }
    
    def export_to_json(self, filepath: str) -> None:
        """Export complete catalog to JSON file."""
        with open(filepath, 'w') as f:
            json.dump(self.get_stability_report(), f, indent=2)


# Usage Example
if __name__ == "__main__":
    catalog = NeuralShieldAPIStabilityCatalog()
    report = catalog.get_stability_report()
    print(f"API Stability Catalog v2.0")
    print(f"Modules documented: {report['total_modules']}")
    print(f"Endpoints documented: {report['total_endpoints']}")
    print(f"Stability breakdown: {report['stability_breakdown']}")
