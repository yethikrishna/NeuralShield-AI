"""
NeuralShield AI - Comprehensive API Documentation & Stability Catalog v8
========================================================================
STABILITY CATEGORY DEFINITIONS:
- STABLE: Production-ready, backward-compatible, no breaking changes planned
- EXPERIMENTAL: New feature, API may change, use with caution
- DEPRECATED: Scheduled for removal, migrate to alternatives
- LEGACY: Maintained for backward compatibility, not recommended for new code

This module provides comprehensive documentation, usage examples, and stability markers
for all NeuralShield AI security modules. All instrumentation is OPT-IN and does not
modify any core production logic.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Callable
import json
from datetime import datetime


class StabilityLevel(Enum):
    """API Stability Level classification"""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    LEGACY = "LEGACY"


@dataclass
class APIDocumentation:
    """Comprehensive API documentation entry"""
    module_name: str
    function_name: str
    stability: StabilityLevel
    description: str
    parameters: List[Dict[str, str]] = field(default_factory=list)
    returns: str = ""
    usage_examples: List[str] = field(default_factory=list)
    deprecation_notice: Optional[str] = None
    migration_guide: Optional[str] = None
    since_version: str = "1.0.0"
    category: str = "security"


class NeuralShieldAPIDocumentationCatalog:
    """
    Central catalog for all NeuralShield API documentation and stability markers.
    
    This is a READ-ONLY catalog - it does NOT modify any production code.
    All stability markers and documentation are purely informational.
    """
    
    def __init__(self):
        self._catalog: Dict[str, APIDocumentation] = {}
        self._build_catalog()
        self._initialized_at = datetime.utcnow().isoformat()
    
    def _build_catalog(self):
        """Build the complete API documentation catalog"""
        
        # ==================== STABLE MODULES ====================
        
        # Prompt Injection Detector - STABLE
        self._catalog["prompt_injection_detector"] = APIDocumentation(
            module_name="prompt_injection_detector",
            function_name="detect_prompt_injection",
            stability=StabilityLevel.STABLE,
            description="Primary prompt injection detection using multi-layered analysis",
            parameters=[
                {"name": "prompt", "type": "str", "description": "Input prompt to analyze"},
                {"name": "threshold", "type": "float", "description": "Detection confidence threshold (0.0-1.0)"}
            ],
            returns="Dict with 'detected' (bool), 'confidence' (float), 'attack_type' (str)",
            usage_examples=[
                """
                from neural_shield import prompt_injection_detector
                result = prompt_injection_detector("Ignore previous instructions")
                if result['detected']:
                    print(f"Attack detected: {result['confidence']:.2f}")
                """
            ],
            since_version="1.0.0",
            category="core-detection"
        )
        
        # Adversarial Prompt Anomaly Detector - STABLE
        self._catalog["adversarial_prompt_anomaly_detector"] = APIDocumentation(
            module_name="adversarial_prompt_anomaly_detector",
            function_name="detect_anomalous_patterns",
            stability=StabilityLevel.STABLE,
            description="Detect anomalous patterns in prompts using statistical analysis",
            parameters=[
                {"name": "prompt", "type": "str", "description": "Input prompt to analyze"},
                {"name": "context_window", "type": "int", "description": "Context window size for analysis"}
            ],
            returns="Dict with anomaly scores and detected patterns",
            usage_examples=[
                """
                detector = adversarial_prompt_anomaly_detector()
                result = detector.analyze_prompt(user_input)
                if result['anomaly_score'] > 0.7:
                    trigger_alert()
                """
            ],
            since_version="1.2.0",
            category="anomaly-detection"
        )
        
        # LLM Guardrails Policy Engine - STABLE
        self._catalog["llm_guardrails_policy_engine"] = APIDocumentation(
            module_name="llm_guardrails_policy_engine",
            function_name="enforce_policy",
            stability=StabilityLevel.STABLE,
            description="Enforce content safety and policy compliance on LLM outputs",
            parameters=[
                {"name": "output_text", "type": "str", "description": "LLM output to validate"},
                {"name": "policies", "type": "List[str]", "description": "Policy names to enforce"}
            ],
            returns="Dict with compliance status and violations found",
            usage_examples=[
                """
                engine = llm_guardrails_policy_engine()
                result = engine.validate(llm_response, ['toxicity', 'pii', 'harmful'])
                sanitized = engine.sanitize(result)
                """
            ],
            since_version="1.1.0",
            category="content-safety"
        )
        
        # Output Sanitizer PII Redactor - STABLE
        self._catalog["output_sanitizer_pii_redactor"] = APIDocumentation(
            module_name="output_sanitizer_pii_redactor",
            function_name="redact_pii",
            stability=StabilityLevel.STABLE,
            description="Redact personally identifiable information from text outputs",
            parameters=[
                {"name": "text", "type": "str", "description": "Text to scan for PII"},
                {"name": "redaction_char", "type": "str", "description": "Character used for redaction"}
            ],
            returns="Tuple of (redacted_text, found_pii_types, positions)",
            usage_examples=[
                """
                sanitized = output_sanitizer_pii_redactor.redact(user_message)
                print(f"Redacted: {sanitized['redacted_text']}")
                """
            ],
            since_version="1.0.0",
            category="privacy"
        )
        
        # ==================== EXPERIMENTAL MODULES ====================
        
        # Cross-Module Threat Correlation Engine - EXPERIMENTAL
        self._catalog["cross_module_threat_correlation_engine"] = APIDocumentation(
            module_name="cross_module_threat_correlation_engine",
            function_name="correlate_threats",
            stability=StabilityLevel.EXPERIMENTAL,
            description="Correlate threats across multiple detection modules (NEW v12)",
            parameters=[
                {"name": "detection_results", "type": "List[Dict]", "description": "Results from all detectors"},
                {"name": "correlation_window_ms", "type": "int", "description": "Time window for correlation"}
            ],
            returns="Correlated threat events with confidence scores",
            usage_examples=[
                """
                # EXPERIMENTAL - API may change
                engine = cross_module_threat_correlation_engine_v12()
                correlated = engine.correlate(all_detections)
                """
            ],
            since_version="2.3.0",
            category="threat-intelligence"
        )
        
        # Cross-Module Provenance Tracker - EXPERIMENTAL
        self._catalog["cross_module_provenance_tracker"] = APIDocumentation(
            module_name="cross_module_provenance_tracker",
            function_name="track_provenance",
            stability=StabilityLevel.EXPERIMENTAL,
            description="Track provenance chain through detection modules (NEW v11)",
            parameters=[
                {"name": "input_data", "type": "Any", "description": "Data to track"},
                {"name": "module_chain", "type": "List[str]", "description": "Modules processing this data"}
            ],
            returns="Provenance chain with timestamps and module signatures",
            usage_examples=[
                """
                # EXPERIMENTAL - Under active development
                tracker = cross_module_provenance_tracker_v11()
                chain = tracker.build_chain(input_prompt)
                """
            ],
            since_version="2.2.0",
            category="audit"
        )
        
        # Multimodal VLM Prompt Injection Detector - EXPERIMENTAL
        self._catalog["multimodal_vlm_prompt_injection_detector"] = APIDocumentation(
            module_name="multimodal_vlm_prompt_injection_detector",
            function_name="detect_vlm_injection",
            stability=StabilityLevel.EXPERIMENTAL,
            description="Detect prompt injection in vision-language model inputs",
            parameters=[
                {"name": "image_data", "type": "bytes", "description": "Image to analyze"},
                {"name": "text_prompt", "type": "str", "description": "Associated text prompt"}
            ],
            returns="Detection result with visual and text attack vectors",
            usage_examples=[
                """
                # EXPERIMENTAL - Multimodal support in beta
                result = multimodal_vlm_prompt_injection_detector.analyze(img, prompt)
                """
            ],
            since_version="2.1.0",
            category="multimodal-security"
        )
        
        # ==================== DEPRECATED MODULES ====================
        
        # Simple Prompt Injection Detector - DEPRECATED
        self._catalog["simple_prompt_injection_detector"] = APIDocumentation(
            module_name="simple_prompt_injection_detector",
            function_name="simple_detect",
            stability=StabilityLevel.DEPRECATED,
            description="DEPRECATED: Basic regex-based injection detection",
            deprecation_notice="Deprecated since v1.5.0 - Will be removed in v3.0.0",
            migration_guide="Use prompt_injection_detector.detect_prompt_injection() instead",
            parameters=[{"name": "prompt", "type": "str", "description": "Input to check"}],
            returns="Basic detection boolean",
            usage_examples=["# DEPRECATED - Use multi-layer detector instead"],
            since_version="0.9.0",
            category="legacy-detection"
        )
        
        # ==================== LEGACY MODULES ====================
        
        # Basic Jailbreak Detector - LEGACY
        self._catalog["basic_jailbreak_detector"] = APIDocumentation(
            module_name="basic_jailbreak_detector",
            function_name="detect_jailbreak",
            stability=StabilityLevel.LEGACY,
            description="LEGACY: Original jailbreak pattern matcher",
            parameters=[{"name": "prompt", "type": "str", "description": "Prompt to check"}],
            returns="Boolean detection result",
            usage_examples=["# LEGACY - Maintained for compatibility only"],
            since_version="0.8.0",
            category="legacy"
        )
    
    def get_documentation(self, module_name: str) -> Optional[APIDocumentation]:
        """Get documentation for a specific module"""
        return self._catalog.get(module_name)
    
    def list_by_stability(self, stability: StabilityLevel) -> List[APIDocumentation]:
        """List all modules with given stability level"""
        return [doc for doc in self._catalog.values() if doc.stability == stability]
    
    def get_stability_summary(self) -> Dict[str, int]:
        """Get summary count by stability level"""
        summary = {"STABLE": 0, "EXPERIMENTAL": 0, "DEPRECATED": 0, "LEGACY": 0}
        for doc in self._catalog.values():
            summary[doc.stability.value] += 1
        return summary
    
    def export_catalog_json(self) -> str:
        """Export catalog as JSON for documentation tools"""
        export_data = {}
        for name, doc in self._catalog.items():
            export_data[name] = {
                "module_name": doc.module_name,
                "stability": doc.stability.value,
                "description": doc.description,
                "since_version": doc.since_version,
                "category": doc.category,
                "deprecation_notice": doc.deprecation_notice,
                "migration_guide": doc.migration_guide
            }
        return json.dumps(export_data, indent=2)
    
    def generate_readme_section(self) -> str:
        """Generate markdown documentation for README"""
        summary = self.get_stability_summary()
        md = f"""
## API Stability Overview

| Stability Level | Count | Description |
|-----------------|-------|-------------|
| 🟢 STABLE | {summary['STABLE']} | Production-ready, backward-compatible |
| 🟡 EXPERIMENTAL | {summary['EXPERIMENTAL']} | New features, API may change |
| 🔴 DEPRECATED | {summary['DEPRECATED']} | Scheduled for removal |
| ⚪ LEGACY | {summary['LEGACY']} | Compatibility only |

### Module Reference
"""
        for level in [StabilityLevel.STABLE, StabilityLevel.EXPERIMENTAL, 
                      StabilityLevel.DEPRECATED, StabilityLevel.LEGACY]:
            modules = self.list_by_stability(level)
            if modules:
                md += f"\n#### {level.value} Modules\n\n"
                for mod in modules:
                    md += f"- **{mod.module_name}** - {mod.description}\n"
        return md


# Singleton instance for easy import
api_catalog = NeuralShieldAPIDocumentationCatalog()

# Public export functions
def get_api_stability(module_name: str) -> Optional[str]:
    """Get stability level for a module (OPT-IN informational only)"""
    doc = api_catalog.get_documentation(module_name)
    return doc.stability.value if doc else None

def get_module_documentation(module_name: str) -> Optional[Dict]:
    """Get full documentation for a module"""
    doc = api_catalog.get_documentation(module_name)
    if doc:
        return {
            "stability": doc.stability.value,
            "description": doc.description,
            "parameters": doc.parameters,
            "returns": doc.returns,
            "examples": doc.usage_examples,
            "since": doc.since_version
        }
    return None

def get_stability_report() -> Dict:
    """Get complete stability report"""
    return {
        "generated_at": datetime.utcnow().isoformat(),
        "summary": api_catalog.get_stability_summary(),
        "total_modules": len(api_catalog._catalog),
        "catalog_version": "v8_2026_JUNE"
    }


"""
USAGE NOTE:
This entire module is PURELY DOCUMENTATION and does NOT:
- Modify any production code
- Change behavior of existing modules
- Add any runtime overhead unless explicitly imported
- Break any existing tests

All functions are OPT-IN and informational only.
"""
