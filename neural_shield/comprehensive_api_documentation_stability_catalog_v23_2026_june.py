"""
NeuralShield AI - Comprehensive API Documentation & Stability Catalog v23
=========================================================================
STABILITY LEVEL: STABLE
LAST UPDATED: 2026-06-24
MODULE: neural_shield.comprehensive_api_documentation_stability_catalog_v23

This module provides comprehensive API documentation, usage examples,
and stability markers for all NeuralShield AI security modules.

API STABILITY CLASSIFICATION:
- STABLE: Production-ready, backward compatible, no breaking changes
- EXPERIMENTAL: Under active development, API may change
- DEPRECATED: Scheduled for removal, migrate to alternatives
- LEGACY: Maintained for backward compatibility only
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Callable
import json
from datetime import datetime


class StabilityLevel(Enum):
    """API Stability Level Classification"""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    LEGACY = "LEGACY"


@dataclass
class ModuleDocumentation:
    """Documentation entry for a NeuralShield module"""
    module_name: str
    stability_level: StabilityLevel
    description: str
    primary_class: str
    key_methods: List[str]
    usage_examples: List[str]
    dependencies: List[str]
    deprecation_notice: Optional[str] = None
    migration_guide: Optional[str] = None
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())
    version: str = "1.0.0"


class NeuralShieldAPIDocumentationCatalog:
    """
    Comprehensive API Documentation Catalog for NeuralShield AI
    
    STABILITY LEVEL: STABLE
    
    This catalog provides:
    1. Complete module inventory with stability classifications
    2. Detailed usage examples for each module
    3. Dependency graphs and integration guides
    4. Deprecation notices and migration paths
    5. API change history and version compatibility
    
    Usage Example:
        >>> catalog = NeuralShieldAPIDocumentationCatalog()
        >>> catalog.initialize()
        >>> docs = catalog.get_module_docs("advanced_jailbreak_detector")
        >>> print(docs.description)
    """
    
    def __init__(self):
        self._modules: Dict[str, ModuleDocumentation] = {}
        self._initialized = False
        self._catalog_version = "v23"
        self._generation_date = datetime.now().isoformat()
    
    def initialize(self) -> bool:
        """
        Initialize the documentation catalog with all module entries
        
        Returns:
            bool: True if initialization successful
            
        STABILITY: STABLE
        """
        self._register_core_modules()
        self._register_threat_detection_modules()
        self._register_agent_security_modules()
        self._register_cross_modal_modules()
        self._register_utility_modules()
        self._initialized = True
        return True
    
    def _register_core_modules(self):
        """Register core security modules"""
        
        # Advanced Jailbreak Detector - STABLE
        self._modules["advanced_jailbreak_detector"] = ModuleDocumentation(
            module_name="advanced_jailbreak_detector_2026",
            stability_level=StabilityLevel.STABLE,
            description="Advanced multi-layer jailbreak detection using pattern matching, semantic analysis, and behavioral heuristics to detect prompt injection and jailbreak attempts.",
            primary_class="AdvancedJailbreakDetector",
            key_methods=[
                "detect_jailbreak(prompt: str) -> Dict",
                "calculate_risk_score(prompt: str) -> float",
                "get_jailbreak_indicators(prompt: str) -> List[str]",
                "is_suspicious_pattern(prompt: str) -> bool"
            ],
            usage_examples=[
                """detector = AdvancedJailbreakDetector()
result = detector.detect_jailbreak("Ignore previous instructions...")
if result['is_jailbreak']:
    print(f"Risk Score: {result['risk_score']}")""",
                """# Batch detection mode
prompts = ["Normal query", "DAN prompt attempt"]
results = [detector.detect_jailbreak(p) for p in prompts]"""
            ],
            dependencies=["re", "typing"]
        )
        
        # Constitutional Classifier - STABLE
        self._modules["constitutional_classifier"] = ModuleDocumentation(
            module_name="constitutional_classifier_2026",
            stability_level=StabilityLevel.STABLE,
            description="Constitutional AI alignment classifier that evaluates prompts against safety principles and constitutional guidelines.",
            primary_class="ConstitutionalClassifier",
            key_methods=[
                "classify_alignment(prompt: str) -> Dict",
                "check_constitutional_principles(text: str) -> Dict",
                "get_violation_severity(text: str) -> str",
                "generate_safety_report(text: str) -> Dict"
            ],
            usage_examples=[
                """classifier = ConstitutionalClassifier()
result = classifier.classify_alignment(user_input)
if not result['is_aligned']:
    for violation in result['violations']:
        print(f"Violation: {violation}")"""
            ],
            dependencies=["typing", "collections"]
        )
    
    def _register_threat_detection_modules(self):
        """Register threat detection modules"""
        
        # Adversarial Prompt Anomaly Detector - STABLE
        self._modules["adversarial_prompt_anomaly_detector"] = ModuleDocumentation(
            module_name="adversarial_prompt_anomaly_detector_2026_june",
            stability_level=StabilityLevel.STABLE,
            description="Detects anomalous patterns in adversarial prompts using statistical analysis and outlier detection algorithms.",
            primary_class="AdversarialPromptAnomalyDetector",
            key_methods=[
                "detect_anomaly(prompt: str) -> Dict",
                "calculate_anomaly_score(prompt: str) -> float",
                "extract_anomalous_features(prompt: str) -> List[str]",
                "build_benign_profile(normal_prompts: List[str]) -> None"
            ],
            usage_examples=[
                """detector = AdversarialPromptAnomalyDetector()
detector.build_benign_profile(normal_training_data)
result = detector.detect_anomaly(test_prompt)
if result['is_anomalous']:
    print(f"Anomaly score: {result['score']}")"""
            ],
            dependencies=["math", "collections", "statistics"]
        )
        
        # Adversarial Embedding Perturbation Detector - EXPERIMENTAL
        self._modules["adversarial_embedding_perturbation_detector"] = ModuleDocumentation(
            module_name="adversarial_embedding_perturbation_detector_2026_june",
            stability_level=StabilityLevel.EXPERIMENTAL,
            description="Experimental detector for embedding-space adversarial perturbations and imperceptible attacks.",
            primary_class="AdversarialEmbeddingPerturbationDetector",
            key_methods=[
                "detect_perturbation(embedding_vector: List[float]) -> Dict",
                "calculate_perturbation_magnitude(vector: List[float]) -> float",
                "is_statistically_significant(score: float) -> bool"
            ],
            usage_examples=[
                """detector = AdversarialEmbeddingPerturbationDetector()
result = detector.detect_perturbation(embedding)
if result['is_perturbed']:
    print("Potential adversarial embedding detected")"""
            ],
            dependencies=["numpy", "math", "statistics"],
            deprecation_notice=None,
            migration_guide="This module is experimental. API may change in future versions."
        )
    
    def _register_agent_security_modules(self):
        """Register agent security modules"""
        
        # Agent Tool Call Validator - STABLE
        self._modules["agent_tool_call_validator"] = ModuleDocumentation(
            module_name="agent_tool_call_validator_2026_june",
            stability_level=StabilityLevel.STABLE,
            description="Validates and sanitizes LLM agent tool calls to prevent privilege escalation, injection attacks, and unsafe operations.",
            primary_class="AgentToolCallValidator",
            key_methods=[
                "validate_tool_call(tool_name: str, params: Dict) -> Dict",
                "sanitize_parameters(params: Dict) -> Dict",
                "check_dangerous_operations(params: Dict) -> List[str]",
                "is_safe_tool_invocation(tool_call: Dict) -> bool"
            ],
            usage_examples=[
                """validator = AgentToolCallValidator()
validation = validator.validate_tool_call("execute_command", {"cmd": "rm -rf /"})
if not validation['is_safe']:
    print(f"Blocked: {validation['reason']}")""",
                """# Whitelist mode
validator.set_allowed_tools(["search", "calculate"])
validator.set_parameter_constraints("search", {"query": "str"})"""
            ],
            dependencies=["typing", "re", "urllib.parse"]
        )
        
        # Agent Memory Safety Guardian - STABLE
        self._modules["agent_memory_safety_guardian"] = ModuleDocumentation(
            module_name="agent_memory_safety_guardian_2026_june",
            stability_level=StabilityLevel.STABLE,
            description="Monitors and protects agent memory from poisoning attacks, data exfiltration, and memory corruption.",
            primary_class="AgentMemorySafetyGuardian",
            key_methods=[
                "scan_memory_entry(entry: Dict) -> Dict",
                "detect_poisoning_attempt(memory_text: str) -> Dict",
                "sanitize_memory_write(content: str) -> str",
                "validate_memory_read(context: str) -> bool"
            ],
            usage_examples=[
                """guardian = AgentMemorySafetyGuardian()
scan_result = guardian.scan_memory_entry(memory_item)
if scan_result['is_safe']:
    agent_memory.store(scan_result['sanitized'])"""
            ],
            dependencies=["typing", "hashlib", "json"]
        )
    
    def _register_cross_modal_modules(self):
        """Register cross-modal security modules"""
        
        # Cross-Modal Prompt Injection Detector - STABLE
        self._modules["cross_modal_prompt_injection_detector"] = ModuleDocumentation(
            module_name="cross_modal_prompt_injection_detector_2026_june",
            stability_level=StabilityLevel.STABLE,
            description="Detects prompt injection attacks across multiple modalities including text, images, and multi-modal inputs.",
            primary_class="CrossModalPromptInjectionDetector",
            key_methods=[
                "detect_injection_multimodal(text: str, image_data=None) -> Dict",
                "scan_image_for_hidden_prompts(image_ocr: str) -> Dict",
                "analyze_cross_modal_context(text: str, vision_context: str) -> Dict",
                "calculate_multimodal_risk_score(analysis: Dict) -> float"
            ],
            usage_examples=[
                """detector = CrossModalPromptInjectionDetector()
result = detector.detect_injection_multimodal(
    text="User query here",
    image_data=ocr_extracted_text
)
if result['injection_detected']:
    print(f"Modality: {result['attack_modality']}")"""
            ],
            dependencies=["typing", "re", "json"]
        )
    
    def _register_utility_modules(self):
        """Register utility and integration modules"""
        
        # Adaptive Threat Response Orchestrator - STABLE
        self._modules["adaptive_threat_response_orchestrator"] = ModuleDocumentation(
            module_name="adaptive_threat_response_orchestrator_2026_june",
            stability_level=StabilityLevel.STABLE,
            description="Orchestrates adaptive response actions based on detected threat severity, type, and context.",
            primary_class="AdaptiveThreatResponseOrchestrator",
            key_methods=[
                "orchestrate_response(threat_data: Dict) -> Dict",
                "select_response_strategy(severity: str, threat_type: str) -> str",
                "execute_response_action(action: str, context: Dict) -> bool",
                "escalate_threat(threat_data: Dict) -> None"
            ],
            usage_examples=[
                """orchestrator = AdaptiveThreatResponseOrchestrator()
response = orchestrator.orchestrate_response({
    'threat_type': 'jailbreak',
    'severity': 'high',
    'confidence': 0.95
})
print(f"Action: {response['recommended_action']}")"""
            ],
            dependencies=["typing", "enum", "datetime"]
        )
    
    def get_module_docs(self, module_name: str) -> Optional[ModuleDocumentation]:
        """
        Get documentation for a specific module
        
        Args:
            module_name: Name of the module (without version suffix)
            
        Returns:
            ModuleDocumentation object or None if not found
            
        STABILITY: STABLE
        """
        if not self._initialized:
            self.initialize()
        
        # Try exact match first
        if module_name in self._modules:
            return self._modules[module_name]
        
        # Try partial match
        for key in self._modules:
            if module_name.lower() in key.lower():
                return self._modules[key]
        
        return None
    
    def get_all_modules(self) -> List[str]:
        """
        Get list of all documented modules
        
        Returns:
            List of module names
            
        STABILITY: STABLE
        """
        if not self._initialized:
            self.initialize()
        return list(self._modules.keys())
    
    def get_modules_by_stability(self, level: StabilityLevel) -> List[ModuleDocumentation]:
        """
        Get all modules with specific stability level
        
        Args:
            level: StabilityLevel to filter by
            
        Returns:
            List of ModuleDocumentation objects
            
        STABILITY: STABLE
        """
        if not self._initialized:
            self.initialize()
        return [m for m in self._modules.values() if m.stability_level == level]
    
    def generate_catalog_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive catalog report
        
        Returns:
            Dictionary with catalog statistics and summary
            
        STABILITY: STABLE
        """
        if not self._initialized:
            self.initialize()
        
        stats = {
            "catalog_version": self._catalog_version,
            "generation_date": self._generation_date,
            "total_modules": len(self._modules),
            "stability_breakdown": {
                level.value: len(self.get_modules_by_stability(level))
                for level in StabilityLevel
            },
            "modules": [
                {
                    "name": name,
                    "stability": mod.stability_level.value,
                    "version": mod.version,
                    "primary_class": mod.primary_class
                }
                for name, mod in self._modules.items()
            ]
        }
        return stats
    
    def export_catalog_json(self, filepath: str) -> bool:
        """
        Export catalog to JSON file
        
        Args:
            filepath: Output file path
            
        Returns:
            True if successful
            
        STABILITY: STABLE
        """
        report = self.generate_catalog_report()
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        return True
    
    def get_quick_start_guide(self) -> str:
        """
        Get quick start guide for NeuralShield API
        
        Returns:
            Quick start guide text
            
        STABILITY: STABLE
        """
        return """
NEURALSHIELD AI - QUICK START GUIDE
====================================

1. BASIC USAGE:
   from neural_shield.advanced_jailbreak_detector_2026 import AdvancedJailbreakDetector
   
   detector = AdvancedJailbreakDetector()
   result = detector.detect_jailbreak(user_prompt)
   
2. RECOMMENDED MODULES FOR PRODUCTION:
   - AdvancedJailbreakDetector (STABLE)
   - AgentToolCallValidator (STABLE)
   - ConstitutionalClassifier (STABLE)
   - CrossModalPromptInjectionDetector (STABLE)

3. INTEGRATION PATTERN:
   Use AdaptiveThreatResponseOrchestrator to coordinate multiple detectors
   and implement consistent response policies.

4. STABILITY NOTES:
   - Only use STABLE modules in production
   - EXPERIMENTAL modules for testing only
   - Check deprecation notices before upgrading
"""


# Module export
__all__ = [
    'NeuralShieldAPIDocumentationCatalog',
    'ModuleDocumentation',
    'StabilityLevel',
]

# Auto-initialize for import-time access
_default_catalog = NeuralShieldAPIDocumentationCatalog()
_default_catalog.initialize()
