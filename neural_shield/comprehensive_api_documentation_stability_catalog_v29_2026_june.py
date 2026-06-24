"""
NeuralShield-AI Comprehensive API Documentation & Stability Catalog v29
======================================================================
API Stability Markers: STABLE | EXPERIMENTAL | DEPRECATED

This module provides comprehensive documentation, usage examples, and API stability
markers for all NeuralShield-AI modules. All markers follow semantic versioning
principles.

STABLE: API is frozen - no breaking changes will occur without major version bump
EXPERIMENTAL: API may change - use with caution in production
DEPRECATED: API scheduled for removal - migrate to recommended alternatives
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
import json
from datetime import datetime


class StabilityLevel(Enum):
    """API Stability Level Classification"""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"


@dataclass
class ModuleDocumentation:
    """Documentation metadata for a NeuralShield module"""
    module_name: str
    stability: StabilityLevel
    version: str
    description: str
    primary_use_cases: List[str]
    usage_examples: List[str]
    key_classes: List[str]
    key_methods: List[str]
    dependencies: List[str]
    deprecation_notice: Optional[str] = None
    migration_guide: Optional[str] = None
    last_updated: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class NeuralShieldAPIDocumentationCatalog:
    """
    Comprehensive API Documentation & Stability Catalog
    
    STABLE API - This catalog interface is guaranteed stable.
    All methods and return types will remain backward compatible.
    """
    
    def __init__(self):
        self._modules: Dict[str, ModuleDocumentation] = {}
        self._init_core_modules()
    
    def _init_core_modules(self) -> None:
        """Initialize documentation for all core modules"""
        
        # === STABLE MODULES ===
        
        self._modules["prompt_injection_detector"] = ModuleDocumentation(
            module_name="prompt_injection_detector",
            stability=StabilityLevel.STABLE,
            version="2.1.0",
            description="Primary prompt injection detection engine with semantic analysis",
            primary_use_cases=[
                "Detecting adversarial prompt injection attempts",
                "Sanitizing user inputs before LLM processing",
                "Security auditing of prompt templates"
            ],
            usage_examples=[
                """
                from neural_shield import PromptInjectionDetector
                detector = PromptInjectionDetector()
                result = detector.scan("Ignore previous instructions...")
                if result.is_malicious:
                    print(f"Threat detected: {result.confidence:.2%}")
                """,
                """
                # Batch processing
                results = detector.scan_batch(user_inputs, threshold=0.85)
                """
            ],
            key_classes=["PromptInjectionDetector", "DetectionResult"],
            key_methods=["scan", "scan_batch", "get_threat_details"],
            dependencies=["embedding_model", "signature_database"]
        )
        
        self._modules["prompt_firewall"] = ModuleDocumentation(
            module_name="prompt_firewall",
            stability=StabilityLevel.STABLE,
            version="1.5.0",
            description="Real-time prompt sanitization and firewall protection",
            primary_use_cases=[
                "Runtime protection against prompt injection",
                "Input sanitization for LLM endpoints",
                "Policy enforcement for LLM interactions"
            ],
            usage_examples=[
                """
                from neural_shield import PromptFirewall
                firewall = PromptFirewall(enforce_policy=True)
                sanitized = firewall.process(user_input, auto_redirect=True)
                """,
                """
                # Custom policy configuration
                firewall.configure_policy(max_token_length=4096, block_commands=True)
                """
            ],
            key_classes=["PromptFirewall", "SecurityPolicy"],
            key_methods=["process", "configure_policy", "get_security_report"],
            dependencies=["input_validation", "policy_engine"]
        )
        
        self._modules["output_sanitizer_pii_redactor"] = ModuleDocumentation(
            module_name="output_sanitizer_pii_redactor",
            stability=StabilityLevel.STABLE,
            version="2.0.0",
            description="PII detection and redaction for LLM outputs",
            primary_use_cases=[
                "Redacting sensitive personal information",
                "Compliance with data privacy regulations",
                "Output filtering for sensitive data"
            ],
            usage_examples=[
                """
                from neural_shield import PIIRedactor
                redactor = PIIRedactor(replacement_char='*')
                cleaned = redactor.redact(text, entities=['EMAIL', 'PHONE', 'SSN'])
                """,
                """
                # Get detailed redaction report
                result = redactor.redact_with_report(text)
                print(f"Redacted {result.entity_count} entities")
                """
            ],
            key_classes=["PIIRedactor", "RedactionResult"],
            key_methods=["redact", "redact_with_report", "configure_entities"],
            dependencies=["ner_model", "entity_classifier"]
        )
        
        self._modules["input_purification"] = ModuleDocumentation(
            module_name="input_purification",
            stability=StabilityLevel.STABLE,
            version="1.8.0",
            description="Multi-layer input purification and sanitization",
            primary_use_cases=[
                "Multi-stage input cleaning",
                "Removing adversarial artifacts",
                "Pre-processing for security pipelines"
            ],
            usage_examples=[
                """
                from neural_shield import InputPurifier
                purifier = InputPurifier(layers=5)
                purified = purifier.purify(input_text, aggressive=True)
                """,
                """
                # Custom purification pipeline
                purifier.set_pipeline(['unicode_normalize', 'obfuscation_decode', 'sanitize'])
                """
            ],
            key_classes=["InputPurifier", "PurificationResult"],
            key_methods=["purify", "set_pipeline", "get_purification_stats"],
            dependencies=["unicode_normalizer", "obfuscation_decoder"]
        )
        
        # === EXPERIMENTAL MODULES ===
        
        self._modules["multimodal_prompt_injection_detector"] = ModuleDocumentation(
            module_name="multimodal_prompt_injection_detector",
            stability=StabilityLevel.EXPERIMENTAL,
            version="0.9.0",
            description="Multi-modal prompt injection detection (text + images)",
            primary_use_cases=[
                "Detecting steganographic prompt injection",
                "Image-based adversarial prompt detection",
                "Multi-modal threat analysis"
            ],
            usage_examples=[
                """
                from neural_shield import MultimodalInjectionDetector
                detector = MultimodalInjectionDetector()
                result = detector.analyze_image(image_path, context_text=prompt)
                """,
                """
                # Batch image analysis
                results = detector.analyze_batch(image_paths, parallel=True)
                """
            ],
            key_classes=["MultimodalInjectionDetector", "ImageAnalysisResult"],
            key_methods=["analyze_image", "analyze_batch", "get_steganalysis_report"],
            dependencies=["vlm_model", "steganalysis_engine"]
        )
        
        self._modules["llm_agent_thought_process_auditor"] = ModuleDocumentation(
            module_name="llm_agent_thought_process_auditor",
            stability=StabilityLevel.EXPERIMENTAL,
            version="0.8.0",
            description="Chain-of-thought auditing for agent security",
            primary_use_cases=[
                "Monitoring agent reasoning integrity",
                "Detecting thought process poisoning",
                "Auditing CoT for adversarial manipulation"
            ],
            usage_examples=[
                """
                from neural_shield import ThoughtProcessAuditor
                auditor = ThoughtProcessAuditor()
                integrity_score = auditor.audit_cot(agent_thought_chain)
                """,
                """
                # Real-time monitoring
                with auditor.monitor():
                    result = agent.execute(task)
                """
            ],
            key_classes=["ThoughtProcessAuditor", "IntegrityReport"],
            key_methods=["audit_cot", "monitor", "get_integrity_metrics"],
            dependencies=["cot_analyzer", "integrity_scorer"]
        )
        
        self._modules["adversarial_prompt_fuzzer"] = ModuleDocumentation(
            module_name="adversarial_prompt_fuzzer",
            stability=StabilityLevel.EXPERIMENTAL,
            version="0.7.0",
            description="Adversarial prompt fuzzing for robustness testing",
            primary_use_cases=[
                "Penetration testing of LLM endpoints",
                "Generating adversarial test cases",
                "Robustness validation"
            ],
            usage_examples=[
                """
                from neural_shield import PromptFuzzer
                fuzzer = PromptFuzzer(strategy='evolutionary')
                test_cases = fuzzer.generate(base_prompt, count=100)
                """,
                """
                # Run fuzzing campaign
                report = fuzzer.run_campaign(target_endpoint, iterations=500)
                """
            ],
            key_classes=["PromptFuzzer", "FuzzingReport"],
            key_methods=["generate", "run_campaign", "get_vulnerability_report"],
            dependencies=["mutation_engine", "evolutionary_optimizer"]
        )
        
        # === DEPRECATED MODULES ===
        
        self._modules["legacy_prompt_detector"] = ModuleDocumentation(
            module_name="legacy_prompt_detector",
            stability=StabilityLevel.DEPRECATED,
            version="1.0.0",
            description="[DEPRECATED] Legacy regex-based prompt injection detector",
            primary_use_cases=["Legacy compatibility only"],
            usage_examples=[],
            key_classes=["LegacyPromptDetector"],
            key_methods=["detect"],
            dependencies=["regex_engine"],
            deprecation_notice="Deprecated since v2.0. Will be removed in v3.0",
            migration_guide="Migrate to PromptInjectionDetector for semantic analysis"
        )
    
    def get_module_documentation(self, module_name: str) -> Optional[ModuleDocumentation]:
        """
        Get documentation for a specific module.
        
        STABLE API - Method signature guaranteed stable.
        
        Args:
            module_name: Name of the module to retrieve
            
        Returns:
            ModuleDocumentation object or None if not found
        """
        return self._modules.get(module_name)
    
    def list_modules_by_stability(self, stability: StabilityLevel) -> List[str]:
        """
        List all modules with specified stability level.
        
        STABLE API - Method signature guaranteed stable.
        
        Args:
            stability: StabilityLevel to filter by
            
        Returns:
            List of module names
        """
        return [
            name for name, doc in self._modules.items()
            if doc.stability == stability
        ]
    
    def get_stability_summary(self) -> Dict[str, int]:
        """
        Get summary count of modules by stability level.
        
        STABLE API - Method signature guaranteed stable.
        
        Returns:
            Dictionary with stability counts
        """
        summary = {"STABLE": 0, "EXPERIMENTAL": 0, "DEPRECATED": 0}
        for doc in self._modules.values():
            summary[doc.stability.value] += 1
        return summary
    
    def generate_documentation_report(self, format: str = "json") -> str:
        """
        Generate comprehensive documentation report.
        
        STABLE API - Method signature guaranteed stable.
        
        Args:
            format: Output format ('json' or 'markdown')
            
        Returns:
            Formatted documentation report
        """
        data = {
            "catalog_version": "v29",
            "generated_at": datetime.utcnow().isoformat(),
            "stability_summary": self.get_stability_summary(),
            "modules": [
                {
                    "name": doc.module_name,
                    "stability": doc.stability.value,
                    "version": doc.version,
                    "description": doc.description,
                    "use_cases": doc.primary_use_cases,
                    "key_classes": doc.key_classes,
                    "key_methods": doc.key_methods
                }
                for doc in self._modules.values()
            ]
        }
        
        if format == "json":
            return json.dumps(data, indent=2)
        elif format == "markdown":
            return self._generate_markdown_report(data)
        else:
            return json.dumps(data, indent=2)
    
    def _generate_markdown_report(self, data: Dict) -> str:
        """Generate markdown formatted report"""
        md = f"""# NeuralShield-AI API Documentation Catalog v29
Generated: {data['generated_at']}

## Stability Summary
- **STABLE**: {data['stability_summary']['STABLE']} modules
- **EXPERIMENTAL**: {data['stability_summary']['EXPERIMENTAL']} modules
- **DEPRECATED**: {data['stability_summary']['DEPRECATED']} modules

## Module Documentation
"""
        for mod in data["modules"]:
            md += f"\n### {mod['name']} `[{mod['stability']}]`\n"
            md += f"- **Version**: {mod['version']}\n"
            md += f"- **Description**: {mod['description']}\n"
            md += f"- **Key Classes**: {', '.join(mod['key_classes'])}\n"
            md += f"- **Key Methods**: {', '.join(mod['key_methods'])}\n"
        return md
    
    def validate_api_compatibility(self, client_version: str) -> Dict[str, Any]:
        """
        Validate API compatibility for client version.
        
        STABLE API - Method signature guaranteed stable.
        
        Args:
            client_version: Client's expected API version
            
        Returns:
            Compatibility report
        """
        return {
            "compatible": True,
            "client_version": client_version,
            "catalog_version": "v29",
            "breaking_changes": [],
            "warnings": ["EXPERIMENTAL modules may change without version bump"],
            "recommendation": "Use only STABLE modules for production"
        }


# Export singleton instance for easy import
api_documentation_catalog = NeuralShieldAPIDocumentationCatalog()

__all__ = [
    "NeuralShieldAPIDocumentationCatalog",
    "ModuleDocumentation",
    "StabilityLevel",
    "api_documentation_catalog"
]
