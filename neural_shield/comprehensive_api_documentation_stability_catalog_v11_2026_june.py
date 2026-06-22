"""
NeuralShield AI - Comprehensive API Documentation & Stability Catalog v11
=========================================================================
STABILITY LEVEL: STABLE
LAST UPDATED: 2026-06-23
MAINTAINER: NeuralShield Security Team

This module provides a centralized catalog of all public APIs with:
- Stability markers (STABLE/EXPERIMENTAL/DEPRECATED)
- Comprehensive docstrings
- Usage examples
- Version compatibility information
- Migration guides
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, TypeVar, Generic
from datetime import datetime
import json
import hashlib


class StabilityLevel(Enum):
    """API Stability Level classification.
    
    Attributes:
        STABLE: Production-ready, backward-compatible, no breaking changes
        EXPERIMENTAL: New feature, subject to change, not for production
        DEPRECATED: Scheduled for removal, migrate to alternatives
        LEGACY: Maintained for compatibility, no new features
    """
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    LEGACY = "LEGACY"


@dataclass
class APIEndpoint:
    """Metadata for a single API endpoint.
    
    Args:
        name: Human-readable API name
        function_path: Full module path to the function
        stability: Stability level classification
        version_added: Version when API was introduced
        version_deprecated: Version when deprecated (if applicable)
        description: Detailed API purpose and behavior
        parameters: List of parameter descriptions
        returns: Return value description
        exceptions: List of possible exceptions
        usage_example: Code example demonstrating usage
        see_also: Related APIs for cross-reference
        migration_guide: Migration instructions if deprecated
    """
    name: str
    function_path: str
    stability: StabilityLevel
    version_added: str
    description: str
    version_deprecated: Optional[str] = None
    parameters: List[Dict[str, str]] = field(default_factory=list)
    returns: str = "None"
    exceptions: List[str] = field(default_factory=list)
    usage_example: str = ""
    see_also: List[str] = field(default_factory=list)
    migration_guide: str = ""


class DocumentationCatalog:
    """Centralized API documentation and stability catalog.
    
    This class provides a single source of truth for all public APIs
    in the NeuralShield AI security platform. It enables:
    - Programmatic API discovery
    - Stability checking at runtime
    - Automated documentation generation
    - Compatibility validation
    
    Example:
        >>> catalog = DocumentationCatalog()
        >>> catalog.get_stability("prompt_injection_detector")
        StabilityLevel.STABLE
    """
    
    def __init__(self) -> None:
        """Initialize the documentation catalog with all registered APIs."""
        self._apis: Dict[str, APIEndpoint] = {}
        self._build_catalog()
        self._catalog_version: str = "11.0.0"
        self._generated_at: datetime = datetime.utcnow()
    
    def _build_catalog(self) -> None:
        """Populate the catalog with all API endpoints."""
        # ==================== STABLE APIs ====================
        
        self._register_api(APIEndpoint(
            name="Prompt Injection Detector",
            function_path="neural_shield.prompt_injection_detector.detect",
            stability=StabilityLevel.STABLE,
            version_added="1.0.0",
            description="Detects prompt injection attacks in user input using ensemble methods.",
            parameters=[
                {"name": "prompt", "type": "str", "description": "User input to analyze"},
                {"name": "threshold", "type": "float", "description": "Detection confidence threshold (0.0-1.0)"}
            ],
            returns="Dict with detection score, risk level, and matched patterns",
            exceptions=["ValueError if prompt is empty", "TypeError if threshold is invalid"],
            usage_example="""
            from neural_shield import prompt_injection_detector
            
            result = prompt_injection_detector.detect(
                prompt="Ignore previous instructions...",
                threshold=0.7
            )
            if result['risk_level'] == 'HIGH':
                print("Potential injection detected!")
            """,
            see_also=["adversarial_prompt_detector", "prompt_sanitizer"]
        ))
        
        self._register_api(APIEndpoint(
            name="Adversarial Prompt Anomaly Detector",
            function_path="neural_shield.adversarial_prompt_anomaly_detector.detect",
            stability=StabilityLevel.STABLE,
            version_added="2.1.0",
            description="Detects anomalous and adversarial prompt patterns using semantic analysis.",
            parameters=[
                {"name": "prompt", "type": "str", "description": "Input prompt to analyze"},
                {"name": "context", "type": "Optional[str]", "description": "Conversation context"}
            ],
            returns="Anomaly detection result with confidence score",
            usage_example="""
            detector = AdversarialPromptAnomalyDetector()
            result = detector.analyze(prompt, context=history)
            print(f"Anomaly score: {result['score']:.2f}")
            """,
            see_also=["prompt_injection_detector", "gradient_anomaly_detector"]
        ))
        
        self._register_api(APIEndpoint(
            name="LLM Output Hallucination Detector",
            function_path="neural_shield.llm_output_hallucination_detector.detect",
            stability=StabilityLevel.STABLE,
            version_added="3.0.0",
            description="Verifies factual accuracy and detects hallucinations in LLM outputs.",
            parameters=[
                {"name": "output", "type": "str", "description": "LLM generated text"},
                {"name": "source_context", "type": "str", "description": "Ground truth context"}
            ],
            returns="Factuality score with conflicting claims identified",
            see_also=["output_fact_checker", "toxicity_detector"]
        ))
        
        self._register_api(APIEndpoint(
            name="Output PII Redactor",
            function_path="neural_shield.output_sanitizer_pii_redactor.redact",
            stability=StabilityLevel.STABLE,
            version_added="2.5.0",
            description="Redacts personally identifiable information from text outputs.",
            parameters=[
                {"name": "text", "type": "str", "description": "Text to sanitize"},
                {"name": "entities", "type": "List[str]", "description": "Entity types to redact"}
            ],
            returns="Sanitized text with PII replaced by placeholders",
            usage_example="""
            sanitized = redact_pii(user_message, entities=['EMAIL', 'PHONE', 'SSN'])
            """,
            see_also=["output_integrity_watermarker"]
        ))
        
        # ==================== EXPERIMENTAL APIs ====================
        
        self._register_api(APIEndpoint(
            name="Multimodal VLM Prompt Injection Detector",
            function_path="neural_shield.multimodal_vlm_prompt_injection_detector.detect",
            stability=StabilityLevel.EXPERIMENTAL,
            version_added="4.2.0",
            description="Detects prompt injection in visual inputs (images with embedded text).",
            parameters=[
                {"name": "image_path", "type": "str", "description": "Path to image file"},
                {"name": "ocr_text", "type": "Optional[str]", "description": "Pre-extracted OCR text"}
            ],
            returns="Injection detection result for visual content",
            usage_example="""
            # EXPERIMENTAL: API may change
            result = detect_vlm_injection("suspicious_image.png")
            """,
            see_also=["multimodal_prompt_injection_detector"]
        ))
        
        self._register_api(APIEndpoint(
            name="Agent Tool Call Validator",
            function_path="neural_shield.agent_tool_call_validator.validate",
            stability=StabilityLevel.EXPERIMENTAL,
            version_added="5.0.0",
            description="Validates safety of LLM agent tool calls before execution.",
            parameters=[
                {"name": "tool_name", "type": "str", "description": "Tool being invoked"},
                {"name": "parameters", "type": "Dict", "description": "Tool parameters"},
                {"name": "context", "type": "str", "description": "Agent context"}
            ],
            returns="Validation decision with risk assessment",
            see_also=["agent_memory_safety_monitor"]
        ))
        
        # ==================== DEPRECATED APIs ====================
        
        self._register_api(APIEndpoint(
            name="Legacy Prompt Injection Detector v1",
            function_path="neural_shield.legacy.prompt_injection_v1.detect",
            stability=StabilityLevel.DEPRECATED,
            version_added="0.9.0",
            version_deprecated="2.0.0",
            description="Legacy regex-based injection detector (DEPRECATED).",
            migration_guide="""
            MIGRATION GUIDE:
            Replace:
                from neural_shield.legacy import prompt_injection_v1
                result = prompt_injection_v1.detect(prompt)
            
            With:
                from neural_shield import prompt_injection_detector
                result = prompt_injection_detector.detect(prompt, threshold=0.7)
            
            Benefits: 40% better detection, semantic analysis, ensemble voting.
            """
        ))
    
    def _register_api(self, api: APIEndpoint) -> None:
        """Register an API endpoint in the catalog.
        
        Args:
            api: APIEndpoint object to register
        """
        key = self._make_key(api.function_path)
        self._apis[key] = api
    
    @staticmethod
    def _make_key(function_path: str) -> str:
        """Create a normalized key from function path."""
        return function_path.lower().replace(".", "_")
    
    def get_stability(self, function_path: str) -> Optional[StabilityLevel]:
        """Get the stability level of an API.
        
        Args:
            function_path: Full function path to query
            
        Returns:
            StabilityLevel or None if not found
        """
        key = self._make_key(function_path)
        api = self._apis.get(key)
        return api.stability if api else None
    
    def get_api(self, function_path: str) -> Optional[APIEndpoint]:
        """Get full API metadata.
        
        Args:
            function_path: Full function path to query
            
        Returns:
            APIEndpoint or None if not found
        """
        key = self._make_key(function_path)
        return self._apis.get(key)
    
    def list_by_stability(self, stability: StabilityLevel) -> List[APIEndpoint]:
        """List all APIs with a given stability level.
        
        Args:
            stability: Stability level to filter by
            
        Returns:
            List of matching APIEndpoints
        """
        return [api for api in self._apis.values() if api.stability == stability]
    
    def generate_documentation(self, format: str = "json") -> str:
        """Generate machine-readable documentation.
        
        Args:
            format: Output format ('json' or 'markdown')
            
        Returns:
            Formatted documentation string
        """
        if format == "json":
            return json.dumps({
                "catalog_version": self._catalog_version,
                "generated_at": self._generated_at.isoformat(),
                "total_apis": len(self._apis),
                "apis": {
                    k: {
                        "name": v.name,
                        "stability": v.stability.value,
                        "version_added": v.version_added,
                        "description": v.description
                    }
                    for k, v in self._apis.items()
                }
            }, indent=2)
        return self._generate_markdown()
    
    def _generate_markdown(self) -> str:
        """Generate markdown documentation."""
        lines = [
            "# NeuralShield AI API Documentation",
            f"*Generated: {self._generated_at.isoformat()}*",
            f"*Catalog Version: {self._catalog_version}*",
            "",
            "## Stability Legend",
            "- 🟢 **STABLE**: Production-ready",
            "- 🟡 **EXPERIMENTAL**: Subject to change",
            "- 🔴 **DEPRECATED**: Scheduled for removal",
            ""
        ]
        
        for level in StabilityLevel:
            lines.append(f"## {level.value} APIs")
            for api in self.list_by_stability(level):
                lines.append(f"### {api.name}")
                lines.append(f"- **Path**: `{api.function_path}`")
                lines.append(f"- **Since**: v{api.version_added}")
                lines.append(f"- **Description**: {api.description}")
                if api.usage_example:
                    lines.append("**Example:**")
                    lines.append("```python")
                    lines.append(api.usage_example.strip())
                    lines.append("```")
                lines.append("")
        
        return "\n".join(lines)
    
    def validate_compatibility(self, client_version: str) -> Dict[str, Any]:
        """Validate client version compatibility.
        
        Args:
            client_version: Client version string
            
        Returns:
            Compatibility report with warnings and recommendations
        """
        deprecated_apis = self.list_by_stability(StabilityLevel.DEPRECATED)
        experimental_apis = self.list_by_stability(StabilityLevel.EXPERIMENTAL)
        
        return {
            "client_version": client_version,
            "catalog_version": self._catalog_version,
            "warnings": [
                f"Using DEPRECATED API: {api.name}" 
                for api in deprecated_apis
            ],
            "experimental_notice": [
                f"EXPERIMENTAL API: {api.name} - may change" 
                for api in experimental_apis
            ],
            "recommendation": "Update to use only STABLE APIs for production"
        }
    
    def get_catalog_hash(self) -> str:
        """Get a hash of the catalog contents for integrity checking.
        
        Returns:
            SHA256 hash of catalog contents
        """
        content = json.dumps({
            k: {
                "name": v.name,
                "function_path": v.function_path,
                "stability": v.stability.value,
                "version_added": v.version_added,
                "description": v.description
            }
            for k, v in self._apis.items()
        }, sort_keys=True).encode()
        return hashlib.sha256(content).hexdigest()


# Global catalog instance for easy access
_global_catalog: Optional[DocumentationCatalog] = None


def get_catalog() -> DocumentationCatalog:
    """Get the global documentation catalog instance.
    
    Returns:
        Singleton DocumentationCatalog instance
    """
    global _global_catalog
    if _global_catalog is None:
        _global_catalog = DocumentationCatalog()
    return _global_catalog


def check_api_stability(function_path: str) -> Optional[str]:
    """Quick helper to check API stability level.
    
    Args:
        function_path: Full function path to check
        
    Returns:
        Stability level string or None
    """
    catalog = get_catalog()
    stability = catalog.get_stability(function_path)
    return stability.value if stability else None


if __name__ == "__main__":
    catalog = get_catalog()
    print(f"Catalog loaded with {len(catalog._apis)} APIs")
    print(f"Stable APIs: {len(catalog.list_by_stability(StabilityLevel.STABLE))}")
    print(f"Experimental APIs: {len(catalog.list_by_stability(StabilityLevel.EXPERIMENTAL))}")
    print(f"Deprecated APIs: {len(catalog.list_by_stability(StabilityLevel.DEPRECATED))}")
    print(f"Catalog hash: {catalog.get_catalog_hash()}")
