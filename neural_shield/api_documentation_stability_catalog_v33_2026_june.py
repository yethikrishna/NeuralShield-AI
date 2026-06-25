"""
NeuralShield AI - API Documentation & Stability Catalog v33
======================================================================
STABILITY MARKERS:
    @STABLE - Production-ready, backward-compatible, no breaking changes
    @EXPERIMENTAL - Under active development, API may change
    @DEPRECATED - Scheduled for removal, migrate to alternatives
    @INTERNAL - Not for public consumption, implementation detail

This module provides comprehensive API documentation, stability markers,
and usage examples for all NeuralShield AI security modules.

All documentation is ADD-ONLY - no production code logic is modified.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
import functools


class StabilityLevel(Enum):
    """API Stability Classification"""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    INTERNAL = "INTERNAL"


@dataclass
class APIDocumentation:
    """Comprehensive API Documentation Entry"""
    module_name: str
    function_name: str
    stability: StabilityLevel
    signature: str
    description: str
    parameters: List[Dict[str, str]] = field(default_factory=list)
    returns: str = ""
    raises: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    deprecation_notice: Optional[str] = None
    migration_guide: Optional[str] = None
    since_version: str = "1.0.0"
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ModuleDocumentation:
    """Module-level Documentation"""
    module_name: str
    description: str
    category: str
    stability: StabilityLevel
    api_entries: List[APIDocumentation] = field(default_factory=list)
    module_examples: List[str] = field(default_factory=list)
    maintainer: str = "NeuralShield AI Security Team"


class DocumentationCatalog:
    """Centralized API Documentation Catalog"""
    
    def __init__(self):
        self._modules: Dict[str, ModuleDocumentation] = {}
        self._stability_counts: Dict[StabilityLevel, int] = {
            StabilityLevel.STABLE: 0,
            StabilityLevel.EXPERIMENTAL: 0,
            StabilityLevel.DEPRECATED: 0,
            StabilityLevel.INTERNAL: 0
        }
    
    def register_module(self, module_doc: ModuleDocumentation) -> None:
        """Register a module's documentation"""
        self._modules[module_doc.module_name] = module_doc
        for api in module_doc.api_entries:
            self._stability_counts[api.stability] += 1
    
    def get_stable_apis(self) -> List[APIDocumentation]:
        """Get all STABLE APIs"""
        results = []
        for mod in self._modules.values():
            results.extend([api for api in mod.api_entries if api.stability == StabilityLevel.STABLE])
        return results
    
    def get_experimental_apis(self) -> List[APIDocumentation]:
        """Get all EXPERIMENTAL APIs"""
        results = []
        for mod in self._modules.values():
            results.extend([api for api in mod.api_entries if api.stability == StabilityLevel.EXPERIMENTAL])
        return results
    
    def get_deprecated_apis(self) -> List[APIDocumentation]:
        """Get all DEPRECATED APIs with migration guides"""
        results = []
        for mod in self._modules.values():
            results.extend([api for api in mod.api_entries if api.stability == StabilityLevel.DEPRECATED])
        return results
    
    def get_stability_summary(self) -> Dict[str, int]:
        """Get summary of API stability levels"""
        return {
            level.value: count for level, count in self._stability_counts.items()
        }
    
    def generate_readme_section(self) -> str:
        """Generate README documentation section"""
        summary = self.get_stability_summary()
        return f"""
## NeuralShield AI API Stability Summary

| Stability Level | Count | Description |
|-----------------|-------|-------------|
| **STABLE**      | {summary['STABLE']} | Production-ready, guaranteed backward-compatible |
| **EXPERIMENTAL**| {summary['EXPERIMENTAL']} | Under active development, API subject to change |
| **DEPRECATED**  | {summary['DEPRECATED']} | Scheduled for removal, see migration guides |
| **INTERNAL**    | {summary['INTERNAL']} | Implementation details, not for public use |

### Usage Guidelines
- Prefer **STABLE** APIs for production code
- **EXPERIMENTAL** APIs are for testing and feedback only
- Migrate away from **DEPRECATED** APIs before next major version
- Do not depend on **INTERNAL** APIs directly
"""


def stable_api(since: str = "1.0.0") -> Callable:
    """
    Decorator to mark API as STABLE
    
    Args:
        since: Version when this API became stable
    
    Example:
        @stable_api(since="2.1.0")
        def detect_threat(input_data):
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        wrapper._api_stability = StabilityLevel.STABLE
        wrapper._api_since = since
        wrapper._api_deprecated = False
        return wrapper
    return decorator


def experimental_api() -> Callable:
    """
    Decorator to mark API as EXPERIMENTAL
    
    APIs marked experimental may change or be removed without notice.
    Suitable for early adopters and testing only.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        wrapper._api_stability = StabilityLevel.EXPERIMENTAL
        wrapper._api_deprecated = False
        return wrapper
    return decorator


def deprecated_api(removal_version: str, migration_guide: str) -> Callable:
    """
    Decorator to mark API as DEPRECATED
    
    Args:
        removal_version: Version when this API will be removed
        migration_guide: Instructions for migrating to alternative API
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            import warnings
            warnings.warn(
                f"API {func.__name__} is deprecated and will be removed in {removal_version}. "
                f"Migration guide: {migration_guide}",
                DeprecationWarning,
                stacklevel=2
            )
            return func(*args, **kwargs)
        wrapper._api_stability = StabilityLevel.DEPRECATED
        wrapper._api_removal_version = removal_version
        wrapper._api_migration_guide = migration_guide
        wrapper._api_deprecated = True
        return wrapper
    return decorator


def internal_api() -> Callable:
    """
    Decorator to mark API as INTERNAL
    
    Internal APIs are implementation details and should not be
    called directly by external code. No stability guarantees.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        wrapper._api_stability = StabilityLevel.INTERNAL
        wrapper._api_deprecated = False
        return wrapper
    return decorator


# ============================================================
# PRE-REGISTERED MODULE DOCUMENTATION
# ============================================================

def build_complete_documentation_catalog() -> DocumentationCatalog:
    """Build the complete documentation catalog for NeuralShield AI"""
    catalog = DocumentationCatalog()
    
    # ========================================
    # Threat Detection Module
    # ========================================
    threat_detection_doc = ModuleDocumentation(
        module_name="threat_detection",
        description="Core threat detection and anomaly identification modules",
        category="Security Detection",
        stability=StabilityLevel.STABLE,
        module_examples=[
            """
            from neural_shield import threat_detection
            
            # Basic threat scan
            result = threat_detection.scan_prompt("user input here")
            if result.is_threat:
                print(f"Threat detected: {result.risk_level}")
            """,
            """
            # Batch processing
            results = threat_detection.batch_scan([prompt1, prompt2, prompt3])
            threats = [r for r in results if r.is_threat]
            """
        ]
    )
    
    threat_detection_doc.api_entries.extend([
        APIDocumentation(
            module_name="threat_detection",
            function_name="scan_prompt",
            stability=StabilityLevel.STABLE,
            signature="scan_prompt(prompt: str, context: Optional[Dict] = None) -> ThreatDetectionResult",
            description="Scan a single prompt for security threats and anomalies",
            parameters=[
                {"name": "prompt", "type": "str", "description": "User input to analyze"},
                {"name": "context", "type": "Optional[Dict]", "description": "Additional context for analysis"}
            ],
            returns="ThreatDetectionResult containing risk assessment and threat classifications",
            raises=["ValueError if prompt is empty", "TypeError for invalid input types"],
            examples=[
                "result = scan_prompt('Hello, how are you?')",
                "result = scan_prompt(user_input, context={'user_role': 'admin'})"
            ],
            since_version="1.0.0"
        ),
        APIDocumentation(
            module_name="threat_detection",
            function_name="batch_scan",
            stability=StabilityLevel.STABLE,
            signature="batch_scan(prompts: List[str], timeout: float = 30.0) -> List[ThreatDetectionResult]",
            description="Scan multiple prompts in batch with timeout protection",
            parameters=[
                {"name": "prompts", "type": "List[str]", "description": "List of prompts to analyze"},
                {"name": "timeout", "type": "float", "description": "Maximum processing time in seconds"}
            ],
            returns="List of detection results, one per input prompt",
            examples=[
                "results = batch_scan([p1, p2, p3], timeout=60.0)"
            ],
            since_version="1.2.0"
        ),
        APIDocumentation(
            module_name="threat_detection",
            function_name="detect_adversarial_perturbations",
            stability=StabilityLevel.EXPERIMENTAL,
            signature="detect_adversarial_perturbations(embedding: Tensor) -> AnomalyScore",
            description="EXPERIMENTAL: Detect subtle adversarial perturbations in embeddings",
            parameters=[
                {"name": "embedding", "type": "Tensor", "description": "Model embedding vector to analyze"}
            ],
            returns="AnomalyScore with confidence metrics",
            examples=[
                "score = detect_adversarial_perturbations(model_embedding)"
            ],
            since_version="2.3.0"
        )
    ])
    
    catalog.register_module(threat_detection_doc)
    
    # ========================================
    # Input Validation Module
    # ========================================
    validation_doc = ModuleDocumentation(
        module_name="input_validation",
        description="Secure input validation and sanitization modules",
        category="Security Hardening",
        stability=StabilityLevel.STABLE
    )
    
    validation_doc.api_entries.extend([
        APIDocumentation(
            module_name="input_validation",
            function_name="validate_and_sanitize",
            stability=StabilityLevel.STABLE,
            signature="validate_and_sanitize(input_str: str, max_length: int = 4096) -> SanitizedInput",
            description="Validate input length, encoding, and sanitize potentially dangerous content",
            parameters=[
                {"name": "input_str", "type": "str", "description": "Raw input string"},
                {"name": "max_length", "type": "int", "description": "Maximum allowed character count"}
            ],
            returns="SanitizedInput object with validation flags",
            raises=["InputTooLongError", "InvalidEncodingError"],
            examples=[
                "clean = validate_and_sanitize(user_input, max_length=2048)"
            ],
            since_version="1.0.0"
        ),
        APIDocumentation(
            module_name="input_validation",
            function_name="constant_time_compare",
            stability=StabilityLevel.STABLE,
            signature="constant_time_compare(a: str, b: str) -> bool",
            description="Timing-attack resistant string comparison",
            parameters=[
                {"name": "a", "type": "str", "description": "First string"},
                {"name": "b", "type": "str", "description": "Second string"}
            ],
            returns="True if strings match, False otherwise",
            examples=[
                "if constant_time_compare(user_token, expected_token): authorize()"
            ],
            since_version="1.1.0"
        )
    ])
    
    catalog.register_module(validation_doc)
    
    # ========================================
    # Error Resilience Module
    # ========================================
    resilience_doc = ModuleDocumentation(
        module_name="error_resilience",
        description="Error handling, retries, and graceful degradation",
        category="Reliability",
        stability=StabilityLevel.STABLE
    )
    
    resilience_doc.api_entries.extend([
        APIDocumentation(
            module_name="error_resilience",
            function_name="with_retry",
            stability=StabilityLevel.STABLE,
            signature="with_retry(max_attempts: int = 3, backoff_factor: float = 1.5)",
            description="Decorator for automatic retry with exponential backoff",
            parameters=[
                {"name": "max_attempts", "type": "int", "description": "Maximum retry attempts"},
                {"name": "backoff_factor", "type": "float", "description": "Exponential backoff multiplier"}
            ],
            returns="Decorated function with retry logic",
            examples=[
                "@with_retry(max_attempts=5)\ndef call_external_api(): pass"
            ],
            since_version="1.3.0"
        ),
        APIDocumentation(
            module_name="error_resilience",
            function_name="with_deadline",
            stability=StabilityLevel.STABLE,
            signature="with_deadline(timeout_seconds: float)",
            description="Decorator to enforce execution deadline",
            parameters=[
                {"name": "timeout_seconds", "type": "float", "description": "Maximum execution time"}
            ],
            returns="Decorated function with timeout enforcement",
            examples=[
                "@with_deadline(5.0)\ndef time_sensitive_operation(): pass"
            ],
            since_version="1.4.0"
        )
    ])
    
    catalog.register_module(resilience_doc)
    
    return catalog


# Global documentation catalog instance
DOCUMENTATION_CATALOG = build_complete_documentation_catalog()


def get_api_stability_summary() -> Dict[str, Any]:
    """
    Get API stability summary for reporting and monitoring
    
    @STABLE API - Production ready
    """
    return {
        "catalog_version": "v33",
        "generated_at": datetime.now().isoformat(),
        "stability_summary": DOCUMENTATION_CATALOG.get_stability_summary(),
        "total_modules_documented": len(DOCUMENTATION_CATALOG._modules),
        "total_apis_documented": sum(DOCUMENTATION_CATALOG._stability_counts.values())
    }


if __name__ == "__main__":
    summary = get_api_stability_summary()
    print("=== NeuralShield AI API Documentation Catalog v33 ===")
    print(f"Generated: {summary['generated_at']}")
    print(f"Total Modules: {summary['total_modules_documented']}")
    print(f"Total APIs: {summary['total_apis_documented']}")
    print("\nStability Summary:")
    for level, count in summary['stability_summary'].items():
        print(f"  {level}: {count} APIs")
    print("\n" + DOCUMENTATION_CATALOG.generate_readme_section())
