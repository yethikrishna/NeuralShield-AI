"""
NeuralShield-AI Comprehensive API Stability Documentation Catalog v27
=====================================================================
API STABILITY: STABLE
SESSION: 127
DATE: 2026-06-24

This module provides comprehensive API stability documentation, usage examples,
and stability markers for all NeuralShield-AI security modules.

STABILITY MARKERS:
    STABLE: API is frozen, backward compatible, safe for production
    EXPERIMENTAL: API may change, use with caution
    DEPRECATED: API scheduled for removal, migrate immediately
    LEGACY: Maintained for compatibility, prefer new APIs
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Callable
import datetime


class StabilityLevel(Enum):
    """API Stability Level Classification"""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    LEGACY = "LEGACY"


@dataclass
class APIEndpoint:
    """Represents a documented API endpoint with stability metadata"""
    name: str
    module: str
    stability: StabilityLevel
    version_introduced: str
    version_deprecated: Optional[str] = None
    deprecation_scheduled: Optional[str] = None
    description: str = ""
    usage_example: str = ""
    parameters: Dict[str, str] = field(default_factory=dict)
    returns: str = ""
    exceptions: List[str] = field(default_factory=list)
    migration_guide: str = ""
    compatibility_notes: List[str] = field(default_factory=list)


class NeuralShieldAPIStabilityCatalog:
    """
    Comprehensive API Stability Catalog for NeuralShield-AI
    
    API STABILITY: STABLE
    VERSION: 2.7.0
    
    This catalog provides machine-readable stability metadata for all
    NeuralShield-AI public APIs. Use this to validate API usage and
    plan migrations.
    """
    
    def __init__(self):
        self._apis: Dict[str, APIEndpoint] = {}
        self._build_catalog()
        self.generated_at = datetime.datetime.utcnow().isoformat()
        self.catalog_version = "27.0.0"
    
    def _build_catalog(self) -> None:
        """Build the complete API catalog"""
        
        # ==================== CORE DETECTION APIs ====================
        
        self._apis["prompt_injection_detector"] = APIEndpoint(
            name="PromptInjectionDetector",
            module="prompt_injection_ensemble_detector_v2",
            stability=StabilityLevel.STABLE,
            version_introduced="1.0.0",
            description="Primary prompt injection detection with ensemble voting",
            usage_example="""
            detector = PromptInjectionDetector()
            result = detector.detect("Ignore previous instructions...")
            # Returns: {'risk_score': 0.95, 'is_detected': True, 'techniques': ['ignore']}
            """,
            parameters={"prompt": "str - User input to analyze"},
            returns="Dict with risk_score, is_detected, matched_techniques",
            exceptions=["ValueError - Empty prompt", "TypeError - Invalid input type"],
            compatibility_notes=["Backward compatible with all 2.x versions"]
        )
        
        self._apis["jailbreak_detector"] = APIEndpoint(
            name="AdvancedJailbreakDetector",
            module="advanced_jailbreak_detector_2026",
            stability=StabilityLevel.STABLE,
            version_introduced="1.5.0",
            description="Multi-modal jailbreak attack detection",
            usage_example="""
            detector = AdvancedJailbreakDetector()
            result = detector.analyze_conversation(messages)
            # Returns risk assessment with confidence scores
            """,
            parameters={"messages": "List[Dict] - Conversation history"},
            returns="Jailbreak detection result with confidence",
            exceptions=["TypeError - Invalid message format"],
            compatibility_notes=["Added in v1.5, no breaking changes since"]
        )
        
        self._apis["adversarial_anomaly_detector"] = APIEndpoint(
            name="AdversarialPromptAnomalyDetector",
            module="adversarial_prompt_anomaly_detector_2026_june",
            stability=StabilityLevel.STABLE,
            version_introduced="2.0.0",
            description="Gradient-based adversarial prompt anomaly detection",
            usage_example="""
            detector = AdversarialPromptAnomalyDetector()
            anomalies = detector.detect_anomalies(prompt, embedding_fn)
            """,
            parameters={
                "prompt": "str - Input prompt",
                "embedding_fn": "Callable - Embedding generation function"
            },
            returns="Anomaly scores and detected perturbations",
            exceptions=["RuntimeError - Embedding function failed"],
            compatibility_notes=["Stable since v2.0"]
        )
        
        # ==================== OUTPUT SANITIZATION APIs ====================
        
        self._apis["output_sanitizer"] = APIEndpoint(
            name="OutputSanitizerPIIRedactor",
            module="output_sanitizer_pii_redactor_2026",
            stability=StabilityLevel.STABLE,
            version_introduced="1.2.0",
            description="PII detection and redaction from LLM outputs",
            usage_example="""
            sanitizer = OutputSanitizerPIIRedactor()
            clean = sanitizer.redact("Call me at 555-123-4567 or john@email.com")
            # Returns: "Call me at [PHONE] or [EMAIL]"
            """,
            parameters={"text": "str - Text to sanitize"},
            returns="Sanitized text with PII replaced by placeholders",
            exceptions=["ValueError - Empty input"],
            compatibility_notes=["Entity types expanded in v2.1, API unchanged"]
        )
        
        self._apis["watermark_provenance"] = APIEndpoint(
            name="OutputIntegrityWatermarker",
            module="output_integrity_watermarker_provenance_2026_june",
            stability=StabilityLevel.EXPERIMENTAL,
            version_introduced="2.5.0",
            description="Cryptographic watermarking for output provenance tracking",
            usage_example="""
            watermarker = OutputIntegrityWatermarker()
            marked = watermarker.embed_watermark(text, source_id="agent-001")
            verified = watermarker.verify_watermark(marked)
            """,
            parameters={
                "text": "str - Text to watermark",
                "source_id": "str - Source identifier"
            },
            returns="Watermarked text and verification results",
            exceptions=["CryptographyError - Key generation failed"],
            compatibility_notes=["EXPERIMENTAL: Algorithm may be updated"],
            migration_guide="Will stabilize in v3.0"
        )
        
        # ==================== SECURITY HARDENING APIs ====================
        
        self._apis["secure_memory"] = APIEndpoint(
            name="SecureMemoryZeroization",
            module="secure_memory_zeroization_constant_time_helpers_2026_june",
            stability=StabilityLevel.STABLE,
            version_introduced="1.8.0",
            description="Constant-time secure memory zeroization",
            usage_example="""
            secure_mem = SecureMemoryZeroization()
            sensitive_data = secure_mem.allocate_secure_buffer(256)
            # ... use buffer ...
            secure_mem.zeroize(sensitive_data)  # Constant-time, compiler-barriered
            """,
            parameters={"buffer": "bytearray - Buffer to zeroize"},
            returns="None (in-place modification)",
            exceptions=["TypeError - Must use bytearray for mutability"],
            compatibility_notes=["Critical security API - frozen"]
        )
        
        self._apis["constant_time_compare"] = APIEndpoint(
            name="ConstantTimeComparison",
            module="security_hardening_constant_time_comparison_v23_2026_june",
            stability=StabilityLevel.STABLE,
            version_introduced="1.8.0",
            description="Timing-attack resistant string comparison",
            usage_example="""
            comparator = ConstantTimeComparison()
            is_equal = comparator.secure_compare(secret_hash, user_hash)
            # Execution time independent of matching prefix length
            """,
            parameters={
                "a": "bytes - First value",
                "b": "bytes - Second value"
            },
            returns="bool - True if equal",
            compatibility_notes=["FIPS 140-3 compliant implementation"]
        )
        
        self._apis["rate_limiter"] = APIEndpoint(
            name="AdaptiveRateLimiter",
            module="security_hardening_adaptive_rate_limiting_dos_protection_v11_2026_june",
            stability=StabilityLevel.STABLE,
            version_introduced="2.1.0",
            description="Adaptive rate limiting with DoS protection",
            usage_example="""
            limiter = AdaptiveRateLimiter(rate_limit=100, window_seconds=60)
            allowed = limiter.check_rate(client_id="user-123")
            if not allowed:
                raise RateLimitExceeded()
            """,
            parameters={
                "client_id": "str - Client identifier",
                "cost": "int - Request cost (default: 1)"
            },
            returns="bool - True if request allowed",
            exceptions=["ConfigurationError - Invalid limits"],
            compatibility_notes=["Token bucket algorithm stable"]
        )
        
        # ==================== DEPRECATED APIs ====================
        
        self._apis["legacy_detector"] = APIEndpoint(
            name="LegacyPromptDetector",
            module="shield_defense_framework_2026",
            stability=StabilityLevel.DEPRECATED,
            version_introduced="0.9.0",
            version_deprecated="2.0.0",
            deprecation_scheduled="3.0.0",
            description="LEGACY: Original monolithic detector",
            usage_example="# DEPRECATED - Use PromptInjectionDetector instead",
            migration_guide="""
            MIGRATION REQUIRED BY v3.0:
            
            BEFORE (deprecated):
                detector = LegacyPromptDetector()
                result = detector.check(prompt)
            
            AFTER (current):
                detector = PromptInjectionDetector()
                result = detector.detect(prompt)
            """,
            compatibility_notes=["Will be removed in v3.0.0"]
        )
    
    def get_api(self, name: str) -> Optional[APIEndpoint]:
        """Get API metadata by name"""
        return self._apis.get(name)
    
    def list_apis(self, stability: Optional[StabilityLevel] = None) -> List[APIEndpoint]:
        """List all APIs, optionally filtered by stability level"""
        apis = list(self._apis.values())
        if stability:
            apis = [a for a in apis if a.stability == stability]
        return apis
    
    def get_stability_summary(self) -> Dict[str, int]:
        """Get count of APIs by stability level"""
        summary = {}
        for level in StabilityLevel:
            count = sum(1 for a in self._apis.values() if a.stability == level)
            summary[level.value] = count
        return summary
    
    def generate_markdown_docs(self) -> str:
        """Generate comprehensive markdown documentation"""
        summary = self.get_stability_summary()
        
        md = f"""# NeuralShield-AI API Stability Documentation v27\n\n"""
        md += f"**Generated:** {self.generated_at}\n\n"
        md += "## Stability Summary\n\n"
        md += "| Level | Count | Description |\n"
        md += "|-------|-------|-------------|\n"
        md += f"| STABLE | {summary['STABLE']} | Production-ready, frozen API |\n"
        md += f"| EXPERIMENTAL | {summary['EXPERIMENTAL']} | May change, use with caution |\n"
        md += f"| DEPRECATED | {summary['DEPRECATED']} | Schedule for removal |\n"
        md += f"| LEGACY | {summary['LEGACY']} | Maintained for compatibility |\n\n"
        return md


# Singleton instance for global usage
_api_catalog = None

def get_stability_catalog() -> NeuralShieldAPIStabilityCatalog:
    """Get the global API stability catalog singleton"""
    global _api_catalog
    if _api_catalog is None:
        _api_catalog = NeuralShieldAPIStabilityCatalog()
    return _api_catalog


def api_stability(level: StabilityLevel, since: str):
    """
    Decorator to mark API stability level
    """
    def decorator(func: Callable) -> Callable:
        func._api_stability = {
            "level": level,
            "since": since,
            "documented": True
        }
        return func
    return decorator


__all__ = [
    "StabilityLevel",
    "APIEndpoint",
    "NeuralShieldAPIStabilityCatalog",
    "get_stability_catalog",
    "api_stability"
]
