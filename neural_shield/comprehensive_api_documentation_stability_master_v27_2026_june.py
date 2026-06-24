"""
NeuralShield-AI Comprehensive API Documentation & Stability Catalog v27
=======================================================================
DIMENSION F: Documentation & API Stability

API STABILITY MARKERS:
- @stable: Production-ready, backward compatible, no breaking changes planned
- @experimental: Under active development, API may change
- @deprecated: Scheduled for removal, use alternative APIs

This module provides:
1. Comprehensive docstring catalog for all public APIs
2. API stability level markers
3. Usage examples and best practices
4. Migration guides for deprecated APIs
5. No production code logic changes - documentation ONLY
"""

import enum
import typing
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type, Union


class StabilityLevel(enum.Enum):
    """API stability level classification."""
    STABLE = "stable"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"
    INTERNAL = "internal"


@dataclass
class APIDocumentation:
    """Documentation metadata for a single API endpoint."""
    module_name: str
    function_name: str
    stability: StabilityLevel
    signature: str
    docstring: str
    examples: List[str] = field(default_factory=list)
    deprecation_notice: Optional[str] = None
    migration_guide: Optional[str] = None
    last_updated: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    version_introduced: str = "1.0.0"


@dataclass
class ModuleDocumentation:
    """Complete documentation for an entire module."""
    module_name: str
    description: str
    apis: List[APIDocumentation] = field(default_factory=list)
    usage_examples: List[str] = field(default_factory=list)
    best_practices: List[str] = field(default_factory=list)


class NeuralShieldDocumentationCatalog:
    """
    Comprehensive API documentation and stability catalog for NeuralShield-AI.
    
    @stable: Production-ready, fully tested, backward compatible
    """
    
    def __init__(self) -> None:
        """Initialize the documentation catalog."""
        self._modules: Dict[str, ModuleDocumentation] = {}
        self._stability_counts: Dict[StabilityLevel, int] = {
            StabilityLevel.STABLE: 0,
            StabilityLevel.EXPERIMENTAL: 0,
            StabilityLevel.DEPRECATED: 0,
            StabilityLevel.INTERNAL: 0,
        }
        self._build_catalog()
    
    def _build_catalog(self) -> None:
        """Build the complete documentation catalog."""
        # Core Threat Detection Modules
        self._add_adversarial_prompt_detection()
        self._add_jailbreak_detection()
        self._add_agent_security_modules()
        self._add_security_hardening()
        self._add_error_resilience()
        self._add_observability_modules()
    
    def _add_adversarial_prompt_detection(self) -> None:
        """Add adversarial prompt detection module documentation."""
        module = ModuleDocumentation(
            module_name="adversarial_prompt_anomaly_detector",
            description="Detects anomalous and potentially malicious prompt patterns using statistical analysis.",
            best_practices=[
                "Always initialize with default thresholds for production use",
                "Combine with ensemble voting for higher confidence",
                "Calibrate false positive rates for your specific use case",
                "Log all detections for audit trail purposes"
            ],
            usage_examples=[
                """
                detector = AdversarialPromptAnomalyDetector()
                result = detector.analyze("User prompt here")
                if result.is_malicious:
                    log_threat(result.threat_score)
                """
            ]
        )
        
        module.apis.extend([
            APIDocumentation(
                module_name="adversarial_prompt_anomaly_detector",
                function_name="AdversarialPromptAnomalyDetector.__init__",
                stability=StabilityLevel.STABLE,
                signature="__init__(self, threshold: float = 0.7, enable_logging: bool = True)",
                docstring="Initialize the anomaly detector with configurable sensitivity threshold.",
                examples=["detector = AdversarialPromptAnomalyDetector(threshold=0.8)"],
                version_introduced="1.0.0"
            ),
            APIDocumentation(
                module_name="adversarial_prompt_anomaly_detector",
                function_name="AdversarialPromptAnomalyDetector.analyze",
                stability=StabilityLevel.STABLE,
                signature="analyze(self, prompt: str) -> DetectionResult",
                docstring="Analyze a prompt for adversarial patterns and anomalies.",
                examples=["result = detector.analyze(prompt_text)"],
                version_introduced="1.0.0"
            ),
            APIDocumentation(
                module_name="adversarial_prompt_anomaly_detector",
                function_name="AdversarialPromptAnomalyDetector.get_statistics",
                stability=StabilityLevel.STABLE,
                signature="get_statistics(self) -> Dict[str, Any]",
                docstring="Get detection statistics and performance metrics.",
                examples=["stats = detector.get_statistics()"],
                version_introduced="1.2.0"
            )
        ])
        
        self._modules[module.module_name] = module
        self._update_counts(module)
    
    def _add_jailbreak_detection(self) -> None:
        """Add jailbreak detection module documentation."""
        module = ModuleDocumentation(
            module_name="advanced_jailbreak_detector",
            description="Advanced detection of prompt injection and jailbreak attempts using multi-layered analysis.",
            best_practices=[
                "Use in conjunction with input sanitization",
                "Enable heuristic checks for high-risk inputs",
                "Monitor for emerging jailbreak patterns",
                "Regularly update pattern databases"
            ],
            usage_examples=[
                """
                detector = AdvancedJailbreakDetector()
                result = detector.detect(prompt)
                if result.risk_level == "HIGH":
                    reject_input()
                """
            ]
        )
        
        module.apis.extend([
            APIDocumentation(
                module_name="advanced_jailbreak_detector",
                function_name="AdvancedJailbreakDetector.__init__",
                stability=StabilityLevel.STABLE,
                signature="__init__(self, strict_mode: bool = False)",
                docstring="Initialize jailbreak detector with optional strict mode.",
                examples=["detector = AdvancedJailbreakDetector(strict_mode=True)"],
                version_introduced="1.0.0"
            ),
            APIDocumentation(
                module_name="advanced_jailbreak_detector",
                function_name="AdvancedJailbreakDetector.detect",
                stability=StabilityLevel.STABLE,
                signature="detect(self, prompt: str) -> JailbreakResult",
                docstring="Detect potential jailbreak attempts in user input.",
                examples=["result = detector.detect(user_prompt)"],
                version_introduced="1.0.0"
            ),
            APIDocumentation(
                module_name="advanced_jailbreak_detector",
                function_name="AdvancedJailbreakDetector.get_pattern_matches",
                stability=StabilityLevel.EXPERIMENTAL,
                signature="get_pattern_matches(self, prompt: str) -> List[PatternMatch]",
                docstring="Get detailed pattern matching information (experimental API).",
                examples=["matches = detector.get_pattern_matches(prompt)"],
                version_introduced="1.5.0"
            )
        ])
        
        self._modules[module.module_name] = module
        self._update_counts(module)
    
    def _add_agent_security_modules(self) -> None:
        """Add agent security module documentation."""
        module = ModuleDocumentation(
            module_name="agent_tool_call_validator",
            description="Validates and sanitizes AI agent tool calls to prevent privilege escalation and injection attacks.",
            best_practices=[
                "Always validate tool calls before execution",
                "Use allowlists for permitted operations",
                "Implement rate limiting per agent",
                "Audit all tool call decisions"
            ],
            usage_examples=[
                """
                validator = AgentToolCallValidator()
                if validator.validate(tool_name, parameters):
                    execute_tool()
                else:
                    log_rejection()
                """
            ]
        )
        
        module.apis.extend([
            APIDocumentation(
                module_name="agent_tool_call_validator",
                function_name="AgentToolCallValidator.__init__",
                stability=StabilityLevel.STABLE,
                signature="__init__(self, allowed_tools: Optional[Set[str]] = None)",
                docstring="Initialize tool call validator with optional tool allowlist.",
                examples=["validator = AgentToolCallValidator(allowed_tools={'read', 'write'})"],
                version_introduced="1.1.0"
            ),
            APIDocumentation(
                module_name="agent_tool_call_validator",
                function_name="AgentToolCallValidator.validate",
                stability=StabilityLevel.STABLE,
                signature="validate(self, tool_name: str, params: Dict[str, Any]) -> ValidationResult",
                docstring="Validate a tool call before execution.",
                examples=["result = validator.validate('read_file', {'path': '/tmp/data.txt'})"],
                version_introduced="1.1.0"
            ),
            APIDocumentation(
                module_name="agent_tool_call_validator",
                function_name="AgentToolCallValidator.sanitize_parameters",
                stability=StabilityLevel.STABLE,
                signature="sanitize_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]",
                docstring="Sanitize potentially malicious parameters.",
                examples=["clean_params = validator.sanitize_parameters(raw_params)"],
                version_introduced="1.3.0"
            )
        ])
        
        self._modules[module.module_name] = module
        self._update_counts(module)
    
    def _add_security_hardening(self) -> None:
        """Add security hardening module documentation."""
        module = ModuleDocumentation(
            module_name="security_hardening_comprehensive",
            description="Comprehensive security utilities including input validation, memory zeroization, and constant-time operations.",
            best_practices=[
                "Validate ALL external inputs",
                "Zero sensitive memory after use",
                "Use constant-time comparisons for secrets",
                "Enable rate limiting for public endpoints"
            ],
            usage_examples=[
                """
                validator = InputValidator()
                if validator.is_safe(user_input):
                    process_input()
                
                zeroize_memory(sensitive_buffer)
                """
            ]
        )
        
        module.apis.extend([
            APIDocumentation(
                module_name="security_hardening_comprehensive",
                function_name="InputValidator.__init__",
                stability=StabilityLevel.STABLE,
                signature="__init__(self, max_length: int = 10000)",
                docstring="Initialize input validator with maximum input length constraint.",
                examples=["validator = InputValidator(max_length=5000)"],
                version_introduced="1.2.0"
            ),
            APIDocumentation(
                module_name="security_hardening_comprehensive",
                function_name="constant_time_compare",
                stability=StabilityLevel.STABLE,
                signature="constant_time_compare(a: bytes, b: bytes) -> bool",
                docstring="Timing-attack resistant comparison for cryptographic operations.",
                examples=["if constant_time_compare(hash1, hash2):"],
                version_introduced="1.0.0"
            ),
            APIDocumentation(
                module_name="security_hardening_comprehensive",
                function_name="zeroize_memory",
                stability=StabilityLevel.STABLE,
                signature="zeroize_memory(buffer: bytearray) -> None",
                docstring="Securely overwrite sensitive memory to prevent data leakage.",
                examples=["zeroize_memory(sensitive_key_material)"],
                version_introduced="1.0.0"
            ),
            APIDocumentation(
                module_name="security_hardening_comprehensive",
                function_name="RateLimiter.__init__",
                stability=StabilityLevel.STABLE,
                signature="__init__(self, max_requests: int, window_seconds: int)",
                docstring="Initialize rate limiter for DoS protection.",
                examples=["limiter = RateLimiter(max_requests=100, window_seconds=60)"],
                version_introduced="1.4.0"
            )
        ])
        
        self._modules[module.module_name] = module
        self._update_counts(module)
    
    def _add_error_resilience(self) -> None:
        """Add error resilience module documentation."""
        module = ModuleDocumentation(
            module_name="error_resilience_comprehensive",
            description="Error resilience utilities including retry logic, circuit breakers, timeouts, and graceful degradation.",
            best_practices=[
                "Use exponential backoff for retries",
                "Implement circuit breakers for external dependencies",
                "Always set reasonable timeouts",
                "Provide graceful fallback mechanisms"
            ],
            usage_examples=[
                """
                @retry(max_attempts=3, backoff_factor=2.0)
                def call_external_api():
                    pass
                
                with timeout(seconds=5):
                    risky_operation()
                """
            ]
        )
        
        module.apis.extend([
            APIDocumentation(
                module_name="error_resilience_comprehensive",
                function_name="retry",
                stability=StabilityLevel.STABLE,
                signature="retry(max_attempts: int = 3, backoff_factor: float = 1.0)",
                docstring="Decorator for automatic retry with exponential backoff.",
                examples=["@retry(max_attempts=5, backoff_factor=2.0)"],
                version_introduced="1.3.0"
            ),
            APIDocumentation(
                module_name="error_resilience_comprehensive",
                function_name="CircuitBreaker.__init__",
                stability=StabilityLevel.STABLE,
                signature="__init__(self, failure_threshold: int, recovery_timeout: int)",
                docstring="Initialize circuit breaker for fault tolerance.",
                examples=["breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=30)"],
                version_introduced="1.3.0"
            ),
            APIDocumentation(
                module_name="error_resilience_comprehensive",
                function_name="timeout",
                stability=StabilityLevel.STABLE,
                signature="timeout(seconds: float)",
                docstring="Context manager for operation timeouts.",
                examples=["with timeout(seconds=10): long_running_operation()"],
                version_introduced="1.3.0"
            ),
            APIDocumentation(
                module_name="error_resilience_comprehensive",
                function_name="fallback",
                stability=StabilityLevel.STABLE,
                signature="fallback(default_value: Any)",
                docstring="Decorator for graceful degradation with fallback values.",
                examples=["@fallback(default_value=[])"],
                version_introduced="1.4.0"
            )
        ])
        
        self._modules[module.module_name] = module
        self._update_counts(module)
    
    def _add_observability_modules(self) -> None:
        """Add observability and instrumentation module documentation."""
        module = ModuleDocumentation(
            module_name="observability_instrumentation",
            description="Structured logging, metrics collection, and health check frameworks (OPT-IN only).",
            best_practices=[
                "Enable instrumentation only when needed",
                "Use structured logging for machine parsing",
                "Collect business-relevant metrics",
                "Implement health checks for critical paths"
            ],
            usage_examples=[
                """
                metrics = MetricsCollector()
                metrics.increment("requests.total")
                
                logger = StructuredLogger()
                logger.info("request_processed", latency_ms=45)
                """
            ]
        )
        
        module.apis.extend([
            APIDocumentation(
                module_name="observability_instrumentation",
                function_name="StructuredLogger.__init__",
                stability=StabilityLevel.STABLE,
                signature="__init__(self, enabled: bool = False)",
                docstring="Initialize structured logger (disabled by default for performance).",
                examples=["logger = StructuredLogger(enabled=True)"],
                version_introduced="1.2.0"
            ),
            APIDocumentation(
                module_name="observability_instrumentation",
                function_name="MetricsCollector.__init__",
                stability=StabilityLevel.STABLE,
                signature="__init__(self, enabled: bool = False)",
                docstring="Initialize metrics collector (disabled by default).",
                examples=["metrics = MetricsCollector(enabled=True)"],
                version_introduced="1.2.0"
            ),
            APIDocumentation(
                module_name="observability_instrumentation",
                function_name="HealthCheck.register",
                stability=StabilityLevel.STABLE,
                signature="register(self, name: str, check_fn: Callable)",
                docstring="Register a health check function.",
                examples=["health.register('database', check_db_connection)"],
                version_introduced="1.2.0"
            )
        ])
        
        self._modules[module.module_name] = module
        self._update_counts(module)
    
    def _update_counts(self, module: ModuleDocumentation) -> None:
        """Update stability level counts."""
        for api in module.apis:
            self._stability_counts[api.stability] += 1
    
    def get_stability_summary(self) -> Dict[str, int]:
        """
        Get summary of API stability levels.
        
        @stable
        """
        return {
            level.value: count
            for level, count in self._stability_counts.items()
        }
    
    def get_module_documentation(self, module_name: str) -> Optional[ModuleDocumentation]:
        """
        Get documentation for a specific module.
        
        @stable
        """
        return self._modules.get(module_name)
    
    def list_all_modules(self) -> List[str]:
        """
        List all documented modules.
        
        @stable
        """
        return list(self._modules.keys())
    
    def generate_markdown_report(self) -> str:
        """
        Generate comprehensive markdown documentation report.
        
        @stable
        """
        lines = [
            "# NeuralShield-AI API Documentation & Stability Report v27",
            "",
            f"Generated: {datetime.utcnow().isoformat()}",
            "",
            "## Stability Summary",
            ""
        ]
        
        for level, count in self._stability_counts.items():
            lines.append(f"- **{level.value.upper()}**: {count} APIs")
        
        lines.extend(["", "## Module Documentation", ""])
        
        for module_name, module in sorted(self._modules.items()):
            lines.extend([
                f"### {module_name}",
                "",
                f"**Description**: {module.description}",
                "",
                "**Best Practices**:",
                ""
            ])
            
            for practice in module.best_practices:
                lines.append(f"- {practice}")
            
            lines.extend(["", "**APIs**:", ""])
            
            for api in module.apis:
                stability_icon = "✅" if api.stability == StabilityLevel.STABLE else "⚠️" if api.stability == StabilityLevel.EXPERIMENTAL else "❌"
                lines.append(f"- {stability_icon} `{api.function_name}` - **{api.stability.value}**")
                lines.append(f"  - Signature: `{api.signature}`")
                lines.append(f"  - Since: v{api.version_introduced}")
                if api.deprecation_notice:
                    lines.append(f"  - ⚠️ Deprecation: {api.deprecation_notice}")
            
            lines.append("")
        
        return "\n".join(lines)


# Singleton instance for easy import
documentation_catalog = NeuralShieldDocumentationCatalog()


def get_documentation_catalog() -> NeuralShieldDocumentationCatalog:
    """
    Get the global documentation catalog instance.
    
    @stable
    """
    return documentation_catalog


def print_stability_summary() -> None:
    """
    Print a quick summary of API stability levels.
    
    @stable
    """
    summary = documentation_catalog.get_stability_summary()
    print("NeuralShield-AI API Stability Summary v27")
    print("=" * 50)
    for level, count in summary.items():
        print(f"{level.upper():15} {count:3} APIs")
    print("=" * 50)


if __name__ == "__main__":
    print_stability_summary()
    print("\nModules documented:", len(documentation_catalog.list_all_modules()))
    for module in documentation_catalog.list_all_modules():
        print(f"  - {module}")
