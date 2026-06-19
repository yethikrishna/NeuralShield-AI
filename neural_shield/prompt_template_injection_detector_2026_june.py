"""
Prompt Template Injection Detector - NeuralShield-AI
June 20, 2026 - Production Release

Detects template injection attacks in AI prompt templates:
- Variable manipulation attacks ({{variable}} poisoning)
- Template syntax injection (Jinja2, Mustache, Handlebars)
- Nested template exploitation
- Control flow injection in templates
- Filter/function injection through template variables

Based on real-world attack patterns from OWASP Top 10 LLM vulnerabilities.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Set, Tuple
import re
from collections import defaultdict


class TemplateInjectionType(Enum):
    """Types of template injection attacks detected"""
    VARIABLE_MANIPULATION = "variable_manipulation"
    NESTED_TEMPLATE = "nested_template"
    CONTROL_FLOW_INJECTION = "control_flow_injection"
    FILTER_INJECTION = "filter_injection"
    FUNCTION_CALL_INJECTION = "function_call_injection"
    SYNTAX_ESCAPE = "syntax_escape"
    COMMENT_INJECTION = "comment_injection"
    RECURSIVE_EXPANSION = "recursive_expansion"
    UNKNOWN = "unknown"


class TemplateInjectionRiskLevel(Enum):
    """Risk levels for template injection findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


@dataclass
class TemplateInjectionFinding:
    """Single finding from template injection detection"""
    injection_type: TemplateInjectionType
    risk_level: TemplateInjectionRiskLevel
    confidence: float  # 0.0 - 1.0
    matched_pattern: str
    location: Tuple[int, int]  # start, end indices
    description: str
    suggested_mitigation: str


@dataclass
class TemplateVariable:
    """Represents a template variable with its usage context"""
    name: str
    raw_value: str
    sanitized: bool = False
    usage_locations: List[Tuple[int, int]] = field(default_factory=list)


@dataclass
class TemplateInjectionDetectionResult:
    """Complete result from template injection detection"""
    is_safe: bool
    overall_risk_level: TemplateInjectionRiskLevel
    findings: List[TemplateInjectionFinding]
    variables_analyzed: List[TemplateVariable]
    template_syntax_detected: Set[str]
    analysis_timestamp: float
    total_scan_time_ms: float
    mitigation_recommendations: List[str]

    def to_dict(self) -> Dict:
        """Convert result to dictionary for serialization"""
        return {
            "is_safe": self.is_safe,
            "overall_risk_level": self.overall_risk_level.value,
            "findings_count": len(self.findings),
            "findings": [
                {
                    "type": f.injection_type.value,
                    "risk": f.risk_level.value,
                    "confidence": f.confidence,
                    "pattern": f.matched_pattern,
                    "description": f.description
                }
                for f in self.findings
            ],
            "variables_count": len(self.variables_analyzed),
            "template_syntax": list(self.template_syntax_detected),
            "mitigations": self.mitigation_recommendations
        }


class PromptTemplateInjectionDetector:
    """
    Production-grade template injection detector for AI prompts.
    
    Detects:
    1. Jinja2/Mustache/Handlebars syntax injection
    2. Nested variable expansion attacks
    3. Control flow injection ({% if %}, {{#each}})
    4. Filter/function injection
    5. Recursive template expansion attacks
    """

    # Template syntax patterns - real patterns from common template engines
    TEMPLATE_SYNTAX_PATTERNS: Dict[str, re.Pattern] = {
        "jinja2_variable": re.compile(r'\{\{\s*[^{}]*(?:\{\{[^{}]*\}\}[^{}]*)*\s*\}\}', re.IGNORECASE),
        "jinja2_control": re.compile(r'\{%\s*(?:if|for|while|macro|include|extends|import)\s+[^%]+\s*%\}', re.IGNORECASE),
        "jinja2_filter": re.compile(r'\{\{\s*[^|}]+\|\s*[a-zA-Z_][a-zA-Z0-9_]*', re.IGNORECASE),
        "mustache_block": re.compile(r'\{\{\s*[#^/]\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\}\}', re.IGNORECASE),
        "mustache_variable": re.compile(r'\{\{\{?\s*[a-zA-Z_][a-zA-Z0-9_.]*\s*\}\}?'),
        "handlebars_helper": re.compile(r'\{\{\s*[a-zA-Z_][a-zA-Z0-9_]*\s+[^}]+\}\}'),
        "twig_expression": re.compile(r'\{\{\s*[^}]+\s+[+\-*/%]\s+[^}]+\s*\}\}'),
        "velocity_directive": re.compile(r'#(?:set|if|foreach|include|parse)\s*\('),
    }

    # Injection patterns - real attack vectors
    INJECTION_PATTERNS: List[Tuple[TemplateInjectionType, TemplateInjectionRiskLevel, re.Pattern, float, str, str]] = [
        # Nested template injection (CRITICAL)
        (TemplateInjectionType.NESTED_TEMPLATE, TemplateInjectionRiskLevel.CRITICAL,
         re.compile(r'\{\{\s*\{\{.*\}\}\s*\}\}'), 0.95,
         "Nested template variable expansion detected",
         "Sanitize all user inputs before template rendering, use output encoding"),

        # Control flow injection (CRITICAL)
        (TemplateInjectionType.CONTROL_FLOW_INJECTION, TemplateInjectionRiskLevel.CRITICAL,
         re.compile(r'\{%\s*(?:if|for|while|set)\s+.*?%\}'), 0.90,
         "Control flow statement injection in template",
         "Disable template control flow in user-controlled contexts"),

        # Filter injection (HIGH)
        (TemplateInjectionType.FILTER_INJECTION, TemplateInjectionRiskLevel.HIGH,
         re.compile(r'\|\s*(?:safe|raw|escape|attr|json|dump|pprint)\b'), 0.85,
         "Security filter manipulation detected",
         "Use allowlist for permitted filters, block 'safe' and 'raw' filters"),

        # Function call injection (HIGH)
        (TemplateInjectionType.FUNCTION_CALL_INJECTION, TemplateInjectionRiskLevel.HIGH,
         re.compile(r'\{\{\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*\)\s*\}\}'), 0.85,
         "Function call injection in template variable",
         "Disable arbitrary function calls in templates, use sandboxed environment"),

        # Syntax escape attempt (HIGH)
        (TemplateInjectionType.SYNTAX_ESCAPE, TemplateInjectionRiskLevel.HIGH,
         re.compile(r'(?:\}\}|\{%\s*end|#\/).*?(?:\{\{|\{%|#)'), 0.80,
         "Template syntax boundary escape attempt",
         "Properly escape template delimiters in user input"),

        # Recursive expansion (HIGH)
        (TemplateInjectionType.RECURSIVE_EXPANSION, TemplateInjectionRiskLevel.HIGH,
         re.compile(r'(?:\{\{.*){3,}'), 0.80,
         "Potential recursive template expansion attack",
         "Limit template recursion depth, validate input length"),

        # Comment injection (MEDIUM)
        (TemplateInjectionType.COMMENT_INJECTION, TemplateInjectionRiskLevel.MEDIUM,
         re.compile(r'\{#.*#\}|\{\%-\s*comment\s*-\%\}'), 0.70,
         "Template comment injection detected",
         "Strip comments from user input before rendering"),

        # Variable manipulation (MEDIUM)
        (TemplateInjectionType.VARIABLE_MANIPULATION, TemplateInjectionRiskLevel.MEDIUM,
         re.compile(r'\{\{\s*[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*'), 0.75,
         "Attribute access on template variable detected",
         "Restrict variable attribute access to safe properties only"),
    ]

    # Dangerous template functions/filters - real security risks
    DANGEROUS_CONSTRUCTS: Set[str] = {
        'safe', 'raw', 'eval', 'exec', 'import', 'include', 'from',
        'os.', 'sys.', 'subprocess', 'open', 'file', 'read', 'write',
        '__import__', '__class__', '__bases__', '__subclasses__',
        'mro', 'globals', 'locals', 'builtins'
    }

    def __init__(self, strict_mode: bool = True, max_recursion_depth: int = 3):
        """
        Initialize the template injection detector.
        
        Args:
            strict_mode: If True, treat suspicious patterns as higher risk
            max_recursion_depth: Maximum allowed template nesting depth
        """
        self.strict_mode = strict_mode
        self.max_recursion_depth = max_recursion_depth
        self._scan_count = 0

    def detect(self, prompt_template: str, user_variables: Optional[Dict[str, str]] = None) -> TemplateInjectionDetectionResult:
        """
        Detect template injection attacks in prompt templates.
        
        Args:
            prompt_template: The template string to analyze
            user_variables: Optional dictionary of user-provided variable values
            
        Returns:
            TemplateInjectionDetectionResult with findings and analysis
        """
        import time
        start_time = time.time()
        self._scan_count += 1

        findings: List[TemplateInjectionFinding] = []
        template_syntax: Set[str] = set()
        variables: List[TemplateVariable] = []

        # Detect template syntax types
        for syntax_name, pattern in self.TEMPLATE_SYNTAX_PATTERNS.items():
            if pattern.search(prompt_template):
                template_syntax.add(syntax_name.split('_')[0])

        # Check for injection patterns
        for inj_type, risk_level, pattern, confidence, desc, mitigation in self.INJECTION_PATTERNS:
            for match in pattern.finditer(prompt_template):
                findings.append(TemplateInjectionFinding(
                    injection_type=inj_type,
                    risk_level=risk_level,
                    confidence=confidence if not self.strict_mode else min(1.0, confidence + 0.1),
                    matched_pattern=match.group(0)[:100],
                    location=(match.start(), match.end()),
                    description=desc,
                    suggested_mitigation=mitigation
                ))

        # Check recursion depth
        recursion_depth = self._calculate_recursion_depth(prompt_template)
        if recursion_depth > self.max_recursion_depth:
            findings.append(TemplateInjectionFinding(
                injection_type=TemplateInjectionType.RECURSIVE_EXPANSION,
                risk_level=TemplateInjectionRiskLevel.HIGH,
                confidence=0.90,
                matched_pattern=f"Recursion depth: {recursion_depth}",
                location=(0, len(prompt_template)),
                description=f"Template recursion depth ({recursion_depth}) exceeds maximum allowed ({self.max_recursion_depth})",
                suggested_mitigation="Reduce template nesting or increase recursion limit carefully"
            ))

        # Check for dangerous constructs
        dangerous_found = self._check_dangerous_constructs(prompt_template)
        for construct, positions in dangerous_found.items():
            for pos in positions:
                findings.append(TemplateInjectionFinding(
                    injection_type=TemplateInjectionType.FUNCTION_CALL_INJECTION,
                    risk_level=TemplateInjectionRiskLevel.CRITICAL,
                    confidence=0.95,
                    matched_pattern=construct,
                    location=pos,
                    description=f"Dangerous template construct detected: {construct}",
                    suggested_mitigation=f"Block usage of '{construct}' in templates, use sandboxed rendering"
                ))

        # Analyze user variables if provided
        if user_variables:
            for var_name, var_value in user_variables.items():
                var_finding = self._analyze_variable(var_name, var_value)
                if var_finding:
                    findings.append(var_finding)
                variables.append(TemplateVariable(
                    name=var_name,
                    raw_value=var_value,
                    sanitized=False,
                    usage_locations=[]
                ))

        # Determine overall risk level
        overall_risk = self._calculate_overall_risk(findings)
        is_safe = overall_risk in (TemplateInjectionRiskLevel.LOW, TemplateInjectionRiskLevel.SAFE) and len(findings) == 0

        # Generate mitigations
        mitigations = self._generate_mitigations(findings, template_syntax)

        scan_time = (time.time() - start_time) * 1000

        return TemplateInjectionDetectionResult(
            is_safe=is_safe,
            overall_risk_level=overall_risk,
            findings=findings,
            variables_analyzed=variables,
            template_syntax_detected=template_syntax,
            analysis_timestamp=time.time(),
            total_scan_time_ms=scan_time,
            mitigation_recommendations=mitigations
        )

    def _calculate_recursion_depth(self, template: str) -> int:
        """Calculate maximum template variable nesting depth"""
        max_depth = 0
        current_depth = 0
        i = 0
        while i < len(template) - 1:
            if template[i:i+2] == '{{':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
                i += 2
            elif template[i:i+2] == '}}':
                current_depth = max(0, current_depth - 1)
                i += 2
            else:
                i += 1
        return max_depth

    def _check_dangerous_constructs(self, template: str) -> Dict[str, List[Tuple[int, int]]]:
        """Check for dangerous template constructs"""
        results: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
        template_lower = template.lower()
        
        for construct in self.DANGEROUS_CONSTRUCTS:
            pos = 0
            while True:
                idx = template_lower.find(construct.lower(), pos)
                if idx == -1:
                    break
                # Verify it's a whole word match
                if (idx == 0 or not template[idx-1].isalnum()) and \
                   (idx + len(construct) >= len(template) or not template[idx + len(construct)].isalnum()):
                    results[construct].append((idx, idx + len(construct)))
                pos = idx + 1
        return dict(results)

    def _analyze_variable(self, var_name: str, var_value: str) -> Optional[TemplateInjectionFinding]:
        """Analyze a single user variable for injection attempts"""
        # Check if variable contains template syntax
        if '{{' in var_value or '{%' in var_value or '{#' in var_value:
            return TemplateInjectionFinding(
                injection_type=TemplateInjectionType.VARIABLE_MANIPULATION,
                risk_level=TemplateInjectionRiskLevel.HIGH,
                confidence=0.88,
                matched_pattern=f"Variable: {var_name}",
                location=(0, len(var_value)),
                description=f"User variable '{var_name}' contains template syntax - potential injection vector",
                suggested_mitigation="Escape template delimiters in user input before substitution"
            )
        return None

    def _calculate_overall_risk(self, findings: List[TemplateInjectionFinding]) -> TemplateInjectionRiskLevel:
        """Calculate overall risk level from all findings"""
        if not findings:
            return TemplateInjectionRiskLevel.SAFE

        risk_weights = {
            TemplateInjectionRiskLevel.CRITICAL: 100,
            TemplateInjectionRiskLevel.HIGH: 50,
            TemplateInjectionRiskLevel.MEDIUM: 20,
            TemplateInjectionRiskLevel.LOW: 5,
            TemplateInjectionRiskLevel.SAFE: 0
        }

        total_risk = sum(risk_weights[f.risk_level] * f.confidence for f in findings)

        if total_risk >= 80:
            return TemplateInjectionRiskLevel.CRITICAL
        elif total_risk >= 40:
            return TemplateInjectionRiskLevel.HIGH
        elif total_risk >= 15:
            return TemplateInjectionRiskLevel.MEDIUM
        elif total_risk >= 5:
            return TemplateInjectionRiskLevel.LOW
        return TemplateInjectionRiskLevel.SAFE

    def _generate_mitigations(self, findings: List[TemplateInjectionFinding], syntax: Set[str]) -> List[str]:
        """Generate mitigation recommendations"""
        mitigations: List[str] = []

        # Base mitigations
        mitigations.append("Always sanitize and validate user input before template rendering")
        mitigations.append("Use output encoding appropriate for the template context")
        mitigations.append("Consider using logic-less templates (Mustache) instead of full-featured engines")

        # Specific mitigations from findings
        unique_mitigations = set(f.suggested_mitigation for f in findings)
        mitigations.extend(sorted(unique_mitigations))

        # Syntax-specific advice
        if 'jinja2' in syntax:
            mitigations.append("For Jinja2: enable autoescape, use SandboxedEnvironment")
        if 'mustache' in syntax:
            mitigations.append("For Mustache: all variables are HTML-escaped by default")

        return mitigations

    def sanitize_template_input(self, user_input: str) -> str:
        """
        Sanitize user input for safe template usage.
        
        Args:
            user_input: Raw user input string
            
        Returns:
            Sanitized string safe for template insertion
        """
        # Escape template delimiters
        sanitized = user_input.replace('{', '&#123;').replace('}', '&#125;')
        sanitized = sanitized.replace('%', '&#37;').replace('#', '&#35;')
        return sanitized

    def get_scan_statistics(self) -> Dict[str, int]:
        """Get scanner usage statistics"""
        return {"total_scans_performed": self._scan_count}


def create_template_injection_detector(strict_mode: bool = True) -> PromptTemplateInjectionDetector:
    """Factory function to create a template injection detector instance"""
    return PromptTemplateInjectionDetector(strict_mode=strict_mode)


# Self-test and demonstration
if __name__ == "__main__":
    print("=" * 60)
    print("NeuralShield-AI: Prompt Template Injection Detector")
    print("June 20, 2026 Production Release")
    print("=" * 60)
    
    detector = create_template_injection_detector()
    
    # Test cases - real attack patterns
    test_cases = [
        # Safe template
        ("Hello {{name}}, welcome to our service!", {"name": "John"}, "Safe template"),
        
        # Nested template injection attack
        ("User input: {{ {{user_input}} }}", {}, "Nested template injection"),
        
        # Control flow injection
        ("{% if user.is_admin %} Admin access {% endif %}", {}, "Control flow injection"),
        
        # Filter injection (bypassing escaping)
        ("{{ user_input|safe }}", {}, "Safe filter injection"),
        
        # Dangerous function call
        ("{{ __import__('os').system('id') }}", {}, "Function call injection"),
    ]
    
    print("\nRunning detection tests...")
    print("-" * 60)
    
    all_passed = True
    for template, variables, description in test_cases:
        result = detector.detect(template, variables)
        status = "✓ DETECTED" if result.findings else "✓ CLEAN"
        if "Safe" in description and result.findings:
            status = "✗ FALSE POSITIVE"
            all_passed = False
        elif "Safe" not in description and not result.findings:
            status = "✗ MISSED"
            all_passed = False
            
        print(f"\n{status}: {description}")
        print(f"  Risk: {result.overall_risk_level.value}")
        print(f"  Findings: {len(result.findings)}")
        for finding in result.findings[:2]:
            print(f"    - {finding.injection_type.value}: {finding.description[:50]}...")
    
    print("\n" + "-" * 60)
    print(f"Test result: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
    print(f"Total scans: {detector.get_scan_statistics()['total_scans_performed']}")
    print("=" * 60)
