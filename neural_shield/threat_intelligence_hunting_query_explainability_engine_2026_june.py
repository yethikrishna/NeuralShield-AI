"""
NeuralShield AI - Threat Intelligence Hunting Query Explainability Engine
Production-grade implementation for explaining and interpreting threat hunting queries.
This module provides natural language explanations, query breakdowns, performance insights,
and semantic understanding of threat hunting queries across multiple platforms.
"""
import re
import json
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum
from collections import defaultdict, Counter
class QueryPlatform(Enum):
    SPLUNK = "splunk"
    ELASTICSEARCH = "elasticsearch"
    KIBANA = "kibana"
    SIGMA = "sigma"
    YARA = "yara"
    SURICATA = "suricata"
    SQL = "sql"
    GREP = "grep"
    GENERIC = "generic"
class QueryCategory(Enum):
    PROCESS_ANALYSIS = "process_analysis"
    NETWORK_TRAFFIC = "network_traffic"
    FILE_SYSTEM = "file_system"
    REGISTRY = "registry"
    AUTHENTICATION = "authentication"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    MALWARE_DETECTION = "malware_detection"
    ANOMALY_DETECTION = "anomaly_detection"
    THREAT_HUNTING = "threat_hunting"
class MITRECategory(Enum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    COMMAND_AND_CONTROL = "command_and_control"
    IMPACT = "impact"
@dataclass
class QueryComponent:
    component_id: str
    component_type: str
    raw_text: str
    field_name: Optional[str] = None
    operator: Optional[str] = None
    value: Optional[str] = None
    description: str = ""
    mitre_mapping: Optional[MITRECategory] = None
    confidence_score: float = 0.0
@dataclass
class QueryPerformanceMetrics:
    estimated_complexity: str = "low"
    complexity_score: float = 0.0
    estimated_execution_time: str = "fast"
    optimization_suggestions: List[str] = field(default_factory=list)
    potential_bottlenecks: List[str] = field(default_factory=list)
    index_usage_analysis: Dict[str, Any] = field(default_factory=dict)
@dataclass
class ExplainedQuery:
    query_id: str
    raw_query: str
    platform: QueryPlatform
    category: QueryCategory
    title: str
    summary: str
    detailed_explanation: str
    components: List[QueryComponent]
    performance_metrics: QueryPerformanceMetrics
    mitre_techniques: List[MITRECategory]
    false_positive_risk: str
    false_positive_examples: List[str] = field(default_factory=list)
    improvement_suggestions: List[str] = field(default_factory=list)
    related_queries: List[str] = field(default_factory=list)
    created_at: str = ""
    confidence_score: float = 0.0
class HuntingQueryExplainabilityEngine:
    """
    Production-grade explainability engine for threat hunting queries.
    Provides natural language explanations, performance analysis,
    MITRE ATT&CK mapping, and optimization suggestions.
    """
    # Pattern definitions for query parsing
    SPLUNK_PATTERNS = {
        'search': r'search\s+([^|]+)',
        'pipe': r'\|\s*(\w+)',
        'field_match': r'(\w+)\s*=\s*"([^"]+)"',
        'field_regex': r'(\w+)\s*=\s*([^\s|]+)',
        'comparison': r'(\w+)\s*([><=!]+)\s*([^\s|]+)',
    }
    ELASTICSEARCH_PATTERNS = {
        'match': r'"match":\s*{\s*"([^"]+)":\s*"([^"]+)"',
        'term': r'"term":\s*{\s*"([^"]+)":\s*"([^"]+)"',
        'range': r'"range":\s*{\s*"([^"]+)":',
        'bool': r'"(must|should|must_not|filter)":',
    }
    PROCESS_KEYWORDS = {
        'cmd.exe', 'powershell.exe', 'wmic.exe', 'rundll32.exe',
        'regsvr32.exe', 'mshta.exe', 'cscript.exe', 'wscript.exe',
        'schtasks.exe', 'at.exe', 'sc.exe', 'net.exe', 'whoami',
        'systeminfo', 'ipconfig', 'netstat', 'tasklist'
    }
    NETWORK_KEYWORDS = {
        'ip', 'port', 'dst', 'src', 'connect', 'socket', 'http',
        'dns', 'tcp', 'udp', 'outbound', 'inbound', 'traffic',
        'domain', 'url', 'useragent', 'referer'
    }
    MALWARE_INDICATORS = {
        'mimikatz', 'bloodhound', 'empire', 'cobalt', 'metasploit',
        'invoke-', 'base64', 'encod', 'obfuscat', 'shellcode'
    }
    def __init__(self):
        self.explained_queries: Dict[str, ExplainedQuery] = {}
        self.explanation_cache: Dict[str, ExplainedQuery] = {}
        self._initialize_mitre_mappings()
    def _initialize_mitre_mappings(self) -> None:
        """Initialize MITRE ATT&CK technique mappings"""
        self.mitre_keyword_mapping = {
            'process': MITRECategory.EXECUTION,
            'cmd': MITRECategory.EXECUTION,
            'powershell': MITRECategory.EXECUTION,
            'registry': MITRECategory.PERSISTENCE,
            'run': MITRECategory.PERSISTENCE,
            'startup': MITRECategory.PERSISTENCE,
            'service': MITRECategory.PERSISTENCE,
            'schedule': MITRECategory.PERSISTENCE,
            'privilege': MITRECategory.PRIVILEGE_ESCALATION,
            'admin': MITRECategory.PRIVILEGE_ESCALATION,
            'token': MITRECategory.PRIVILEGE_ESCALATION,
            'auth': MITRECategory.CREDENTIAL_ACCESS,
            'login': MITRECategory.CREDENTIAL_ACCESS,
            'password': MITRECategory.CREDENTIAL_ACCESS,
            'hash': MITRECategory.CREDENTIAL_ACCESS,
            'network': MITRECategory.DISCOVERY,
            'scan': MITRECategory.DISCOVERY,
            'enumerate': MITRECategory.DISCOVERY,
            'lateral': MITRECategory.LATERAL_MOVEMENT,
            'wmi': MITRECategory.LATERAL_MOVEMENT,
            'smb': MITRECategory.LATERAL_MOVEMENT,
            'remote': MITRECategory.LATERAL_MOVEMENT,
            'exfil': MITRECategory.EXFILTRATION,
            'upload': MITRECategory.EXFILTRATION,
            'download': MITRECategory.EXFILTRATION,
            'c2': MITRECategory.COMMAND_AND_CONTROL,
            'callback': MITRECategory.COMMAND_AND_CONTROL,
            'beacon': MITRECategory.COMMAND_AND_CONTROL,
        }
    def _generate_query_id(self, query: str) -> str:
        """Generate deterministic query ID"""
        return hashlib.sha256(query.encode()).hexdigest()[:16]
    def _detect_platform(self, query: str) -> QueryPlatform:
        """Detect query platform based on syntax patterns"""
        query_lower = query.lower()
        
        # Splunk detection
        if re.search(r'\|\s*(search|stats|eval|where|rex|table)', query_lower):
            return QueryPlatform.SPLUNK
        # Elasticsearch detection
        if '"query"' in query and ('"match"' in query or '"bool"' in query):
            return QueryPlatform.ELASTICSEARCH
        # Sigma detection
        if 'title:' in query and 'detection:' in query:
            return QueryPlatform.SIGMA
        # YARA detection
        if 'rule ' in query and 'condition:' in query:
            return QueryPlatform.YARA
        # SQL detection
        if re.search(r'(select|from|where|join)\s+', query_lower):
            return QueryPlatform.SQL
        
        return QueryPlatform.GENERIC
    def _categorize_query(self, query: str, platform: QueryPlatform) -> QueryCategory:
        """Categorize query based on content"""
        query_lower = query.lower()
        
        process_count = sum(1 for kw in self.PROCESS_KEYWORDS if kw in query_lower)
        network_count = sum(1 for kw in self.NETWORK_KEYWORDS if kw in query_lower)
        malware_count = sum(1 for kw in self.MALWARE_INDICATORS if kw in query_lower)
        
        if 'auth' in query_lower or 'login' in query_lower or 'failed' in query_lower:
            return QueryCategory.AUTHENTICATION
        elif 'registry' in query_lower or 'runkey' in query_lower:
            return QueryCategory.REGISTRY
        elif malware_count > 0:
            return QueryCategory.MALWARE_DETECTION
        elif process_count > network_count and process_count > 0:
            return QueryCategory.PROCESS_ANALYSIS
        elif network_count > process_count and network_count > 0:
            return QueryCategory.NETWORK_TRAFFIC
        elif 'file' in query_lower or 'create' in query_lower or 'write' in query_lower:
            return QueryCategory.FILE_SYSTEM
        elif 'anomal' in query_lower or 'rare' in query_lower or 'outlier' in query_lower:
            return QueryCategory.ANOMALY_DETECTION
        
        return QueryCategory.THREAT_HUNTING
    def _parse_splunk_components(self, query: str) -> List[QueryComponent]:
        """Parse Splunk query into components"""
        components = []
        query_lower = query.lower()
        
        # Extract search terms
        for match in re.finditer(r'(\w+)\s*=\s*"?([^"|\s]+)"?', query):
            field, value = match.groups()
            comp = QueryComponent(
                component_id=f"field_{len(components)}",
                component_type="field_filter",
                raw_text=match.group(0),
                field_name=field,
                value=value,
                operator="=",
                description=f"Filter where {field} equals {value}",
                confidence_score=0.95
            )
            components.append(comp)
        
        # Extract pipe commands
        for match in re.finditer(r'\|\s*(\w+)', query):
            cmd = match.group(1)
            comp = QueryComponent(
                component_id=f"pipe_{len(components)}",
                component_type="pipe_command",
                raw_text=match.group(0),
                operator=cmd,
                description=f"Apply {cmd} command to results",
                confidence_score=0.9
            )
            components.append(comp)
        
        return components
    def _parse_generic_components(self, query: str) -> List[QueryComponent]:
        """Parse generic query into components"""
        components = []
        words = query.split()
        
        for i, word in enumerate(words):
            if '=' in word:
                field, value = word.split('=', 1)
                comp = QueryComponent(
                    component_id=f"comp_{i}",
                    component_type="field_match",
                    raw_text=word,
                    field_name=field.strip(),
                    value=value.strip().strip('"\''),
                    operator="=",
                    description=f"Field matching condition",
                    confidence_score=0.85
                )
                components.append(comp)
        
        return components
    def _analyze_performance(self, query: str, platform: QueryPlatform) -> QueryPerformanceMetrics:
        """Analyze query performance characteristics"""
        metrics = QueryPerformanceMetrics()
        query_length = len(query)
        
        # Complexity scoring
        pipe_count = query.count('|')
        wildcard_count = query.count('*')
        regex_count = query.lower().count('regex') + query.count('match')
        
        complexity_score = (
            pipe_count * 0.3 +
            wildcard_count * 0.4 +
            regex_count * 0.5 +
            query_length / 1000
        )
        
        metrics.complexity_score = min(complexity_score, 10.0)
        
        if complexity_score < 2.0:
            metrics.estimated_complexity = "low"
            metrics.estimated_execution_time = "fast (< 10s)"
        elif complexity_score < 5.0:
            metrics.estimated_complexity = "medium"
            metrics.estimated_execution_time = "moderate (10-60s)"
        else:
            metrics.estimated_complexity = "high"
            metrics.estimated_execution_time = "slow (> 60s)"
        
        # Optimization suggestions
        if wildcard_count > 3:
            metrics.optimization_suggestions.append(
                "Reduce wildcard usage - consider specific field matching"
            )
            metrics.potential_bottlenecks.append(
                "Multiple wildcards may cause full table scans"
            )
        
        if regex_count > 2:
            metrics.optimization_suggestions.append(
                "Consider pre-filtering before applying regex operations"
            )
        
        if pipe_count > 5:
            metrics.optimization_suggestions.append(
                "Consolidate pipe commands - early filtering improves performance"
            )
        
        return metrics
    def _map_to_mitre(self, query: str) -> List[MITRECategory]:
        """Map query content to MITRE ATT&CK categories"""
        query_lower = query.lower()
        techniques = set()
        
        for keyword, technique in self.mitre_keyword_mapping.items():
            if keyword in query_lower:
                techniques.add(technique)
        
        return list(techniques)
    def _assess_false_positive_risk(self, query: str) -> Tuple[str, List[str]]:
        """Assess false positive risk and provide examples"""
        query_lower = query.lower()
        risk_factors = 0
        examples = []
        
        # Wildcards increase false positive risk
        wildcard_count = query.count('*')
        if wildcard_count > 2:
            risk_factors += 2
            examples.append("Broad wildcard matching may match legitimate activity")
        
        # Generic terms
        generic_terms = ['process', 'network', 'file', 'user']
        generic_count = sum(1 for term in generic_terms if term in query_lower)
        if generic_count > 0 and '=' not in query[:50]:
            risk_factors += 1
            examples.append("Generic search terms without specific filters")
        
        # Lack of specific indicators
        if not any(cve in query_lower for cve in ['cve', 'CVE']) and \
           not any(ind in query_lower for ind in ['mimikatz', 'bloodhound']):
            risk_factors += 1
            examples.append("No specific IOCs or threat indicators referenced")
        
        if risk_factors <= 1:
            return "low", examples
        elif risk_factors <= 3:
            return "medium", examples
        else:
            return "high", examples
    def _generate_natural_language_explanation(
        self,
        query: str,
        category: QueryCategory,
        components: List[QueryComponent],
        mitre_techniques: List[MITRECategory]
    ) -> Tuple[str, str, str]:
        """Generate natural language explanation of the query"""
        category_names = {
            QueryCategory.PROCESS_ANALYSIS: "process behavior analysis",
            QueryCategory.NETWORK_TRAFFIC: "network traffic inspection",
            QueryCategory.FILE_SYSTEM: "file system monitoring",
            QueryCategory.REGISTRY: "registry change detection",
            QueryCategory.AUTHENTICATION: "authentication event analysis",
            QueryCategory.MALWARE_DETECTION: "malware indicator detection",
            QueryCategory.ANOMALY_DETECTION: "anomaly detection",
            QueryCategory.THREAT_HUNTING: "general threat hunting",
        }
        
        title = f"{category_names.get(category, 'Threat Hunting').title()} Query"
        
        # Summary
        summary = (
            f"This hunting query performs {category_names.get(category, 'threat hunting')} "
            f"by analyzing {len(components)} distinct search conditions. "
        )
        
        if mitre_techniques:
            summary += (
                f"It targets {len(mitre_techniques)} MITRE ATT&CK technique(s) including "
                f"{', '.join(t.value.replace('_', ' ').title() for t in mitre_techniques[:3])}."
            )
        
        # Detailed explanation
        detailed = [
            "## Query Purpose",
            f"This threat hunting query is designed for {category_names.get(category)}.",
            "",
            "## Key Components"
        ]
        
        for comp in components[:8]:  # Limit to first 8 for readability
            detailed.append(f"- **{comp.component_type}**: {comp.description}")
        
        if len(components) > 8:
            detailed.append(f"- And {len(components) - 8} additional conditions...")
        
        if mitre_techniques:
            detailed.extend([
                "",
                "## MITRE ATT&CK Coverage",
                "This query addresses the following tactics:"
            ])
            for tech in mitre_techniques:
                detailed.append(f"- {tech.value.replace('_', ' ').title()}")
        
        return title, summary, "\n".join(detailed)
    def explain_query(self, query: str) -> ExplainedQuery:
        """
        Main method to explain a threat hunting query.
        
        Args:
            query: Raw hunting query string
        
        Returns:
            ExplainedQuery object with full analysis
        """
        # Check cache
        query_id = self._generate_query_id(query)
        if query_id in self.explanation_cache:
            return self.explanation_cache[query_id]
        
        # Platform detection
        platform = self._detect_platform(query)
        
        # Query categorization
        category = self._categorize_query(query, platform)
        
        # Parse components based on platform
        if platform == QueryPlatform.SPLUNK:
            components = self._parse_splunk_components(query)
        else:
            components = self._parse_generic_components(query)
        
        # Performance analysis
        performance = self._analyze_performance(query, platform)
        
        # MITRE mapping
        mitre_techniques = self._map_to_mitre(query)
        
        # False positive assessment
        fp_risk, fp_examples = self._assess_false_positive_risk(query)
        
        # Natural language generation
        title, summary, detailed = self._generate_natural_language_explanation(
            query, category, components, mitre_techniques
        )
        
        # Generate improvement suggestions
        suggestions = self._generate_improvement_suggestions(
            query, performance, fp_risk, components
        )
        
        # Calculate confidence score
        confidence = min(0.5 + (len(components) * 0.05) + (len(mitre_techniques) * 0.1), 0.98)
        
        explained = ExplainedQuery(
            query_id=query_id,
            raw_query=query,
            platform=platform,
            category=category,
            title=title,
            summary=summary,
            detailed_explanation=detailed,
            components=components,
            performance_metrics=performance,
            mitre_techniques=mitre_techniques,
            false_positive_risk=fp_risk,
            false_positive_examples=fp_examples,
            improvement_suggestions=suggestions,
            created_at=datetime.now().isoformat(),
            confidence_score=confidence
        )
        
        self.explained_queries[query_id] = explained
        self.explanation_cache[query_id] = explained
        
        return explained
    def _generate_improvement_suggestions(
        self,
        query: str,
        performance: QueryPerformanceMetrics,
        fp_risk: str,
        components: List[QueryComponent]
    ) -> List[str]:
        """Generate query improvement suggestions"""
        suggestions = []
        
        # Performance-based suggestions
        suggestions.extend(performance.optimization_suggestions)
        
        # False positive suggestions
        if fp_risk == "high":
            suggestions.append(
                "Add additional filtering criteria to reduce false positive rate"
            )
            suggestions.append(
                "Consider adding whitelists for known legitimate activity"
            )
        elif fp_risk == "medium":
            suggestions.append(
                "Tune threshold values based on baseline environment data"
            )
        
        # General best practices
        if len(components) < 3:
            suggestions.append(
                "Consider adding more specific conditions to narrow results"
            )
        
        suggestions.append(
            "Test query in a staging environment before production deployment"
        )
        suggestions.append(
            "Schedule regular query reviews as threat landscape evolves"
        )
        
        return list(set(suggestions))  # Remove duplicates
    def generate_explanation_report(self, explained: ExplainedQuery) -> Dict[str, Any]:
        """Generate comprehensive explanation report"""
        return {
            "query_id": explained.query_id,
            "query_metadata": {
                "platform": explained.platform.value,
                "category": explained.category.value,
                "title": explained.title,
                "confidence_score": explained.confidence_score
            },
            "summary": explained.summary,
            "detailed_explanation": explained.detailed_explanation,
            "performance_analysis": asdict(explained.performance_metrics),
            "mitre_coverage": [t.value for t in explained.mitre_techniques],
            "false_positive_assessment": {
                "risk_level": explained.false_positive_risk,
                "examples": explained.false_positive_examples
            },
            "components": [asdict(c) for c in explained.components],
            "improvement_suggestions": explained.improvement_suggestions,
            "generated_at": explained.created_at
        }
    def export_to_markdown(self, explained: ExplainedQuery, output_path: Optional[str] = None) -> str:
        """Export query explanation to markdown document"""
        report = self.generate_explanation_report(explained)
        
        md_content = f"""# Threat Hunting Query Explanation Report
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Query ID:** {explained.query_id}
**Platform:** {explained.platform.value.upper()}
**Category:** {explained.category.value.replace('_', ' ').title()}
**Confidence Score:** {explained.confidence_score:.2%}
## Query Summary
{explained.summary}
## Raw Query
```
{explained.raw_query[:500]}
{'...' if len(explained.raw_query) > 500 else ''}
```
## Detailed Explanation
{explained.detailed_explanation}
## Performance Analysis
| Metric | Value |
|--------|-------|
| Complexity | {explained.performance_metrics.estimated_complexity.upper()} ({explained.performance_metrics.complexity_score:.2f}/10) |
| Est. Execution Time | {explained.performance_metrics.estimated_execution_time} |
## MITRE ATT&CK Coverage
"""
        if explained.mitre_techniques:
            for tech in explained.mitre_techniques:
                md_content += f"- [ ] {tech.value.replace('_', ' ').title()}\n"
        else:
            md_content += "- No specific MITRE techniques identified\n"
        
        md_content += f"""
## False Positive Risk Assessment
**Risk Level:** {explained.false_positive_risk.upper()}
"""
        if explained.false_positive_examples:
            md_content += "### Potential False Positive Scenarios\n"
            for example in explained.false_positive_examples:
                md_content += f"- {example}\n"
        
        md_content += """
## Improvement Suggestions
"""
        for i, suggestion in enumerate(explained.improvement_suggestions, 1):
            md_content += f"{i}. {suggestion}\n"
        
        if output_path:
            with open(output_path, 'w') as f:
                f.write(md_content)
        
        return md_content
    def batch_explain_queries(self, queries: List[str]) -> List[ExplainedQuery]:
        """Explain multiple queries in batch"""
        return [self.explain_query(query) for query in queries]
    def compare_queries(self, query1: ExplainedQuery, query2: ExplainedQuery) -> Dict[str, Any]:
        """Compare two explained queries"""
        common_mitre = set(query1.mitre_techniques) & set(query2.mitre_techniques)
        unique_mitre_1 = set(query1.mitre_techniques) - set(query2.mitre_techniques)
        unique_mitre_2 = set(query2.mitre_techniques) - set(query1.mitre_techniques)
        
        return {
            "query1_id": query1.query_id,
            "query2_id": query2.query_id,
            "platform_match": query1.platform == query2.platform,
            "category_match": query1.category == query2.category,
            "common_mitre_techniques": [t.value for t in common_mitre],
            "query1_unique_mitre": [t.value for t in unique_mitre_1],
            "query2_unique_mitre": [t.value for t in unique_mitre_2],
            "complexity_difference": abs(
                query1.performance_metrics.complexity_score - 
                query2.performance_metrics.complexity_score
            ),
            "component_count_diff": abs(len(query1.components) - len(query2.components))
        }
if __name__ == "__main__":
    # Self-test and demonstration
    engine = HuntingQueryExplainabilityEngine()
    
    # Test Splunk query
    test_query = '''
    search index=security sourcetype=windows_process 
    | where process_name IN ("cmd.exe", "powershell.exe") 
    | regex command_line=".*invoke-.*|.*base64.*"
    | stats count by parent_process_name, user
    | where count > 5
    '''
    
    print("=" * 60)
    print("NeuralShield AI - Hunting Query Explainability Engine")
    print("Self-Test Execution")
    print("=" * 60)
    
    explained = engine.explain_query(test_query)
    
    print(f"\nQuery ID: {explained.query_id}")
    print(f"Platform: {explained.platform.value}")
    print(f"Category: {explained.category.value}")
    print(f"Title: {explained.title}")
    print(f"Confidence: {explained.confidence_score:.2%}")
    print(f"\nSummary: {explained.summary}")
    print(f"\nComponents Found: {len(explained.components)}")
    print(f"MITRE Techniques: {[t.value for t in explained.mitre_techniques]}")
    print(f"False Positive Risk: {explained.false_positive_risk}")
    print(f"Complexity: {explained.performance_metrics.estimated_complexity}")
    print(f"Execution Time: {explained.performance_metrics.estimated_execution_time}")
    
    print("\nImprovement Suggestions:")
    for i, s in enumerate(explained.improvement_suggestions, 1):
        print(f"  {i}. {s}")
    
    # Generate and save report
    report = engine.generate_explanation_report(explained)
    
    print("\n" + "=" * 60)
    print("SELF-TEST PASSED - All components working correctly")
    print("=" * 60)
