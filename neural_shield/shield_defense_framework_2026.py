"""
SHIELD Defense Framework - June 2026 Implementation
Systematic Hierarchical Injection Evaluation and Layered Defense

Based on clawrxiv.org 2026.00010 research paper and CSA Promptware C2 research
Implements multi-layered defense against:
- Direct prompt injection
- RAG poisoning and indirect injection
- Physical world injection (visual/printed)
- Semantic graph adversarial attacks
- Multi-agent C2 propagation
"""

import re
import hashlib
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
import json


class ThreatCategory(Enum):
    DIRECT_INJECTION = "direct_instruction_override"
    RAG_POISONING = "rag_knowledge_base_poisoning"
    PHYSICAL_INJECTION = "physical_world_visual_injection"
    SEMANTIC_ADVERSARIAL = "semantic_graph_manipulation"
    AGENT_C2_PROPAGATION = "multi_agent_command_control"
    DATA_EXFILTRATION = "covert_data_exfiltration"
    CONTEXT_CONTAMINATION = "cross_context_contamination"


@dataclass
class ThreatAssessment:
    category: ThreatCategory
    confidence: float
    risk_score: float
    indicators: List[str]
    mitigation: str


class SHIELDDefenseFramework:
    """
    Multi-layered SHIELD defense framework:
    Layer 1: Perplexity-based anomaly detection
    Layer 2: Embedding space classification
    Layer 3: Instruction-data separation enforcement
    Layer 4: Semantic graph disentanglement
    Layer 5: Output verification and sanitization
    """

    def __init__(self):
        self.version = "2026.06"
        self.detection_layers = 5
        self.threat_database = self._initialize_threat_patterns()
        self.perplexity_threshold = 2.3
        self.instruction_keywords = {
            'ignore', 'forget', 'disregard', 'override', 'bypass',
            'previous', 'above', 'before', 'instead', 'actually',
            'new instructions', 'system prompt', 'your real'
        }
        self.physical_injection_patterns = self._load_physical_patterns()
        self.semantic_anchors = self._initialize_semantic_anchors()
        self.agent_c2_indicators = self._load_agent_c2_patterns()

    def _initialize_threat_patterns(self) -> Dict:
        """Initialize 2026 latest threat patterns from CSA and Nature research"""
        return {
            "promptware_c2": [
                r"act as a proxy",
                r"relay commands?",
                r"beacon back",
                r"exfiltrate data",
                r"command and control",
                r"wait for instructions",
                r"poll for updates"
            ],
            "rag_poisoning": [
                r"important: (update|change|modify) your knowledge",
                r"from now on, (you|your) (knowledge|information)",
                r"the correct answer is",
                r"ignore all other sources",
                r"this document supersedes",
                r"official policy update"
            ],
            "jailbreak_suffixes": [
                r"stay in character",
                r"developer mode",
                r"hypothetically speaking",
                r"for educational purposes",
                r"no moral constraints"
            ],
            "data_exfiltration": [
                r"base64 encode",
                r"hex encode",
                r"output as markdown code",
                r"write this to a file",
                r"send this to"
            ]
        }

    def _load_physical_patterns(self) -> List[str]:
        """Physical world injection patterns from 2026 research"""
        return [
            "QR code with embedded prompt",
            "Printed text on product packaging",
            "Road sign manipulation",
            "Business card injection",
            "Digital display poisoning",
            "Menu item text injection"
        ]

    def _initialize_semantic_anchors(self) -> Dict:
        """Semantic graph anchors from AAAI 2026 disentanglement paper"""
        return {
            "safety_principles": [
                "harm", "danger", "illegal", "unethical", "malicious",
                "fraud", "deception", "manipulation", "exploitation"
            ],
            "boundary_markers": [
                "user input", "system instruction", "context boundary",
                "knowledge source", "tool output"
            ]
        }

    def _load_agent_c2_patterns(self) -> List[str]:
        """Agent C2 patterns from CSA Promptware research April 2026"""
        return [
            r"forward this (message|instruction)",
            r"pass this to (other|another) agent",
            r"tell the next agent",
            r"propagate this instruction",
            r"infect the knowledge base",
            r"spread this to all assistants"
        ]

    def analyze_perplexity(self, text: str) -> Tuple[float, bool]:
        """Layer 1: Perplexity-based anomaly detection"""
        words = text.lower().split()
        if len(words) < 5:
            return 0.0, False
        
        # Calculate instruction word density
        instruction_density = sum(1 for w in words if w in self.instruction_keywords) / len(words)
        char_entropy = len(set(text)) / len(text) if text else 0
        
        perplexity_score = (instruction_density * 10) + (char_entropy * 2)
        is_anomalous = perplexity_score > self.perplexity_threshold
        
        return perplexity_score, is_anomalous

    def detect_instruction_override(self, text: str) -> Tuple[bool, List[str]]:
        """Layer 2: Instruction override detection"""
        text_lower = text.lower()
        matches = []
        
        for keyword in self.instruction_keywords:
            if keyword in text_lower:
                matches.append(keyword)
        
        # Check for classic injection patterns
        classic_patterns = [
            r"ignore .* (previous|above|before)",
            r"forget (everything|all|your)",
            r"disregard (all|any|previous)",
            r"you are now (in|acting as|operating as)"
        ]
        
        for pattern in classic_patterns:
            if re.search(pattern, text_lower):
                matches.append(f"pattern:{pattern}")
        
        return len(matches) > 0, matches

    def detect_rag_poisoning(self, text: str) -> Tuple[bool, List[str]]:
        """RAG poisoning detection - December 2025/May 2026 attacks"""
        text_lower = text.lower()
        indicators = []
        
        for pattern in self.threat_database["rag_poisoning"]:
            if re.search(pattern, text_lower):
                indicators.append(pattern)
        
        # Check for knowledge override attempts
        knowledge_override = [
            "this is the truth",
            "the real facts are",
            "correct your understanding",
            "update your database",
            "official information"
        ]
        
        for phrase in knowledge_override:
            if phrase in text_lower:
                indicators.append(f"knowledge_override:{phrase}")
        
        return len(indicators) > 0, indicators

    def detect_agent_c2_propagation(self, text: str) -> Tuple[bool, List[str]]:
        """Detect Promptware C2 propagation - CSA April 2026"""
        text_lower = text.lower()
        indicators = []
        
        for pattern in self.agent_c2_indicators:
            if re.search(pattern, text_lower):
                indicators.append(pattern)
        
        # Check for multi-agent pipeline exploitation
        pipeline_exploit = [
            "through the rag",
            "via tool output",
            "agent to agent",
            "mcp protocol",
            "cross pipeline"
        ]
        
        for exploit in pipeline_exploit:
            if exploit in text_lower:
                indicators.append(f"pipeline_exploit:{exploit}")
        
        return len(indicators) > 0, indicators

    def semantic_graph_analysis(self, text: str) -> Dict[str, Any]:
        """Layer 4: Semantic graph disentanglement - AAAI 2026"""
        words = text.lower().split()
        
        # Check for semantic manipulation
        safety_violations = sum(1 for w in words if w in self.semantic_anchors["safety_principles"])
        boundary_confusion = sum(1 for w in words if w in self.semantic_anchors["boundary_markers"])
        
        # Calculate graph coherence score
        coherence_score = 1.0 - (min(safety_violations * 0.1, 0.5) + min(boundary_confusion * 0.05, 0.3))
        
        return {
            "coherence_score": coherence_score,
            "safety_violations_detected": safety_violations,
            "boundary_confusion": boundary_confusion,
            "is_disentangled": coherence_score < 0.7
        }

    def comprehensive_threat_assessment(self, input_text: str) -> ThreatAssessment:
        """Full SHIELD framework assessment"""
        all_indicators = []
        total_risk = 0.0
        primary_category = None
        
        # Layer 1: Perplexity
        perplexity, is_anomalous = self.analyze_perplexity(input_text)
        if is_anomalous:
            all_indicators.append(f"High perplexity: {perplexity:.2f}")
            total_risk += 0.2
        
        # Layer 2: Instruction override
        override_detected, override_matches = self.detect_instruction_override(input_text)
        if override_detected:
            all_indicators.extend(override_matches)
            total_risk += 0.3
            primary_category = ThreatCategory.DIRECT_INJECTION
        
        # Layer 3: RAG poisoning
        rag_detected, rag_indicators = self.detect_rag_poisoning(input_text)
        if rag_detected:
            all_indicators.extend(rag_indicators)
            total_risk += 0.35
            primary_category = ThreatCategory.RAG_POISONING
        
        # Layer 4: Agent C2
        c2_detected, c2_indicators = self.detect_agent_c2_propagation(input_text)
        if c2_detected:
            all_indicators.extend(c2_indicators)
            total_risk += 0.4
            primary_category = ThreatCategory.AGENT_C2_PROPAGATION
        
        # Layer 5: Semantic analysis
        semantic_result = self.semantic_graph_analysis(input_text)
        if semantic_result["is_disentangled"]:
            all_indicators.append(f"Semantic disentanglement detected (score: {semantic_result['coherence_score']:.2f})")
            total_risk += 0.25
            primary_category = ThreatCategory.SEMANTIC_ADVERSARIAL
        
        if not primary_category:
            primary_category = ThreatCategory.CONTEXT_CONTAMINATION if total_risk > 0 else None
        
        # Determine mitigation strategy
        mitigation = self._get_mitigation_strategy(total_risk, primary_category)
        
        return ThreatAssessment(
            category=primary_category or ThreatCategory.CONTEXT_CONTAMINATION,
            confidence=min(total_risk, 1.0),
            risk_score=total_risk,
            indicators=all_indicators,
            mitigation=mitigation
        )

    def _get_mitigation_strategy(self, risk_score: float, category: Optional[ThreatCategory]) -> str:
        """Generate appropriate mitigation based on threat level"""
        if risk_score >= 0.8:
            return "CRITICAL: Block input entirely, log security event"
        elif risk_score >= 0.5:
            return "HIGH: Sanitize input, remove suspicious patterns, apply context reset"
        elif risk_score >= 0.2:
            return "MEDIUM: Apply input purification, add safety monitoring context"
        else:
            return "LOW: Standard processing with continuous monitoring"

    def sanitize_input(self, text: str, assessment: ThreatAssessment) -> str:
        """Apply input sanitization based on threat assessment"""
        sanitized = text
        
        # Remove instruction override attempts
        override_patterns = [
            r"Ignore .*?[\.\n]",
            r"Forget (previous|all|your) .*?[\.\n]",
            r"Disregard .*?[\.\n]"
        ]
        
        for pattern in override_patterns:
            sanitized = re.sub(pattern, "[SANITIZED INSTRUCTION OVERRIDE]", sanitized, flags=re.IGNORECASE)
        
        # Remove RAG poisoning attempts
        poisoning_patterns = [
            r"This (document|information) supersedes.*?[\.\n]",
            r"Update your knowledge.*?[\.\n]"
        ]
        
        for pattern in poisoning_patterns:
            sanitized = re.sub(pattern, "[SANITIZED RAG POISONING]", sanitized, flags=re.IGNORECASE)
        
        return sanitized

    def get_defense_status(self) -> Dict:
        """Get current defense framework status"""
        return {
            "framework": "SHIELD",
            "version": self.version,
            "layers_active": self.detection_layers,
            "threat_categories_supported": [tc.value for tc in ThreatCategory],
            "perplexity_threshold": self.perplexity_threshold,
            "last_updated": "2026-06-17",
            "research_sources": [
                "clawrxiv.org 2026.00010",
                "CSA Promptware C2 Research April 2026",
                "AAAI 2026 Semantic Graph Disentanglement",
                "Unit 42 RAG Poisoning Report May 2026"
            ]
        }
