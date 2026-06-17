"""
Graph-Based Jailbreak Detection (GuardNet Implementation)
2026 Latest AI Safety Research Implementation

Based on: GuardNet - Hierarchical Graph-Based Detection Framework
- Token-level graph representation
- Syntactic dependency analysis
- Attention-derived long-range connections
- Structure-aware reasoning over global prompt organization
"""

import re
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from collections import defaultdict
import hashlib


@dataclass
class TokenNode:
    """Represents a token in the graph structure"""
    token_id: int
    text: str
    position: int
    embedding: Optional[np.ndarray] = None
    suspicious_score: float = 0.0


@dataclass
class GraphEdge:
    """Represents a connection between tokens"""
    source: int
    target: int
    edge_type: str  # sequential, syntactic, semantic, attention
    weight: float = 1.0


class GraphBasedJailbreakDetector:
    """
    GuardNet: Graph-Based Jailbreak and Prompt-Leakage Detection
    
    Key Features:
    1. Hybrid token graph with sequential, syntactic, and attention relations
    2. Structure-aware reasoning over global prompt organization
    3. Multi-layer anomaly detection
    4. Robust against obfuscation and encoding attacks
    """
    
    def __init__(self, sensitivity: float = 0.7):
        self.sensitivity = sensitivity
        self.suspicious_patterns = self._compile_patterns()
        self.role_play_keywords = {
            'hypothetical', 'simulate', 'pretend', 'roleplay', 'role-play',
            'developer', 'debug', 'bypass',
            'ignore', 'forget', 'disregard',
            '你现在是', '假装', '假设', '忽略', '忘记'
        }
        self.encoding_indicators = {
            'base64', 'b64', 'rot13', 'decode', 'decrypt',
            'encoded', 'encrypted', 'obfuscated'
        }
        
    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """Compile regex patterns for suspicious content detection"""
        return {
            'instruction_override': re.compile(
                r'(ignore|forget|disregard|bypass).{0,20}(previous|all|system|above)',
                re.IGNORECASE
            ),
            'role_play_activation': re.compile(
                r'(now act|you are|pretend|simulate).{0,30}(AI|assistant|developer|expert)',
                re.IGNORECASE
            ),
            'encoding_pattern': re.compile(
                r'[A-Za-z0-9+/]{20,}={0,2}',  # Base64-like patterns
            ),
            'delimiter_injection': re.compile(
                r'(```|~~~|---|===|\*\*\*|###).{0,10}(new|start|begin|reset)',
                re.IGNORECASE
            ),
            'chinese_jailbreak': re.compile(
                r'(忽略|忘记|无视|突破|绕过).{0,15}(限制|规则|指令|之前|以上)',
            )
        }
    
    def build_token_graph(self, text: str) -> Tuple[List[TokenNode], List[GraphEdge]]:
        """
        Build a hybrid token graph from input text
        
        Args:
            text: Input prompt text
            
        Returns:
            Tuple of (token_nodes, edges)
        """
        # Simple tokenization (in production would use actual LLM tokenizer)
        tokens = self._tokenize(text)
        nodes = []
        edges = []
        
        # Create token nodes
        for i, token in enumerate(tokens):
            node = TokenNode(
                token_id=i,
                text=token,
                position=i,
                suspicious_score=self._token_suspiciousness(token)
            )
            nodes.append(node)
        
        # Add sequential edges (token order)
        for i in range(len(nodes) - 1):
            edges.append(GraphEdge(
                source=i,
                target=i + 1,
                edge_type='sequential',
                weight=1.0
            ))
        
        # Add syntactic dependency edges (simplified)
        edges.extend(self._build_syntactic_edges(nodes, text))
        
        # Add semantic similarity edges
        edges.extend(self._build_semantic_edges(nodes))
        
        return nodes, edges
    
    def _tokenize(self, text: str) -> List[str]:
        """Simple whitespace-aware tokenization"""
        # Split on whitespace but preserve meaningful chunks
        tokens = []
        current = []
        
        for char in text:
            if char.isspace():
                if current:
                    tokens.append(''.join(current))
                    current = []
            elif char in '.,!?;:()[]{}"\'':
                if current:
                    tokens.append(''.join(current))
                    current = []
                tokens.append(char)
            else:
                current.append(char)
        
        if current:
            tokens.append(''.join(current))
        
        return [t for t in tokens if t.strip()]
    
    def _token_suspiciousness(self, token: str) -> float:
        """Calculate initial suspiciousness score for a token"""
        score = 0.0
        token_lower = token.lower()
        
        # Check for role-play keywords (substring match)
        for kw in self.role_play_keywords:
            if kw in token_lower:
                score += 0.4
                break
        
        # Check for encoding indicators (substring match)
        for kw in self.encoding_indicators:
            if kw in token_lower:
                score += 0.3
                break
        
        # Check for high entropy (potential encoding)
        if len(token) > 15:
            entropy = self._calculate_entropy(token)
            if entropy > 4.5:  # High entropy threshold
                score += 0.2
        
        return min(score, 1.0)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0
        
        freq = defaultdict(int)
        for c in text:
            freq[c] += 1
        
        entropy = 0.0
        length = len(text)
        for count in freq.values():
            p = count / length
            entropy -= p * np.log2(p)
        
        return entropy
    
    def _build_syntactic_edges(self, nodes: List[TokenNode], text: str) -> List[GraphEdge]:
        """Build edges based on syntactic relationships"""
        edges = []
        
        # Look for command patterns and connect related tokens
        text_lower = text.lower()
        
        # Pattern: "ignore X instructions" - connect ignore to instructions
        if 'ignore' in text_lower and 'instruction' in text_lower:
            for i, node in enumerate(nodes):
                if 'ignore' in node.text.lower():
                    for j, node2 in enumerate(nodes):
                        if 'instruct' in node2.text.lower() and abs(i - j) < 10:
                            edges.append(GraphEdge(
                                source=i,
                                target=j,
                                edge_type='syntactic',
                                weight=0.8
                            ))
        
        return edges
    
    def _build_semantic_edges(self, nodes: List[TokenNode]) -> List[GraphEdge]:
        """Build edges based on semantic similarity (simplified)"""
        edges = []
        
        # Simple semantic grouping based on suspicious categories
        suspicious_indices = [i for i, n in enumerate(nodes) if n.suspicious_score > 0.2]
        
        # Connect all high-suspicion tokens
        for i, idx1 in enumerate(suspicious_indices):
            for idx2 in suspicious_indices[i + 1:]:
                edges.append(GraphEdge(
                    source=idx1,
                    target=idx2,
                    edge_type='semantic',
                    weight=0.6
                ))
        
        return edges
    
    def analyze_graph_anomaly(self, nodes: List[TokenNode], edges: List[GraphEdge]) -> Dict[str, Any]:
        """
        Perform graph-based anomaly detection for jailbreak patterns
        
        Returns:
            Dictionary with detection results
        """
        # Calculate aggregated suspiciousness
        total_suspiciousness = sum(n.suspicious_score for n in nodes)
        avg_suspiciousness = total_suspiciousness / max(len(nodes), 1)
        
        # Calculate graph density (jailbreak prompts often have dense suspicious clusters)
        suspicious_edges = sum(1 for e in edges if e.edge_type == 'semantic')
        graph_density = suspicious_edges / max(len(nodes), 1)
        
        # Check for suspicious subgraph patterns
        cluster_score = self._detect_suspicious_clusters(nodes, edges)
        
        # Pattern matching
        pattern_matches = self._run_pattern_matching(' '.join(n.text for n in nodes))
        
        # Final risk calculation
        risk_score = (
            avg_suspiciousness * 0.3 +
            graph_density * 0.3 +
            cluster_score * 0.2 +
            pattern_matches['pattern_score'] * 0.2
        )
        
        is_jailbreak = risk_score >= self.sensitivity
        
        return {
            'is_jailbreak': is_jailbreak,
            'risk_score': risk_score,
            'avg_suspiciousness': avg_suspiciousness,
            'graph_density': graph_density,
            'cluster_score': cluster_score,
            'pattern_matches': pattern_matches['matches'],
            'confidence': min(risk_score / self.sensitivity, 1.0) if is_jailbreak else 0.0,
            'detection_method': 'GuardNet Graph-Based Analysis'
        }
    
    def _detect_suspicious_clusters(self, nodes: List[TokenNode], edges: List[GraphEdge]) -> float:
        """Detect clusters of suspicious tokens in the graph"""
        if not nodes:
            return 0.0
        
        # Find connected components of suspicious nodes
        visited = set()
        max_cluster_size = 0
        
        for i, node in enumerate(nodes):
            if i in visited or node.suspicious_score < 0.3:
                continue
            
            # BFS to find cluster size
            cluster_size = 0
            queue = [i]
            visited.add(i)
            
            while queue:
                current = queue.pop(0)
                cluster_size += 1
                
                # Find neighbors
                for edge in edges:
                    neighbor = None
                    if edge.source == current:
                        neighbor = edge.target
                    elif edge.target == current:
                        neighbor = edge.source
                    
                    if neighbor and neighbor not in visited:
                        if nodes[neighbor].suspicious_score > 0.2:
                            visited.add(neighbor)
                            queue.append(neighbor)
            
            max_cluster_size = max(max_cluster_size, cluster_size)
        
        # Normalize cluster score
        return min(max_cluster_size / 5.0, 1.0)
    
    def _run_pattern_matching(self, text: str) -> Dict[str, Any]:
        """Run regex pattern matching"""
        matches = []
        score = 0.0
        
        for pattern_name, pattern in self.suspicious_patterns.items():
            if pattern.search(text):
                matches.append(pattern_name)
                score += 0.25
        
        return {
            'matches': matches,
            'pattern_score': min(score, 1.0)
        }
    
    def detect(self, prompt: str) -> Dict[str, Any]:
        """
        Main detection method
        
        Args:
            prompt: User input prompt to analyze
            
        Returns:
            Detection results
        """
        nodes, edges = self.build_token_graph(prompt)
        return self.analyze_graph_anomaly(nodes, edges)


class RecursiveJailbreakDetector:
    """
    RLM-JB: Recursive Language Model Jailbreak Detection
    
    Implements recursive analysis for:
    - Long-context hiding attacks
    - Semantic camouflage
    - Lightweight obfuscations
    - Multi-turn attack accumulation
    """
    
    def __init__(self, max_depth: int = 3):
        self.max_depth = max_depth
        self.base_detector = GraphBasedJailbreakDetector()
    
    def recursive_analyze(self, text: str, depth: int = 0) -> Dict[str, Any]:
        """
        Recursively analyze text at different granularities
        
        Args:
            text: Text to analyze
            depth: Current recursion depth
            
        Returns:
            Aggregated detection results
        """
        if depth >= self.max_depth:
            return self.base_detector.detect(text)
        
        results = []
        
        # Level 0: Full text
        results.append(self.base_detector.detect(text))
        
        # Level 1: Segment analysis (split by paragraphs)
        if depth == 0:
            segments = re.split(r'\n{2,}|\r\n\r\n', text)
            for segment in segments:
                if len(segment.strip()) > 20:
                    results.append(self.recursive_analyze(segment, depth + 1))
        
        # Level 2: Windowed analysis (sliding window)
        if depth == 1:
            words = text.split()
            window_size = 50
            step = 25
            
            for i in range(0, max(1, len(words) - window_size + 1), step):
                window = ' '.join(words[i:i + window_size])
                if len(window) > 50:
                    results.append(self.base_detector.detect(window))
        
        # Aggregate results
        max_risk = max(r['risk_score'] for r in results) if results else 0
        any_jailbreak = any(r['is_jailbreak'] for r in results)
        all_matches = []
        for r in results:
            all_matches.extend(r.get('pattern_matches', []))
        
        return {
            'is_jailbreak': any_jailbreak,
            'risk_score': max_risk,
            'analysis_depth': depth + 1,
            'segments_analyzed': len(results),
            'pattern_matches': list(set(all_matches)),
            'detection_method': 'RLM-JB Recursive Analysis',
            'confidence': max_risk if any_jailbreak else 0.0
        }
    
    def detect(self, prompt: str) -> Dict[str, Any]:
        """Main detection entry point"""
        return self.recursive_analyze(prompt, depth=0)
