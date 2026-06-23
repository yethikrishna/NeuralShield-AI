"""
Threat Intelligence Semantic Vector Search Engine v20
NeuralShield AI - Dimension A Feature Expansion

Provides semantic similarity search capabilities for threat intelligence
using vector embeddings and cosine similarity matching. Enables finding
semantically similar threats, IOCs, and attack patterns even when exact
string matches don't exist.

STABLE API - Production Ready
"""

import hashlib
import heapq
import math
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime, timedelta


@dataclass
class VectorEmbedding:
    """Represents a vector embedding for semantic search."""
    vector: List[float]
    dimension: int
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SearchResult:
    """Result from semantic search query."""
    document_id: str
    similarity_score: float
    content: str
    threat_type: str
    severity: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class SemanticVectorizer:
    """
    Converts text content into semantic vector embeddings
    using term frequency-inverse document frequency with
    n-gram support for threat intelligence domain.
    """

    def __init__(self, dimension: int = 128):
        self.dimension = dimension
        self._lock = threading.Lock()
        self._term_vocabulary: Dict[str, int] = {}
        self._document_frequencies: Dict[str, int] = {}
        self._total_documents = 0
        self._stop_words = self._build_threat_intel_stop_words()
        self._initialize_vocabulary()

    def _build_threat_intel_stop_words(self) -> Set[str]:
        """Build domain-specific stop words for threat intelligence."""
        return {
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to',
            'for', 'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be',
            'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did',
            'will', 'would', 'could', 'should', 'may', 'might', 'must',
            'shall', 'can', 'need', 'dare', 'ought', 'used', 'i', 'you',
            'he', 'she', 'it', 'we', 'they', 'me', 'him', 'her', 'us',
            'them', 'my', 'your', 'his', 'its', 'our', 'their', 'this',
            'that', 'these', 'those', 'as', 'if', 'than', 'because',
            'while', 'until', 'unless', 'since', 'so', 'though', 'although',
            'even', 'just', 'also', 'too', 'very', 'much', 'many', 'more',
            'most', 'some', 'any', 'no', 'not', 'only', 'own', 'same',
            'such', 'no', 'nor', 'not', 'only', 'own', 'same', 'so',
            'than', 'too', 'very', 'just', 'also', 'now', 'here', 'there',
            'when', 'where', 'why', 'how', 'all', 'each', 'few', 'more',
            'most', 'other', 'some', 'such', 'no', 'nor', 'not', 'only'
        }

    def _initialize_vocabulary(self) -> None:
        """Initialize threat intelligence domain vocabulary."""
        threat_terms = [
            'malware', 'ransomware', 'phishing', 'exploit', 'vulnerability',
            'cve', 'attack', 'breach', 'compromise', 'injection', 'sql',
            'xss', 'csrf', 'ddos', 'botnet', 'trojan', 'virus', 'worm',
            'rootkit', 'backdoor', 'keylogger', 'spyware', 'adware',
            'zero-day', '0day', 'apt', 'threat', 'actor', 'ioc', 'indicator',
            'hash', 'ip', 'domain', 'url', 'email', 'payload', 'shellcode',
            'buffer', 'overflow', 'heap', 'stack', 'privilege', 'escalation',
            'lateral', 'movement', 'persistence', 'exfiltration', 'tunneling',
            'encryption', 'decryption', 'obfuscation', 'packer', 'unpacker',
            'sandbox', 'emulation', 'heuristic', 'signature', 'anomaly',
            'behavioral', 'static', 'dynamic', 'forensics', 'incident',
            'response', 'mitigation', 'remediation', 'hunting', 'detection',
            'prevention', 'protection', 'defense', 'firewall', 'ids', 'ips',
            'edr', 'xdr', 'siem', 'soar', 'ueba', 'threatfeed', 'osint',
            'mitre', 'attack', 'tactic', 'technique', 'procedure', 'ttp'
        ]
        
        with self._lock:
            for idx, term in enumerate(threat_terms):
                self._term_vocabulary[term] = idx % self.dimension

    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text with threat intelligence awareness."""
        text = text.lower()
        tokens = re.findall(r'[a-z0-9_-]+', text)
        return [t for t in tokens if t not in self._stop_words and len(t) > 2]

    def _compute_tf(self, tokens: List[str]) -> Dict[str, float]:
        """Compute term frequency."""
        tf: Dict[str, float] = {}
        total = len(tokens)
        if total == 0:
            return tf
        
        for token in tokens:
            tf[token] = tf.get(token, 0) + 1.0 / total
        return tf

    def vectorize(self, text: str, metadata: Optional[Dict[str, Any]] = None) -> VectorEmbedding:
        """Convert text to semantic vector embedding."""
        tokens = self._tokenize(text)
        tf = self._compute_tf(tokens)
        
        vector = [0.0] * self.dimension
        
        with self._lock:
            for token, weight in tf.items():
                if token in self._term_vocabulary:
                    idx = self._term_vocabulary[token]
                    idf = math.log(1 + self._total_documents / (1 + self._document_frequencies.get(token, 1)))
                    vector[idx] += weight * idf
                else:
                    # Hash-based distribution for unknown terms
                    h = hashlib.md5(token.encode()).hexdigest()
                    idx = int(h[:8], 16) % self.dimension
                    vector[idx] += weight * 0.5
        
        # L2 normalization
        norm = math.sqrt(sum(v * v for v in vector))
        if norm > 0:
            vector = [v / norm for v in vector]
        
        return VectorEmbedding(
            vector=vector,
            dimension=self.dimension,
            metadata=metadata or {}
        )

    def update_document_frequency(self, tokens: List[str]) -> None:
        """Update document frequencies with new document tokens."""
        with self._lock:
            seen = set()
            for token in tokens:
                if token not in seen:
                    seen.add(token)
                    self._document_frequencies[token] = self._document_frequencies.get(token, 0) + 1
            self._total_documents += 1


class SemanticSimilaritySearch:
    """
    Semantic similarity search engine for threat intelligence.
    Uses cosine similarity to find semantically similar documents.
    """

    def __init__(self, vector_dimension: int = 128):
        self.vector_dimension = vector_dimension
        self.vectorizer = SemanticVectorizer(dimension=vector_dimension)
        self._lock = threading.Lock()
        self._documents: Dict[str, Dict[str, Any]] = {}
        self._vectors: Dict[str, VectorEmbedding] = {}
        self._index_built = False
        self._search_cache: Dict[str, List[SearchResult]] = {}
        self._cache_ttl = timedelta(minutes=5)
        self._cache_created: Dict[str, datetime] = {}

    def _cosine_similarity(self, v1: List[float], v2: List[float]) -> float:
        """Compute cosine similarity between two vectors."""
        if len(v1) != len(v2):
            return 0.0
        
        dot_product = sum(a * b for a, b in zip(v1, v2))
        norm1 = math.sqrt(sum(a * a for a in v1))
        norm2 = math.sqrt(sum(b * b for b in v2))
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)

    def add_document(
        self,
        document_id: str,
        content: str,
        threat_type: str = "unknown",
        severity: str = "medium",
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Add a document to the search index."""
        if not document_id or not content:
            return False
        
        doc_metadata = metadata or {}
        
        with self._lock:
            embedding = self.vectorizer.vectorize(content, doc_metadata)
            self._documents[document_id] = {
                'content': content,
                'threat_type': threat_type,
                'severity': severity,
                'metadata': doc_metadata,
                'indexed_at': datetime.utcnow()
            }
            self._vectors[document_id] = embedding
            self._index_built = True
            # Invalidate cache
            self._search_cache.clear()
            self._cache_created.clear()
        
        return True

    def search(
        self,
        query: str,
        top_k: int = 10,
        min_similarity: float = 0.3,
        threat_type_filter: Optional[str] = None,
        severity_filter: Optional[str] = None
    ) -> List[SearchResult]:
        """
        Perform semantic similarity search.
        
        Args:
            query: Search query text
            top_k: Number of results to return
            min_similarity: Minimum similarity threshold (0.0 - 1.0)
            threat_type_filter: Optional filter by threat type
            severity_filter: Optional filter by severity level
            
        Returns:
            List of SearchResult sorted by similarity score
        """
        if not query or top_k <= 0:
            return []
        
        # Check cache
        cache_key = f"{query}:{top_k}:{min_similarity}:{threat_type_filter}:{severity_filter}"
        now = datetime.utcnow()
        
        with self._lock:
            if cache_key in self._search_cache:
                created = self._cache_created.get(cache_key, now)
                if now - created < self._cache_ttl:
                    return self._search_cache[cache_key]
        
        query_vector = self.vectorizer.vectorize(query)
        results: List[SearchResult] = []
        
        with self._lock:
            for doc_id, doc_vector in self._vectors.items():
                doc = self._documents.get(doc_id, {})
                
                # Apply filters
                if threat_type_filter and doc.get('threat_type') != threat_type_filter:
                    continue
                if severity_filter and doc.get('severity') != severity_filter:
                    continue
                
                similarity = self._cosine_similarity(query_vector.vector, doc_vector.vector)
                
                if similarity >= min_similarity:
                    results.append(SearchResult(
                        document_id=doc_id,
                        similarity_score=round(similarity, 4),
                        content=doc.get('content', ''),
                        threat_type=doc.get('threat_type', 'unknown'),
                        severity=doc.get('severity', 'medium'),
                        metadata=doc.get('metadata', {})
                    ))
        
        # Sort by similarity and take top_k
        results.sort(key=lambda x: x.similarity_score, reverse=True)
        results = results[:top_k]
        
        # Cache results
        with self._lock:
            self._search_cache[cache_key] = results
            self._cache_created[cache_key] = now
        
        return results

    def find_similar_by_id(
        self,
        document_id: str,
        top_k: int = 5,
        min_similarity: float = 0.4
    ) -> List[SearchResult]:
        """Find documents similar to an existing indexed document."""
        if document_id not in self._vectors:
            return []
        
        with self._lock:
            doc_vector = self._vectors[document_id]
            doc = self._documents[document_id]
        
        return self.search(
            query=doc.get('content', ''),
            top_k=top_k + 1,  # +1 to exclude self
            min_similarity=min_similarity
        )

    def get_document_count(self) -> int:
        """Get total number of indexed documents."""
        with self._lock:
            return len(self._documents)

    def clear_index(self) -> None:
        """Clear all indexed documents and cache."""
        with self._lock:
            self._documents.clear()
            self._vectors.clear()
            self._search_cache.clear()
            self._cache_created.clear()
            self._index_built = False

    def get_threat_type_distribution(self) -> Dict[str, int]:
        """Get distribution of threat types in the index."""
        distribution: Dict[str, int] = {}
        with self._lock:
            for doc in self._documents.values():
                threat_type = doc.get('threat_type', 'unknown')
                distribution[threat_type] = distribution.get(threat_type, 0) + 1
        return distribution


class ThreatIntelSemanticSearchEngine:
    """
    Main threat intelligence semantic search engine.
    Provides high-level API for threat intelligence semantic search operations.
    """

    def __init__(self, vector_dimension: int = 128):
        self.search_engine = SemanticSimilaritySearch(vector_dimension=vector_dimension)
        self._lock = threading.Lock()
        self._query_history: List[Dict[str, Any]] = []
        self._max_history = 1000

    def index_threat_intel(
        self,
        threat_id: str,
        description: str,
        threat_type: str,
        severity: str,
        iocs: Optional[List[str]] = None,
        ttp_tags: Optional[List[str]] = None
    ) -> bool:
        """
        Index threat intelligence with semantic search support.
        
        Args:
            threat_id: Unique threat identifier
            description: Threat description
            threat_type: Type of threat (malware, phishing, etc.)
            severity: Severity level (low, medium, high, critical)
            iocs: Optional list of IOCs
            ttp_tags: Optional MITRE ATT&CK tags
            
        Returns:
            True if indexed successfully
        """
        # Build enriched content for better semantic matching
        enriched_content = f"{description} "
        if iocs:
            enriched_content += " ".join(iocs) + " "
        if ttp_tags:
            enriched_content += " ".join(ttp_tags)
        
        metadata = {
            'iocs': iocs or [],
            'ttp_tags': ttp_tags or [],
            'indexed_at': datetime.utcnow().isoformat()
        }
        
        return self.search_engine.add_document(
            document_id=threat_id,
            content=enriched_content,
            threat_type=threat_type,
            severity=severity,
            metadata=metadata
        )

    def semantic_search(
        self,
        query: str,
        top_k: int = 10,
        min_similarity: float = 0.3,
        threat_type: Optional[str] = None,
        severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Perform semantic search on threat intelligence.
        
        Returns:
            List of matching threats with similarity scores
        """
        results = self.search_engine.search(
            query=query,
            top_k=top_k,
            min_similarity=min_similarity,
            threat_type_filter=threat_type,
            severity_filter=severity
        )
        
        # Log query
        with self._lock:
            self._query_history.append({
                'query': query,
                'timestamp': datetime.utcnow(),
                'result_count': len(results)
            })
            if len(self._query_history) > self._max_history:
                self._query_history.pop(0)
        
        return [
            {
                'threat_id': r.document_id,
                'similarity_score': r.similarity_score,
                'description': r.content[:200] + '...' if len(r.content) > 200 else r.content,
                'threat_type': r.threat_type,
                'severity': r.severity,
                'metadata': r.metadata
            }
            for r in results
        ]

    def find_related_threats(self, threat_id: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Find semantically related threats."""
        results = self.search_engine.find_similar_by_id(
            document_id=threat_id,
            top_k=top_k
        )
        
        return [
            {
                'threat_id': r.document_id,
                'similarity_score': r.similarity_score,
                'threat_type': r.threat_type,
                'severity': r.severity
            }
            for r in results
            if r.document_id != threat_id  # Exclude self
        ]

    def get_search_statistics(self) -> Dict[str, Any]:
        """Get search engine statistics."""
        with self._lock:
            return {
                'indexed_documents': self.search_engine.get_document_count(),
                'total_queries': len(self._query_history),
                'threat_distribution': self.search_engine.get_threat_type_distribution(),
                'vector_dimension': self.search_engine.vector_dimension
            }


# Export public API
__all__ = [
    'ThreatIntelSemanticSearchEngine',
    'SemanticSimilaritySearch',
    'SemanticVectorizer',
    'VectorEmbedding',
    'SearchResult'
]
