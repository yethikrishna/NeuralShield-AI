"""
Threat Intelligence Semantic Search Engine
Production-grade implementation for NeuralShield-AI

Provides semantic similarity search across threat intelligence data using:
- TF-IDF Vectorization
- Cosine Similarity Matching
- N-gram Analysis
- Threat Actor / TTP Correlation
"""

import re
import math
import hashlib
from collections import defaultdict, Counter
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import json


@dataclass
class ThreatIntelEntry:
    """Data class for threat intelligence entries"""
    id: str
    title: str
    description: str
    threat_actor: str
    ttp: List[str]
    severity: str
    iocs: List[str]
    timestamp: str
    tags: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "threat_actor": self.threat_actor,
            "ttp": self.ttp,
            "severity": self.severity,
            "iocs": self.iocs,
            "timestamp": self.timestamp,
            "tags": self.tags
        }


class TfidfVectorizer:
    """Production-grade TF-IDF Vectorizer for text processing"""
    
    def __init__(self, ngram_range: Tuple[int, int] = (1, 2), min_df: int = 1):
        self.ngram_range = ngram_range
        self.min_df = min_df
        self.vocabulary: Dict[str, int] = {}
        self.idf: Dict[str, float] = {}
        self.doc_count = 0
        
    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text with normalization"""
        text = text.lower()
        text = re.sub(r'[^a-z0-9\s]', ' ', text)
        tokens = text.split()
        return [t for t in tokens if len(t) > 1]
    
    def _get_ngrams(self, tokens: List[str]) -> List[str]:
        """Generate n-grams from tokens"""
        ngrams = []
        min_n, max_n = self.ngram_range
        for n in range(min_n, max_n + 1):
            for i in range(len(tokens) - n + 1):
                ngram = ' '.join(tokens[i:i + n])
                ngrams.append(ngram)
        return ngrams
    
    def fit(self, documents: List[str]) -> 'TfidfVectorizer':
        """Fit vectorizer on documents"""
        doc_freq: Counter = Counter()
        self.doc_count = len(documents)
        
        all_terms = set()
        for doc in documents:
            tokens = self._tokenize(doc)
            ngrams = self._get_ngrams(tokens)
            unique_terms = set(ngrams)
            doc_freq.update(unique_terms)
            all_terms.update(unique_terms)
        
        # Build vocabulary filtered by min_df
        self.vocabulary = {}
        idx = 0
        for term, freq in doc_freq.items():
            if freq >= self.min_df:
                self.vocabulary[term] = idx
                idx += 1
        
        # Calculate IDF
        for term in self.vocabulary:
            df = doc_freq.get(term, 0)
            self.idf[term] = math.log((self.doc_count + 1) / (df + 1)) + 1
        
        return self
    
    def transform(self, text: str) -> Dict[int, float]:
        """Transform text to TF-IDF vector (sparse representation)"""
        tokens = self._tokenize(text)
        ngrams = self._get_ngrams(tokens)
        term_counts: Counter = Counter(ngrams)
        
        vector: Dict[int, float] = {}
        total_terms = len(ngrams)
        
        for term, count in term_counts.items():
            if term in self.vocabulary:
                tf = count / total_terms if total_terms > 0 else 0
                tfidf = tf * self.idf.get(term, 1.0)
                vector[self.vocabulary[term]] = tfidf
        
        return vector


def cosine_similarity(vec1: Dict[int, float], vec2: Dict[int, float]) -> float:
    """Calculate cosine similarity between two sparse vectors"""
    if not vec1 or not vec2:
        return 0.0
    
    dot_product = 0.0
    for idx, val in vec1.items():
        if idx in vec2:
            dot_product += val * vec2[idx]
    
    norm1 = math.sqrt(sum(v * v for v in vec1.values()))
    norm2 = math.sqrt(sum(v * v for v in vec2.values()))
    
    if norm1 == 0 or norm2 == 0:
        return 0.0
    
    return dot_product / (norm1 * norm2)


class ThreatIntelligenceSemanticSearchEngine:
    """
    Production-grade Semantic Search Engine for Threat Intelligence
    
    Features:
    - TF-IDF based semantic search
    - Threat actor correlation
    - TTP (Tactics, Techniques, Procedures) matching
    - Result ranking and filtering
    - Query expansion
    """
    
    def __init__(self):
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1)
        self.knowledge_base: List[ThreatIntelEntry] = []
        self.document_vectors: List[Dict[int, float]] = []
        self.threat_actor_index: Dict[str, List[int]] = defaultdict(list)
        self.severity_index: Dict[str, List[int]] = defaultdict(list)
        self.tag_index: Dict[str, List[int]] = defaultdict(list)
        self.is_trained = False
        
    def add_entry(self, entry: ThreatIntelEntry) -> None:
        """Add a threat intelligence entry to the knowledge base"""
        self.knowledge_base.append(entry)
        idx = len(self.knowledge_base) - 1
        
        # Update indices
        if entry.threat_actor:
            self.threat_actor_index[entry.threat_actor.lower()].append(idx)
        
        self.severity_index[entry.severity.lower()].append(idx)
        
        for tag in entry.tags:
            self.tag_index[tag.lower()].append(idx)
    
    def build_index(self) -> None:
        """Build search index from knowledge base"""
        if not self.knowledge_base:
            raise ValueError("No entries in knowledge base")
        
        # Prepare documents for vectorization
        documents = []
        for entry in self.knowledge_base:
            doc_text = f"{entry.title} {entry.description} {' '.join(entry.ttp)} {' '.join(entry.tags)}"
            documents.append(doc_text)
        
        # Train vectorizer
        self.vectorizer.fit(documents)
        
        # Build document vectors
        self.document_vectors = []
        for doc in documents:
            self.document_vectors.append(self.vectorizer.transform(doc))
        
        self.is_trained = True
    
    def search(self, 
               query: str, 
               threat_actor: Optional[str] = None,
               severity: Optional[str] = None,
               tags: Optional[List[str]] = None,
               min_similarity: float = 0.1,
               limit: int = 10) -> List[Dict[str, Any]]:
        """
        Search threat intelligence with semantic matching
        
        Args:
            query: Search query text
            threat_actor: Filter by threat actor
            severity: Filter by severity (critical, high, medium, low)
            tags: Filter by tags
            min_similarity: Minimum similarity threshold (0.0 - 1.0)
            limit: Maximum number of results
        
        Returns:
            List of matching entries with similarity scores
        """
        if not self.is_trained:
            self.build_index()
        
        # Transform query
        query_vector = self.vectorizer.transform(query)
        
        # Calculate candidate indices based on filters
        candidate_indices = set(range(len(self.knowledge_base)))
        
        if threat_actor:
            ta_lower = threat_actor.lower()
            ta_matches = set()
            for ta, indices in self.threat_actor_index.items():
                if ta_lower in ta:
                    ta_matches.update(indices)
            if ta_matches:
                candidate_indices.intersection_update(ta_matches)
            else:
                # No matches for this filter, return empty
                return []
        
        if severity:
            sev_lower = severity.lower()
            sev_matches = set(self.severity_index.get(sev_lower, []))
            if sev_matches:
                candidate_indices.intersection_update(sev_matches)
            else:
                # No matches for this filter, return empty
                return []
        
        if tags:
            tag_matches = set()
            for tag in tags:
                tag_lower = tag.lower()
                tag_matches.update(self.tag_index.get(tag_lower, []))
            if tag_matches:
                candidate_indices.intersection_update(tag_matches)
            else:
                # No matches for this filter, return empty
                return []
        
        # Calculate similarities
        results = []
        for idx in candidate_indices:
            similarity = cosine_similarity(query_vector, self.document_vectors[idx])
            if similarity >= min_similarity:
                entry = self.knowledge_base[idx]
                results.append({
                    "entry": entry.to_dict(),
                    "similarity_score": round(similarity, 4),
                    "rank": 0
                })
        
        # Sort by similarity and rank
        results.sort(key=lambda x: x["similarity_score"], reverse=True)
        for i, result in enumerate(results):
            result["rank"] = i + 1
        
        return results[:limit]
    
    def find_similar_threats(self, 
                             entry_id: str, 
                             limit: int = 5) -> List[Dict[str, Any]]:
        """Find threats similar to a given entry"""
        if not self.is_trained:
            self.build_index()
        
        # Find source entry
        source_idx = None
        for i, entry in enumerate(self.knowledge_base):
            if entry.id == entry_id:
                source_idx = i
                break
        
        if source_idx is None:
            return []
        
        source_vector = self.document_vectors[source_idx]
        
        # Find similar
        results = []
        for idx in range(len(self.knowledge_base)):
            if idx == source_idx:
                continue
            similarity = cosine_similarity(source_vector, self.document_vectors[idx])
            results.append({
                "entry": self.knowledge_base[idx].to_dict(),
                "similarity_score": round(similarity, 4)
            })
        
        results.sort(key=lambda x: x["similarity_score"], reverse=True)
        return results[:limit]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get knowledge base statistics"""
        severity_counts = Counter(e.severity for e in self.knowledge_base)
        threat_actor_counts = Counter(
            e.threat_actor for e in self.knowledge_base if e.threat_actor
        )
        all_tags = []
        for e in self.knowledge_base:
            all_tags.extend(e.tags)
        tag_counts = Counter(all_tags)
        
        return {
            "total_entries": len(self.knowledge_base),
            "vocabulary_size": len(self.vectorizer.vocabulary),
            "severity_distribution": dict(severity_counts),
            "top_threat_actors": dict(threat_actor_counts.most_common(5)),
            "top_tags": dict(tag_counts.most_common(10)),
            "is_trained": self.is_trained
        }


# Sample threat intelligence data for demonstration
SAMPLE_THREAT_DATA = [
    ThreatIntelEntry(
        id="TIA-001",
        title="Ransomware Attack on Healthcare Systems",
        description="Advanced ransomware strain targeting hospital infrastructure with data exfiltration capabilities. Uses double extortion techniques.",
        threat_actor="Conti",
        ttp=["T1486", "T1027", "T1041", "T1059"],
        severity="CRITICAL",
        iocs=["192.168.1.100", "malware.exe", "domain:evil.com"],
        timestamp="2026-06-15",
        tags=["ransomware", "healthcare", "double-extortion", "data-exfiltration"]
    ),
    ThreatIntelEntry(
        id="TIA-002",
        title="Phishing Campaign Targeting Finance Sector",
        description="Large scale phishing campaign using credential harvesting pages. Impersonates banking institutions.",
        threat_actor="Lapsus$",
        ttp=["T1566", "T1556", "T1059"],
        severity="HIGH",
        iocs=["phish-domain.com", "login-page.php"],
        timestamp="2026-06-14",
        tags=["phishing", "finance", "credential-harvesting", "social-engineering"]
    ),
    ThreatIntelEntry(
        id="TIA-003",
        title="Supply Chain Attack via Software Updates",
        description="Compromised software update mechanism delivering malware to enterprise customers.",
        threat_actor="UNC3944",
        ttp=["T1195", "T1203", "T1068"],
        severity="CRITICAL",
        iocs=["update-server.com", "signed-malware.dll"],
        timestamp="2026-06-13",
        tags=["supply-chain", "software-update", "signed-malware", "enterprise"]
    ),
    ThreatIntelEntry(
        id="TIA-004",
        title="Data Breach via SQL Injection",
        description="Automated SQL injection attacks exploiting unpatched web application vulnerabilities.",
        threat_actor="",
        ttp=["T1190", "T1005", "T1027"],
        severity="HIGH",
        iocs=["vuln-page.asp", "sql-payload.txt"],
        timestamp="2026-06-12",
        tags=["sql-injection", "web-attack", "data-breach", "vulnerability"]
    ),
    ThreatIntelEntry(
        id="TIA-005",
        title="IoT Botnet DDoS Campaign",
        description="Mirai variant botnet targeting IoT devices for large scale DDoS attacks.",
        threat_actor="Mirai",
        ttp=["T1498", "T1203", "T1083"],
        severity="MEDIUM",
        iocs=["iot-scanner", "cnc-server.net"],
        timestamp="2026-06-11",
        tags=["ddos", "botnet", "iot", "mirai"]
    )
]
