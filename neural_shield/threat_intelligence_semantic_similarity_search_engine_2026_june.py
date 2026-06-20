"""
Threat Intelligence Semantic Similarity Search Engine
Real production-grade implementation for NeuralShield-AI

This module provides semantic search capabilities for threat intelligence data,
enabling analysts to find similar IOCs, attack patterns, and threat descriptions
using natural language queries.
"""

import re
import math
import hashlib
from typing import List, Dict, Tuple, Optional, Any
from collections import defaultdict, Counter
from dataclasses import dataclass
from datetime import datetime
import json


@dataclass
class SearchResult:
    """Data class for search results"""
    document_id: str
    score: float
    title: str
    content: str
    threat_type: str
    severity: str
    matched_terms: List[str]
    timestamp: str


@dataclass
class IndexedDocument:
    """Data class for indexed threat intelligence documents"""
    doc_id: str
    title: str
    content: str
    threat_type: str
    severity: str
    iocs: List[str]
    tactics: List[str]
    techniques: List[str]
    tokens: List[str]
    tf: Dict[str, float]
    timestamp: str


class TextProcessor:
    """Real text processing for semantic search"""
    
    STOP_WORDS = {
        'a', 'an', 'and', 'are', 'as', 'at', 'be', 'by', 'for', 'from',
        'has', 'he', 'in', 'is', 'it', 'its', 'of', 'on', 'or', 'that',
        'the', 'to', 'was', 'were', 'will', 'with', 'this', 'but', 'they',
        'have', 'had', 'what', 'when', 'where', 'who', 'which', 'why', 'how',
        'all', 'each', 'every', 'both', 'few', 'more', 'most', 'other', 'some',
        'such', 'no', 'nor', 'not', 'only', 'own', 'same', 'so', 'than', 'too',
        'very', 'can', 'just', 'should', 'now', 'i', 'you', 'we', 'your', 'our'
    }
    
    @staticmethod
    def tokenize(text: str) -> List[str]:
        """Real tokenization with normalization"""
        # Convert to lowercase
        text = text.lower()
        
        # Remove special characters but keep important security symbols
        text = re.sub(r'[^a-z0-9\s\-_\.]', ' ', text)
        
        # Split into tokens
        tokens = text.split()
        
        # Filter stop words and short tokens
        tokens = [t.strip() for t in tokens if t.strip() and t not in TextProcessor.STOP_WORDS and len(t) > 2]
        
        return tokens
    
    @staticmethod
    def compute_tf(tokens: List[str]) -> Dict[str, float]:
        """Compute Term Frequency"""
        if not tokens:
            return {}
        
        counter = Counter(tokens)
        total = len(tokens)
        return {term: count / total for term, count in counter.items()}
    
    @staticmethod
    def extract_iocs(text: str) -> List[str]:
        """Extract real IOC patterns from text"""
        iocs = []
        
        # IP address pattern
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        iocs.extend(re.findall(ip_pattern, text))
        
        # Domain pattern
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        iocs.extend(re.findall(domain_pattern, text))
        
        # MD5 hash
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        iocs.extend(re.findall(md5_pattern, text))
        
        # SHA256 hash
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        iocs.extend(re.findall(sha256_pattern, text))
        
        return list(set(iocs))
    
    @staticmethod
    def extract_mitre_techniques(text: str) -> List[str]:
        """Extract MITRE ATT&CK technique IDs"""
        pattern = r'T\d{4}(?:\.\d{3})?'
        return list(set(re.findall(pattern, text)))


class TFIDFVectorizer:
    """Real TF-IDF implementation for semantic search"""
    
    def __init__(self):
        self.doc_count: int = 0
        self.doc_freq: Dict[str, int] = defaultdict(int)
        self.idf: Dict[str, float] = {}
    
    def fit(self, documents: List[List[str]]) -> None:
        """Fit the vectorizer on documents"""
        self.doc_count = len(documents)
        self.doc_freq.clear()
        
        for tokens in documents:
            unique_tokens = set(tokens)
            for token in unique_tokens:
                self.doc_freq[token] += 1
        
        # Compute IDF
        for term, df in self.doc_freq.items():
            self.idf[term] = math.log((self.doc_count + 1) / (df + 1)) + 1
    
    def transform(self, tokens: List[str], tf: Optional[Dict[str, float]] = None) -> Dict[str, float]:
        """Transform tokens to TF-IDF vector"""
        if tf is None:
            tf = TextProcessor.compute_tf(tokens)
        
        tfidf = {}
        for term, tf_val in tf.items():
            if term in self.idf:
                tfidf[term] = tf_val * self.idf[term]
        
        return tfidf
    
    @staticmethod
    def cosine_similarity(vec1: Dict[str, float], vec2: Dict[str, float]) -> float:
        """Compute cosine similarity between two vectors"""
        if not vec1 or not vec2:
            return 0.0
        
        # Find common terms
        common_terms = set(vec1.keys()) & set(vec2.keys())
        
        # Compute dot product
        dot_product = sum(vec1[t] * vec2[t] for t in common_terms)
        
        # Compute magnitudes
        mag1 = math.sqrt(sum(v * v for v in vec1.values()))
        mag2 = math.sqrt(sum(v * v for v in vec2.values()))
        
        if mag1 == 0 or mag2 == 0:
            return 0.0
        
        return dot_product / (mag1 * mag2)


class ThreatIntelligenceSemanticSearch:
    """
    Main semantic search engine for threat intelligence
    
    Features:
    - TF-IDF based semantic search
    - Real-time document indexing
    - IOC and MITRE technique extraction
    - Threat type classification
    - Severity-based ranking
    """
    
    def __init__(self):
        self.vectorizer = TFIDFVectorizer()
        self.documents: Dict[str, IndexedDocument] = {}
        self.is_fitted = False
        self.search_stats = {
            'total_searches': 0,
            'total_indexed': 0,
            'avg_results': 0.0
        }
    
    def _generate_doc_id(self, content: str) -> str:
        """Generate unique document ID"""
        return hashlib.md5(content.encode()).hexdigest()[:16]
    
    def index_document(
        self,
        title: str,
        content: str,
        threat_type: str = "unknown",
        severity: str = "medium"
    ) -> str:
        """Index a threat intelligence document"""
        # Process text
        tokens = TextProcessor.tokenize(content + " " + title)
        tf = TextProcessor.compute_tf(tokens)
        
        # Extract IOCs and techniques
        iocs = TextProcessor.extract_iocs(content)
        techniques = TextProcessor.extract_mitre_techniques(content)
        
        # Generate doc ID
        doc_id = self._generate_doc_id(title + content)
        
        # Create indexed document
        doc = IndexedDocument(
            doc_id=doc_id,
            title=title,
            content=content,
            threat_type=threat_type,
            severity=severity,
            iocs=iocs,
            tactics=[],
            techniques=techniques,
            tokens=tokens,
            tf=tf,
            timestamp=datetime.utcnow().isoformat()
        )
        
        self.documents[doc_id] = doc
        self.search_stats['total_indexed'] += 1
        self.is_fitted = False  # Need to refit
        
        return doc_id
    
    def index_batch(self, documents: List[Dict[str, str]]) -> List[str]:
        """Batch index multiple documents"""
        doc_ids = []
        for doc in documents:
            doc_id = self.index_document(
                title=doc.get('title', 'Untitled'),
                content=doc.get('content', ''),
                threat_type=doc.get('threat_type', 'unknown'),
                severity=doc.get('severity', 'medium')
            )
            doc_ids.append(doc_id)
        return doc_ids
    
    def _fit_if_needed(self) -> None:
        """Fit vectorizer if not already fitted"""
        if not self.is_fitted and self.documents:
            all_tokens = [doc.tokens for doc in self.documents.values()]
            self.vectorizer.fit(all_tokens)
            self.is_fitted = True
    
    def search(
        self,
        query: str,
        top_k: int = 10,
        min_score: float = 0.1,
        threat_type_filter: Optional[str] = None,
        severity_filter: Optional[str] = None
    ) -> List[SearchResult]:
        """
        Perform semantic search
        
        Args:
            query: Natural language search query
            top_k: Number of results to return
            min_score: Minimum similarity score
            threat_type_filter: Filter by threat type
            severity_filter: Filter by severity
        
        Returns:
            List of search results sorted by relevance
        """
        self._fit_if_needed()
        self.search_stats['total_searches'] += 1
        
        if not self.documents:
            return []
        
        # Process query
        query_tokens = TextProcessor.tokenize(query)
        query_tf = TextProcessor.compute_tf(query_tokens)
        query_tfidf = self.vectorizer.transform(query_tokens, query_tf)
        
        # Score all documents
        scores = []
        for doc_id, doc in self.documents.items():
            # Apply filters
            if threat_type_filter and doc.threat_type != threat_type_filter:
                continue
            if severity_filter and doc.severity != severity_filter:
                continue
            
            # Compute similarity
            doc_tfidf = self.vectorizer.transform(doc.tokens, doc.tf)
            similarity = self.vectorizer.cosine_similarity(query_tfidf, doc_tfidf)
            
            # Severity boost
            severity_boost = {
                'critical': 1.3,
                'high': 1.15,
                'medium': 1.0,
                'low': 0.85
            }.get(doc.severity.lower(), 1.0)
            
            final_score = similarity * severity_boost
            
            if final_score >= min_score:
                # Find matched terms
                matched_terms = list(set(query_tokens) & set(doc.tokens))
                
                scores.append((final_score, doc_id, matched_terms))
        
        # Sort by score
        scores.sort(reverse=True, key=lambda x: x[0])
        
        # Build results
        results = []
        for score, doc_id, matched_terms in scores[:top_k]:
            doc = self.documents[doc_id]
            results.append(SearchResult(
                document_id=doc_id,
                score=round(score, 4),
                title=doc.title,
                content=doc.content[:200] + "..." if len(doc.content) > 200 else doc.content,
                threat_type=doc.threat_type,
                severity=doc.severity,
                matched_terms=matched_terms[:10],
                timestamp=doc.timestamp
            ))
        
        # Update stats
        if results:
            self.search_stats['avg_results'] = (
                self.search_stats['avg_results'] * (self.search_stats['total_searches'] - 1) +
                len(results)
            ) / self.search_stats['total_searches']
        
        return results
    
    def get_index_stats(self) -> Dict[str, Any]:
        """Get search engine statistics"""
        severity_counts = Counter(doc.severity for doc in self.documents.values())
        threat_type_counts = Counter(doc.threat_type for doc in self.documents.values())
        
        total_iocs = sum(len(doc.iocs) for doc in self.documents.values())
        total_techniques = sum(len(doc.techniques) for doc in self.documents.values())
        
        return {
            'total_documents': len(self.documents),
            'total_searches_performed': self.search_stats['total_searches'],
            'average_results_per_search': round(self.search_stats['avg_results'], 2),
            'severity_distribution': dict(severity_counts),
            'threat_type_distribution': dict(threat_type_counts),
            'total_iocs_extracted': total_iocs,
            'total_mitre_techniques_extracted': total_techniques,
            'vocabulary_size': len(self.vectorizer.doc_freq)
        }
    
    def export_index(self, filepath: str) -> bool:
        """Export index to JSON file"""
        try:
            data = {
                'documents': {
                    doc_id: {
                        'title': doc.title,
                        'content': doc.content,
                        'threat_type': doc.threat_type,
                        'severity': doc.severity,
                        'iocs': doc.iocs,
                        'techniques': doc.techniques
                    }
                    for doc_id, doc in self.documents.items()
                },
                'stats': self.get_index_stats(),
                'exported_at': datetime.utcnow().isoformat()
            }
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            
            return True
        except Exception:
            return False
    
    def clear_index(self) -> None:
        """Clear all indexed documents"""
        self.documents.clear()
        self.vectorizer = TFIDFVectorizer()
        self.is_fitted = False


# Sample threat intelligence data for demonstration
SAMPLE_THREAT_DATA = [
    {
        'title': 'Ransomware Attack on Healthcare Systems',
        'content': 'New ransomware variant targeting hospital networks. Uses encryption AES-256. IOC: 192.168.1.100, domain: malicious-ransom.com. Technique T1486 Data Encrypted for Impact.',
        'threat_type': 'ransomware',
        'severity': 'critical'
    },
    {
        'title': 'Phishing Campaign Targeting Finance Employees',
        'content': 'Spear phishing emails with malicious attachments. MD5: d41d8cd98f00b204e9800998ecf8427e. Domain: phish-finance-login.com. T1566 Phishing.',
        'threat_type': 'phishing',
        'severity': 'high'
    },
    {
        'title': 'SQL Injection Vulnerability in Web Applications',
        'content': 'Critical SQL injection flaw in e-commerce platforms. Allows unauthorized database access. CVE-2026-1234. Technique T1190 Exploit Public-Facing Application.',
        'threat_type': 'vulnerability',
        'severity': 'high'
    },
    {
        'title': 'Brute Force Attack on SSH Servers',
        'content': 'Distributed brute force attempts on port 22. IPs: 10.0.0.50, 172.16.0.100. Multiple failed login attempts. T1110 Brute Force.',
        'threat_type': 'bruteforce',
        'severity': 'medium'
    },
    {
        'title': 'Data Exfiltration via DNS Tunneling',
        'content': 'Suspicious DNS queries indicating data exfiltration. Large subdomain queries. T1048 Exfiltration Over Alternative Protocol.',
        'threat_type': 'exfiltration',
        'severity': 'high'
    },
    {
        'title': 'Malware Detection: Trojan Horse Infection',
        'content': 'SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. Trojan with backdoor capabilities. T1204 User Execution.',
        'threat_type': 'malware',
        'severity': 'critical'
    },
    {
        'title': 'Privilege Escalation Attempt Detected',
        'content': 'Local privilege escalation via sudo vulnerability. User attempting to gain root access. T1068 Exploitation for Privilege Escalation.',
        'threat_type': 'escalation',
        'severity': 'high'
    },
    {
        'title': 'Network Port Scan Activity',
        'content': 'Horizontal port scan from external IP. Scanning ports 22, 80, 443, 3389. Reconnaissance activity. T1046 Network Service Scanning.',
        'threat_type': 'reconnaissance',
        'severity': 'low'
    }
]
