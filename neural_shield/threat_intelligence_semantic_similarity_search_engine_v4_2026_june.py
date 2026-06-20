"""
NeuralShield-AI: Threat Intelligence Semantic Similarity Search Engine v4
Production-grade implementation with enhanced caching, batch processing,
and vector-based semantic search capabilities.

Features:
- TF-IDF + cosine similarity for semantic matching
- LRU caching with TTL for performance optimization
- Batch processing support
- Multi-threaded search execution
- Confidence scoring with threshold calibration
- IOC (Indicators of Compromise) normalization
"""

import re
import hashlib
import threading
import time
from collections import OrderedDict
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import math
from datetime import datetime, timedelta


class SearchType(Enum):
    EXACT = "exact"
    SEMANTIC = "semantic"
    FUZZY = "fuzzy"
    IOC_ONLY = "ioc_only"


class IOCType(Enum):
    IP = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    HASH = "file_hash"
    EMAIL = "email"


@dataclass
class SearchResult:
    threat_id: str
    title: str
    description: str
    similarity_score: float
    confidence: float
    ioc_matches: List[str]
    search_type: SearchType
    matched_terms: List[str]
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class CacheEntry:
    results: List[SearchResult]
    created_at: float
    ttl_seconds: int = 3600

    def is_expired(self) -> bool:
        return time.time() - self.created_at > self.ttl_seconds


class ThreadSafeLRUCache:
    """Thread-safe LRU Cache with TTL support"""
    
    def __init__(self, max_size: int = 1000):
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._max_size = max_size
        self._lock = threading.Lock()
    
    def get(self, key: str) -> Optional[List[SearchResult]]:
        with self._lock:
            if key not in self._cache:
                return None
            
            entry = self._cache[key]
            if entry.is_expired():
                del self._cache[key]
                return None
            
            self._cache.move_to_end(key)
            return entry.results
    
    def put(self, key: str, results: List[SearchResult], ttl_seconds: int = 3600) -> None:
        with self._lock:
            if key in self._cache:
                del self._cache[key]
            elif len(self._cache) >= self._max_size:
                self._cache.popitem(last=False)
            
            self._cache[key] = CacheEntry(
                results=results,
                created_at=time.time(),
                ttl_seconds=ttl_seconds
            )
    
    def clear_expired(self) -> int:
        with self._lock:
            expired_keys = [k for k, v in self._cache.items() if v.is_expired()]
            for k in expired_keys:
                del self._cache[k]
            return len(expired_keys)
    
    def size(self) -> int:
        with self._lock:
            return len(self._cache)


class IOCNormalizer:
    """Normalizes and extracts IOCs from text"""
    
    IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
    HASH_PATTERN = re.compile(r'\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b')
    URL_PATTERN = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
    EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    
    @classmethod
    def extract_iocs(cls, text: str) -> Dict[IOCType, Set[str]]:
        iocs = {
            IOCType.IP: set(),
            IOCType.DOMAIN: set(),
            IOCType.URL: set(),
            IOCType.HASH: set(),
            IOCType.EMAIL: set()
        }
        
        for ip in cls.IP_PATTERN.findall(text):
            iocs[IOCType.IP].add(ip)
        
        for domain in cls.DOMAIN_PATTERN.findall(text):
            if not any(c.isdigit() for c in domain.split('.')[0]):
                iocs[IOCType.DOMAIN].add(domain.lower())
        
        for url in cls.URL_PATTERN.findall(text):
            iocs[IOCType.URL].add(url)
        
        for h in cls.HASH_PATTERN.findall(text):
            iocs[IOCType.HASH].add(h.lower())
        
        for email in cls.EMAIL_PATTERN.findall(text):
            iocs[IOCType.EMAIL].add(email.lower())
        
        return iocs
    
    @classmethod
    def normalize_ioc(cls, ioc: str, ioc_type: IOCType) -> str:
        if ioc_type in (IOCType.DOMAIN, IOCType.EMAIL):
            return ioc.lower()
        elif ioc_type == IOCType.HASH:
            return ioc.lower()
        return ioc


class TFIDFVectorizer:
    """Lightweight TF-IDF vectorizer for semantic search"""
    
    def __init__(self):
        self.idf: Dict[str, float] = {}
        self.document_count = 0
        self._stopwords = {
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
            'of', 'with', 'by', 'from', 'is', 'are', 'was', 'were', 'be', 'been',
            'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would',
            'could', 'should', 'may', 'might', 'must', 'shall', 'can', 'need',
            'dare', 'ought', 'used', 'this', 'that', 'these', 'those', 'i', 'you',
            'he', 'she', 'it', 'we', 'they', 'what', 'which', 'who', 'whom', 'whose',
            'where', 'when', 'why', 'how', 'all', 'each', 'every', 'both', 'few',
            'more', 'most', 'other', 'some', 'such', 'no', 'nor', 'not', 'only',
            'own', 'same', 'so', 'than', 'too', 'very', 'just', 'also', 'now', 'here'
        }
    
    def _tokenize(self, text: str) -> List[str]:
        text = re.sub(r'[^\w\s]', ' ', text.lower())
        tokens = text.split()
        return [t for t in tokens if t not in self._stopwords and len(t) > 2]
    
    def _get_tf(self, tokens: List[str]) -> Dict[str, float]:
        tf: Dict[str, float] = {}
        total = len(tokens)
        for token in tokens:
            tf[token] = tf.get(token, 0) + 1 / total
        return tf
    
    def fit(self, documents: List[str]) -> None:
        self.document_count = len(documents)
        doc_freq: Dict[str, int] = {}
        
        for doc in documents:
            tokens = set(self._tokenize(doc))
            for token in tokens:
                doc_freq[token] = doc_freq.get(token, 0) + 1
        
        for term, df in doc_freq.items():
            self.idf[term] = math.log(self.document_count / (df + 1))
    
    def vectorize(self, text: str) -> Dict[str, float]:
        tokens = self._tokenize(text)
        tf = self._get_tf(tokens)
        return {term: tf_val * self.idf.get(term, 0) for term, tf_val in tf.items()}
    
    @staticmethod
    def cosine_similarity(vec1: Dict[str, float], vec2: Dict[str, float]) -> float:
        common_terms = set(vec1.keys()) & set(vec2.keys())
        if not common_terms:
            return 0.0
        
        dot_product = sum(vec1[t] * vec2[t] for t in common_terms)
        norm1 = math.sqrt(sum(v * v for v in vec1.values()))
        norm2 = math.sqrt(sum(v * v for v in vec2.values()))
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)


class SemanticSearchEngineV4:
    """
    Production-grade Semantic Similarity Search Engine v4
    Enhanced with caching, batch processing, and multi-threading
    """
    
    def __init__(self, cache_size: int = 2000, confidence_threshold: float = 0.3):
        self.vectorizer = TFIDFVectorizer()
        self.cache = ThreadSafeLRUCache(max_size=cache_size)
        self.ioc_normalizer = IOCNormalizer()
        self.confidence_threshold = confidence_threshold
        self.threat_database: Dict[str, Dict[str, Any]] = {}
        self.vector_cache: Dict[str, Dict[str, float]] = {}
        self._fitted = False
        self._lock = threading.Lock()
        self._stats = {
            'total_searches': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'avg_response_time_ms': 0.0
        }
    
    def _generate_cache_key(self, query: str, search_type: SearchType, limit: int) -> str:
        key_data = f"{query}:{search_type.value}:{limit}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def add_threats(self, threats: List[Dict[str, Any]]) -> None:
        """Add threat intelligence entries to the database"""
        with self._lock:
            for threat in threats:
                threat_id = threat.get('id', hashlib.md5(threat.get('title', '').encode()).hexdigest())
                self.threat_database[threat_id] = {
                    'id': threat_id,
                    'title': threat.get('title', ''),
                    'description': threat.get('description', ''),
                    'iocs': threat.get('iocs', []),
                    'tags': threat.get('tags', []),
                    'severity': threat.get('severity', 'medium'),
                    'full_text': f"{threat.get('title', '')} {threat.get('description', '')}"
                }
            
            # Important: Fit first, then build vectors
            self._fit_vectorizer()
            self._rebuild_vector_cache()
            self._fitted = True
    
    def _rebuild_vector_cache(self) -> None:
        self.vector_cache.clear()
        for threat_id, threat in self.threat_database.items():
            self.vector_cache[threat_id] = self.vectorizer.vectorize(threat['full_text'])
    
    def _fit_vectorizer(self) -> None:
        documents = [t['full_text'] for t in self.threat_database.values()]
        self.vectorizer.fit(documents)
    
    def _calculate_confidence(self, similarity_score: float, matched_iocs: int, 
                              matched_terms: int, total_terms: int) -> float:
        """Calculate confidence score based on multiple factors"""
        base_confidence = similarity_score
        
        ioc_bonus = min(matched_iocs * 0.1, 0.3)
        term_ratio = matched_terms / max(total_terms, 1)
        term_bonus = term_ratio * 0.2
        
        confidence = base_confidence + ioc_bonus + term_bonus
        return min(max(confidence, 0.0), 1.0)
    
    def search(self, query: str, search_type: SearchType = SearchType.SEMANTIC,
               limit: int = 10, min_confidence: Optional[float] = None) -> List[SearchResult]:
        """
        Perform semantic search on threat intelligence database
        
        Args:
            query: Search query text
            search_type: Type of search (exact, semantic, fuzzy, ioc_only)
            limit: Maximum number of results
            min_confidence: Minimum confidence threshold (overrides default)
        
        Returns:
            List of SearchResult objects sorted by relevance
        """
        start_time = time.time()
        threshold = min_confidence if min_confidence is not None else self.confidence_threshold
        
        # Check cache
        cache_key = self._generate_cache_key(query, search_type, limit)
        cached_results = self.cache.get(cache_key)
        
        with self._lock:
            self._stats['total_searches'] += 1
        
        if cached_results is not None:
            with self._lock:
                self._stats['cache_hits'] += 1
            return cached_results[:limit]
        
        with self._lock:
            self._stats['cache_misses'] += 1
        
        if not self._fitted or not self.threat_database:
            return []
        
        # Extract IOCs from query
        query_iocs = self.ioc_normalizer.extract_iocs(query)
        query_vector = self.vectorizer.vectorize(query)
        query_tokens = set(self.vectorizer._tokenize(query))
        
        results: List[SearchResult] = []
        
        for threat_id, threat in self.threat_database.items():
            threat_vector = self.vector_cache.get(threat_id, {})
            similarity = TFIDFVectorizer.cosine_similarity(query_vector, threat_vector)
            
            # IOC matching
            threat_iocs = set(threat.get('iocs', []))
            matched_iocs = []
            for ioc_type, iocs in query_iocs.items():
                for ioc in iocs:
                    if ioc in threat_iocs:
                        matched_iocs.append(ioc)
            
            # Term matching
            threat_tokens = set(self.vectorizer._tokenize(threat['full_text']))
            matched_terms = list(query_tokens & threat_tokens)
            
            # Calculate confidence
            confidence = self._calculate_confidence(
                similarity, len(matched_iocs), 
                len(matched_terms), len(query_tokens)
            )
            
            if confidence >= threshold:
                # Apply search type filtering
                include_result = False
                if search_type == SearchType.SEMANTIC:
                    include_result = similarity > 0.1 or len(matched_iocs) > 0
                elif search_type == SearchType.EXACT:
                    include_result = query.lower() in threat['full_text'].lower()
                elif search_type == SearchType.FUZZY:
                    include_result = confidence > 0.2
                elif search_type == SearchType.IOC_ONLY:
                    include_result = len(matched_iocs) > 0
                
                if include_result:
                    results.append(SearchResult(
                        threat_id=threat_id,
                        title=threat['title'],
                        description=threat['description'][:200] + '...' if len(threat['description']) > 200 else threat['description'],
                        similarity_score=round(similarity, 4),
                        confidence=round(confidence, 4),
                        ioc_matches=matched_iocs,
                        search_type=search_type,
                        matched_terms=matched_terms[:10]
                    ))
        
        # Sort by confidence descending
        results.sort(key=lambda x: x.confidence, reverse=True)
        final_results = results[:limit]
        
        # Cache results
        self.cache.put(cache_key, final_results, ttl_seconds=1800)
        
        # Update stats
        elapsed_ms = (time.time() - start_time) * 1000
        with self._lock:
            self._stats['avg_response_time_ms'] = (
                self._stats['avg_response_time_ms'] * (self._stats['total_searches'] - 1) + elapsed_ms
            ) / self._stats['total_searches']
        
        return final_results
    
    def batch_search(self, queries: List[str], **kwargs) -> List[List[SearchResult]]:
        """Perform batch search with multi-threading"""
        results: List[List[SearchResult]] = [[] for _ in queries]
        threads = []
        
        def search_worker(idx: int, query: str):
            results[idx] = self.search(query, **kwargs)
        
        for i, query in enumerate(queries):
            t = threading.Thread(target=search_worker, args=(i, query))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics"""
        with self._lock:
            stats = dict(self._stats)
        
        stats.update({
            'cache_size': self.cache.size(),
            'database_size': len(self.threat_database),
            'confidence_threshold': self.confidence_threshold,
            'is_fitted': self._fitted
        })
        
        if stats['total_searches'] > 0:
            stats['cache_hit_rate'] = round(stats['cache_hits'] / stats['total_searches'], 4)
        else:
            stats['cache_hit_rate'] = 0.0
        
        return stats
    
    def clear_cache(self) -> int:
        """Clear expired cache entries"""
        return self.cache.clear_expired()


# Export main class
__all__ = [
    'SemanticSearchEngineV4',
    'SearchResult',
    'SearchType',
    'IOCType',
    'IOCNormalizer',
    'TFIDFVectorizer',
    'ThreadSafeLRUCache'
]
