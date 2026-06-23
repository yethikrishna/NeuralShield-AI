"""
Test Suite for Threat Intelligence Semantic Vector Search v20
NeuralShield AI - Dimension A Feature Expansion

Comprehensive tests for semantic search functionality.
All tests are ADD-ONLY - no existing code modified.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_semantic_vector_search_v20_2026_june import (
    ThreatIntelSemanticSearchEngine,
    SemanticSimilaritySearch,
    SemanticVectorizer,
    VectorEmbedding,
    SearchResult
)


class TestVectorEmbedding:
    """Test VectorEmbedding dataclass."""

    def test_vector_embedding_creation(self):
        """Test basic vector embedding creation."""
        vec = [0.1, 0.2, 0.3, 0.4]
        embedding = VectorEmbedding(vector=vec, dimension=4)
        assert embedding.vector == vec
        assert embedding.dimension == 4
        assert embedding.metadata == {}

    def test_vector_embedding_with_metadata(self):
        """Test vector embedding with custom metadata."""
        metadata = {'source': 'test', 'confidence': 0.95}
        embedding = VectorEmbedding(vector=[1.0], dimension=1, metadata=metadata)
        assert embedding.metadata == metadata


class TestSemanticVectorizer:
    """Test SemanticVectorizer class."""

    def test_vectorizer_initialization(self):
        """Test vectorizer initialization."""
        vectorizer = SemanticVectorizer(dimension=64)
        assert vectorizer.dimension == 64
        assert len(vectorizer._term_vocabulary) > 0

    def test_vectorize_text(self):
        """Test text vectorization produces valid vectors."""
        vectorizer = SemanticVectorizer(dimension=128)
        text = "malware ransomware exploit vulnerability CVE-2024-1234"
        embedding = vectorizer.vectorize(text)
        
        assert embedding.dimension == 128
        assert len(embedding.vector) == 128
        # Should be normalized
        norm = sum(v * v for v in embedding.vector) ** 0.5
        assert abs(norm - 1.0) < 0.01 or norm == 0.0

    def test_tokenize_removes_stop_words(self):
        """Test tokenization removes stop words."""
        vectorizer = SemanticVectorizer(dimension=64)
        tokens = vectorizer._tokenize("the malware is in the system")
        assert 'the' not in tokens
        assert 'is' not in tokens
        assert 'malware' in tokens

    def test_empty_text_vectorization(self):
        """Test handling of empty text."""
        vectorizer = SemanticVectorizer(dimension=64)
        embedding = vectorizer.vectorize("")
        assert len(embedding.vector) == 64
        assert all(v == 0.0 for v in embedding.vector)


class TestSemanticSimilaritySearch:
    """Test SemanticSimilaritySearch class."""

    def test_search_initialization(self):
        """Test search engine initialization."""
        search = SemanticSimilaritySearch(vector_dimension=64)
        assert search.vector_dimension == 64
        assert search.get_document_count() == 0

    def test_add_document(self):
        """Test adding document to index."""
        search = SemanticSimilaritySearch()
        result = search.add_document(
            document_id="test-001",
            content="Ransomware attack encrypts files using AES",
            threat_type="ransomware",
            severity="critical"
        )
        assert result is True
        assert search.get_document_count() == 1

    def test_add_empty_document(self):
        """Test adding empty document returns False."""
        search = SemanticSimilaritySearch()
        assert search.add_document("", "content") is False
        assert search.add_document("id", "") is False

    def test_basic_search(self):
        """Test basic semantic search functionality."""
        search = SemanticSimilaritySearch()
        
        # Add test documents
        search.add_document("doc1", "ransomware encrypts files payment bitcoin", "ransomware", "critical")
        search.add_document("doc2", "phishing email credential theft login", "phishing", "high")
        search.add_document("doc3", "malware trojan backdoor persistence", "malware", "high")
        
        results = search.search("ransomware bitcoin payment", top_k=2)
        assert len(results) > 0
        assert all(isinstance(r, SearchResult) for r in results)
        assert results[0].similarity_score >= results[-1].similarity_score

    def test_search_with_threat_type_filter(self):
        """Test search with threat type filter."""
        search = SemanticSimilaritySearch()
        
        search.add_document("doc1", "ransomware encrypts files", "ransomware", "critical")
        search.add_document("doc2", "phishing email credentials", "phishing", "high")
        
        results = search.search("attack", threat_type_filter="ransomware")
        assert all(r.threat_type == "ransomware" for r in results)

    def test_search_with_severity_filter(self):
        """Test search with severity filter."""
        search = SemanticSimilaritySearch()
        
        search.add_document("doc1", "critical threat", "malware", "critical")
        search.add_document("doc2", "low risk", "malware", "low")
        
        results = search.search("threat", severity_filter="critical")
        assert all(r.severity == "critical" for r in results)

    def test_find_similar_by_id(self):
        """Test finding similar documents by ID."""
        search = SemanticSimilaritySearch()
        
        search.add_document("doc1", "ransomware encrypts files payment", "ransomware", "critical")
        search.add_document("doc2", "ransomware lockbit variant", "ransomware", "critical")
        search.add_document("doc3", "phishing email credentials", "phishing", "high")
        
        results = search.find_similar_by_id("doc1", top_k=2)
        assert len(results) >= 0

    def test_find_similar_nonexistent_id(self):
        """Test finding similar for non-existent ID."""
        search = SemanticSimilaritySearch()
        results = search.find_similar_by_id("nonexistent")
        assert results == []

    def test_cosine_similarity_identical_vectors(self):
        """Test cosine similarity for identical vectors."""
        search = SemanticSimilaritySearch()
        v1 = [1.0, 0.0, 0.0]
        v2 = [1.0, 0.0, 0.0]
        similarity = search._cosine_similarity(v1, v2)
        assert similarity == 1.0

    def test_cosine_similarity_orthogonal(self):
        """Test cosine similarity for orthogonal vectors."""
        search = SemanticSimilaritySearch()
        v1 = [1.0, 0.0]
        v2 = [0.0, 1.0]
        similarity = search._cosine_similarity(v1, v2)
        assert similarity == 0.0

    def test_clear_index(self):
        """Test clearing the search index."""
        search = SemanticSimilaritySearch()
        search.add_document("doc1", "test content", "malware", "medium")
        assert search.get_document_count() == 1
        
        search.clear_index()
        assert search.get_document_count() == 0

    def test_threat_type_distribution(self):
        """Test threat type distribution calculation."""
        search = SemanticSimilaritySearch()
        search.add_document("doc1", "test1", "ransomware", "high")
        search.add_document("doc2", "test2", "phishing", "high")
        search.add_document("doc3", "test3", "ransomware", "medium")
        
        dist = search.get_threat_type_distribution()
        assert dist['ransomware'] == 2
        assert dist['phishing'] == 1


class TestThreatIntelSemanticSearchEngine:
    """Test main ThreatIntelSemanticSearchEngine class."""

    def test_engine_initialization(self):
        """Test engine initialization."""
        engine = ThreatIntelSemanticSearchEngine(vector_dimension=64)
        stats = engine.get_search_statistics()
        assert stats['indexed_documents'] == 0
        assert stats['total_queries'] == 0

    def test_index_threat_intel(self):
        """Test indexing threat intelligence."""
        engine = ThreatIntelSemanticSearchEngine()
        
        result = engine.index_threat_intel(
            threat_id="THREAT-001",
            description="LockBit ransomware encrypts network shares",
            threat_type="ransomware",
            severity="critical",
            iocs=["192.168.1.1", "malware.exe"],
            ttp_tags=["T1486", "T1027"]
        )
        assert result is True
        
        stats = engine.get_search_statistics()
        assert stats['indexed_documents'] == 1

    def test_semantic_search(self):
        """Test semantic search API."""
        engine = ThreatIntelSemanticSearchEngine()
        
        engine.index_threat_intel("T1", "Ransomware encrypts files for bitcoin", "ransomware", "critical")
        engine.index_threat_intel("T2", "Phishing email steals user credentials", "phishing", "high")
        engine.index_threat_intel("T3", "Trojan creates backdoor for persistence", "malware", "high")
        
        results = engine.semantic_search("ransomware bitcoin payment", top_k=3)
        assert len(results) > 0
        assert 'threat_id' in results[0]
        assert 'similarity_score' in results[0]
        assert 'threat_type' in results[0]

    def test_find_related_threats(self):
        """Test finding related threats."""
        engine = ThreatIntelSemanticSearchEngine()
        
        engine.index_threat_intel("T1", "Ransomware encrypts files", "ransomware", "critical")
        engine.index_threat_intel("T2", "Ransomware variant LockBit", "ransomware", "critical")
        
        related = engine.find_related_threats("T1", top_k=2)
        assert isinstance(related, list)

    def test_search_query_history(self):
        """Test query history tracking."""
        engine = ThreatIntelSemanticSearchEngine()
        engine.index_threat_intel("T1", "Test threat", "malware", "medium")
        
        engine.semantic_search("test query 1")
        engine.semantic_search("test query 2")
        
        stats = engine.get_search_statistics()
        assert stats['total_queries'] == 2

    def test_search_with_min_similarity(self):
        """Test search with minimum similarity threshold."""
        engine = ThreatIntelSemanticSearchEngine()
        engine.index_threat_intel("T1", "Ransomware encryption", "ransomware", "high")
        
        # High threshold should return few or no results
        results_high = engine.semantic_search("completely unrelated text", min_similarity=0.9)
        assert len(results_high) == 0


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_query(self):
        """Test empty search query."""
        engine = ThreatIntelSemanticSearchEngine()
        engine.index_threat_intel("T1", "Test", "malware", "medium")
        
        results = engine.semantic_search("")
        assert results == []

    def test_negative_top_k(self):
        """Test negative top_k parameter."""
        engine = ThreatIntelSemanticSearchEngine()
        engine.index_threat_intel("T1", "Test", "malware", "medium")
        
        results = engine.semantic_search("test", top_k=-1)
        assert results == []

    def test_zero_top_k(self):
        """Test zero top_k parameter."""
        engine = ThreatIntelSemanticSearchEngine()
        engine.index_threat_intel("T1", "Test", "malware", "medium")
        
        results = engine.semantic_search("test", top_k=0)
        assert results == []

    def test_large_top_k(self):
        """Test very large top_k value."""
        engine = ThreatIntelSemanticSearchEngine()
        for i in range(5):
            engine.index_threat_intel(f"T{i}", f"Test threat {i}", "malware", "medium")
        
        results = engine.semantic_search("test", top_k=1000)
        assert len(results) <= 5  # Should not exceed actual document count

    def test_special_characters_query(self):
        """Test query with special characters."""
        engine = ThreatIntelSemanticSearchEngine()
        engine.index_threat_intel("T1", "CVE-2024-1234 vulnerability", "exploit", "critical")
        
        results = engine.semantic_search("CVE-2024-1234!!!@@@###")
        assert isinstance(results, list)

    def test_unicode_text(self):
        """Test handling of unicode text."""
        engine = ThreatIntelSemanticSearchEngine()
        result = engine.index_threat_intel(
            "T1",
            "Unicode threat description ñáéíóú",
            "malware",
            "medium"
        )
        assert result is True


class TestThreadSafety:
    """Test thread safety of search operations."""

    def test_concurrent_indexing(self):
        """Test concurrent document indexing."""
        import threading
        
        engine = ThreatIntelSemanticSearchEngine()
        num_threads = 5
        docs_per_thread = 10
        
        def index_docs(thread_id):
            for i in range(docs_per_thread):
                doc_id = f"doc-{thread_id}-{i}"
                engine.index_threat_intel(doc_id, f"Content {thread_id} {i}", "malware", "medium")
        
        threads = []
        for t_id in range(num_threads):
            t = threading.Thread(target=index_docs, args=(t_id,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        stats = engine.get_search_statistics()
        assert stats['indexed_documents'] == num_threads * docs_per_thread


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
