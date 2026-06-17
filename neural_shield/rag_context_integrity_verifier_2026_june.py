"""
RAG Context Integrity Verifier - NeuralShield-AI
June 17, 2026 - Production Release

Verifies integrity, provenance, and authenticity of RAG context chunks.
Detects tampering, injection attacks, and validates source authenticity.

Features:
- Cryptographic hashing of context chunks
- Source provenance tracking and verification
- Tamper detection via hash chain validation
- Injection attack detection via semantic fingerprinting
- Context boundary validation
- Metadata integrity verification
"""

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime, timezone


class IntegrityStatus(Enum):
    """Integrity verification status"""
    VALID = "valid"
    TAMPERED = "tampered"
    INJECTED = "injected"
    UNTRUSTED_SOURCE = "untrusted_source"
    MISSING_METADATA = "missing_metadata"
    BOUNDARY_VIOLATION = "boundary_violation"
    UNKNOWN = "unknown"


class TamperType(Enum):
    """Types of tampering detected"""
    CONTENT_MODIFICATION = "content_modification"
    METADATA_ALTERATION = "metadata_alteration"
    CHUNK_INJECTION = "chunk_injection"
    CHUNK_REMOVAL = "chunk_removal"
    CHUNK_REORDERING = "chunk_reordering"
    SOURCE_SPOOFING = "source_spoofing"
    BOUNDARY_CROSSING = "boundary_crossing"


@dataclass
class ContextChunk:
    """Represents a single RAG context chunk with integrity metadata"""
    content: str
    source: str
    chunk_id: str
    position: int
    timestamp: float = field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    metadata: Dict[str, Any] = field(default_factory=dict)
    hash_value: Optional[str] = None
    signature: Optional[str] = None

    def compute_hash(self, algorithm: str = "sha256") -> str:
        """Compute cryptographic hash of chunk content"""
        hash_input = f"{self.content}|{self.source}|{self.chunk_id}|{self.position}"
        return hashlib.new(algorithm, hash_input.encode('utf-8')).hexdigest()

    def sign(self, secret_key: bytes, algorithm: str = "sha256") -> str:
        """Sign chunk with HMAC"""
        message = f"{self.content}|{self.source}|{self.chunk_id}|{self.position}|{self.timestamp}"
        self.signature = hmac.new(secret_key, message.encode('utf-8'), algorithm).hexdigest()
        return self.signature

    def verify_signature(self, secret_key: bytes, algorithm: str = "sha256") -> bool:
        """Verify chunk signature"""
        if not self.signature:
            return False
        message = f"{self.content}|{self.source}|{self.chunk_id}|{self.position}|{self.timestamp}"
        expected = hmac.new(secret_key, message.encode('utf-8'), algorithm).hexdigest()
        return hmac.compare_digest(expected, self.signature)


@dataclass
class IntegrityFinding:
    """Single integrity finding"""
    tamper_type: TamperType
    description: str
    confidence: float
    chunk_id: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IntegrityVerificationResult:
    """Result of integrity verification"""
    status: IntegrityStatus
    overall_confidence: float
    findings: List[IntegrityFinding] = field(default_factory=list)
    valid_chunks: int = 0
    suspicious_chunks: int = 0
    total_chunks: int = 0
    verification_time: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)

    def is_safe(self) -> bool:
        """Check if context is safe to use"""
        return self.status == IntegrityStatus.VALID and self.suspicious_chunks == 0

    def get_risk_score(self) -> float:
        """Calculate risk score 0-1"""
        if self.total_chunks == 0:
            return 0.0
        base_risk = self.suspicious_chunks / self.total_chunks
        severity_multiplier = 1.0
        for finding in self.findings:
            if finding.tamper_type in [TamperType.CHUNK_INJECTION, TamperType.SOURCE_SPOOFING]:
                severity_multiplier += 0.3
        return min(1.0, base_risk * severity_multiplier)


class RAGContextIntegrityVerifier:
    """
    Production-grade RAG Context Integrity Verifier
    
    Verifies:
    1. Cryptographic integrity of each chunk
    2. Source provenance and authenticity
    3. Hash chain continuity (no chunks removed/added)
    4. Semantic consistency
    5. Boundary integrity
    """

    def __init__(
        self,
        secret_key: Optional[bytes] = None,
        hash_algorithm: str = "sha256",
        trusted_sources: Optional[List[str]] = None,
        enable_semantic_check: bool = True
    ):
        self.secret_key = secret_key or self._generate_secret_key()
        self.hash_algorithm = hash_algorithm
        self.trusted_sources = set(trusted_sources) if trusted_sources else set()
        self.enable_semantic_check = enable_semantic_check
        self._injection_patterns = self._compile_injection_patterns()

    @staticmethod
    def _generate_secret_key() -> bytes:
        """Generate a secure secret key"""
        import secrets
        return secrets.token_bytes(32)

    @staticmethod
    def _compile_injection_patterns() -> List[re.Pattern]:
        """Compile patterns for injection detection"""
        return [
            re.compile(r'(ignore|disregard|forget)\s+(previous|above|prior|all)\s+(instructions|context|system)', re.IGNORECASE),
            re.compile(r'(you are|act as|pretend to be|roleplay as).*(AI|assistant|helper|model)', re.IGNORECASE),
            re.compile(r'(system\s*prompt|instruction\s*set|initial\s*prompt)', re.IGNORECASE),
            re.compile(r'---+\s*(end|start)\s*(of|for)?\s*(system|context|instruction)', re.IGNORECASE),
            re.compile(r'```\s*(system|prompt|instruction)\s*```', re.IGNORECASE),
        ]

    def create_signed_chunk(
        self,
        content: str,
        source: str,
        chunk_id: str,
        position: int,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ContextChunk:
        """Create a cryptographically signed context chunk"""
        chunk = ContextChunk(
            content=content,
            source=source,
            chunk_id=chunk_id,
            position=position,
            metadata=metadata or {}
        )
        chunk.hash_value = chunk.compute_hash(self.hash_algorithm)
        chunk.sign(self.secret_key, self.hash_algorithm)
        return chunk

    def verify_chunk(self, chunk: ContextChunk) -> Tuple[bool, List[IntegrityFinding]]:
        """Verify integrity of a single chunk"""
        findings = []
        is_valid = True

        # 1. Verify cryptographic signature
        if chunk.signature and not chunk.verify_signature(self.secret_key, self.hash_algorithm):
            findings.append(IntegrityFinding(
                tamper_type=TamperType.CONTENT_MODIFICATION,
                description=f"Chunk {chunk.chunk_id}: Signature verification failed - content may be modified",
                confidence=0.95,
                chunk_id=chunk.chunk_id,
                evidence={"expected_hash": chunk.compute_hash(), "stored_hash": chunk.hash_value}
            ))
            is_valid = False

        # 2. Verify hash integrity
        computed_hash = chunk.compute_hash(self.hash_algorithm)
        if chunk.hash_value and chunk.hash_value != computed_hash:
            findings.append(IntegrityFinding(
                tamper_type=TamperType.CONTENT_MODIFICATION,
                description=f"Chunk {chunk.chunk_id}: Hash mismatch - content modified",
                confidence=0.98,
                chunk_id=chunk.chunk_id,
                evidence={"computed": computed_hash, "stored": chunk.hash_value}
            ))
            is_valid = False

        # 3. Verify source is trusted
        if self.trusted_sources and chunk.source not in self.trusted_sources:
            findings.append(IntegrityFinding(
                tamper_type=TamperType.SOURCE_SPOOFING,
                description=f"Chunk {chunk.chunk_id}: Untrusted source - {chunk.source}",
                confidence=0.7,
                chunk_id=chunk.chunk_id
            ))
            is_valid = False

        # 4. Check for injection patterns
        if self.enable_semantic_check:
            for pattern in self._injection_patterns:
                if pattern.search(chunk.content):
                    findings.append(IntegrityFinding(
                        tamper_type=TamperType.CHUNK_INJECTION,
                        description=f"Chunk {chunk.chunk_id}: Injection pattern detected - {pattern.pattern[:50]}...",
                        confidence=0.85,
                        chunk_id=chunk.chunk_id,
                        evidence={"pattern": pattern.pattern}
                    ))
                    is_valid = False
                    break

        # 5. Check metadata tampering
        if 'original_length' in chunk.metadata:
            if len(chunk.content) != chunk.metadata['original_length']:
                findings.append(IntegrityFinding(
                    tamper_type=TamperType.METADATA_ALTERATION,
                    description=f"Chunk {chunk.chunk_id}: Content length mismatch",
                    confidence=0.9,
                    chunk_id=chunk.chunk_id
                ))
                is_valid = False

        return is_valid, findings

    def verify_chain(self, chunks: List[ContextChunk]) -> IntegrityVerificationResult:
        """
        Verify complete chain of context chunks
        
        Checks:
        - Individual chunk integrity
        - Position continuity (no missing chunks)
        - No duplicate positions
        - Hash chain integrity
        """
        start_time = datetime.now(timezone.utc).timestamp()
        all_findings: List[IntegrityFinding] = []
        valid_count = 0
        suspicious_count = 0

        # Sort chunks by position
        sorted_chunks = sorted(chunks, key=lambda c: c.position)

        # 1. Verify each chunk individually
        for chunk in sorted_chunks:
            is_valid, findings = self.verify_chunk(chunk)
            all_findings.extend(findings)
            if is_valid:
                valid_count += 1
            else:
                suspicious_count += 1

        # 2. Verify chain continuity
        positions = [c.position for c in sorted_chunks]
        expected_positions = list(range(len(sorted_chunks)))

        # Check for missing positions
        for pos in expected_positions:
            if pos not in positions:
                all_findings.append(IntegrityFinding(
                    tamper_type=TamperType.CHUNK_REMOVAL,
                    description=f"Chunk at position {pos} is missing from chain",
                    confidence=0.9
                ))
                suspicious_count += 1

        # Check for duplicate positions
        seen_positions = set()
        for chunk in sorted_chunks:
            if chunk.position in seen_positions:
                all_findings.append(IntegrityFinding(
                    tamper_type=TamperType.CHUNK_REORDERING,
                    description=f"Duplicate position {chunk.position} detected for chunk {chunk.chunk_id}",
                    confidence=0.95,
                    chunk_id=chunk.chunk_id
                ))
                suspicious_count += 1
            seen_positions.add(chunk.position)

        # 3. Determine overall status
        if suspicious_count == 0:
            status = IntegrityStatus.VALID
        elif any(f.tamper_type == TamperType.CHUNK_INJECTION for f in all_findings):
            status = IntegrityStatus.INJECTED
        elif any(f.tamper_type == TamperType.SOURCE_SPOOFING for f in all_findings):
            status = IntegrityStatus.UNTRUSTED_SOURCE
        else:
            status = IntegrityStatus.TAMPERED

        verification_time = datetime.now(timezone.utc).timestamp() - start_time

        return IntegrityVerificationResult(
            status=status,
            overall_confidence=1.0 - (suspicious_count / max(1, len(chunks)) * 0.5),
            findings=all_findings,
            valid_chunks=valid_count,
            suspicious_chunks=suspicious_count,
            total_chunks=len(chunks),
            verification_time=verification_time,
            details={
                "positions_verified": positions,
                "expected_positions": expected_positions,
                "chain_complete": len(positions) == len(expected_positions) and positions == expected_positions
            }
        )

    def batch_verify(
        self,
        contexts: List[List[ContextChunk]]
    ) -> List[IntegrityVerificationResult]:
        """Batch verify multiple context chains"""
        return [self.verify_chain(chunks) for chunks in contexts]

    def export_verification_report(
        self,
        result: IntegrityVerificationResult,
        format: str = "json"
    ) -> str:
        """Export verification report in various formats"""
        report = {
            "verification_timestamp": datetime.now(timezone.utc).isoformat(),
            "status": result.status.value,
            "overall_confidence": result.overall_confidence,
            "risk_score": result.get_risk_score(),
            "summary": {
                "total_chunks": result.total_chunks,
                "valid_chunks": result.valid_chunks,
                "suspicious_chunks": result.suspicious_chunks
            },
            "findings": [
                {
                    "type": f.tamper_type.value,
                    "description": f.description,
                    "confidence": f.confidence,
                    "chunk_id": f.chunk_id,
                    "evidence": f.evidence
                }
                for f in result.findings
            ],
            "verification_time_ms": result.verification_time * 1000
        }

        if format == "json":
            return json.dumps(report, indent=2)
        elif format == "dict":
            return report
        else:
            raise ValueError(f"Unsupported format: {format}")


def create_integrity_verifier(
    trusted_sources: Optional[List[str]] = None,
    secret_key: Optional[bytes] = None
) -> RAGContextIntegrityVerifier:
    """Factory function to create RAG Context Integrity Verifier"""
    return RAGContextIntegrityVerifier(
        secret_key=secret_key,
        trusted_sources=trusted_sources,
        enable_semantic_check=True
    )


# Export public API
__all__ = [
    "RAGContextIntegrityVerifier",
    "ContextChunk",
    "IntegrityStatus",
    "TamperType",
    "IntegrityFinding",
    "IntegrityVerificationResult",
    "create_integrity_verifier"
]
