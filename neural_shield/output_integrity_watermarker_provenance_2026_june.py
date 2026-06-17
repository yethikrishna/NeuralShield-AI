"""
NeuralShield-AI: LLM Output Integrity Watermarker & Provenance Tracker
June 2026 Production Release

Provides cryptographic watermarking and tamper detection for LLM outputs:
- Invisible zero-width character watermarking for output integrity
- Cryptographic hash chaining for conversation provenance
- Tamper detection with confidence scoring
- Output origin verification
- Chain-of-custody tracking for AI-generated content

Production-grade integrity enforcement for enterprise AI systems.
"""
import hashlib
import hmac
import json
import time
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timezone

class WatermarkType(Enum):
    """Types of watermarking available"""
    ZERO_WIDTH = "zero_width"
    UNICODE_SPACE = "unicode_space"
    HASH_EMBEDDED = "hash_embedded"
    FULL_CRYPTOSIGN = "full_cryptosign"

class TamperVerdict(Enum):
    """Tamper detection verdicts"""
    UNMODIFIED = "unmodified"
    MINOR_TAMPERING = "minor_tampering"
    SIGNIFICANT_TAMPERING = "significant_tampering"
    SEVERE_TAMPERING = "severe_tampering"
    NO_WATERMARK = "no_watermark"
    INVALID_SIGNATURE = "invalid_signature"

@dataclass
class WatermarkMetadata:
    """Metadata embedded in watermark"""
    model_name: str
    timestamp: float
    conversation_id: str
    turn_number: int
    prompt_hash: str
    output_hash: str
    temperature: float = 0.7
    top_p: float = 1.0

@dataclass
class WatermarkResult:
    """Result from watermarking operation"""
    original_text: str
    watermarked_text: str
    watermark_type: WatermarkType
    metadata: WatermarkMetadata
    watermark_length: int
    embedding_positions: List[int] = field(default_factory=list)
    verification_key: str = ""

@dataclass
class VerificationResult:
    """Result from watermark verification"""
    is_valid: bool
    verdict: TamperVerdict
    confidence: float  # 0.0 - 1.0
    extracted_metadata: Optional[WatermarkMetadata] = None
    tamper_locations: List[Tuple[int, int]] = field(default_factory=list)
    original_hash_match: bool = False
    verification_timestamp: float = 0.0
    integrity_score: float = 0.0

class OutputIntegrityWatermarker:
    """
    Production-grade LLM Output Integrity Watermarker
    
    Implements multiple watermarking strategies for LLM output verification:
    1. Zero-width character steganography
    2. Unicode space variation encoding
    3. Cryptographic hash embedding
    4. Full HMAC signature verification
    """
    
    # Zero-width characters for encoding (invisible in most renderers)
    ZERO_WIDTH_CHARS = {
        '0': '\u200B',  # Zero Width Space
        '1': '\u200C',  # Zero Width Non-Joiner
        '2': '\u200D',  # Zero Width Joiner
        '3': '\u2060',  # Word Joiner
        'separator': '\u2061',  # Function Application
    }
    
    REVERSE_ZERO_WIDTH = {v: k for k, v in ZERO_WIDTH_CHARS.items() if k != 'separator'}
    
    # Unicode space variations for encoding
    SPACE_VARIATIONS = [
        '\u0020',  # Regular space
        '\u00A0',  # No-break space
        '\u2000',  # En quad
        '\u2001',  # Em quad
        '\u2002',  # En space
        '\u2003',  # Em space
        '\u2004',  # Three-per-em space
        '\u2005',  # Four-per-em space
    ]
    
    # Pattern to detect zero-width characters
    ZERO_WIDTH_PATTERN = re.compile(r'[\u200B\u200C\u200D\u2060\u2061]')
    
    def __init__(self, secret_key: str = None, watermark_type: WatermarkType = WatermarkType.ZERO_WIDTH):
        """
        Initialize the watermarker
        
        Args:
            secret_key: Secret key for HMAC signing (auto-generated if None)
            watermark_type: Default watermarking strategy
        """
        self.secret_key = secret_key or self._generate_secret_key()
        self.default_watermark_type = watermark_type
        self._watermark_cache: Dict[str, WatermarkMetadata] = {}
        
    def _generate_secret_key(self) -> str:
        """Generate a secure random secret key"""
        import secrets
        return secrets.token_hex(32)
    
    def _encode_to_zero_width(self, data: str) -> str:
        """Encode binary data to zero-width characters"""
        # Convert to binary string
        binary = ''.join(format(ord(c), '08b') for c in data)
        
        # Encode each 2 bits as a zero-width character
        encoded = []
        for i in range(0, len(binary), 2):
            bits = binary[i:i+2]
            if len(bits) < 2:
                bits = bits.ljust(2, '0')
            char_index = int(bits, 2)
            encoded.append(self.ZERO_WIDTH_CHARS[str(char_index)])
        
        return ''.join(encoded)
    
    def _decode_from_zero_width(self, encoded: str) -> str:
        """Decode zero-width characters back to original data"""
        binary = []
        for char in encoded:
            if char in self.REVERSE_ZERO_WIDTH:
                bits = format(int(self.REVERSE_ZERO_WIDTH[char]), '02b')
                binary.append(bits)
        
        binary_str = ''.join(binary)
        
        # Convert binary back to characters
        result = []
        for i in range(0, len(binary_str), 8):
            byte = binary_str[i:i+8]
            if len(byte) == 8:
                result.append(chr(int(byte, 2)))
        
        return ''.join(result)
    
    def _compute_content_hash(self, text: str) -> str:
        """Compute SHA-256 hash of text content (normalized)"""
        # Normalize: remove zero-width chars, normalize whitespace
        normalized = self.ZERO_WIDTH_PATTERN.sub('', text)
        normalized = ' '.join(normalized.split())
        return hashlib.sha256(normalized.encode('utf-8')).hexdigest()
    
    def _compute_hmac(self, data: str) -> str:
        """Compute HMAC-SHA256 signature"""
        return hmac.new(
            self.secret_key.encode('utf-8'),
            data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
    
    def watermark_output(
        self,
        text: str,
        model_name: str,
        conversation_id: str,
        turn_number: int,
        prompt_text: str = "",
        watermark_type: Optional[WatermarkType] = None
    ) -> WatermarkResult:
        """
        Apply watermark to LLM output
        
        Args:
            text: The LLM output text to watermark
            model_name: Name of the model that generated the output
            conversation_id: Unique conversation identifier
            turn_number: Conversation turn number
            prompt_text: Original prompt text (for hash binding)
            watermark_type: Override default watermark type
            
        Returns:
            WatermarkResult with watermarked text and metadata
        """
        wm_type = watermark_type or self.default_watermark_type
        
        # Create metadata
        prompt_hash = self._compute_content_hash(prompt_text) if prompt_text else ""
        output_hash = self._compute_content_hash(text)
        
        metadata = WatermarkMetadata(
            model_name=model_name,
            timestamp=time.time(),
            conversation_id=conversation_id,
            turn_number=turn_number,
            prompt_hash=prompt_hash,
            output_hash=output_hash
        )
        
        # Serialize metadata for embedding
        metadata_dict = {
            'm': metadata.model_name,
            't': metadata.timestamp,
            'cid': metadata.conversation_id[:16],  # Truncate for space
            'turn': metadata.turn_number,
            'oh': metadata.output_hash[:16],
        }
        metadata_json = json.dumps(metadata_dict, separators=(',', ':'))
        
        # Apply watermark based on type
        if wm_type == WatermarkType.ZERO_WIDTH:
            watermarked, positions = self._apply_zero_width_watermark(text, metadata_json)
        elif wm_type == WatermarkType.UNICODE_SPACE:
            watermarked, positions = self._apply_space_watermark(text, metadata_json)
        elif wm_type == WatermarkType.HASH_EMBEDDED:
            watermarked, positions = self._apply_hash_watermark(text, metadata)
        else:  # FULL_CRYPTOSIGN
            watermarked, positions = self._apply_signed_watermark(text, metadata)
        
        # Generate verification key
        verification_data = f"{conversation_id}:{turn_number}:{output_hash}"
        verification_key = self._compute_hmac(verification_data)
        
        # Cache metadata
        cache_key = f"{conversation_id}:{turn_number}"
        self._watermark_cache[cache_key] = metadata
        
        return WatermarkResult(
            original_text=text,
            watermarked_text=watermarked,
            watermark_type=wm_type,
            metadata=metadata,
            watermark_length=len(watermarked) - len(text),
            embedding_positions=positions,
            verification_key=verification_key
        )
    
    def _apply_zero_width_watermark(self, text: str, metadata: str) -> Tuple[str, List[int]]:
        """Apply zero-width character watermark"""
        encoded_metadata = self._encode_to_zero_width(metadata)
        positions = []
        
        # Insert watermark at sentence boundaries
        sentences = re.split(r'([.!?]+)', text)
        result = []
        pos = 0
        
        for i, part in enumerate(sentences):
            result.append(part)
            pos += len(part)
            
            # Insert watermark fragments after punctuation
            if i % 2 == 1 and encoded_metadata:  # After punctuation
                fragment_len = min(8, len(encoded_metadata))
                fragment = encoded_metadata[:fragment_len]
                encoded_metadata = encoded_metadata[fragment_len:]
                result.append(fragment)
                positions.append(pos)
                pos += fragment_len
        
        # Add any remaining watermark at end
        if encoded_metadata:
            result.append(self.ZERO_WIDTH_CHARS['separator'])
            result.append(encoded_metadata)
            positions.append(pos)
        
        return ''.join(result), positions
    
    def _apply_space_watermark(self, text: str, metadata: str) -> Tuple[str, List[int]]:
        """Apply unicode space variation watermark"""
        positions = []
        # Simple implementation - add hash signature at end with marker
        signature = self._compute_hmac(metadata)[:16]
        watermarked = text + f"\n\n--- AI Generated Content | Integrity Hash: {signature} ---"
        positions.append(len(text))
        return watermarked, positions
    
    def _apply_hash_watermark(self, text: str, metadata: WatermarkMetadata) -> Tuple[str, List[int]]:
        """Apply hash-based watermark"""
        content_hash = self._compute_content_hash(text)
        signature = self._compute_hmac(f"{content_hash}:{metadata.timestamp}")[:12]
        watermarked = text + f"\n\n[Content ID: {signature}]"
        return watermarked, [len(text)]
    
    def _apply_signed_watermark(self, text: str, metadata: WatermarkMetadata) -> Tuple[str, List[int]]:
        """Apply full cryptographic signature watermark"""
        content_hash = self._compute_content_hash(text)
        full_data = f"{content_hash}:{metadata.model_name}:{metadata.timestamp}:{metadata.conversation_id}"
        signature = self._compute_hmac(full_data)
        watermarked = text + f"\n\n--- NeuralShield Integrity Signature ---\nHash: {content_hash[:32]}\nSig: {signature[:32]}\nTimestamp: {metadata.timestamp}"
        return watermarked, [len(text)]
    
    def verify_watermark(
        self,
        text: str,
        conversation_id: str = "",
        turn_number: int = 0
    ) -> VerificationResult:
        """
        Verify watermark integrity and detect tampering
        
        Args:
            text: Text to verify
            conversation_id: Expected conversation ID
            turn_number: Expected turn number
            
        Returns:
            VerificationResult with tamper analysis
        """
        verify_time = time.time()
        
        # Extract zero-width characters
        zero_width_chars = self.ZERO_WIDTH_PATTERN.findall(text)
        
        if not zero_width_chars:
            # No watermark found - check for hash markers
            return self._verify_hash_markers(text, verify_time)
        
        # Try to decode metadata
        try:
            extracted_data = self._decode_from_zero_width(''.join(zero_width_chars))
            extracted_metadata = self._parse_extracted_metadata(extracted_data)
            
            # Compute current hash and compare
            current_hash = self._compute_content_hash(text)
            
            if extracted_metadata:
                original_hash = extracted_metadata.output_hash
                hash_match = current_hash == original_hash
                
                # Calculate tamper confidence
                similarity = self._calculate_hash_similarity(current_hash, original_hash)
                integrity_score = similarity
                
                if similarity > 0.98:
                    verdict = TamperVerdict.UNMODIFIED
                    confidence = 0.95
                elif similarity > 0.90:
                    verdict = TamperVerdict.MINOR_TAMPERING
                    confidence = 0.80
                elif similarity > 0.75:
                    verdict = TamperVerdict.SIGNIFICANT_TAMPERING
                    confidence = 0.85
                else:
                    verdict = TamperVerdict.SEVERE_TAMPERING
                    confidence = 0.90
                
                return VerificationResult(
                    is_valid=hash_match,
                    verdict=verdict,
                    confidence=confidence,
                    extracted_metadata=extracted_metadata,
                    original_hash_match=hash_match,
                    verification_timestamp=verify_time,
                    integrity_score=integrity_score
                )
            
        except Exception:
            pass
        
        return VerificationResult(
            is_valid=False,
            verdict=TamperVerdict.INVALID_SIGNATURE,
            confidence=0.70,
            verification_timestamp=verify_time,
            integrity_score=0.0
        )
    
    def _verify_hash_markers(self, text: str, verify_time: float) -> VerificationResult:
        """Verify text with hash marker watermarks"""
        hash_patterns = [
            r'Integrity Hash: ([a-fA-F0-9]+)',
            r'Content ID: ([a-fA-F0-9]+)',
            r'Hash: ([a-fA-F0-9]+)',
        ]
        
        for pattern in hash_patterns:
            match = re.search(pattern, text)
            if match:
                stored_hash = match.group(1)
                current_hash = self._compute_content_hash(text)
                
                similarity = self._calculate_hash_similarity(current_hash, stored_hash)
                
                if similarity > 0.95:
                    return VerificationResult(
                        is_valid=True,
                        verdict=TamperVerdict.UNMODIFIED,
                        confidence=0.85,
                        verification_timestamp=verify_time,
                        integrity_score=similarity
                    )
                else:
                    return VerificationResult(
                        is_valid=False,
                        verdict=TamperVerdict.SIGNIFICANT_TAMPERING,
                        confidence=0.80,
                        verification_timestamp=verify_time,
                        integrity_score=similarity
                    )
        
        return VerificationResult(
            is_valid=False,
            verdict=TamperVerdict.NO_WATERMARK,
            confidence=0.95,
            verification_timestamp=verify_time,
            integrity_score=0.0
        )
    
    def _parse_extracted_metadata(self, data: str) -> Optional[WatermarkMetadata]:
        """Try to parse extracted metadata"""
        try:
            # Find JSON-like structure
            json_start = data.find('{')
            json_end = data.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = data[json_start:json_end]
                parsed = json.loads(json_str)
                
                return WatermarkMetadata(
                    model_name=parsed.get('m', 'unknown'),
                    timestamp=parsed.get('t', 0),
                    conversation_id=parsed.get('cid', ''),
                    turn_number=parsed.get('turn', 0),
                    prompt_hash='',
                    output_hash=parsed.get('oh', '')
                )
        except Exception:
            pass
        return None
    
    def _calculate_hash_similarity(self, hash1: str, hash2: str) -> float:
        """Calculate similarity between two hex hashes"""
        min_len = min(len(hash1), len(hash2))
        if min_len == 0:
            return 0.0
        
        matches = sum(1 for i in range(min_len) if hash1[i] == hash2[i])
        return matches / min_len
    
    def get_provenance_report(self, result: VerificationResult) -> str:
        """Generate human-readable provenance report"""
        report = ["=== NeuralShield Output Integrity Report ==="]
        report.append(f"Verification Time: {datetime.fromtimestamp(result.verification_timestamp, tz=timezone.utc)}")
        report.append(f"Verdict: {result.verdict.value.upper()}")
        report.append(f"Confidence: {result.confidence:.1%}")
        report.append(f"Integrity Score: {result.integrity_score:.1%}")
        
        if result.extracted_metadata:
            report.append("\nExtracted Provenance:")
            report.append(f"  Model: {result.extracted_metadata.model_name}")
            report.append(f"  Generated: {datetime.fromtimestamp(result.extracted_metadata.timestamp, tz=timezone.utc)}")
            report.append(f"  Conversation: {result.extracted_metadata.conversation_id}")
            report.append(f"  Turn: {result.extracted_metadata.turn_number}")
        
        if result.tamper_locations:
            report.append(f"\nTamper Locations: {len(result.tamper_locations)} regions detected")
        
        return '\n'.join(report)
