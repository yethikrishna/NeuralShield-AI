"""
Test Suite for Threat Intelligence IOC Hash Validator
June 2026 - Production Grade Tests
"""

import pytest
import json
from neural_shield.threat_intelligence_ioc_hash_validator_2026_june import (
    IOCHashValidator,
    HashType,
    HashValidationStatus,
    HashValidationResult
)


class TestHashTypeDetection:
    """Tests for hash type auto-detection"""

    def setup_method(self):
        self.validator = IOCHashValidator()

    def test_detect_md5(self):
        """Test MD5 hash detection"""
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        assert self.validator.detect_hash_type(md5_hash) == HashType.MD5

    def test_detect_sha1(self):
        """Test SHA1 hash detection"""
        sha1_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert self.validator.detect_hash_type(sha1_hash) == HashType.SHA1

    def test_detect_sha256(self):
        """Test SHA256 hash detection"""
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert self.validator.detect_hash_type(sha256_hash) == HashType.SHA256

    def test_detect_sha512(self):
        """Test SHA512 hash detection"""
        sha512_hash = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        assert self.validator.detect_hash_type(sha512_hash) == HashType.SHA512

    def test_detect_unknown_short(self):
        """Test detection of too short hash"""
        assert self.validator.detect_hash_type("abc123") == HashType.UNKNOWN

    def test_detect_unknown_invalid_chars(self):
        """Test detection with invalid hex characters"""
        assert self.validator.detect_hash_type("g41d8cd98f00b204e9800998ecf8427e") == HashType.UNKNOWN


class TestHashNormalization:
    """Tests for hash normalization"""

    def setup_method(self):
        self.validator = IOCHashValidator()

    def test_normalize_lowercase(self):
        """Test uppercase to lowercase normalization"""
        result = self.validator.normalize_hash("D41D8CD98F00B204E9800998ECF8427E")
        assert result == "d41d8cd98f00b204e9800998ecf8427e"

    def test_normalize_trim_whitespace(self):
        """Test whitespace trimming"""
        result = self.validator.normalize_hash("  d41d8cd98f00b204e9800998ecf8427e  ")
        assert result == "d41d8cd98f00b204e9800998ecf8427e"

    def test_case_sensitive_preserved(self):
        """Test case sensitive mode preserves case"""
        validator = IOCHashValidator(case_sensitive=True)
        result = validator.normalize_hash("D41D8CD98F00B204E9800998ECF8427E")
        assert result == "D41D8CD98F00B204E9800998ECF8427E"


class TestHashValidation:
    """Tests for core hash validation"""

    def setup_method(self):
        self.validator = IOCHashValidator()

    def test_valid_md5_hash(self):
        """Test validation of valid MD5 hash"""
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        result = self.validator.validate_single_hash(md5_hash)
        
        assert result.is_valid is True
        assert result.status == HashValidationStatus.VALID
        assert result.hash_type == HashType.MD5
        assert result.confidence_score == 0.7

    def test_valid_sha256_hash(self):
        """Test validation of valid SHA256 hash"""
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = self.validator.validate_single_hash(sha256_hash)
        
        assert result.is_valid is True
        assert result.status == HashValidationStatus.VALID
        assert result.hash_type == HashType.SHA256
        assert result.confidence_score == 0.98

    def test_invalid_format_hash(self):
        """Test validation of invalid hash format"""
        invalid_hash = "invalid_hash_123"
        result = self.validator.validate_single_hash(invalid_hash)
        
        assert result.is_valid is False
        assert result.status == HashValidationStatus.INVALID_FORMAT

    def test_hash_too_short(self):
        """Test validation of hash with wrong length"""
        result = self.validator.validate_single_hash("abc123")
        assert result.is_valid is False
        assert result.status == HashValidationStatus.INVALID_FORMAT


class TestWhitelistBlacklist:
    """Tests for whitelist and blacklist functionality"""

    def test_whitelist_detection(self):
        """Test whitelist hash detection"""
        whitelisted = "d41d8cd98f00b204e9800998ecf8427e"
        validator = IOCHashValidator(whitelist_hashes=[whitelisted])
        
        result = validator.validate_single_hash(whitelisted)
        assert result.status == HashValidationStatus.WHITELISTED
        assert result.is_valid is False

    def test_blacklist_detection(self):
        """Test blacklist hash detection"""
        blacklisted = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        validator = IOCHashValidator(blacklist_hashes=[blacklisted])
        
        result = validator.validate_single_hash(blacklisted)
        assert result.status == HashValidationStatus.BLACKLISTED
        assert result.is_valid is True
        assert result.enrichment_data["threat_level"] == "high"

    def test_add_to_whitelist_runtime(self):
        """Test adding to whitelist after initialization"""
        validator = IOCHashValidator()
        test_hash = "d41d8cd98f00b204e9800998ecf8427e"
        
        # First validation should be valid
        result1 = validator.validate_single_hash(test_hash)
        assert result1.status == HashValidationStatus.VALID
        
        # Add to whitelist
        validator.add_to_whitelist([test_hash])
        
        # Clear cache and re-validate
        validator.clear_processed_cache()
        result2 = validator.validate_single_hash(test_hash)
        assert result2.status == HashValidationStatus.WHITELISTED


class TestDuplicateDetection:
    """Tests for duplicate hash detection"""

    def test_duplicate_detection_enabled(self):
        """Test duplicate detection when enabled"""
        validator = IOCHashValidator(enable_duplicate_detection=True)
        test_hash = "d41d8cd98f00b204e9800998ecf8427e"
        
        # First validation
        result1 = validator.validate_single_hash(test_hash)
        assert result1.status == HashValidationStatus.VALID
        
        # Second validation - duplicate
        result2 = validator.validate_single_hash(test_hash)
        assert result2.status == HashValidationStatus.DUPLICATE
        assert "first_seen" in result2.validation_details

    def test_duplicate_detection_disabled(self):
        """Test duplicate detection when disabled"""
        validator = IOCHashValidator(enable_duplicate_detection=False)
        test_hash = "d41d8cd98f00b204e9800998ecf8427e"
        
        # Both validations should be VALID
        result1 = validator.validate_single_hash(test_hash)
        result2 = validator.validate_single_hash(test_hash)
        
        assert result1.status == HashValidationStatus.VALID
        assert result2.status == HashValidationStatus.VALID

    def test_clear_processed_cache(self):
        """Test clearing processed cache"""
        validator = IOCHashValidator()
        test_hash = "d41d8cd98f00b204e9800998ecf8427e"
        
        validator.validate_single_hash(test_hash)
        validator.clear_processed_cache()
        
        # Should not be duplicate after cache clear
        result = validator.validate_single_hash(test_hash)
        assert result.status == HashValidationStatus.VALID


class TestBatchProcessing:
    """Tests for batch hash validation"""

    def setup_method(self):
        self.validator = IOCHashValidator(enable_duplicate_detection=False)

    def test_batch_validation_all_valid(self):
        """Test batch validation with all valid hashes"""
        hashes = [
            "d41d8cd98f00b204e9800998ecf8427e",  # MD5
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256
        ]
        
        results = self.validator.validate_batch(hashes)
        
        assert len(results) == 3
        assert all(r.is_valid for r in results)
        assert results[0].hash_type == HashType.MD5
        assert results[1].hash_type == HashType.SHA1
        assert results[2].hash_type == HashType.SHA256

    def test_batch_validation_mixed(self):
        """Test batch validation with mixed valid/invalid hashes"""
        hashes = [
            "d41d8cd98f00b204e9800998ecf8427e",  # Valid
            "invalid_hash",  # Invalid
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # Valid
        ]
        
        results = self.validator.validate_batch(hashes)
        
        assert len(results) == 3
        assert results[0].is_valid is True
        assert results[1].is_valid is False
        assert results[2].is_valid is True


class TestFileContentValidation:
    """Tests for file content hash generation and validation"""

    def setup_method(self):
        self.validator = IOCHashValidator()

    def test_empty_file_content(self):
        """Test hashing empty file content"""
        content = b""
        results = self.validator.validate_file_content(content)
        
        assert "md5" in results
        assert "sha1" in results
        assert "sha256" in results
        assert "sha512" in results
        assert all(r.is_valid for r in results.values())
        
        # Verify empty file MD5
        assert results["md5"].normalized_hash == "d41d8cd98f00b204e9800998ecf8427e"

    def test_sample_file_content(self):
        """Test hashing sample content"""
        content = b"Hello, NeuralShield-AI Security!"
        results = self.validator.validate_file_content(content)
        
        assert all(r.is_valid for r in results.values())
        assert results["sha256"].confidence_score == 0.98


class TestStatistics:
    """Tests for validation statistics"""

    def test_statistics_tracking(self):
        """Test statistics are properly tracked"""
        validator = IOCHashValidator()
        
        # Process some hashes
        validator.validate_single_hash("d41d8cd98f00b204e9800998ecf8427e")  # Valid
        validator.validate_single_hash("invalid")  # Invalid
        validator.validate_single_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709")  # Valid
        
        stats = validator.get_statistics()
        
        assert stats["total_processed"] == 3
        assert stats["valid"] == 2
        assert stats["invalid_format"] == 1
        assert stats["valid_percentage"] > 60

    def test_empty_statistics(self):
        """Test statistics with no processing"""
        validator = IOCHashValidator()
        stats = validator.get_statistics()
        
        assert stats["total_processed"] == 0
        assert stats["valid_percentage"] == 0.0


class TestExportResults:
    """Tests for result export functionality"""

    def test_export_json(self):
        """Test JSON export"""
        validator = IOCHashValidator()
        results = validator.validate_batch([
            "d41d8cd98f00b204e9800998ecf8427e",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ])
        
        json_output = validator.export_results(results, "json")
        parsed = json.loads(json_output)
        
        assert len(parsed) == 2
        assert "hash_value" in parsed[0]
        assert "is_valid" in parsed[0]

    def test_export_jsonl(self):
        """Test JSONL export"""
        validator = IOCHashValidator()
        results = validator.validate_batch([
            "d41d8cd98f00b204e9800998ecf8427e"
        ])
        
        jsonl_output = validator.export_results(results, "jsonl")
        lines = jsonl_output.strip().split("\n")
        
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert "normalized_hash" in parsed


class TestEnrichmentData:
    """Tests for hash enrichment data"""

    def test_enrichment_data_present(self):
        """Test enrichment data is included in results"""
        validator = IOCHashValidator()
        result = validator.validate_single_hash(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        
        enrichment = result.enrichment_data
        assert "hash_entropy" in enrichment
        assert "cryptographic_strength" in enrichment
        assert "recommended_for_threat_intel" in enrichment
        assert "bit_length" in enrichment
        assert enrichment["bit_length"] == 256

    def test_entropy_calculation(self):
        """Test entropy calculation produces reasonable values"""
        validator = IOCHashValidator()
        result = validator.validate_single_hash(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        
        # Hex strings should have entropy around 4 bits per character
        entropy = result.enrichment_data["hash_entropy"]
        assert 3.0 < entropy < 5.0


class TestResultToDict:
    """Tests for HashValidationResult serialization"""

    def test_result_to_dict(self):
        """Test result converts to dictionary properly"""
        result = HashValidationResult(
            hash_value="test_hash",
            hash_type=HashType.SHA256,
            status=HashValidationStatus.VALID,
            normalized_hash="test_hash",
            is_valid=True,
            confidence_score=0.98
        )
        
        result_dict = result.to_dict()
        
        assert result_dict["hash_value"] == "test_hash"
        assert result_dict["hash_type"] == "sha256"
        assert result_dict["status"] == "valid"
        assert result_dict["is_valid"] is True
        assert result_dict["confidence_score"] == 0.98


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
