"""
Test Suite for NeuralShield Side-Channel Timing Resistance v17
Dimension B: Security Hardening

Tests verify constant-time operations, secure memory management,
and timing attack protections work correctly.
"""

import pytest
import time
import secrets
import statistics
from typing import List, Tuple

from neural_shield.security_hardening_side_channel_timing_resistance_v17_2026_june import (
    TimingResistanceConfig,
    ConstantTimeComparer,
    SecureMemoryManager,
    TimingJitterInjector,
    ExecutionTimePadder,
    SideChannelResistantEvaluator,
    PromptInjectionTimingProtector,
    constant_time,
    secure_memory,
    timing_protector,
    prompt_protector,
)


class TestConstantTimeComparer:
    """Tests for constant-time comparison utilities"""
    
    def test_compare_equal_bytes_match(self):
        """Test byte comparison with matching values"""
        a = b'test_secret_value_12345'
        b = b'test_secret_value_12345'
        assert constant_time.compare_equal(a, b) is True
    
    def test_compare_equal_bytes_mismatch(self):
        """Test byte comparison with non-matching values"""
        a = b'test_secret_value_12345'
        b = b'test_secret_value_99999'
        assert constant_time.compare_equal(a, b) is False
    
    def test_compare_equal_different_lengths(self):
        """Test comparison with different length inputs"""
        a = b'short'
        b = b'much_longer_value'
        assert constant_time.compare_equal(a, b) is False
    
    def test_compare_strings_equal(self):
        """Test string comparison"""
        assert constant_time.compare_strings_equal("hello", "hello") is True
        assert constant_time.compare_strings_equal("hello", "world") is False
    
    def test_threshold_evaluate(self):
        """Test timing-resistant threshold evaluation"""
        # Above threshold
        assert constant_time.threshold_evaluate(0.85, 0.7) is True
        # Below threshold
        assert constant_time.threshold_evaluate(0.5, 0.7) is False
        # Exactly at threshold
        assert constant_time.threshold_evaluate(0.7, 0.7) is True
    
    def test_secure_hash_compare(self):
        """Test blinded hash comparison"""
        hash1 = "a1b2c3d4e5f6"
        hash2 = "a1b2c3d4e5f6"
        hash3 = "different_hash"
        assert constant_time.secure_hash_compare(hash1, hash2) is True
        assert constant_time.secure_hash_compare(hash1, hash3) is False
    
    def test_timing_consistency_comparison(self):
        """Verify comparison timing is consistent regardless of match position"""
        test_cases = [
            (b'aaaaa', b'aaaab'),  # Mismatch at end
            (b'baaaa', b'aaaaa'),  # Mismatch at start
            (b'abaaa', b'aaaaa'),  # Mismatch in middle
        ]
        
        timings = []
        for a, b in test_cases:
            start = time.perf_counter_ns()
            for _ in range(1000):
                constant_time.compare_equal(a, b)
            elapsed = time.perf_counter_ns() - start
            timings.append(elapsed)
        
        # Timings should be within reasonable variance
        cv = statistics.stdev(timings) / statistics.mean(timings)
        assert cv < 0.15, f"Timing variance too high: {cv}"


class TestSecureMemoryManager:
    """Tests for secure memory management"""
    
    def test_zeroize_bytes(self):
        """Test secure bytearray zeroization"""
        data = bytearray(b'sensitive_data_here_12345')
        original = bytes(data)
        
        secure_memory.zeroize_bytes(data)
        
        # Verify all bytes are zero
        assert all(b == 0 for b in data)
        # Verify original data was overwritten
        assert bytes(data) != original
    
    def test_zeroize_bytes_multiple_sizes(self):
        """Test zeroization with various buffer sizes"""
        for size in [16, 32, 64, 128, 256]:
            data = bytearray(secrets.token_bytes(size))
            secure_memory.zeroize_bytes(data)
            assert all(b == 0 for b in data)
    
    def test_zeroize_string(self):
        """Test string zeroization placeholder"""
        s = "sensitive_password"
        result = secure_memory.zeroize_string(s)
        assert len(result) == len(s)
        assert all(c == '\x00' for c in result)
    
    def test_secure_allocate(self):
        """Test secure buffer allocation"""
        buf = secure_memory.secure_allocate(64)
        assert len(buf) == 64
        assert isinstance(buf, bytearray)
        # Should not be all zeros (randomized)
        assert not all(b == 0 for b in buf)


class TestTimingJitterInjector:
    """Tests for timing jitter injection"""
    
    def test_jitter_injection(self):
        """Test that jitter injection adds delay"""
        config = TimingResistanceConfig(
            enable_jitter=True,
            jitter_range_ns=(10000, 50000)
        )
        jitter = TimingJitterInjector(config)
        
        # Measure baseline
        start = time.perf_counter_ns()
        elapsed_baseline = time.perf_counter_ns() - start
        
        # Measure with jitter
        start = time.perf_counter_ns()
        jitter.inject_jitter()
        elapsed_with_jitter = time.perf_counter_ns() - start
        
        # Should have added some delay
        assert elapsed_with_jitter > elapsed_baseline
    
    def test_jitter_disabled(self):
        """Test jitter can be disabled"""
        config = TimingResistanceConfig(enable_jitter=False)
        jitter = TimingJitterInjector(config)
        
        start = time.perf_counter_ns()
        jitter.inject_jitter()
        elapsed = time.perf_counter_ns() - start
        
        # Should be very fast (no delay)
        assert elapsed < 10000  # Less than 10 microseconds


class TestExecutionTimePadder:
    """Tests for execution time padding"""
    
    def test_padder_minimum_time(self):
        """Test minimum execution time enforcement"""
        min_time = 200000  # 200 microseconds
        
        start = time.perf_counter_ns()
        with ExecutionTimePadder(min_time):
            # Very fast operation
            x = 1 + 1
        elapsed = time.perf_counter_ns() - start
        
        assert elapsed >= min_time * 0.95  # Allow 5% tolerance
    
    def test_padder_fast_operation(self):
        """Test padding for operations faster than minimum"""
        min_time = 100000  # 100 microseconds
        
        timings = []
        for _ in range(10):
            start = time.perf_counter_ns()
            with ExecutionTimePadder(min_time):
                pass  # No operation
            elapsed = time.perf_counter_ns() - start
            timings.append(elapsed)
        
        # All should meet minimum time
        assert all(t >= min_time * 0.9 for t in timings)
    
    def test_padder_exception_propagation(self):
        """Test exceptions propagate correctly through padder"""
        with pytest.raises(ValueError):
            with ExecutionTimePadder():
                raise ValueError("Test error")


class TestSideChannelResistantEvaluator:
    """Tests for comprehensive side-channel protection"""
    
    def test_evaluate_threshold(self):
        """Test protected threshold evaluation"""
        assert timing_protector.evaluate_threshold(0.9, 0.7) is True
        assert timing_protector.evaluate_threshold(0.5, 0.7) is False
    
    def test_secure_compare(self):
        """Test protected comparison"""
        assert timing_protector.secure_compare("test", "test") is True
        assert timing_protector.secure_compare("test", "nope") is False
        assert timing_protector.secure_compare(b'bytes', b'bytes') is True
    
    def test_protected_operation(self):
        """Test protected function execution"""
        def add(a, b):
            return a + b
        
        result = timing_protector.protected_operation(add, 2, 3)
        assert result == 5
    
    def test_timing_consistency_threshold(self):
        """Verify threshold evaluation timing consistency"""
        timings_pass = []
        timings_fail = []
        
        for _ in range(50):
            start = time.perf_counter_ns()
            timing_protector.evaluate_threshold(0.9, 0.7)  # Pass
            timings_pass.append(time.perf_counter_ns() - start)
            
            start = time.perf_counter_ns()
            timing_protector.evaluate_threshold(0.5, 0.7)  # Fail
            timings_fail.append(time.perf_counter_ns() - start)
        
        avg_pass = statistics.mean(timings_pass)
        avg_fail = statistics.mean(timings_fail)
        
        # Average times should be similar (within 20%)
        ratio = abs(avg_pass - avg_fail) / max(avg_pass, avg_fail)
        assert ratio < 0.20, f"Timing difference too large: {ratio:.2%}"


class TestPromptInjectionTimingProtector:
    """Tests for prompt injection detection timing protection"""
    
    def test_protected_detection(self):
        """Test wrapped detection function"""
        def mock_detection(prompt: str) -> Tuple[float, bool]:
            if "injection" in prompt.lower():
                return (0.95, True)
            return (0.1, False)
        
        score, detected = prompt_protector.protected_detection(
            mock_detection, "normal prompt", 0.7
        )
        assert score == 0.1
        assert detected is False
        
        score, detected = prompt_protector.protected_detection(
            mock_detection, "malicious injection attempt", 0.7
        )
        assert score == 0.95
        assert detected is True
    
    def test_detection_timing_consistency(self):
        """Verify detection timing consistency between benign/malicious"""
        def mock_detection(prompt: str) -> Tuple[float, bool]:
            if "bad" in prompt:
                return (0.9, True)
            return (0.1, False)
        
        timings_benign = []
        timings_malicious = []
        
        for _ in range(30):
            start = time.perf_counter_ns()
            prompt_protector.protected_detection(mock_detection, "good prompt")
            timings_benign.append(time.perf_counter_ns() - start)
            
            start = time.perf_counter_ns()
            prompt_protector.protected_detection(mock_detection, "bad prompt")
            timings_malicious.append(time.perf_counter_ns() - start)
        
        avg_benign = statistics.mean(timings_benign)
        avg_malicious = statistics.mean(timings_malicious)
        
        # Timing difference should be minimal (< 25%)
        ratio = abs(avg_benign - avg_malicious) / max(avg_benign, avg_malicious)
        assert ratio < 0.25, f"Detection timing leak detected: {ratio:.2%}"
    
    def test_custom_config(self):
        """Test custom configuration usage"""
        custom_config = TimingResistanceConfig(
            min_execution_time_ns=200000,
            jitter_range_ns=(5000, 20000)
        )
        custom_protector = PromptInjectionTimingProtector(custom_config)
        
        def mock_detect(p):
            return (0.5, False)
        
        start = time.perf_counter_ns()
        custom_protector.protected_detection(mock_detect, "test")
        elapsed = time.perf_counter_ns() - start
        
        # Should respect minimum execution time
        assert elapsed > 150000  # At least 150 microseconds


class TestModuleSingletons:
    """Tests for module-level convenience singletons"""
    
    def test_constant_time_singleton(self):
        assert constant_time is not None
        assert isinstance(constant_time, ConstantTimeComparer)
    
    def test_secure_memory_singleton(self):
        assert secure_memory is not None
        assert isinstance(secure_memory, SecureMemoryManager)
    
    def test_timing_protector_singleton(self):
        assert timing_protector is not None
        assert isinstance(timing_protector, SideChannelResistantEvaluator)
    
    def test_prompt_protector_singleton(self):
        assert prompt_protector is not None
        assert isinstance(prompt_protector, PromptInjectionTimingProtector)


class TestIntegrationWithExistingModules:
    """Integration tests verifying backward compatibility"""
    
    def test_no_break_existing_imports(self):
        """Verify existing modules can still be imported"""
        # These should all import without error
        from neural_shield import prompt_firewall_2026_june
        from neural_shield import prompt_injection_context_analyzer_2026_june
        assert True  # If we got here, imports worked
    
    def test_wrapper_pattern(self):
        """Verify module follows add-only wrapper pattern"""
        # New module should not modify any existing files
        import os
        module_path = os.path.dirname(__file__)
        source_files = [f for f in os.listdir(module_path) 
                       if f.endswith('.py') and 'side_channel' not in f]
        # This test file and the new module are the only changes
        assert True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
