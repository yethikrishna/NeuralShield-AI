"""
Tests for NeuralShield AI - Enhanced Distributed Tracing with Baggage Context v9
Dimension D: Observability & Instrumentation

Covers:
- W3C Trace Context compliance
- Baggage propagation
- Cross-module correlation IDs
- Intelligent sampling strategies
- Trace context injection/extraction
- Zero overhead when disabled
"""

import os
import pytest
import time
import threading
from unittest.mock import patch

# Import module
from neural_shield.observability_enhanced_distributed_tracing_baggage_v9_2026_june import (
    TraceContext,
    TraceManager,
    BaggageManager,
    TraceSampler,
    TraceFlag,
    SamplingStrategy,
    TraceLevel,
    TraceExporter,
    LogTraceExporter,
    traced,
    NS_TRACING_ENABLED,
)


class TestTraceContextW3CCompliance:
    """Test W3C Trace Context standard compliance"""
    
    def test_trace_id_format(self):
        """Trace ID must be 32 hex characters"""
        ctx = TraceContext()
        assert len(ctx.trace_id) == 32
        # Verify hex
        int(ctx.trace_id, 16)  # Should not raise
    
    def test_span_id_format(self):
        """Span ID must be 16 hex characters"""
        ctx = TraceContext()
        assert len(ctx.parent_id) == 16
        int(ctx.parent_id, 16)  # Should not raise
    
    def test_traceparent_serialization(self):
        """Test W3C traceparent format: version-traceid-parentid-flags"""
        ctx = TraceContext(flags=TraceFlag.SAMPLED.value)
        traceparent = ctx.to_traceparent()
        parts = traceparent.split("-")
        assert len(parts) == 4
        assert parts[0] == "00"  # version
        assert len(parts[1]) == 32  # trace_id
        assert len(parts[2]) == 16  # parent_id
        assert len(parts[3]) == 2  # flags hex
    
    def test_traceparent_parsing(self):
        """Test parsing valid W3C traceparent"""
        valid = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        ctx = TraceContext.from_traceparent(valid)
        assert ctx is not None
        assert ctx.version == "00"
        assert ctx.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
        assert ctx.parent_id == "00f067aa0ba902b7"
        assert ctx.flags == 0x01
    
    def test_traceparent_parsing_invalid(self):
        """Test parsing invalid traceparent formats"""
        invalid_cases = [
            "",
            "invalid",
            "00-tooshort-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-tooshort-01",
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",  # wrong version
        ]
        for invalid in invalid_cases:
            assert TraceContext.from_traceparent(invalid) is None
    
    def test_sampled_flag(self):
        """Test sampled flag detection and modification"""
        ctx = TraceContext(flags=0)
        assert not ctx.is_sampled()
        
        sampled = ctx.with_sampled(True)
        assert sampled.is_sampled()
        assert sampled.trace_id == ctx.trace_id  # Immutable, new object
    
    def test_child_span_creation(self):
        """Test child span inherits trace ID but gets new parent ID"""
        parent = TraceContext()
        child = parent.child_span("test_operation")
        
        assert child.trace_id == parent.trace_id  # Same trace
        assert child.parent_id != parent.parent_id  # Different span
        assert child.attributes["parent_span_id"] == parent.parent_id
    
    def test_duration_measurement(self):
        """Test duration measurement works"""
        ctx = TraceContext()
        time.sleep(0.01)
        duration = ctx.duration_ms()
        assert duration >= 10.0  # At least 10ms
    
    def test_to_headers(self):
        """Test HTTP headers generation"""
        ctx = TraceContext()
        headers = ctx.to_headers()
        assert "traceparent" in headers
        assert isinstance(headers["traceparent"], str)


class TestBaggageManager:
    """Test baggage context propagation"""
    
    def setup_method(self):
        BaggageManager.clear_baggage()
    
    def test_set_and_get_baggage(self):
        """Test basic baggage operations"""
        BaggageManager.set_baggage("user_id", "user_123")
        assert BaggageManager.get_baggage("user_id") == "user_123"
    
    def test_get_baggage_default(self):
        """Test default value for missing baggage"""
        assert BaggageManager.get_baggage("nonexistent", "default") == "default"
    
    def test_get_all_baggage(self):
        """Test getting all baggage entries"""
        BaggageManager.set_baggage("key1", "val1")
        BaggageManager.set_baggage("key2", "val2")
        all_baggage = BaggageManager.get_all_baggage()
        assert all_baggage["key1"] == "val1"
        assert all_baggage["key2"] == "val2"
    
    def test_remove_baggage(self):
        """Test removing baggage entry"""
        BaggageManager.set_baggage("temp", "value")
        BaggageManager.remove_baggage("temp")
        assert BaggageManager.get_baggage("temp") is None
    
    def test_clear_baggage(self):
        """Test clearing all baggage"""
        BaggageManager.set_baggage("key", "val")
        BaggageManager.clear_baggage()
        assert BaggageManager.get_all_baggage() == {}
    
    def test_baggage_header_serialization(self):
        """Test W3C baggage header format"""
        BaggageManager.set_baggage("tenant", "acme")
        BaggageManager.set_baggage("env", "prod")
        header = BaggageManager.to_baggage_header()
        assert "tenant=acme" in header
        assert "env=prod" in header
    
    def test_baggage_header_parsing(self):
        """Test parsing W3C baggage header"""
        header = "tenant=acme,env=prod,user=alice"
        BaggageManager.from_baggage_header(header)
        assert BaggageManager.get_baggage("tenant") == "acme"
        assert BaggageManager.get_baggage("env") == "prod"
    
    def test_baggage_size_limits(self):
        """Test baggage entry limits are enforced"""
        for i in range(100):  # More than MAX_ENTRIES
            BaggageManager.set_baggage(f"key{i}", f"val{i}")
        all_baggage = BaggageManager.get_all_baggage()
        assert len(all_baggage) <= BaggageManager.MAX_ENTRIES


class TestTraceSampler:
    """Test intelligent sampling strategies"""
    
    def test_always_off_strategy(self):
        """ALWAYS_OFF never samples"""
        sampler = TraceSampler(strategy=SamplingStrategy.ALWAYS_OFF)
        ctx = TraceContext()
        for _ in range(100):
            assert not sampler.should_sample(ctx)
    
    def test_always_on_strategy(self):
        """ALWAYS_ON always samples"""
        sampler = TraceSampler(strategy=SamplingStrategy.ALWAYS_ON)
        ctx = TraceContext()
        for _ in range(100):
            assert sampler.should_sample(ctx)
    
    def test_error_only_strategy(self):
        """ERROR_ONLY samples only when error occurred"""
        sampler = TraceSampler(strategy=SamplingStrategy.ERROR_ONLY)
        ctx = TraceContext()
        assert not sampler.should_sample(ctx, error_occurred=False)
        assert sampler.should_sample(ctx, error_occurred=True)
    
    def test_probabilistic_strategy(self):
        """PROBABILISTIC samples at given rate"""
        sampler = TraceSampler(
            strategy=SamplingStrategy.PROBABILISTIC,
            sample_rate=1.0
        )
        ctx = TraceContext()
        for _ in range(100):
            assert sampler.should_sample(ctx)
    
    def test_rate_limited_strategy(self):
        """RATE_LIMITED enforces TPS limit"""
        sampler = TraceSampler(
            strategy=SamplingStrategy.RATE_LIMITED,
            max_traces_per_second=5
        )
        ctx = TraceContext()
        sampled = 0
        for _ in range(20):
            if sampler.should_sample(ctx):
                sampled += 1
        assert sampled <= 5  # Should respect limit
    
    def test_adaptive_strategy(self):
        """ADAPTIVE samples errors always, success rarely"""
        sampler = TraceSampler(
            strategy=SamplingStrategy.ADAPTIVE,
            sample_rate=0.0
        )
        ctx = TraceContext()
        # Errors always sampled
        assert sampler.should_sample(ctx, error_occurred=True)
        # Success never sampled at 0% rate
        assert not sampler.should_sample(ctx, error_occurred=False)
    
    def test_deterministic_sampling(self):
        """Deterministic sampling based on trace ID hash"""
        sampler = TraceSampler(sample_rate=1.0)
        trace_id = TraceContext.generate_trace_id()
        # Same trace ID always gives same result
        result1 = sampler.deterministic_sample(trace_id)
        result2 = sampler.deterministic_sample(trace_id)
        assert result1 == result2


class TestTraceManager:
    """Test global trace manager"""
    
    def test_is_enabled(self):
        """Test enabled check works"""
        # Should return bool
        assert isinstance(TraceManager.is_enabled(), bool)
    
    def test_start_and_end_trace(self):
        """Test basic trace lifecycle"""
        ctx = TraceManager.start_trace("test_operation")
        assert ctx is not None
        assert ctx.attributes["trace_name"] == "test_operation"
        
        summary = TraceManager.end_trace(ctx)
        # Summary is None unless sampled
        assert summary is None or isinstance(summary, dict)
    
    def test_start_trace_with_attributes(self):
        """Test starting trace with custom attributes"""
        attrs = {"module": "security", "operation": "scan"}
        ctx = TraceManager.start_trace("test", attributes=attrs)
        assert ctx.attributes["module"] == "security"
        assert ctx.attributes["operation"] == "scan"
    
    def test_start_trace_with_parent(self):
        """Test starting child trace from parent"""
        parent = TraceContext()
        child = TraceManager.start_trace("child", parent=parent)
        assert child.trace_id == parent.trace_id
    
    def test_current_trace_context(self):
        """Test getting current trace context"""
        ctx = TraceManager.start_trace("current_test")
        current = TraceManager.current_trace()
        # When disabled, current may be None
        if NS_TRACING_ENABLED:
            assert current is not None
        TraceManager.end_trace(ctx)
    
    def test_extract_context_from_headers(self):
        """Test extracting trace context from HTTP headers"""
        headers = {
            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        }
        ctx = TraceManager.extract_context(headers)
        if NS_TRACING_ENABLED:
            assert ctx is not None
            assert ctx.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    
    def test_inject_context_to_headers(self):
        """Test injecting trace context to headers"""
        ctx = TraceManager.start_trace("inject_test")
        headers = TraceManager.inject_context(ctx)
        assert isinstance(headers, dict)
    
    def test_correlation_id_generation(self):
        """Test correlation ID generation and persistence"""
        BaggageManager.clear_baggage()
        corr_id = TraceManager.get_correlation_id()
        assert corr_id.startswith("ns-correlation-")
        assert len(corr_id) > 20
        
        # Same ID returned on subsequent calls
        corr_id2 = TraceManager.get_correlation_id()
        assert corr_id == corr_id2


class TestTracedDecorator:
    """Test @traced decorator"""
    
    def test_decorator_basic_functionality(self):
        """Test decorator wraps function correctly"""
        @traced(name="test_func")
        def add(a, b):
            return a + b
        
        result = add(2, 3)
        assert result == 5
    
    def test_decorator_preserves_function(self):
        """Test decorator preserves function behavior"""
        call_count = [0]
        
        @traced()
        def my_func():
            call_count[0] += 1
            return "success"
        
        result = my_func()
        assert result == "success"
        assert call_count[0] == 1
    
    def test_decorator_exception_propagation(self):
        """Test decorator propagates exceptions correctly"""
        @traced(capture_exceptions=True)
        def error_func():
            raise ValueError("test error")
        
        with pytest.raises(ValueError, match="test error"):
            error_func()
    
    def test_decorator_with_attributes(self):
        """Test decorator with custom attributes"""
        @traced(attributes={"category": "test", "priority": "high"})
        def func():
            return True
        
        assert func() is True


class TestTraceExporter:
    """Test trace exporters"""
    
    def test_base_exporter_interface(self):
        """Test base exporter interface"""
        exporter = TraceExporter()
        # Should not raise
        exporter.export({"trace_id": "test"})
    
    def test_log_exporter(self):
        """Test log exporter creates valid JSON"""
        exporter = LogTraceExporter()
        summary = {
            "trace_id": "abc123",
            "span_id": "def456",
            "duration_ms": 42.5
        }
        # Should not raise
        exporter.export(summary)


class TestThreadSafety:
    """Test thread safety of context management"""
    
    def test_baggage_thread_isolation(self):
        """Test baggage is isolated per thread"""
        results = []
        
        def worker(thread_id):
            BaggageManager.set_baggage("thread_id", str(thread_id))
            time.sleep(0.01)  # Let other threads run
            val = BaggageManager.get_baggage("thread_id")
            results.append((thread_id, val))
        
        threads = []
        for i in range(3):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # Each thread should see its own value
        for expected, actual in results:
            assert actual == str(expected)


class TestEnums:
    """Test enum classes"""
    
    def test_trace_flag_values(self):
        """Test trace flag values are correct"""
        assert TraceFlag.NOT_SAMPLED.value == 0x00
        assert TraceFlag.SAMPLED.value == 0x01
    
    def test_sampling_strategy_enum(self):
        """Test all sampling strategies exist"""
        assert hasattr(SamplingStrategy, "ALWAYS_OFF")
        assert hasattr(SamplingStrategy, "ALWAYS_ON")
        assert hasattr(SamplingStrategy, "PROBABILISTIC")
        assert hasattr(SamplingStrategy, "RATE_LIMITED")
        assert hasattr(SamplingStrategy, "ERROR_ONLY")
        assert hasattr(SamplingStrategy, "ADAPTIVE")
    
    def test_trace_level_enum(self):
        """Test trace level enum exists"""
        assert hasattr(TraceLevel, "MINIMAL")
        assert hasattr(TraceLevel, "STANDARD")
        assert hasattr(TraceLevel, "DETAILED")
        assert hasattr(TraceLevel, "DEBUG")


class TestModuleExports:
    """Test module exports are complete"""
    
    def test_all_exports_present(self):
        """Test all expected exports are available"""
        import neural_shield.observability_enhanced_distributed_tracing_baggage_v9_2026_june as module
        
        expected_exports = [
            "TraceContext",
            "TraceManager",
            "BaggageManager",
            "TraceSampler",
            "TraceFlag",
            "SamplingStrategy",
            "TraceLevel",
            "TraceExporter",
            "LogTraceExporter",
            "traced",
            "NS_TRACING_ENABLED",
        ]
        
        for export in expected_exports:
            assert hasattr(module, export), f"Missing export: {export}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
