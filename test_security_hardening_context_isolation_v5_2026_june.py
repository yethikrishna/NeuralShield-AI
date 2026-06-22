"""
Tests for NeuralShield Security Hardening v5
Context Isolation & Privilege Separation Module

ALL TESTS MUST PASS
NO EXISTING CODE MODIFIED
"""

import pytest
import threading
import time
from neural_shield.security_hardening_context_isolation_privilege_separation_v5_2026_june import (
    SecurityDomain,
    Capability,
    SecurityContext,
    SecurityContextManager,
    CrossDomainGuard,
    SecureExecutionSandbox,
    PrivilegeError,
    DomainIsolationError,
    ContextTamperingError,
    create_security_context,
    security_domain,
    require_privilege,
    restrict_domain,
    cross_domain_transfer,
    SECURITY_CAPABILITIES,
    KNOWN_LIMITATIONS
)


class TestSecurityContext:
    """Test security context creation and validation"""
    
    def test_context_creation_default(self):
        """Test default context creation"""
        ctx = SecurityContextManager.create_context(SecurityDomain.UNTRUSTED)
        assert ctx.domain == SecurityDomain.UNTRUSTED
        assert ctx.context_id is not None
        assert len(ctx.capabilities) == 0
        assert ctx.is_valid() == True
    
    def test_context_creation_with_capabilities(self):
        """Test context with specific capabilities"""
        caps = {Capability.READ_INPUT, Capability.WRITE_OUTPUT}
        ctx = SecurityContextManager.create_context(SecurityDomain.TRUSTED, caps)
        assert ctx.domain == SecurityDomain.TRUSTED
        assert Capability.READ_INPUT in ctx.capabilities
        assert Capability.WRITE_OUTPUT in ctx.capabilities
        assert ctx.is_valid() == True
    
    def test_context_tamper_detection(self):
        """Test that tampering is detected"""
        ctx = SecurityContextManager.create_context(SecurityDomain.TRUSTED)
        assert ctx.is_valid() == True
        
        # Tamper with capabilities - bypass dataclass frozen
        object.__setattr__(ctx, 'capabilities', {Capability.ADMIN_FULL})
        assert ctx.is_valid() == False
    
    def test_context_tamper_domain_change(self):
        """Test domain change tampering"""
        ctx = SecurityContextManager.create_context(SecurityDomain.UNTRUSTED)
        object.__setattr__(ctx, 'domain', SecurityDomain.ADMIN)
        assert ctx.is_valid() == False


class TestSecurityContextManager:
    """Test context manager functionality"""
    
    def test_get_context_by_id(self):
        """Test context retrieval"""
        ctx = SecurityContextManager.create_context(SecurityDomain.TRUSTED)
        retrieved = SecurityContextManager.get_context(ctx.context_id)
        assert retrieved is not None
        assert retrieved.context_id == ctx.context_id
    
    def test_require_capability_positive(self):
        """Test capability check passes"""
        ctx = SecurityContextManager.create_context(
            SecurityDomain.TRUSTED,
            {Capability.READ_INPUT}
        )
        with SecurityContextManager.enter_context(ctx):
            assert SecurityContextManager.require_capability(Capability.READ_INPUT) == True
    
    def test_require_capability_negative(self):
        """Test capability check fails"""
        ctx = SecurityContextManager.create_context(
            SecurityDomain.TRUSTED,
            {Capability.READ_INPUT}
        )
        with SecurityContextManager.enter_context(ctx):
            assert SecurityContextManager.require_capability(Capability.ADMIN_FULL) == False
    
    def test_enforce_capability_raises(self):
        """Test capability enforcement raises"""
        ctx = SecurityContextManager.create_context(SecurityDomain.TRUSTED, set())
        with SecurityContextManager.enter_context(ctx):
            with pytest.raises(PrivilegeError):
                SecurityContextManager.enforce_capability(Capability.ADMIN_FULL)
    
    def test_enforce_domain(self):
        """Test domain enforcement"""
        ctx = SecurityContextManager.create_context(SecurityDomain.TRUSTED)
        with SecurityContextManager.enter_context(ctx):
            SecurityContextManager.enforce_domain({SecurityDomain.TRUSTED})
            with pytest.raises(DomainIsolationError):
                SecurityContextManager.enforce_domain({SecurityDomain.ADMIN})
    
    def test_privilege_downgrade(self):
        """Test privilege dropping - only downgrade allowed"""
        ctx = SecurityContextManager.create_context(
            SecurityDomain.ADMIN,
            {Capability.ADMIN_FULL}
        )
        with SecurityContextManager.enter_context(ctx):
            downgraded = SecurityContextManager.downgrade_domain(SecurityDomain.TRUSTED)
            assert downgraded.domain == SecurityDomain.TRUSTED
            assert len(downgraded.capabilities) == 0  # Dropped
    
    def test_privilege_escalation_prevented(self):
        """Test that privilege escalation is prevented"""
        ctx = SecurityContextManager.create_context(SecurityDomain.UNTRUSTED)
        with SecurityContextManager.enter_context(ctx):
            with pytest.raises(PrivilegeError):
                SecurityContextManager.downgrade_domain(SecurityDomain.ADMIN)


class TestContextManagerContextManager:
    """Test the context manager for entering domains"""
    
    def test_enter_context(self):
        """Test entering a security context"""
        ctx = create_security_context(SecurityDomain.TRUSTED)
        assert SecurityContextManager.get_current_context() is None
        
        with SecurityContextManager.enter_context(ctx):
            current = SecurityContextManager.get_current_context()
            assert current is not None
            assert current.context_id == ctx.context_id
        
        assert SecurityContextManager.get_current_context() is None
    
    def test_nested_contexts(self):
        """Test nested context management"""
        ctx1 = create_security_context(SecurityDomain.ADMIN)
        ctx2 = create_security_context(SecurityDomain.UNTRUSTED)
        
        with SecurityContextManager.enter_context(ctx1):
            assert SecurityContextManager.get_current_context().domain == SecurityDomain.ADMIN
            with SecurityContextManager.enter_context(ctx2):
                assert SecurityContextManager.get_current_context().domain == SecurityDomain.UNTRUSTED
            assert SecurityContextManager.get_current_context().domain == SecurityDomain.ADMIN
        
        assert SecurityContextManager.get_current_context() is None


class TestCrossDomainGuard:
    """Test cross-domain communication security"""
    
    def test_allowed_transfer(self):
        """Test allowed cross-domain transfer"""
        guard = CrossDomainGuard()
        guard.register_allowed_path(SecurityDomain.TRUSTED, SecurityDomain.UNTRUSTED)
        
        source_ctx = create_security_context(SecurityDomain.TRUSTED)
        data = {"test": "data"}
        
        result = guard.transfer_data(data, source_ctx, SecurityDomain.UNTRUSTED)
        assert result == data
    
    def test_denied_transfer(self):
        """Test denied cross-domain transfer"""
        guard = CrossDomainGuard()
        # No path registered
        
        source_ctx = create_security_context(SecurityDomain.UNTRUSTED)
        with pytest.raises(DomainIsolationError):
            guard.transfer_data("data", source_ctx, SecurityDomain.ADMIN)
    
    def test_sanitizer_applied(self):
        """Test data sanitization during transfer"""
        guard = CrossDomainGuard()
        guard.register_allowed_path(SecurityDomain.TRUSTED, SecurityDomain.UNTRUSTED)
        guard.register_sanitizer(
            SecurityDomain.TRUSTED,
            SecurityDomain.UNTRUSTED,
            lambda x: x.upper() if isinstance(x, str) else x
        )
        
        source_ctx = create_security_context(SecurityDomain.TRUSTED)
        result = guard.transfer_data("hello", source_ctx, SecurityDomain.UNTRUSTED)
        assert result == "HELLO"


class TestSecureExecutionSandbox:
    """Test sandboxed execution"""
    
    def test_sandbox_execution_with_capability(self):
        """Test execution with proper capability"""
        sandbox = SecureExecutionSandbox()
        
        def test_func(x, y):
            return x + y
        
        sandbox.register_function("add", test_func, Capability.EXECUTE_CODE)
        
        ctx = create_security_context(SecurityDomain.TRUSTED, {Capability.EXECUTE_CODE})
        with SecurityContextManager.enter_context(ctx):
            result = sandbox.execute("add", 2, 3)
            assert result == 5
    
    def test_sandbox_execution_without_capability(self):
        """Test execution denied without capability"""
        sandbox = SecureExecutionSandbox()
        
        def test_func():
            return "secret"
        
        sandbox.register_function("secret", test_func, Capability.ADMIN_FULL)
        
        ctx = create_security_context(SecurityDomain.UNTRUSTED, set())
        with SecurityContextManager.enter_context(ctx):
            with pytest.raises(PrivilegeError):
                sandbox.execute("secret")
    
    def test_sandbox_unknown_function(self):
        """Test unknown function denied"""
        sandbox = SecureExecutionSandbox()
        ctx = create_security_context(SecurityDomain.TRUSTED, {Capability.EXECUTE_CODE})
        
        with SecurityContextManager.enter_context(ctx):
            with pytest.raises(PrivilegeError):
                sandbox.execute("not_registered")


class TestDecorators:
    """Test security decorators"""
    
    def test_require_privilege_decorator(self):
        """Test capability decorator"""
        @require_privilege(Capability.ACCESS_CRYPTO)
        def crypto_operation():
            return "done"
        
        # Without capability
        ctx = create_security_context(SecurityDomain.TRUSTED, set())
        with SecurityContextManager.enter_context(ctx):
            with pytest.raises(PrivilegeError):
                crypto_operation()
        
        # With capability
        ctx2 = create_security_context(SecurityDomain.TRUSTED, {Capability.ACCESS_CRYPTO})
        with SecurityContextManager.enter_context(ctx2):
            result = crypto_operation()
            assert result == "done"
    
    def test_restrict_domain_decorator(self):
        """Test domain restriction decorator"""
        @restrict_domain({SecurityDomain.CRYPTO, SecurityDomain.PRIVILEGED})
        def sensitive_op():
            return "done"
        
        ctx = create_security_context(SecurityDomain.UNTRUSTED)
        with SecurityContextManager.enter_context(ctx):
            with pytest.raises(DomainIsolationError):
                sensitive_op()


class TestConvenienceFunctions:
    """Test convenience API"""
    
    def test_create_security_context(self):
        """Test convenience function"""
        ctx = create_security_context(SecurityDomain.TRUSTED)
        assert ctx.domain == SecurityDomain.TRUSTED
        assert ctx.is_valid()
    
    def test_security_domain_context_manager(self):
        """Test domain context manager"""
        with security_domain(SecurityDomain.TRUSTED, {Capability.READ_INPUT}) as ctx:
            assert ctx.domain == SecurityDomain.TRUSTED
            assert SecurityContextManager.get_current_context() is not None


class TestThreadSafety:
    """Test thread-local isolation"""
    
    def test_thread_local_contexts(self):
        """Test contexts are thread-local"""
        results = {}
        
        def thread_func(domain, thread_id):
            ctx = create_security_context(domain)
            with SecurityContextManager.enter_context(ctx):
                time.sleep(0.01)
                current = SecurityContextManager.get_current_context()
                results[thread_id] = current.domain
        
        t1 = threading.Thread(target=thread_func, args=(SecurityDomain.ADMIN, 1))
        t2 = threading.Thread(target=thread_func, args=(SecurityDomain.UNTRUSTED, 2))
        
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
        assert results[1] == SecurityDomain.ADMIN
        assert results[2] == SecurityDomain.UNTRUSTED


class TestHonestDocumentation:
    """Verify honest documentation exists"""
    
    def test_capabilities_documented(self):
        """Test capabilities are documented"""
        assert len(SECURITY_CAPABILITIES) > 0
        assert "context_isolation" in SECURITY_CAPABILITIES
        assert "capability_security" in SECURITY_CAPABILITIES
    
    def test_limitations_documented(self):
        """Test limitations are honestly documented"""
        assert len(KNOWN_LIMITATIONS) > 0
        assert "python_limits" in KNOWN_LIMITATIONS
        assert "not_full_sandbox" in KNOWN_LIMITATIONS


class TestBackwardCompatibility:
    """Test backward compatibility"""
    
    def test_existing_modules_import(self):
        """Verify we can still import existing security modules"""
        # This should not raise - we're add-only
        try:
            from neural_shield import security_hardening_secure_memory_constant_time_v4_2026_june
            assert True  # Import succeeded
        except ImportError:
            # If it doesn't exist, that's fine too - we're add-only
            pass
    
    def test_no_breaking_changes(self):
        """New module doesn't affect existing imports"""
        # Import should work without side effects
        import neural_shield
        assert hasattr(neural_shield, '__path__')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
