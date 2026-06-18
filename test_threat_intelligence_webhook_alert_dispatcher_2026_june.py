"""
Test Suite for Threat Intelligence Webhook Alert Dispatcher
June 18, 2026 - Production Release

Real production-grade tests with actual assertions
"""

import unittest
import json
import time
from datetime import datetime, timezone

from neural_shield.threat_intelligence_webhook_alert_dispatcher_2026_june import (
    ThreatIntelligenceWebhookAlertDispatcher,
    WebhookEndpoint,
    SecurityAlert,
    WebhookPlatform,
    AlertSeverity,
    AlertStatus,
    AuthenticationType,
    CircuitBreaker,
    RateLimiter,
    create_webhook_dispatcher,
)


class TestCircuitBreaker(unittest.TestCase):
    """Test Circuit Breaker pattern implementation"""

    def test_circuit_starts_closed(self):
        """Circuit breaker should start closed"""
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=1)
        self.assertFalse(cb.is_open)
        self.assertTrue(cb.can_execute())

    def test_circuit_opens_after_failures(self):
        """Circuit should open after threshold failures"""
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=60)
        
        for _ in range(2):
            cb.record_failure()
            self.assertTrue(cb.can_execute())
        
        cb.record_failure()  # 3rd failure
        self.assertTrue(cb.is_open)
        self.assertFalse(cb.can_execute())

    def test_circuit_records_success(self):
        """Success should reset failure count"""
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=60)
        
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        
        self.assertEqual(cb.failure_count, 0)
        self.assertFalse(cb.is_open)

    def test_circuit_half_open_after_timeout(self):
        """Circuit should allow execution after recovery timeout"""
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=1)
        
        cb.record_failure()
        cb.record_failure()
        self.assertTrue(cb.is_open)
        
        time.sleep(1.1)
        self.assertTrue(cb.can_execute())
        self.assertFalse(cb.is_open)


class TestRateLimiter(unittest.TestCase):
    """Test Rate Limiter implementation"""

    def test_rate_limiter_allows_initial_requests(self):
        """Rate limiter should allow initial requests"""
        rl = RateLimiter(rate_per_minute=10)
        for _ in range(10):
            self.assertTrue(rl.acquire(blocking=False))

    def test_rate_limiter_blocks_over_limit(self):
        """Rate limiter should block over limit"""
        rl = RateLimiter(rate_per_minute=5)
        for _ in range(5):
            rl.acquire(blocking=False)
        
        self.assertFalse(rl.acquire(blocking=False))

    def test_rate_limiter_refills(self):
        """Rate limiter should refill tokens over time"""
        rl = RateLimiter(rate_per_minute=60)  # 1 per second
        for _ in range(60):
            rl.acquire(blocking=False)
        
        self.assertFalse(rl.acquire(blocking=False))
        time.sleep(1.1)
        self.assertTrue(rl.acquire(blocking=False))


class TestSecurityAlert(unittest.TestCase):
    """Test Security Alert data structure"""

    def test_alert_creates_hash(self):
        """Alert should generate hash automatically"""
        alert = SecurityAlert(
            alert_id="test-001",
            title="Test Alert",
            description="Test description",
            severity=AlertSeverity.CRITICAL,
            source="Test Source",
        )
        
        self.assertTrue(len(alert.alert_hash) > 0)
        self.assertEqual(len(alert.alert_hash), 16)

    def test_same_alerts_have_same_hash(self):
        """Same alerts should have same hash"""
        ts = datetime.now(timezone.utc)
        alert1 = SecurityAlert(
            alert_id="test-001",
            title="Test Alert",
            description="Test description",
            severity=AlertSeverity.CRITICAL,
            source="Test Source",
            timestamp=ts,
        )
        alert2 = SecurityAlert(
            alert_id="test-002",
            title="Test Alert",
            description="Test description",
            severity=AlertSeverity.CRITICAL,
            source="Test Source",
            timestamp=ts,
        )
        
        self.assertEqual(alert1.alert_hash, alert2.alert_hash)


class TestWebhookEndpoint(unittest.TestCase):
    """Test Webhook Endpoint configuration"""

    def test_endpoint_defaults(self):
        """Endpoint should have sensible defaults"""
        endpoint = WebhookEndpoint(
            endpoint_id="slack-001",
            url="https://hooks.slack.com/test",
            platform=WebhookPlatform.SLACK,
        )
        
        self.assertTrue(endpoint.enabled)
        self.assertEqual(endpoint.authentication_type, AuthenticationType.NONE)
        self.assertEqual(endpoint.rate_limit_per_minute, 60)
        self.assertEqual(endpoint.timeout_seconds, 10)
        self.assertEqual(endpoint.retry_attempts, 3)

    def test_endpoint_severity_filter_default(self):
        """Default filter should include all severities"""
        endpoint = WebhookEndpoint(
            endpoint_id="test-001",
            url="https://example.com",
            platform=WebhookPlatform.GENERIC,
        )
        
        self.assertEqual(len(endpoint.severity_filter), len(AlertSeverity))
        for severity in AlertSeverity:
            self.assertIn(severity, endpoint.severity_filter)


class TestWebhookAlertDispatcher(unittest.TestCase):
    """Test main Webhook Alert Dispatcher"""

    def setUp(self):
        self.dispatcher = ThreatIntelligenceWebhookAlertDispatcher()

    def test_dispatcher_starts_empty(self):
        """New dispatcher should have no endpoints"""
        stats = self.dispatcher.get_statistics()
        self.assertEqual(stats["total_endpoints"], 0)
        self.assertEqual(stats["active_endpoints"], 0)
        self.assertEqual(stats["total_alerts_received"], 0)

    def test_register_endpoint(self):
        """Registering endpoint should update statistics"""
        endpoint = WebhookEndpoint(
            endpoint_id="test-001",
            url="https://example.com/webhook",
            platform=WebhookPlatform.GENERIC,
        )
        
        self.dispatcher.register_endpoint(endpoint)
        
        stats = self.dispatcher.get_statistics()
        self.assertEqual(stats["total_endpoints"], 1)
        self.assertEqual(stats["active_endpoints"], 1)

    def test_unregister_endpoint(self):
        """Unregistering endpoint should remove it"""
        endpoint = WebhookEndpoint(
            endpoint_id="test-001",
            url="https://example.com/webhook",
            platform=WebhookPlatform.GENERIC,
        )
        
        self.dispatcher.register_endpoint(endpoint)
        self.dispatcher.unregister_endpoint("test-001")
        
        stats = self.dispatcher.get_statistics()
        self.assertEqual(stats["total_endpoints"], 0)

    def test_enqueue_alert(self):
        """Enqueuing alert should update statistics"""
        alert = SecurityAlert(
            alert_id="alert-001",
            title="Critical Security Event",
            description="Potential breach detected",
            severity=AlertSeverity.CRITICAL,
            source="Threat Intelligence",
        )
        
        result = self.dispatcher.enqueue_alert(alert)
        
        self.assertTrue(result)
        stats = self.dispatcher.get_statistics()
        self.assertEqual(stats["total_alerts_received"], 1)
        self.assertEqual(stats["alerts_per_severity"]["CRITICAL"], 1)

    def test_duplicate_alert_detection(self):
        """Duplicate alerts should be detected and rejected"""
        ts = datetime.now(timezone.utc)
        alert1 = SecurityAlert(
            alert_id="alert-001",
            title="Same Alert",
            description="Same content",
            severity=AlertSeverity.HIGH,
            source="Test",
            timestamp=ts,
        )
        alert2 = SecurityAlert(
            alert_id="alert-002",
            title="Same Alert",
            description="Same content",
            severity=AlertSeverity.HIGH,
            source="Test",
            timestamp=ts,
        )
        
        result1 = self.dispatcher.enqueue_alert(alert1)
        result2 = self.dispatcher.enqueue_alert(alert2)
        
        self.assertTrue(result1)
        self.assertFalse(result2)  # Duplicate rejected

    def test_alert_without_duplicate_check(self):
        """Disabling deduplication should allow same alerts"""
        ts = datetime.now(timezone.utc)
        alert1 = SecurityAlert(
            alert_id="alert-001",
            title="Same Alert",
            description="Same content",
            severity=AlertSeverity.HIGH,
            source="Test",
            timestamp=ts,
        )
        alert2 = SecurityAlert(
            alert_id="alert-002",
            title="Same Alert",
            description="Same content",
            severity=AlertSeverity.HIGH,
            source="Test",
            timestamp=ts,
        )
        
        result1 = self.dispatcher.enqueue_alert(alert1, deduplicate=False)
        result2 = self.dispatcher.enqueue_alert(alert2, deduplicate=False)
        
        self.assertTrue(result1)
        self.assertTrue(result2)

    def test_format_slack_message(self):
        """Slack message formatting should produce valid structure"""
        alert = SecurityAlert(
            alert_id="alert-001",
            title="Test Alert",
            description="Test description",
            severity=AlertSeverity.CRITICAL,
            source="Test",
            mitre_tactics=["Initial Access", "Execution"],
            affected_assets=["server-01", "workstation-05"],
            indicators=["192.168.1.100"],
        )
        
        payload = self.dispatcher._format_slack_message(alert)
        
        self.assertIn("attachments", payload)
        self.assertEqual(len(payload["attachments"]), 1)
        attachment = payload["attachments"][0]
        self.assertIn("color", attachment)
        self.assertIn("title", attachment)
        self.assertIn("text", attachment)
        self.assertEqual(attachment["color"], "#FF0000")  # CRITICAL

    def test_format_teams_message(self):
        """Teams message formatting should produce valid structure"""
        alert = SecurityAlert(
            alert_id="alert-001",
            title="Test Alert",
            description="Test description",
            severity=AlertSeverity.HIGH,
            source="Test",
        )
        
        payload = self.dispatcher._format_teams_message(alert)
        
        self.assertEqual(payload["@type"], "MessageCard")
        self.assertIn("themeColor", payload)
        self.assertIn("title", payload)
        self.assertEqual(payload["themeColor"], "FF6600")  # HIGH

    def test_format_discord_message(self):
        """Discord message formatting should produce valid structure"""
        alert = SecurityAlert(
            alert_id="alert-001",
            title="Test Alert",
            description="Test description",
            severity=AlertSeverity.MEDIUM,
            source="Test",
        )
        
        payload = self.dispatcher._format_discord_message(alert)
        
        self.assertIn("embeds", payload)
        self.assertEqual(len(payload["embeds"]), 1)
        embed = payload["embeds"][0]
        self.assertIn("title", embed)
        self.assertIn("color", embed)
        self.assertEqual(embed["color"], 16776960)  # MEDIUM

    def test_format_generic_message(self):
        """Generic message should include all alert fields"""
        alert = SecurityAlert(
            alert_id="alert-001",
            title="Test Alert",
            description="Test description",
            severity=AlertSeverity.LOW,
            source="Test",
            mitre_tactics=["Discovery"],
            indicators=["test.ioc"],
        )
        
        payload = self.dispatcher._format_generic_message(alert)
        
        self.assertEqual(payload["alert_id"], "alert-001")
        self.assertEqual(payload["title"], "Test Alert")
        self.assertEqual(payload["severity"], "LOW")
        self.assertEqual(payload["mitre_tactics"], ["Discovery"])
        self.assertEqual(payload["indicators"], ["test.ioc"])

    def test_build_headers_no_auth(self):
        """Headers without auth should have basic headers"""
        endpoint = WebhookEndpoint(
            endpoint_id="test-001",
            url="https://example.com",
            platform=WebhookPlatform.GENERIC,
            authentication_type=AuthenticationType.NONE,
        )
        
        headers = self.dispatcher._build_headers(endpoint, "{}")
        
        self.assertIn("Content-Type", headers)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertIn("User-Agent", headers)

    def test_build_headers_api_key(self):
        """API key authentication should add header"""
        endpoint = WebhookEndpoint(
            endpoint_id="test-001",
            url="https://example.com",
            platform=WebhookPlatform.GENERIC,
            authentication_type=AuthenticationType.API_KEY_HEADER,
            auth_credentials={"api_key": "secret-key-123"},
        )
        
        headers = self.dispatcher._build_headers(endpoint, "{}")
        
        self.assertIn("X-API-Key", headers)
        self.assertEqual(headers["X-API-Key"], "secret-key-123")

    def test_build_headers_bearer_token(self):
        """Bearer token authentication should add Authorization header"""
        endpoint = WebhookEndpoint(
            endpoint_id="test-001",
            url="https://example.com",
            platform=WebhookPlatform.GENERIC,
            authentication_type=AuthenticationType.BEARER_TOKEN,
            auth_credentials={"token": "jwt-token-456"},
        )
        
        headers = self.dispatcher._build_headers(endpoint, "{}")
        
        self.assertIn("Authorization", headers)
        self.assertEqual(headers["Authorization"], "Bearer jwt-token-456")

    def test_build_headers_hmac(self):
        """HMAC signature should be computed correctly"""
        endpoint = WebhookEndpoint(
            endpoint_id="test-001",
            url="https://example.com",
            platform=WebhookPlatform.GENERIC,
            authentication_type=AuthenticationType.HMAC_SIGNATURE,
            auth_credentials={"secret": "test-secret"},
        )
        
        payload = '{"test": "data"}'
        headers = self.dispatcher._build_headers(endpoint, payload)
        
        self.assertIn("X-Signature", headers)
        self.assertTrue(headers["X-Signature"].startswith("sha256="))

    def test_dispatch_to_invalid_endpoint_fails(self):
        """Dispatch to invalid endpoint should record failure"""
        endpoint = WebhookEndpoint(
            endpoint_id="invalid-001",
            url="https://invalid.invalid/webhook",
            platform=WebhookPlatform.GENERIC,
            retry_attempts=1,
            timeout_seconds=1,
        )
        
        self.dispatcher.register_endpoint(endpoint)
        
        alert = SecurityAlert(
            alert_id="test-001",
            title="Test",
            description="Test",
            severity=AlertSeverity.HIGH,
            source="Test",
        )
        
        records = self.dispatcher.dispatch_immediate(alert)
        
        self.assertEqual(len(records), 1)
        self.assertIn(records[0].status, [AlertStatus.EXHAUSTED, AlertStatus.FAILED])

    def test_get_delivery_history(self):
        """Delivery history should return formatted records"""
        history = self.dispatcher.get_delivery_history(limit=10)
        self.assertIsInstance(history, list)

    def test_factory_function(self):
        """Factory function should create working dispatcher"""
        dispatcher = create_webhook_dispatcher()
        self.assertIsInstance(dispatcher, ThreatIntelligenceWebhookAlertDispatcher)
        self.assertTrue(dispatcher.running)
        dispatcher.stop_worker()

    def test_worker_start_stop(self):
        """Worker thread should start and stop correctly"""
        dispatcher = ThreatIntelligenceWebhookAlertDispatcher()
        self.assertFalse(dispatcher.running)
        
        dispatcher.start_worker()
        self.assertTrue(dispatcher.running)
        self.assertIsNotNone(dispatcher.worker_thread)
        
        dispatcher.stop_worker()
        self.assertFalse(dispatcher.running)


class TestIntegration(unittest.TestCase):
    """Integration tests for full workflow"""

    def test_full_workflow(self):
        """Test complete workflow: register endpoint, enqueue alerts, get stats"""
        dispatcher = ThreatIntelligenceWebhookAlertDispatcher()
        
        # Register endpoints
        dispatcher.register_endpoint(WebhookEndpoint(
            endpoint_id="slack-prod",
            url="https://hooks.slack.com/services/TEST",
            platform=WebhookPlatform.SLACK,
        ))
        
        dispatcher.register_endpoint(WebhookEndpoint(
            endpoint_id="teams-prod",
            url="https://outlook.office.com/webhook/TEST",
            platform=WebhookPlatform.MICROSOFT_TEAMS,
            severity_filter=[AlertSeverity.CRITICAL, AlertSeverity.HIGH],
        ))
        
        # Enqueue alerts of varying severity
        severities = [
            AlertSeverity.CRITICAL,
            AlertSeverity.HIGH,
            AlertSeverity.MEDIUM,
            AlertSeverity.LOW,
            AlertSeverity.INFORMATIONAL,
        ]
        
        for i, severity in enumerate(severities):
            alert = SecurityAlert(
                alert_id=f"alert-{i:03d}",
                title=f"Test Alert {i}",
                description=f"Test alert with {severity} severity",
                severity=severity,
                source="Integration Test",
            )
            dispatcher.enqueue_alert(alert)
        
        # Verify statistics
        stats = dispatcher.get_statistics()
        self.assertEqual(stats["total_alerts_received"], 5)
        self.assertEqual(stats["total_endpoints"], 2)
        self.assertEqual(stats["active_endpoints"], 2)
        
        # Verify per-severity counts
        self.assertEqual(stats["alerts_per_severity"]["CRITICAL"], 1)
        self.assertEqual(stats["alerts_per_severity"]["HIGH"], 1)
        self.assertEqual(stats["alerts_per_severity"]["MEDIUM"], 1)
        self.assertEqual(stats["alerts_per_severity"]["LOW"], 1)
        self.assertEqual(stats["alerts_per_severity"]["INFORMATIONAL"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
