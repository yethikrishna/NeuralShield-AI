"""
Tests for Threat Hunting Query Builder - NeuralShield AI
Comprehensive test coverage for all features.

All tests must pass - no breaking changes.
"""

import pytest
import json
from datetime import datetime, timedelta
from neural_shield.threat_hunting_query_builder_v27_2026_june import (
    ThreatHuntingQueryBuilder,
    QueryPlatform,
    IOCType,
    SeverityLevel,
    IOC,
    TimeRange,
    MITRETechnique,
    SplunkQueryTemplate,
    ElasticsearchQueryTemplate,
    get_query_builder
)


class TestTimeRange:
    """Tests for TimeRange utility class."""

    def test_last_hours_creation(self):
        """Test time range creation for last N hours."""
        time_range = TimeRange.last_hours(24)
        assert time_range.end_time > time_range.start_time
        delta = time_range.end_time - time_range.start_time
        assert delta.total_seconds() >= 24 * 3600 - 1  # Allow 1s tolerance

    def test_last_days_creation(self):
        """Test time range creation for last N days."""
        time_range = TimeRange.last_days(7)
        assert time_range.end_time > time_range.start_time
        delta = time_range.end_time - time_range.start_time
        assert delta.total_seconds() >= 7 * 24 * 3600 - 1

    def test_iso_format_conversion(self):
        """Test ISO 8601 format conversion."""
        start = datetime(2026, 1, 1, 0, 0, 0)
        end = datetime(2026, 1, 2, 0, 0, 0)
        time_range = TimeRange(start_time=start, end_time=end)
        start_iso, end_iso = time_range.to_iso_format()
        assert "2026-01-01T00:00:00" in start_iso
        assert "2026-01-02T00:00:00" in end_iso


class TestIOCValidation:
    """Tests for IOC validation functionality."""

    def test_valid_ip_address(self):
        """Test validation of valid IP address."""
        builder = ThreatHuntingQueryBuilder()
        ioc = IOC(value="192.168.1.1", ioc_type=IOCType.IP_ADDRESS)
        is_valid, errors = builder.validate_ioc(ioc)
        assert is_valid
        assert len(errors) == 0

    def test_invalid_ip_address(self):
        """Test validation of invalid IP address."""
        builder = ThreatHuntingQueryBuilder()
        ioc = IOC(value="999.999.999.999", ioc_type=IOCType.IP_ADDRESS)
        is_valid, errors = builder.validate_ioc(ioc)
        assert not is_valid
        assert len(errors) > 0

    def test_valid_domain(self):
        """Test validation of valid domain."""
        builder = ThreatHuntingQueryBuilder()
        ioc = IOC(value="malicious-domain.com", ioc_type=IOCType.DOMAIN)
        is_valid, errors = builder.validate_ioc(ioc)
        assert is_valid
        assert len(errors) == 0

    def test_valid_md5_hash(self):
        """Test validation of valid MD5 hash."""
        builder = ThreatHuntingQueryBuilder()
        ioc = IOC(
            value="d41d8cd98f00b204e9800998ecf8427e",
            ioc_type=IOCType.FILE_HASH
        )
        is_valid, errors = builder.validate_ioc(ioc)
        assert is_valid

    def test_valid_sha256_hash(self):
        """Test validation of valid SHA256 hash."""
        builder = ThreatHuntingQueryBuilder()
        ioc = IOC(
            value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ioc_type=IOCType.FILE_HASH
        )
        is_valid, errors = builder.validate_ioc(ioc)
        assert is_valid

    def test_empty_ioc_value(self):
        """Test validation rejects empty IOC value."""
        builder = ThreatHuntingQueryBuilder()
        ioc = IOC(value="", ioc_type=IOCType.IP_ADDRESS)
        is_valid, errors = builder.validate_ioc(ioc)
        assert not is_valid
        assert "empty" in errors[0].lower()

    def test_invalid_confidence(self):
        """Test validation rejects invalid confidence values."""
        builder = ThreatHuntingQueryBuilder()
        ioc = IOC(
            value="192.168.1.1",
            ioc_type=IOCType.IP_ADDRESS,
            confidence=2.0
        )
        is_valid, errors = builder.validate_ioc(ioc)
        assert not is_valid


class TestSplunkQueryTemplate:
    """Tests for Splunk query template generation."""

    def test_basic_query_generation(self):
        """Test basic Splunk query generation."""
        template = SplunkQueryTemplate()
        query = template.generate(
            index="security",
            sourcetype="firewall",
            conditions=[]
        )
        assert "index=security" in query
        assert "sourcetype=firewall" in query

    def test_query_with_conditions(self):
        """Test query with filter conditions."""
        template = SplunkQueryTemplate()
        query = template.generate(
            index="*",
            sourcetype="*",
            conditions=["src_ip=192.168.1.1", "action=blocked"]
        )
        assert "src_ip=192.168.1.1" in query
        assert "action=blocked" in query

    def test_query_validation_rejects_dangerous(self):
        """Test validation rejects dangerous commands."""
        template = SplunkQueryTemplate()
        assert not template.validate("index=* | delete")
        assert not template.validate("index=* | outputlookup")

    def test_query_validation_accepts_safe(self):
        """Test validation accepts safe queries."""
        template = SplunkQueryTemplate()
        assert template.validate("index=security sourcetype=*")


class TestElasticsearchQueryTemplate:
    """Tests for Elasticsearch query template generation."""

    def test_basic_query_generation(self):
        """Test basic Elasticsearch query generation."""
        template = ElasticsearchQueryTemplate()
        query_str = template.generate(
            must_conditions=[{"match": {"event.category": "network"}}],
            filter_conditions=[]
        )
        query = json.loads(query_str)
        assert "query" in query
        assert "bool" in query["query"]

    def test_query_with_time_range(self):
        """Test query with time range filter."""
        template = ElasticsearchQueryTemplate()
        time_range = TimeRange.last_hours(24)
        query_str = template.generate(
            must_conditions=[],
            filter_conditions=[],
            time_range=time_range
        )
        query = json.loads(query_str)
        assert "range" in str(query)
        assert "@timestamp" in str(query)

    def test_query_validation_valid_json(self):
        """Test validation accepts valid JSON."""
        template = ElasticsearchQueryTemplate()
        valid_query = json.dumps({"query": {"match_all": {}}})
        assert template.validate(valid_query)

    def test_query_validation_invalid_json(self):
        """Test validation rejects invalid JSON."""
        template = ElasticsearchQueryTemplate()
        assert not template.validate("not valid json")


class TestThreatHuntingQueryBuilder:
    """Tests for main ThreatHuntingQueryBuilder class."""

    def test_initialization_default_platform(self):
        """Test builder initialization with default platform."""
        builder = ThreatHuntingQueryBuilder()
        assert builder.default_platform == QueryPlatform.SPLUNK

    def test_initialization_custom_platform(self):
        """Test builder initialization with custom platform."""
        builder = ThreatHuntingQueryBuilder(QueryPlatform.ELASTICSEARCH)
        assert builder.default_platform == QueryPlatform.ELASTICSEARCH

    def test_get_supported_techniques(self):
        """Test retrieval of supported MITRE techniques."""
        builder = ThreatHuntingQueryBuilder()
        techniques = builder.get_supported_techniques()
        assert len(techniques) > 0
        assert all(isinstance(t, MITRETechnique) for t in techniques)

    def test_get_technique_by_id_valid(self):
        """Test retrieval of technique by valid ID."""
        builder = ThreatHuntingQueryBuilder()
        technique = builder.get_technique_by_id("T1059")
        assert technique is not None
        assert technique.technique_id == "T1059"

    def test_get_technique_by_id_invalid(self):
        """Test retrieval of technique by invalid ID."""
        builder = ThreatHuntingQueryBuilder()
        technique = builder.get_technique_by_id("T9999")
        assert technique is None


class TestIOCSearchQueries:
    """Tests for IOC search query building."""

    def test_build_ioc_query_single_ip(self):
        """Test building query for single IP IOC."""
        builder = ThreatHuntingQueryBuilder()
        iocs = [IOC(value="192.168.1.1", ioc_type=IOCType.IP_ADDRESS)]
        result = builder.build_ioc_search_query(iocs)
        assert result["valid_iocs_count"] == 1
        assert "query" in result
        assert len(result["query"]) > 0

    def test_build_ioc_query_multiple_types(self):
        """Test building query for multiple IOC types."""
        builder = ThreatHuntingQueryBuilder()
        iocs = [
            IOC(value="192.168.1.1", ioc_type=IOCType.IP_ADDRESS),
            IOC(value="evil.com", ioc_type=IOCType.DOMAIN),
        ]
        result = builder.build_ioc_search_query(iocs)
        assert result["valid_iocs_count"] == 2
        assert "ip_address" in result["iocs_by_type"]
        assert "domain" in result["iocs_by_type"]

    def test_build_ioc_query_with_invalid(self):
        """Test building query with some invalid IOCs."""
        builder = ThreatHuntingQueryBuilder()
        iocs = [
            IOC(value="192.168.1.1", ioc_type=IOCType.IP_ADDRESS),
            IOC(value="invalid-ip", ioc_type=IOCType.IP_ADDRESS),
        ]
        result = builder.build_ioc_search_query(iocs)
        assert result["valid_iocs_count"] == 1
        assert len(result["validation"]) == 2

    def test_build_ioc_query_all_invalid(self):
        """Test building query with all invalid IOCs."""
        builder = ThreatHuntingQueryBuilder()
        iocs = [IOC(value="invalid", ioc_type=IOCType.IP_ADDRESS)]
        result = builder.build_ioc_search_query(iocs)
        assert result["valid_iocs_count"] == 0
        assert "error" in result

    def test_build_ioc_query_elasticsearch(self):
        """Test building Elasticsearch IOC query."""
        builder = ThreatHuntingQueryBuilder()
        iocs = [IOC(value="192.168.1.1", ioc_type=IOCType.IP_ADDRESS)]
        result = builder.build_ioc_search_query(
            iocs, platform=QueryPlatform.ELASTICSEARCH
        )
        assert result["platform"] == "elasticsearch"
        # Should be valid JSON
        json.loads(result["query"])

    def test_build_ioc_query_with_time_range(self):
        """Test building IOC query with time range."""
        builder = ThreatHuntingQueryBuilder()
        iocs = [IOC(value="192.168.1.1", ioc_type=IOCType.IP_ADDRESS)]
        time_range = TimeRange.last_days(7)
        result = builder.build_ioc_search_query(iocs, time_range=time_range)
        assert result["time_range"] is not None


class TestMITRETechniqueQueries:
    """Tests for MITRE technique query building."""

    def test_build_mitre_query_valid_technique(self):
        """Test building query for valid technique."""
        builder = ThreatHuntingQueryBuilder()
        result = builder.build_mitre_technique_query("T1059")
        assert "error" not in result
        assert result["technique"]["id"] == "T1059"
        assert len(result["query"]) > 0

    def test_build_mitre_query_invalid_technique(self):
        """Test building query for invalid technique."""
        builder = ThreatHuntingQueryBuilder()
        result = builder.build_mitre_technique_query("T9999")
        assert "error" in result
        assert "supported_techniques" in result

    def test_build_mitre_query_elasticsearch(self):
        """Test building Elasticsearch MITRE query."""
        builder = ThreatHuntingQueryBuilder()
        result = builder.build_mitre_technique_query(
            "T1059", platform=QueryPlatform.ELASTICSEARCH
        )
        assert result["platform"] == "elasticsearch"
        json.loads(result["query"])

    def test_build_mitre_query_with_filters(self):
        """Test building MITRE query with additional filters."""
        builder = ThreatHuntingQueryBuilder()
        result = builder.build_mitre_technique_query(
            "T1059",
            additional_filters={"host": "server-01", "user": "admin"}
        )
        assert "additional_filters" in result
        assert result["additional_filters"]["host"] == "server-01"


class TestQueryHistoryAndStats:
    """Tests for query history and statistics tracking."""

    def test_query_history_tracking(self):
        """Test that queries are added to history."""
        builder = ThreatHuntingQueryBuilder()
        initial_count = len(builder.get_query_history())

        builder.build_ioc_search_query([
            IOC(value="192.168.1.1", ioc_type=IOCType.IP_ADDRESS)
        ])

        assert len(builder.get_query_history()) == initial_count + 1

    def test_query_history_limit(self):
        """Test history retrieval with limit."""
        builder = ThreatHuntingQueryBuilder()
        for i in range(5):
            builder.build_ioc_search_query([
                IOC(value=f"192.168.1.{i}", ioc_type=IOCType.IP_ADDRESS)
            ])

        history = builder.get_query_history(limit=3)
        assert len(history) == 3

    def test_query_statistics(self):
        """Test query statistics generation."""
        builder = ThreatHuntingQueryBuilder()
        builder.build_ioc_search_query([
            IOC(value="192.168.1.1", ioc_type=IOCType.IP_ADDRESS)
        ])
        builder.build_mitre_technique_query("T1059")

        stats = builder.get_query_statistics()
        assert stats["total_queries_generated"] >= 2
        assert "queries_by_platform" in stats
        assert "queries_by_technique" in stats


class TestQuerySanitization:
    """Tests for query sanitization functionality."""

    def test_sanitize_removes_delete(self):
        """Test sanitization removes | delete command."""
        builder = ThreatHuntingQueryBuilder()
        query = "index=* | delete"
        sanitized = builder.sanitize_query(query)
        assert "delete" not in sanitized

    def test_sanitize_removes_outputlookup(self):
        """Test sanitization removes | outputlookup command."""
        builder = ThreatHuntingQueryBuilder()
        query = "index=* | outputlookup bad.csv"
        sanitized = builder.sanitize_query(query)
        assert "outputlookup" not in sanitized

    def test_sanitize_preserves_safe_content(self):
        """Test sanitization preserves safe query content."""
        builder = ThreatHuntingQueryBuilder()
        query = "index=security sourcetype=firewall src_ip=1.2.3.4"
        sanitized = builder.sanitize_query(query)
        assert sanitized == query


class TestQueryPackageExport:
    """Tests for query package export functionality."""

    def test_export_package_structure(self):
        """Test query package export structure."""
        builder = ThreatHuntingQueryBuilder()
        queries = [
            builder.build_ioc_search_query([
                IOC(value="192.168.1.1", ioc_type=IOCType.IP_ADDRESS)
            ])
        ]

        package_json = builder.export_query_package(
            queries, name="IOC Hunt Package", description="Daily IOC hunt"
        )
        package = json.loads(package_json)

        assert package["name"] == "IOC Hunt Package"
        assert package["version"] == "1.0.0"
        assert "queries" in package
        assert "checksum" in package
        assert len(package["checksum"]) == 64  # SHA256


class TestSingletonPattern:
    """Tests for singleton get_query_builder function."""

    def test_singleton_returns_same_instance(self):
        """Test that singleton returns same instance."""
        builder1 = get_query_builder()
        builder2 = get_query_builder()
        assert builder1 is builder2

    def test_singleton_different_platforms(self):
        """Test singleton behavior with different platforms."""
        # Note: singleton caches first call
        builder1 = get_query_builder(QueryPlatform.SPLUNK)
        builder2 = get_query_builder(QueryPlatform.ELASTICSEARCH)
        # Should return same cached instance
        assert builder1 is builder2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
