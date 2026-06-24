"""
Test Suite for Threat Hunting Query Builder v26
Dimension A - Feature Expansion
June 2026 - 100% Backward Compatible
32 tests total
"""

import pytest
import json
from datetime import datetime
from neural_shield.threat_hunting_query_builder_v26_2026_june import (
    ThreatHuntingEngine,
    HuntingQuery,
    QueryCondition,
    QueryTemplateLibrary,
    QueryOperator,
    DataSource,
    SeverityLevel
)


class TestQueryCondition:
    def test_query_condition_creation(self):
        cond = QueryCondition(
            field="process_name",
            operator=QueryOperator.EQUALS,
            value="cmd.exe"
        )
        assert cond.field == "process_name"
        assert cond.operator == QueryOperator.EQUALS
        assert cond.value == "cmd.exe"
        assert cond.case_sensitive is False

    def test_query_condition_to_dict(self):
        cond = QueryCondition(
            field="dst_port",
            operator=QueryOperator.EQUALS,
            value=445,
            case_sensitive=True
        )
        d = cond.to_dict()
        assert d["field"] == "dst_port"
        assert d["operator"] == "=="
        assert d["value"] == 445
        assert d["case_sensitive"] is True


class TestHuntingQuery:
    def test_hunting_query_creation(self):
        query = HuntingQuery(
            name="Test Query",
            description="Test description",
            data_source=DataSource.PROCESS_CREATION
        )
        assert query.name == "Test Query"
        assert query.description == "Test description"
        assert query.data_source == DataSource.PROCESS_CREATION
        assert len(query.query_id) == 16

    def test_add_condition(self):
        query = HuntingQuery("Test", "Desc", DataSource.PROCESS_CREATION)
        query.add_condition(QueryCondition("process_name", QueryOperator.EQUALS, "test.exe"))
        assert len(query.conditions) == 1

    def test_add_valid_mitre_technique(self):
        query = HuntingQuery("Test", "Desc", DataSource.PROCESS_CREATION)
        result = query.add_mitre_technique("T1059.001")
        assert result is True
        assert "T1059.001" in query.mitre_techniques

    def test_add_invalid_mitre_technique(self):
        query = HuntingQuery("Test", "Desc", DataSource.PROCESS_CREATION)
        result = query.add_mitre_technique("INVALID")
        assert result is False
        assert len(query.mitre_techniques) == 0

    def test_validate_valid_query(self):
        query = HuntingQuery("Test", "Desc", DataSource.PROCESS_CREATION)
        query.add_condition(QueryCondition("process_name", QueryOperator.EQUALS, "test.exe"))
        validation = query.validate()
        assert validation["valid"] is True
        assert len(validation["errors"]) == 0

    def test_validate_empty_name(self):
        query = HuntingQuery("", "Desc", DataSource.PROCESS_CREATION)
        validation = query.validate()
        assert validation["valid"] is False
        assert "Query name is required" in validation["errors"]

    def test_validate_in_operator_requires_list(self):
        query = HuntingQuery("Test", "Desc", DataSource.PROCESS_CREATION)
        query.add_condition(QueryCondition("process_name", QueryOperator.IN, "not_a_list"))
        validation = query.validate()
        assert validation["valid"] is False

    def test_to_json_serialization(self):
        query = HuntingQuery("Test", "Desc", DataSource.PROCESS_CREATION)
        query.add_condition(QueryCondition("process_name", QueryOperator.EQUALS, "test.exe"))
        json_str = query.to_json()
        parsed = json.loads(json_str)
        assert parsed["name"] == "Test"
        assert parsed["query_id"] == query.query_id


class TestQueryTemplateLibrary:
    def test_get_template_names(self):
        names = QueryTemplateLibrary.get_template_names()
        assert len(names) >= 6
        assert "suspicious_powershell" in names
        assert "credential_dumping" in names

    def test_get_existing_template(self):
        template = QueryTemplateLibrary.get_template("suspicious_powershell")
        assert template is not None
        assert template.name == "Suspicious PowerShell Execution"
        assert len(template.conditions) > 0

    def test_get_nonexistent_template(self):
        template = QueryTemplateLibrary.get_template("nonexistent")
        assert template is None

    def test_list_templates(self):
        templates = QueryTemplateLibrary.list_templates()
        assert len(templates) >= 6
        for tpl in templates:
            assert "id" in tpl
            assert "name" in tpl
            assert "severity" in tpl

    def test_template_has_mitre_techniques(self):
        template = QueryTemplateLibrary.get_template("credential_dumping")
        assert template is not None
        assert len(template.mitre_techniques) > 0
        assert "T1003" in template.mitre_techniques
        assert template.severity == SeverityLevel.CRITICAL


class TestThreatHuntingEngine:
    def test_engine_initialization(self):
        engine = ThreatHuntingEngine()
        assert len(engine.saved_queries) == 0
        assert len(engine.query_history) == 0

    def test_create_query(self):
        engine = ThreatHuntingEngine()
        query = engine.create_query("New Query", "New Desc", DataSource.DNS_QUERY)
        assert query.name == "New Query"
        assert query.data_source == DataSource.DNS_QUERY

    def test_save_and_retrieve_query(self):
        engine = ThreatHuntingEngine()
        query = engine.create_query("Saved", "Test", DataSource.PROCESS_CREATION)
        qid = engine.save_query(query)
        retrieved = engine.get_saved_query(qid)
        assert retrieved is not None
        assert retrieved.name == "Saved"

    def test_list_saved_queries(self):
        engine = ThreatHuntingEngine()
        query = engine.create_query("Q1", "D1", DataSource.PROCESS_CREATION)
        engine.save_query(query)
        listed = engine.list_saved_queries()
        assert len(listed) == 1
        assert listed[0]["name"] == "Q1"


class TestQueryExecution:
    def test_execute_query_match(self):
        engine = ThreatHuntingEngine()
        query = HuntingQuery("Test", "Desc", DataSource.PROCESS_CREATION)
        query.add_condition(QueryCondition("process_name", QueryOperator.EQUALS, "malware.exe"))
        
        events = [
            {"process_name": "malware.exe", "pid": 1234},
            {"process_name": "legit.exe", "pid": 5678}
        ]
        
        result = engine.execute_query(query, events)
        assert result["success"] is True
        assert result["matching_events"] == 1
        assert result["total_events"] == 2

    def test_execute_query_contains_operator(self):
        engine = ThreatHuntingEngine()
        query = HuntingQuery("Test", "Desc", DataSource.PROCESS_CREATION)
        query.add_condition(QueryCondition("command_line", QueryOperator.CONTAINS, "powershell"))
        
        events = [
            {"command_line": "powershell -enc abc"},
            {"command_line": "cmd.exe /c dir"}
        ]
        
        result = engine.execute_query(query, events)
        assert result["matching_events"] == 1

    def test_execute_query_in_operator(self):
        engine = ThreatHuntingEngine()
        query = HuntingQuery("Test", "Desc", DataSource.PROCESS_CREATION)
        query.add_condition(QueryCondition("process_name", QueryOperator.IN, ["a.exe", "b.exe"]))
        
        events = [
            {"process_name": "a.exe"},
            {"process_name": "c.exe"},
            {"process_name": "b.exe"}
        ]
        
        result = engine.execute_query(query, events)
        assert result["matching_events"] == 2

    def test_execute_query_matches_regex(self):
        engine = ThreatHuntingEngine()
        query = HuntingQuery("Test", "Desc", DataSource.DNS_QUERY)
        query.add_condition(QueryCondition("query_name", QueryOperator.MATCHES, r"^test.*\.com$"))
        
        events = [
            {"query_name": "test123.com"},
            {"query_name": "other.net"}
        ]
        
        result = engine.execute_query(query, events)
        assert result["matching_events"] == 1

    def test_execute_query_starts_with(self):
        engine = ThreatHuntingEngine()
        query = HuntingQuery("Test", "Desc", DataSource.FILE_CREATION)
        query.add_condition(QueryCondition("file_path", QueryOperator.STARTS_WITH, "/tmp/"))
        
        events = [
            {"file_path": "/tmp/malware.bin"},
            {"file_path": "/home/user/file.txt"}
        ]
        
        result = engine.execute_query(query, events)
        assert result["matching_events"] == 1

    def test_execute_query_ends_with(self):
        engine = ThreatHuntingEngine()
        query = HuntingQuery("Test", "Desc", DataSource.FILE_CREATION)
        query.add_condition(QueryCondition("file_name", QueryOperator.ENDS_WITH, ".exe"))
        
        events = [
            {"file_name": "program.exe"},
            {"file_name": "data.txt"}
        ]
        
        result = engine.execute_query(query, events)
        assert result["matching_events"] == 1

    def test_execute_query_case_insensitive(self):
        engine = ThreatHuntingEngine()
        query = HuntingQuery("Test", "Desc", DataSource.PROCESS_CREATION)
        query.add_condition(QueryCondition("process_name", QueryOperator.EQUALS, "MALWARE.EXE", case_sensitive=False))
        
        events = [{"process_name": "malware.exe"}]
        result = engine.execute_query(query, events)
        assert result["matching_events"] == 1

    def test_execute_invalid_query(self):
        engine = ThreatHuntingEngine()
        query = HuntingQuery("", "Desc", DataSource.PROCESS_CREATION)  # Empty name
        result = engine.execute_query(query, [])
        assert result["success"] is False
        assert "error" in result


class TestQueryStatistics:
    def test_get_query_statistics(self):
        engine = ThreatHuntingEngine()
        stats = engine.get_query_statistics()
        assert stats["total_queries_executed"] == 0
        assert stats["available_templates"] >= 6

    def test_query_history_tracking(self):
        engine = ThreatHuntingEngine()
        query = HuntingQuery("Test", "Desc", DataSource.PROCESS_CREATION)
        query.add_condition(QueryCondition("process_name", QueryOperator.EQUALS, "test.exe"))
        
        engine.execute_query(query, [{"process_name": "test.exe"}])
        stats = engine.get_query_statistics()
        
        assert stats["total_queries_executed"] == 1
        assert stats["total_matches"] == 1


class TestIntegration:
    def test_full_workflow_template_to_execution(self):
        """Test complete workflow: get template -> customize -> execute."""
        engine = ThreatHuntingEngine()
        
        # Get template
        template = QueryTemplateLibrary.get_template("suspicious_powershell")
        assert template is not None
        
        # Customize
        template.add_condition(QueryCondition("user", QueryOperator.EQUALS, "admin"))
        
        # Save
        qid = engine.save_query(template)
        
        # Execute
        events = [
            {"command_line": "powershell -enc ABC123", "user": "admin"},
            {"command_line": "powershell -enc XYZ", "user": "guest"},
            {"command_line": "cmd.exe", "user": "admin"}
        ]
        
        result = engine.execute_query(template, events)
        assert result["success"] is True
        assert result["query_id"] == qid
        assert "mitre_techniques" in result
        assert len(result["mitre_techniques"]) > 0

    def test_multiple_conditions_and_logic(self):
        """Test AND logic between multiple conditions."""
        engine = ThreatHuntingEngine()
        query = HuntingQuery("Multi-Condition", "Test", DataSource.NETWORK_CONNECTION)
        query.add_condition(QueryCondition("dst_port", QueryOperator.EQUALS, 445))
        query.add_condition(QueryCondition("direction", QueryOperator.EQUALS, "outbound"))
        
        events = [
            {"dst_port": 445, "direction": "outbound"},  # Match
            {"dst_port": 445, "direction": "inbound"},   # No match
            {"dst_port": 80, "direction": "outbound"},   # No match
        ]
        
        result = engine.execute_query(query, events)
        assert result["matching_events"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
