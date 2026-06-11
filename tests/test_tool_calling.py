"""
Tests for LLM Tool Calling Implementation.

These tests verify that the tool calling infrastructure works correctly
without requiring actual LLM API calls.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import Mock, MagicMock
from dataclasses import dataclass

# Add src to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.llm.client import LLMResponse, Message, ToolCall, LLMClient
from src.llm.analyzer import FindingAnalyzer, Verdict, AnalysisResult
from src.llm.tools import ANALYSIS_TOOLS
from src.context.code_lookup import CodeLookup
from src.semgrep.runner import SemgrepFinding
from src.context.extractor import ExtractedContext, FunctionContext


class TestToolDefinitions:
    """Test that tool definitions are correctly formatted."""

    def test_tools_have_required_fields(self):
        """Each tool should have type, function, name, description, parameters."""
        for tool in ANALYSIS_TOOLS:
            assert tool["type"] == "function"
            assert "function" in tool
            func = tool["function"]
            assert "name" in func
            assert "description" in func
            assert "parameters" in func
            assert func["parameters"]["type"] == "object"

    def test_all_tools_present(self):
        """All expected tools should be defined."""
        tool_names = {t["function"]["name"] for t in ANALYSIS_TOOLS}
        expected_tools = {
            "get_function_code",
            "get_caller_function",
            "get_class_code",
            "get_method_code",
            "search_codebase",
            "get_imports",
            "map_arguments",
            # trace_taint_path deprecated in favor of analyze_data_flow
            "get_sanitization_check",
            "get_caller_chain",
            "analyze_data_flow",
        }
        assert expected_tools == tool_names


class TestCodeLookup:
    """Test the CodeLookup functionality."""

    @pytest.fixture
    def sample_project(self, tmp_path):
        """Create a sample project structure for testing."""
        # Create a sample Java file
        java_dir = tmp_path / "src" / "main" / "java"
        java_dir.mkdir(parents=True)

        java_code = '''package com.example;

import java.sql.Connection;
import java.sql.PreparedStatement;

public class UserRepository {
    private Connection connection;

    public User findById(String id) {
        String sql = "SELECT * FROM users WHERE id = ?";
        PreparedStatement stmt = connection.prepareStatement(sql);
        stmt.setString(1, id);
        return executeQuery(stmt);
    }

    public void sanitizeInput(String input) {
        // Sanitization logic
        return input.replaceAll("[^a-zA-Z0-9]", "");
    }

    private User executeQuery(PreparedStatement stmt) {
        // Execute and return
        return new User();
    }
}
'''
        (java_dir / "UserRepository.java").write_text(java_code)
        return tmp_path

    def test_get_class_code(self, sample_project):
        """Test retrieving full class code."""
        lookup = CodeLookup(sample_project)
        result = lookup.get_class_code("UserRepository")
        assert "public class UserRepository" in result
        assert "findById" in result

    def test_get_function_code(self, sample_project):
        """Test retrieving function code."""
        lookup = CodeLookup(sample_project)
        result = lookup.get_function_code("findById")
        assert "findById" in result
        assert "PreparedStatement" in result

    def test_search_codebase(self, sample_project):
        """Test searching the codebase."""
        lookup = CodeLookup(sample_project)
        result = lookup.search_codebase("PreparedStatement")
        assert "PreparedStatement" in result

    def test_get_imports(self, sample_project):
        """Test getting imports from a file."""
        lookup = CodeLookup(sample_project)
        result = lookup.get_imports("UserRepository.java")
        assert "import java.sql.Connection" in result
        assert "import java.sql.PreparedStatement" in result


class TestFindingAnalyzer:
    """Test the FindingAnalyzer with tool calling."""

    @pytest.fixture
    def mock_finding(self):
        """Create a mock Semgrep finding."""
        return SemgrepFinding(
            rule_id="java.lang.security.audit.sqli.jdbc-sqli",
            message="SQL Injection vulnerability",
            severity="ERROR",
            file_path="src/main/java/UserRepository.java",
            start_line=10,
            end_line=12,
            start_col=1,
            end_col=50,
            code_snippet='String sql = "SELECT * FROM users WHERE id = " + id;',
        )

    @pytest.fixture
    def mock_context(self):
        """Create a mock extracted context."""
        return ExtractedContext(
            finding_line=10,
            finding_code='String sql = "SELECT * FROM users WHERE id = " + id;',
            function_context=FunctionContext(
                name="findById",
                full_code="public User findById(String id) { ... }",
                start_line=8,
                end_line=15,
                file_path="UserRepository.java",
                language="java",
            ),
            surrounding_context="",
            file_path="UserRepository.java",
            additional_context={"class_name": "UserRepository"},
        )

    def test_parse_json_response(self, mock_finding, mock_context):
        """Test parsing a JSON response."""
        mock_client = Mock(spec=LLMClient)
        mock_client.complete.return_value = LLMResponse(
            content=json.dumps({
                "guided_answers": {"q1": "answer1"},
                "verdict": "true_positive",
                "confidence": 0.9,
                "reasoning": "SQL injection found",
            }),
            model="gpt-4",
            prompt_tokens=100,
            completion_tokens=50,
            total_tokens=150,
        )

        analyzer = FindingAnalyzer(mock_client, enable_tool_calling=False)
        result = analyzer.analyze(mock_finding, mock_context, ["q1"])

        assert result.verdict == Verdict.TRUE_POSITIVE
        assert result.confidence == 0.9

    def test_parse_status_code_1337(self, mock_finding, mock_context):
        """Test parsing status code 1337 (true positive)."""
        mock_client = Mock(spec=LLMClient)
        mock_client.complete.return_value = LLMResponse(
            content="Based on my analysis, this is a TRUE POSITIVE. Status: 1337",
            model="gpt-4",
            prompt_tokens=100,
            completion_tokens=50,
            total_tokens=150,
        )

        analyzer = FindingAnalyzer(mock_client, enable_tool_calling=False)
        result = analyzer.analyze(mock_finding, mock_context, ["q1"])

        assert result.verdict == Verdict.TRUE_POSITIVE

    def test_parse_status_code_1007(self, mock_finding, mock_context):
        """Test parsing status code 1007 (false positive)."""
        mock_client = Mock(spec=LLMClient)
        mock_client.complete.return_value = LLMResponse(
            content="Input is sanitized upstream. Status: 1007",
            model="gpt-4",
            prompt_tokens=100,
            completion_tokens=50,
            total_tokens=150,
        )

        analyzer = FindingAnalyzer(mock_client, enable_tool_calling=False)
        result = analyzer.analyze(mock_finding, mock_context, ["q1"])

        assert result.verdict == Verdict.FALSE_POSITIVE

    def test_parse_markdown_json(self, mock_finding, mock_context):
        """Test parsing JSON wrapped in markdown code blocks."""
        mock_client = Mock(spec=LLMClient)
        mock_client.complete.return_value = LLMResponse(
            content='''Here is my analysis:

```json
{
    "guided_answers": {"q1": "answer"},
    "verdict": "false_positive",
    "confidence": 0.85,
    "reasoning": "Uses parameterized queries"
}
```
''',
            model="gpt-4",
            prompt_tokens=100,
            completion_tokens=50,
            total_tokens=150,
        )

        analyzer = FindingAnalyzer(mock_client, enable_tool_calling=False)
        result = analyzer.analyze(mock_finding, mock_context, ["q1"])

        assert result.verdict == Verdict.FALSE_POSITIVE
        assert result.confidence == 0.85


class TestToolCallExecution:
    """Test tool call execution in the analyzer."""

    @pytest.fixture
    def sample_project(self, tmp_path):
        """Create a sample project for tool execution tests."""
        java_dir = tmp_path / "src"
        java_dir.mkdir()

        (java_dir / "Service.java").write_text('''
public class Service {
    public void processData(String input) {
        String sanitized = sanitize(input);
        repository.save(sanitized);
    }

    private String sanitize(String input) {
        return input.replaceAll("[<>]", "");
    }
}
''')
        return tmp_path

    def test_tool_execution_get_function(self, sample_project):
        """Test executing get_function_code tool."""
        lookup = CodeLookup(sample_project)
        result = lookup.get_function_code("sanitize")
        assert "sanitize" in result
        assert "replaceAll" in result


class TestIterativeContextExpansion:
    """Test the iterative context expansion functionality."""

    def test_verdict_needs_more_context(self):
        """Test that NEEDS_MORE_CONTEXT verdict is properly defined."""
        from src.llm.analyzer import Verdict
        assert Verdict.NEEDS_MORE_CONTEXT.value == "needs_more_context"

    def test_context_expansion_request_dataclass(self):
        """Test ContextExpansionRequest dataclass."""
        from src.llm.analyzer import ContextExpansionRequest
        req = ContextExpansionRequest(
            request_type="caller",
            target="validateInput",
            reason="Need to check input validation",
            priority=2
        )
        assert req.request_type == "caller"
        assert req.target == "validateInput"
        assert req.priority == 2

    def test_analysis_result_needs_more_context_property(self):
        """Test the needs_more_context property on AnalysisResult."""
        from src.llm.analyzer import AnalysisResult, Verdict, CONFIDENCE_THRESHOLD_LOW
        from src.llm.client import LLMResponse
        from src.semgrep.runner import SemgrepFinding

        finding = SemgrepFinding(
            rule_id="test-rule",
            message="Test message",
            severity="WARNING",
            file_path="test.java",
            start_line=10,
            end_line=10,
            start_col=1,
            end_col=20,
            code_snippet="test code"
        )

        response = LLMResponse(
            content="test",
            model="test",
            prompt_tokens=10,
            completion_tokens=10,
            total_tokens=20
        )

        # Test with NEEDS_MORE_CONTEXT verdict
        result = AnalysisResult(
            finding=finding,
            verdict=Verdict.NEEDS_MORE_CONTEXT,
            confidence=0.3,
            reasoning="Need more context",
            guided_answers={},
            llm_response=response
        )
        assert result.needs_more_context is True

        # Test with low confidence NEEDS_REVIEW
        result2 = AnalysisResult(
            finding=finding,
            verdict=Verdict.NEEDS_REVIEW,
            confidence=0.4,  # Below CONFIDENCE_THRESHOLD_LOW
            reasoning="Uncertain",
            guided_answers={},
            llm_response=response
        )
        assert result2.needs_more_context is True

        # Test with high confidence FALSE_POSITIVE
        result3 = AnalysisResult(
            finding=finding,
            verdict=Verdict.FALSE_POSITIVE,
            confidence=0.9,
            reasoning="Definitely safe",
            guided_answers={},
            llm_response=response
        )
        assert result3.needs_more_context is False

    def test_confidence_thresholds(self):
        """Test that confidence thresholds are properly defined."""
        from src.llm.analyzer import (
            CONFIDENCE_THRESHOLD_HIGH,
            CONFIDENCE_THRESHOLD_LOW,
            MAX_CONTEXT_ITERATIONS
        )
        # Thresholds were tuned for better accuracy
        assert CONFIDENCE_THRESHOLD_HIGH == 0.75
        assert CONFIDENCE_THRESHOLD_LOW == 0.5
        assert MAX_CONTEXT_ITERATIONS == 3


class TestConfidenceBreakdown:
    """Test the structured confidence scoring system."""

    def test_confidence_breakdown_creation(self):
        """Test creating a ConfidenceBreakdown."""
        from src.llm.confidence import ConfidenceBreakdown

        breakdown = ConfidenceBreakdown(
            context_completeness=0.8,
            data_flow_visibility=0.7,
            sanitization_evidence=0.9,
            pattern_match_strength=0.6,
            caller_context=0.5,
            cross_file_resolution=0.4,
        )

        assert breakdown.context_completeness == 0.8
        assert breakdown.data_flow_visibility == 0.7
        assert breakdown.sanitization_evidence == 0.9

    def test_confidence_breakdown_overall_score(self):
        """Test the weighted overall score calculation."""
        from src.llm.confidence import ConfidenceBreakdown

        # All factors at 0.5 should give overall 0.5
        breakdown = ConfidenceBreakdown()
        assert breakdown.overall_score == 0.5

        # All factors at 1.0 should give overall 1.0
        breakdown_high = ConfidenceBreakdown(
            context_completeness=1.0,
            data_flow_visibility=1.0,
            sanitization_evidence=1.0,
            pattern_match_strength=1.0,
            caller_context=1.0,
            cross_file_resolution=1.0,
        )
        assert breakdown_high.overall_score == 1.0

    def test_confidence_breakdown_weakest_factors(self):
        """Test identifying weakest confidence factors."""
        from src.llm.confidence import ConfidenceBreakdown

        breakdown = ConfidenceBreakdown(
            context_completeness=0.9,
            data_flow_visibility=0.2,  # Weakest
            sanitization_evidence=0.8,
            pattern_match_strength=0.3,  # Second weakest
            caller_context=0.4,  # Third weakest
            cross_file_resolution=0.7,
        )

        weakest = breakdown.weakest_factors
        assert len(weakest) == 3
        assert weakest[0][0] == 'data_flow_visibility'
        assert weakest[0][1] == 0.2

    def test_confidence_breakdown_to_dict(self):
        """Test serialization to dictionary."""
        from src.llm.confidence import ConfidenceBreakdown

        breakdown = ConfidenceBreakdown(context_completeness=0.8)
        d = breakdown.to_dict()

        assert 'context_completeness' in d
        assert 'overall_score' in d
        assert 'weakest_factors' in d

    def test_confidence_breakdown_improvement_suggestions(self):
        """Test that improvement suggestions are generated."""
        from src.llm.confidence import ConfidenceBreakdown

        breakdown = ConfidenceBreakdown(
            context_completeness=0.3,
            data_flow_visibility=0.2,
            caller_context=0.4,
        )

        suggestions = breakdown.improvement_suggestions
        assert len(suggestions) > 0
        assert any("context" in s.lower() for s in suggestions)


class TestInvestigationTrace:
    """Test the investigation trace functionality."""

    def test_investigation_trace_creation(self):
        """Test creating an InvestigationTrace."""
        from src.llm.confidence import InvestigationTrace

        trace = InvestigationTrace(
            finding_id="test:file.py:10",
            rule_id="test-rule",
            file_path="file.py",
        )

        assert trace.finding_id == "test:file.py:10"
        assert trace.total_iterations == 0
        assert trace.steps == []

    def test_investigation_trace_add_step(self):
        """Test adding steps to a trace."""
        from src.llm.confidence import InvestigationTrace, InvestigationStep

        trace = InvestigationTrace(
            finding_id="test:file.py:10",
            rule_id="test-rule",
            file_path="file.py",
        )

        step = InvestigationStep(
            iteration=1,
            action="initial_analysis",
            context_gathered=["proactive_context"],
            confidence_before=0.0,
            confidence_after=0.6,
            verdict_changed=False,
            tool_calls=2,
        )

        trace.add_step(step)

        assert trace.total_iterations == 1
        assert trace.total_tool_calls == 2
        assert trace.confidence_progression == [0.6]

    def test_investigation_trace_to_dict(self):
        """Test serialization of investigation trace."""
        from src.llm.confidence import InvestigationTrace, InvestigationStep

        trace = InvestigationTrace(
            finding_id="test:file.py:10",
            rule_id="test-rule",
            file_path="file.py",
            start_time_ms=1000,
            end_time_ms=2000,
            final_verdict="true_positive",
            final_confidence=0.9,
        )

        d = trace.to_dict()

        assert d['finding_id'] == "test:file.py:10"
        assert d['final_verdict'] == "true_positive"
        assert d['total_duration_ms'] == 1000


class TestInvestigationEngine:
    """Test the investigation engine."""

    def test_investigation_engine_creation(self):
        """Test creating an investigation engine."""
        from src.llm.investigation_engine import InvestigationEngine, InvestigationConfig

        config = InvestigationConfig(max_iterations=5)
        engine = InvestigationEngine(config=config)

        assert engine.config.max_iterations == 5

    def test_investigation_engine_start_and_complete(self):
        """Test starting and completing an investigation."""
        from src.llm.investigation_engine import InvestigationEngine, InvestigationState

        engine = InvestigationEngine()

        trace = engine.start_investigation(
            finding_id="test:file.py:10",
            rule_id="test-rule",
            file_path="file.py",
        )

        assert engine.state == InvestigationState.IN_PROGRESS
        assert trace.finding_id == "test:file.py:10"

        engine.complete_investigation(
            verdict="false_positive",
            confidence=0.9,
        )

        assert engine.state == InvestigationState.COMPLETED

    def test_investigation_engine_should_continue(self):
        """Test the should_continue logic."""
        from src.llm.investigation_engine import InvestigationEngine

        engine = InvestigationEngine()

        # High confidence should not continue
        should_continue, reason = engine.should_continue(1, "true_positive", 0.9)
        assert should_continue is False

        # Low confidence should continue
        should_continue, reason = engine.should_continue(1, "needs_review", 0.3)
        assert should_continue is True

        # Max iterations should not continue
        should_continue, reason = engine.should_continue(3, "needs_review", 0.4)
        assert should_continue is False


class TestInvestigationMetrics:
    """Test the investigation metrics aggregation."""

    def test_metrics_add_investigation(self):
        """Test adding investigations to metrics."""
        from src.llm.confidence import InvestigationMetrics, InvestigationTrace, InvestigationStep

        metrics = InvestigationMetrics()

        trace = InvestigationTrace(
            finding_id="test:file.py:10",
            rule_id="test-rule",
            file_path="file.py",
            start_time_ms=1000,
            end_time_ms=2000,
            final_verdict="true_positive",
            final_confidence=0.9,
        )
        trace.add_step(InvestigationStep(
            iteration=1,
            action="analysis",
            context_gathered=[],
            confidence_before=0.0,
            confidence_after=0.9,
            verdict_changed=False,
            tool_calls=1,
        ))

        metrics.add_investigation(trace)

        assert metrics.total_findings == 1
        assert metrics.true_positives == 1
        assert metrics.single_iteration_findings == 1

    def test_metrics_to_dict(self):
        """Test serialization of metrics."""
        from src.llm.confidence import InvestigationMetrics

        metrics = InvestigationMetrics()
        metrics.total_findings = 10
        metrics.true_positives = 5
        metrics.false_positives = 4
        metrics.needs_review = 1

        d = metrics.to_dict()

        assert d['total_findings'] == 10
        assert d['verdict_distribution']['true_positives'] == 5


class TestAnalysisResultEnhancements:
    """Test the enhanced AnalysisResult with confidence breakdown."""

    def test_analysis_result_with_confidence_breakdown(self):
        """Test AnalysisResult with confidence breakdown."""
        from src.llm.analyzer import AnalysisResult, Verdict
        from src.llm.confidence import ConfidenceBreakdown
        from src.llm.client import LLMResponse
        from src.semgrep.runner import SemgrepFinding

        finding = SemgrepFinding(
            rule_id="test-rule",
            file_path="test.py",
            start_line=10,
            end_line=10,
            start_col=0,
            end_col=20,
            code_snippet="unsafe(input)",
            message="Test finding",
            severity="ERROR",
            metadata={},
        )

        breakdown = ConfidenceBreakdown(
            context_completeness=0.8,
            data_flow_visibility=0.7,
        )

        response = LLMResponse(
            content="test",
            model="test-model",
            prompt_tokens=10,
            completion_tokens=10,
            total_tokens=20
        )

        result = AnalysisResult(
            finding=finding,
            verdict=Verdict.TRUE_POSITIVE,
            confidence=0.9,
            reasoning="Test",
            guided_answers={},
            llm_response=response,
            confidence_breakdown=breakdown,
        )

        assert result.confidence_breakdown is not None
        assert result.confidence_breakdown.context_completeness == 0.8

    def test_analysis_result_to_dict(self):
        """Test AnalysisResult serialization."""
        from src.llm.analyzer import AnalysisResult, Verdict
        from src.llm.client import LLMResponse
        from src.semgrep.runner import SemgrepFinding

        finding = SemgrepFinding(
            rule_id="test-rule",
            file_path="test.py",
            start_line=10,
            end_line=10,
            start_col=0,
            end_col=20,
            code_snippet="unsafe(input)",
            message="Test finding",
            severity="ERROR",
            metadata={},
        )

        response = LLMResponse(
            content="test",
            model="test-model",
            prompt_tokens=10,
            completion_tokens=10,
            total_tokens=20
        )

        result = AnalysisResult(
            finding=finding,
            verdict=Verdict.FALSE_POSITIVE,
            confidence=0.85,
            reasoning="Safe code",
            guided_answers={"q1": "answer1"},
            llm_response=response,
        )

        d = result.to_dict()

        assert d['verdict'] == 'false_positive'
        assert d['confidence'] == 0.85
        assert 'finding_id' in d


class TestCallGraph:
    """Test the CallGraph functionality."""

    def test_call_graph_creation(self):
        """Test creating a call graph."""
        from src.context.call_graph import CallGraph, CallGraphNode, CallGraphEdge

        graph = CallGraph()
        assert graph._nodes == {}
        assert graph._edges == []

    def test_call_graph_add_node(self):
        """Test adding nodes to call graph."""
        from src.context.call_graph import CallGraph, CallGraphNode

        graph = CallGraph()
        node = CallGraphNode(
            id="pkg.ClassA.method1",
            name="method1",
            class_name="ClassA",
            package="pkg",
            file_path="A.java",
            start_line=10,
            end_line=20,
            is_entry_point=True
        )
        graph.add_node(node)

        assert "pkg.ClassA.method1" in graph._nodes
        assert graph.get_node("pkg.ClassA.method1") == node

    def test_call_graph_add_edge(self):
        """Test adding edges to call graph."""
        from src.context.call_graph import CallGraph, CallGraphNode, CallGraphEdge

        graph = CallGraph()
        node1 = CallGraphNode(
            id="pkg.ClassA.method1", name="method1", class_name="ClassA",
            package="pkg", file_path="A.java", start_line=10, end_line=20
        )
        node2 = CallGraphNode(
            id="pkg.ClassB.method2", name="method2", class_name="ClassB",
            package="pkg", file_path="B.java", start_line=15, end_line=25
        )
        graph.add_node(node1)
        graph.add_node(node2)

        edge = CallGraphEdge(
            caller_id="pkg.ClassA.method1",
            callee_id="pkg.ClassB.method2",
            call_line=15
        )
        graph.add_edge(edge)

        assert len(graph._edges) == 1
        assert "pkg.ClassA.method1" in graph._callees
        assert "pkg.ClassB.method2" in graph._callers

    def test_call_graph_get_callers(self):
        """Test getting callers of a node."""
        from src.context.call_graph import CallGraph, CallGraphNode, CallGraphEdge

        graph = CallGraph()
        node1 = CallGraphNode(
            id="pkg.ClassA.method1", name="method1", class_name="ClassA",
            package="pkg", file_path="A.java", start_line=10, end_line=20
        )
        node2 = CallGraphNode(
            id="pkg.ClassB.method2", name="method2", class_name="ClassB",
            package="pkg", file_path="B.java", start_line=15, end_line=25
        )
        graph.add_node(node1)
        graph.add_node(node2)
        graph.add_edge(CallGraphEdge(
            caller_id="pkg.ClassA.method1",
            callee_id="pkg.ClassB.method2",
            call_line=15
        ))

        callers = graph.get_callers("pkg.ClassB.method2")
        assert len(callers) == 1
        assert callers[0].name == "method1"

    def test_call_graph_get_callees(self):
        """Test getting callees of a node."""
        from src.context.call_graph import CallGraph, CallGraphNode, CallGraphEdge

        graph = CallGraph()
        node1 = CallGraphNode(
            id="pkg.ClassA.method1", name="method1", class_name="ClassA",
            package="pkg", file_path="A.java", start_line=10, end_line=20
        )
        node2 = CallGraphNode(
            id="pkg.ClassB.method2", name="method2", class_name="ClassB",
            package="pkg", file_path="B.java", start_line=15, end_line=25
        )
        graph.add_node(node1)
        graph.add_node(node2)
        graph.add_edge(CallGraphEdge(
            caller_id="pkg.ClassA.method1",
            callee_id="pkg.ClassB.method2",
            call_line=15
        ))

        callees = graph.get_callees("pkg.ClassA.method1")
        assert len(callees) == 1
        assert callees[0].name == "method2"

    def test_call_graph_find_paths_to_sink(self):
        """Test finding paths to sink nodes."""
        from src.context.call_graph import CallGraph, CallGraphNode, CallGraphEdge

        graph = CallGraph()
        node1 = CallGraphNode(
            id="pkg.ClassA.method1", name="method1", class_name="ClassA",
            package="pkg", file_path="A.java", start_line=10, end_line=20,
            is_entry_point=True
        )
        node2 = CallGraphNode(
            id="pkg.ClassB.method2", name="method2", class_name="ClassB",
            package="pkg", file_path="B.java", start_line=15, end_line=25,
            is_sink=True
        )
        graph.add_node(node1)
        graph.add_node(node2)
        graph.add_edge(CallGraphEdge(
            caller_id="pkg.ClassA.method1",
            callee_id="pkg.ClassB.method2",
            call_line=15
        ))

        paths = graph.find_paths_to_sink("pkg.ClassA.method1")
        assert len(paths) == 1
        assert paths[0].length == 1
        assert "method1" in paths[0].to_string()
        assert "method2" in paths[0].to_string()

    def test_call_graph_stats(self):
        """Test call graph statistics."""
        from src.context.call_graph import CallGraph, CallGraphNode, CallGraphEdge

        graph = CallGraph()
        node1 = CallGraphNode(
            id="pkg.ClassA.method1", name="method1", class_name="ClassA",
            package="pkg", file_path="A.java", start_line=10, end_line=20,
            is_entry_point=True
        )
        node2 = CallGraphNode(
            id="pkg.ClassB.method2", name="method2", class_name="ClassB",
            package="pkg", file_path="B.java", start_line=15, end_line=25,
            is_sink=True
        )
        graph.add_node(node1)
        graph.add_node(node2)
        graph.add_edge(CallGraphEdge(
            caller_id="pkg.ClassA.method1",
            callee_id="pkg.ClassB.method2",
            call_line=15
        ))

        stats = graph.get_stats()
        assert stats["total_nodes"] == 2
        assert stats["total_edges"] == 1
        assert stats["entry_points"] == 1
        assert stats["sinks"] == 1


class TestDataFlowTools:
    """Test the data flow tracing tools."""

    @pytest.fixture
    def sample_project(self, tmp_path):
        """Create a sample project with vulnerable and safe code."""
        java_dir = tmp_path / "src"
        java_dir.mkdir(parents=True)

        vulnerable_code = '''package com.example;

import java.sql.*;

public class VulnerableController {
    public void handleRequest(HttpServletRequest request) {
        String userId = request.getParameter("id");
        String query = "SELECT * FROM users WHERE id = " + userId;
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);
    }
}
'''
        (java_dir / "VulnerableController.java").write_text(vulnerable_code)

        safe_code = '''package com.example;

import java.sql.*;

public class SafeController {
    public void handleRequest(HttpServletRequest request) {
        String userId = request.getParameter("id");
        PreparedStatement pstmt = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
        pstmt.setString(1, userId);
        ResultSet rs = pstmt.executeQuery();
    }
}
'''
        (java_dir / "SafeController.java").write_text(safe_code)
        return tmp_path

    def test_trace_taint_path_vulnerable(self, sample_project):
        """Test tracing taint path in vulnerable code."""
        lookup = CodeLookup(sample_project)
        result = lookup.trace_taint_path(
            source_variable="request.getParameter",
            sink_function="executeQuery",
            file_path="VulnerableController.java"
        )

        assert "Taint Path Analysis" in result
        assert "Sanitization Found:** No" in result
        assert "Sink Reached:** Yes" in result

    def test_trace_taint_path_safe(self, sample_project):
        """Test tracing taint path in safe code."""
        lookup = CodeLookup(sample_project)
        result = lookup.trace_taint_path(
            source_variable="request.getParameter",
            sink_function="executeQuery",
            file_path="SafeController.java"
        )

        assert "Taint Path Analysis" in result
        # Safe code uses PreparedStatement
        assert "Sink Reached:** Yes" in result

    def test_get_sanitization_check_with_sanitization(self, sample_project):
        """Test sanitization check finds PreparedStatement."""
        lookup = CodeLookup(sample_project)
        result = lookup.get_sanitization_check(
            variable_name="userId",
            file_path="SafeController.java",
            start_line=6,
            end_line=10
        )

        assert "Sanitization Check" in result
        assert "setString" in result
        assert "HIGH" in result

    def test_get_sanitization_check_without_sanitization(self, sample_project):
        """Test sanitization check detects missing sanitization."""
        lookup = CodeLookup(sample_project)
        result = lookup.get_sanitization_check(
            variable_name="userId",
            file_path="VulnerableController.java",
            start_line=6,
            end_line=10
        )

        assert "Sanitization Check" in result
        assert "No sanitization found" in result


class TestToolsIncludeNewTools:
    """Test that new tools are included in ANALYSIS_TOOLS."""

    def test_analyze_data_flow_tool_defined(self):
        """Test analyze_data_flow tool is defined (replaced trace_taint_path)."""
        tool_names = {t["function"]["name"] for t in ANALYSIS_TOOLS}
        assert "analyze_data_flow" in tool_names

    def test_get_sanitization_check_tool_defined(self):
        """Test get_sanitization_check tool is defined."""
        tool_names = {t["function"]["name"] for t in ANALYSIS_TOOLS}
        assert "get_sanitization_check" in tool_names

    def test_get_caller_chain_tool_defined(self):
        """Test get_caller_chain tool is defined."""
        tool_names = {t["function"]["name"] for t in ANALYSIS_TOOLS}
        assert "get_caller_chain" in tool_names


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

