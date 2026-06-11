"""
Confidence Scoring Module for Structured Vulnerability Analysis.

This module provides dataclasses for:
1. ConfidenceBreakdown - Detailed confidence factors for each analysis
2. InvestigationStep - A single step in the investigation process
3. InvestigationTrace - Full trace of an investigation
4. InvestigationMetrics - Aggregated metrics across investigations
"""

from dataclasses import dataclass, field
from typing import Optional
import time


@dataclass
class ConfidenceFactor:
    """A single confidence factor with name and value."""
    name: str
    value: float
    description: str = ""


@dataclass
class ConfidenceBreakdown:
    """Detailed breakdown of confidence factors for an analysis."""
    context_completeness: float = 0.5
    data_flow_visibility: float = 0.5
    sanitization_evidence: float = 0.5
    pattern_match_strength: float = 0.5
    caller_context: float = 0.5
    cross_file_resolution: float = 0.5

    # Weights for overall score calculation
    WEIGHTS = {
        "context_completeness": 0.20,
        "data_flow_visibility": 0.25,
        "sanitization_evidence": 0.20,
        "pattern_match_strength": 0.15,
        "caller_context": 0.10,
        "cross_file_resolution": 0.10,
    }

    @property
    def overall_score(self) -> float:
        """Calculate weighted overall confidence score."""
        total = 0.0
        for name, weight in self.WEIGHTS.items():
            total += getattr(self, name) * weight
        return total

    @property
    def weakest_factors(self) -> list[tuple[str, float]]:
        """Get the 3 weakest confidence factors."""
        factors = [
            (name, getattr(self, name))
            for name in self.WEIGHTS.keys()
        ]
        factors.sort(key=lambda x: x[1])
        return factors[:3]

    @property
    def improvement_suggestions(self) -> list[str]:
        """Generate suggestions for improving confidence."""
        suggestions = []
        if self.context_completeness < 0.5:
            suggestions.append("Gather more surrounding code context")
        if self.data_flow_visibility < 0.5:
            suggestions.append("Trace data flow from source to sink")
        if self.sanitization_evidence < 0.5:
            suggestions.append("Search for validation/sanitization patterns")
        if self.caller_context < 0.5:
            suggestions.append("Get caller functions to check input handling")
        if self.cross_file_resolution < 0.5:
            suggestions.append("Resolve cross-file dependencies")
        return suggestions

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "context_completeness": self.context_completeness,
            "data_flow_visibility": self.data_flow_visibility,
            "sanitization_evidence": self.sanitization_evidence,
            "pattern_match_strength": self.pattern_match_strength,
            "caller_context": self.caller_context,
            "cross_file_resolution": self.cross_file_resolution,
            "overall_score": self.overall_score,
            "weakest_factors": self.weakest_factors,
        }


@dataclass
class InvestigationStep:
    """A single step in the investigation process."""
    iteration: int
    action: str  # "initial_analysis", "context_expansion", "re_analysis"
    context_gathered: list[str] = field(default_factory=list)
    confidence_before: float = 0.0
    confidence_after: float = 0.0
    verdict_before: str = ""
    verdict_after: str = ""
    verdict_changed: bool = False
    tool_calls: int = 0
    duration_ms: int = 0
    confidence_breakdown: Optional[ConfidenceBreakdown] = None

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "iteration": self.iteration,
            "action": self.action,
            "context_gathered": self.context_gathered,
            "confidence_before": self.confidence_before,
            "confidence_after": self.confidence_after,
            "verdict_changed": self.verdict_changed,
            "tool_calls": self.tool_calls,
            "duration_ms": self.duration_ms,
        }


@dataclass
class InvestigationTrace:
    """Full trace of an investigation."""
    finding_id: str
    rule_id: str
    file_path: str
    start_time_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    end_time_ms: int = 0
    steps: list[InvestigationStep] = field(default_factory=list)
    final_verdict: str = ""
    final_confidence: float = 0.0
    final_confidence_breakdown: Optional[ConfidenceBreakdown] = None
    early_exit: bool = False
    early_exit_reason: str = ""
    total_context_requests: int = 0

    def add_step(self, step: InvestigationStep):
        """Add a step to the trace."""
        self.steps.append(step)

    @property
    def total_iterations(self) -> int:
        return len(self.steps)

    @property
    def total_tool_calls(self) -> int:
        return sum(s.tool_calls for s in self.steps)

    @property
    def confidence_progression(self) -> list[float]:
        return [s.confidence_after for s in self.steps]

    @property
    def total_duration_ms(self) -> int:
        return self.end_time_ms - self.start_time_ms if self.end_time_ms else 0

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "total_iterations": self.total_iterations,
            "total_tool_calls": self.total_tool_calls,
            "total_duration_ms": self.total_duration_ms,
            "final_verdict": self.final_verdict,
            "final_confidence": self.final_confidence,
            "confidence_progression": self.confidence_progression,
            "steps": [s.to_dict() for s in self.steps],
        }


@dataclass
class InvestigationMetrics:
    """Aggregated metrics across multiple investigations."""
    total_findings: int = 0
    true_positives: int = 0
    false_positives: int = 0
    needs_review: int = 0
    single_iteration_findings: int = 0
    multi_iteration_findings: int = 0
    total_tool_calls: int = 0
    total_context_requests: int = 0
    average_confidence: float = 0.0
    average_iterations: float = 0.0
    investigations: list[InvestigationTrace] = field(default_factory=list)

    def add_investigation(self, trace: InvestigationTrace):
        """Add an investigation trace to metrics."""
        self.investigations.append(trace)
        self.total_findings += 1

        # Count verdicts
        if trace.final_verdict == "true_positive":
            self.true_positives += 1
        elif trace.final_verdict == "false_positive":
            self.false_positives += 1
        else:
            self.needs_review += 1

        # Count iterations
        if trace.total_iterations == 1:
            self.single_iteration_findings += 1
        else:
            self.multi_iteration_findings += 1

        self.total_tool_calls += trace.total_tool_calls
        self.total_context_requests += trace.total_context_requests

        # Update averages
        confidences = [t.final_confidence for t in self.investigations]
        self.average_confidence = sum(confidences) / len(confidences)
        iterations = [t.total_iterations for t in self.investigations]
        self.average_iterations = sum(iterations) / len(iterations)

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "total_findings": self.total_findings,
            "verdict_distribution": {
                "true_positives": self.true_positives,
                "false_positives": self.false_positives,
                "needs_review": self.needs_review,
            },
            "iteration_distribution": {
                "single_iteration": self.single_iteration_findings,
                "multi_iteration": self.multi_iteration_findings,
            },
            "total_tool_calls": self.total_tool_calls,
            "average_confidence": self.average_confidence,
            "average_iterations": self.average_iterations,
        }

