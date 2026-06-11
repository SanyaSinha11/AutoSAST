"""
Investigation Engine for Iterative Vulnerability Analysis.

This module provides:
1. InvestigationConfig - Configuration for investigation behavior
2. InvestigationState - State machine for investigation lifecycle
3. InvestigationEngine - Orchestrates iterative context gathering
4. InvestigationResult - Result of an investigation
"""

import time
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .confidence import (
    ConfidenceBreakdown,
    InvestigationStep,
    InvestigationTrace,
)

logger = logging.getLogger(__name__)


class InvestigationState(Enum):
    """State of an investigation."""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class InvestigationConfig:
    """Configuration for investigation behavior."""
    max_iterations: int = 3
    confidence_threshold_high: float = 0.75
    confidence_threshold_medium: float = 0.6
    confidence_threshold_low: float = 0.5
    max_tool_calls_per_iteration: int = 6
    enable_proactive_context: bool = True


@dataclass
class InvestigationResult:
    """Result of an investigation."""
    verdict: str
    confidence: float
    reasoning: str
    trace: InvestigationTrace
    success: bool = True
    error: Optional[str] = None


class InvestigationEngine:
    """
    Orchestrates iterative context gathering for vulnerability analysis.
    
    The engine tracks:
    - Investigation state
    - Confidence progression
    - Context gathered at each step
    - Exit conditions
    """

    def __init__(self, config: Optional[InvestigationConfig] = None):
        self.config = config or InvestigationConfig()
        self.state = InvestigationState.NOT_STARTED
        self._current_trace: Optional[InvestigationTrace] = None
        self._iteration = 0

    def start_investigation(
        self,
        finding_id: str,
        rule_id: str,
        file_path: str,
    ) -> InvestigationTrace:
        """Start a new investigation."""
        self.state = InvestigationState.IN_PROGRESS
        self._iteration = 0
        self._current_trace = InvestigationTrace(
            finding_id=finding_id,
            rule_id=rule_id,
            file_path=file_path,
            start_time_ms=int(time.time() * 1000),
        )
        return self._current_trace

    def record_step(
        self,
        iteration: int,
        action: str,
        context_gathered: list[str],
        confidence_before: float,
        confidence_after: float,
        verdict_before: str = "",
        verdict_after: str = "",
        tool_calls: int = 0,
        duration_ms: int = 0,
        confidence_breakdown: Optional[ConfidenceBreakdown] = None,
    ) -> InvestigationStep:
        """Record a step in the investigation."""
        step = InvestigationStep(
            iteration=iteration,
            action=action,
            context_gathered=context_gathered,
            confidence_before=confidence_before,
            confidence_after=confidence_after,
            verdict_before=verdict_before,
            verdict_after=verdict_after,
            verdict_changed=verdict_before != verdict_after and verdict_before != "",
            tool_calls=tool_calls,
            duration_ms=duration_ms,
            confidence_breakdown=confidence_breakdown,
        )
        if self._current_trace:
            self._current_trace.add_step(step)
        self._iteration = iteration
        return step

    def should_continue(
        self,
        iteration: int,
        verdict: str,
        confidence: float,
    ) -> tuple[bool, str]:
        """
        Determine if investigation should continue.
        
        Returns:
            Tuple of (should_continue, reason)
        """
        # Check max iterations
        if iteration >= self.config.max_iterations:
            return False, "max_iterations_reached"

        # High confidence definitive verdicts don't need more context
        if confidence >= self.config.confidence_threshold_high:
            if verdict in ("true_positive", "false_positive"):
                return False, "high_confidence_verdict"

        # Needs more context verdict should continue
        if verdict == "needs_more_context":
            return True, "needs_more_context"

        # Low confidence should trigger context expansion
        if confidence < self.config.confidence_threshold_low:
            return True, "low_confidence"

        # Medium confidence verdicts are acceptable
        return False, "acceptable_confidence"

    def complete_investigation(
        self,
        verdict: str,
        confidence: float,
        confidence_breakdown: Optional[ConfidenceBreakdown] = None,
        early_exit: bool = False,
        early_exit_reason: str = "",
    ) -> InvestigationTrace:
        """Complete the investigation and return the trace."""
        self.state = InvestigationState.COMPLETED
        if self._current_trace:
            self._current_trace.end_time_ms = int(time.time() * 1000)
            self._current_trace.final_verdict = verdict
            self._current_trace.final_confidence = confidence
            self._current_trace.final_confidence_breakdown = confidence_breakdown
            self._current_trace.early_exit = early_exit
            self._current_trace.early_exit_reason = early_exit_reason
        return self._current_trace


def create_investigation_engine(
    max_iterations: int = 3,
    confidence_threshold_high: float = 0.75,
    confidence_threshold_low: float = 0.5,
) -> InvestigationEngine:
    """Factory function to create an investigation engine."""
    config = InvestigationConfig(
        max_iterations=max_iterations,
        confidence_threshold_high=confidence_threshold_high,
        confidence_threshold_low=confidence_threshold_low,
    )
    return InvestigationEngine(config=config)

