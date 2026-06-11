"""
Pre-Analysis Filter - Early detection of false positives.

This module provides a filtering layer before LLM analysis to:
1. Detect obvious false positives based on static analysis
2. Enrich context with constant and sink analysis
3. Reduce unnecessary LLM calls for clear-cut cases

Key Features:
- Integrates ConstantAnalyzer for trusted source detection
- Integrates SinkVerifier for output context validation
- Provides pre-LLM verdict recommendations
- Injects analysis results into context for LLM consumption
"""

import re
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from enum import Enum

from .constant_analyzer import (
    ConstantAnalyzer,
    ConstantInfo,
    CallerArgumentAnalysis,
)
from .sink_verifier import (
    SinkVerifier,
    SinkVerificationResult,
    VulnerabilityType,
)
from .source_classifier import (
    SourceClassifier,
    SourceClassification,
    SourceType,
)
from .extractor import ExtractedContext

logger = logging.getLogger(__name__)


class PreAnalysisVerdict(Enum):
    """Verdict from pre-analysis."""
    LIKELY_FALSE_POSITIVE = "likely_false_positive"
    LIKELY_TRUE_POSITIVE = "likely_true_positive"
    NEEDS_LLM_ANALYSIS = "needs_llm_analysis"
    UNKNOWN = "unknown"


@dataclass
class PreAnalysisResult:
    """Result of pre-analysis filtering."""
    verdict: PreAnalysisVerdict
    confidence: float
    reasons: list[str] = field(default_factory=list)
    constant_info: Optional[ConstantInfo] = None
    caller_analysis: Optional[CallerArgumentAnalysis] = None
    sink_verification: Optional[SinkVerificationResult] = None
    source_classification: Optional[SourceClassification] = None
    skip_llm: bool = False
    enhanced_context: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "skip_llm": self.skip_llm,
            "constant_info": self.constant_info.to_dict() if self.constant_info else None,
            "caller_analysis": self.caller_analysis.to_dict() if self.caller_analysis else None,
            "sink_verification": self.sink_verification.to_dict() if self.sink_verification else None,
            "source_classification": self.source_classification.to_dict() if self.source_classification else None,
        }
    
    def format_for_llm(self) -> str:
        """Format the pre-analysis result for inclusion in LLM prompt."""
        lines = ["## Pre-Analysis Results\n"]
        
        # Summary verdict
        if self.verdict == PreAnalysisVerdict.LIKELY_FALSE_POSITIVE:
            lines.append("🔍 **Pre-Analysis Verdict: LIKELY FALSE POSITIVE**")
            lines.append(f"   Confidence: {self.confidence:.0%}")
        elif self.verdict == PreAnalysisVerdict.LIKELY_TRUE_POSITIVE:
            lines.append("⚠️ **Pre-Analysis Verdict: LIKELY TRUE POSITIVE**")
            lines.append(f"   Confidence: {self.confidence:.0%}")
        else:
            lines.append("❓ **Pre-Analysis Verdict: NEEDS INVESTIGATION**")
        
        lines.append("")
        
        # Reasons
        if self.reasons:
            lines.append("### Analysis Findings:")
            for reason in self.reasons:
                lines.append(f"- {reason}")
            lines.append("")
        
        # Constant analysis
        if self.constant_info:
            lines.append("### Constant Source Analysis:")
            if self.constant_info.is_trusted:
                lines.append(f"✓ Variable `{self.constant_info.name}` is from trusted constant")
                if self.constant_info.value:
                    val_preview = self.constant_info.value[:50] + "..." if len(self.constant_info.value) > 50 else self.constant_info.value
                    lines.append(f"  Value: `{val_preview}`")
            lines.append("")
        
        # Caller analysis
        if self.caller_analysis:
            lines.append("### Caller Argument Analysis:")
            lines.append(f"Method `{self.caller_analysis.method_name}` (param {self.caller_analysis.parameter_index}):")
            lines.append(f"- Total callers: {self.caller_analysis.total_callers}")
            lines.append(f"- Passing literals: {self.caller_analysis.callers_with_literals}")
            if self.caller_analysis.all_pass_literals:
                lines.append("✓ **ALL callers pass string literals**")
                if self.caller_analysis.literal_values:
                    lines.append("  Example values:")
                    for val in self.caller_analysis.literal_values[:3]:
                        val_preview = val[:40] + "..." if len(val) > 40 else val
                        lines.append(f"  - `{val_preview}`")
            lines.append("")
        
        # Sink verification
        if self.sink_verification:
            lines.append("### Sink Verification:")
            if self.sink_verification.is_valid_sink:
                lines.append(f"✗ Valid {self.sink_verification.vulnerability_type.value} sink detected")
            else:
                lines.append(f"✓ No valid {self.sink_verification.vulnerability_type.value} sink found")
                lines.append(f"  Reason: {self.sink_verification.reason}")
            lines.append("")
        
        # Source classification
        if self.source_classification:
            lines.append("### Data Flow Source Analysis:")
            sc = self.source_classification
            trust_icon = "✓" if sc.is_trusted() else "✗"
            lines.append(f"{trust_icon} Source type: **{sc.source_type.value}**")
            lines.append(f"  Confidence: {sc.confidence:.0%}")
            if sc.is_trusted():
                lines.append(f"  **Data comes from trusted source (not user input)**")
            else:
                lines.append(f"  **Data may come from untrusted user input**")
            if sc.reasons:
                lines.append("  Reasons:")
                for reason in sc.reasons[:3]:
                    lines.append(f"    - {reason}")
            lines.append("")
        
        return "\n".join(lines)


class PreAnalysisFilter:
    """
    Pre-filters findings before LLM analysis to detect obvious false positives.
    
    This improves efficiency by:
    1. Skipping LLM for clear-cut false positives
    2. Providing enhanced context for ambiguous cases
    3. Giving LLM a head start with static analysis results
    """
    
    def __init__(self, project_root: Path, call_graph=None):
        """
        Initialize the pre-analysis filter.
        
        Args:
            project_root: Root directory of the project
            call_graph: Optional pre-built call graph
        """
        self.project_root = project_root
        self.call_graph = call_graph
        self.constant_analyzer = ConstantAnalyzer(project_root)
        self.sink_verifier = SinkVerifier(project_root)
        self.source_classifier = SourceClassifier(project_root, call_graph)
    
    def analyze(self, rule_id: str, code: str, file_path: str,
                line_number: int, variable_name: Optional[str] = None,
                function_name: Optional[str] = None,
                callers: Optional[list[tuple[str, str, int]]] = None) -> PreAnalysisResult:
        """
        Perform pre-analysis on a finding.
        
        Args:
            rule_id: Semgrep rule ID
            code: Code context around the finding
            file_path: Path to the file
            line_number: Line number of the finding
            variable_name: Optional variable name involved
            function_name: Optional function name containing the finding
            callers: Optional list of (caller_code, caller_file, call_line) tuples
            
        Returns:
            PreAnalysisResult with verdict and analysis details
        """
        reasons = []
        confidence = 0.5  # Start neutral
        constant_info = None
        caller_analysis = None
        sink_verification = None
        verdict = PreAnalysisVerdict.NEEDS_LLM_ANALYSIS
        
        # 1. Check for trusted constant sources
        if variable_name:
            is_trusted, reason = self.constant_analyzer.is_trusted_source(
                variable_name, code, Path(file_path) if file_path else None
            )
            if is_trusted:
                reasons.append(f"Variable `{variable_name}` from trusted source: {reason}")
                confidence += 0.3
                
                # Get constant info
                _, const = self.constant_analyzer.is_variable_from_constant(
                    variable_name, code, Path(file_path) if file_path else None
                )
                if const:
                    constant_info = const
        
        # 2. Check for hardcoded in template vs actual secret
        vuln_type = self.sink_verifier.infer_vulnerability_type(rule_id)
        if vuln_type == VulnerabilityType.HARDCODED_SECRET and variable_name:
            is_hardcoded, reason = self.constant_analyzer.detect_hardcoded_in_template(
                code, variable_name
            )
            if not is_hardcoded:
                reasons.append(f"Not hardcoded: {reason}")
                confidence += 0.25
        
        # 3. Analyze caller arguments - try to extract from code if not provided
        if function_name:
            # If no callers provided, try to extract from the code
            if not callers:
                callers = self._extract_callers_from_code(code, function_name)
            
            if callers:
                # Extract parameter index from flagged line
                param_index = self._infer_parameter_index(code, line_number, function_name)
                if param_index >= 0:
                    caller_analysis = self.constant_analyzer.analyze_caller_arguments(
                        callers, function_name, param_index
                    )
                    if caller_analysis.all_pass_literals:
                        reasons.append(
                            f"All {caller_analysis.total_callers} callers pass string literals"
                        )
                        confidence += 0.35
        
        # 4. Verify sink matches vulnerability type
        sink_verification = self.sink_verifier.verify_sink(code, rule_id, line_number)
        if not sink_verification.is_valid_sink:
            reasons.append(f"Invalid sink: {sink_verification.reason}")
            confidence += 0.2
        
        # 5. XSS-specific check
        if vuln_type == VulnerabilityType.XSS and variable_name:
            is_xss_risk, xss_reason = self.sink_verifier.verify_xss_output_context(
                code, variable_name
            )
            if not is_xss_risk:
                reasons.append(f"XSS context: {xss_reason}")
                confidence += 0.25
        
        # 6. Source classification - intelligent data flow tracing
        source_classification = None
        if variable_name or function_name:
            try:
                target_var = variable_name or "param"
                
                # If it's a method parameter, classify via caller analysis
                if function_name:
                    source_classification = self.source_classifier.classify_parameter(
                        method_name=function_name,
                        param_name=target_var,
                        param_index=0,  # Default to first param
                        code=code,
                        file_path=file_path,
                    )
                else:
                    # Classify the variable directly
                    source_classification = self.source_classifier.classify_variable(
                        variable_name=target_var,
                        code=code,
                        file_path=file_path,
                        line_number=line_number,
                    )
                
                # Adjust confidence based on source classification
                if source_classification and source_classification.is_trusted():
                    reasons.append(f"Source is {source_classification.source_type.value}: {', '.join(source_classification.reasons[:2])}")
                    confidence += 0.35  # Strong signal for trusted source
                elif source_classification and source_classification.source_type == SourceType.USER_INPUT:
                    reasons.append("Source is user input - potential vulnerability")
                    confidence = max(0.3, confidence - 0.2)  # Reduce FP likelihood
            except Exception as e:
                logger.debug(f"Source classification failed: {e}")
        
        # Determine final verdict
        if confidence >= 0.75:
            verdict = PreAnalysisVerdict.LIKELY_FALSE_POSITIVE
        elif confidence <= 0.35:
            verdict = PreAnalysisVerdict.LIKELY_TRUE_POSITIVE
        else:
            verdict = PreAnalysisVerdict.NEEDS_LLM_ANALYSIS
        
        # Determine if we can skip LLM
        skip_llm = (verdict == PreAnalysisVerdict.LIKELY_FALSE_POSITIVE and 
                   confidence >= 0.85)
        
        result = PreAnalysisResult(
            verdict=verdict,
            confidence=min(confidence, 1.0),
            reasons=reasons,
            constant_info=constant_info,
            caller_analysis=caller_analysis,
            sink_verification=sink_verification,
            source_classification=source_classification,
            skip_llm=skip_llm,
        )
        
        # Generate enhanced context for LLM
        result.enhanced_context = result.format_for_llm()
        
        return result
    
    def _infer_parameter_index(self, code: str, line_number: int, 
                                function_name: str) -> int:
        """
        Infer which parameter index is involved in the vulnerability.
        
        This is a heuristic based on the flagged line and function signature.
        
        Args:
            code: Code context
            line_number: Flagged line number
            function_name: Name of the function
            
        Returns:
            Parameter index (0-based), or -1 if cannot determine
        """
        # Look for function signature
        sig_pattern = rf'{function_name}\s*\(([^)]+)\)'
        match = re.search(sig_pattern, code)
        
        if not match:
            return 0  # Default to first parameter
        
        params_str = match.group(1)
        params = [p.strip().split()[-1] for p in params_str.split(',')]
        
        # Get the flagged line
        lines = code.split('\n')
        if 0 < line_number <= len(lines):
            flagged_line = lines[line_number - 1]
            
            # Check which parameter is used on the flagged line
            for idx, param in enumerate(params):
                if re.search(rf'\b{re.escape(param)}\b', flagged_line):
                    return idx
        
        return 0  # Default to first parameter
    
    def _extract_callers_from_code(self, code: str, function_name: str) -> list[tuple[str, str, int]]:
        """
        Extract caller information from the code itself.
        
        This looks for all calls to the function within the provided code
        and extracts the calling context.
        
        Args:
            code: Code to search for callers
            function_name: Name of the function to find calls to
            
        Returns:
            List of (caller_code, file, line) tuples
        """
        callers = []
        lines = code.split('\n')
        
        # Pattern to match function calls - more lenient to handle multi-line
        # Match: functionName( with anything following
        call_pattern = rf'\b{re.escape(function_name)}\s*\('
        
        # Pattern to detect function DEFINITION (to skip)
        # Look for: [access modifier] [static] [return type] functionName(
        # Access modifier is REQUIRED for detecting definitions to avoid matching 'return foo()'
        def_pattern = rf'(?:private|public|protected)\s+(?:static\s+)?(?:\w+(?:<[^>]+>)?)\s+{re.escape(function_name)}\s*\('
        
        for line_num, line in enumerate(lines, 1):
            # Skip empty lines
            if not line.strip():
                continue
                
            # Skip the function definition itself
            if re.search(def_pattern, line, re.IGNORECASE):
                continue
            
            # Check if this line contains a call to the function
            if re.search(call_pattern, line):
                # Get surrounding context (2 lines before and after)
                start = max(0, line_num - 3)
                end = min(len(lines), line_num + 2)
                caller_context = '\n'.join(lines[start:end])
                callers.append((caller_context, "inline", line_num))
        
        return callers

    
    def enhance_context(self, context: ExtractedContext, 
                        pre_result: PreAnalysisResult) -> ExtractedContext:
        """
        Enhance the extracted context with pre-analysis results.
        
        Args:
            context: Original ExtractedContext
            pre_result: PreAnalysisResult from analyze()
            
        Returns:
            Enhanced ExtractedContext with pre-analysis data
        """
        # Create a copy with enhanced data
        enhanced = ExtractedContext(
            file_path=context.file_path,
            finding_line=context.finding_line,
            finding_code=context.finding_code,
            function_context=context.function_context,
            surrounding_context=context.surrounding_context,
            additional_context=dict(context.additional_context),
            cross_file_context=dict(context.cross_file_context) if context.cross_file_context else {},
            full_class_code=context.full_class_code,
        )
        
        # Add pre-analysis results
        if "pre_analysis" not in enhanced.cross_file_context:
            enhanced.cross_file_context["pre_analysis"] = {}
        
        enhanced.cross_file_context["pre_analysis"] = pre_result.to_dict()
        enhanced.cross_file_context["pre_analysis_summary"] = pre_result.format_for_llm()
        
        return enhanced
    
    def get_callers_for_function(self, class_name: str, 
                                  method_name: str, 
                                  max_callers: int = 10) -> list[tuple[str, str, int]]:
        """
        Get callers for a function from the call graph.
        
        Args:
            class_name: Name of the class
            method_name: Name of the method
            max_callers: Maximum number of callers to return
            
        Returns:
            List of (caller_code, caller_file, call_line) tuples
        """
        if not self.call_graph:
            return []
        
        callers = []
        
        # Try to find the node
        node_id = f"{class_name}.{method_name}" if class_name else method_name
        
        caller_ids = self.call_graph.get_callers(node_id)
        
        for caller_id in caller_ids[:max_callers]:
            caller_node = self.call_graph.get_node(caller_id)
            if caller_node:
                # Read caller code
                try:
                    file_path = Path(caller_node.file_path)
                    if file_path.exists():
                        content = file_path.read_text(encoding="utf-8", errors="replace")
                        lines = content.split('\n')
                        
                        # Extract method body
                        start = max(0, caller_node.start_line - 1)
                        end = min(len(lines), caller_node.end_line)
                        caller_code = '\n'.join(lines[start:end])
                        
                        # Find call line
                        call_line = caller_node.start_line
                        for edge in self.call_graph.edges:
                            if edge.caller_id == caller_id and edge.callee_id == node_id:
                                call_line = edge.call_line
                                break
                        
                        callers.append((caller_code, str(file_path), call_line))
                except Exception as e:
                    logger.debug(f"Failed to read caller {caller_id}: {e}")
        
        return callers
