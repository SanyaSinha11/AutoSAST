"""
LLM Analyzer - Uses guided questions to analyze Semgrep findings.

This is the core of the false positive reduction system. It:
1. Takes a Semgrep finding with its code context
2. Applies issue-specific guided questions
3. Forces the LLM to reason step-by-step
4. Supports dynamic tool calling for additional context (VulnHalla-inspired)
5. Returns a verdict with confidence and reasoning
"""

import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from .client import LLMClient, LLMResponse, Message, ToolCall
from .tools import ANALYSIS_TOOLS
from .prompt_templates import build_system_messages, get_issue_hint
from .confidence import (
    ConfidenceBreakdown,
    InvestigationStep,
    InvestigationTrace,
    InvestigationMetrics,
)
from .investigation_engine import InvestigationEngine, InvestigationConfig
from .context_manager import (
    InvestigationState,
    truncate_tool_response,
    generate_checkpoint_summary,
    extract_source_sink_from_finding,
    get_vulnerability_type,
    CHECKPOINT_INTERVAL,
)
from ..context.extractor import ExtractedContext
from ..context.code_lookup import CodeLookup
from ..semgrep.runner import SemgrepFinding

# Import pre-analysis modules for early FP detection
try:
    from ..context.pre_analysis_filter import (
        PreAnalysisFilter,
        PreAnalysisResult,
        PreAnalysisVerdict,
    )
    _PRE_ANALYSIS_AVAILABLE = True
except ImportError:
    _PRE_ANALYSIS_AVAILABLE = False
    PreAnalysisFilter = None
    PreAnalysisResult = None
    PreAnalysisVerdict = None


logger = logging.getLogger(__name__)

# Constants for tool calling
MAX_TOOL_CALLS = 8  # Increased to allow thorough investigation with state management
MAX_TEXT_TOOL_RETRIES = 2  # Max retries when LLM outputs tool calls as text

# Patterns to detect text-based tool calls (LLM wrote JSON instead of using API)
TEXT_TOOL_PATTERNS = [
    '"recipient_name"',
    '"function_name"',
    '"get_caller_function"',
    '"get_function_code"',
    '"search_code"',
    '"get_class_code"',
    '"get_method_code"',
    '"get_imports"',
    '"map_arguments"',
    '"read_file"',
    'functions.get_',
]


def _detect_text_tool_call(content: str) -> bool:
    """Detect if the LLM tried to call tools via text instead of the API."""
    if not content:
        return False
    content_lower = content.lower()
    # Check for patterns indicating the LLM tried to write a tool call as text
    for pattern in TEXT_TOOL_PATTERNS:
        if pattern.lower() in content_lower:
            return True
    # Also check for JSON-like tool call patterns
    if '"parameters"' in content_lower and ('caller_index' in content_lower or 'function_name' in content_lower):
        return True
    return False


class Verdict(Enum):
    """Verdict for a finding."""
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"
    INSUFFICIENT_CONTEXT = "insufficient_context"
    NEEDS_MORE_CONTEXT = "needs_more_context"  # Triggers iterative context expansion


# Confidence thresholds for iterative context expansion
CONFIDENCE_THRESHOLD_HIGH = 0.75  # Above this, verdict is final (lowered for better iteration)
CONFIDENCE_THRESHOLD_MEDIUM = 0.6  # Between low and high - may benefit from more context
CONFIDENCE_THRESHOLD_LOW = 0.5   # Below this, trigger context expansion
MAX_CONTEXT_ITERATIONS = 3       # Maximum iterations for context expansion


@dataclass
class ContextExpansionRequest:
    """Request for additional context during iterative analysis."""
    request_type: str  # "caller", "callee", "class", "search", "imports", "method", "file"
    target: str        # What to look up (function name, class name, pattern)
    reason: str        # Why this context is needed
    priority: int = 1  # Higher priority = more important
    file_hint: str = ""  # Optional file path hint for better lookup


@dataclass
class AnalysisResult:
    """Result of LLM analysis for a finding."""
    finding: SemgrepFinding
    verdict: Verdict
    confidence: float  # 0.0 to 1.0
    reasoning: str
    guided_answers: dict[str, str]  # Question -> Answer mapping
    llm_response: LLMResponse
    tool_calls_made: int = 0  # Number of tool calls during analysis
    conversation_history: list[dict] = field(default_factory=list)  # Full conversation for auditing
    context_iterations: int = 0  # Number of context expansion iterations
    context_expansion_requests: list[ContextExpansionRequest] = field(default_factory=list)  # Requested expansions
    final_iteration: bool = True  # Whether this is the final analysis result

    # Enhanced fields for structured confidence and investigation trace
    confidence_breakdown: Optional[ConfidenceBreakdown] = None  # Detailed confidence factors
    investigation_trace: Optional[InvestigationTrace] = None  # Full investigation trace
    pre_analysis: Optional[dict] = None  # Pre-analysis results from source classification

    @property
    def is_actionable(self) -> bool:
        """Whether this finding requires developer attention."""
        return self.verdict == Verdict.TRUE_POSITIVE or self.verdict == Verdict.NEEDS_REVIEW

    @property
    def needs_more_context(self) -> bool:
        """Whether this result indicates more context is needed."""
        return (
            self.verdict == Verdict.NEEDS_MORE_CONTEXT or
            self.verdict == Verdict.INSUFFICIENT_CONTEXT or
            (self.confidence < CONFIDENCE_THRESHOLD_LOW and self.verdict == Verdict.NEEDS_REVIEW)
        )

    @property
    def weakest_confidence_factors(self) -> list[tuple[str, float]]:
        """Get weakest confidence factors if breakdown is available."""
        if self.confidence_breakdown:
            return self.confidence_breakdown.weakest_factors
        return []

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'finding_id': f"{self.finding.rule_id}:{self.finding.file_path}:{self.finding.start_line}",
            'verdict': self.verdict.value,
            'confidence': self.confidence,
            'confidence_breakdown': self.confidence_breakdown.to_dict() if self.confidence_breakdown else None,
            'reasoning': self.reasoning,
            'guided_answers': self.guided_answers,
            'tool_calls_made': self.tool_calls_made,
            'context_iterations': self.context_iterations,
            'final_iteration': self.final_iteration,
            'investigation_trace': self.investigation_trace.to_dict() if self.investigation_trace else None,
            'pre_analysis': self.pre_analysis,
        }


# Enhanced system prompt with tool calling and iterative context instructions
SYSTEM_PROMPT = """You are a security code reviewer specializing in identifying false positives in static analysis results.

Your task is to analyze a security finding from Semgrep and determine if it's a TRUE POSITIVE (real vulnerability) or FALSE POSITIVE (not actually vulnerable).

## Available Tools (10 Total)
You have access to these tools to request additional code context:

### Primary Navigation Tools (USE THESE FIRST)
1. `read_file(file_path, line_number?, context_lines?)`: Read any file, optionally centered on a line. Your PRIMARY tool for exploring code.
2. `search_code(pattern, file_extension?)`: Search codebase for patterns (method names, variables, classes). Returns file:line for navigation.

### Code Retrieval Tools
3. `get_function_code`: Get the source code of any function/method by name
4. `get_caller_function`: Get code of functions that call the vulnerable function (by index)
5. `get_class_code`: Get the full source code of a class by name
6. `get_method_code`: Get a specific method from a class (class_name + method_name)
7. `get_imports`: Get import statements from a file path

### Data Flow Analysis Tools
8. `map_arguments`: Map caller arguments to callee parameters for understanding data flow
9. `get_sanitization_check`: Check if a specific variable is sanitized/validated before reaching a sink
10. `get_caller_chain`: Get the full call chain from entry points (controllers/handlers) to the vulnerable function
11. `analyze_data_flow`: **RECOMMENDED** - Perform inter-procedural data flow analysis to track tainted variables from source to sink, including through function calls. Returns comprehensive sanitization analysis.

## ⚠️ MANDATORY: Answer Guided Questions Using Tools

**YOU MUST USE TOOLS TO ANSWER EACH GUIDED QUESTION BEFORE MAKING A VERDICT.**

For each guided question provided, you MUST:
1. Identify what code context is needed to answer the question
2. Call the appropriate tool(s) to gather that context
3. Analyze the returned code to form your answer
4. Only then answer the question with specific code evidence

### Tool Usage Strategy by Question Type:

| Question Type | Tools to Use |
|--------------|--------------|
| "Is input sanitized/validated?" | `get_sanitization_check`, `search_code("sanitize\|validate\|escape")` |
| "Is PreparedStatement used?" | `search_code("PreparedStatement\|setString")`, `read_file` to examine matches |
| "Where does input come from?" | `get_caller_chain`, `get_caller_function`, `read_file` to trace callers |
| "What encoding is applied?" | `search_code("encode\|escape\|HtmlUtils")`, `get_sanitization_check` |
| "Is data flow to sink safe?" | `analyze_data_flow`, `map_arguments`, `get_caller_function` |
| "What libraries are used?" | `get_imports`, `search_code` |

### Example Tool Usage Flow:
```
Question: "Is user input written directly to HttpServletResponse without encoding?"

Step 1: Call `search_code("getParameter")` to find where user input enters
Step 2: Call `read_file("<file>", <line>)` to examine each match
Step 3: Call `search_code("HtmlUtils|escapeHtml|encode")` to find sanitization
Step 4: Call `get_sanitization_check` with variable="userInput"
Step 5: Now answer with evidence from tool results
```

**DO NOT SKIP TOOL CALLS. If you answer a question without tool evidence, you MUST call tools first.**

## Analysis Process
1. Review the initial context provided
2. **For EACH guided question**: Use tools to gather evidence, then answer
3. Use data flow tools (`trace_taint_path`, `get_caller_chain`) to understand the full path
4. Only provide verdict after answering ALL questions with tool-backed evidence

## CRITICAL: Structured Confidence Scoring
Your confidence score determines if more context will be gathered. Provide a STRUCTURED breakdown:

### Confidence Factors (each 0.0-1.0):
- **context_completeness**: How complete is the code context you have?
- **data_flow_visibility**: Can you trace the data flow from source to sink?
- **sanitization_evidence**: Do you have evidence of sanitization/validation (or lack thereof)?
- **pattern_match_strength**: How well does the code match known vulnerable/safe patterns?
- **caller_context**: Do you have information about how this function is called?
- **cross_file_resolution**: Are imported classes and dependencies resolved?

### Overall Confidence Thresholds:
- **0.75-1.0**: HIGH - Definitive verdict with clear evidence
- **0.5-0.75**: MEDIUM - Likely correct but some uncertainty
- **Below 0.5**: LOW - MUST use "needs_more_context" verdict

### When to Request More Context
Request more context when any factor is below 0.5:
1. Low context_completeness → Request surrounding code
2. Low data_flow_visibility → Request callers/callees
3. Low sanitization_evidence → Search for validation patterns
4. Low caller_context → Request caller functions
5. Low cross_file_resolution → Request imports/classes

### Context Request Format
When confidence is low, ALWAYS provide specific context requests:
```json
{
    "context_requests": [
        {
            "type": "caller",
            "target": "executeQuery",
            "reason": "Need to see how user input reaches this SQL query",
            "priority": 1
        },
        {
            "type": "method",
            "target": "sanitizeInput",
            "reason": "Need to verify this sanitization method is effective",
            "priority": 2
        }
    ]
}
```

## Context Request Types
- **"caller"**: Get functions that call the vulnerable function (check upstream validation)
- **"callee"**: Get called functions (check if they sanitize/validate)
- **"method"**: Get a specific method by name (e.g., "validateInput")
- **"class"**: Get full class code (understand all related methods)
- **"search"**: Search codebase for pattern (e.g., "parameterized query")
- **"imports"**: Get import statements (identify frameworks/libraries)
- **"file"**: Get content from a specific file path

## Output Format
Output your analysis as JSON with STRUCTURED confidence breakdown:
```json
{
    "guided_answers": {
        "question1": "your detailed answer based on code evidence",
        "question2": "your detailed answer with specific line references"
    },
    "verdict": "true_positive" | "false_positive" | "needs_review" | "needs_more_context",
    "confidence": 0.0-1.0,
    "confidence_breakdown": {
        "context_completeness": 0.0-1.0,
        "data_flow_visibility": 0.0-1.0,
        "sanitization_evidence": 0.0-1.0,
        "pattern_match_strength": 0.0-1.0,
        "caller_context": 0.0-1.0,
        "cross_file_resolution": 0.0-1.0
    },
    "reasoning": "Your overall reasoning with specific code evidence",
    "context_requests": [
        {"type": "caller|callee|method|class|search", "target": "name", "reason": "why needed", "priority": 1-3}
    ]
}
```

## Status Codes (Alternative Output)
- **1337** = True Positive (real vulnerability found)
- **1007** = False Positive (definitely not vulnerable)
- **7331** = Needs More Context (will trigger context expansion)

## Important Guidelines
1. **USE TOOLS FIRST**: Call tools to gather evidence BEFORE answering questions
2. **Be evidence-based**: Cite specific code from tool results
3. **Trace full data flow**: Use `read_file` + `search_code` to trace from sink to source
4. **Check for sanitization**: Use `get_sanitization_check` and `search_code` to find security controls
5. **Be conservative**: When unsure after using tools, mark as NEEDS_REVIEW

## ⚠️ CRITICAL REMINDER
- You have 11 tools available - USE THEM
- Use `read_file` and `search_code` as your PRIMARY navigation tools
- Do NOT answer guided questions without tool evidence
- Each question should trigger at least one tool call
- Minimum expected tool calls: 3-5 per analysis"""


# Simpler system prompt for non-tool-calling mode
SYSTEM_PROMPT_SIMPLE = """You are a security code reviewer specializing in identifying false positives in static analysis results.

Your task is to analyze a security finding from Semgrep and determine if it's a TRUE POSITIVE (real vulnerability) or FALSE POSITIVE (not actually vulnerable).

## Analysis Requirements
1. Answer each guided question with specific code evidence
2. Trace data flow from source to sink
3. Look for sanitization, validation, encoding, or parameterization
4. Check for allowlist patterns and security controls
5. Be conservative - if unsure, mark as NEEDS_REVIEW

## Structured Confidence Scoring (CRITICAL)
Rate each factor from 0.0 to 1.0:
- **context_completeness**: How complete is the code context?
- **data_flow_visibility**: Can you trace source to sink?
- **sanitization_evidence**: Evidence of validation/sanitization?
- **caller_context**: Do you have caller information?

Overall thresholds:
- **0.75-1.0**: HIGH - Definitive verdict | **0.5-0.75**: MEDIUM | **Below 0.5**: LOW → use "needs_more_context"

## Output Format
```json
{
    "guided_answers": {"question1": "answer with evidence", "question2": "answer with line refs"},
    "verdict": "true_positive" | "false_positive" | "needs_review" | "needs_more_context",
    "confidence": 0.0-1.0,
    "confidence_breakdown": {
        "context_completeness": 0.0-1.0,
        "data_flow_visibility": 0.0-1.0,
        "sanitization_evidence": 0.0-1.0,
        "caller_context": 0.0-1.0
    },
    "reasoning": "Your reasoning with code evidence",
    "context_requests": [{"type": "caller|method|search", "target": "name", "reason": "why"}]
}
```

## Status Codes
- 1337 = True Positive | 1007 = False Positive | 7331 = Needs More Context"""


def build_analysis_prompt(
    finding: SemgrepFinding,
    context: ExtractedContext,
    guided_questions: list[str],
) -> str:
    """Build the analysis prompt for the LLM with comprehensive context."""

    # Build context section
    context_section = ""
    if context.function_context:
        context_section = f"""
## Function Context
Function: {context.function_context.name}
Lines {context.function_context.start_line}-{context.function_context.end_line}

```
{context.function_context.full_code}
```
"""
    else:
        context_section = f"""
## Surrounding Context
```
{context.surrounding_context}
```
"""

    # Build additional context
    additional = ""
    if context.additional_context.get("imports"):
        additional = "\n## Imports\n" + "\n".join(context.additional_context["imports"][:15])

    # Build class methods context (to understand the full class structure)
    methods_section = ""
    if context.additional_context.get("methods"):
        methods = context.additional_context["methods"]
        if len(methods) > 1:
            methods_section = "\n## Other Methods in This Class\n"
            for m in methods[:10]:
                methods_section += f"- {m['name']}() at line {m['line']}\n"

    # Build full class context for deeper analysis (critical for vulnerability assessment)
    full_class_section = ""
    if context.full_class_code:
        # Include the full class but limit to relevant portions
        lines = context.full_class_code.split('\n')
        if len(lines) > 150:
            # Include first 150 lines for larger classes
            full_class_section = "\n## Full Class Code (first 150 lines)\n```\n"
            full_class_section += '\n'.join(lines[:150])
            full_class_section += f"\n... ({len(lines) - 150} more lines)\n```"
        else:
            full_class_section = f"\n## Full Class Code ({len(lines)} lines)\n```\n"
            full_class_section += context.full_class_code
            full_class_section += "\n```"

    # Build cross-file context section
    cross_file_section = ""
    if context.cross_file_context:
        cf = context.cross_file_context

        # Add entry points summary if available (from call graph)
        if cf.get("entry_points"):
            cross_file_section += "\n## 🎯 Entry Points Identified (via Call Graph)\n"
            cross_file_section += "The following entry points call into this function chain:\n"
            for ep in cf["entry_points"][:5]:
                cross_file_section += f"  • {ep}\n"
            cross_file_section += "\n**Check these entry points for input validation/sanitization.**\n"

        # Add data flow chain summary if available
        if cf.get("data_flow_chain"):
            cross_file_section += "\n## Data Flow Chain (Entry Point → This Function)\n"
            cross_file_section += "This shows how data flows from entry points to this function:\n"
            chain = cf["data_flow_chain"]
            cross_file_section += " → ".join(chain[:5]) + "\n"
            cross_file_section += "\n**IMPORTANT**: Check if any sanitization/validation occurs in the upstream callers.\n"

        # Add pre-detected sanitization (critical for FP reduction)
        if cf.get("sanitization_detected"):
            cross_file_section += "\n## ✅ Pre-Detected Sanitization/Validation (via Call Graph Analysis)\n"
            cross_file_section += "The following sanitization was detected in the call chain:\n"
            for s in cf["sanitization_detected"][:5]:
                cross_file_section += f"\n  • **{s['location']}**: {', '.join(s['patterns'][:3])}\n"
            cross_file_section += "\n**This suggests the vulnerability may be a FALSE POSITIVE if input is sanitized before reaching the sink.**\n"

        if cf.get("callers"):
            cross_file_section += "\n## Callers of This Function (Full Call Chain)\n"
            cross_file_section += "**Review each caller to check for input sanitization before data reaches this function:**\n"
            for caller in cf["callers"][:5]:
                class_name = caller.get('class', 'Unknown')
                is_entry = " ⭐ ENTRY POINT" if caller.get('is_entry_point') else ""
                sanitization_marker = " ✅ HAS_SANITIZATION" if caller.get('has_sanitization') else ""
                cross_file_section += f"\n### {class_name}.{caller['method']}(){is_entry}{sanitization_marker} at {caller['file']}:{caller['line']}\n"
                if caller.get('sanitization_hints'):
                    cross_file_section += f"_Sanitization patterns found: {', '.join(caller['sanitization_hints'][:3])}_\n"
                cross_file_section += f"```\n{caller['snippet']}\n```\n"

        if cf.get("related_methods"):
            cross_file_section += "\n## Related Methods in Same Class\n"
            for method in cf["related_methods"][:3]:
                cross_file_section += f"\n### {method['name']}() at line {method['line']}\n"
                cross_file_section += f"```\n{method['snippet']}\n```\n"

        # Add proactively gathered context (from iterative context expansion)
        if cf.get("proactive_context"):
            cross_file_section += "\n## Pre-fetched Context (Automatically Gathered)\n"
            for item in cf["proactive_context"][:5]:
                ctx_type = item.get("type", "unknown")
                reason = item.get("reason", "")
                cross_file_section += f"\n### {ctx_type}: {reason}\n"
                if item.get("code"):
                    cross_file_section += f"```\n{item['code'][:1500]}\n```\n"
                elif item.get("results"):
                    cross_file_section += f"```\n{item['results'][:1500]}\n```\n"

        # Add expanded callers from context expansion iterations
        if cf.get("expanded_callers"):
            cross_file_section += "\n## Expanded Callers (From Context Expansion)\n"
            for caller in cf["expanded_callers"][:3]:
                cross_file_section += f"\n### Caller: {caller.get('target', 'unknown')}\n"
                cross_file_section += f"**Reason**: {caller.get('reason', 'N/A')}\n"
                cross_file_section += f"```\n{caller.get('code', '')[:1500]}\n```\n"

        # Add expanded methods
        if cf.get("expanded_methods"):
            cross_file_section += "\n## Expanded Methods (From Context Expansion)\n"
            for method in cf["expanded_methods"][:3]:
                cross_file_section += f"\n### Method: {method.get('target', 'unknown')}\n"
                cross_file_section += f"**Reason**: {method.get('reason', 'N/A')}\n"
                cross_file_section += f"```\n{method.get('code', '')[:1500]}\n```\n"

        # Add expanded callees
        if cf.get("expanded_callees"):
            cross_file_section += "\n## Called Functions (From Context Expansion)\n"
            for callee in cf["expanded_callees"][:3]:
                cross_file_section += f"\n### Function: {callee.get('target', 'unknown')}\n"
                cross_file_section += f"**Reason**: {callee.get('reason', 'N/A')}\n"
                cross_file_section += f"```\n{callee.get('code', '')[:1500]}\n```\n"

        # Add search results
        if cf.get("search_results"):
            cross_file_section += "\n## Codebase Search Results\n"
            for result in cf["search_results"][:2]:
                cross_file_section += f"\n### Pattern: `{result.get('pattern', '')}`\n"
                cross_file_section += f"**Reason**: {result.get('reason', 'N/A')}\n"
                cross_file_section += f"```\n{result.get('results', '')[:2000]}\n```\n"

        # Add pre-analysis hints (from PreAnalysisFilter)
        if cf.get("pre_analysis_hints"):
            cross_file_section += "\n## 🔍 Pre-Analysis Static Analysis Results\n"
            cross_file_section += "**The following static analysis was performed before LLM analysis:**\n\n"
            for hint in cf["pre_analysis_hints"][:2]:
                verdict = hint.get("verdict", "unknown")
                confidence = hint.get("confidence", 0)
                
                if verdict == "likely_false_positive":
                    cross_file_section += f"⚠️ **Pre-Analysis Verdict: LIKELY FALSE POSITIVE** (confidence: {confidence:.0%})\n\n"
                elif verdict == "likely_true_positive":
                    cross_file_section += f"🚨 **Pre-Analysis Verdict: LIKELY TRUE POSITIVE** (confidence: {confidence:.0%})\n\n"
                else:
                    cross_file_section += f"❓ **Pre-Analysis Verdict: NEEDS INVESTIGATION** (confidence: {confidence:.0%})\n\n"
                
                if hint.get("summary"):
                    cross_file_section += f"{hint['summary']}\n\n"
            
            cross_file_section += "**Consider the above static analysis when making your verdict.**\n"

        # Add pre-analysis summary if available (detailed format)
        if cf.get("pre_analysis_summary"):
            cross_file_section += "\n" + cf["pre_analysis_summary"] + "\n"


    # Build guided questions section
    questions_section = "\n".join(f"{i+1}. {q}" for i, q in enumerate(guided_questions))

    prompt = f"""# Security Finding Analysis

## Finding Details
- **Rule**: {finding.rule_id}
- **Severity**: {finding.severity}
- **Message**: {finding.message}
- **Location**: {finding.location_str}

## Flagged Code
```
{finding.code_snippet}
```
{context_section}
{full_class_section}
{cross_file_section}
{additional}
{methods_section}

## Guided Questions
Please answer each question carefully by examining ALL the context above:

{questions_section}

IMPORTANT: Before concluding, verify:
1. Have you checked the FULL class code for how the vulnerable parameter is generated/obtained?
2. Have you traced data flow from source to sink?
3. Have you checked for any related methods that handle security?

Analyze this finding and provide your response as JSON."""

    return prompt


class FindingAnalyzer:
    """Analyzes Semgrep findings using LLM with guided questions and tool calling."""

    def __init__(
        self,
        llm_client: LLMClient,
        temperature: float = 0.2,
        enable_tool_calling: bool = True,
        project_root: Optional[Path] = None,
    ):
        self.llm_client = llm_client
        self.temperature = temperature
        self.enable_tool_calling = enable_tool_calling
        self.project_root = project_root
        self._code_lookup: Optional[CodeLookup] = None

    def _get_code_lookup(self) -> Optional[CodeLookup]:
        """Lazy initialize code lookup."""
        if self._code_lookup is None and self.project_root:
            self._code_lookup = CodeLookup(self.project_root)
        return self._code_lookup

    def map_arguments(self, caller_code: str, callee_code: str) -> str:
        """
        Map arguments from caller to callee function (VulnHalla-style).

        This helps understand data flow by identifying which variables
        in the caller are passed to which parameters in the callee.

        Args:
            caller_code: Source code of the calling function
            callee_code: Source code of the called function

        Returns:
            Mapping of caller variables to callee parameters
        """
        args_prompt = (
            "Given caller function and callee function.\n"
            "Write only what are the names of the vars in the caller that were sent to the callee "
            "and what are their names in the callee.\n"
            "Format: caller_var (caller_name) -> callee_var (callee_name)\n\n"
            f"Caller function:\n{caller_code}\n\n"
            f"Callee function:\n{callee_code}"
        )

        response = self.llm_client.complete(
            messages=[Message(role="user", content=args_prompt)],
            temperature=0.1,  # Low temperature for deterministic mapping
        )

        return response.content

    def analyze(
        self,
        finding: SemgrepFinding,
        context: ExtractedContext,
        guided_questions: list[str],
    ) -> AnalysisResult:
        """Analyze a single finding using simple completion."""

        prompt = build_analysis_prompt(finding, context, guided_questions)

        logger.debug(f"Analyzing finding: {finding.rule_id} at {finding.location_str}")

        response = self.llm_client.complete(
            prompt=prompt,
            system_prompt=SYSTEM_PROMPT_SIMPLE,
            temperature=self.temperature,
        )

        return self._parse_response(finding, response)

    def analyze_with_pre_filter(
        self,
        finding: SemgrepFinding,
        context: ExtractedContext,
        guided_questions: list[str],
        call_graph=None,
    ) -> AnalysisResult:
        """
        Analyze a finding with pre-analysis filtering for early FP detection.
        
        This method integrates static analysis before LLM to:
        1. Detect obvious false positives (skip LLM)
        2. Enhance context with constant/sink analysis
        3. Improve LLM accuracy with pre-analysis insights
        
        Args:
            finding: The Semgrep finding to analyze
            context: Extracted code context
            guided_questions: Questions for the LLM to answer
            call_graph: Optional pre-built call graph for caller analysis
            
        Returns:
            AnalysisResult with verdict and reasoning
        """
        if not _PRE_ANALYSIS_AVAILABLE or not self.project_root:
            logger.debug("Pre-analysis not available, falling back to standard analysis")
            return self.analyze_with_tools(finding, context, guided_questions)
        
        # Extract variable name from finding
        variable_name = self._extract_variable_from_finding(finding)
        
        # Extract function name from context
        function_name = None
        if context.function_context:
            function_name = context.function_context.name
        
        # Initialize pre-analysis filter
        pre_filter = PreAnalysisFilter(
            project_root=self.project_root,
            call_graph=call_graph,
        )
        
        # Get callers if call graph available
        callers = []
        if call_graph and function_name:
            class_name = context.additional_context.get("class_name", "")
            callers = pre_filter.get_callers_for_function(class_name, function_name)
        
        # Get full code for analysis
        code = context.function_context.full_code if context.function_context else context.surrounding_context
        if context.full_class_code:
            code = context.full_class_code
        
        # Perform pre-analysis
        pre_result = pre_filter.analyze(
            rule_id=finding.rule_id or "",
            code=code,
            file_path=finding.file_path or "",
            line_number=finding.start_line,
            variable_name=variable_name,
            function_name=function_name,
            callers=callers if callers else None,
        )
        
        logger.info(
            f"Pre-analysis for {finding.rule_id}: verdict={pre_result.verdict.value}, "
            f"confidence={pre_result.confidence:.2f}, skip_llm={pre_result.skip_llm}"
        )
        
        # If pre-analysis is highly confident it's FP, skip LLM
        if pre_result.skip_llm and pre_result.verdict == PreAnalysisVerdict.LIKELY_FALSE_POSITIVE:
            logger.info(f"Skipping LLM for {finding.location_str} - pre-analysis detected FP")
            
            # Create result from pre-analysis
            reasoning = f"**Pre-Analysis Detected False Positive**\n\n"
            reasoning += "\n".join(f"- {r}" for r in pre_result.reasons)
            
            return AnalysisResult(
                finding=finding,
                verdict=Verdict.FALSE_POSITIVE,
                confidence=pre_result.confidence,
                reasoning=reasoning,
                guided_answers={"pre_analysis": "Skipped LLM - static analysis detected false positive"},
                llm_response=LLMResponse(content="[Skipped - Pre-analysis detected FP]"),
                tool_calls_made=0,
                conversation_history=[{"role": "system", "content": "Pre-analysis FP detection"}],
            )
        
        # Enhance context with pre-analysis results
        enhanced_context = pre_filter.enhance_context(context, pre_result)
        
        # Add pre-analysis summary to prompt
        if pre_result.enhanced_context:
            if "pre_analysis_hints" not in enhanced_context.cross_file_context:
                enhanced_context.cross_file_context["pre_analysis_hints"] = []
            enhanced_context.cross_file_context["pre_analysis_hints"].append({
                "type": "pre_analysis_summary",
                "verdict": pre_result.verdict.value,
                "confidence": pre_result.confidence,
                "summary": pre_result.enhanced_context,
            })
        
        # Continue with tool-enabled analysis using enhanced context
        return self.analyze_with_tools(finding, enhanced_context, guided_questions)
    
    def _extract_variable_from_finding(self, finding: SemgrepFinding) -> Optional[str]:
        """
        Extract the main variable name from a finding.
        
        Args:
            finding: The Semgrep finding
            
        Returns:
            Variable name if found, None otherwise
        """
        import re
        
        code = finding.code_snippet or ""
        
        # Try different patterns to extract variable names
        patterns = [
            # Java: Type varName = 
            r'\b(?:String|int|long|Object|List|Map|Set)\s+(\w+)\s*=',
            # Assignment
            r'(\w+)\s*=\s*request\.get',
            # Method parameter usage
            r'\.(?:execute|write|print|read)\s*\(\s*(\w+)',
            # Generic variable after assignment
            r'(\w+)\s*=\s*[^=]',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, code)
            if match:
                return match.group(1)
        
        return None

    def analyze_with_tools(
        self,
        finding: SemgrepFinding,
        context: ExtractedContext,
        guided_questions: list[str],
    ) -> AnalysisResult:
        """Analyze a finding with tool calling support for dynamic context retrieval."""

        if not self.enable_tool_calling or not self.project_root:
            logger.debug("Tool calling disabled or no project root, falling back to simple analysis")
            return self.analyze(finding, context, guided_questions)

        prompt = build_analysis_prompt(finding, context, guided_questions)

        # Build structured system messages (VulnHalla-style)
        system_messages = build_system_messages(finding.rule_id)

        # Build initial messages with structured prompts
        messages = [Message(role=m["role"], content=m["content"]) for m in system_messages]
        messages.append(Message(role="user", content=prompt))

        # Track conversation history for auditing
        conversation_history = [{"role": m["role"], "content": m["content"]} for m in system_messages]
        conversation_history.append({"role": "user", "content": prompt})
        tool_calls_count = 0
        final_response: Optional[LLMResponse] = None

        logger.debug(f"Analyzing with tools: {finding.rule_id} at {finding.location_str}")

        # Initialize investigation state for context management
        source, sink = extract_source_sink_from_finding(finding, context)
        investigation_state = InvestigationState(
            rule_id=finding.rule_id or "unknown",
            file=Path(finding.file_path).name if finding.file_path else "unknown",
            line=finding.start_line if hasattr(finding, 'start_line') else 0,
            source=source,
            sink=sink,
            vulnerability_type=get_vulnerability_type(finding.rule_id or ""),
        )
        
        # Track recent tool results for checkpoint summaries
        recent_tool_results: list[str] = []

        # Track text-based tool call retries
        text_tool_retries = 0

        # Tool calling loop
        while tool_calls_count < MAX_TOOL_CALLS:
            response = self.llm_client.complete_with_tools(
                messages=messages,
                tools=ANALYSIS_TOOLS,
                temperature=self.temperature,
            )

            # Check if LLM wants to call tools
            if response.has_tool_calls:
                # Add assistant message with tool calls
                tool_calls_raw = [
                    {"id": tc.id, "type": "function", "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)}}
                    for tc in response.tool_calls
                ]
                messages.append(Message(role="assistant", content=response.content, tool_calls=tool_calls_raw))
                conversation_history.append({"role": "assistant", "content": response.content, "tool_calls": tool_calls_raw})

                # Execute ALL tool calls (must respond to each one to avoid API error)
                for tool_call in response.tool_calls:
                    tool_calls_count += 1
                    logger.debug(f"Tool call {tool_calls_count}: {tool_call.name}({tool_call.arguments})")

                    result = self._execute_tool(finding, context, tool_call)
                    
                    # === CONTEXT WINDOW MANAGEMENT ===
                    # 1. Truncate large tool responses to prevent context overflow
                    truncated_result = truncate_tool_response(result)
                    
                    # 2. Update investigation state based on tool result
                    investigation_state.update_from_tool_result(tool_call.name, result)
                    
                    # 3. Generate state reminder block
                    state_reminder = investigation_state.to_reminder_block()
                    
                    # 4. Combine truncated result with state reminder
                    enriched_result = f"{truncated_result}\n{state_reminder}"
                    
                    # Track for checkpoint summaries
                    recent_tool_results.append(truncated_result[:500])
                    
                    # 5. Add checkpoint summary every N tool calls
                    if tool_calls_count % CHECKPOINT_INTERVAL == 0 and tool_calls_count > 0:
                        checkpoint = generate_checkpoint_summary(investigation_state, recent_tool_results)
                        enriched_result += f"\n{checkpoint}"
                        recent_tool_results.clear()  # Reset after checkpoint

                    # Add tool result message with enriched content
                    messages.append(Message(role="tool", content=enriched_result, tool_call_id=tool_call.id, name=tool_call.name))
                    conversation_history.append({"role": "tool", "content": enriched_result, "tool_call_id": tool_call.id})

                # Check limit after processing all tool calls in this batch
                if tool_calls_count >= MAX_TOOL_CALLS:
                    break
            else:
                # Check if LLM tried to call tools via text instead of API
                if _detect_text_tool_call(response.content) and text_tool_retries < MAX_TEXT_TOOL_RETRIES:
                    text_tool_retries += 1
                    logger.debug(f"Detected text-based tool call attempt, retry {text_tool_retries}")

                    # Add a correction message to guide the LLM to use proper function calling
                    messages.append(Message(role="assistant", content=response.content))
                    conversation_history.append({"role": "assistant", "content": response.content})

                    correction_msg = (
                        "I see you want to call a tool, but you wrote the tool call as text. "
                        "Please USE THE FUNCTION CALLING API instead of writing JSON. "
                        "Simply invoke the tool directly - for example, call read_file(file_path='MyClass.java', line_number=45) "
                        "or search_code(pattern='sanitize') using the function calling mechanism. "
                        "Do NOT write JSON - just call the function."
                    )
                    messages.append(Message(role="user", content=correction_msg))
                    conversation_history.append({"role": "user", "content": correction_msg})
                    continue  # Retry with the correction

                # No more tool calls, we have the final answer
                final_response = response
                conversation_history.append({"role": "assistant", "content": response.content})
                break

        # If we hit the limit, ask for final answer with finding reminder
        if final_response is None:
            # Add finding re-anchor to ensure context isn't lost
            reanchor = investigation_state.to_finding_reanchor()
            final_prompt = (
                f"{reanchor}\n\n"
                f"You've reached the maximum number of tool calls ({MAX_TOOL_CALLS}). "
                f"Based on the evidence gathered, please provide your final analysis now as JSON.\n\n"
                f"Key findings: {', '.join(investigation_state.key_findings[-3:]) if investigation_state.key_findings else 'None confirmed'}"
            )
            messages.append(Message(role="user", content=final_prompt))
            final_response = self.llm_client.complete_with_tools(
                messages=messages,
                tools=None,  # No more tools
                temperature=self.temperature,
            )
            conversation_history.append({"role": "assistant", "content": final_response.content})


        result = self._parse_response(finding, final_response)
        result.tool_calls_made = tool_calls_count
        result.conversation_history = conversation_history
        return result

    def _proactively_gather_context(
        self,
        finding: SemgrepFinding,
        context: ExtractedContext,
    ) -> ExtractedContext:
        """
        Proactively gather additional context before the first LLM analysis.

        This pre-fetches likely needed context based on:
        1. The vulnerability type (from rule_id)
        2. Code patterns in the flagged code
        3. Cross-file references

        Args:
            finding: The Semgrep finding to analyze
            context: Initial extracted context

        Returns:
            Enhanced context with proactively gathered information
        """
        code_lookup = self._get_code_lookup()
        if not code_lookup:
            return context

        # Create enhanced context
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

        code = context.function_context.full_code if context.function_context else context.surrounding_context
        rule_lower = finding.rule_id.lower()

        # Initialize proactive context section
        if "proactive_context" not in enhanced.cross_file_context:
            enhanced.cross_file_context["proactive_context"] = []

        try:
            # 1. For SQL injection - look for parameterized query patterns
            if "sql" in rule_lower or "injection" in rule_lower:
                param_results = code_lookup.search_codebase("PreparedStatement|parameterized|setString|setInt", ".java")
                if param_results and "not found" not in param_results.lower():
                    enhanced.cross_file_context["proactive_context"].append({
                        "type": "parameterized_query_patterns",
                        "reason": "Searching for parameterized query usage",
                        "results": param_results[:2000]
                    })

            # 2. For XSS - look for encoding/escaping patterns
            if "xss" in rule_lower or "cross-site" in rule_lower:
                xss_results = code_lookup.search_codebase("htmlEncode|escapeHtml|sanitize|HtmlUtils", ".java")
                if xss_results and "not found" not in xss_results.lower():
                    enhanced.cross_file_context["proactive_context"].append({
                        "type": "xss_protection_patterns",
                        "reason": "Searching for XSS protection methods",
                        "results": xss_results[:2000]
                    })

            # 3. For path traversal - look for path validation
            if "path" in rule_lower or "traversal" in rule_lower:
                path_results = code_lookup.search_codebase("normalize|canonical|validatePath|Paths.get", ".java")
                if path_results and "not found" not in path_results.lower():
                    enhanced.cross_file_context["proactive_context"].append({
                        "type": "path_validation_patterns",
                        "reason": "Searching for path validation methods",
                        "results": path_results[:2000]
                    })

            # 4. Look for validation/sanitization methods called in the flagged code
            import re
            method_calls = re.findall(r'(\w+)\s*\(', code)
            validation_keywords = ['valid', 'sanitiz', 'check', 'verify', 'filter', 'escape', 'encode', 'clean']
            for method in method_calls:
                if any(kw in method.lower() for kw in validation_keywords):
                    method_code = code_lookup.get_function_code(method, None, Path(finding.file_path) if finding.file_path else None)
                    if method_code and "not found" not in method_code.lower():
                        enhanced.cross_file_context["proactive_context"].append({
                            "type": "validation_method",
                            "method": method,
                            "reason": f"Pre-fetched {method} implementation",
                            "code": method_code[:1500]
                        })

            # 5. Get callers if function context available
            if context.function_context and context.function_context.name:
                class_name = context.additional_context.get("class_name", "")
                caller_code = code_lookup.get_caller_function(class_name, context.function_context.name, 0)
                if caller_code and "not found" not in caller_code.lower():
                    enhanced.cross_file_context["proactive_context"].append({
                        "type": "caller",
                        "reason": f"Pre-fetched caller of {context.function_context.name}",
                        "code": caller_code[:2000]
                    })

        except Exception as e:
            logger.debug(f"Proactive context gathering failed: {e}")

        return enhanced

    def analyze_with_iterative_context(
        self,
        finding: SemgrepFinding,
        context: ExtractedContext,
        guided_questions: list[str],
        max_iterations: int = MAX_CONTEXT_ITERATIONS,
        investigation_engine: Optional[InvestigationEngine] = None,
    ) -> AnalysisResult:
        """
        Analyze a finding with iterative context expansion.

        This method implements the "Needs More Info" verdict system:
        1. Proactively gather likely-needed context
        2. Perform initial analysis with enhanced context
        3. If confidence is low, expand context based on LLM requests
        4. Re-analyze with expanded context
        5. Repeat until confidence is high or max iterations reached

        Args:
            finding: The Semgrep finding to analyze
            context: Initial extracted context
            guided_questions: Questions to guide the analysis
            max_iterations: Maximum number of context expansion iterations
            investigation_engine: Optional engine for tracking investigation metrics

        Returns:
            Final AnalysisResult with accumulated context and investigation trace
        """
        # Initialize investigation engine if not provided
        engine = investigation_engine or InvestigationEngine(
            config=InvestigationConfig(
                max_iterations=max_iterations,
                confidence_threshold_high=CONFIDENCE_THRESHOLD_HIGH,
                confidence_threshold_medium=CONFIDENCE_THRESHOLD_MEDIUM,
                confidence_threshold_low=CONFIDENCE_THRESHOLD_LOW,
            )
        )

        # Start investigation trace
        finding_id = f"{finding.rule_id}:{finding.file_path}:{finding.start_line}"
        trace = engine.start_investigation(finding_id, finding.rule_id, finding.file_path or "unknown")

        # Step 0: Pre-analysis with source classification
        pre_analysis_result = None
        if _PRE_ANALYSIS_AVAILABLE and self.project_root:
            try:
                from src.context.pre_analysis_filter import PreAnalysisFilter, PreAnalysisVerdict
                
                pre_filter = PreAnalysisFilter(
                    project_root=self.project_root,
                    call_graph=None,
                )
                
                # Extract variable and function names
                variable_name = self._extract_variable_from_finding(finding)
                function_name = context.function_context.name if context.function_context else None
                code = context.full_class_code or (
                    context.function_context.full_code if context.function_context 
                    else context.surrounding_context
                )
                
                pre_analysis_result = pre_filter.analyze(
                    rule_id=finding.rule_id or "",
                    code=code,
                    file_path=finding.file_path or "",
                    line_number=finding.start_line,
                    variable_name=variable_name,
                    function_name=function_name,
                )
                
                logger.info(
                    f"  📊 Pre-analysis: verdict={pre_analysis_result.verdict.value}, "
                    f"confidence={pre_analysis_result.confidence:.2f}"
                )
                
                # If pre-analysis is high confidence FP, return early
                if (pre_analysis_result.skip_llm and 
                    pre_analysis_result.verdict == PreAnalysisVerdict.LIKELY_FALSE_POSITIVE):
                    logger.info(f"  ✓ Pre-analysis skipped LLM - false positive detected")
                    
                    reasoning = "**Pre-Analysis Detected False Positive**\n\n"
                    reasoning += "\n".join(f"- {r}" for r in pre_analysis_result.reasons)
                    
                    result = AnalysisResult(
                        finding=finding,
                        verdict=Verdict.FALSE_POSITIVE,
                        confidence=pre_analysis_result.confidence,
                        reasoning=reasoning,
                        guided_answers={"pre_analysis": "Static analysis detected false positive"},
                        llm_response=LLMResponse(content="[Skipped - Pre-analysis detected FP]"),
                        tool_calls_made=0,
                        conversation_history=[{"role": "system", "content": "Pre-analysis FP detection"}],
                    )
                    result.pre_analysis = pre_analysis_result.to_dict()
                    return result
                
                # Add pre-analysis context to the context
                if pre_analysis_result.enhanced_context:
                    if "pre_analysis_hints" not in context.cross_file_context:
                        context.cross_file_context["pre_analysis_hints"] = []
                    context.cross_file_context["pre_analysis_hints"].append({
                        "type": "pre_analysis_summary",
                        "verdict": pre_analysis_result.verdict.value,
                        "confidence": pre_analysis_result.confidence,
                        "summary": pre_analysis_result.enhanced_context,
                    })
            except Exception as e:
                logger.debug(f"Pre-analysis failed: {e}")

        # Step 1: Proactively gather additional context
        logger.debug(f"Proactively gathering context for {finding.rule_id}")
        current_context = self._proactively_gather_context(finding, context)

        iteration = 0
        all_context_requests: list[ContextExpansionRequest] = []
        total_tool_calls = 0
        full_conversation_history: list[dict] = []
        previous_confidence = 0.0
        previous_verdict = ""

        while iteration < max_iterations:
            iteration += 1
            step_start = int(time.time() * 1000)
            logger.info(f"  🔄 Iteration {iteration}/{max_iterations} (prev confidence: {previous_confidence:.2f})")

            # Perform analysis with current context
            result = self.analyze_with_tools(finding, current_context, guided_questions)
            total_tool_calls += result.tool_calls_made
            full_conversation_history.extend(result.conversation_history)

            confidence_delta = result.confidence - previous_confidence
            logger.info(f"     Confidence: {result.confidence:.2f} (Δ{confidence_delta:+.2f}), Verdict: {result.verdict.value}")

            # Record investigation step
            step_duration = int(time.time() * 1000) - step_start
            context_gathered = []
            if iteration == 1:
                context_gathered.append("proactive_context")
            if result.context_expansion_requests:
                context_gathered.extend([f"{r.request_type}:{r.target}" for r in result.context_expansion_requests[:3]])

            engine.record_step(
                iteration=iteration,
                action="analysis" if iteration == 1 else "re_analysis",
                context_gathered=context_gathered,
                confidence_before=previous_confidence,
                confidence_after=result.confidence,
                verdict_before=previous_verdict,
                verdict_after=result.verdict.value,
                tool_calls=result.tool_calls_made,
                duration_ms=step_duration,
                confidence_breakdown=result.confidence_breakdown,
            )

            # Check if we should continue using the engine
            should_continue, exit_reason = engine.should_continue(
                iteration, result.verdict.value, result.confidence
            )

            if not should_continue:
                logger.info(f"  ✅ Investigation complete: {exit_reason}")
                result.context_iterations = iteration
                result.tool_calls_made = total_tool_calls
                result.conversation_history = full_conversation_history
                result.final_iteration = True

                # Complete investigation and attach trace
                trace = engine.complete_investigation(
                    verdict=result.verdict.value,
                    confidence=result.confidence,
                    confidence_breakdown=result.confidence_breakdown,
                    early_exit=iteration < max_iterations,
                    early_exit_reason=exit_reason,
                )
                trace.total_context_requests = len(all_context_requests)
                result.investigation_trace = trace
                if pre_analysis_result:
                    result.pre_analysis = pre_analysis_result.to_dict()
                return result

            if not result.context_expansion_requests:
                # LLM didn't provide specific requests - generate some based on the code
                logger.debug(f"No context requests provided, generating automatic requests")
                result.context_expansion_requests = self._generate_automatic_context_requests(
                    finding, current_context
                )

            if not result.context_expansion_requests:
                logger.info(f"  ℹ️  No context expansion possible at iteration {iteration}")
                result.context_iterations = iteration
                result.tool_calls_made = total_tool_calls
                result.conversation_history = full_conversation_history
                result.final_iteration = True

                trace = engine.complete_investigation(
                    verdict=result.verdict.value,
                    confidence=result.confidence,
                    confidence_breakdown=result.confidence_breakdown,
                    early_exit=True,
                    early_exit_reason="no_expansion_possible",
                )
                result.investigation_trace = trace
                if pre_analysis_result:
                    result.pre_analysis = pre_analysis_result.to_dict()
                return result

            # Log what context is being requested
            for req in result.context_expansion_requests[:3]:
                logger.debug(f"     Context request: {req.request_type}({req.target}) - {req.reason}")

            # Expand context based on requests
            all_context_requests.extend(result.context_expansion_requests)
            expanded_context = self._expand_context(
                finding, current_context, result.context_expansion_requests
            )

            if expanded_context is None:
                # No new context could be retrieved
                logger.info(f"  ⚠️  Context expansion failed at iteration {iteration}")
                result.context_iterations = iteration
                result.tool_calls_made = total_tool_calls
                result.conversation_history = full_conversation_history
                result.context_expansion_requests = all_context_requests
                # Upgrade verdict if it's still needs_more_context
                if result.verdict == Verdict.NEEDS_MORE_CONTEXT:
                    result.verdict = Verdict.NEEDS_REVIEW

                trace = engine.complete_investigation(
                    verdict=result.verdict.value,
                    confidence=result.confidence,
                    confidence_breakdown=result.confidence_breakdown,
                    early_exit=True,
                    early_exit_reason="expansion_failed",
                )
                result.investigation_trace = trace
                if pre_analysis_result:
                    result.pre_analysis = pre_analysis_result.to_dict()
                return result

            # Track confidence for next iteration
            previous_confidence = result.confidence
            previous_verdict = result.verdict.value
            current_context = expanded_context

        # Max iterations reached - do final analysis
        logger.info(f"  🔄 Final iteration (max {max_iterations} reached)")
        result = self.analyze_with_tools(finding, current_context, guided_questions)
        result.context_iterations = max_iterations
        result.tool_calls_made = total_tool_calls + result.tool_calls_made
        result.conversation_history = full_conversation_history + result.conversation_history
        result.context_expansion_requests = all_context_requests
        result.final_iteration = True

        # If still low confidence after max iterations, mark as needs_review
        if result.verdict == Verdict.NEEDS_MORE_CONTEXT:
            result.verdict = Verdict.NEEDS_REVIEW
            result.reasoning = f"[After {max_iterations} context iterations] " + result.reasoning

        # Complete investigation trace
        trace = engine.complete_investigation(
            verdict=result.verdict.value,
            confidence=result.confidence,
            confidence_breakdown=result.confidence_breakdown,
            early_exit=False,
            early_exit_reason="max_iterations_reached",
        )
        trace.total_context_requests = len(all_context_requests)
        result.investigation_trace = trace

        logger.info(f"  📊 Final: {result.verdict.value} (confidence: {result.confidence:.2f})")
        if pre_analysis_result:
            result.pre_analysis = pre_analysis_result.to_dict()
        return result

    def _generate_automatic_context_requests(
        self,
        finding: SemgrepFinding,
        context: ExtractedContext,
    ) -> list[ContextExpansionRequest]:
        """
        Generate automatic context expansion requests based on code analysis.

        This is used when the LLM doesn't provide specific requests.
        """
        import re
        requests = []
        code = context.function_context.full_code if context.function_context else context.surrounding_context

        # Look for method calls that might be security-relevant
        method_calls = re.findall(r'\.(\w+)\s*\(', code)
        security_keywords = ['execute', 'query', 'run', 'process', 'write', 'send', 'eval']

        for method in method_calls:
            if any(kw in method.lower() for kw in security_keywords):
                requests.append(ContextExpansionRequest(
                    request_type="method",
                    target=method,
                    reason=f"Security-relevant method {method} needs verification",
                    priority=2
                ))

        # Look for callers if we have a function context
        if context.function_context and context.function_context.name:
            requests.append(ContextExpansionRequest(
                request_type="caller",
                target=context.function_context.name,
                reason="Need to trace data flow from callers",
                priority=1
            ))

        return requests[:3]  # Limit to 3 automatic requests

    def _expand_context(
        self,
        finding: SemgrepFinding,
        current_context: ExtractedContext,
        requests: list[ContextExpansionRequest],
    ) -> Optional[ExtractedContext]:
        """
        Expand context based on LLM requests.

        Args:
            finding: The finding being analyzed
            current_context: Current context to expand
            requests: List of context expansion requests from LLM

        Returns:
            Expanded context or None if no new context could be retrieved
        """
        code_lookup = self._get_code_lookup()
        if not code_lookup:
            return None

        # Create a copy of the context to expand
        expanded = ExtractedContext(
            file_path=current_context.file_path,
            finding_line=current_context.finding_line,
            finding_code=current_context.finding_code,
            function_context=current_context.function_context,
            surrounding_context=current_context.surrounding_context,
            additional_context=dict(current_context.additional_context),
            cross_file_context=dict(current_context.cross_file_context) if current_context.cross_file_context else {},
            full_class_code=current_context.full_class_code,
        )

        new_context_added = False

        # Sort requests by priority
        sorted_requests = sorted(requests, key=lambda r: r.priority, reverse=True)

        for req in sorted_requests[:5]:  # Limit to top 5 requests
            try:
                if req.request_type == "caller":
                    # Get caller function code
                    class_name = current_context.additional_context.get("class_name", "")
                    method_name = current_context.function_context.name if current_context.function_context else ""
                    caller_code = code_lookup.get_caller_function(class_name, method_name, 0)
                    if caller_code and "not found" not in caller_code.lower():
                        if "expanded_callers" not in expanded.cross_file_context:
                            expanded.cross_file_context["expanded_callers"] = []
                        expanded.cross_file_context["expanded_callers"].append({
                            "target": req.target,
                            "reason": req.reason,
                            "code": caller_code[:2000],
                        })
                        new_context_added = True

                elif req.request_type == "callee":
                    # Get called function code
                    callee_code = code_lookup.get_function_code(
                        req.target, None, Path(finding.file_path) if finding.file_path else None
                    )
                    if callee_code and "not found" not in callee_code.lower():
                        if "expanded_callees" not in expanded.cross_file_context:
                            expanded.cross_file_context["expanded_callees"] = []
                        expanded.cross_file_context["expanded_callees"].append({
                            "target": req.target,
                            "reason": req.reason,
                            "code": callee_code[:2000],
                        })
                        new_context_added = True

                elif req.request_type == "class":
                    # Get full class code
                    class_code = code_lookup.get_class_code(req.target)
                    if class_code and "not found" not in class_code.lower():
                        expanded.full_class_code = class_code[:5000]
                        new_context_added = True

                elif req.request_type == "search":
                    # Search codebase for pattern
                    search_results = code_lookup.search_codebase(req.target)
                    if search_results and "not found" not in search_results.lower():
                        if "search_results" not in expanded.cross_file_context:
                            expanded.cross_file_context["search_results"] = []
                        expanded.cross_file_context["search_results"].append({
                            "pattern": req.target,
                            "reason": req.reason,
                            "results": search_results[:3000],
                        })
                        new_context_added = True

                elif req.request_type == "imports":
                    # Get imports from file
                    imports = code_lookup.get_imports(finding.file_path)
                    if imports and "not found" not in imports.lower():
                        expanded.additional_context["expanded_imports"] = imports
                        new_context_added = True

                elif req.request_type == "method":
                    # Get a specific method by name (try to find it anywhere)
                    method_code = code_lookup.get_function_code(
                        req.target, None, Path(finding.file_path) if finding.file_path else None
                    )
                    if method_code and "not found" not in method_code.lower():
                        if "expanded_methods" not in expanded.cross_file_context:
                            expanded.cross_file_context["expanded_methods"] = []
                        expanded.cross_file_context["expanded_methods"].append({
                            "target": req.target,
                            "reason": req.reason,
                            "code": method_code[:2000],
                        })
                        new_context_added = True
                        logger.debug(f"  ✓ Found method: {req.target}")

                elif req.request_type == "file":
                    # Get content from a specific file
                    try:
                        file_path = Path(req.file_hint) if req.file_hint else Path(req.target)
                        if self.project_root:
                            full_path = self.project_root / file_path
                            if full_path.exists():
                                content = full_path.read_text()[:5000]
                                if "expanded_files" not in expanded.cross_file_context:
                                    expanded.cross_file_context["expanded_files"] = []
                                expanded.cross_file_context["expanded_files"].append({
                                    "path": str(file_path),
                                    "reason": req.reason,
                                    "content": content,
                                })
                                new_context_added = True
                                logger.debug(f"  ✓ Read file: {file_path}")
                    except Exception as e:
                        logger.debug(f"  ✗ Failed to read file {req.target}: {e}")

            except Exception as e:
                logger.debug(f"Context expansion request failed: {req.request_type}({req.target}): {e}")
                continue

        return expanded if new_context_added else None

    def _execute_tool(self, finding: SemgrepFinding, context: ExtractedContext, tool_call: ToolCall) -> str:
        """Execute a tool call and return the result."""
        code_lookup = self._get_code_lookup()
        if not code_lookup:
            return "Error: Code lookup not available"

        try:
            args = tool_call.arguments
            class_name = context.additional_context.get("class_name", "")
            method_name = context.function_context.name if context.function_context else ""

            if tool_call.name == "get_function_code":
                return code_lookup.get_function_code(
                    args.get("function_name", ""),
                    args.get("class_name"),
                    Path(finding.file_path) if finding.file_path else None
                )

            elif tool_call.name == "get_caller_function":
                return code_lookup.get_caller_function(
                    class_name,
                    method_name,
                    args.get("caller_index", 0)
                )

            elif tool_call.name == "get_class_code":
                return code_lookup.get_class_code(args.get("class_name", ""))

            elif tool_call.name == "get_method_code":
                return code_lookup.get_method_code(
                    args.get("class_name", ""),
                    args.get("method_name", "")
                )

            elif tool_call.name == "read_file":
                # Core autonomous navigation tool - read file with optional line focus
                return code_lookup.read_file(
                    args.get("file_path", finding.file_path),
                    args.get("line_number"),
                    args.get("context_lines", 50)
                )

            elif tool_call.name == "search_code":
                # Core autonomous navigation tool - search and navigate
                return code_lookup.search_code(
                    args.get("pattern", ""),
                    args.get("file_extension")
                )

            elif tool_call.name == "search_codebase":
                # Backward compatibility alias for search_code
                return code_lookup.search_code(
                    args.get("pattern", ""),
                    args.get("file_extension")
                )

            elif tool_call.name == "get_imports":
                return code_lookup.get_imports(args.get("file_path", finding.file_path))

            elif tool_call.name == "map_arguments":
                # Get caller and callee code, then use LLM to map arguments
                caller_name = args.get("caller_function", "")
                callee_name = args.get("callee_function", "")
                file_path = args.get("file_path", finding.file_path)

                caller_code = code_lookup.get_function_code(caller_name, None, Path(file_path) if file_path else None)
                callee_code = code_lookup.get_function_code(callee_name, None, Path(file_path) if file_path else None)

                if "not found" in caller_code.lower() or "not found" in callee_code.lower():
                    return f"Could not find both functions. Caller: {caller_code[:100]}... Callee: {callee_code[:100]}..."

                return self.map_arguments(caller_code, callee_code)

            elif tool_call.name == "trace_taint_path":
                # Trace data flow from source to sink
                source_var = args.get("source_variable", "")
                sink_type = args.get("sink_type", "")
                file_path = args.get("file_path", finding.file_path)
                start_line = args.get("start_line")
                end_line = args.get("end_line")
                return code_lookup.trace_taint_path(
                    source_var, sink_type, file_path, start_line, end_line
                )

            elif tool_call.name == "get_sanitization_check":
                # Check if variable is sanitized
                var_name = args.get("variable_name", "")
                file_path = args.get("file_path", finding.file_path)
                # Use finding's line range if not provided
                start_line = args.get("start_line", finding.start_line if hasattr(finding, 'start_line') else 1)
                end_line = args.get("end_line", finding.end_line if hasattr(finding, 'end_line') else start_line + 50)
                return code_lookup.get_sanitization_check(
                    var_name, file_path, start_line, end_line
                )

            elif tool_call.name == "get_caller_chain":
                # Get full caller chain to entry points
                func_name = args.get("function_name", method_name)
                max_depth = args.get("max_depth", 5)
                return code_lookup.get_caller_chain(
                    func_name, class_name, max_depth
                )

            elif tool_call.name == "analyze_data_flow":
                # Perform inter-procedural data flow analysis
                source_var = args.get("source_variable", "")
                file_path = args.get("file_path", finding.file_path)
                func_name = args.get("function_name", method_name)
                include_callers = args.get("include_callers", True)
                return code_lookup.analyze_data_flow(
                    source_var, file_path, func_name, include_callers
                )

            else:
                return f"Unknown tool: {tool_call.name}"

        except Exception as e:
            logger.warning(f"Tool execution error: {e}")
            return f"Error executing tool: {str(e)}"

    def _extract_guided_answers_from_text(self, content: str) -> dict[str, str]:
        """Extract guided answers from structured text response.

        Parses patterns like:
        1. **Question text?**
           - Answer text

        Or:
        1. Question text?
           Answer text
        """
        import re
        guided_answers = {}

        # Pattern 1: Numbered questions with bold markdown
        # e.g., "1. **Is the SQL query...?**\n   - Yes, the SQL query is..."
        bold_pattern = r'\d+\.\s*\*\*([^*]+\??)\*\*\s*[-\n]\s*(.+?)(?=\n\d+\.\s*\*\*|\n###|\n\*\*|\Z)'
        matches = re.findall(bold_pattern, content, re.DOTALL)

        for i, (question, answer) in enumerate(matches):
            q = question.strip().rstrip('?') + '?'
            a = answer.strip().lstrip('-').strip()
            # Clean up the answer (take first paragraph only)
            a = a.split('\n\n')[0].strip()
            a = re.sub(r'\s+', ' ', a)  # Normalize whitespace
            guided_answers[f"Q{i+1}: {q[:80]}"] = a[:500]  # Limit lengths

        # Pattern 2: Simple numbered questions without bold
        # e.g., "1. Is the SQL query...?\n   Yes, ..."
        if not matches:
            simple_pattern = r'\d+\.\s*([^*\n]+\??)\s*\n\s*(.+?)(?=\n\d+\.|\n###|\Z)'
            matches = re.findall(simple_pattern, content, re.DOTALL)
            for i, (question, answer) in enumerate(matches):
                q = question.strip()
                if '?' in q:  # Only capture if it looks like a question
                    q = q.rstrip('?') + '?'
                    a = answer.strip()
                    a = a.split('\n\n')[0].strip()
                    a = re.sub(r'\s+', ' ', a)
                    guided_answers[f"Q{i+1}: {q[:80]}"] = a[:500]

        return guided_answers

    def _parse_response(self, finding: SemgrepFinding, response: LLMResponse) -> AnalysisResult:
        """Parse LLM response into structured result."""
        content = response.content.strip()
        verdict = Verdict.NEEDS_REVIEW
        confidence = 0.5
        reasoning = ""
        guided_answers = {}
        context_requests: list[ContextExpansionRequest] = []
        confidence_breakdown: Optional[ConfidenceBreakdown] = None

        # Try to parse status codes first (VulnHalla style)
        if "1337" in content:
            verdict = Verdict.TRUE_POSITIVE
            confidence = 0.9
        elif "1007" in content:
            verdict = Verdict.FALSE_POSITIVE
            confidence = 0.9
        elif "7331" in content:
            verdict = Verdict.NEEDS_MORE_CONTEXT
            confidence = 0.3

        # Try to extract guided answers from text (before JSON parsing)
        guided_answers = self._extract_guided_answers_from_text(content)

        # Try to parse JSON
        try:
            # Extract JSON from response (handle markdown code blocks)
            json_content = content
            if "```json" in content:
                json_content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                parts = content.split("```")
                if len(parts) >= 2:
                    json_content = parts[1]
                    if json_content.startswith("json"):
                        json_content = json_content[4:]

            data = json.loads(json_content.strip())

            # Override status code verdict if JSON has explicit verdict
            json_verdict = data.get("verdict", "")
            if json_verdict:
                # Handle both old and new verdict names
                if json_verdict == "insufficient_context":
                    verdict = Verdict.NEEDS_MORE_CONTEXT
                else:
                    verdict = Verdict(json_verdict)
            confidence = float(data.get("confidence", confidence))
            reasoning = data.get("reasoning", "")

            # Use JSON guided_answers if provided, otherwise keep text-extracted ones
            json_guided_answers = data.get("guided_answers", {})
            if json_guided_answers:
                guided_answers = json_guided_answers

            # Parse structured confidence breakdown if provided
            json_confidence_breakdown = data.get("confidence_breakdown", {})
            if json_confidence_breakdown:
                confidence_breakdown = ConfidenceBreakdown(
                    context_completeness=float(json_confidence_breakdown.get("context_completeness", 0.5)),
                    data_flow_visibility=float(json_confidence_breakdown.get("data_flow_visibility", 0.5)),
                    sanitization_evidence=float(json_confidence_breakdown.get("sanitization_evidence", 0.5)),
                    pattern_match_strength=float(json_confidence_breakdown.get("pattern_match_strength", 0.5)),
                    caller_context=float(json_confidence_breakdown.get("caller_context", 0.5)),
                    cross_file_resolution=float(json_confidence_breakdown.get("cross_file_resolution", 0.5)),
                )
                # If LLM provided breakdown, use its calculated score unless explicit confidence given
                if "confidence" not in data:
                    confidence = confidence_breakdown.overall_score

            # Parse context expansion requests
            json_context_requests = data.get("context_requests", [])
            for req in json_context_requests:
                if isinstance(req, dict):
                    context_requests.append(ContextExpansionRequest(
                        request_type=req.get("type", "search"),
                        target=req.get("target", ""),
                        reason=req.get("reason", ""),
                        priority=req.get("priority", 1),
                    ))

        except (json.JSONDecodeError, ValueError, KeyError) as e:
            logger.debug(f"JSON parsing failed, using status codes: {e}")
            # Keep the status code verdict if JSON failed
            if reasoning == "":
                reasoning = content[:1000] if content else "No response content"

        # Determine if this result needs more context based on confidence
        final_iteration = True
        if confidence < CONFIDENCE_THRESHOLD_LOW and verdict not in [Verdict.TRUE_POSITIVE, Verdict.FALSE_POSITIVE]:
            # Low confidence and uncertain verdict - mark as needing more context
            if verdict == Verdict.NEEDS_REVIEW:
                verdict = Verdict.NEEDS_MORE_CONTEXT
            final_iteration = False

        return AnalysisResult(
            finding=finding,
            verdict=verdict,
            confidence=confidence,
            reasoning=reasoning,
            guided_answers=guided_answers,
            llm_response=response,
            context_expansion_requests=context_requests,
            final_iteration=final_iteration,
            confidence_breakdown=confidence_breakdown,
        )

