"""
Context Window Management for LLM Analysis.

This module provides utilities to manage the LLM's context window during
multi-turn tool-calling conversations. Key features:

1. InvestigationState: Tracks source/sink/sanitization status
2. State reminder blocks injected after each tool call
3. Tool response truncation to prevent context bloat
4. Checkpoint summaries every N tool calls

Rationale:
- LLMs suffer from "lost in the middle" - content in the middle gets less attention
- Large tool responses (e.g., 2000-line classes) can overflow context
- Periodic reminders of the investigation goal prevent "forgetting"
"""

from dataclasses import dataclass, field
from typing import Optional, List
import re
import logging

logger = logging.getLogger(__name__)

# Configuration constants
MAX_TOOL_RESPONSE_TOKENS = 800  # ~3200 chars, roughly 1 page of code
CHECKPOINT_INTERVAL = 3  # Summarize every N tool calls
STATE_REMINDER_MAX_CHARS = 500  # Keep state block compact


@dataclass
class InvestigationState:
    """
    Tracks the current state of vulnerability investigation.
    
    This state is used to generate reminder blocks that keep the LLM
    focused on the original finding after processing tool results.
    """
    # Static context (set once at start)
    rule_id: str
    file: str
    line: int
    source: str  # e.g., "request.getParameter('id')"
    sink: str    # e.g., "stmt.executeQuery(query)"
    vulnerability_type: str  # e.g., "SQL Injection", "XSS"
    
    # Dynamic state (updated during investigation)
    sanitization_found: bool = False
    sanitization_method: Optional[str] = None
    sanitization_location: Optional[str] = None
    callers_checked: List[str] = field(default_factory=list)
    key_findings: List[str] = field(default_factory=list)
    confidence: float = 0.5
    current_hypothesis: str = "Investigating data flow..."
    tools_called: int = 0
    
    def update_from_tool_result(self, tool_name: str, result: str):
        """Update state based on tool result."""
        self.tools_called += 1
        
        # Detect sanitization in result
        sanitization_patterns = [
            (r'sanitize\w*', 'sanitize'),
            (r'escape\w*', 'escape'),
            (r'encode\w*', 'encode'),
            (r'PreparedStatement', 'PreparedStatement'),
            (r'setString\s*\(', 'parameterized binding'),
            (r'htmlEscape', 'HTML encoding'),
            (r'ESAPI', 'ESAPI encoding'),
            (r'StringEscapeUtils', 'Apache Commons escape'),
        ]
        
        for pattern, name in sanitization_patterns:
            if re.search(pattern, result, re.IGNORECASE):
                self.sanitization_found = True
                self.sanitization_method = name
                self.confidence = min(self.confidence + 0.15, 0.95)
                self.key_findings.append(f"Found {name} sanitization")
                break
        
        # Track callers
        if tool_name == "get_caller_function" or tool_name == "get_caller_chain":
            # Extract caller names from result
            caller_match = re.search(r'(\w+)\.(\w+)\(\)', result)
            if caller_match:
                caller_name = f"{caller_match.group(1)}.{caller_match.group(2)}"
                if caller_name not in self.callers_checked:
                    self.callers_checked.append(caller_name)
        
        # Update confidence based on tool type
        if tool_name == "analyze_data_flow":
            if "SAFE" in result.upper() or "sanitized" in result.lower():
                self.confidence = min(self.confidence + 0.2, 0.95)
                self.current_hypothesis = "Data flow appears safe"
            elif "vulnerability" in result.lower() or "NOT FOUND" in result.upper():
                self.confidence = min(self.confidence + 0.15, 0.9)
                self.current_hypothesis = "Potential vulnerability detected"
    
    def to_reminder_block(self) -> str:
        """Generate a compact state reminder to inject after tool results."""
        sanitization_status = (
            f"✅ FOUND: {self.sanitization_method}" 
            if self.sanitization_found 
            else "❌ NOT FOUND"
        )
        
        callers_str = ", ".join(self.callers_checked[-2:]) if self.callers_checked else "None"
        
        return f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 INVESTIGATION STATE (Tool #{self.tools_called})
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📍 Location: {self.file}:{self.line}
🔍 Type: {self.vulnerability_type}
📥 Source: {self.source[:50]}{'...' if len(self.source) > 50 else ''}
📤 Sink: {self.sink[:50]}{'...' if len(self.sink) > 50 else ''}
🧹 Sanitization: {sanitization_status}
📞 Callers Checked: {callers_str}
📊 Confidence: {self.confidence*100:.0f}%
💭 Status: {self.current_hypothesis}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

    def to_finding_reanchor(self) -> str:
        """Generate a compact finding reminder for end of context."""
        return (
            f"🔔 REMINDER: You are analyzing {self.vulnerability_type} "
            f"at {self.file}:{self.line}. "
            f"Source: `{self.source[:40]}`, Sink: `{self.sink[:40]}`. "
            f"Sanitization: {'FOUND' if self.sanitization_found else 'NOT FOUND YET'}."
        )


def truncate_tool_response(response: str, max_chars: int = MAX_TOOL_RESPONSE_TOKENS * 4) -> str:
    """
    Truncate tool response to prevent context overflow.
    
    Strategy:
    - Keep first 60% and last 20% of content (most important parts)
    - Add truncation notice in the middle
    """
    if len(response) <= max_chars:
        return response
    
    # Calculate split points
    first_portion = int(max_chars * 0.6)
    last_portion = int(max_chars * 0.2)
    
    truncated_lines = response.count('\n') - response[:first_portion].count('\n') - response[-last_portion:].count('\n')
    
    truncated = (
        response[:first_portion] +
        f"\n\n... [TRUNCATED: ~{truncated_lines} lines omitted to save context] ...\n\n" +
        response[-last_portion:]
    )
    
    return truncated


def generate_checkpoint_summary(
    state: InvestigationState,
    recent_tool_results: List[str]
) -> str:
    """
    Generate a checkpoint summary after every N tool calls.
    
    This consolidates learnings and reduces the need to re-read
    all previous tool results.
    """
    findings_str = "\n".join(f"  • {f}" for f in state.key_findings[-5:]) if state.key_findings else "  • None yet"
    
    return f"""
┌────────────────────────────────────────────────────────────┐
│ 📋 CHECKPOINT SUMMARY (After {state.tools_called} tool calls)           │
├────────────────────────────────────────────────────────────┤
│ Investigation: {state.vulnerability_type} in {state.file}
│ 
│ Key Findings So Far:
{findings_str}
│ 
│ Current Confidence: {state.confidence*100:.0f}%
│ Hypothesis: {state.current_hypothesis}
│ 
│ Next Step: Continue investigating or provide verdict.
└────────────────────────────────────────────────────────────┘
"""


def extract_source_sink_from_finding(finding, context) -> tuple[str, str]:
    """
    Extract source and sink from finding context.
    
    Returns:
        (source, sink) tuple
    """
    code = finding.code_snippet or ""
    rule_id = finding.rule_id or ""
    
    # Common source patterns
    source_patterns = [
        (r"request\.getParameter\(['\"](\w+)['\"]\)", lambda m: f"request.getParameter('{m.group(1)}')"),
        (r"@RequestParam[^)]*\)\s*\w+\s+(\w+)", lambda m: f"@RequestParam {m.group(1)}"),
        (r"req\.getParameter\(['\"](\w+)['\"]\)", lambda m: f"req.getParameter('{m.group(1)}')"),
        (r"input\.get\w*\(\)", lambda m: m.group(0)),
        (r"request\.body\.(\w+)", lambda m: f"request.body.{m.group(1)}"),
    ]
    
    # Common sink patterns based on rule
    sink_patterns = {
        "sql": [r"executeQuery\(", r"execute\(", r"createStatement\(\)", r"prepareStatement\("],
        "xss": [r"response\.getWriter\(\)", r"out\.print", r"innerHTML", r"document\.write"],
        "command": [r"Runtime\.exec\(", r"ProcessBuilder", r"subprocess\."],
        "crypto": [r"getInstance\(", r"Cipher\.", r"MessageDigest\."],
    }
    
    # Find source
    source = "user input"
    for pattern, extractor in source_patterns:
        match = re.search(pattern, code)
        if match:
            source = extractor(match)
            break
    
    # Find sink based on rule type
    sink = "dangerous function"
    for category, patterns in sink_patterns.items():
        if category in rule_id.lower():
            for pattern in patterns:
                match = re.search(pattern, code)
                if match:
                    sink = match.group(0)
                    break
            break
    
    return source, sink


def get_vulnerability_type(rule_id: str) -> str:
    """Map rule ID to human-readable vulnerability type."""
    rule_lower = rule_id.lower()
    
    if "sql" in rule_lower or "formatted-sql" in rule_lower:
        return "SQL Injection"
    elif "xss" in rule_lower or "response-writer" in rule_lower:
        return "Cross-Site Scripting (XSS)"
    elif "command" in rule_lower or "exec" in rule_lower:
        return "Command Injection"
    elif "crypto" in rule_lower or "md5" in rule_lower or "sha1" in rule_lower:
        return "Weak Cryptography"
    elif "cbc" in rule_lower or "padding" in rule_lower:
        return "Padding Oracle"
    elif "ssrf" in rule_lower:
        return "Server-Side Request Forgery"
    elif "path" in rule_lower or "traversal" in rule_lower:
        return "Path Traversal"
    else:
        return "Security Vulnerability"
