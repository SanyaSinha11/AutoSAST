"""
Taint Analyzer - Inter-procedural data flow analysis.

This module provides true data flow tracking across function boundaries,
enabling accurate detection of whether user input reaches sinks after
being sanitized or transformed.

Key Features:
1. Track variable assignments and transformations
2. Propagate taint through function calls
3. Detect sanitization along the data flow path
4. Support for multiple programming languages
"""

import re
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from enum import Enum

logger = logging.getLogger(__name__)


class TaintLevel(Enum):
    """Level of taint for a variable."""
    UNTAINTED = "untainted"      # Safe value (literal, constant)
    TAINTED = "tainted"          # User-controlled/external input
    SANITIZED = "sanitized"      # Was tainted but has been sanitized
    UNKNOWN = "unknown"          # Cannot determine


class TaintSource(Enum):
    """Source of tainted data."""
    HTTP_PARAM = "http_param"          # request.getParameter, req.query
    HTTP_HEADER = "http_header"        # request.getHeader
    HTTP_BODY = "http_body"            # request body
    FILE_READ = "file_read"            # file input
    DATABASE = "database"              # database query result
    ENVIRONMENT = "environment"        # environment variable
    USER_INPUT = "user_input"          # stdin, prompts
    EXTERNAL_API = "external_api"      # external API response
    UNKNOWN = "unknown"


@dataclass
class TaintVariable:
    """Represents a tainted variable with its flow history."""
    name: str
    taint_level: TaintLevel
    source: TaintSource
    defined_at: tuple[str, int]  # (file_path, line_number)
    transformations: list[str] = field(default_factory=list)
    sanitization_applied: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)  # Other variable names this was assigned to
    
    def __post_init__(self):
        if self.transformations is None:
            self.transformations = []
        if self.sanitization_applied is None:
            self.sanitization_applied = []
        if self.aliases is None:
            self.aliases = []
    
    def apply_sanitization(self, method: str, line: int):
        """Record that sanitization was applied."""
        self.sanitization_applied.append(f"{method}@L{line}")
        self.taint_level = TaintLevel.SANITIZED
    
    def apply_transformation(self, transform: str, line: int):
        """Record a transformation (may or may not be sanitization)."""
        self.transformations.append(f"{transform}@L{line}")
    
    def add_alias(self, alias_name: str):
        """Record that this variable was assigned to another name."""
        if alias_name not in self.aliases and alias_name != self.name:
            self.aliases.append(alias_name)
    
    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "taint_level": self.taint_level.value,
            "source": self.source.value,
            "defined_at": f"{self.defined_at[0]}:{self.defined_at[1]}",
            "transformations": self.transformations,
            "sanitization_applied": self.sanitization_applied,
            "aliases": self.aliases,
        }


@dataclass
class TaintFlowStep:
    """A single step in the taint flow."""
    file_path: str
    line_number: int
    description: str
    variable_name: str
    taint_level: TaintLevel
    is_sanitization: bool = False
    is_sink: bool = False
    code_snippet: str = ""


@dataclass
class TaintPath:
    """Complete path from source to sink."""
    source_variable: TaintVariable
    sink_location: tuple[str, int, str]  # (file, line, function_name)
    steps: list[TaintFlowStep] = field(default_factory=list)
    is_sanitized: bool = False
    sanitization_points: list[str] = field(default_factory=list)
    
    def add_step(self, step: TaintFlowStep):
        self.steps.append(step)
        if step.is_sanitization:
            self.is_sanitized = True
            self.sanitization_points.append(f"{step.file_path}:{step.line_number}")
    
    def to_dict(self) -> dict:
        return {
            "source": self.source_variable.to_dict(),
            "sink": f"{self.sink_location[0]}:{self.sink_location[1]} in {self.sink_location[2]}",
            "is_sanitized": self.is_sanitized,
            "sanitization_points": self.sanitization_points,
            "steps": [
                {
                    "file": s.file_path,
                    "line": s.line_number,
                    "description": s.description,
                    "variable": s.variable_name,
                    "taint": s.taint_level.value,
                    "is_sanitization": s.is_sanitization,
                    "is_sink": s.is_sink,
                }
                for s in self.steps
            ],
        }
    
    def format_for_llm(self) -> str:
        """Format the path for LLM consumption."""
        lines = ["## Data Flow Analysis Results\n"]
        
        # Source info
        lines.append(f"**Source:** `{self.source_variable.name}` ({self.source_variable.source.value})")
        lines.append(f"**Defined at:** {self.source_variable.defined_at[0]}:{self.source_variable.defined_at[1]}")
        lines.append(f"**Final Status:** {'SANITIZED ✓' if self.is_sanitized else 'TAINTED ✗'}")
        lines.append("")
        
        # Flow path
        lines.append("### Data Flow Path:")
        for i, step in enumerate(self.steps, 1):
            marker = "🔒" if step.is_sanitization else ("🎯" if step.is_sink else "→")
            lines.append(f"{i}. {marker} **{step.file_path}:{step.line_number}**")
            lines.append(f"   `{step.variable_name}` - {step.description}")
            if step.code_snippet:
                lines.append(f"   ```")
                lines.append(f"   {step.code_snippet.strip()}")
                lines.append(f"   ```")
        
        # Sanitization summary
        if self.sanitization_points:
            lines.append("")
            lines.append("### Sanitization Points:")
            for point in self.sanitization_points:
                lines.append(f"- ✓ {point}")
        
        return "\n".join(lines)


class TaintAnalyzer:
    """
    Analyzes data flow to track taint propagation across functions.
    
    Uses pattern matching and AST analysis to:
    1. Identify taint sources (user input, external data)
    2. Track variable assignments and transformations
    3. Detect sanitization methods
    4. Trace flow to sinks (SQL execution, file operations, etc.)
    """
    
    # Patterns that introduce taint (source patterns)
    TAINT_SOURCES = {
        # Java
        r"request\.getParameter\s*\(": (TaintSource.HTTP_PARAM, "HTTP request parameter"),
        r"request\.getHeader\s*\(": (TaintSource.HTTP_HEADER, "HTTP request header"),
        r"request\.getQueryString\s*\(": (TaintSource.HTTP_PARAM, "HTTP query string"),
        r"request\.getInputStream\s*\(": (TaintSource.HTTP_BODY, "HTTP request body"),
        r"request\.getReader\s*\(": (TaintSource.HTTP_BODY, "HTTP request body"),
        r"@RequestParam": (TaintSource.HTTP_PARAM, "Spring request parameter"),
        r"@PathVariable": (TaintSource.HTTP_PARAM, "Spring path variable"),
        r"@RequestBody": (TaintSource.HTTP_BODY, "Spring request body"),
        # Python
        r"request\.args\.get\s*\(": (TaintSource.HTTP_PARAM, "Flask request arg"),
        r"request\.form\.get\s*\(": (TaintSource.HTTP_PARAM, "Flask form data"),
        r"request\.json": (TaintSource.HTTP_BODY, "Flask JSON body"),
        r"request\.GET\.get\s*\(": (TaintSource.HTTP_PARAM, "Django GET param"),
        r"request\.POST\.get\s*\(": (TaintSource.HTTP_PARAM, "Django POST param"),
        # JavaScript
        r"req\.query\[": (TaintSource.HTTP_PARAM, "Express query param"),
        r"req\.query\.": (TaintSource.HTTP_PARAM, "Express query param"),
        r"req\.body\.": (TaintSource.HTTP_BODY, "Express body"),
        r"req\.params\.": (TaintSource.HTTP_PARAM, "Express route param"),
        # Generic
        r"System\.getenv\s*\(": (TaintSource.ENVIRONMENT, "Environment variable"),
        r"os\.environ": (TaintSource.ENVIRONMENT, "Environment variable"),
        r"process\.env\.": (TaintSource.ENVIRONMENT, "Environment variable"),
    }
    
    # Patterns that sanitize tainted data
    SANITIZATION_PATTERNS = {
        # SQL
        r"PreparedStatement": "SQL parameterized query",
        r"\.setString\s*\(": "Parameterized binding",
        r"\.setInt\s*\(": "Type-safe binding",
        # XSS
        r"escapeHtml": "HTML escaping",
        r"htmlEscape": "HTML escaping",
        r"encodeForHTML": "HTML encoding",
        r"StringEscapeUtils\.escape": "Apache Commons escaping",
        r"DOMPurify\.sanitize": "DOMPurify sanitization",
        r"bleach\.clean": "Bleach HTML sanitizer",
        # Path
        r"\.getCanonicalPath\s*\(": "Path canonicalization",
        r"Paths\.get\([^)]+\)\.normalize": "Path normalization",
        # Command
        r"ProcessBuilder": "ProcessBuilder (safe array args)",
        r"shlex\.quote": "Shell escaping",
        # Generic
        r"sanitize\w*\s*\(": "Sanitization function",
        r"escape\w*\s*\(": "Escape function",
        r"validate\w*\s*\(": "Validation function",
        r"clean\w*\s*\(": "Cleaning function",
        r"Integer\.parseInt": "Type conversion",
        r"Long\.parseLong": "Type conversion",
        r"UUID\.fromString": "UUID parsing",
    }
    
    # Patterns that are sinks (dangerous operations)
    SINK_PATTERNS = {
        # SQL
        r"executeQuery\s*\(": "SQL query execution",
        r"execute\s*\(": "SQL/command execution",
        r"executeUpdate\s*\(": "SQL update execution",
        r"createStatement\s*\(\s*\)\.execute": "Statement execution",
        r"cursor\.execute\s*\(": "Python SQL execution",
        # Command
        r"Runtime\.getRuntime\s*\(\s*\)\.exec": "Command execution",
        r"ProcessBuilder.*\.start": "Process execution",
        r"subprocess\.": "Python subprocess",
        r"os\.system\s*\(": "OS command",
        r"eval\s*\(": "Code evaluation",
        r"exec\s*\(": "Code execution",
        # XSS
        r"\.write\s*\(": "Response write",
        r"innerHTML": "DOM innerHTML",
        r"document\.write": "Document write",
        r"\.html\s*\(": "jQuery HTML",
        # File
        r"FileWriter\s*\(": "File write",
        r"FileOutputStream\s*\(": "File output stream",
        r"open\s*\([^)]+,\s*['\"]w": "Python file write",
    }

    def __init__(self, project_root: Path):
        """
        Initialize the taint analyzer.
        
        Args:
            project_root: Root directory of the project
        """
        self.project_root = project_root
        self._file_cache: dict[str, str] = {}
        self._variable_map: dict[str, TaintVariable] = {}
    
    def _read_file(self, file_path: Path) -> str:
        """Read and cache file contents."""
        key = str(file_path)
        if key not in self._file_cache:
            try:
                self._file_cache[key] = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                logger.warning(f"Failed to read {file_path}: {e}")
                self._file_cache[key] = ""
        return self._file_cache[key]
    
    def _get_line(self, content: str, line_number: int) -> str:
        """Get a specific line from content."""
        lines = content.split("\n")
        if 0 < line_number <= len(lines):
            return lines[line_number - 1]
        return ""
    
    def _get_lines(self, content: str, start: int, end: int) -> list[str]:
        """Get a range of lines from content."""
        lines = content.split("\n")
        return lines[max(0, start - 1):min(len(lines), end)]
    
    def find_taint_sources(self, code: str, file_path: str = "") -> list[TaintVariable]:
        """
        Find all taint sources in the given code.
        
        Returns a list of TaintVariables representing tainted inputs.
        """
        sources = []
        lines = code.split("\n")
        
        for line_num, line in enumerate(lines, 1):
            for pattern, (source_type, description) in self.TAINT_SOURCES.items():
                if re.search(pattern, line, re.IGNORECASE):
                    # Extract variable name from assignment
                    var_name = self._extract_assigned_variable(line)
                    if var_name:
                        taint_var = TaintVariable(
                            name=var_name,
                            taint_level=TaintLevel.TAINTED,
                            source=source_type,
                            defined_at=(file_path, line_num),
                        )
                        taint_var.apply_transformation(description, line_num)
                        sources.append(taint_var)
        
        return sources
    
    def _extract_assigned_variable(self, line: str) -> Optional[str]:
        """Extract the variable name being assigned in a line."""
        # Match patterns like: Type varName = or var varName = or varName =
        patterns = [
            r"^\s*(?:final\s+)?(?:\w+(?:<[^>]+>)?(?:\[\])?)\s+(\w+)\s*=",  # Java: Type var =
            r"^\s*(?:var|let|const)\s+(\w+)\s*=",  # JS: var/let/const name =
            r"^\s*(\w+)\s*=",  # Python/simple: name =
            r"^\s*String\s+(\w+)\s*=",  # Java String
            r"^\s*(\w+)\s*:\s*\w+\s*=",  # Python type hint: name: Type =
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        
        return None
    
    def track_variable_assignments(self, code: str, taint_var: TaintVariable, 
                                   file_path: str = "") -> list[str]:
        """
        Track how a tainted variable is assigned to other variables.
        
        Returns list of all variable names that inherit the taint.
        """
        lines = code.split("\n")
        tainted_vars = {taint_var.name}
        
        for line_num, line in enumerate(lines, 1):
            # Check if any tainted variable is used on RHS of assignment
            for known_tainted in list(tainted_vars):
                if re.search(rf'\b{re.escape(known_tainted)}\b', line):
                    # Check if it's an assignment
                    assigned_var = self._extract_assigned_variable(line)
                    if assigned_var and assigned_var != known_tainted:
                        tainted_vars.add(assigned_var)
                        taint_var.add_alias(assigned_var)
                        taint_var.apply_transformation(f"assigned to {assigned_var}", line_num)
        
        return list(tainted_vars)
    
    def check_sanitization(self, code: str, variable_name: str, 
                          start_line: int = 1, end_line: Optional[int] = None) -> list[tuple[int, str]]:
        """
        Check if a variable is sanitized in the given code range.
        
        Returns list of (line_number, sanitization_method) tuples.
        """
        sanitizations = []
        lines = code.split("\n")
        
        if end_line is None:
            end_line = len(lines)
        
        var_pattern = re.escape(variable_name)
        
        for line_num in range(start_line, min(end_line + 1, len(lines) + 1)):
            line = lines[line_num - 1] if line_num <= len(lines) else ""
            
            # Check if variable is used on this line
            if not re.search(rf'\b{var_pattern}\b', line):
                continue
            
            # Check for sanitization patterns
            for pattern, description in self.SANITIZATION_PATTERNS.items():
                if re.search(pattern, line, re.IGNORECASE):
                    sanitizations.append((line_num, description))
        
        return sanitizations
    
    def check_sinks(self, code: str, variable_name: str) -> list[tuple[int, str]]:
        """
        Check if a variable reaches a sink (dangerous operation).
        
        Returns list of (line_number, sink_type) tuples.
        """
        sinks = []
        lines = code.split("\n")
        var_pattern = re.escape(variable_name)
        
        for line_num, line in enumerate(lines, 1):
            # Check if variable is used on this line
            if not re.search(rf'\b{var_pattern}\b', line):
                continue
            
            # Check for sink patterns
            for pattern, description in self.SINK_PATTERNS.items():
                if re.search(pattern, line, re.IGNORECASE):
                    sinks.append((line_num, description))
        
        return sinks
    
    def trace_taint_path(self, source_var: str, code: str, file_path: str,
                         start_line: int = 1, end_line: Optional[int] = None) -> TaintPath:
        """
        Trace the complete taint path from source to sink.
        
        This is the main analysis method that:
        1. Identifies the taint source
        2. Tracks assignments and transformations
        3. Detects sanitization points
        4. Identifies sinks
        """
        lines = code.split("\n")
        if end_line is None:
            end_line = len(lines)
        
        # Find the source
        source_line = start_line
        source_type = TaintSource.UNKNOWN
        
        for pattern, (src_type, desc) in self.TAINT_SOURCES.items():
            for i in range(start_line - 1, min(end_line, len(lines))):
                if re.search(pattern, lines[i], re.IGNORECASE):
                    source_line = i + 1
                    source_type = src_type
                    break
        
        taint_var = TaintVariable(
            name=source_var,
            taint_level=TaintLevel.TAINTED,
            source=source_type,
            defined_at=(file_path, source_line),
        )
        
        # Find sink
        sinks = self.check_sinks(code, source_var)
        sink_line = sinks[0][0] if sinks else end_line
        sink_desc = sinks[0][1] if sinks else "Unknown sink"
        
        taint_path = TaintPath(
            source_variable=taint_var,
            sink_location=(file_path, sink_line, sink_desc),
        )
        
        # Add source step
        taint_path.add_step(TaintFlowStep(
            file_path=file_path,
            line_number=source_line,
            description=f"Taint source: {source_type.value}",
            variable_name=source_var,
            taint_level=TaintLevel.TAINTED,
            code_snippet=self._get_line(code, source_line),
        ))
        
        # Track assignments
        tainted_vars = self.track_variable_assignments(
            "\n".join(lines[source_line - 1:sink_line]),
            taint_var,
            file_path,
        )
        
        # Add assignment steps
        for alias in taint_var.aliases:
            for i in range(source_line, sink_line + 1):
                if i <= len(lines) and re.search(rf'\b{alias}\b\s*=', lines[i - 1]):
                    taint_path.add_step(TaintFlowStep(
                        file_path=file_path,
                        line_number=i,
                        description=f"Assigned to variable: {alias}",
                        variable_name=alias,
                        taint_level=TaintLevel.TAINTED,
                        code_snippet=lines[i - 1].strip(),
                    ))
                    break
        
        # Check sanitization
        all_vars = [source_var] + list(taint_var.aliases)
        for var in all_vars:
            sanitizations = self.check_sanitization(code, var, source_line, sink_line)
            for san_line, san_desc in sanitizations:
                taint_var.apply_sanitization(san_desc, san_line)
                taint_path.add_step(TaintFlowStep(
                    file_path=file_path,
                    line_number=san_line,
                    description=f"Sanitization: {san_desc}",
                    variable_name=var,
                    taint_level=TaintLevel.SANITIZED,
                    is_sanitization=True,
                    code_snippet=self._get_line(code, san_line),
                ))
        
        # Add sink step
        if sinks:
            taint_path.add_step(TaintFlowStep(
                file_path=file_path,
                line_number=sink_line,
                description=f"Sink: {sink_desc}",
                variable_name=all_vars[-1] if tainted_vars else source_var,
                taint_level=taint_var.taint_level,
                is_sink=True,
                code_snippet=self._get_line(code, sink_line),
            ))
        
        return taint_path
    
    def analyze_cross_function_taint(self, caller_code: str, callee_code: str,
                                     caller_file: str, callee_file: str,
                                     function_call_line: int,
                                     argument_mapping: dict[str, str]) -> TaintPath:
        """
        Analyze taint propagation across function calls.
        
        Args:
            caller_code: Code of the calling function
            callee_code: Code of the called function
            caller_file: File path of caller
            callee_file: File path of callee
            function_call_line: Line number of the function call
            argument_mapping: Maps caller variable names to callee parameter names
        
        Returns:
            Combined TaintPath tracking flow through both functions
        """
        # Find taint sources in caller
        caller_sources = self.find_taint_sources(caller_code, caller_file)
        
        if not caller_sources:
            # No taint sources found, return empty path
            return TaintPath(
                source_variable=TaintVariable(
                    name="unknown",
                    taint_level=TaintLevel.UNTAINTED,
                    source=TaintSource.UNKNOWN,
                    defined_at=(caller_file, 1),
                ),
                sink_location=(callee_file, 1, "unknown"),
            )
        
        # Use the first taint source
        source = caller_sources[0]
        
        # Trace in caller up to function call
        caller_path = self.trace_taint_path(
            source.name, caller_code, caller_file,
            source.defined_at[1], function_call_line,
        )
        
        # Map tainted variable to callee parameter
        callee_var = None
        for caller_var, callee_param in argument_mapping.items():
            if caller_var == source.name or caller_var in source.aliases:
                callee_var = callee_param
                break
        
        if not callee_var:
            return caller_path
        
        # Continue tracing in callee
        callee_path = self.trace_taint_path(
            callee_var, callee_code, callee_file,
        )
        
        # Merge paths
        for step in callee_path.steps:
            caller_path.add_step(step)
        
        # Update final status
        caller_path.is_sanitized = caller_path.is_sanitized or caller_path.source_variable.taint_level == TaintLevel.SANITIZED
        caller_path.sink_location = callee_path.sink_location
        
        return caller_path
    
    def analyze_function(self, code: str, file_path: str = "") -> dict:
        """
        Analyze a function for taint flow.
        
        Returns a summary dict with:
        - sources: List of taint sources found
        - sinks: List of sinks found
        - is_safe: Whether all tainted data is sanitized before reaching sinks
        - paths: List of TaintPaths
        """
        sources = self.find_taint_sources(code, file_path)
        all_paths = []
        is_safe = True
        
        for source in sources:
            # Track assignments to find all related variables
            tainted_vars = self.track_variable_assignments(code, source, file_path)
            
            # Check each variable for sinks
            for var in tainted_vars:
                sinks = self.check_sinks(code, var)
                if sinks:
                    # Trace the path
                    path = self.trace_taint_path(var, code, file_path)
                    all_paths.append(path)
                    
                    if not path.is_sanitized:
                        is_safe = False
        
        return {
            "sources": [s.to_dict() for s in sources],
            "paths": [p.to_dict() for p in all_paths],
            "is_safe": is_safe,
            "summary": self._generate_summary(sources, all_paths),
        }
    
    def _generate_summary(self, sources: list[TaintVariable], 
                          paths: list[TaintPath]) -> str:
        """Generate a human-readable summary of the analysis."""
        if not sources:
            return "No taint sources found in the code."
        
        lines = [f"Found {len(sources)} taint source(s):"]
        for s in sources:
            lines.append(f"  - {s.name} ({s.source.value}) at line {s.defined_at[1]}")
        
        if not paths:
            lines.append("\nNo taint paths to sinks detected.")
            return "\n".join(lines)
        
        safe_count = sum(1 for p in paths if p.is_sanitized)
        unsafe_count = len(paths) - safe_count
        
        lines.append(f"\nAnalyzed {len(paths)} path(s) to sinks:")
        lines.append(f"  - {safe_count} sanitized (safe)")
        lines.append(f"  - {unsafe_count} unsanitized (potentially vulnerable)")
        
        if unsafe_count > 0:
            lines.append("\n⚠️  UNSANITIZED PATHS DETECTED - Review required!")
        else:
            lines.append("\n✓ All paths are sanitized.")
        
        return "\n".join(lines)
