"""
Constant Analyzer - Detects trusted constant sources.

This module provides detection of values that are known to be safe:
1. Private static final String constants
2. String literals passed as arguments
3. Configuration-loaded values from trusted sources

Key Features:
- Pattern-based detection of constant definitions
- Argument literal detection at call sites
- Integration with taint analysis
"""

import re
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from enum import Enum

logger = logging.getLogger(__name__)


class ConstantType(Enum):
    """Type of constant value."""
    STATIC_FINAL = "static_final"           # private static final String
    LITERAL = "literal"                      # "string literal" directly
    CONFIG_VALUE = "config_value"            # Loaded from config/env
    ENUM_VALUE = "enum_value"                # Enum constant
    UNKNOWN = "unknown"


@dataclass
class ConstantInfo:
    """Information about a detected constant."""
    name: str
    value: Optional[str]
    constant_type: ConstantType
    file_path: str
    line_number: int
    is_trusted: bool = True
    confidence: float = 1.0
    
    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "value": self.value[:100] if self.value and len(self.value) > 100 else self.value,
            "type": self.constant_type.value,
            "file": self.file_path,
            "line": self.line_number,
            "is_trusted": self.is_trusted,
            "confidence": self.confidence,
        }


@dataclass
class CallerArgumentAnalysis:
    """Analysis of arguments passed by callers."""
    method_name: str
    parameter_index: int
    total_callers: int
    callers_with_literals: int
    all_pass_literals: bool
    literal_values: list[str] = field(default_factory=list)
    non_literal_callers: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "method": self.method_name,
            "param_index": self.parameter_index,
            "total_callers": self.total_callers,
            "callers_with_literals": self.callers_with_literals,
            "all_pass_literals": self.all_pass_literals,
            "literal_values": self.literal_values[:10],  # Limit for display
            "non_literal_callers": self.non_literal_callers[:5],
        }


class ConstantAnalyzer:
    """
    Analyzes code to detect trusted constant sources.
    
    This is critical for reducing false positives where values
    come from hardcoded constants rather than user input.
    """
    
    # Patterns for static final constant definitions
    STATIC_FINAL_PATTERNS = [
        # Java: private/public static final String NAME = "value";
        r'(?:private|public|protected)?\s*static\s+final\s+String\s+(\w+)\s*=\s*"([^"]*)"',
        # Java: private/public static final String NAME = 'value';
        r"(?:private|public|protected)?\s*static\s+final\s+String\s+(\w+)\s*=\s*'([^']*)'",
        # Kotlin: const val NAME = "value"
        r'const\s+val\s+(\w+)\s*=\s*"([^"]*)"',
        # TypeScript/JavaScript: const NAME = "value"
        r'const\s+(\w+)\s*=\s*"([^"]*)"',
        # Python: NAME = "value" (at module level, UPPER_CASE convention)
        r'^([A-Z][A-Z0-9_]+)\s*=\s*["\']([^"\']*)["\']',
    ]
    
    # Patterns for trusted configuration sources
    CONFIG_SOURCE_PATTERNS = [
        r'@Value\s*\(\s*["\']([^"\']+)["\']\s*\)',           # Spring @Value
        r'System\.getenv\s*\(\s*["\']([^"\']+)["\']\s*\)',   # Environment variable
        r'properties\.getProperty\s*\(',                      # Properties file
        r'config\.get\s*\(',                                  # Generic config
        r'getenv\s*\(',                                       # Python os.getenv
        r'os\.environ\s*\[',                                  # Python environ
    ]
    
    # Patterns for string literals in method calls
    STRING_LITERAL_PATTERN = r'"([^"\\]*(?:\\.[^"\\]*)*)"'
    
    # Patterns that indicate NOT a constant (variable/parameter)
    VARIABLE_PATTERNS = [
        r'request\.',           # HTTP request
        r'\.getParameter\(',    # Parameter extraction
        r'\.getHeader\(',       # Header extraction
        r'args\[',              # Array access
        r'params\.',            # Parameter object
    ]
    
    def __init__(self, project_root: Path):
        """
        Initialize the constant analyzer.
        
        Args:
            project_root: Root directory of the project
        """
        self.project_root = project_root
        self._file_cache: dict[str, str] = {}
        self._constant_cache: dict[str, list[ConstantInfo]] = {}
    
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
    
    def find_constant_definitions(self, file_path: Path) -> list[ConstantInfo]:
        """
        Find all constant definitions in a file.
        
        Returns:
            List of ConstantInfo for each detected constant
        """
        key = str(file_path)
        if key in self._constant_cache:
            return self._constant_cache[key]
        
        constants = []
        content = self._read_file(file_path)
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern in self.STATIC_FINAL_PATTERNS:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    name = match.group(1)
                    value = match.group(2) if len(match.groups()) > 1 else None
                    constants.append(ConstantInfo(
                        name=name,
                        value=value,
                        constant_type=ConstantType.STATIC_FINAL,
                        file_path=str(file_path),
                        line_number=line_num,
                        is_trusted=True,
                        confidence=1.0,
                    ))
        
        self._constant_cache[key] = constants
        return constants
    
    def is_variable_from_constant(self, variable_name: str, code: str, 
                                   file_path: Optional[Path] = None) -> tuple[bool, Optional[ConstantInfo]]:
        """
        Check if a variable is assigned from a constant source.
        
        Args:
            variable_name: Name of the variable to check
            code: Code context to search
            file_path: Optional file path for constant lookup
            
        Returns:
            (is_constant: bool, constant_info: Optional[ConstantInfo])
        """
        # Check if variable name matches a static final pattern in current code
        for pattern in self.STATIC_FINAL_PATTERNS:
            match = re.search(pattern, code, re.IGNORECASE)
            if match and match.group(1) == variable_name:
                return True, ConstantInfo(
                    name=variable_name,
                    value=match.group(2) if len(match.groups()) > 1 else None,
                    constant_type=ConstantType.STATIC_FINAL,
                    file_path=str(file_path) if file_path else "",
                    line_number=0,
                )
        
        # Check if variable is assigned from a known constant
        # Pattern: varName = CONSTANT_NAME;
        constant_ref_pattern = rf'\b{re.escape(variable_name)}\s*=\s*([A-Z][A-Z0-9_]+)\s*;'
        match = re.search(constant_ref_pattern, code)
        if match:
            constant_name = match.group(1)
            # Look up the constant in the file
            if file_path:
                constants = self.find_constant_definitions(file_path)
                for const in constants:
                    if const.name == constant_name:
                        return True, const
        
        return False, None
    
    def is_string_literal(self, value: str) -> bool:
        """
        Check if a value is a string literal.
        
        Args:
            value: The value to check
            
        Returns:
            True if the value is a string literal (starts/ends with quotes)
        """
        value = value.strip()
        return (
            (value.startswith('"') and value.endswith('"')) or
            (value.startswith("'") and value.endswith("'"))
        )
    
    def is_trusted_source(self, variable_name: str, code: str,
                          file_path: Optional[Path] = None) -> tuple[bool, str]:
        """
        Check if a variable comes from a trusted source.
        
        Args:
            variable_name: Name of the variable
            code: Code context
            file_path: Optional file path
            
        Returns:
            (is_trusted: bool, reason: str)
        """
        # Check for static final constant
        is_const, const_info = self.is_variable_from_constant(variable_name, code, file_path)
        if is_const:
            return True, f"Assigned from static final constant: {const_info.name if const_info else 'unknown'}"
        
        # Check for config source patterns
        for pattern in self.CONFIG_SOURCE_PATTERNS:
            # Look for: variable = ...pattern...
            assignment_pattern = rf'\b{re.escape(variable_name)}\s*=\s*[^;]*{pattern}'
            if re.search(assignment_pattern, code, re.IGNORECASE | re.DOTALL):
                return True, "Loaded from configuration source"
        
        # Check if it's a simple literal assignment
        literal_pattern = rf'\b{re.escape(variable_name)}\s*=\s*"[^"]*"\s*;'
        if re.search(literal_pattern, code):
            return True, "Assigned from string literal"
        
        # Check for untrusted patterns
        for pattern in self.VARIABLE_PATTERNS:
            assignment_pattern = rf'\b{re.escape(variable_name)}\s*=\s*[^;]*{pattern}'
            if re.search(assignment_pattern, code, re.IGNORECASE):
                return False, f"Assigned from untrusted source matching pattern: {pattern}"
        
        return False, "Could not determine source"
    
    def extract_argument_at_call_site(self, call_code: str, method_name: str, 
                                       param_index: int) -> tuple[Optional[str], bool]:
        """
        Extract the argument value at a specific parameter position in a method call.
        
        Args:
            call_code: Code containing the method call
            method_name: Name of the method being called
            param_index: Index of the parameter (0-based)
            
        Returns:
            (argument_value: str or None, is_literal: bool)
        """
        # Pattern to find method call with arguments
        call_pattern = rf'{re.escape(method_name)}\s*\(([^)]+)\)'
        match = re.search(call_pattern, call_code)
        
        if not match:
            return None, False
        
        args_str = match.group(1)
        
        # Split arguments (simple approach - doesn't handle nested calls well)
        # Track parentheses depth to handle nested calls
        args = []
        current_arg = []
        depth = 0
        
        for char in args_str:
            if char == '(' or char == '[' or char == '{':
                depth += 1
                current_arg.append(char)
            elif char == ')' or char == ']' or char == '}':
                depth -= 1
                current_arg.append(char)
            elif char == ',' and depth == 0:
                args.append(''.join(current_arg).strip())
                current_arg = []
            else:
                current_arg.append(char)
        
        if current_arg:
            args.append(''.join(current_arg).strip())
        
        if param_index >= len(args):
            return None, False
        
        arg_value = args[param_index]
        is_literal = self.is_string_literal(arg_value)
        
        return arg_value, is_literal
    
    def analyze_caller_arguments(self, caller_codes: list[tuple[str, str, int]], 
                                  method_name: str, 
                                  param_index: int) -> CallerArgumentAnalysis:
        """
        Analyze what arguments callers pass to a method at a specific parameter position.
        
        Args:
            caller_codes: List of (caller_code, caller_file, call_line) tuples
            method_name: Name of the method being analyzed
            param_index: Index of the parameter to analyze
            
        Returns:
            CallerArgumentAnalysis with detailed results
        """
        literal_values = []
        non_literal_callers = []
        
        for caller_code, caller_file, call_line in caller_codes:
            arg_value, is_literal = self.extract_argument_at_call_site(
                caller_code, method_name, param_index
            )
            
            if arg_value:
                if is_literal:
                    # Extract just the string content (without quotes)
                    clean_value = arg_value.strip('"\'')
                    literal_values.append(clean_value)
                else:
                    non_literal_callers.append(f"{caller_file}:{call_line}")
        
        total_callers = len(caller_codes)
        callers_with_literals = len(literal_values)
        all_pass_literals = (total_callers > 0 and 
                           callers_with_literals == total_callers and 
                           len(non_literal_callers) == 0)
        
        return CallerArgumentAnalysis(
            method_name=method_name,
            parameter_index=param_index,
            total_callers=total_callers,
            callers_with_literals=callers_with_literals,
            all_pass_literals=all_pass_literals,
            literal_values=literal_values,
            non_literal_callers=non_literal_callers,
        )
    
    def detect_hardcoded_in_template(self, code: str, variable_name: str) -> tuple[bool, str]:
        """
        Distinguish between a hardcoded value and a template placeholder.
        
        Example:
            HARDCODED: String secret = "myPassword123";  // TRUE POSITIVE
            TEMPLATE:  String cfg = "password=%s".format(config.getPassword());  // FALSE POSITIVE
            
        Args:
            code: Code to analyze
            variable_name: Variable name to check
            
        Returns:
            (is_hardcoded: bool, reason: str)
        """
        # Pattern for template strings (contains %s, {}, etc.)
        template_patterns = [
            r'"[^"]*%[sd][^"]*"',           # printf style: "user=%s"
            r'"[^"]*\{[^}]*\}[^"]*"',       # format style: "user={0}"
            r'"[^"]*\$\{[^}]*\}[^"]*"',     # interpolation: "user=${name}"
            r'"[^"]*\+\s*\w+',               # Concatenation: "user=" + name
        ]
        
        # Check if variable is in a template context
        var_pattern = rf'{re.escape(variable_name)}\s*=\s*([^;]+);'
        match = re.search(var_pattern, code, re.DOTALL)
        
        if match:
            assignment = match.group(1)
            
            # Check for getter calls (not hardcoded)
            if re.search(r'\.\w+\(\)', assignment):
                return False, "Value comes from getter method, not hardcoded"
            
            # Check for template patterns
            for pattern in template_patterns:
                if re.search(pattern, assignment):
                    return False, "Value is from template string with dynamic content"
            
            # Check for String.format or similar
            if re.search(r'String\.format\s*\(|\.format\s*\(', assignment):
                return False, "Value uses String.format with dynamic content"
        
        return True, "Appears to be hardcoded value"
    
    def format_analysis_for_llm(self, 
                                 constant_info: Optional[ConstantInfo],
                                 caller_analysis: Optional[CallerArgumentAnalysis]) -> str:
        """
        Format constant and caller analysis for LLM consumption.
        
        Args:
            constant_info: Optional constant information
            caller_analysis: Optional caller argument analysis
            
        Returns:
            Formatted string for inclusion in LLM prompt
        """
        lines = ["## Static Analysis Results\n"]
        
        if constant_info:
            lines.append("### Constant Source Detection")
            if constant_info.is_trusted:
                lines.append(f"✓ **TRUSTED SOURCE**: Variable `{constant_info.name}` is from a static final constant")
                if constant_info.value:
                    lines.append(f"  - Value: `{constant_info.value[:50]}{'...' if len(constant_info.value) > 50 else ''}`")
                lines.append(f"  - Defined at: {constant_info.file_path}:{constant_info.line_number}")
                lines.append("")
                lines.append("> **Recommendation**: This is likely a FALSE POSITIVE as the value is hardcoded.")
            else:
                lines.append(f"✗ Variable `{constant_info.name}` is NOT from a trusted constant source")
        
        if caller_analysis:
            lines.append("")
            lines.append("### Caller Argument Analysis")
            lines.append(f"Method: `{caller_analysis.method_name}` (parameter {caller_analysis.parameter_index})")
            lines.append(f"- Total callers found: {caller_analysis.total_callers}")
            lines.append(f"- Callers passing string literals: {caller_analysis.callers_with_literals}")
            
            if caller_analysis.all_pass_literals:
                lines.append("")
                lines.append("✓ **ALL CALLERS PASS STRING LITERALS**")
                if caller_analysis.literal_values:
                    lines.append("  Values passed:")
                    for val in caller_analysis.literal_values[:5]:
                        lines.append(f"  - `{val[:60]}{'...' if len(val) > 60 else ''}`")
                lines.append("")
                lines.append("> **Recommendation**: This is likely a FALSE POSITIVE as all callers pass hardcoded strings.")
            else:
                if caller_analysis.non_literal_callers:
                    lines.append("")
                    lines.append("✗ Some callers pass non-literal values:")
                    for caller in caller_analysis.non_literal_callers[:3]:
                        lines.append(f"  - {caller}")
        
        return "\n".join(lines)
