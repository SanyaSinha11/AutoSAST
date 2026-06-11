"""
Code Lookup - Handles tool execution for dynamic context retrieval.

This module provides the backend for LLM tool calls, allowing the LLM
to request specific code during analysis.

Architecture:
- Uses Tree-sitter AST parsing for accurate method extraction
- Falls back to regex when AST is unavailable
- Optimized for LLM tool call performance
"""

import os
import re
import logging
from pathlib import Path
from typing import Optional
from functools import lru_cache

from .cross_file_resolver import CrossFileResolver, ResolvedReference

logger = logging.getLogger(__name__)

# Configuration for AST parsing
USE_AST_PARSER = os.getenv("USE_AST_PARSER", "true").lower() in ("true", "1", "yes")

# Try to import AST parser
_AST_AVAILABLE = False
try:
    from .ast_parser import (
        get_ast_parser_for_file,
        is_tree_sitter_available,
        JavaASTParser,
        PythonASTParser,
        JavaScriptASTParser,
    )
    _AST_AVAILABLE = is_tree_sitter_available()
except ImportError:
    logger.debug("AST parser module not available for code lookup")
    get_ast_parser_for_file = None
    is_tree_sitter_available = lambda: False
    JavaASTParser = None
    PythonASTParser = None
    JavaScriptASTParser = None


class CodeLookup:
    """
    Handles code lookups for LLM tool calls during vulnerability analysis.

    Uses Tree-sitter AST parsing for accurate method extraction,
    with regex fallback for compatibility.
    """

    def __init__(self, project_root: Path, resolver: Optional[CrossFileResolver] = None):
        self.project_root = project_root
        self.resolver = resolver or CrossFileResolver(project_root)
        self._file_cache: dict[str, str] = {}
        self._class_locations: dict[str, Path] = {}
        self._ast_parsers: dict[str, object] = {}

        # Initialize AST parsers if available
        if USE_AST_PARSER and _AST_AVAILABLE:
            try:
                if JavaASTParser:
                    self._ast_parsers["java"] = JavaASTParser()
                if PythonASTParser:
                    self._ast_parsers["python"] = PythonASTParser()
                if JavaScriptASTParser:
                    self._ast_parsers["javascript"] = JavaScriptASTParser()
            except Exception as e:
                logger.debug(f"Failed to initialize AST parsers for code lookup: {e}")

        self._build_indexes()

    def _get_ast_parser(self, file_path: Path):
        """Get the appropriate AST parser for a file."""
        suffix = file_path.suffix.lower()
        if suffix == ".java":
            return self._ast_parsers.get("java")
        elif suffix == ".py":
            return self._ast_parsers.get("python")
        elif suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs"):
            return self._ast_parsers.get("javascript")
        return None

    def _build_indexes(self):
        """Build indexes for fast lookups."""
        # Index all Java classes
        for file_path in self.project_root.rglob("*.java"):
            try:
                content = self._read_file(file_path)

                # Try AST-based class extraction
                parser = self._get_ast_parser(file_path)
                if parser:
                    try:
                        classes = parser.extract_classes(content)
                        for cls in classes:
                            self._class_locations[cls.name] = file_path
                        continue
                    except Exception as e:
                        logger.debug(f"AST class extraction failed for {file_path}: {e}")

                # Fallback to regex
                class_match = re.search(r'(?:public\s+)?class\s+(\w+)', content)
                if class_match:
                    self._class_locations[class_match.group(1)] = file_path
            except Exception as e:
                logger.debug(f"Error indexing {file_path}: {e}")

    @lru_cache(maxsize=500)
    def _read_file(self, file_path: Path) -> str:
        """Read and cache file contents."""
        try:
            return file_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            logger.warning(f"Error reading {file_path}: {e}")
            return ""

    def get_function_code(
        self,
        function_name: str,
        class_name: Optional[str] = None,
        current_file: Optional[Path] = None
    ) -> str:
        """Get the source code of a function or method."""
        # If class_name provided, look in that class
        if class_name:
            file_path = self._class_locations.get(class_name)
            if file_path:
                return self._extract_method_from_file(file_path, function_name)

        # Search in current file first
        if current_file:
            result = self._extract_method_from_file(current_file, function_name)
            if result and "not found" not in result.lower():
                return result

        # Search all files
        for file_path in self._class_locations.values():
            result = self._extract_method_from_file(file_path, function_name)
            if result and "not found" not in result.lower():
                return f"Found in {file_path.name}:\n{result}"

        return f"Function '{function_name}' not found in the codebase."

    def _extract_method_from_file(self, file_path: Path, method_name: str) -> str:
        """Extract a method's source code from a file."""
        content = self._read_file(file_path)

        # Try AST-based extraction first
        parser = self._get_ast_parser(file_path)
        if parser and USE_AST_PARSER:
            try:
                functions = parser.extract_functions(content)
                for func in functions:
                    if func.name == method_name:
                        return func.source_code
            except Exception as e:
                logger.debug(f"AST method extraction failed for {file_path}: {e}")

        # Fallback to regex-based extraction
        return self._extract_method_regex(content, method_name, file_path.name)

    def _extract_method_regex(self, content: str, method_name: str, file_name: str) -> str:
        """Regex-based method extraction (fallback)."""
        lines = content.split('\n')

        # Pattern to match method definitions
        method_pattern = re.compile(
            rf'^\s*(?:@\w+\s*(?:\([^)]*\))?\s*)*'
            rf'(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?'
            rf'(?:\w+(?:<[^>]+>)?(?:\[\])*)\s+{re.escape(method_name)}\s*\([^)]*\)',
            re.MULTILINE
        )

        for match in method_pattern.finditer(content):
            start_line = content[:match.start()].count('\n')
            # Include annotations above
            actual_start = start_line
            for i in range(start_line - 1, max(0, start_line - 5), -1):
                if lines[i].strip().startswith('@') or lines[i].strip() == '':
                    actual_start = i
                else:
                    break

            # Find method end
            end_line = self._find_method_end(lines, start_line)
            method_code = '\n'.join(lines[actual_start:end_line])
            return method_code

        return f"Method '{method_name}' not found in {file_name}"

    def _find_method_end(self, lines: list[str], start_line: int) -> int:
        """Find the end of a method by counting braces."""
        brace_count = 0
        started = False

        for i in range(start_line, len(lines)):
            line = lines[i]
            # Skip strings and comments (simplified)
            in_string = False
            for j, char in enumerate(line):
                if char == '"' and (j == 0 or line[j-1] != '\\'):
                    in_string = not in_string
                if not in_string:
                    if char == '{':
                        brace_count += 1
                        started = True
                    elif char == '}':
                        brace_count -= 1

            if started and brace_count == 0:
                return i + 1

        return min(start_line + 50, len(lines))

    def get_caller_function(
        self,
        class_name: str,
        method_name: str,
        caller_index: int = 0
    ) -> str:
        """Get the code of a caller of the specified method."""
        callers = self.resolver.find_callers(class_name, method_name, max_results=10)

        if not callers:
            return f"No callers found for {class_name}.{method_name}()"

        if caller_index >= len(callers):
            return f"Only {len(callers)} callers found. Use index 0-{len(callers)-1}."

        caller = callers[caller_index]
        return (
            f"Caller #{caller_index}: {caller.source_class}.{caller.source_method}() "
            f"at {Path(caller.source_file).name}:{caller.line_number}\n\n"
            f"{caller.code_snippet}"
        )

    def get_class_code(self, class_name: str, max_lines: int = 200) -> str:
        """Get the full source code of a class."""
        file_path = self._class_locations.get(class_name)
        if not file_path:
            return f"Class '{class_name}' not found in the codebase."

        content = self._read_file(file_path)
        lines = content.split('\n')

        if len(lines) > max_lines:
            return '\n'.join(lines[:max_lines]) + f"\n\n... ({len(lines) - max_lines} more lines)"
        return content

    def get_method_code(self, class_name: str, method_name: str) -> str:
        """Get the source code of a specific method within a class."""
        file_path = self._class_locations.get(class_name)
        if not file_path:
            return f"Class '{class_name}' not found in the codebase."
        return self._extract_method_from_file(file_path, method_name)

    def read_file(
        self,
        file_path: str,
        line_number: Optional[int] = None,
        context_lines: int = 50
    ) -> str:
        """
        Read a file's source code, optionally centered around a specific line.

        This is the PRIMARY tool for autonomous code exploration.
        Returns the file content with line numbers for easy navigation.
        """
        # Try to find the file
        full_path = self.project_root / file_path
        if not full_path.exists():
            # Try just the filename
            for fp in self.project_root.rglob(Path(file_path).name):
                full_path = fp
                break

        if not full_path.exists():
            # Also try partial path matching
            path_parts = Path(file_path).parts
            if path_parts:
                pattern = "**/{}".format("/".join(path_parts[-2:]) if len(path_parts) > 1 else path_parts[-1])
                matches = list(self.project_root.glob(pattern))
                if matches:
                    full_path = matches[0]

        if not full_path.exists():
            return f"❌ File not found: '{file_path}'\n\nTip: Use search_code to find the correct file path."

        content = self._read_file(full_path)
        lines = content.split('\n')
        total_lines = len(lines)

        # Build header with file info
        rel_path = full_path.relative_to(self.project_root) if full_path.is_relative_to(self.project_root) else full_path
        header = f"📄 **{rel_path}** ({total_lines} lines)\n"
        header += "=" * 60 + "\n"

        # If line_number specified, center around that line
        if line_number and line_number > 0:
            start = max(0, line_number - context_lines - 1)
            end = min(total_lines, line_number + context_lines)

            # Build content with line numbers and highlight target line
            numbered_lines = []
            for i in range(start, end):
                line_num = i + 1
                marker = ">>>" if line_num == line_number else "   "
                numbered_lines.append(f"{marker} {line_num:4d} | {lines[i]}")

            if start > 0:
                header += f"(showing lines {start+1}-{end} around line {line_number})\n\n"
            else:
                header += f"(showing lines 1-{end})\n\n"

            return header + '\n'.join(numbered_lines)
        else:
            # Show from beginning, limited to reasonable size
            max_lines = min(total_lines, 150)
            numbered_lines = [f"   {i+1:4d} | {lines[i]}" for i in range(max_lines)]

            if total_lines > max_lines:
                header += f"(showing first {max_lines} of {total_lines} lines)\n\n"

            return header + '\n'.join(numbered_lines)

    def search_code(
        self,
        pattern: str,
        file_extension: Optional[str] = None,
        max_results: int = 15
    ) -> str:
        """
        Search the codebase for a pattern using AST-aware searching.

        This is a SMART search that:
        1. Uses AST to find method calls, function definitions, and class usages
        2. Falls back to text search for general patterns
        3. Returns navigation-friendly results with context

        Use this to find callers, usages, or implementations, then use read_file
        to examine matches in detail.
        """
        results = []
        ast_results = []
        text_results = []

        # Determine file extensions to search
        if file_extension:
            extensions = [file_extension] if file_extension.startswith('.') else [f'.{file_extension}']
        else:
            extensions = ['.java', '.py', '.js', '.ts', '.jsx', '.tsx']

        for file_path in self.project_root.rglob("*"):
            if not file_path.is_file() or file_path.suffix not in extensions:
                continue
            if len(ast_results) + len(text_results) >= max_results:
                break

            try:
                content = self._read_file(file_path)
                lines = content.split('\n')
                rel_path = file_path.relative_to(self.project_root)

                # Try AST-based search first for better accuracy
                parser = self._get_ast_parser(file_path)
                if parser and USE_AST_PARSER and _AST_AVAILABLE:
                    try:
                        # Search for method/function calls
                        calls = parser.extract_calls(content)
                        for call in calls:
                            if pattern.lower() in call.callee_name.lower():
                                line_content = lines[call.line - 1].strip() if call.line <= len(lines) else ""
                                ast_results.append({
                                    'file': file_path,
                                    'rel_path': rel_path,
                                    'line': call.line,
                                    'type': 'call',
                                    'name': call.callee_name,
                                    'caller': call.caller_function,
                                    'snippet': line_content[:100],
                                })
                                if len(ast_results) >= max_results:
                                    break

                        # Search for function/method definitions
                        if len(ast_results) < max_results:
                            functions = parser.extract_functions(content)
                            for func in functions:
                                if pattern.lower() in func.name.lower():
                                    line_content = lines[func.start_line - 1].strip() if func.start_line <= len(lines) else ""
                                    ast_results.append({
                                        'file': file_path,
                                        'rel_path': rel_path,
                                        'line': func.start_line,
                                        'type': 'definition',
                                        'name': func.name,
                                        'caller': None,
                                        'snippet': line_content[:100],
                                    })
                                    if len(ast_results) >= max_results:
                                        break

                        # Search for class definitions
                        if len(ast_results) < max_results:
                            classes = parser.extract_classes(content)
                            for cls in classes:
                                if pattern.lower() in cls.name.lower():
                                    line_content = lines[cls.start_line - 1].strip() if cls.start_line <= len(lines) else ""
                                    ast_results.append({
                                        'file': file_path,
                                        'rel_path': rel_path,
                                        'line': cls.start_line,
                                        'type': 'class',
                                        'name': cls.name,
                                        'caller': None,
                                        'snippet': line_content[:100],
                                    })
                                    if len(ast_results) >= max_results:
                                        break

                    except Exception as e:
                        logger.debug(f"AST search failed for {file_path}: {e}")

                # Also do text search to catch patterns AST might miss
                # (like string literals, comments, annotations)
                if len(ast_results) + len(text_results) < max_results:
                    for i, line in enumerate(lines):
                        if pattern.lower() in line.lower():
                            # Avoid duplicates with AST results
                            line_num = i + 1
                            is_duplicate = any(
                                r['rel_path'] == rel_path and r['line'] == line_num
                                for r in ast_results
                            )
                            if not is_duplicate:
                                text_results.append({
                                    'file': file_path,
                                    'rel_path': rel_path,
                                    'line': line_num,
                                    'type': 'text',
                                    'name': pattern,
                                    'caller': None,
                                    'snippet': line.strip()[:100],
                                })
                            if len(ast_results) + len(text_results) >= max_results:
                                break

            except Exception as e:
                logger.debug(f"Error searching {file_path}: {e}")
                continue

        # Combine results, prioritizing AST results
        all_results = ast_results + text_results
        all_results = all_results[:max_results]

        if not all_results:
            return f"❌ Pattern '{pattern}' not found in the codebase.\n\nTip: Try a simpler search term or check spelling."

        # Format as navigation-friendly output with context
        output = [f"🔍 Found {len(all_results)} matches for '{pattern}':\n"]
        output.append("=" * 60)

        # Group by type for better readability
        definitions = [r for r in all_results if r['type'] == 'definition']
        calls = [r for r in all_results if r['type'] == 'call']
        classes = [r for r in all_results if r['type'] == 'class']
        text_matches = [r for r in all_results if r['type'] == 'text']

        if definitions:
            output.append("\n📘 **Function/Method Definitions:**")
            for r in definitions:
                output.append(f"  • {r['rel_path']}:{r['line']} - {r['name']}()")
                output.append(f"    → {r['snippet']}")

        if classes:
            output.append("\n📦 **Class Definitions:**")
            for r in classes:
                output.append(f"  • {r['rel_path']}:{r['line']} - class {r['name']}")
                output.append(f"    → {r['snippet']}")

        if calls:
            output.append("\n📞 **Method Calls (Usages):**")
            for r in calls:
                caller_info = f" (in {r['caller']})" if r['caller'] else ""
                output.append(f"  • {r['rel_path']}:{r['line']} - {r['name']}(){caller_info}")
                output.append(f"    → {r['snippet']}")

        if text_matches:
            output.append("\n📝 **Other Matches:**")
            for r in text_matches:
                output.append(f"  • {r['rel_path']}:{r['line']}")
                output.append(f"    → {r['snippet']}")

        output.append("\n" + "=" * 60)
        output.append("📌 **Next step:** Use read_file(\"<file_path>\", <line_number>) to examine any match in detail.")

        return '\n'.join(output)

    def search_codebase(
        self,
        pattern: str,
        file_extension: Optional[str] = None,
        max_results: int = 15
    ) -> str:
        """Alias for search_code (backward compatibility)."""
        return self.search_code(pattern, file_extension, max_results)

    def get_imports(self, file_path: str) -> str:
        """Get the import statements from a file."""
        full_path = self.project_root / file_path
        if not full_path.exists():
            # Try to find the file
            for fp in self.project_root.rglob(Path(file_path).name):
                full_path = fp
                break

        if not full_path.exists():
            return f"File '{file_path}' not found."

        content = self._read_file(full_path)
        lines = content.split('\n')

        imports = []
        for line in lines[:100]:
            stripped = line.strip()
            if stripped.startswith('import ') or stripped.startswith('from '):
                imports.append(stripped)
            elif stripped.startswith('package '):
                imports.insert(0, stripped)

        if not imports:
            return "No imports found in the file."
        return '\n'.join(imports)

    def trace_taint_path(
        self,
        source_variable: str,
        sink_function: str,
        file_path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None
    ) -> str:
        """
        Trace data flow from a source variable to a sink function.

        Returns the path of data transformations and whether sanitization is applied.
        """
        full_path = self.project_root / file_path
        if not full_path.exists():
            for fp in self.project_root.rglob(Path(file_path).name):
                full_path = fp
                break

        if not full_path.exists():
            return f"File '{file_path}' not found."

        content = self._read_file(full_path)
        lines = content.split('\n')

        # Determine the range to analyze
        if start_line and end_line:
            analysis_lines = lines[start_line - 1:end_line]
            line_offset = start_line - 1
        else:
            analysis_lines = lines
            line_offset = 0

        analysis_text = '\n'.join(analysis_lines)

        # Track variable assignments and transformations
        var_pattern = re.escape(source_variable.split('(')[0].split('.')[-1])
        transformations = []
        sanitization_found = False
        sink_reached = False

        # Common sanitization patterns
        sanitization_patterns = [
            r'escape\w*\(', r'sanitize\w*\(', r'encode\w*\(',
            r'validate\w*\(', r'clean\w*\(', r'filter\w*\(',
            r'PreparedStatement', r'setString\(', r'setInt\(',
            r'htmlEscape', r'StringEscapeUtils', r'ESAPI',
        ]

        for i, line in enumerate(analysis_lines):
            actual_line = i + line_offset + 1

            # Check for variable usage
            if re.search(var_pattern, line, re.IGNORECASE):
                transformations.append(f"Line {actual_line}: {line.strip()}")

                # Check for sanitization
                for pattern in sanitization_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        sanitization_found = True
                        transformations.append(f"  ↳ SANITIZATION DETECTED: {pattern}")

            # Check for sink
            if re.search(re.escape(sink_function), line, re.IGNORECASE):
                sink_reached = True
                transformations.append(f"Line {actual_line} [SINK]: {line.strip()}")

        result = f"## Taint Path Analysis\n"
        result += f"**Source:** {source_variable}\n"
        result += f"**Sink:** {sink_function}\n"
        result += f"**Sanitization Found:** {'Yes' if sanitization_found else 'No'}\n"
        result += f"**Sink Reached:** {'Yes' if sink_reached else 'No'}\n\n"
        result += "### Data Flow:\n"
        result += '\n'.join(transformations) if transformations else "No data flow path found."

        return result

    def get_sanitization_check(
        self,
        variable_name: str,
        file_path: str,
        start_line: int,
        end_line: int
    ) -> str:
        """
        Check if a variable is sanitized before reaching a sink.

        Returns sanitization methods found and their effectiveness.
        """
        full_path = self.project_root / file_path
        if not full_path.exists():
            for fp in self.project_root.rglob(Path(file_path).name):
                full_path = fp
                break

        if not full_path.exists():
            return f"File '{file_path}' not found."

        content = self._read_file(full_path)
        lines = content.split('\n')
        analysis_lines = lines[start_line - 1:end_line]

        # Sanitization patterns with effectiveness ratings
        sanitization_checks = {
            'PreparedStatement': ('HIGH', 'Parameterized query - prevents SQL injection'),
            'setString': ('HIGH', 'Parameterized binding - prevents SQL injection'),
            'setInt': ('HIGH', 'Type-safe binding - prevents SQL injection'),
            'htmlEscape': ('HIGH', 'HTML encoding - prevents XSS'),
            'StringEscapeUtils.escapeHtml': ('HIGH', 'HTML encoding - prevents XSS'),
            'ESAPI.encoder': ('HIGH', 'OWASP ESAPI encoding - prevents multiple injection types'),
            'URLEncoder.encode': ('MEDIUM', 'URL encoding - context-dependent'),
            'Pattern.matches': ('MEDIUM', 'Regex validation - depends on pattern'),
            'Integer.parseInt': ('MEDIUM', 'Type conversion - prevents string injection'),
            'Long.parseLong': ('MEDIUM', 'Type conversion - prevents string injection'),
            'trim()': ('LOW', 'Whitespace removal - minimal security benefit'),
            'toLowerCase': ('LOW', 'Case normalization - minimal security benefit'),
        }

        found_sanitizations = []
        var_pattern = re.escape(variable_name)

        for i, line in enumerate(analysis_lines):
            actual_line = start_line + i
            if re.search(var_pattern, line, re.IGNORECASE):
                for pattern, (effectiveness, description) in sanitization_checks.items():
                    if pattern in line:
                        found_sanitizations.append({
                            'line': actual_line,
                            'pattern': pattern,
                            'effectiveness': effectiveness,
                            'description': description,
                            'code': line.strip()
                        })

        result = f"## Sanitization Check for '{variable_name}'\n"
        result += f"**Lines analyzed:** {start_line} to {end_line}\n\n"

        if found_sanitizations:
            result += "### Sanitization Methods Found:\n"
            for s in found_sanitizations:
                result += f"\n**Line {s['line']}:** `{s['pattern']}`\n"
                result += f"- Effectiveness: {s['effectiveness']}\n"
                result += f"- Description: {s['description']}\n"
                result += f"- Code: `{s['code']}`\n"
        else:
            result += "### ⚠️ No sanitization found!\n"
            result += "The variable appears to flow to the sink without sanitization.\n"

        return result

    def get_caller_chain(
        self,
        function_name: str,
        class_name: str,
        max_depth: int = 5
    ) -> str:
        """
        Trace backwards from a function to find all callers up to entry points.

        Useful for understanding how user input reaches a vulnerable function.
        """
        callers = self.resolver.find_callers(class_name, function_name, max_results=20)

        if not callers:
            return f"No callers found for {class_name}.{function_name}()"

        result = f"## Caller Chain for {class_name}.{function_name}()\n\n"

        # Group by depth level
        current_level = callers
        depth = 0

        while current_level and depth < max_depth:
            result += f"### Level {depth + 1} Callers:\n"
            next_level = []

            for caller in current_level:
                result += f"\n**{caller.source_class}.{caller.source_method}()** "
                result += f"({caller.source_file}:{caller.line_number})\n"
                result += f"```\n{caller.code_snippet[:300]}...\n```\n"

                # Check if this is an entry point
                if self._is_entry_point(caller.code_snippet):
                    result += "↳ **ENTRY POINT** (Controller/Handler)\n"
                else:
                    # Find callers of this caller
                    upstream = self.resolver.find_callers(
                        caller.source_class, caller.source_method, max_results=5
                    )
                    next_level.extend(upstream)

            current_level = next_level[:10]  # Limit breadth
            depth += 1

        return result

    def _is_entry_point(self, code: str) -> bool:
        """Check if code indicates an entry point (controller, handler, etc.)."""
        entry_patterns = [
            r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)',
            r'@(Get|Post|Put|Delete|Path)',
            r'doGet|doPost|doPut|doDelete',
            r'@EventListener|@Scheduled',
            r'public static void main',
        ]
        return any(re.search(p, code) for p in entry_patterns)

    def analyze_data_flow(
        self,
        source_variable: str,
        file_path: str,
        function_name: Optional[str] = None,
        include_callers: bool = True
    ) -> str:
        """
        Perform inter-procedural data flow analysis.
        
        Uses TaintAnalyzer to track how data flows from source to sink,
        including through function calls and assignments.
        
        Args:
            source_variable: Variable to track
            file_path: Path to the file to analyze
            function_name: Optional function name to focus on
            include_callers: Whether to trace through caller functions
        
        Returns:
            Formatted analysis result for LLM consumption
        """
        # Import TaintAnalyzer here to avoid circular imports
        try:
            from .taint_analyzer import TaintAnalyzer, TaintPath
        except ImportError:
            return "Error: TaintAnalyzer not available"
        
        # Find the file
        full_path = self.project_root / file_path
        if not full_path.exists():
            # Try to find it
            for fp in self.project_root.rglob(Path(file_path).name):
                full_path = fp
                break
        
        if not full_path.exists():
            return f"Error: File '{file_path}' not found in project."
        
        # Read file content
        content = self._read_file(full_path)
        if not content:
            return f"Error: Could not read file '{file_path}'."
        
        # Initialize analyzer
        analyzer = TaintAnalyzer(self.project_root)
        
        # If function name provided, extract just that function
        if function_name:
            func_code = self._extract_method_from_file(full_path, function_name)
            if "not found" in func_code.lower():
                # Fall back to full file
                code_to_analyze = content
            else:
                code_to_analyze = func_code
        else:
            code_to_analyze = content
        
        # Perform analysis
        result = analyzer.analyze_function(code_to_analyze, str(full_path))
        
        # Format output
        output_lines = ["## Inter-Procedural Data Flow Analysis\n"]
        output_lines.append(f"**File:** {file_path}")
        output_lines.append(f"**Variable:** `{source_variable}`\n")
        
        # Summary
        output_lines.append(result["summary"])
        output_lines.append("")
        
        # Detailed paths
        if result["paths"]:
            output_lines.append("### Data Flow Paths:\n")
            for i, path in enumerate(result["paths"], 1):
                output_lines.append(f"#### Path {i}:")
                output_lines.append(f"- **Sanitized:** {'Yes ✓' if path.get('is_sanitized') else 'No ✗'}")
                if path.get("sanitization_points"):
                    for sp in path["sanitization_points"]:
                        output_lines.append(f"  - `{sp}`")
                output_lines.append("")
                
                # Steps
                if path.get("steps"):
                    output_lines.append("**Flow:**")
                    for step in path["steps"]:
                        marker = "🔒" if step.get("is_sanitization") else ("🎯" if step.get("is_sink") else "→")
                        output_lines.append(f"{marker} `{step['file']}:{step['line']}` - {step['description']}")
        
        # Trace through callers if requested and no sanitization found locally
        if include_callers and not result.get("is_safe", True):
            output_lines.append("\n### Checking Caller Chain for Sanitization...\n")
            
            # Try to infer class name from file
            class_name = self._extract_class_name_from_file(full_path)
            if class_name and function_name:
                callers = self.resolver.find_callers(class_name, function_name, max_results=5)
                
                if callers:
                    for caller in callers:
                        # Check if caller has sanitization
                        caller_analysis = analyzer.check_sanitization(
                            caller.code_snippet, source_variable
                        )
                        if caller_analysis:
                            output_lines.append(f"✓ **Sanitization found in caller:**")
                            output_lines.append(f"  `{caller.source_class}.{caller.source_method}()` at line {caller.line_number}")
                            for san_line, san_desc in caller_analysis:
                                output_lines.append(f"  - {san_desc}")
                            result["is_safe"] = True
                        else:
                            output_lines.append(f"✗ No sanitization found in `{caller.source_class}.{caller.source_method}()`")
        
        # Final verdict
        output_lines.append("\n### Verdict:\n")
        if result.get("is_safe", True):
            output_lines.append("✅ **Data flow appears SAFE** - sanitization detected before sink.")
        else:
            output_lines.append("⚠️ **Potential vulnerability** - no sanitization detected between source and sink.")
        
        return "\n".join(output_lines)
    
    def _extract_class_name_from_file(self, file_path: Path) -> Optional[str]:
        """Extract the main class name from a file."""
        content = self._read_file(file_path)
        
        # Java
        match = re.search(r'(?:public\s+)?class\s+(\w+)', content)
        if match:
            return match.group(1)
        
        # Python - use filename as module name
        if file_path.suffix == ".py":
            return file_path.stem
        
        return None

