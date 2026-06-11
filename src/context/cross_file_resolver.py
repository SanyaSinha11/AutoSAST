"""
Cross-File Context Resolver - Traces data flow across files.

This module provides the critical capability to:
1. Follow imports to find related classes/functions
2. Find callers of vulnerable functions
3. Trace data flow from sources to sinks
4. Resolve method implementations in other files

Architecture:
- Uses pre-indexed CallGraph for O(1) caller lookups when available
- Uses Tree-sitter AST parsing for accurate method/call detection
- Falls back to regex when AST is unavailable
- Optimized for scaled scanning with caching
"""

import re
import os
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING
from functools import lru_cache

if TYPE_CHECKING:
    from .call_graph import CallGraph

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
        FunctionInfo,
        CallInfo,
    )
    _AST_AVAILABLE = is_tree_sitter_available()
except ImportError:
    logger.debug("AST parser module not available for cross-file resolution")
    get_ast_parser_for_file = None
    is_tree_sitter_available = lambda: False
    JavaASTParser = None
    FunctionInfo = None
    CallInfo = None


@dataclass
class ResolvedReference:
    """A resolved cross-file reference."""
    source_file: str
    source_class: str
    source_method: str
    target_file: str
    target_class: str
    target_method: Optional[str]
    code_snippet: str
    line_number: int
    reference_type: str  # "caller", "callee", "import", "field"


@dataclass
class CrossFileContext:
    """Cross-file context for vulnerability analysis."""
    callers: list[ResolvedReference] = field(default_factory=list)
    callees: list[ResolvedReference] = field(default_factory=list)
    resolved_imports: list[ResolvedReference] = field(default_factory=list)
    related_methods: list[ResolvedReference] = field(default_factory=list)
    data_flow_chain: list[str] = field(default_factory=list)
    full_class_code: Optional[str] = None


class CrossFileResolver:
    """
    Resolves cross-file references for vulnerability analysis.

    Uses pre-indexed CallGraph for O(1) caller lookups when available.
    Falls back to Tree-sitter AST parsing for accurate call site detection,
    with regex fallback for compatibility.
    """

    def __init__(self, project_root: Path, call_graph: Optional["CallGraph"] = None):
        self.project_root = project_root
        self._file_cache: dict[str, str] = {}
        self._class_file_map: dict[str, Path] = {}
        self._ast_parser = None
        self._call_index: dict[str, list[tuple[Path, "CallInfo"]]] = {}  # method_name -> [(file, call_info)]
        self._call_graph = call_graph  # Pre-indexed call graph for O(1) lookups

        # Initialize AST parser if available
        if USE_AST_PARSER and _AST_AVAILABLE and JavaASTParser:
            try:
                self._ast_parser = JavaASTParser()
            except Exception as e:
                logger.debug(f"Failed to initialize Java AST parser for cross-file resolution: {e}")

        self._build_class_index()

    def _build_class_index(self):
        """Build an index of class names to file paths."""
        java_files = list(self.project_root.rglob("*.java"))
        for file_path in java_files:
            try:
                content = self._read_file(file_path)

                # Use AST for more accurate class extraction
                if self._ast_parser:
                    try:
                        classes = self._ast_parser.extract_classes(content)
                        pkg_match = re.search(r'package\s+([\w.]+);', content)
                        package = pkg_match.group(1) if pkg_match else ""

                        for cls in classes:
                            fqn = f"{package}.{cls.name}" if package else cls.name
                            self._class_file_map[fqn] = file_path
                            self._class_file_map[cls.name] = file_path
                        continue
                    except Exception as e:
                        logger.debug(f"AST class extraction failed for {file_path}, using regex: {e}")

                # Fallback to regex
                class_matches = re.findall(
                    r'(?:public\s+)?(?:class|interface|enum)\s+(\w+)',
                    content
                )
                pkg_match = re.search(r'package\s+([\w.]+);', content)
                package = pkg_match.group(1) if pkg_match else ""

                for class_name in class_matches:
                    fqn = f"{package}.{class_name}" if package else class_name
                    self._class_file_map[fqn] = file_path
                    self._class_file_map[class_name] = file_path
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

    def find_callers(self, class_name: str, method_name: str, max_results: int = 10) -> list[ResolvedReference]:
        """
        Find all callers of a specific method.

        Uses pre-indexed CallGraph for O(1) lookups when available.
        Falls back to AST parsing for accurate call site detection, then regex.
        """
        # First, try pre-indexed call graph for O(1) lookup
        if self._call_graph:
            callers = self._find_callers_from_graph(class_name, method_name, max_results)
            if callers:
                logger.debug(f"Found {len(callers)} callers from pre-indexed call graph")
                return callers

        # Fallback to AST/regex scanning
        callers = []

        for file_path in self.project_root.rglob("*.java"):
            try:
                content = self._read_file(file_path)
                lines = content.split('\n')

                # Try AST-based call extraction first
                if self._ast_parser and USE_AST_PARSER:
                    try:
                        calls = self._ast_parser.extract_calls(content)
                        for call in calls:
                            if call.callee_name == method_name:
                                # Get the full method body for context
                                snippet = self._extract_method_body_ast(content, call.line) or \
                                         self._extract_method_body(content, call.line, lines)

                                callers.append(ResolvedReference(
                                    source_file=str(file_path),
                                    source_class=self._extract_class_name(content),
                                    source_method=call.caller_function or "unknown",
                                    target_file="",
                                    target_class=class_name,
                                    target_method=method_name,
                                    code_snippet=snippet,
                                    line_number=call.line,
                                    reference_type="caller"
                                ))

                                if len(callers) >= max_results:
                                    return callers
                        continue  # Successfully used AST, skip regex
                    except Exception as e:
                        logger.debug(f"AST call extraction failed for {file_path}: {e}")

                # Fallback to regex-based detection
                callers.extend(self._find_callers_regex(
                    file_path, content, lines, class_name, method_name, max_results - len(callers)
                ))

                if len(callers) >= max_results:
                    return callers

            except Exception as e:
                logger.debug(f"Error searching {file_path}: {e}")

        return callers

    def _find_callers_from_graph(self, class_name: str, method_name: str,
                                  max_results: int) -> list[ResolvedReference]:
        """
        Find callers using pre-indexed call graph (O(1) lookup).

        This is much faster and more accurate than scanning files.
        """
        if not self._call_graph:
            return []

        # Try multiple node ID formats
        # Format could be: "ClassName.methodName" or "package.ClassName.methodName"
        possible_ids = [
            f"{class_name}.{method_name}",
            method_name,
        ]

        # Check all nodes for matching class and method
        for node_id, node in self._call_graph._nodes.items():
            if node.class_name == class_name and node.name == method_name:
                possible_ids.insert(0, node_id)  # Prefer exact match
                break

        callers = []
        caller_nodes = []

        for node_id in possible_ids:
            caller_nodes = self._call_graph.get_callers(node_id)
            if caller_nodes:
                logger.debug(f"Found {len(caller_nodes)} callers using node ID: {node_id}")
                break

        for caller_node in caller_nodes[:max_results]:
            # Read the source file to get the code snippet
            try:
                file_path = Path(caller_node.file_path) if caller_node.file_path else None
                if file_path and file_path.exists():
                    content = self._read_file(file_path)
                    lines = content.split('\n')
                    snippet = self._extract_method_body(content, caller_node.start_line, lines)
                else:
                    snippet = caller_node.source_code or ""

                callers.append(ResolvedReference(
                    source_file=caller_node.file_path or "",
                    source_class=caller_node.class_name or "",
                    source_method=caller_node.name,
                    target_file="",
                    target_class=class_name,
                    target_method=method_name,
                    code_snippet=snippet,
                    line_number=caller_node.start_line,
                    reference_type="caller"
                ))
            except Exception as e:
                logger.debug(f"Error reading caller node: {e}")

        return callers

    def _find_callers_regex(self, file_path: Path, content: str, lines: list,
                            class_name: str, method_name: str, max_results: int) -> list[ResolvedReference]:
        """Regex-based caller finding (fallback method)."""
        callers = []
        pattern = re.compile(
            rf'(\w+)\s*\.\s*{re.escape(method_name)}\s*\(' +
            rf'|{re.escape(method_name)}\s*\(',
            re.MULTILINE
        )

        for match in pattern.finditer(content):
            line_num = content[:match.start()].count('\n') + 1

            # Find the containing method
            containing_method = self._find_containing_method(content, line_num)

            # Get the full method body for better context
            snippet = self._extract_method_body(content, line_num, lines)

            callers.append(ResolvedReference(
                source_file=str(file_path),
                source_class=self._extract_class_name(content),
                source_method=containing_method or "unknown",
                target_file="",
                target_class=class_name,
                target_method=method_name,
                code_snippet=snippet,
                line_number=line_num,
                reference_type="caller"
            ))

            if len(callers) >= max_results:
                break

        return callers

    def _extract_method_body_ast(self, content: str, line: int) -> Optional[str]:
        """Extract method body using AST parsing."""
        if not self._ast_parser:
            return None

        try:
            func_info = self._ast_parser.find_function_at_line(content, line)
            if func_info:
                return func_info.source_code
        except Exception as e:
            logger.debug(f"AST method body extraction failed: {e}")

        return None

    def _extract_method_body(self, content: str, call_line: int, lines: list) -> str:
        """
        Extract the full method body containing the call.

        This is critical for seeing sanitization that happens before the call.
        """
        # Find method start by searching backwards for method signature patterns
        method_start = call_line - 1

        # Method signature pattern - must have parentheses for parameters
        method_sig_pattern = re.compile(
            r'^\s*(public|private|protected|@Override)\s+' +
            r'|^\s*\w+\s+\w+\s*\([^)]*\)\s*(throws|{)'
        )

        # Look for method signature (handles multi-line signatures)
        for i in range(call_line - 1, max(0, call_line - 30), -1):
            line = lines[i]
            # Check for @Override annotation or method with parameters
            if '@Override' in line or (re.search(r'\w+\s+\w+\s*\(', line) and '=' not in line):
                # Verify this is a method by checking for opening brace nearby
                for j in range(i, min(i + 5, call_line)):
                    if '{' in lines[j]:
                        method_start = i
                        break
                if method_start == i:
                    break

        # Find method end by counting braces
        brace_count = 0
        method_end = call_line
        started = False

        for i in range(method_start, min(len(lines), method_start + 50)):
            line = lines[i]
            for char in line:
                if char == '{':
                    brace_count += 1
                    started = True
                elif char == '}':
                    brace_count -= 1

            if started and brace_count == 0:
                method_end = i + 1
                break

        # Return the method body (up to 30 lines to keep context manageable)
        end = min(method_end, method_start + 30)
        return '\n'.join(lines[method_start:end])

    def _find_containing_method(self, content: str, line_num: int) -> Optional[str]:
        """Find the method containing a given line."""
        lines = content.split('\n')
        # Search backwards for method definition
        method_pattern = re.compile(
            r'(?:public|private|protected)?\s*(?:static\s+)?'
            r'(?:\w+(?:<[^>]+>)?)\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{'
        )
        for i in range(line_num - 1, -1, -1):
            match = method_pattern.search(lines[i])
            if match:
                return match.group(1)
        return None

    def _extract_class_name(self, content: str) -> str:
        """Extract the main class name from file content."""
        match = re.search(r'(?:public\s+)?class\s+(\w+)', content)
        return match.group(1) if match else "Unknown"

    def resolve_import(self, import_stmt: str, current_file: Path) -> Optional[ResolvedReference]:
        """Resolve an import statement to its source file."""
        # Extract class name from import
        match = re.search(r'import\s+(?:static\s+)?([\w.]+)(?:\.\*)?;', import_stmt)
        if not match:
            return None

        fqn = match.group(1)
        class_name = fqn.split('.')[-1]

        # Try to find the file
        if fqn in self._class_file_map:
            target_file = self._class_file_map[fqn]
        elif class_name in self._class_file_map:
            target_file = self._class_file_map[class_name]
        else:
            return None

        content = self._read_file(target_file)
        # Get first 50 lines as snippet
        snippet = '\n'.join(content.split('\n')[:50])

        return ResolvedReference(
            source_file=str(current_file),
            source_class="",
            source_method="",
            target_file=str(target_file),
            target_class=class_name,
            target_method=None,
            code_snippet=snippet,
            line_number=1,
            reference_type="import"
        )

    def get_full_class_code(self, file_path: Path) -> str:
        """Get the full class code from a file."""
        return self._read_file(file_path)

    def find_related_methods(self, file_path: Path, method_name: str) -> list[ResolvedReference]:
        """Find other methods in the same class that are related to the given method."""
        content = self._read_file(file_path)
        related = []

        # Find methods called by the target method
        method_pattern = re.compile(
            r'(?:public|private|protected)?\s*(?:static\s+)?'
            r'(?:\w+(?:<[^>]+>)?)\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{',
            re.MULTILINE
        )

        for match in method_pattern.finditer(content):
            found_method = match.group(1)
            if found_method != method_name:
                line_num = content[:match.start()].count('\n') + 1
                # Get method body (up to 30 lines)
                lines = content.split('\n')
                start = line_num - 1
                end = min(len(lines), start + 30)
                snippet = '\n'.join(lines[start:end])

                related.append(ResolvedReference(
                    source_file=str(file_path),
                    source_class=self._extract_class_name(content),
                    source_method=found_method,
                    target_file=str(file_path),
                    target_class=self._extract_class_name(content),
                    target_method=method_name,
                    code_snippet=snippet,
                    line_number=line_num,
                    reference_type="related"
                ))

        return related

    def trace_caller_chain(
        self,
        class_name: str,
        method_name: str,
        max_depth: int = 3,
        visited: Optional[set] = None
    ) -> list[ResolvedReference]:
        """
        Trace the call chain backwards to find entry points (controllers).

        This is critical for detecting false positives where sanitization
        happens upstream in the call chain.

        For example:
        - OrderController.doGet() sanitizes input
        - OrderController.doGet() calls OrderService.findOrder()
        - OrderService.findOrder() calls OrderRepository.findByIdAndCustomer()

        When analyzing OrderRepository, we need to see the full chain back
        to OrderController to detect the sanitization.
        """
        if visited is None:
            visited = set()

        chain = []
        key = f"{class_name}.{method_name}"

        if key in visited or max_depth <= 0:
            return chain

        visited.add(key)

        # Find immediate callers
        callers = self.find_callers(class_name, method_name, max_results=5)

        for caller in callers:
            # Skip self-references
            if caller.source_class == class_name and caller.source_method == method_name:
                continue

            chain.append(caller)

            # Recursively trace the caller's callers
            if caller.source_method and caller.source_method != "unknown":
                upstream = self.trace_caller_chain(
                    caller.source_class,
                    caller.source_method,
                    max_depth - 1,
                    visited
                )
                chain.extend(upstream)

        return chain

    def get_caller_chain_context(self, callers: list[ResolvedReference]) -> str:
        """
        Build a formatted context string showing the full caller chain.

        This helps the LLM understand the data flow from entry point to sink.
        """
        if not callers:
            return ""

        lines = ["## Caller Chain (Data Flow Trace)"]
        lines.append("The following shows how data flows from entry points to this function:\n")

        # Group by depth/level
        seen_methods = set()
        for caller in callers:
            method_key = f"{caller.source_class}.{caller.source_method}"
            if method_key in seen_methods:
                continue
            seen_methods.add(method_key)

            lines.append(f"### {caller.source_class}.{caller.source_method}() at {Path(caller.source_file).name}:{caller.line_number}")
            lines.append("```")
            lines.append(caller.code_snippet)
            lines.append("```\n")

        return "\n".join(lines)

    def resolve_context(
        self,
        file_path: Path,
        class_name: str,
        method_name: str,
        max_callers: int = 5,
        resolve_imports: bool = True,
        trace_call_chain: bool = True
    ) -> CrossFileContext:
        """
        Build comprehensive cross-file context for vulnerability analysis.

        This is the main entry point that:
        1. Finds all callers of the vulnerable function
        2. Traces the full call chain back to entry points
        3. Gets related methods in the same class
        4. Resolves relevant imports
        5. Builds the full class context
        """
        ctx = CrossFileContext()

        # Get full class code
        ctx.full_class_code = self.get_full_class_code(file_path)

        # Find immediate callers
        ctx.callers = self.find_callers(class_name, method_name, max_callers)

        # Trace full call chain if requested (for repository/service layer findings)
        if trace_call_chain:
            call_chain = self.trace_caller_chain(class_name, method_name, max_depth=3)
            # Add unique callers from the chain
            existing_keys = {f"{c.source_class}.{c.source_method}" for c in ctx.callers}
            for caller in call_chain:
                key = f"{caller.source_class}.{caller.source_method}"
                if key not in existing_keys:
                    ctx.callers.append(caller)
                    existing_keys.add(key)

            # Build data flow chain description
            if call_chain:
                ctx.data_flow_chain = [
                    f"{c.source_class}.{c.source_method}()" for c in call_chain
                ]

        # Get related methods
        ctx.related_methods = self.find_related_methods(file_path, method_name)

        # Resolve imports if requested
        if resolve_imports and ctx.full_class_code:
            import_pattern = re.compile(r'import\s+[\w.]+;', re.MULTILINE)
            for match in import_pattern.finditer(ctx.full_class_code):
                ref = self.resolve_import(match.group(0), file_path)
                if ref and 'java.' not in match.group(0) and 'javax.' not in match.group(0):
                    # Only resolve project imports, not JDK
                    ctx.resolved_imports.append(ref)

        return ctx

