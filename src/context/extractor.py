"""
Code Context Extractor - Extracts function and class context from source files.

This module provides the context that the LLM needs to make informed decisions
about whether a finding is a true or false positive.

Architecture:
- Primary: Tree-sitter AST parsing for accurate, production-grade extraction
- Fallback: Regex-based parsing when Tree-sitter is unavailable or fails

The AST-based extraction provides:
- Accurate function/method boundary detection
- Proper handling of nested structures, comments, and strings
- Language-agnostic approach with language-specific grammars
- Better performance for scaled scanning
"""

import re
import os
import logging
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

# Configuration for AST parsing
USE_AST_PARSER = os.getenv("USE_AST_PARSER", "true").lower() in ("true", "1", "yes")
AST_PARSER_FALLBACK = os.getenv("AST_PARSER_FALLBACK", "true").lower() in ("true", "1", "yes")

# Try to import AST parser
_AST_AVAILABLE = False
try:
    from .ast_parser import (
        get_ast_parser_for_file,
        is_tree_sitter_available,
        FunctionInfo as ASTFunctionInfo,
    )
    _AST_AVAILABLE = is_tree_sitter_available()
except ImportError:
    logger.debug("AST parser module not available, using regex-only extraction")
    get_ast_parser_for_file = None
    is_tree_sitter_available = lambda: False
    ASTFunctionInfo = None


@dataclass
class FunctionContext:
    """Context information about a function containing a finding."""
    name: str
    full_code: str
    start_line: int
    end_line: int
    file_path: str
    language: str
    
    @property
    def line_count(self) -> int:
        return self.end_line - self.start_line + 1


@dataclass
class ExtractedContext:
    """Full context extracted for a finding."""
    finding_line: int
    finding_code: str
    function_context: Optional[FunctionContext]
    surrounding_context: str  # Lines before/after if no function found
    file_path: str
    additional_context: dict  # For imports, globals, etc.
    cross_file_context: Optional[dict] = None  # Cross-file references and related code
    full_class_code: Optional[str] = None  # Complete class source for deeper analysis


class ContextExtractor(ABC):
    """Base class for language-specific context extractors."""
    
    @abstractmethod
    def extract_function_at_line(self, source: str, line: int, file_path: str) -> Optional[FunctionContext]:
        """Extract the function containing the given line."""
        pass
    
    def extract_context(
        self,
        file_path: Path,
        finding_line: int,
        context_lines_before: int = 10,
        context_lines_after: int = 10,
    ) -> ExtractedContext:
        """Extract full context for a finding."""
        if not file_path.exists():
            logger.warning(f"File not found: {file_path}")
            return ExtractedContext(
                finding_line=finding_line,
                finding_code="",
                function_context=None,
                surrounding_context="[File not found]",
                file_path=str(file_path),
                additional_context={},
            )
        
        source = file_path.read_text(encoding="utf-8", errors="replace")
        lines = source.split("\n")
        
        # Get the finding line itself
        finding_code = lines[finding_line - 1] if 0 < finding_line <= len(lines) else ""
        
        # Try to extract function context
        function_context = self.extract_function_at_line(source, finding_line, str(file_path))
        
        # Get surrounding context as fallback
        start = max(0, finding_line - context_lines_before - 1)
        end = min(len(lines), finding_line + context_lines_after)
        surrounding = "\n".join(f"{i+1}: {lines[i]}" for i in range(start, end))
        
        return ExtractedContext(
            finding_line=finding_line,
            finding_code=finding_code,
            function_context=function_context,
            surrounding_context=surrounding,
            file_path=str(file_path),
            additional_context=self._extract_additional_context(source, lines),
        )
    
    def _extract_additional_context(self, source: str, lines: list[str]) -> dict:
        """Extract additional context like imports, globals, etc."""
        return {}


class PythonExtractor(ContextExtractor):
    """Context extractor for Python source files.

    Uses Tree-sitter AST parsing for accurate extraction, with regex fallback.
    """

    # Regex to match Python function/method definitions (fallback)
    FUNC_PATTERN = re.compile(
        r'^(\s*)(async\s+)?def\s+(\w+)\s*\([^)]*\)\s*(?:->\s*[^:]+)?\s*:',
        re.MULTILINE
    )

    CLASS_PATTERN = re.compile(
        r'^(\s*)class\s+(\w+)\s*(?:\([^)]*\))?\s*:',
        re.MULTILINE
    )

    def __init__(self):
        self._ast_parser = None
        if USE_AST_PARSER and _AST_AVAILABLE:
            try:
                from .ast_parser import PythonASTParser
                self._ast_parser = PythonASTParser()
            except Exception as e:
                logger.debug(f"Failed to initialize Python AST parser: {e}")

    def extract_function_at_line(self, source: str, line: int, file_path: str) -> Optional[FunctionContext]:
        """Extract Python function containing the given line."""
        # Try AST-based extraction first
        if self._ast_parser and USE_AST_PARSER:
            try:
                func_info = self._ast_parser.find_function_at_line(source, line)
                if func_info:
                    return FunctionContext(
                        name=func_info.name,
                        full_code=func_info.source_code,
                        start_line=func_info.start_line,
                        end_line=func_info.end_line,
                        file_path=file_path,
                        language="python",
                    )
                # AST parsed successfully but no function found at line
                if not AST_PARSER_FALLBACK:
                    return None
            except Exception as e:
                logger.debug(f"AST extraction failed for {file_path}, falling back to regex: {e}")
                if not AST_PARSER_FALLBACK:
                    return None

        # Fallback to regex-based extraction
        return self._extract_function_regex(source, line, file_path)

    def _extract_function_regex(self, source: str, line: int, file_path: str) -> Optional[FunctionContext]:
        """Regex-based function extraction (fallback method)."""
        lines = source.split("\n")

        # Find all function definitions
        functions = []
        for match in self.FUNC_PATTERN.finditer(source):
            func_start = source[:match.start()].count("\n") + 1
            indent = len(match.group(1))
            func_name = match.group(3)

            # Find function end by tracking indentation
            func_end = func_start
            for i in range(func_start, len(lines)):
                curr_line = lines[i]
                if curr_line.strip() and not curr_line.startswith(" " * (indent + 1)) and i > func_start:
                    # Check if it's a continuation or new definition
                    if not curr_line.strip().startswith(("#", "@", "def ", "class ", "async def ")):
                        continue
                    break
                func_end = i + 1

            functions.append((func_start, func_end, func_name, indent))

        # Find which function contains our line
        for start, end, name, indent in functions:
            if start <= line <= end:
                func_lines = lines[start - 1:end]
                return FunctionContext(
                    name=name,
                    full_code="\n".join(func_lines),
                    start_line=start,
                    end_line=end,
                    file_path=file_path,
                    language="python",
                )

        return None

    def _extract_additional_context(self, source: str, lines: list[str]) -> dict:
        """Extract imports and globals for Python."""
        imports = []
        for line in lines[:50]:  # Check first 50 lines for imports
            stripped = line.strip()
            if stripped.startswith(("import ", "from ")):
                imports.append(stripped)
        return {"imports": imports}


class JavaScriptExtractor(ContextExtractor):
    """Context extractor for JavaScript/TypeScript source files.

    Uses Tree-sitter AST parsing for accurate extraction, with regex fallback.
    """

    # Patterns for JS/TS functions (fallback)
    FUNC_PATTERNS = [
        re.compile(r'^(\s*)(?:async\s+)?function\s+(\w+)\s*\([^)]*\)', re.MULTILINE),
        re.compile(r'^(\s*)(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>', re.MULTILINE),
        re.compile(r'^(\s*)(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function', re.MULTILINE),
        re.compile(r'^(\s*)(\w+)\s*\([^)]*\)\s*{', re.MULTILINE),  # Method shorthand
    ]

    def __init__(self):
        self._ast_parser = None
        if USE_AST_PARSER and _AST_AVAILABLE:
            try:
                from .ast_parser import JavaScriptASTParser
                self._ast_parser = JavaScriptASTParser()
            except Exception as e:
                logger.debug(f"Failed to initialize JavaScript AST parser: {e}")

    def extract_function_at_line(self, source: str, line: int, file_path: str) -> Optional[FunctionContext]:
        """Extract JavaScript function containing the given line."""
        # Try AST-based extraction first
        if self._ast_parser and USE_AST_PARSER:
            try:
                func_info = self._ast_parser.find_function_at_line(source, line)
                if func_info:
                    return FunctionContext(
                        name=func_info.name,
                        full_code=func_info.source_code,
                        start_line=func_info.start_line,
                        end_line=func_info.end_line,
                        file_path=file_path,
                        language="javascript",
                    )
                if not AST_PARSER_FALLBACK:
                    return None
            except Exception as e:
                logger.debug(f"AST extraction failed for {file_path}, falling back to regex: {e}")
                if not AST_PARSER_FALLBACK:
                    return None

        # Fallback to regex-based extraction
        return self._extract_function_regex(source, line, file_path)

    def _extract_function_regex(self, source: str, line: int, file_path: str) -> Optional[FunctionContext]:
        """Regex-based function extraction (fallback method)."""
        lines = source.split("\n")

        # Find all function definitions
        functions = []
        for pattern in self.FUNC_PATTERNS:
            for match in pattern.finditer(source):
                func_start = source[:match.start()].count("\n") + 1
                func_name = match.group(2)

                # Find function end by counting braces
                func_end = self._find_block_end(lines, func_start - 1)
                functions.append((func_start, func_end, func_name))

        # Find which function contains our line
        for start, end, name in functions:
            if start <= line <= end:
                func_lines = lines[start - 1:end]
                return FunctionContext(
                    name=name,
                    full_code="\n".join(func_lines),
                    start_line=start,
                    end_line=end,
                    file_path=file_path,
                    language="javascript",
                )

        return None

    def _find_block_end(self, lines: list[str], start_idx: int) -> int:
        """Find the end of a brace-delimited block."""
        brace_count = 0
        started = False

        for i in range(start_idx, len(lines)):
            line = lines[i]
            for char in line:
                if char == '{':
                    brace_count += 1
                    started = True
                elif char == '}':
                    brace_count -= 1

            if started and brace_count == 0:
                return i + 1

        return len(lines)


class JavaExtractor(ContextExtractor):
    """Context extractor for Java source files.

    Uses Tree-sitter AST parsing for accurate extraction, with regex fallback.
    """

    # Pattern to match Java method definitions (fallback)
    METHOD_PATTERN = re.compile(
        r'^(\s*)(?:(?:public|private|protected|static|final|abstract|synchronized|native)\s+)*'
        r'(?:<[^>]+>\s+)?'  # Generic type parameters
        r'(\w+(?:<[^>]+>)?(?:\[\])*)\s+'  # Return type
        r'(\w+)\s*\([^)]*\)\s*'  # Method name and parameters
        r'(?:throws\s+[\w,\s]+)?\s*\{',  # Optional throws clause
        re.MULTILINE
    )

    # Pattern to match class definitions
    CLASS_PATTERN = re.compile(
        r'^(\s*)(?:(?:public|private|protected|static|final|abstract)\s+)*'
        r'class\s+(\w+)(?:<[^>]+>)?'
        r'(?:\s+extends\s+\w+(?:<[^>]+>)?)?'
        r'(?:\s+implements\s+[\w,\s<>]+)?\s*\{',
        re.MULTILINE
    )

    def __init__(self):
        self._ast_parser = None
        if USE_AST_PARSER and _AST_AVAILABLE:
            try:
                from .ast_parser import JavaASTParser
                self._ast_parser = JavaASTParser()
            except Exception as e:
                logger.debug(f"Failed to initialize Java AST parser: {e}")

    def extract_function_at_line(self, source: str, line: int, file_path: str) -> Optional[FunctionContext]:
        """Extract Java method containing the given line."""
        # Try AST-based extraction first
        if self._ast_parser and USE_AST_PARSER:
            try:
                func_info = self._ast_parser.find_function_at_line(source, line)
                if func_info:
                    return FunctionContext(
                        name=func_info.name,
                        full_code=func_info.source_code,
                        start_line=func_info.start_line,
                        end_line=func_info.end_line,
                        file_path=file_path,
                        language="java",
                    )
                if not AST_PARSER_FALLBACK:
                    return None
            except Exception as e:
                logger.debug(f"AST extraction failed for {file_path}, falling back to regex: {e}")
                if not AST_PARSER_FALLBACK:
                    return None

        # Fallback to regex-based extraction
        return self._extract_function_regex(source, line, file_path)

    def _extract_function_regex(self, source: str, line: int, file_path: str) -> Optional[FunctionContext]:
        """Regex-based function extraction (fallback method)."""
        lines = source.split("\n")

        # Find all method definitions
        methods = []
        for match in self.METHOD_PATTERN.finditer(source):
            method_start = source[:match.start()].count("\n") + 1
            method_name = match.group(3)

            # Find method end by counting braces
            method_end = self._find_block_end(lines, method_start - 1)
            methods.append((method_start, method_end, method_name))

        # Find which method contains our line
        for start, end, name in methods:
            if start <= line <= end:
                # Include annotations above the method
                actual_start = start
                for i in range(start - 2, -1, -1):
                    stripped = lines[i].strip()
                    if stripped.startswith("@") or stripped == "":
                        actual_start = i + 1
                    else:
                        break

                method_lines = lines[actual_start - 1:end]
                return FunctionContext(
                    name=name,
                    full_code="\n".join(method_lines),
                    start_line=actual_start,
                    end_line=end,
                    file_path=file_path,
                    language="java",
                )

        return None

    def _find_block_end(self, lines: list[str], start_idx: int) -> int:
        """Find the end of a brace-delimited block."""
        brace_count = 0
        started = False
        in_string = False
        in_char = False
        in_comment = False
        in_multiline_comment = False

        for i in range(start_idx, len(lines)):
            line = lines[i]
            j = 0
            while j < len(line):
                char = line[j]
                prev_char = line[j-1] if j > 0 else ''
                next_char = line[j+1] if j < len(line) - 1 else ''

                # Handle comments
                if not in_string and not in_char:
                    if char == '/' and next_char == '/':
                        break  # Rest of line is comment
                    if char == '/' and next_char == '*':
                        in_multiline_comment = True
                        j += 2
                        continue
                    if char == '*' and next_char == '/' and in_multiline_comment:
                        in_multiline_comment = False
                        j += 2
                        continue

                if in_multiline_comment:
                    j += 1
                    continue

                # Handle strings
                if char == '"' and prev_char != '\\':
                    in_string = not in_string
                if char == "'" and prev_char != '\\' and not in_string:
                    in_char = not in_char

                if not in_string and not in_char:
                    if char == '{':
                        brace_count += 1
                        started = True
                    elif char == '}':
                        brace_count -= 1

                j += 1

            if started and brace_count == 0:
                return i + 1

        return len(lines)

    def _extract_additional_context(self, source: str, lines: list[str]) -> dict:
        """Extract imports, class info, and all method signatures for Java."""
        imports = []
        package = ""
        class_name = ""
        methods = []
        class_fields = []

        for line in lines[:100]:
            stripped = line.strip()
            if stripped.startswith("package "):
                package = stripped
            elif stripped.startswith("import "):
                imports.append(stripped)
            elif "class " in stripped and not stripped.startswith("//"):
                match = self.CLASS_PATTERN.match(line)
                if match:
                    class_name = match.group(2)

        # Extract all method signatures
        for match in self.METHOD_PATTERN.finditer(source):
            method_name = match.group(3)
            method_start = source[:match.start()].count("\n") + 1
            methods.append({"name": method_name, "line": method_start})

        # Extract class fields (instance variables)
        field_pattern = re.compile(
            r'^\s*(?:private|protected|public)?\s*(?:static\s+)?(?:final\s+)?'
            r'(\w+(?:<[^>]+>)?(?:\[\])*)\s+(\w+)\s*[;=]',
            re.MULTILINE
        )
        for match in field_pattern.finditer(source):
            field_type = match.group(1)
            field_name = match.group(2)
            # Skip method parameters (inside parentheses)
            line_start = source[:match.start()].rfind('\n')
            line_content = source[line_start:match.end()]
            if '(' not in line_content or ')' in line_content[:line_content.find('(')]:
                class_fields.append({"type": field_type, "name": field_name})

        return {
            "imports": imports,
            "package": package,
            "class_name": class_name,
            "methods": methods,
            "class_fields": class_fields[:20],  # Limit to first 20 fields
        }


class GenericExtractor(ContextExtractor):
    """Generic extractor for unsupported languages - just provides surrounding context."""

    def extract_function_at_line(self, source: str, line: int, file_path: str) -> Optional[FunctionContext]:
        """No function extraction for generic files."""
        return None


# =============================================================================
# EXTRACTOR CACHE - Singleton instances for scaled scanning
# =============================================================================

_extractor_cache: dict[str, ContextExtractor] = {}
_extractor_lock = __import__("threading").Lock()


def get_extractor_for_file(file_path: Path) -> ContextExtractor:
    """
    Get the appropriate extractor for a file based on its extension.

    Extractors are cached as singletons for efficiency during scaled scanning.
    Each extractor maintains its own AST parser instance.

    Args:
        file_path: Path to the source file

    Returns:
        ContextExtractor instance for the file's language
    """
    suffix = file_path.suffix.lower()

    # Check cache first
    if suffix in _extractor_cache:
        return _extractor_cache[suffix]

    # Create extractor with lock for thread safety
    with _extractor_lock:
        # Double-check after acquiring lock
        if suffix in _extractor_cache:
            return _extractor_cache[suffix]

        extractor_classes = {
            ".py": PythonExtractor,
            ".js": JavaScriptExtractor,
            ".jsx": JavaScriptExtractor,
            ".ts": JavaScriptExtractor,
            ".tsx": JavaScriptExtractor,
            ".mjs": JavaScriptExtractor,
            ".java": JavaExtractor,
        }

        extractor_class = extractor_classes.get(suffix)
        if extractor_class:
            extractor = extractor_class()
            _extractor_cache[suffix] = extractor
            return extractor

        # Return generic extractor (not cached, as it's stateless)
        return GenericExtractor()


def clear_extractor_cache() -> None:
    """Clear the extractor cache. Useful for testing."""
    global _extractor_cache
    with _extractor_lock:
        _extractor_cache.clear()


def get_extraction_stats() -> dict:
    """Get statistics about the extraction system."""
    return {
        "ast_available": _AST_AVAILABLE,
        "ast_enabled": USE_AST_PARSER,
        "fallback_enabled": AST_PARSER_FALLBACK,
        "cached_extractors": list(_extractor_cache.keys()),
    }

