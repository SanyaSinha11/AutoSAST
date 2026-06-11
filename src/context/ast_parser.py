"""
AST Parser - Production-grade Tree-sitter based code parsing.

This module provides high-performance, accurate code extraction using Tree-sitter
AST parsing. It supports Python, Java, and JavaScript/TypeScript with graceful
fallback to regex-based parsing when Tree-sitter is unavailable.

Features:
- Thread-safe parser caching for scaled scanning
- Lazy language loading to minimize memory footprint
- Binary search for efficient function lookup
- Comprehensive error handling and logging
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from threading import Lock
from typing import Optional, Union

logger = logging.getLogger(__name__)

# Try to import tree-sitter components
_TREE_SITTER_AVAILABLE = False
try:
    from tree_sitter import Language, Parser, Query, Node, Tree
    _TREE_SITTER_AVAILABLE = True
except ImportError:
    logger.warning("tree-sitter not installed. AST parsing will be disabled.")
    Language = None
    Parser = None
    Query = None
    Node = None
    Tree = None


def is_tree_sitter_available() -> bool:
    """Check if Tree-sitter is available for use."""
    return _TREE_SITTER_AVAILABLE


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class FunctionInfo:
    """Information about a function/method extracted from AST."""
    name: str
    start_line: int  # 1-indexed
    end_line: int    # 1-indexed, inclusive
    start_byte: int
    end_byte: int
    parameters: list[str] = field(default_factory=list)
    return_type: Optional[str] = None
    decorators: list[str] = field(default_factory=list)  # Python @decorator
    annotations: list[str] = field(default_factory=list)  # Java @Override
    modifiers: list[str] = field(default_factory=list)    # public/private/static
    class_name: Optional[str] = None  # Containing class
    source_code: str = ""  # Full source of the function
    is_async: bool = False
    is_constructor: bool = False
    
    def contains_line(self, line: int) -> bool:
        """Check if this function contains the given line (1-indexed)."""
        return self.start_line <= line <= self.end_line


@dataclass
class ClassInfo:
    """Information about a class extracted from AST."""
    name: str
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int
    methods: list[FunctionInfo] = field(default_factory=list)
    parent_class: Optional[str] = None
    interfaces: list[str] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)
    source_code: str = ""
    
    def contains_line(self, line: int) -> bool:
        """Check if this class contains the given line."""
        return self.start_line <= line <= self.end_line


@dataclass
class CallInfo:
    """Information about a function/method call site."""
    caller_function: Optional[str]
    callee_name: str
    line: int
    column: int
    object_name: Optional[str] = None  # For method calls: obj.method()
    arguments: list[str] = field(default_factory=list)
    file_path: str = ""


@dataclass
class ImportInfo:
    """Information about an import statement."""
    module: str
    names: list[str] = field(default_factory=list)
    alias: Optional[str] = None
    line: int = 0
    is_wildcard: bool = False


# =============================================================================
# LANGUAGE LOADER - Thread-safe lazy loading of language grammars
# =============================================================================

class LanguageLoader:
    """
    Thread-safe lazy loader for Tree-sitter language grammars.
    
    Languages are loaded on first use and cached for subsequent calls.
    This minimizes memory usage and startup time for scaled scanning.
    """
    
    _languages: dict[str, "Language"] = {}
    _lock = Lock()
    
    @classmethod
    def get_language(cls, lang_name: str) -> Optional["Language"]:
        """
        Get a Tree-sitter Language object for the given language.
        
        Args:
            lang_name: One of 'python', 'java', 'javascript'
            
        Returns:
            Language object or None if not available
        """
        if not _TREE_SITTER_AVAILABLE:
            return None
            
        if lang_name in cls._languages:
            return cls._languages[lang_name]
            
        with cls._lock:
            # Double-check after acquiring lock
            if lang_name in cls._languages:
                return cls._languages[lang_name]
                
            try:
                language = cls._load_language(lang_name)
                if language:
                    cls._languages[lang_name] = language
                return language
            except Exception as e:
                logger.warning(f"Failed to load Tree-sitter language '{lang_name}': {e}")
                return None

    @staticmethod
    def _load_language(lang_name: str) -> Optional["Language"]:
        """Load a specific language grammar."""
        if lang_name == "python":
            import tree_sitter_python
            return Language(tree_sitter_python.language())
        elif lang_name == "java":
            import tree_sitter_java
            return Language(tree_sitter_java.language())
        elif lang_name in ("javascript", "typescript"):
            import tree_sitter_javascript
            return Language(tree_sitter_javascript.language())
        else:
            logger.warning(f"Unsupported language: {lang_name}")
            return None


# =============================================================================
# BASE AST PARSER
# =============================================================================

class ASTParser(ABC):
    """
    Abstract base class for language-specific AST parsers.

    Provides common functionality for parsing source code and extracting
    functions, classes, and call sites using Tree-sitter.
    """

    def __init__(self, language_name: str):
        self.language_name = language_name
        self._parser: Optional["Parser"] = None
        self._language: Optional["Language"] = None
        self._queries: dict[str, "Query"] = {}
        self._initialized = False
        self._init_lock = Lock()

    def _ensure_initialized(self) -> bool:
        """Lazily initialize the parser. Returns True if successful."""
        if self._initialized:
            return self._parser is not None

        with self._init_lock:
            if self._initialized:
                return self._parser is not None

            self._language = LanguageLoader.get_language(self.language_name)
            if self._language:
                self._parser = Parser(self._language)
                self._init_queries()
            self._initialized = True
            return self._parser is not None

    def _init_queries(self) -> None:
        """Initialize Tree-sitter queries for this language."""
        from .ast_queries import LANGUAGE_QUERIES

        queries = LANGUAGE_QUERIES.get(self.language_name, {})
        for query_type, query_str in queries.items():
            try:
                self._queries[query_type] = Query(self._language, query_str)
            except Exception as e:
                logger.warning(f"Failed to compile {query_type} query for {self.language_name}: {e}")

    def parse(self, source: Union[str, bytes], encoding: str = "utf-8") -> Optional["Tree"]:
        """
        Parse source code into an AST.

        Args:
            source: Source code as string or bytes
            encoding: Encoding for string sources (default: utf-8)

        Returns:
            Tree object or None if parsing failed
        """
        if not self._ensure_initialized():
            return None

        if isinstance(source, str):
            source = source.encode(encoding)

        try:
            return self._parser.parse(source)
        except Exception as e:
            logger.warning(f"Failed to parse source: {e}")
            return None

    def parse_file(self, file_path: Path) -> Optional["Tree"]:
        """Parse a file into an AST."""
        try:
            content = file_path.read_bytes()
            return self.parse(content)
        except Exception as e:
            logger.warning(f"Failed to read/parse file {file_path}: {e}")
            return None

    @abstractmethod
    def extract_functions(self, source: Union[str, bytes]) -> list[FunctionInfo]:
        """Extract all function definitions from source code."""
        pass

    @abstractmethod
    def extract_classes(self, source: Union[str, bytes]) -> list[ClassInfo]:
        """Extract all class definitions from source code."""
        pass

    @abstractmethod
    def extract_calls(self, source: Union[str, bytes]) -> list[CallInfo]:
        """Extract all function/method calls from source code."""
        pass

    def find_function_at_line(self, source: Union[str, bytes], line: int) -> Optional[FunctionInfo]:
        """
        Find the function containing the given line using binary search.

        Args:
            source: Source code
            line: Line number (1-indexed)

        Returns:
            FunctionInfo if found, None otherwise
        """
        functions = self.extract_functions(source)
        if not functions:
            return None

        # Sort by start_line for binary search
        functions.sort(key=lambda f: f.start_line)

        # Binary search for the containing function
        left, right = 0, len(functions) - 1
        result = None

        while left <= right:
            mid = (left + right) // 2
            func = functions[mid]

            if func.start_line <= line <= func.end_line:
                # Found a containing function, but there might be nested ones
                result = func
                # Look for more specific (nested) function
                left = mid + 1
            elif func.start_line > line:
                right = mid - 1
            else:
                left = mid + 1

        # Check for nested functions - find the most specific one
        if result:
            for func in functions:
                if (func.contains_line(line) and
                    func.start_line >= result.start_line and
                    func.end_line <= result.end_line and
                    func != result):
                    result = func

        return result

    def _get_node_text(self, node: "Node", source: bytes) -> str:
        """Extract the text of a node from source bytes."""
        return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    def _node_to_line(self, node: "Node") -> int:
        """Convert node's start point to 1-indexed line number."""
        return node.start_point[0] + 1

    def _node_end_line(self, node: "Node") -> int:
        """Get the 1-indexed end line of a node."""
        return node.end_point[0] + 1


# =============================================================================
# PYTHON AST PARSER
# =============================================================================

class PythonASTParser(ASTParser):
    """AST parser for Python source code."""

    def __init__(self):
        super().__init__("python")

    def extract_functions(self, source: Union[str, bytes]) -> list[FunctionInfo]:
        """Extract all function definitions from Python source."""
        if isinstance(source, str):
            source_bytes = source.encode("utf-8")
        else:
            source_bytes = source

        tree = self.parse(source_bytes)
        if not tree:
            return []

        functions = []
        query = self._queries.get("function")
        if not query:
            return self._extract_functions_manual(tree.root_node, source_bytes)

        # Execute query
        captures = self._execute_query(query, tree.root_node)

        # Group captures by function node
        function_captures = {}
        for name, nodes in captures.items():
            for node in nodes:
                # Find parent function node
                func_node = self._find_parent_function(node)
                if func_node:
                    if func_node.id not in function_captures:
                        function_captures[func_node.id] = {"node": func_node}
                    function_captures[func_node.id][name] = node

        # Build FunctionInfo objects
        for func_id, captured in function_captures.items():
            func_node = captured["node"]
            name_node = captured.get("name")
            params_node = captured.get("params")
            body_node = captured.get("body")
            return_type_node = captured.get("return_type")

            if not name_node:
                continue

            # Get decorators
            decorators = []
            decorator_nodes = captured.get("decorator", [])
            if isinstance(decorator_nodes, list):
                for dec_node in decorator_nodes:
                    decorators.append(self._get_node_text(dec_node, source_bytes))

            # Determine start line (include decorators if present)
            start_line = self._node_to_line(func_node)

            # Check for decorated_definition parent
            parent = func_node.parent
            if parent and parent.type == "decorated_definition":
                start_line = self._node_to_line(parent)
                func_node = parent

            func_info = FunctionInfo(
                name=self._get_node_text(name_node, source_bytes),
                start_line=start_line,
                end_line=self._node_end_line(func_node),
                start_byte=func_node.start_byte,
                end_byte=func_node.end_byte,
                parameters=self._extract_python_params(params_node, source_bytes) if params_node else [],
                return_type=self._get_node_text(return_type_node, source_bytes) if return_type_node else None,
                decorators=decorators,
                source_code=self._get_node_text(func_node, source_bytes),
                is_async=self._is_async_python_function(func_node),
                class_name=self._find_containing_class_name(func_node, source_bytes),
            )
            functions.append(func_info)

        # Fallback to manual extraction if query didn't work
        if not functions:
            functions = self._extract_functions_manual(tree.root_node, source_bytes)

        return functions

    def _extract_functions_manual(self, root: "Node", source: bytes) -> list[FunctionInfo]:
        """Manual tree traversal to extract functions (fallback)."""
        functions = []

        def visit(node: "Node", class_name: Optional[str] = None):
            if node.type == "function_definition":
                name_node = node.child_by_field_name("name")
                if name_node:
                    # Check for decorated parent
                    actual_node = node
                    parent = node.parent
                    if parent and parent.type == "decorated_definition":
                        actual_node = parent

                    functions.append(FunctionInfo(
                        name=self._get_node_text(name_node, source),
                        start_line=self._node_to_line(actual_node),
                        end_line=self._node_end_line(actual_node),
                        start_byte=actual_node.start_byte,
                        end_byte=actual_node.end_byte,
                        source_code=self._get_node_text(actual_node, source),
                        class_name=class_name,
                    ))
            elif node.type == "class_definition":
                name_node = node.child_by_field_name("name")
                new_class_name = self._get_node_text(name_node, source) if name_node else None
                for child in node.children:
                    visit(child, new_class_name)
                return

            for child in node.children:
                visit(child, class_name)

        visit(root)
        return functions

    def _find_parent_function(self, node: "Node") -> Optional["Node"]:
        """Find the parent function_definition or decorated_definition node."""
        current = node
        while current:
            if current.type in ("function_definition", "decorated_definition"):
                return current
            current = current.parent
        return None

    def _is_async_python_function(self, node: "Node") -> bool:
        """Check if a function is async."""
        for child in node.children:
            if child.type == "async":
                return True
        # Check the function_definition inside decorated_definition
        if node.type == "decorated_definition":
            for child in node.children:
                if child.type == "function_definition":
                    return self._is_async_python_function(child)
        return False

    def _extract_python_params(self, params_node: "Node", source: bytes) -> list[str]:
        """Extract parameter names from a parameters node."""
        params = []
        for child in params_node.children:
            if child.type in ("identifier", "typed_parameter", "default_parameter"):
                if child.type == "identifier":
                    params.append(self._get_node_text(child, source))
                else:
                    name_child = child.child_by_field_name("name")
                    if name_child:
                        params.append(self._get_node_text(name_child, source))
        return params

    def _find_containing_class_name(self, node: "Node", source: bytes) -> Optional[str]:
        """Find the name of the class containing this node."""
        current = node.parent
        while current:
            if current.type == "class_definition":
                name_node = current.child_by_field_name("name")
                if name_node:
                    return self._get_node_text(name_node, source)
            current = current.parent
        return None

    def _execute_query(self, query: "Query", root: "Node") -> dict[str, list["Node"]]:
        """Execute a query and return captures grouped by name."""
        try:
            from tree_sitter import QueryCursor
            cursor = QueryCursor(query)
            return cursor.captures(root)
        except Exception as e:
            logger.warning(f"Query execution failed: {e}")
            return {}

    def extract_classes(self, source: Union[str, bytes]) -> list[ClassInfo]:
        """Extract all class definitions from Python source."""
        if isinstance(source, str):
            source_bytes = source.encode("utf-8")
        else:
            source_bytes = source

        tree = self.parse(source_bytes)
        if not tree:
            return []

        classes = []

        def visit(node: "Node"):
            if node.type == "class_definition":
                name_node = node.child_by_field_name("name")
                if name_node:
                    # Check for decorated parent
                    actual_node = node
                    parent = node.parent
                    if parent and parent.type == "decorated_definition":
                        actual_node = parent

                    # Extract superclasses
                    parent_class = None
                    superclasses = node.child_by_field_name("superclasses")
                    if superclasses and superclasses.named_child_count > 0:
                        first_super = superclasses.named_children[0]
                        parent_class = self._get_node_text(first_super, source_bytes)

                    # Extract methods
                    methods = []
                    body = node.child_by_field_name("body")
                    if body:
                        for child in body.children:
                            if child.type == "function_definition":
                                fn_name = child.child_by_field_name("name")
                                if fn_name:
                                    methods.append(FunctionInfo(
                                        name=self._get_node_text(fn_name, source_bytes),
                                        start_line=self._node_to_line(child),
                                        end_line=self._node_end_line(child),
                                        start_byte=child.start_byte,
                                        end_byte=child.end_byte,
                                        source_code=self._get_node_text(child, source_bytes),
                                        class_name=self._get_node_text(name_node, source_bytes),
                                    ))

                    classes.append(ClassInfo(
                        name=self._get_node_text(name_node, source_bytes),
                        start_line=self._node_to_line(actual_node),
                        end_line=self._node_end_line(actual_node),
                        start_byte=actual_node.start_byte,
                        end_byte=actual_node.end_byte,
                        methods=methods,
                        parent_class=parent_class,
                        source_code=self._get_node_text(actual_node, source_bytes),
                    ))

            for child in node.children:
                visit(child)

        visit(tree.root_node)
        return classes

    def extract_calls(self, source: Union[str, bytes]) -> list[CallInfo]:
        """Extract all function/method calls from Python source."""
        if isinstance(source, str):
            source_bytes = source.encode("utf-8")
        else:
            source_bytes = source

        tree = self.parse(source_bytes)
        if not tree:
            return []

        calls = []

        def visit(node: "Node", current_function: Optional[str] = None):
            # Track current function
            if node.type == "function_definition":
                name_node = node.child_by_field_name("name")
                if name_node:
                    current_function = self._get_node_text(name_node, source_bytes)

            if node.type == "call":
                func = node.child_by_field_name("function")
                if func:
                    if func.type == "identifier":
                        calls.append(CallInfo(
                            caller_function=current_function,
                            callee_name=self._get_node_text(func, source_bytes),
                            line=self._node_to_line(node),
                            column=node.start_point[1],
                        ))
                    elif func.type == "attribute":
                        obj = func.child_by_field_name("object")
                        attr = func.child_by_field_name("attribute")
                        if attr:
                            calls.append(CallInfo(
                                caller_function=current_function,
                                callee_name=self._get_node_text(attr, source_bytes),
                                object_name=self._get_node_text(obj, source_bytes) if obj else None,
                                line=self._node_to_line(node),
                                column=node.start_point[1],
                            ))

            for child in node.children:
                visit(child, current_function)

        visit(tree.root_node)
        return calls


# =============================================================================
# JAVA AST PARSER
# =============================================================================

class JavaASTParser(ASTParser):
    """AST parser for Java source code."""

    def __init__(self):
        super().__init__("java")

    def extract_functions(self, source: Union[str, bytes]) -> list[FunctionInfo]:
        """Extract all method definitions from Java source."""
        if isinstance(source, str):
            source_bytes = source.encode("utf-8")
        else:
            source_bytes = source

        tree = self.parse(source_bytes)
        if not tree:
            return []

        methods = []

        def visit(node: "Node", class_name: Optional[str] = None):
            # Track class context
            if node.type in ("class_declaration", "interface_declaration", "enum_declaration"):
                name_node = node.child_by_field_name("name")
                new_class_name = self._get_node_text(name_node, source_bytes) if name_node else None
                for child in node.children:
                    visit(child, new_class_name)
                return

            if node.type in ("method_declaration", "constructor_declaration"):
                name_node = node.child_by_field_name("name")
                if name_node:
                    # Extract modifiers and annotations
                    modifiers = []
                    annotations = []
                    modifiers_node = None

                    for child in node.children:
                        if child.type == "modifiers":
                            modifiers_node = child
                            break

                    if modifiers_node:
                        for mod_child in modifiers_node.children:
                            if mod_child.type in ("marker_annotation", "annotation"):
                                annotations.append(self._get_node_text(mod_child, source_bytes))
                            elif mod_child.is_named:
                                modifiers.append(self._get_node_text(mod_child, source_bytes))
                            elif not mod_child.is_named:
                                # Keywords like public, private, static
                                mod_text = self._get_node_text(mod_child, source_bytes)
                                if mod_text in ("public", "private", "protected", "static",
                                               "final", "abstract", "synchronized", "native"):
                                    modifiers.append(mod_text)

                    # Get return type
                    return_type = None
                    type_node = node.child_by_field_name("type")
                    if type_node:
                        return_type = self._get_node_text(type_node, source_bytes)

                    # Get parameters
                    params = []
                    params_node = node.child_by_field_name("parameters")
                    if params_node:
                        params = self._extract_java_params(params_node, source_bytes)

                    # Determine the start line (include annotations)
                    start_line = self._node_to_line(node)
                    if modifiers_node and annotations:
                        start_line = self._node_to_line(modifiers_node)

                    methods.append(FunctionInfo(
                        name=self._get_node_text(name_node, source_bytes),
                        start_line=start_line,
                        end_line=self._node_end_line(node),
                        start_byte=node.start_byte,
                        end_byte=node.end_byte,
                        parameters=params,
                        return_type=return_type,
                        annotations=annotations,
                        modifiers=modifiers,
                        class_name=class_name,
                        source_code=self._get_node_text(node, source_bytes),
                        is_constructor=(node.type == "constructor_declaration"),
                    ))

            for child in node.children:
                visit(child, class_name)

        visit(tree.root_node)
        return methods

    def _extract_java_params(self, params_node: "Node", source: bytes) -> list[str]:
        """Extract parameter names from formal_parameters node."""
        params = []
        for child in params_node.children:
            if child.type == "formal_parameter":
                name_node = child.child_by_field_name("name")
                if name_node:
                    params.append(self._get_node_text(name_node, source))
            elif child.type == "spread_parameter":
                name_node = child.child_by_field_name("name")
                if name_node:
                    params.append("..." + self._get_node_text(name_node, source))
        return params

    def extract_classes(self, source: Union[str, bytes]) -> list[ClassInfo]:
        """Extract all class definitions from Java source."""
        if isinstance(source, str):
            source_bytes = source.encode("utf-8")
        else:
            source_bytes = source

        tree = self.parse(source_bytes)
        if not tree:
            return []

        classes = []

        def visit(node: "Node"):
            if node.type in ("class_declaration", "interface_declaration", "enum_declaration"):
                name_node = node.child_by_field_name("name")
                if name_node:
                    class_name = self._get_node_text(name_node, source_bytes)

                    # Extract modifiers
                    modifiers = []
                    for child in node.children:
                        if child.type == "modifiers":
                            for mod in child.children:
                                if not mod.is_named:
                                    modifiers.append(self._get_node_text(mod, source_bytes))

                    # Extract superclass
                    parent_class = None
                    superclass = node.child_by_field_name("superclass")
                    if superclass:
                        for child in superclass.children:
                            if child.type == "type_identifier":
                                parent_class = self._get_node_text(child, source_bytes)
                                break

                    # Extract interfaces
                    interfaces = []
                    ifaces = node.child_by_field_name("interfaces")
                    if ifaces:
                        for child in ifaces.named_children:
                            if child.type in ("type_identifier", "type_list"):
                                interfaces.append(self._get_node_text(child, source_bytes))

                    # Extract methods
                    methods = []
                    body = node.child_by_field_name("body")
                    if body:
                        for child in body.children:
                            if child.type in ("method_declaration", "constructor_declaration"):
                                fn_name = child.child_by_field_name("name")
                                if fn_name:
                                    methods.append(FunctionInfo(
                                        name=self._get_node_text(fn_name, source_bytes),
                                        start_line=self._node_to_line(child),
                                        end_line=self._node_end_line(child),
                                        start_byte=child.start_byte,
                                        end_byte=child.end_byte,
                                        source_code=self._get_node_text(child, source_bytes),
                                        class_name=class_name,
                                    ))

                    classes.append(ClassInfo(
                        name=class_name,
                        start_line=self._node_to_line(node),
                        end_line=self._node_end_line(node),
                        start_byte=node.start_byte,
                        end_byte=node.end_byte,
                        methods=methods,
                        parent_class=parent_class,
                        interfaces=interfaces,
                        modifiers=modifiers,
                        source_code=self._get_node_text(node, source_bytes),
                    ))

            for child in node.children:
                visit(child)

        visit(tree.root_node)
        return classes

    def extract_calls(self, source: Union[str, bytes]) -> list[CallInfo]:
        """Extract all method calls from Java source."""
        if isinstance(source, str):
            source_bytes = source.encode("utf-8")
        else:
            source_bytes = source

        tree = self.parse(source_bytes)
        if not tree:
            return []

        calls = []

        def find_containing_method(node: "Node") -> Optional[str]:
            """Walk up the tree to find the containing method."""
            current = node.parent
            while current:
                if current.type in ("method_declaration", "constructor_declaration"):
                    name_node = current.child_by_field_name("name")
                    if name_node:
                        return self._get_node_text(name_node, source_bytes)
                current = current.parent
            return None

        def visit(node: "Node"):
            if node.type == "method_invocation":
                name_node = node.child_by_field_name("name")
                obj_node = node.child_by_field_name("object")

                if name_node:
                    calls.append(CallInfo(
                        caller_function=find_containing_method(node),
                        callee_name=self._get_node_text(name_node, source_bytes),
                        object_name=self._get_node_text(obj_node, source_bytes) if obj_node else None,
                        line=self._node_to_line(node),
                        column=node.start_point[1],
                    ))

            elif node.type == "object_creation_expression":
                type_node = node.child_by_field_name("type")
                if type_node:
                    calls.append(CallInfo(
                        caller_function=find_containing_method(node),
                        callee_name=self._get_node_text(type_node, source_bytes),
                        line=self._node_to_line(node),
                        column=node.start_point[1],
                    ))

            for child in node.children:
                visit(child)

        visit(tree.root_node)
        return calls


# =============================================================================
# JAVASCRIPT/TYPESCRIPT AST PARSER
# =============================================================================

class JavaScriptASTParser(ASTParser):
    """AST parser for JavaScript/TypeScript source code."""

    def __init__(self):
        super().__init__("javascript")

    def extract_functions(self, source: Union[str, bytes]) -> list[FunctionInfo]:
        """Extract all function definitions from JavaScript source."""
        if isinstance(source, str):
            source_bytes = source.encode("utf-8")
        else:
            source_bytes = source

        tree = self.parse(source_bytes)
        if not tree:
            return []

        functions = []

        def visit(node: "Node", class_name: Optional[str] = None):
            # Track class context
            if node.type == "class_declaration":
                name_node = node.child_by_field_name("name")
                new_class_name = self._get_node_text(name_node, source_bytes) if name_node else None
                for child in node.children:
                    visit(child, new_class_name)
                return

            # Function declarations
            if node.type == "function_declaration":
                name_node = node.child_by_field_name("name")
                if name_node:
                    is_async = any(c.type == "async" for c in node.children if not c.is_named)
                    functions.append(FunctionInfo(
                        name=self._get_node_text(name_node, source_bytes),
                        start_line=self._node_to_line(node),
                        end_line=self._node_end_line(node),
                        start_byte=node.start_byte,
                        end_byte=node.end_byte,
                        source_code=self._get_node_text(node, source_bytes),
                        class_name=class_name,
                        is_async=is_async,
                    ))

            # Generator function declarations
            elif node.type == "generator_function_declaration":
                name_node = node.child_by_field_name("name")
                if name_node:
                    functions.append(FunctionInfo(
                        name=self._get_node_text(name_node, source_bytes),
                        start_line=self._node_to_line(node),
                        end_line=self._node_end_line(node),
                        start_byte=node.start_byte,
                        end_byte=node.end_byte,
                        source_code=self._get_node_text(node, source_bytes),
                        class_name=class_name,
                    ))

            # Method definitions in classes
            elif node.type == "method_definition":
                name_node = node.child_by_field_name("name")
                if name_node:
                    is_async = any(c.type == "async" for c in node.children if not c.is_named)
                    functions.append(FunctionInfo(
                        name=self._get_node_text(name_node, source_bytes),
                        start_line=self._node_to_line(node),
                        end_line=self._node_end_line(node),
                        start_byte=node.start_byte,
                        end_byte=node.end_byte,
                        source_code=self._get_node_text(node, source_bytes),
                        class_name=class_name,
                        is_async=is_async,
                    ))

            # Variable declarations with arrow functions or function expressions
            elif node.type in ("lexical_declaration", "variable_declaration"):
                for declarator in node.children:
                    if declarator.type == "variable_declarator":
                        name_node = declarator.child_by_field_name("name")
                        value_node = declarator.child_by_field_name("value")

                        if name_node and value_node:
                            if value_node.type in ("arrow_function", "function_expression", "function"):
                                is_async = False
                                for child in value_node.children:
                                    if not child.is_named and self._get_node_text(child, source_bytes) == "async":
                                        is_async = True
                                        break

                                functions.append(FunctionInfo(
                                    name=self._get_node_text(name_node, source_bytes),
                                    start_line=self._node_to_line(node),
                                    end_line=self._node_end_line(node),
                                    start_byte=node.start_byte,
                                    end_byte=node.end_byte,
                                    source_code=self._get_node_text(node, source_bytes),
                                    class_name=class_name,
                                    is_async=is_async,
                                ))

            for child in node.children:
                visit(child, class_name)

        visit(tree.root_node)
        return functions

    def extract_classes(self, source: Union[str, bytes]) -> list[ClassInfo]:
        """Extract all class definitions from JavaScript source."""
        if isinstance(source, str):
            source_bytes = source.encode("utf-8")
        else:
            source_bytes = source

        tree = self.parse(source_bytes)
        if not tree:
            return []

        classes = []

        def visit(node: "Node"):
            if node.type == "class_declaration":
                name_node = node.child_by_field_name("name")
                if name_node:
                    class_name = self._get_node_text(name_node, source_bytes)

                    # Extract superclass
                    parent_class = None
                    heritage = node.child_by_field_name("heritage")
                    if heritage:
                        for child in heritage.children:
                            if child.type == "extends_clause":
                                for super_child in child.children:
                                    if super_child.type == "identifier":
                                        parent_class = self._get_node_text(super_child, source_bytes)
                                        break

                    # Extract methods
                    methods = []
                    body = node.child_by_field_name("body")
                    if body:
                        for child in body.children:
                            if child.type == "method_definition":
                                fn_name = child.child_by_field_name("name")
                                if fn_name:
                                    methods.append(FunctionInfo(
                                        name=self._get_node_text(fn_name, source_bytes),
                                        start_line=self._node_to_line(child),
                                        end_line=self._node_end_line(child),
                                        start_byte=child.start_byte,
                                        end_byte=child.end_byte,
                                        source_code=self._get_node_text(child, source_bytes),
                                        class_name=class_name,
                                    ))

                    classes.append(ClassInfo(
                        name=class_name,
                        start_line=self._node_to_line(node),
                        end_line=self._node_end_line(node),
                        start_byte=node.start_byte,
                        end_byte=node.end_byte,
                        methods=methods,
                        parent_class=parent_class,
                        source_code=self._get_node_text(node, source_bytes),
                    ))

            for child in node.children:
                visit(child)

        visit(tree.root_node)
        return classes

    def extract_calls(self, source: Union[str, bytes]) -> list[CallInfo]:
        """Extract all function/method calls from JavaScript source."""
        if isinstance(source, str):
            source_bytes = source.encode("utf-8")
        else:
            source_bytes = source

        tree = self.parse(source_bytes)
        if not tree:
            return []

        calls = []

        def find_containing_function(node: "Node") -> Optional[str]:
            """Walk up the tree to find the containing function."""
            current = node.parent
            while current:
                if current.type in ("function_declaration", "method_definition", "generator_function_declaration"):
                    name_node = current.child_by_field_name("name")
                    if name_node:
                        return self._get_node_text(name_node, source_bytes)
                elif current.type == "variable_declarator":
                    name_node = current.child_by_field_name("name")
                    value_node = current.child_by_field_name("value")
                    if name_node and value_node and value_node.type in ("arrow_function", "function_expression"):
                        return self._get_node_text(name_node, source_bytes)
                current = current.parent
            return None

        def visit(node: "Node"):
            if node.type == "call_expression":
                func = node.child_by_field_name("function")
                if func:
                    if func.type == "identifier":
                        calls.append(CallInfo(
                            caller_function=find_containing_function(node),
                            callee_name=self._get_node_text(func, source_bytes),
                            line=self._node_to_line(node),
                            column=node.start_point[1],
                        ))
                    elif func.type == "member_expression":
                        obj = func.child_by_field_name("object")
                        prop = func.child_by_field_name("property")
                        if prop:
                            calls.append(CallInfo(
                                caller_function=find_containing_function(node),
                                callee_name=self._get_node_text(prop, source_bytes),
                                object_name=self._get_node_text(obj, source_bytes) if obj else None,
                                line=self._node_to_line(node),
                                column=node.start_point[1],
                            ))

            elif node.type == "new_expression":
                constructor = node.child_by_field_name("constructor")
                if constructor:
                    calls.append(CallInfo(
                        caller_function=find_containing_function(node),
                        callee_name=self._get_node_text(constructor, source_bytes),
                        line=self._node_to_line(node),
                        column=node.start_point[1],
                    ))

            for child in node.children:
                visit(child)

        visit(tree.root_node)
        return calls


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================

# Parser cache for reuse across calls
_parser_cache: dict[str, ASTParser] = {}
_parser_cache_lock = Lock()


def get_ast_parser(language: str) -> Optional[ASTParser]:
    """
    Get an AST parser for the specified language.

    Parsers are cached for reuse. Thread-safe.

    Args:
        language: One of 'python', 'java', 'javascript', 'typescript'

    Returns:
        ASTParser instance or None if language not supported
    """
    # Normalize language name
    lang = language.lower()
    if lang in ("js", "jsx", "mjs"):
        lang = "javascript"
    elif lang in ("ts", "tsx"):
        lang = "typescript"
    elif lang == "py":
        lang = "python"

    # Check cache
    if lang in _parser_cache:
        return _parser_cache[lang]

    # Create parser with lock
    with _parser_cache_lock:
        if lang in _parser_cache:
            return _parser_cache[lang]

        parser = None
        if lang == "python":
            parser = PythonASTParser()
        elif lang == "java":
            parser = JavaASTParser()
        elif lang in ("javascript", "typescript"):
            parser = JavaScriptASTParser()

        if parser:
            _parser_cache[lang] = parser

        return parser


def get_ast_parser_for_file(file_path: Path) -> Optional[ASTParser]:
    """
    Get an AST parser for a file based on its extension.

    Args:
        file_path: Path to the source file

    Returns:
        ASTParser instance or None if file type not supported
    """
    suffix = file_path.suffix.lower()

    extension_map = {
        ".py": "python",
        ".java": "java",
        ".js": "javascript",
        ".jsx": "javascript",
        ".mjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
    }

    language = extension_map.get(suffix)
    if language:
        return get_ast_parser(language)
    return None


def clear_parser_cache() -> None:
    """Clear the parser cache. Useful for testing."""
    global _parser_cache
    with _parser_cache_lock:
        _parser_cache.clear()

