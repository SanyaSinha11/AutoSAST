"""
Pre-indexed Call Graph for Efficient Data Flow Analysis.

This module provides:
1. CallGraphNode - Represents a function/method in the call graph
2. CallGraphEdge - Represents a call relationship between nodes
3. CallGraph - Pre-indexed bidirectional call graph for efficient navigation

The call graph is built once during context extraction and provides:
- O(1) lookup of callers and callees
- Bidirectional traversal (up to callers, down to callees)
- Efficient path finding between source and sink
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from functools import lru_cache

logger = logging.getLogger(__name__)


@dataclass
class CallGraphNode:
    """A node in the call graph representing a function/method."""
    id: str  # Unique identifier: "package.ClassName.methodName"
    name: str  # Method name
    class_name: str
    package: str
    file_path: str
    start_line: int
    end_line: int
    is_entry_point: bool = False  # Controllers, handlers, etc.
    is_sink: bool = False  # Database queries, system calls, etc.

    @property
    def qualified_name(self) -> str:
        """Get fully qualified name."""
        if self.package:
            return f"{self.package}.{self.class_name}.{self.name}"
        return f"{self.class_name}.{self.name}"


@dataclass
class CallGraphEdge:
    """An edge in the call graph representing a call relationship."""
    caller_id: str
    callee_id: str
    call_line: int
    call_column: int = 0
    arguments: list[str] = field(default_factory=list)


@dataclass
class CallPath:
    """A path through the call graph from source to sink."""
    nodes: list[CallGraphNode]
    edges: list[CallGraphEdge]

    @property
    def length(self) -> int:
        return len(self.edges)

    def to_string(self) -> str:
        """Convert path to string representation."""
        if not self.nodes:
            return ""
        return " → ".join(f"{n.class_name}.{n.name}()" for n in self.nodes)


class CallGraph:
    """
    Pre-indexed bidirectional call graph for efficient data flow analysis.
    
    Provides O(1) lookup of:
    - All callers of a function (who calls this?)
    - All callees of a function (what does this call?)
    - Paths between any two nodes
    """

    def __init__(self, project_root: Optional[Path] = None):
        self.project_root = project_root
        self._nodes: dict[str, CallGraphNode] = {}
        self._edges: list[CallGraphEdge] = []
        # Bidirectional indexes for O(1) lookup
        self._callers: dict[str, list[str]] = {}  # callee_id -> [caller_ids]
        self._callees: dict[str, list[str]] = {}  # caller_id -> [callee_ids]
        self._built = False

    def add_node(self, node: CallGraphNode):
        """Add a node to the graph."""
        self._nodes[node.id] = node

    def add_edge(self, edge: CallGraphEdge):
        """Add an edge to the graph and update indexes."""
        self._edges.append(edge)
        # Update caller index
        if edge.callee_id not in self._callers:
            self._callers[edge.callee_id] = []
        if edge.caller_id not in self._callers[edge.callee_id]:
            self._callers[edge.callee_id].append(edge.caller_id)
        # Update callee index
        if edge.caller_id not in self._callees:
            self._callees[edge.caller_id] = []
        if edge.callee_id not in self._callees[edge.caller_id]:
            self._callees[edge.caller_id].append(edge.callee_id)

    def get_node(self, node_id: str) -> Optional[CallGraphNode]:
        """Get a node by ID."""
        return self._nodes.get(node_id)

    def get_callers(self, node_id: str) -> list[CallGraphNode]:
        """Get all callers of a node (O(1) lookup)."""
        caller_ids = self._callers.get(node_id, [])
        return [self._nodes[cid] for cid in caller_ids if cid in self._nodes]

    def get_callees(self, node_id: str) -> list[CallGraphNode]:
        """Get all callees of a node (O(1) lookup)."""
        callee_ids = self._callees.get(node_id, [])
        return [self._nodes[cid] for cid in callee_ids if cid in self._nodes]

    def find_paths_to_sink(
        self,
        source_id: str,
        max_depth: int = 10,
        visited: Optional[set] = None
    ) -> list[CallPath]:
        """Find all paths from source to any sink node."""
        if visited is None:
            visited = set()

        paths = []
        source = self._nodes.get(source_id)
        if not source:
            return paths

        if source.is_sink:
            return [CallPath(nodes=[source], edges=[])]

        if source_id in visited or max_depth <= 0:
            return paths

        visited.add(source_id)

        for callee_id in self._callees.get(source_id, []):
            callee_paths = self.find_paths_to_sink(callee_id, max_depth - 1, visited.copy())
            for path in callee_paths:
                edge = self._find_edge(source_id, callee_id)
                if edge:
                    paths.append(CallPath(
                        nodes=[source] + path.nodes,
                        edges=[edge] + path.edges
                    ))

        return paths

    def _find_edge(self, caller_id: str, callee_id: str) -> Optional[CallGraphEdge]:
        """Find edge between two nodes."""
        for edge in self._edges:
            if edge.caller_id == caller_id and edge.callee_id == callee_id:
                return edge
        return None

    def trace_caller_chain(
        self,
        node_id: str,
        max_depth: int = 5,
        visited: Optional[set] = None
    ) -> list[CallGraphNode]:
        """Trace backwards through the call chain to find entry points."""
        if visited is None:
            visited = set()

        chain = []
        if node_id in visited or max_depth <= 0:
            return chain

        visited.add(node_id)
        node = self._nodes.get(node_id)
        if node:
            chain.append(node)
            if node.is_entry_point:
                return chain

        for caller_id in self._callers.get(node_id, []):
            upstream = self.trace_caller_chain(caller_id, max_depth - 1, visited.copy())
            chain.extend(upstream)

        return chain

    def get_entry_points(self) -> list[CallGraphNode]:
        """Get all entry point nodes (controllers, handlers, etc.)."""
        return [n for n in self._nodes.values() if n.is_entry_point]

    def get_sinks(self) -> list[CallGraphNode]:
        """Get all sink nodes (database queries, system calls, etc.)."""
        return [n for n in self._nodes.values() if n.is_sink]

    def get_stats(self) -> dict:
        """Get statistics about the call graph."""
        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "entry_points": len(self.get_entry_points()),
            "sinks": len(self.get_sinks()),
            "avg_callers_per_node": sum(len(c) for c in self._callers.values()) / max(len(self._nodes), 1),
            "avg_callees_per_node": sum(len(c) for c in self._callees.values()) / max(len(self._nodes), 1),
        }

    def to_dict(self) -> dict:
        """Serialize the call graph to a dictionary."""
        return {
            "nodes": [
                {
                    "id": n.id,
                    "name": n.name,
                    "class": n.class_name,
                    "file": n.file_path,
                    "line": n.start_line,
                    "is_entry_point": n.is_entry_point,
                    "is_sink": n.is_sink,
                }
                for n in self._nodes.values()
            ],
            "edges": [
                {
                    "caller": e.caller_id,
                    "callee": e.callee_id,
                    "line": e.call_line,
                }
                for e in self._edges
            ],
            "stats": self.get_stats(),
        }


class CallGraphBuilder:
    """
    Builds a call graph from a project using AST parsing.

    Identifies:
    - Entry points (controllers, servlets, handlers)
    - Sinks (SQL queries, file operations, system commands)
    - Call relationships between methods
    """

    # Patterns to identify entry points
    ENTRY_POINT_PATTERNS = [
        r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)',
        r'@(Get|Post|Put|Delete|Path)',
        r'doGet|doPost|doPut|doDelete|service',
        r'@EventListener|@Scheduled|@Async',
        r'public static void main',
    ]

    # Patterns to identify sinks
    SINK_PATTERNS = [
        r'executeQuery|executeUpdate|execute|prepareStatement',
        r'Runtime\.exec|ProcessBuilder',
        r'FileWriter|FileOutputStream|Files\.write',
        r'eval|exec|system',
        r'sendRedirect|forward',
    ]

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self._ast_parser = None
        self._init_ast_parser()

    def _init_ast_parser(self):
        """Initialize AST parser if available."""
        try:
            from .ast_parser import JavaASTParser, is_tree_sitter_available
            if is_tree_sitter_available():
                self._ast_parser = JavaASTParser()
        except ImportError:
            logger.debug("AST parser not available for call graph building")

    def build(self) -> CallGraph:
        """Build the call graph from the project."""
        graph = CallGraph(self.project_root)

        for file_path in self.project_root.rglob("*.java"):
            try:
                self._process_file(file_path, graph)
            except Exception as e:
                logger.debug(f"Error processing {file_path} for call graph: {e}")

        graph._built = True
        logger.info(f"Built call graph: {graph.get_stats()}")
        return graph

    def _process_file(self, file_path: Path, graph: CallGraph):
        """Process a single file and add its nodes/edges to the graph."""
        content = file_path.read_text(encoding="utf-8", errors="replace")

        # Extract package and class name
        pkg_match = re.search(r'package\s+([\w.]+);', content)
        package = pkg_match.group(1) if pkg_match else ""
        class_match = re.search(r'(?:public\s+)?class\s+(\w+)', content)
        class_name = class_match.group(1) if class_match else file_path.stem

        # Check if file has entry points or sinks
        is_entry_file = any(re.search(p, content) for p in self.ENTRY_POINT_PATTERNS)
        has_sinks = any(re.search(p, content) for p in self.SINK_PATTERNS)

        # Extract methods using AST or regex
        methods = self._extract_methods(content)

        for method in methods:
            node_id = f"{package}.{class_name}.{method['name']}" if package else f"{class_name}.{method['name']}"
            is_entry = is_entry_file and self._is_entry_point(method['code'])
            is_sink = self._is_sink(method['code'])

            node = CallGraphNode(
                id=node_id,
                name=method['name'],
                class_name=class_name,
                package=package,
                file_path=str(file_path),
                start_line=method['start_line'],
                end_line=method['end_line'],
                is_entry_point=is_entry,
                is_sink=is_sink,
            )
            graph.add_node(node)

            # Extract calls from this method
            calls = self._extract_calls_from_method(method['code'], method['start_line'])
            for call in calls:
                # Create edge (callee might not exist yet, will be resolved later)
                edge = CallGraphEdge(
                    caller_id=node_id,
                    callee_id=call['callee'],
                    call_line=call['line'],
                )
                graph.add_edge(edge)

    def _extract_methods(self, content: str) -> list[dict]:
        """Extract methods from content."""
        methods = []
        if self._ast_parser:
            try:
                funcs = self._ast_parser.extract_functions(content)
                for f in funcs:
                    methods.append({
                        'name': f.name,
                        'start_line': f.start_line,
                        'end_line': f.end_line,
                        'code': f.body or "",
                    })
                return methods
            except Exception:
                pass

        # Regex fallback
        pattern = r'(?:public|private|protected)?\s*(?:static\s+)?[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{'
        for match in re.finditer(pattern, content):
            name = match.group(1)
            start = content[:match.start()].count('\n') + 1
            methods.append({
                'name': name,
                'start_line': start,
                'end_line': start + 10,  # Approximate
                'code': content[match.start():match.start()+500],
            })
        return methods

    def _extract_calls_from_method(self, method_code: str, base_line: int) -> list[dict]:
        """Extract method calls from a method body."""
        calls = []
        # Simple pattern: object.method() or method()
        for match in re.finditer(r'(\w+)\.(\w+)\s*\(|(?<!\.)(\w+)\s*\(', method_code):
            receiver = match.group(1)
            method_name = match.group(2) or match.group(3)
            line = base_line + method_code[:match.start()].count('\n')
            callee_id = f"{receiver}.{method_name}" if receiver else method_name
            calls.append({'callee': callee_id, 'line': line})
        return calls

    def _is_entry_point(self, code: str) -> bool:
        """Check if method code indicates an entry point."""
        return any(re.search(p, code) for p in self.ENTRY_POINT_PATTERNS)

    def _is_sink(self, code: str) -> bool:
        """Check if method code contains a sink."""
        return any(re.search(p, code) for p in self.SINK_PATTERNS)


class PythonCallGraphBuilder:
    """
    Builds a call graph from a Python project.
    
    Identifies:
    - Entry points (Flask/Django routes, main functions)
    - Sinks (SQL queries, subprocess, file operations)
    - Call relationships between functions
    """

    # Patterns to identify entry points
    ENTRY_POINT_PATTERNS = [
        r'@app\.route\s*\(',
        r'@router\.(get|post|put|delete|patch)\s*\(',
        r'@(api_view|action)\s*\(',
        r'def (get|post|put|patch|delete)\s*\(',  # Django CBV
        r'def lambda_handler\s*\(',
        r'def main\s*\(',
        r'if\s+__name__\s*==\s*[\'"]__main__[\'"]\s*:',
        r'@click\.command',
        r'@celery\.task',
    ]

    # Patterns to identify sinks
    SINK_PATTERNS = [
        r'cursor\.(execute|executemany)\s*\(',
        r'\.raw\s*\(',  # Django raw SQL
        r'subprocess\.(run|call|Popen|check_output)\s*\(',
        r'os\.(system|popen|exec\w*)\s*\(',
        r'eval\s*\(',
        r'exec\s*\(',
        r'open\s*\([^)]+,\s*[\'"]w',
        r'pickle\.(load|loads)\s*\(',
        r'yaml\.(unsafe_)?load\s*\(',
    ]

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self._ast_parser = None
        self._init_ast_parser()

    def _init_ast_parser(self):
        """Initialize AST parser if available."""
        try:
            from .ast_parser import PythonASTParser, is_tree_sitter_available
            if is_tree_sitter_available():
                self._ast_parser = PythonASTParser()
        except ImportError:
            logger.debug("AST parser not available for Python call graph building")

    def build(self) -> CallGraph:
        """Build the call graph from the project."""
        graph = CallGraph(self.project_root)

        for file_path in self.project_root.rglob("*.py"):
            # Skip test files, __pycache__, venv, etc.
            if any(skip in str(file_path) for skip in ['__pycache__', 'venv', 'test_', '_test.py', 'tests/']):
                continue
            try:
                self._process_file(file_path, graph)
            except Exception as e:
                logger.debug(f"Error processing {file_path} for call graph: {e}")

        graph._built = True
        logger.info(f"Built Python call graph: {graph.get_stats()}")
        return graph

    def _process_file(self, file_path: Path, graph: CallGraph):
        """Process a single Python file and add its nodes/edges to the graph."""
        try:
            content = file_path.read_text(encoding='utf-8', errors='replace')
        except Exception:
            return

        # Extract module name from path
        try:
            rel_path = file_path.relative_to(self.project_root)
            module_name = str(rel_path.with_suffix('')).replace('/', '.').replace('\\', '.')
        except ValueError:
            module_name = file_path.stem

        # Extract functions using regex (fallback)
        functions = self._extract_functions(content)
        
        for func in functions:
            func_name = func['name']
            func_code = func['code']
            
            node_id = f"{module_name}.{func_name}"
            node = CallGraphNode(
                id=node_id,
                name=func_name,
                class_name=func.get('class', ''),
                package=module_name,
                file_path=str(file_path),
                start_line=func.get('start_line', 1),
                end_line=func.get('end_line', 1),
                is_entry_point=self._is_entry_point(func_code),
                is_sink=self._is_sink(func_code),
            )
            graph.add_node(node)
            
            # Extract calls
            calls = self._extract_calls_from_function(func_code, func.get('start_line', 1))
            for call in calls:
                edge = CallGraphEdge(
                    caller_id=node_id,
                    callee_id=call['callee'],
                    call_line=call['line'],
                )
                graph.add_edge(edge)

    def _extract_functions(self, content: str) -> list[dict]:
        """Extract functions from Python content."""
        functions = []
        lines = content.split('\n')
        
        # Pattern for function definitions (including async and methods)
        func_pattern = re.compile(r'^(\s*)(async\s+)?def\s+(\w+)\s*\(([^)]*)\)\s*(?:->.*)?:', re.MULTILINE)
        
        # Track class context
        current_class = None
        class_pattern = re.compile(r'^class\s+(\w+)')
        
        i = 0
        while i < len(lines):
            line = lines[i]
            
            # Check for class
            class_match = class_pattern.match(line)
            if class_match:
                current_class = class_match.group(1)
            
            # Check for function
            func_match = func_pattern.match(line)
            if func_match:
                indent = len(func_match.group(1))
                func_name = func_match.group(3)
                start_line = i + 1
                
                # Find function end by indentation
                end_line = start_line
                for j in range(i + 1, len(lines)):
                    l = lines[j]
                    if l.strip():  # Non-empty line
                        curr_indent = len(l) - len(l.lstrip())
                        if curr_indent <= indent and not l.strip().startswith('#'):
                            break
                        end_line = j + 1
                
                func_code = '\n'.join(lines[i:end_line])
                functions.append({
                    'name': func_name,
                    'code': func_code,
                    'class': current_class if indent > 0 else '',
                    'start_line': start_line,
                    'end_line': end_line,
                })
            
            i += 1
        
        return functions

    def _extract_calls_from_function(self, func_code: str, base_line: int) -> list[dict]:
        """Extract function calls from a function body."""
        calls = []
        call_pattern = re.compile(r'(?:(\w+)\.)?(\w+)\s*\(')
        
        for i, line in enumerate(func_code.split('\n')):
            for match in call_pattern.finditer(line):
                obj = match.group(1) or ''
                method = match.group(2)
                if method not in ['if', 'for', 'while', 'with', 'def', 'class', 'return', 'print', 'range', 'len', 'str', 'int', 'list', 'dict']:
                    callee_id = f"{obj}.{method}" if obj else method
                    calls.append({'callee': callee_id, 'line': base_line + i})
        
        return calls

    def _is_entry_point(self, code: str) -> bool:
        """Check if function code indicates an entry point."""
        return any(re.search(p, code) for p in self.ENTRY_POINT_PATTERNS)

    def _is_sink(self, code: str) -> bool:
        """Check if function code contains a sink."""
        return any(re.search(p, code) for p in self.SINK_PATTERNS)


class JavaScriptCallGraphBuilder:
    """
    Builds a call graph from a JavaScript/TypeScript project.
    
    Identifies:
    - Entry points (Express/Fastify routes, event handlers, exports)
    - Sinks (eval, DOM manipulation, exec, SQL)
    - Call relationships between functions
    """

    # Patterns to identify entry points
    ENTRY_POINT_PATTERNS = [
        r'app\.(get|post|put|patch|delete|use)\s*\(',
        r'router\.(get|post|put|patch|delete)\s*\(',
        r'fastify\.(get|post|put|delete)\s*\(',
        r'export\s+(default\s+)?(async\s+)?function',
        r'export\s+(const|let)\s+\w+\s*=\s*(async\s+)?(?:function|\()',
        r'addEventListener\s*\(',
        r'\.on\s*\([\'"]',
        r'module\.exports\s*=',
        r'exports\.\w+\s*=',
    ]

    # Patterns to identify sinks
    SINK_PATTERNS = [
        r'eval\s*\(',
        r'Function\s*\(',
        r'exec\s*\(',
        r'\.innerHTML\s*=',
        r'document\.write\s*\(',
        r'\.html\s*\(',
        r'child_process\.(exec|spawn|execSync)\s*\(',
        r'new\s+Function\s*\(',
        r'\$\s*\(\s*[^)]+\)\s*\.\s*html\s*\(',
        r'\.query\s*\(',
        r'\.raw\s*\(',
    ]

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self._ast_parser = None
        self._init_ast_parser()

    def _init_ast_parser(self):
        """Initialize AST parser if available."""
        try:
            from .ast_parser import JavaScriptASTParser, is_tree_sitter_available
            if is_tree_sitter_available():
                self._ast_parser = JavaScriptASTParser()
        except ImportError:
            logger.debug("AST parser not available for JavaScript call graph building")

    def build(self) -> CallGraph:
        """Build the call graph from the project."""
        graph = CallGraph(self.project_root)

        extensions = ['*.js', '*.jsx', '*.ts', '*.tsx']
        for ext in extensions:
            for file_path in self.project_root.rglob(ext):
                # Skip node_modules, dist, build, test files
                if any(skip in str(file_path) for skip in ['node_modules', 'dist/', 'build/', '.test.', '.spec.', '__tests__']):
                    continue
                try:
                    self._process_file(file_path, graph)
                except Exception as e:
                    logger.debug(f"Error processing {file_path} for call graph: {e}")

        graph._built = True
        logger.info(f"Built JavaScript call graph: {graph.get_stats()}")
        return graph

    def _process_file(self, file_path: Path, graph: CallGraph):
        """Process a single JavaScript file and add its nodes/edges to the graph."""
        try:
            content = file_path.read_text(encoding='utf-8', errors='replace')
        except Exception:
            return

        # Use relative path as module ID
        try:
            rel_path = file_path.relative_to(self.project_root)
            module_name = str(rel_path.with_suffix(''))
        except ValueError:
            module_name = file_path.stem

        # Extract functions
        functions = self._extract_functions(content)
        
        for func in functions:
            func_name = func['name']
            func_code = func['code']
            
            node_id = f"{module_name}:{func_name}"
            node = CallGraphNode(
                id=node_id,
                name=func_name,
                class_name=func.get('class', ''),
                package=module_name,
                file_path=str(file_path),
                start_line=func.get('start_line', 1),
                end_line=func.get('end_line', 1),
                is_entry_point=self._is_entry_point(func_code),
                is_sink=self._is_sink(func_code),
            )
            graph.add_node(node)
            
            # Extract calls
            calls = self._extract_calls_from_function(func_code, func.get('start_line', 1))
            for call in calls:
                edge = CallGraphEdge(
                    caller_id=node_id,
                    callee_id=call['callee'],
                    call_line=call['line'],
                )
                graph.add_edge(edge)

    def _extract_functions(self, content: str) -> list[dict]:
        """Extract functions from JavaScript content."""
        functions = []
        lines = content.split('\n')
        
        # Patterns for function definitions
        patterns = [
            re.compile(r'^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+(\w+)\s*\('),
            re.compile(r'^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>|\w+\s*=>)'),
            re.compile(r'^\s*(?:async\s+)?(\w+)\s*\([^)]*\)\s*{'),  # Method shorthand
        ]
        
        i = 0
        while i < len(lines):
            line = lines[i]
            
            for pattern in patterns:
                match = pattern.match(line)
                if match:
                    func_name = match.group(1)
                    start_line = i + 1
                    
                    # Find function end by brace counting
                    brace_count = line.count('{') - line.count('}')
                    end_line = start_line
                    
                    for j in range(i + 1, len(lines)):
                        l = lines[j]
                        brace_count += l.count('{') - l.count('}')
                        end_line = j + 1
                        if brace_count <= 0:
                            break
                    
                    func_code = '\n'.join(lines[i:end_line])
                    functions.append({
                        'name': func_name,
                        'code': func_code,
                        'start_line': start_line,
                        'end_line': end_line,
                    })
                    break
            
            i += 1
        
        return functions

    def _extract_calls_from_function(self, func_code: str, base_line: int) -> list[dict]:
        """Extract function calls from a function body."""
        calls = []
        call_pattern = re.compile(r'(?:(\w+)\.)?(\w+)\s*\(')
        
        for i, line in enumerate(func_code.split('\n')):
            for match in call_pattern.finditer(line):
                obj = match.group(1) or ''
                method = match.group(2)
                if method not in ['if', 'for', 'while', 'switch', 'catch', 'function', 'return', 'new', 'typeof', 'instanceof']:
                    callee_id = f"{obj}.{method}" if obj else method
                    calls.append({'callee': callee_id, 'line': base_line + i})
        
        return calls

    def _is_entry_point(self, code: str) -> bool:
        """Check if function code indicates an entry point."""
        return any(re.search(p, code) for p in self.ENTRY_POINT_PATTERNS)

    def _is_sink(self, code: str) -> bool:
        """Check if function code contains a sink."""
        return any(re.search(p, code) for p in self.SINK_PATTERNS)


class MultiLanguageCallGraphBuilder:
    """
    Builds call graphs for multiple languages.
    
    Automatically detects the primary language of a project and uses
    the appropriate language-specific builder.
    """

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self._builders = {
            'java': CallGraphBuilder,
            'python': PythonCallGraphBuilder,
            'javascript': JavaScriptCallGraphBuilder,
        }

    def detect_languages(self) -> list[str]:
        """Detect which languages are present in the project."""
        detected = []
        
        if list(self.project_root.rglob("*.java")):
            detected.append('java')
        if list(self.project_root.rglob("*.py")):
            detected.append('python')
        if list(self.project_root.rglob("*.js")) or list(self.project_root.rglob("*.ts")):
            detected.append('javascript')
        
        return detected

    def build(self) -> CallGraph:
        """Build a combined call graph for all detected languages."""
        languages = self.detect_languages()
        
        if not languages:
            logger.warning("No supported languages detected in project")
            return CallGraph(self.project_root)
        
        # Build graphs for each language and merge
        combined = CallGraph(self.project_root)
        
        for lang in languages:
            builder_class = self._builders.get(lang)
            if builder_class:
                try:
                    builder = builder_class(self.project_root)
                    graph = builder.build()
                    
                    # Merge nodes and edges
                    for node in graph._nodes.values():
                        combined.add_node(node)
                    for edge in graph._edges.values():
                        combined.add_edge(edge)
                    
                    logger.info(f"Added {len(graph._nodes)} nodes from {lang}")
                except Exception as e:
                    logger.warning(f"Failed to build {lang} call graph: {e}")
        
        combined._built = True
        return combined

    def build_for_language(self, language: str) -> CallGraph:
        """Build call graph for a specific language."""
        builder_class = self._builders.get(language)
        if not builder_class:
            logger.warning(f"No builder for language: {language}")
            return CallGraph(self.project_root)
        
        builder = builder_class(self.project_root)
        return builder.build()

