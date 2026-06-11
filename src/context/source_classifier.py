"""
Source Classifier - Intelligent data flow tracing from source to sink.

This module provides intelligent classification of data sources to distinguish:
1. USER_INPUT - Untrusted data from HTTP requests, user uploads, etc.
2. CONFIG_LOADED - Trusted data from databases, config files, properties
3. SYSTEM_INTERNAL - Trusted data from internal computations, constants
4. DERIVED - Data computed from other sources (needs recursive tracing)

Key capabilities:
- Cross-file data flow tracing
- Annotation and pattern recognition
- Recursive source classification
"""

import re
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Set, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class SourceType(Enum):
    """Classification of data source trustworthiness."""
    USER_INPUT = "user_input"           # HTTP request params, body, headers - UNTRUSTED
    CONFIG_LOADED = "config_loaded"     # MongoDB, properties, @Value - TRUSTED
    SYSTEM_INTERNAL = "system_internal" # Constants, generated IDs - TRUSTED
    DERIVED = "derived"                 # Computed from other sources
    UNKNOWN = "unknown"                 # Cannot determine


@dataclass
class SourceTrace:
    """Single step in the source trace."""
    location: str           # file:line
    expression: str         # The code expression
    description: str        # Human-readable explanation
    source_type: SourceType # Classification at this step


@dataclass
class SourceClassification:
    """Complete classification result for a variable."""
    variable_name: str
    source_type: SourceType
    confidence: float
    trace: List[SourceTrace] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    
    def is_trusted(self) -> bool:
        """Return True if source is trusted (not user input)."""
        return self.source_type in (SourceType.CONFIG_LOADED, SourceType.SYSTEM_INTERNAL)
    
    def format_for_llm(self) -> str:
        """Format classification for LLM consumption."""
        lines = [
            f"## Source Classification: `{self.variable_name}`",
            f"**Type**: {self.source_type.value}",
            f"**Confidence**: {self.confidence:.0%}",
            f"**Trusted**: {'✅ Yes' if self.is_trusted() else '⚠️ No'}",
            "",
            "### Trace Path:",
        ]
        for i, step in enumerate(self.trace, 1):
            lines.append(f"{i}. **{step.description}**")
            lines.append(f"   `{step.expression[:100]}{'...' if len(step.expression) > 100 else ''}`")
            lines.append(f"   Classification: {step.source_type.value}")
        
        if self.reasons:
            lines.append("")
            lines.append("### Reasoning:")
            for reason in self.reasons:
                lines.append(f"- {reason}")
        
        return "\n".join(lines)
    
    def to_dict(self) -> dict:
        return {
            "variable": self.variable_name,
            "source_type": self.source_type.value,
            "confidence": self.confidence,
            "is_trusted": self.is_trusted(),
            "trace_steps": len(self.trace),
            "reasons": self.reasons,
        }


class SourceClassifier:
    """
    Classifies data sources by tracing data flow from origin to sink.
    
    This is the core intelligence for distinguishing:
    - User-controlled input (vulnerable)
    - Configuration-loaded data (safe)
    - System-internal data (safe)
    """
    
    # ========== USER INPUT PATTERNS (UNTRUSTED) ==========
    USER_INPUT_PATTERNS = [
        # Java Servlet
        (r'request\.getParameter\s*\(', "HTTP request parameter"),
        (r'request\.getHeader\s*\(', "HTTP request header"),
        (r'request\.getCookies\s*\(', "HTTP cookies"),
        (r'request\.getInputStream\s*\(', "HTTP request body stream"),
        (r'request\.getReader\s*\(', "HTTP request reader"),
        (r'request\.getQueryString\s*\(', "HTTP query string"),
        (r'request\.getPathInfo\s*\(', "HTTP path info"),
        (r'request\.getAttribute\s*\(', "HTTP request attribute"),
        
        # Spring MVC
        (r'@RequestParam', "Spring @RequestParam annotation"),
        (r'@PathVariable', "Spring @PathVariable annotation"),
        (r'@RequestBody', "Spring @RequestBody annotation"),
        (r'@RequestHeader', "Spring @RequestHeader annotation"),
        (r'@CookieValue', "Spring @CookieValue annotation"),
        (r'@MatrixVariable', "Spring @MatrixVariable annotation"),
        
        # JAX-RS
        (r'@QueryParam', "JAX-RS @QueryParam annotation"),
        (r'@FormParam', "JAX-RS @FormParam annotation"),
        (r'@HeaderParam', "JAX-RS @HeaderParam annotation"),
        
        # Generic patterns for user input
        (r'userInput', "Variable named userInput"),
        (r'fromUser', "Variable indicating user source"),
    ]
    
    # ========== CONFIG LOADED PATTERNS (TRUSTED) ==========
    CONFIG_PATTERNS = [
        # MongoDB Spring Data
        (r'@Document', "MongoDB @Document entity"),
        (r'@Entity', "JPA @Entity"),
        (r'MongoRepository', "Spring Data MongoDB repository"),
        (r'\.findById\s*\(', "Repository findById call"),
        (r'\.findBy\w+\s*\(', "Repository finder method"),
        (r'\.findOne\s*\(', "Repository findOne call"),
        (r'\.findAll\s*\(', "Repository findAll call"),
        (r'getMongoTemplate\s*\(\)', "MongoDB template access"),
        
        # Spring Configuration
        (r'@Value\s*\(', "Spring @Value injection"),
        (r'@ConfigurationProperties', "Spring configuration properties"),
        (r'properties\.get', "Properties file read"),
        (r'\.getProperty\s*\(', "Property getter"),
        (r'environment\.get', "Spring Environment access"),
        
        # Environment variables
        (r'System\.getenv\s*\(', "Environment variable"),
        (r'System\.getProperty\s*\(', "System property"),
        
        # Configuration objects
        (r'config\.get', "Configuration getter"),
        (r'Config\s+\w+\s*=', "Configuration assignment"),
        (r'settings\.get', "Settings getter"),
    ]
    
    # ========== SYSTEM INTERNAL PATTERNS (TRUSTED) ==========
    SYSTEM_PATTERNS = [
        # Constants
        (r'private\s+static\s+final\s+String', "Static final constant"),
        (r'public\s+static\s+final\s+String', "Public static final constant"),
        (r'const\s+', "Const declaration"),
        
        # Generated values
        (r'UUID\.randomUUID\s*\(', "Generated UUID"),
        (r'\.getId\s*\(\)', "Entity ID getter"),
        (r'System\.currentTimeMillis\s*\(', "System timestamp"),
        (r'new\s+Date\s*\(', "New Date object"),
        
        # Internal methods
        (r'generate\w+\s*\(', "Internal generator method"),
        (r'create\w+Id\s*\(', "Internal ID creator"),
    ]
    
    # ========== ENTITY/DTO GETTER PATTERNS ==========
    ENTITY_GETTER_PATTERNS = [
        # Standard getter patterns on configuration/entity objects
        (r'(\w+(?:Metadata|Config|Settings|Entity|DTO|Bean))\s*\.\s*get(\w+)\s*\(\s*\)', 
         "Entity/Config getter: {0}.get{1}()"),
        (r'(\w+)(?:Copy|Data)?\s*\.\s*get(\w+)\s*\(\s*\)',
         "Data object getter"),
    ]
    
    def __init__(self, project_root: Path, call_graph=None):
        """
        Initialize the source classifier.
        
        Args:
            project_root: Root directory of the project
            call_graph: Optional pre-built call graph for cross-file tracing
        """
        self.project_root = project_root
        self.call_graph = call_graph
        self._file_cache: Dict[str, str] = {}
        self._class_annotations: Dict[str, List[str]] = {}
    
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
    
    def classify_variable(self, variable_name: str, code: str, 
                          file_path: str, line_number: int,
                          max_depth: int = 5) -> SourceClassification:
        """
        Classify the source of a variable.
        
        Args:
            variable_name: Name of the variable to classify
            code: Code context containing the variable
            file_path: Path to the file
            line_number: Line number where variable is used
            max_depth: Maximum recursion depth for tracing
            
        Returns:
            SourceClassification with type, confidence, and trace
        """
        trace = []
        reasons = []
        
        # Step 1: Check if variable comes from user input
        user_result = self._check_user_input_source(variable_name, code, file_path)
        if user_result:
            return SourceClassification(
                variable_name=variable_name,
                source_type=SourceType.USER_INPUT,
                confidence=user_result[1],
                trace=[SourceTrace(
                    location=f"{file_path}:{line_number}",
                    expression=user_result[2],
                    description=user_result[0],
                    source_type=SourceType.USER_INPUT,
                )],
                reasons=[f"Detected user input: {user_result[0]}"],
            )
        
        # Step 2: Check if variable comes from configuration
        config_result = self._check_config_source(variable_name, code, file_path)
        if config_result:
            return SourceClassification(
                variable_name=variable_name,
                source_type=SourceType.CONFIG_LOADED,
                confidence=config_result[1],
                trace=[SourceTrace(
                    location=f"{file_path}:{line_number}",
                    expression=config_result[2],
                    description=config_result[0],
                    source_type=SourceType.CONFIG_LOADED,
                )],
                reasons=[f"Detected config source: {config_result[0]}"],
            )
        
        # Step 3: Check if variable comes from system internal
        system_result = self._check_system_internal(variable_name, code, file_path)
        if system_result:
            return SourceClassification(
                variable_name=variable_name,
                source_type=SourceType.SYSTEM_INTERNAL,
                confidence=system_result[1],
                trace=[SourceTrace(
                    location=f"{file_path}:{line_number}",
                    expression=system_result[2],
                    description=system_result[0],
                    source_type=SourceType.SYSTEM_INTERNAL,
                )],
                reasons=[f"Detected system internal: {system_result[0]}"],
            )
        
        # Step 4: Check if variable comes from entity/DTO getter
        entity_result = self._check_entity_getter(variable_name, code, file_path)
        if entity_result:
            # Need to trace the entity source
            entity_class = entity_result[3] if len(entity_result) > 3 else None
            
            # Check if entity class has @Document or @Entity annotation
            if entity_class and self._is_config_entity(entity_class, code, file_path):
                return SourceClassification(
                    variable_name=variable_name,
                    source_type=SourceType.CONFIG_LOADED,
                    confidence=0.90,
                    trace=[SourceTrace(
                        location=f"{file_path}:{line_number}",
                        expression=entity_result[2],
                        description=f"Getter on config entity: {entity_result[0]}",
                        source_type=SourceType.CONFIG_LOADED,
                    )],
                    reasons=[
                        f"Value from {entity_class} getter",
                        f"Entity class is a configuration/database entity",
                    ],
                )
        
        # Step 5: If variable is a method parameter, trace callers
        param_result = self._check_method_parameter(variable_name, code, file_path)
        if param_result and max_depth > 0:
            method_name = param_result[0]
            param_index = param_result[1]
            
            # Find and analyze all callers
            caller_result = self._analyze_all_callers(
                method_name, param_index, code, file_path, max_depth - 1
            )
            if caller_result:
                return caller_result
        
        # Step 6: Unknown - cannot determine
        return SourceClassification(
            variable_name=variable_name,
            source_type=SourceType.UNKNOWN,
            confidence=0.5,
            trace=[],
            reasons=["Could not determine source through static analysis"],
        )
    
    def _check_user_input_source(self, variable_name: str, code: str, 
                                  file_path: str) -> Optional[Tuple[str, float, str]]:
        """Check if variable comes from user input."""
        # Look for assignment to this variable from user input
        for pattern, description in self.USER_INPUT_PATTERNS:
            # Pattern: variable = ...userInputPattern...
            assignment_pattern = rf'\b{re.escape(variable_name)}\s*=\s*[^;]*{pattern}'
            match = re.search(assignment_pattern, code, re.IGNORECASE | re.MULTILINE)
            if match:
                return (description, 0.95, match.group(0)[:100])
            
            # Check for annotation on method parameter
            if pattern.startswith('@'):
                param_pattern = rf'{pattern}\s+\w+\s+{re.escape(variable_name)}'
                match = re.search(param_pattern, code, re.IGNORECASE)
                if match:
                    return (description, 0.95, match.group(0))
        
        return None
    
    def _check_config_source(self, variable_name: str, code: str,
                              file_path: str) -> Optional[Tuple[str, float, str]]:
        """Check if variable comes from configuration source."""
        for pattern, description in self.CONFIG_PATTERNS:
            # Pattern: variable = ...configPattern...
            assignment_pattern = rf'\b{re.escape(variable_name)}\s*=\s*[^;]*{pattern}'
            match = re.search(assignment_pattern, code, re.IGNORECASE | re.MULTILINE)
            if match:
                return (description, 0.90, match.group(0)[:100])
            
            # Check for annotation on field/parameter
            if pattern.startswith('@'):
                field_pattern = rf'{pattern}[^;]*\s+{re.escape(variable_name)}\s*[;=]'
                match = re.search(field_pattern, code, re.IGNORECASE)
                if match:
                    return (description, 0.90, match.group(0))
        
        return None
    
    def _check_system_internal(self, variable_name: str, code: str,
                                file_path: str) -> Optional[Tuple[str, float, str]]:
        """Check if variable comes from system internal source."""
        for pattern, description in self.SYSTEM_PATTERNS:
            # Check for constant definition
            const_pattern = rf'{pattern}\s+{re.escape(variable_name)}\s*='
            match = re.search(const_pattern, code, re.IGNORECASE)
            if match:
                return (description, 0.95, match.group(0)[:100])
            
            # Check for assignment from pattern
            assignment_pattern = rf'\b{re.escape(variable_name)}\s*=\s*[^;]*{pattern}'
            match = re.search(assignment_pattern, code, re.IGNORECASE | re.MULTILINE)
            if match:
                return (description, 0.85, match.group(0)[:100])
        
        return None
    
    def _check_entity_getter(self, variable_name: str, code: str,
                              file_path: str) -> Optional[Tuple[str, float, str, str]]:
        """Check if variable comes from an entity/DTO getter."""
        # Look for pattern: variable = someEntity.getProperty()
        getter_pattern = rf'\b{re.escape(variable_name)}\s*=\s*(\w+)\s*\.\s*get(\w+)\s*\(\s*\)'
        match = re.search(getter_pattern, code)
        if match:
            entity_name = match.group(1)
            property_name = match.group(2)
            return (
                f"{entity_name}.get{property_name}()",
                0.85,
                match.group(0),
                entity_name,
            )
        
        # Check for direct parameter passing: methodCall(entity.getProperty())
        # This is for tracing callers
        for pattern, desc in self.ENTITY_GETTER_PATTERNS:
            match = re.search(pattern, code)
            if match:
                return (
                    f"Entity getter: {match.group(0)[:50]}",
                    0.85,
                    match.group(0),
                    match.group(1) if match.lastindex >= 1 else None,
                )
        
        return None
    
    def _is_config_entity(self, entity_class: str, code: str, file_path: str) -> bool:
        """
        Check if an entity class is a configuration/database entity.
        
        Looks for @Document, @Entity annotations or repository patterns.
        """
        # Check in current code
        entity_patterns = [
            rf'class\s+{re.escape(entity_class)}.*@Document',
            rf'@Document.*class\s+{re.escape(entity_class)}',
            rf'class\s+{re.escape(entity_class)}.*@Entity',
            rf'@Entity.*class\s+{re.escape(entity_class)}',
            rf'{re.escape(entity_class)}Repo',
            rf'{re.escape(entity_class)}Repository',
        ]
        
        for pattern in entity_patterns:
            if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
                return True
        
        # Check class name patterns that indicate config/entity
        config_class_patterns = [
            r'Metadata$',
            r'Config$',
            r'Configuration$',
            r'Settings$',
            r'Properties$',
            r'Entity$',
            r'DTO$',
            r'Bean$',
        ]
        
        for pattern in config_class_patterns:
            if re.search(pattern, entity_class):
                return True
        
        # Try to find the class file and check annotations
        class_file = self._find_class_file(entity_class)
        if class_file:
            class_content = self._read_file(class_file)
            if '@Document' in class_content or '@Entity' in class_content:
                return True
        
        return False
    
    def _find_class_file(self, class_name: str) -> Optional[Path]:
        """Find the file containing a class definition."""
        # Search for Java files with matching class name
        for java_file in self.project_root.rglob(f"{class_name}.java"):
            return java_file
        return None
    
    def _check_method_parameter(self, variable_name: str, code: str,
                                 file_path: str) -> Optional[Tuple[str, int]]:
        """
        Check if variable is a method parameter.
        
        Returns:
            (method_name, parameter_index) if variable is a parameter
        """
        # Find method signature containing this variable as parameter
        # Pattern: returnType methodName(... Type variableName, ...)
        method_sig_pattern = rf'(?:public|private|protected)?\s*(?:static)?\s*\w+(?:<[^>]+>)?\s+(\w+)\s*\(([^)]*)\)'
        
        for match in re.finditer(method_sig_pattern, code):
            method_name = match.group(1)
            params_str = match.group(2)
            
            # Parse parameters
            params = [p.strip() for p in params_str.split(',') if p.strip()]
            for idx, param in enumerate(params):
                # Extract parameter name (last word)
                param_parts = param.split()
                if param_parts and param_parts[-1] == variable_name:
                    return (method_name, idx)
        
        return None
    
    def _analyze_all_callers(self, method_name: str, param_index: int,
                             code: str, file_path: str,
                             max_depth: int) -> Optional[SourceClassification]:
        """
        Analyze all callers of a method to classify the parameter source.
        
        If ALL callers pass trusted sources, the parameter is trusted.
        """
        # Find callers within the current code
        callers = self._find_callers_in_code(method_name, code)
        
        if not callers:
            return None
        
        caller_sources = []
        all_trusted = True
        
        for caller_code, caller_line in callers:
            # Extract the argument at param_index
            arg_value = self._extract_argument(caller_code, method_name, param_index)
            if arg_value:
                # Classify this argument's source
                arg_classification = self._classify_argument(arg_value, code, file_path)
                caller_sources.append((arg_value, arg_classification))
                
                if arg_classification.source_type == SourceType.USER_INPUT:
                    all_trusted = False
                elif arg_classification.source_type == SourceType.UNKNOWN:
                    all_trusted = False
        
        if not caller_sources:
            return None
        
        # Build trace
        trace = []
        reasons = []
        
        for arg_value, classification in caller_sources:
            trace.append(SourceTrace(
                location=file_path,
                expression=f"{method_name}({arg_value})",
                description=f"Caller passes: {arg_value}",
                source_type=classification.source_type,
            ))
            reasons.extend(classification.reasons)
        
        if all_trusted:
            return SourceClassification(
                variable_name=f"param[{param_index}] of {method_name}",
                source_type=SourceType.CONFIG_LOADED,
                confidence=0.90,
                trace=trace,
                reasons=[
                    f"All {len(caller_sources)} callers pass trusted sources",
                ] + reasons[:3],
            )
        else:
            # At least one untrusted source
            return SourceClassification(
                variable_name=f"param[{param_index}] of {method_name}",
                source_type=SourceType.USER_INPUT,
                confidence=0.85,
                trace=trace,
                reasons=[
                    "At least one caller passes untrusted source",
                ] + reasons[:3],
            )
    
    def _find_callers_in_code(self, method_name: str, code: str) -> List[Tuple[str, int]]:
        """Find all calls to a method within the code."""
        callers = []
        lines = code.split('\n')
        
        # Pattern to match function call (not definition)
        call_pattern = rf'\b{re.escape(method_name)}\s*\('
        def_pattern = rf'(?:private|public|protected)\s+(?:static\s+)?(?:\w+(?:<[^>]+>)?)\s+{re.escape(method_name)}\s*\('
        
        for line_num, line in enumerate(lines, 1):
            if re.search(call_pattern, line) and not re.search(def_pattern, line):
                callers.append((line, line_num))
        
        return callers
    
    def _extract_argument(self, caller_code: str, method_name: str, 
                          param_index: int) -> Optional[str]:
        """Extract the argument at a specific position from a method call."""
        call_pattern = rf'{re.escape(method_name)}\s*\(([^)]+)\)'
        match = re.search(call_pattern, caller_code)
        
        if not match:
            return None
        
        args_str = match.group(1)
        
        # Parse arguments handling nested parentheses
        args = []
        current_arg = []
        depth = 0
        
        for char in args_str:
            if char in '([{':
                depth += 1
                current_arg.append(char)
            elif char in ')]}':
                depth -= 1
                current_arg.append(char)
            elif char == ',' and depth == 0:
                args.append(''.join(current_arg).strip())
                current_arg = []
            else:
                current_arg.append(char)
        
        if current_arg:
            args.append(''.join(current_arg).strip())
        
        if param_index < len(args):
            return args[param_index]
        
        return None
    
    def _classify_argument(self, arg_value: str, code: str,
                           file_path: str) -> SourceClassification:
        """Classify the source of an argument expression."""
        # Normalize: remove trailing incomplete parens
        arg_value = arg_value.strip()
        
        # Check if it's a string literal
        if (arg_value.startswith('"') and arg_value.endswith('"')) or \
           (arg_value.startswith("'") and arg_value.endswith("'")):
            return SourceClassification(
                variable_name=arg_value,
                source_type=SourceType.SYSTEM_INTERNAL,
                confidence=0.95,
                reasons=["String literal"],
            )
        
        # Check if it's an entity getter pattern - flexible matching
        # Match patterns like: entity.getProperty() or entity.getProperty(
        getter_patterns = [
            r'(\w+)\s*\.\s*get(\w+)\s*\(\s*\)',        # Full: entity.getProperty()
            r'(\w+)\s*\.\s*get(\w+)\s*\(',              # Partial: entity.getProperty(
            r'(\w+)\s*\.\s*get(\w+)',                   # No parens: entity.getProperty
        ]
        
        for getter_pattern in getter_patterns:
            getter_match = re.match(getter_pattern, arg_value)
            if getter_match:
                entity_name = getter_match.group(1)
                property_name = getter_match.group(2)
                
                # Check if entity is a config entity
                if self._is_config_entity(entity_name, code, file_path):
                    return SourceClassification(
                        variable_name=arg_value,
                        source_type=SourceType.CONFIG_LOADED,
                        confidence=0.90,
                        reasons=[f"Getter on config entity: {entity_name}.get{property_name}()"],
                    )
                
                # Also check the type pattern (e.g., tableCopyMetadata -> TableCopyMetadata type)
                # CamelCase the entity name
                type_name = entity_name[0].upper() + entity_name[1:] if entity_name else ""
                if self._is_config_entity(type_name, code, file_path):
                    return SourceClassification(
                        variable_name=arg_value,
                        source_type=SourceType.CONFIG_LOADED,
                        confidence=0.90,
                        reasons=[f"Getter on config entity: {type_name}.get{property_name}()"],
                    )
        
        # Check for user input patterns
        for pattern, description in self.USER_INPUT_PATTERNS:
            if re.search(pattern, arg_value):
                return SourceClassification(
                    variable_name=arg_value,
                    source_type=SourceType.USER_INPUT,
                    confidence=0.90,
                    reasons=[f"User input pattern: {description}"],
                )
        
        # Unknown
        return SourceClassification(
            variable_name=arg_value,
            source_type=SourceType.UNKNOWN,
            confidence=0.5,
            reasons=["Could not classify argument source"],
        )
    
    def classify_parameter(self, method_name: str, param_name: str, 
                           param_index: int, code: str, 
                           file_path: str) -> SourceClassification:
        """
        Classify a method parameter by analyzing all callers.
        
        This is the main entry point for analyzing method parameters
        that are used in sinks (like SQL queries).
        
        Args:
            method_name: Name of the method
            param_name: Name of the parameter
            param_index: Index of the parameter (0-based)
            code: Code context (ideally the full class)
            file_path: Path to the file
            
        Returns:
            SourceClassification with aggregated caller analysis
        """
        return self._analyze_all_callers(
            method_name, param_index, code, file_path, max_depth=3
        ) or SourceClassification(
            variable_name=param_name,
            source_type=SourceType.UNKNOWN,
            confidence=0.5,
            reasons=["No callers found for cross-file analysis"],
        )
