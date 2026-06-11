"""
Tree-sitter Query Definitions for AST-based Code Extraction.

This module contains language-specific Tree-sitter queries for extracting
functions, classes, methods, and call sites from source code.

Queries are optimized for:
- Production-grade accuracy
- Scaled scanning performance
- Complete coverage of language constructs
"""

# =============================================================================
# PYTHON QUERIES
# =============================================================================

PYTHON_FUNCTION_QUERY = """
; Match function definitions with optional decorators
(decorated_definition
  (decorator)* @decorator
  definition: (function_definition
    name: (identifier) @name
    parameters: (parameters) @params
    return_type: (type)? @return_type
    body: (block) @body)) @function

; Match standalone function definitions (no decorators)
(function_definition
  name: (identifier) @name
  parameters: (parameters) @params
  return_type: (type)? @return_type
  body: (block) @body) @function
"""

PYTHON_CLASS_QUERY = """
; Match class definitions with optional decorators
(decorated_definition
  (decorator)* @decorator
  definition: (class_definition
    name: (identifier) @class_name
    superclasses: (argument_list)? @superclasses
    body: (block) @class_body)) @class

; Match standalone class definitions
(class_definition
  name: (identifier) @class_name
  superclasses: (argument_list)? @superclasses
  body: (block) @class_body) @class
"""

PYTHON_CALL_QUERY = """
; Match function/method calls
(call
  function: [
    (identifier) @callee
    (attribute
      object: (_) @object
      attribute: (identifier) @method)
  ]
  arguments: (argument_list) @args) @call
"""

PYTHON_IMPORT_QUERY = """
; Match import statements
(import_statement
  name: (dotted_name) @import_name) @import

; Match from imports
(import_from_statement
  module_name: (dotted_name)? @module
  name: [
    (dotted_name) @import_name
    (aliased_import name: (dotted_name) @import_name alias: (identifier) @alias)
    (wildcard_import) @wildcard
  ]) @import
"""

# =============================================================================
# JAVA QUERIES
# =============================================================================

JAVA_METHOD_QUERY = """
; Match method declarations with annotations
(method_declaration
  (modifiers
    (marker_annotation)* @annotation
    (annotation)* @annotation
    ["public" "private" "protected" "static" "final" "abstract" "synchronized" "native"]* @modifier
  )? @modifiers
  type: (_) @return_type
  name: (identifier) @name
  parameters: (formal_parameters) @params
  body: (block)? @body) @method

; Match constructor declarations
(constructor_declaration
  (modifiers)? @modifiers
  name: (identifier) @name
  parameters: (formal_parameters) @params
  body: (constructor_body) @body) @method
"""

JAVA_CLASS_QUERY = """
; Match class declarations
(class_declaration
  (modifiers)? @modifiers
  name: (identifier) @class_name
  superclass: (superclass (type_identifier) @superclass)?
  interfaces: (super_interfaces (type_list) @interfaces)?
  body: (class_body) @class_body) @class

; Match interface declarations
(interface_declaration
  (modifiers)? @modifiers
  name: (identifier) @class_name
  body: (interface_body) @class_body) @class

; Match enum declarations
(enum_declaration
  (modifiers)? @modifiers
  name: (identifier) @class_name
  interfaces: (super_interfaces)?
  body: (enum_body) @class_body) @class
"""

JAVA_CALL_QUERY = """
; Match method invocations
(method_invocation
  object: (_)? @object
  name: (identifier) @method
  arguments: (argument_list) @args) @call

; Match object creation
(object_creation_expression
  type: (type_identifier) @class
  arguments: (argument_list) @args) @call
"""

JAVA_IMPORT_QUERY = """
; Match import declarations
(import_declaration
  (scoped_identifier) @import_path
  (asterisk)? @wildcard) @import

; Match package declaration
(package_declaration
  (scoped_identifier) @package) @package_decl
"""

# =============================================================================
# JAVASCRIPT/TYPESCRIPT QUERIES
# =============================================================================

JAVASCRIPT_FUNCTION_QUERY = """
; Match function declarations
(function_declaration
  name: (identifier) @name
  parameters: (formal_parameters) @params
  body: (statement_block) @body) @function

; Match arrow functions assigned to variables
(lexical_declaration
  (variable_declarator
    name: (identifier) @name
    value: (arrow_function
      parameters: [(formal_parameters) (identifier)] @params
      body: [
        (statement_block) @body
        (_) @body
      ]))) @function

; Match var declarations with functions
(variable_declaration
  (variable_declarator
    name: (identifier) @name
    value: [(arrow_function) (function_expression)])) @function

; Match method definitions in classes
(method_definition
  name: (property_identifier) @name
  parameters: (formal_parameters) @params
  body: (statement_block) @body) @method

; Match generator functions
(generator_function_declaration
  name: (identifier) @name
  parameters: (formal_parameters) @params
  body: (statement_block) @body) @function

; Match async functions
(function_declaration
  "async" @async
  name: (identifier) @name
  parameters: (formal_parameters) @params
  body: (statement_block) @body) @function
"""

JAVASCRIPT_CLASS_QUERY = """
; Match class declarations
(class_declaration
  name: (identifier) @class_name
  heritage: (class_heritage
    (extends_clause (identifier) @superclass))?
  body: (class_body) @class_body) @class

; Match class expressions assigned to variables
(lexical_declaration
  (variable_declarator
    name: (identifier) @class_name
    value: (class
      body: (class_body) @class_body))) @class
"""

JAVASCRIPT_CALL_QUERY = """
; Match function calls
(call_expression
  function: [
    (identifier) @callee
    (member_expression
      object: (_) @object
      property: (property_identifier) @method)
  ]
  arguments: (arguments) @args) @call

; Match new expressions
(new_expression
  constructor: (identifier) @class
  arguments: (arguments)? @args) @call
"""

JAVASCRIPT_IMPORT_QUERY = """
; Match ES6 imports
(import_statement
  source: (string) @source
  (import_clause
    [
      (identifier) @default_import
      (named_imports (import_specifier name: (identifier) @named_import)*)
      (namespace_import (identifier) @namespace_import)
    ]?)) @import

; Match CommonJS requires
(lexical_declaration
  (variable_declarator
    name: [(identifier) (object_pattern)] @require_name
    value: (call_expression
      function: (identifier) @require_fn
      arguments: (arguments (string) @source)))) @require
"""

# =============================================================================
# QUERY REGISTRY - Maps language to queries
# =============================================================================

LANGUAGE_QUERIES = {
    "python": {
        "function": PYTHON_FUNCTION_QUERY,
        "class": PYTHON_CLASS_QUERY,
        "call": PYTHON_CALL_QUERY,
        "import": PYTHON_IMPORT_QUERY,
    },
    "java": {
        "function": JAVA_METHOD_QUERY,
        "class": JAVA_CLASS_QUERY,
        "call": JAVA_CALL_QUERY,
        "import": JAVA_IMPORT_QUERY,
    },
    "javascript": {
        "function": JAVASCRIPT_FUNCTION_QUERY,
        "class": JAVASCRIPT_CLASS_QUERY,
        "call": JAVASCRIPT_CALL_QUERY,
        "import": JAVASCRIPT_IMPORT_QUERY,
    },
    "typescript": {
        # TypeScript uses JavaScript queries (tree-sitter-javascript handles both)
        "function": JAVASCRIPT_FUNCTION_QUERY,
        "class": JAVASCRIPT_CLASS_QUERY,
        "call": JAVASCRIPT_CALL_QUERY,
        "import": JAVASCRIPT_IMPORT_QUERY,
    },
}

