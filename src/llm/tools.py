"""
LLM Tool Definitions for Dynamic Context Retrieval.

Inspired by VulnHalla's approach, this module defines tools that allow the LLM
to dynamically request additional code context during vulnerability analysis.

The key insight is that providing all context upfront can be:
- Too much context (overwhelming the LLM)
- Not enough context (missing the exact code needed)

By allowing the LLM to request specific context, we get better analysis.
"""

import json
import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ToolDefinition:
    """Definition of a tool that the LLM can call."""
    name: str
    description: str
    parameters: dict[str, Any]
    handler: Optional[Callable] = None


@dataclass
class ToolCall:
    """A tool call requested by the LLM."""
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class ToolResult:
    """Result of executing a tool call."""
    tool_call_id: str
    content: str
    success: bool = True


# Tool definitions in OpenAI function calling format
ANALYSIS_TOOLS = [
    # ============================================================
    # CORE AUTONOMOUS NAVIGATION TOOLS
    # These tools enable the LLM to explore code like a human developer
    # ============================================================
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a file's source code, optionally centered around a specific line number. Use this as your PRIMARY tool for understanding code - see imports, class structure, method implementations, and surrounding context. Essential for tracing data flow.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file (can be relative path or just the filename)"
                    },
                    "line_number": {
                        "type": "integer",
                        "description": "Optional: Center the view around this line number to see specific code in context"
                    },
                    "context_lines": {
                        "type": "integer",
                        "description": "Number of lines to show before and after the target line (default: 50)"
                    }
                },
                "required": ["file_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_code",
            "description": "Search the codebase for a pattern (method call, variable usage, class name, etc.). Returns file paths and line numbers for navigation. Use this to find callers, usages, or implementations, then use read_file to examine matches.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "The pattern to search for (method name, variable, class, or any text)"
                    },
                    "file_extension": {
                        "type": "string",
                        "description": "Optional: Limit search to files with this extension (e.g., '.java')"
                    }
                },
                "required": ["pattern"]
            }
        }
    },
    # ============================================================
    # STRUCTURED CODE RETRIEVAL TOOLS
    # These tools extract specific code constructs
    # ============================================================
    {
        "type": "function",
        "function": {
            "name": "get_function_code",
            "description": "Get the full source code of a function or method by name. Use this to examine functions called from the vulnerable code or helper functions that might contain sanitization.",
            "parameters": {
                "type": "object",
                "properties": {
                    "function_name": {
                        "type": "string",
                        "description": "Name of the function to retrieve"
                    },
                    "class_name": {
                        "type": "string",
                        "description": "Optional: Name of the class containing the method"
                    }
                },
                "required": ["function_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_caller_function",
            "description": "Get the code of a function that calls the current vulnerable function. Use this to trace data flow backwards and check for sanitization in callers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "caller_index": {
                        "type": "integer",
                        "description": "Index of the caller to retrieve (0 = first/most relevant caller)"
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_class_code",
            "description": "Get the full source code of a class. Use this to understand the complete context including all methods and fields.",
            "parameters": {
                "type": "object",
                "properties": {
                    "class_name": {
                        "type": "string",
                        "description": "Name of the class to retrieve"
                    }
                },
                "required": ["class_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_method_code",
            "description": "Get the source code of a specific method within a class. Use this when you need to check a specific method's implementation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "class_name": {
                        "type": "string",
                        "description": "Name of the class containing the method"
                    },
                    "method_name": {
                        "type": "string",
                        "description": "Name of the method to retrieve"
                    }
                },
                "required": ["class_name", "method_name"]
            }
        }
    },
    # NOTE: search_codebase is now an alias for search_code (kept for backward compatibility)
    # Prefer using search_code for new implementations
    {
        "type": "function",
        "function": {
            "name": "get_imports",
            "description": "Get the import statements from a file. Use this to understand what libraries and utilities are available.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file (relative to project root)"
                    }
                },
                "required": ["file_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "map_arguments",
            "description": "Map arguments from a caller function to a callee function. Use this to understand data flow between functions - which variables in the caller are passed to which parameters in the callee.",
            "parameters": {
                "type": "object",
                "properties": {
                    "caller_function": {
                        "type": "string",
                        "description": "Name of the calling function"
                    },
                    "callee_function": {
                        "type": "string",
                        "description": "Name of the called function"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file containing the caller (optional, uses current file if not specified)"
                    }
                },
                "required": ["caller_function", "callee_function"]
            }
        }
    },
    # NOTE: trace_taint_path has been deprecated in favor of analyze_data_flow
    # which provides inter-procedural analysis with comprehensive sanitization detection
    {
        "type": "function",
        "function": {
            "name": "get_sanitization_check",
            "description": "Check if a variable is sanitized or validated before reaching a sink. Returns sanitization methods found and their effectiveness.",
            "parameters": {
                "type": "object",
                "properties": {
                    "variable_name": {
                        "type": "string",
                        "description": "The variable to check for sanitization"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to analyze"
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "Line number where the variable is first used"
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "Line number of the sink"
                    }
                },
                "required": ["variable_name", "file_path", "start_line", "end_line"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_caller_chain",
            "description": "Trace backwards from a function to find all callers up to entry points (controllers, handlers). Useful for understanding how user input reaches a vulnerable function.",
            "parameters": {
                "type": "object",
                "properties": {
                    "function_name": {
                        "type": "string",
                        "description": "The function to trace callers for"
                    },
                    "class_name": {
                        "type": "string",
                        "description": "The class containing the function"
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "Maximum depth to trace (default: 5)"
                    }
                },
                "required": ["function_name", "class_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_data_flow",
            "description": "Perform inter-procedural data flow analysis to track how a tainted variable flows from source to sink, including through function calls. Returns whether the data is sanitized along the path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "source_variable": {
                        "type": "string",
                        "description": "The variable to track (e.g., 'userId', 'request.getParameter()')"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to analyze"
                    },
                    "function_name": {
                        "type": "string",
                        "description": "Name of the function containing the code"
                    },
                    "include_callers": {
                        "type": "boolean",
                        "description": "Whether to trace through caller functions (default: true)"
                    }
                },
                "required": ["source_variable", "file_path"]
            }
        }
    }
]


