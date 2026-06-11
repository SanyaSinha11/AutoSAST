# Code context extraction module

from .extractor import (
    ContextExtractor,
    ExtractedContext,
    FunctionContext,
    PythonExtractor,
    JavaScriptExtractor,
    JavaExtractor,
    GenericExtractor,
    get_extractor_for_file,
    clear_extractor_cache,
    get_extraction_stats,
)
from .cross_file_resolver import (
    CrossFileResolver,
    CrossFileContext,
    ResolvedReference,
)
from .code_lookup import CodeLookup
from .call_graph import (
    CallGraph,
    CallGraphNode,
    CallGraphEdge,
    CallPath,
    CallGraphBuilder,
    PythonCallGraphBuilder,
    JavaScriptCallGraphBuilder,
    MultiLanguageCallGraphBuilder,
)

# Taint analysis for inter-procedural data flow
try:
    from .taint_analyzer import (
        TaintAnalyzer,
        TaintVariable,
        TaintPath,
        TaintFlowStep,
        TaintLevel,
        TaintSource,
    )
    _TAINT_AVAILABLE = True
except ImportError:
    _TAINT_AVAILABLE = False
    TaintAnalyzer = None
    TaintVariable = None
    TaintPath = None
    TaintFlowStep = None
    TaintLevel = None
    TaintSource = None

# Constant analyzer for trusted source detection
try:
    from .constant_analyzer import (
        ConstantAnalyzer,
        ConstantInfo,
        ConstantType,
        CallerArgumentAnalysis,
    )
    _CONSTANT_ANALYZER_AVAILABLE = True
except ImportError:
    _CONSTANT_ANALYZER_AVAILABLE = False
    ConstantAnalyzer = None
    ConstantInfo = None
    ConstantType = None
    CallerArgumentAnalysis = None

# Sink verifier for output context validation
try:
    from .sink_verifier import (
        SinkVerifier,
        SinkVerificationResult,
        VulnerabilityType,
    )
    _SINK_VERIFIER_AVAILABLE = True
except ImportError:
    _SINK_VERIFIER_AVAILABLE = False
    SinkVerifier = None
    SinkVerificationResult = None
    VulnerabilityType = None

try:
    from .pre_analysis_filter import (
        PreAnalysisFilter,
        PreAnalysisResult,
        PreAnalysisVerdict,
    )
    _PRE_ANALYSIS_AVAILABLE = True
except ImportError:
    _PRE_ANALYSIS_AVAILABLE = False
    PreAnalysisFilter = None
    PreAnalysisResult = None
    PreAnalysisVerdict = None

# Source classifier for intelligent data flow tracing
try:
    from .source_classifier import (
        SourceClassifier,
        SourceClassification,
        SourceType,
        SourceTrace,
    )
    _SOURCE_CLASSIFIER_AVAILABLE = True
except ImportError:
    _SOURCE_CLASSIFIER_AVAILABLE = False
    SourceClassifier = None
    SourceClassification = None
    SourceType = None
    SourceTrace = None

# AST parser exports (optional - may not be available if tree-sitter not installed)
try:
    from .ast_parser import (
        ASTParser,
        PythonASTParser,
        JavaScriptASTParser,
        JavaASTParser,
        FunctionInfo,
        ClassInfo,
        CallInfo,
        get_ast_parser_for_file,
        is_tree_sitter_available,
    )
    _AST_AVAILABLE = True
except ImportError:
    _AST_AVAILABLE = False
    ASTParser = None
    PythonASTParser = None
    JavaScriptASTParser = None
    JavaASTParser = None
    FunctionInfo = None
    ClassInfo = None
    CallInfo = None
    get_ast_parser_for_file = None
    is_tree_sitter_available = lambda: False

__all__ = [
    # Core extractors
    "ContextExtractor",
    "ExtractedContext",
    "FunctionContext",
    "PythonExtractor",
    "JavaScriptExtractor",
    "JavaExtractor",
    "GenericExtractor",
    "get_extractor_for_file",
    "clear_extractor_cache",
    "get_extraction_stats",
    # Cross-file resolution
    "CrossFileResolver",
    "CrossFileContext",
    "ResolvedReference",
    # Code lookup
    "CodeLookup",
    # Call graph
    "CallGraph",
    "CallGraphNode",
    "CallGraphEdge",
    "CallPath",
    "CallGraphBuilder",
    # AST parser (optional)
    "ASTParser",
    "PythonASTParser",
    "JavaScriptASTParser",
    "JavaASTParser",
    "FunctionInfo",
    "ClassInfo",
    "CallInfo",
    "get_ast_parser_for_file",
    "is_tree_sitter_available",
    # Constant analyzer
    "ConstantAnalyzer",
    "ConstantInfo",
    "ConstantType",
    "CallerArgumentAnalysis",
    # Sink verifier
    "SinkVerifier",
    "SinkVerificationResult",
    "VulnerabilityType",
    # Pre-analysis filter
    "PreAnalysisFilter",
    "PreAnalysisResult",
    "PreAnalysisVerdict",
    # Source classifier
    "SourceClassifier",
    "SourceClassification",
    "SourceType",
    "SourceTrace",
]
