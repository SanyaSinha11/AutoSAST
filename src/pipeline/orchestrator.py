"""
Pipeline Orchestrator - Coordinates the full analysis workflow.

This module ties together:
1. Semgrep scanning
2. Code context extraction
3. LLM analysis with guided questions
4. Result aggregation and reporting
"""

import json
import logging
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..config import Config, load_config
from ..semgrep.runner import SemgrepRunner, SemgrepResults, SemgrepFinding
from ..context.extractor import get_extractor_for_file, ExtractedContext
from ..context.cross_file_resolver import CrossFileResolver, CrossFileContext
from ..context.call_graph import CallGraph, CallGraphBuilder
from ..llm.client import create_llm_client, LLMClient
from ..llm.analyzer import FindingAnalyzer, AnalysisResult, Verdict
from ..questions.templates import get_questions_for_rule

logger = logging.getLogger(__name__)


@dataclass
class PipelineStats:
    """Statistics from a pipeline run."""
    total_findings: int = 0
    true_positives: int = 0
    false_positives: int = 0
    needs_review: int = 0
    insufficient_context: int = 0
    needs_more_context: int = 0  # New: Findings that needed more context
    analysis_errors: int = 0
    total_tokens_used: int = 0
    scan_time_seconds: float = 0.0
    analysis_time_seconds: float = 0.0
    # New: File and function analysis stats
    files_analyzed: int = 0
    functions_analyzed: int = 0
    cross_file_refs_resolved: int = 0
    unique_callers_found: int = 0
    unique_imports_resolved: int = 0
    files_scanned: set = field(default_factory=set)
    functions_analyzed_list: list = field(default_factory=list)
    # Tool calling stats
    total_tool_calls: int = 0
    # Context expansion stats
    total_context_iterations: int = 0
    findings_with_context_expansion: int = 0

    @property
    def false_positive_rate(self) -> float:
        if self.total_findings == 0:
            return 0.0
        return self.false_positives / self.total_findings

    @property
    def reduction_percentage(self) -> float:
        """Percentage of findings filtered as false positives."""
        return self.false_positive_rate * 100


@dataclass
class PipelineResult:
    """Complete result from a pipeline run."""
    scan_results: SemgrepResults
    analysis_results: list[AnalysisResult]
    stats: PipelineStats
    timestamp: datetime = field(default_factory=datetime.now)
    extracted_contexts: dict = field(default_factory=dict)  # Context info for each finding

    def get_actionable_findings(self) -> list[AnalysisResult]:
        """Get findings that require developer attention."""
        return [r for r in self.analysis_results if r.is_actionable]

    def get_filtered_findings(self) -> list[AnalysisResult]:
        """Get findings identified as false positives."""
        return [r for r in self.analysis_results if r.verdict == Verdict.FALSE_POSITIVE]

    def save_detailed_results(self, output_dir: Path) -> None:
        """
        Save detailed results per finding (VulnHalla-style).

        Creates two files per finding:
        - {finding_id}_raw.json: Raw input data (finding, context, prompt)
        - {finding_id}_final.json: Full LLM conversation history

        Args:
            output_dir: Directory to save results to
        """
        import json

        output_dir.mkdir(parents=True, exist_ok=True)

        for i, result in enumerate(self.analysis_results, 1):
            finding_id = f"{i:03d}"

            # Save raw input data
            context_key = f"{result.finding.file_path}:{result.finding.start_line}"
            raw_data = {
                "finding_id": finding_id,
                "rule_id": result.finding.rule_id,
                "severity": result.finding.severity,
                "message": result.finding.message,
                "location": result.finding.location_str,
                "code_snippet": result.finding.code_snippet,
                "context": self.extracted_contexts.get(context_key, {}),
            }
            raw_file = output_dir / f"{finding_id}_raw.json"
            with open(raw_file, "w") as f:
                json.dump(raw_data, f, indent=2, default=str)

            # Save final LLM conversation
            final_data = {
                "finding_id": finding_id,
                "verdict": result.verdict.value,
                "confidence": result.confidence,
                "reasoning": result.reasoning,
                "guided_answers": result.guided_answers,
                "tool_calls_made": result.tool_calls_made,
                "conversation_history": result.conversation_history,
                "tokens_used": result.llm_response.total_tokens,
            }
            final_file = output_dir / f"{finding_id}_final.json"
            with open(final_file, "w") as f:
                json.dump(final_data, f, indent=2, default=str)

        logger.info(f"Saved detailed results for {len(self.analysis_results)} findings to {output_dir}")

    def to_dict(self, include_context: bool = False) -> dict:
        """Convert to dictionary for JSON serialization."""
        findings_list = []
        for r in self.analysis_results:
            finding_dict = {
                "rule_id": r.finding.rule_id,
                "location": r.finding.location_str,
                "verdict": r.verdict.value,
                "confidence": r.confidence,
                "reasoning": r.reasoning,
                "guided_answers": r.guided_answers,
                "tool_calls_made": r.tool_calls_made,  # Track tool usage per finding
            }

            # Include context if requested
            if include_context:
                context_key = f"{r.finding.file_path}:{r.finding.start_line}"
                if context_key in self.extracted_contexts:
                    finding_dict["context"] = self.extracted_contexts[context_key]
                # Include conversation history for auditing
                if r.conversation_history:
                    finding_dict["conversation_history"] = r.conversation_history

            findings_list.append(finding_dict)

        return {
            "timestamp": self.timestamp.isoformat(),
            "stats": {
                "total_findings": self.stats.total_findings,
                "true_positives": self.stats.true_positives,
                "false_positives": self.stats.false_positives,
                "needs_review": self.stats.needs_review,
                "needs_more_context": self.stats.needs_more_context,
                "reduction_percentage": self.stats.reduction_percentage,
                "files_analyzed": self.stats.files_analyzed,
                "functions_analyzed": self.stats.functions_analyzed,
                "cross_file_refs_resolved": self.stats.cross_file_refs_resolved,
                "unique_callers_found": self.stats.unique_callers_found,
                "unique_imports_resolved": self.stats.unique_imports_resolved,
                "total_tool_calls": self.stats.total_tool_calls,  # VulnHalla-style tool calls
                "total_context_iterations": self.stats.total_context_iterations,
                "findings_with_context_expansion": self.stats.findings_with_context_expansion,
            },
            "analysis_scope": {
                "files_scanned": list(self.stats.files_scanned),
                "functions_analyzed": self.stats.functions_analyzed_list,
            },
            "findings": findings_list,
        }


class Pipeline:
    """Main pipeline for Semgrep false positive reduction."""

    def __init__(
        self,
        config: Optional[Config] = None,
        llm_client: Optional[LLMClient] = None,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        verbose: bool = False,
        include_context: bool = False,
        enable_tool_calling: bool = True,  # Enable VulnHalla-style tool calling
        enable_iterative_context: bool = False,  # Enable iterative context expansion
        max_context_iterations: int = 3,  # Max iterations for context expansion
        use_call_graph: bool = True,  # Use pre-indexed call graph for O(1) caller lookups
    ):
        self.config = config or load_config()
        self.llm_client = llm_client or self._create_llm_client()
        self.progress_callback = progress_callback
        self.verbose = verbose
        self.include_context = include_context
        self.enable_tool_calling = enable_tool_calling
        self.enable_iterative_context = enable_iterative_context
        self.max_context_iterations = max_context_iterations
        self.use_call_graph = use_call_graph
        self._target_path: Optional[Path] = None  # Set during run()
        self._call_graph: Optional[CallGraph] = None  # Built lazily during run()

        # Store extracted contexts for each finding (for debugging/visualization)
        self.extracted_contexts: dict[str, dict] = {}

        self.semgrep_runner = SemgrepRunner(self.config.semgrep_path)
        # Analyzer will be configured with project_root during run()
        self.analyzer = FindingAnalyzer(
            self.llm_client,
            self.config.temperature,
            enable_tool_calling=enable_tool_calling,
        )
    
    def _create_llm_client(self) -> LLMClient:
        return create_llm_client(
            provider=self.config.provider,
            model=self.config.model,
            openai_api_key=self.config.openai_api_key,
            azure_api_key=self.config.azure_api_key,
            azure_endpoint=self.config.azure_endpoint,
            azure_api_version=self.config.azure_api_version,
            google_api_key=self.config.google_api_key,
            groq_api_key=self.config.groq_api_key,
            ollama_base_url=self.config.ollama_base_url,
        )
    
    def _report_progress(self, current: int, total: int, message: str):
        if self.progress_callback:
            self.progress_callback(current, total, message)
        logger.info(f"[{current}/{total}] {message}")

    def _infer_project_root(self, target_path: Path) -> Path:
        """
        Infer the project root from the target path.

        This is important for cross-file analysis - we need to scan related files
        to find callers, validators, etc.
        """
        # If it's already a directory, use it
        if target_path.is_dir():
            return target_path

        # For files, try to find a reasonable project root
        current = target_path.parent

        # Markers that indicate project root
        root_markers = [
            'pom.xml', 'build.gradle', 'build.gradle.kts',  # Java
            'package.json',  # JavaScript/TypeScript
            'requirements.txt', 'pyproject.toml', 'setup.py',  # Python
            '.git', 'src',  # Generic
        ]

        # Walk up the directory tree looking for markers
        for _ in range(10):  # Limit depth to prevent going too far up
            if not current or current == current.parent:
                break

            for marker in root_markers:
                if (current / marker).exists():
                    logger.debug(f"Found project root marker '{marker}' at {current}")
                    return current

            current = current.parent

        # If no marker found, use the parent of the target file
        # Try to find a 'src' or similar directory
        current = target_path.parent
        while current.name and current.name not in ['src', 'main', 'java', 'test']:
            if current == current.parent:
                break
            current = current.parent

        # If we found 'src' or similar, use its parent
        if current.name in ['src', 'main', 'java']:
            while current.name in ['src', 'main', 'java', 'test']:
                current = current.parent
            return current

        # Fallback to 3 levels up from the file
        result = target_path.parent.parent.parent if target_path.is_file() else target_path
        logger.debug(f"Using inferred project root: {result}")
        return result

    def run(
        self,
        target_path: Path,
        semgrep_config: Optional[str] = None,
        semgrep_rules_path: Optional[Path] = None,
        max_workers: int = 4,
        max_findings: Optional[int] = None,
    ) -> PipelineResult:
        """Run the full analysis pipeline.
        
        Args:
            target_path: Directory or file to scan
            semgrep_config: Semgrep config string (e.g., "p/security-audit", "auto")
            semgrep_rules_path: Path to custom rules file/directory
            max_workers: Maximum parallel workers for analysis
            max_findings: Limit number of findings to analyze
        """
        import time

        # Set project root for tool calling
        # If target is a file, use its parent directory to find related files
        # Try to find a reasonable project root (look for src/, pom.xml, build.gradle, etc.)
        self._target_path = target_path
        project_root = self._infer_project_root(target_path)
        self.analyzer.project_root = project_root
        logger.debug(f"Project root for tool calling: {project_root}")

        # Build call graph for O(1) caller lookups (if enabled)
        if self.use_call_graph:
            try:
                graph_start = time.time()
                builder = CallGraphBuilder(project_root)
                self._call_graph = builder.build()
                graph_time = time.time() - graph_start
                logger.info(f"Built call graph in {graph_time:.2f}s: {self._call_graph.get_stats()}")
                if self.verbose:
                    print(f"📊 Call graph built: {self._call_graph.get_stats()}")
            except Exception as e:
                logger.warning(f"Failed to build call graph, falling back to scanning: {e}")
                self._call_graph = None

        stats = PipelineStats()

        # Step 1: Run Semgrep scan
        self._report_progress(0, 1, "Running Semgrep scan...")
        scan_start = time.time()
        scan_results = self.semgrep_runner.scan(
            target_path, 
            config=semgrep_config,
            rules_path=semgrep_rules_path
        )
        stats.scan_time_seconds = time.time() - scan_start
        stats.total_findings = scan_results.finding_count

        if scan_results.errors:
            for error in scan_results.errors:
                logger.warning(f"Semgrep error: {error}")

        self._report_progress(1, 1, f"Found {stats.total_findings} findings")

        # Apply limit if specified
        findings_to_analyze = scan_results.findings
        if max_findings and max_findings < len(findings_to_analyze):
            logger.info(f"Limiting analysis to {max_findings} findings (out of {len(findings_to_analyze)})")
            findings_to_analyze = findings_to_analyze[:max_findings]
            stats.total_findings = max_findings

        # Step 2: Analyze each finding
        analysis_results = []
        analysis_start = time.time()

        for i, finding in enumerate(findings_to_analyze):
            self._report_progress(
                i + 1,
                stats.total_findings,
                f"Analyzing {finding.rule_id} at {finding.location_str}",
            )

            try:
                result = self._analyze_finding(finding, target_path, stats)
                analysis_results.append(result)

                # Update stats
                stats.total_tokens_used += result.llm_response.total_tokens
                stats.total_tool_calls += result.tool_calls_made  # Track tool calls

                # Track context expansion stats
                if hasattr(result, 'context_iterations') and result.context_iterations > 1:
                    stats.total_context_iterations += result.context_iterations
                    stats.findings_with_context_expansion += 1

                if result.verdict == Verdict.TRUE_POSITIVE:
                    stats.true_positives += 1
                elif result.verdict == Verdict.FALSE_POSITIVE:
                    stats.false_positives += 1
                elif result.verdict == Verdict.NEEDS_REVIEW:
                    stats.needs_review += 1
                elif result.verdict == Verdict.NEEDS_MORE_CONTEXT:
                    stats.needs_more_context += 1
                else:
                    stats.insufficient_context += 1

            except Exception as e:
                logger.error(f"Error analyzing finding: {e}", exc_info=True)
                stats.analysis_errors += 1

        stats.analysis_time_seconds = time.time() - analysis_start

        return PipelineResult(
            scan_results=scan_results,
            analysis_results=analysis_results,
            stats=stats,
            extracted_contexts=self.extracted_contexts,
        )
    
    def _analyze_finding(self, finding: SemgrepFinding, base_path: Path, stats: PipelineStats) -> AnalysisResult:
        """Analyze a single finding with context extraction and cross-file resolution."""
        # Extract code context
        # Semgrep returns paths relative to CWD, not relative to target path
        # So we just use the path directly if it exists, otherwise try with base_path
        finding_path = Path(finding.file_path)
        if finding_path.exists():
            file_path = finding_path
        elif not finding_path.is_absolute():
            file_path = base_path / finding.file_path
        else:
            file_path = finding_path
        extractor = get_extractor_for_file(file_path)
        context = extractor.extract_context(file_path, finding.start_line)

        # Track files analyzed
        stats.files_scanned.add(str(file_path))
        stats.files_analyzed = len(stats.files_scanned)

        # Track functions analyzed
        if context.function_context:
            func_info = f"{context.additional_context.get('class_name', 'Unknown')}.{context.function_context.name}"
            if func_info not in stats.functions_analyzed_list:
                stats.functions_analyzed_list.append(func_info)
            stats.functions_analyzed = len(stats.functions_analyzed_list)

        # Cross-file resolution for supported languages (Java, Python, JavaScript)
        supported_extensions = {'.java', '.py', '.js', '.jsx', '.ts', '.tsx'}
        if file_path.suffix in supported_extensions and context.function_context:
            try:
                # Pass call graph for O(1) caller lookups
                cross_resolver = CrossFileResolver(base_path, call_graph=self._call_graph)
                class_name = context.additional_context.get('class_name', '')
                method_name = context.function_context.name

                cross_ctx = cross_resolver.resolve_context(
                    file_path, class_name, method_name,
                    max_callers=5, resolve_imports=True
                )

                # Track cross-file resolution stats
                stats.unique_callers_found += len(cross_ctx.callers)
                stats.unique_imports_resolved += len(cross_ctx.resolved_imports)
                stats.cross_file_refs_resolved += len(cross_ctx.callers) + len(cross_ctx.resolved_imports) + len(cross_ctx.related_methods)

                # Track files referenced by cross-file resolution
                for caller in cross_ctx.callers:
                    stats.files_scanned.add(caller.source_file)
                for imp in cross_ctx.resolved_imports:
                    stats.files_scanned.add(imp.target_file)
                stats.files_analyzed = len(stats.files_scanned)

                # Add cross-file context to the extracted context
                context.cross_file_context = self._cross_file_to_dict(cross_ctx)
                context.full_class_code = cross_ctx.full_class_code

                if self.verbose:
                    self._log_cross_file_context(cross_ctx)
            except Exception as e:
                logger.debug(f"Cross-file resolution failed: {e}")

        # Get guided questions for this rule (with file path for language-specific questions)
        questions = get_questions_for_rule(finding.rule_id, finding.file_path)

        # Verbose logging of context extraction
        if self.verbose:
            self._log_context_details(finding, context, questions, extractor)

        # Store context for later reference
        context_key = f"{finding.file_path}:{finding.start_line}"
        self.extracted_contexts[context_key] = self._context_to_dict(context, questions, finding)

        # Run LLM analysis - choose analysis method based on configuration
        if self.enable_iterative_context and self.enable_tool_calling:
            # Use iterative context expansion for maximum accuracy
            result = self.analyzer.analyze_with_iterative_context(
                finding, context, questions,
                max_iterations=self.max_context_iterations
            )
            if self.verbose:
                if result.tool_calls_made > 0:
                    logger.info(f"  Tool calls made: {result.tool_calls_made}")
                if result.context_iterations > 1:
                    logger.info(f"  Context iterations: {result.context_iterations}")
            return result
        elif self.enable_tool_calling:
            result = self.analyzer.analyze_with_tools(finding, context, questions)
            if self.verbose and result.tool_calls_made > 0:
                logger.info(f"  Tool calls made: {result.tool_calls_made}")
            return result
        else:
            return self.analyzer.analyze(finding, context, questions)

    def _cross_file_to_dict(self, cross_ctx: CrossFileContext) -> dict:
        """Convert cross-file context to dictionary with enriched call graph data."""
        import re

        # Detect entry points in the caller chain
        entry_point_patterns = ['Controller', 'Servlet', 'Handler', 'doGet', 'doPost',
                                '@GetMapping', '@PostMapping', '@RequestMapping']

        # Sanitization/validation patterns to detect
        sanitization_patterns = [
            r'\.escapeHtml\(', r'\.encodeForHTML\(', r'\.sanitize\(',
            r'StringEscapeUtils\.escape', r'HtmlUtils\.htmlEscape',
            r'\.matches\s*\([^)]*\)', r'Pattern\.matches', r'\.replaceAll\s*\(',
            r'Integer\.parseInt', r'Long\.parseLong', r'Double\.parseDouble',
            r'\.trim\(\)', r'\.strip\(',
            r'@Valid\b', r'@NotNull\b', r'@NotBlank\b', r'@Pattern\(',
            r'Validator\.', r'\.validate\(',
            r'PreparedStatement', r'\.setString\(', r'\.setInt\(',
            r'\.createQuery\([^)]+\)\.setParameter\(',
        ]
        sanitization_regex = '|'.join(sanitization_patterns)

        callers_data = []
        entry_points_found = []
        sanitization_found = []

        for c in cross_ctx.callers[:8]:
            is_entry_point = any(
                pattern in c.source_class or pattern in c.code_snippet
                for pattern in entry_point_patterns
            )

            # Check for sanitization in this caller
            sanitization_matches = re.findall(sanitization_regex, c.code_snippet, re.IGNORECASE)
            has_sanitization = len(sanitization_matches) > 0

            caller_info = {
                "file": c.source_file.split('/')[-1],
                "class": c.source_class,
                "method": c.source_method,
                "line": c.line_number,
                "snippet": c.code_snippet[:500],  # Increased for better context
                "is_entry_point": is_entry_point,
                "has_sanitization": has_sanitization,
                "sanitization_hints": sanitization_matches[:3] if sanitization_matches else [],
            }
            callers_data.append(caller_info)

            if is_entry_point:
                entry_points_found.append(f"{c.source_class}.{c.source_method}()")

            if has_sanitization:
                sanitization_found.append({
                    "location": f"{c.source_class}.{c.source_method}()",
                    "patterns": sanitization_matches[:3],
                })

        return {
            "callers": callers_data,
            "related_methods": [
                {
                    "name": m.source_method,
                    "line": m.line_number,
                    "snippet": m.code_snippet[:200]
                }
                for m in cross_ctx.related_methods[:5]
            ],
            "resolved_imports_count": len(cross_ctx.resolved_imports),
            "data_flow_chain": cross_ctx.data_flow_chain,  # Add the traced call chain
            "entry_points": entry_points_found,  # Identified entry points
            "sanitization_detected": sanitization_found,  # Pre-detected sanitization
            "has_call_chain": len(cross_ctx.callers) > 0,
        }

    def _log_cross_file_context(self, cross_ctx: CrossFileContext) -> None:
        """Log cross-file context for debugging."""
        print("\n" + "-" * 40)
        print("🔗 CROSS-FILE CONTEXT")
        print("-" * 40)

        if cross_ctx.callers:
            print(f"📞 Callers ({len(cross_ctx.callers)}):")
            for c in cross_ctx.callers[:3]:
                print(f"   • {c.source_class}.{c.source_method}() at {c.source_file.split('/')[-1]}:{c.line_number}")

        if cross_ctx.related_methods:
            print(f"🔗 Related Methods ({len(cross_ctx.related_methods)}):")
            for m in cross_ctx.related_methods[:5]:
                print(f"   • {m.source_method}() at line {m.line_number}")

        if cross_ctx.resolved_imports:
            print(f"📦 Resolved Imports ({len(cross_ctx.resolved_imports)}):")
            for i in cross_ctx.resolved_imports[:3]:
                print(f"   • {i.target_class} -> {i.target_file.split('/')[-1]}")

    def _log_context_details(self, finding: SemgrepFinding, context: ExtractedContext,
                              questions: list[str], extractor) -> None:
        """Log detailed context extraction information."""
        print("\n" + "=" * 80)
        print(f"📋 CONTEXT EXTRACTION DETAILS")
        print("=" * 80)
        print(f"📍 Finding: {finding.rule_id}")
        print(f"📄 File: {finding.file_path}:{finding.start_line}")
        print(f"🔧 Extractor: {extractor.__class__.__name__}")
        print()

        # Function context
        if context.function_context:
            fc = context.function_context
            print(f"✅ Function Context Found:")
            print(f"   • Function Name: {fc.name}")
            print(f"   • Lines: {fc.start_line}-{fc.end_line} ({fc.line_count} lines)")
            print(f"   • Language: {fc.language}")
            print()
            print("   📝 Function Code:")
            for i, line in enumerate(fc.full_code.split('\n')[:20]):
                print(f"      {fc.start_line + i:4d} | {line}")
            if fc.line_count > 20:
                print(f"      ... ({fc.line_count - 20} more lines)")
        else:
            print("⚠️  No function context extracted (using surrounding lines)")
            print()
            print("   📝 Surrounding Context:")
            print(context.surrounding_context[:500])

        print()

        # Additional context
        if context.additional_context:
            print("📦 Additional Context:")
            if context.additional_context.get("imports"):
                print(f"   • Imports: {len(context.additional_context['imports'])} found")
                for imp in context.additional_context['imports'][:5]:
                    print(f"      - {imp}")
            if context.additional_context.get("package"):
                print(f"   • Package: {context.additional_context['package']}")
            if context.additional_context.get("class_name"):
                print(f"   • Class: {context.additional_context['class_name']}")

        print()

        # Guided questions
        print(f"❓ Guided Questions ({len(questions)}):")
        for i, q in enumerate(questions, 1):
            print(f"   {i}. {q}")

        # Context gaps analysis
        print()
        print("🔍 CONTEXT GAP ANALYSIS:")
        gaps = self._analyze_context_gaps(finding, context)
        if gaps:
            for gap in gaps:
                print(f"   ⚠️  {gap}")
        else:
            print("   ✅ No significant context gaps detected")

        print("=" * 80)

    def _analyze_context_gaps(self, finding: SemgrepFinding, context: ExtractedContext) -> list[str]:
        """Analyze what context might be missing for better analysis."""
        gaps = []

        # Check if function context was extracted
        if not context.function_context:
            gaps.append("Could not extract containing function - analysis based on surrounding lines only")

        # Check for cross-file references
        code = context.function_context.full_code if context.function_context else context.surrounding_context

        # Look for method calls that might need more context
        if '.validate' in code.lower() or '.sanitize' in code.lower():
            gaps.append("Code references validation/sanitization methods - their implementation is not included")

        if '.getParameter' in code or '.getHeader' in code:
            gaps.append("Code processes HTTP input - upstream validation (filters, interceptors) not visible")

        # Check for service/dependency injection patterns
        if 'service.' in code.lower() or 'repository.' in code.lower():
            gaps.append("Code calls service/repository methods - their implementations are not included")

        # Check for class fields/constructor that might have sanitization
        if 'this.' in code.lower() and not context.additional_context.get("class_fields"):
            gaps.append("Code uses class fields - field initialization/configuration not visible")

        # Check for annotations that might add security
        if finding.file_path.endswith('.java'):
            if '@Valid' not in code and '@Validated' not in code:
                gaps.append("No Bean Validation annotations visible - may exist at class or parameter level")
            if 'PreparedStatement' not in code and 'JdbcTemplate' not in code and 'sql' in finding.rule_id.lower():
                gaps.append("No parameterized query visible - DAO/Repository layer not inspected")

        # Check for framework-specific security
        if 'spring' in str(context.additional_context.get('imports', [])).lower():
            gaps.append("Spring framework detected - security configurations (WebSecurityConfig, filters) not visible")

        return gaps

    def _context_to_dict(self, context: ExtractedContext, questions: list[str],
                          finding: Optional[SemgrepFinding] = None) -> dict:
        """Convert context to a dictionary for JSON output."""
        result = {
            "finding_line": context.finding_line,
            "finding_code": context.finding_code,
            "file_path": context.file_path,
            "guided_questions": questions,
        }

        if context.function_context:
            fc = context.function_context
            result["function_context"] = {
                "name": fc.name,
                "start_line": fc.start_line,
                "end_line": fc.end_line,
                "line_count": fc.line_count,
                "language": fc.language,
                "code": fc.full_code,
            }
        else:
            result["function_context"] = None
            result["surrounding_context"] = context.surrounding_context

        result["additional_context"] = context.additional_context

        # Include context gaps analysis if finding is provided
        if finding:
            result["context_gaps"] = self._analyze_context_gaps(finding, context)

        return result

