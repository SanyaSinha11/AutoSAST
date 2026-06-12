"""
CLI entry point for AutoSAST - LLM-Powered False Positive Reduction for Static Analysis.

Usage:
    python -m src.cli scan <target> [options]
    python -m src.cli context <file> <line> [--rule <rule_id>]
    python -m src.cli view <results_file>

Examples:
    python -m src.cli scan ./src --config auto --limit 10
    python -m src.cli scan ./project -o results.json --ui
"""

import argparse
import json
import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich.style import Style
from rich.box import ROUNDED, HEAVY, DOUBLE
from rich import box

from .config import load_config
from .pipeline.orchestrator import Pipeline, PipelineResult
from .llm.analyzer import Verdict
from .git_utils import GitRepositoryHandler, GitCloneResult

# Initialize Rich console
console = Console()


def generate_output_path(target: Path, base_dir: str = "results") -> Path:
    """
    Generate automatic output path with timestamp and target name.

    Creates results folder if it doesn't exist.
    Naming convention: scan_<target>_<timestamp>.json

    Args:
        target: Target path that was scanned
        base_dir: Base directory for results (default: "results")

    Returns:
        Path object for the output file
    """
    # Create results directory if it doesn't exist
    results_dir = Path(base_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    # Generate timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Generate sanitized target name
    target_name = Path(target).name if Path(target).name else "codebase"
    # Remove special characters from target name
    target_name = "".join(c if c.isalnum() or c in ('-', '_') else '_' for c in target_name)

    # Generate filename: scan_<target>_<timestamp>.json
    filename = f"scan_{target_name}_{timestamp}.json"

    return results_dir / filename


def setup_logging(level: str = "INFO", log_file: Optional[str] = None, quiet: bool = False):
    """Configure logging."""
    handlers = []
    if not quiet:
        handlers.append(logging.StreamHandler())
    if log_file:
        handlers.append(logging.FileHandler(log_file))

    if handlers:
        logging.basicConfig(
            level=getattr(logging, level.upper()),
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=handlers,
        )
    else:
        logging.disable(logging.CRITICAL)


def print_banner():
    """Print the enhanced AutoSAST banner."""
    from rich.align import Align
    from rich.text import Text
    from rich.panel import Panel

    # Create stylized banner text
    banner_lines = []

    # Title with ASCII styling
    title = Text()
    title.append("    ", style="")
    title.append("╔══════════════════════════════════════════════════════════╗", style="bold bright_cyan")
    banner_lines.append(title)

    line1 = Text()
    line1.append("    ", style="")
    line1.append("║  ", style="bold bright_cyan")
    line1.append("   ░█████╗░██╗░░░██╗████████╗░█████╗░░██████╗░█████╗░░██████╗████████╗", style="bold bright_cyan")
    line1.append("   ║", style="bold bright_cyan")
    banner_lines.append(line1)

    line2 = Text()
    line2.append("    ", style="")
    line2.append("║  ", style="bold bright_cyan")
    line2.append("   ██╔══██╗██║░░░██║╚══██╔══╝██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝", style="bold bright_cyan")
    line2.append("   ║", style="bold bright_cyan")
    banner_lines.append(line2)

    line3 = Text()
    line3.append("    ", style="")
    line3.append("║  ", style="bold bright_cyan")
    line3.append("   ███████║██║░░░██║░░░██║░░░██║░░██║╚█████╗░███████║╚█████╗░░░░██║░░░", style="bold bright_cyan")
    line3.append("   ║", style="bold bright_cyan")
    banner_lines.append(line3)

    line4 = Text()
    line4.append("    ", style="")
    line4.append("║  ", style="bold bright_cyan")
    line4.append("   ██╔══██║██║░░░██║░░░██║░░░██║░░██║░╚═══██╗██╔══██║░╚═══██╗░░░██║░░░", style="bold bright_cyan")
    line4.append("   ║", style="bold bright_cyan")
    banner_lines.append(line4)

    line5 = Text()
    line5.append("    ", style="")
    line5.append("║  ", style="bold bright_cyan")
    line5.append("   ██║░░██║╚██████╔╝░░░██║░░░╚█████╔╝██████╔╝██║░░██║██████╔╝░░░██║░░░", style="bold bright_cyan")
    line5.append("   ║", style="bold bright_cyan")
    banner_lines.append(line5)

    line6 = Text()
    line6.append("    ", style="")
    line6.append("║  ", style="bold bright_cyan")
    line6.append("   ╚═╝░░╚═╝░╚═════╝░░░░╚═╝░░░░╚════╝░╚═════╝░╚═╝░░╚═╝╚═════╝░░░░╚═╝░░░", style="bold bright_cyan")
    line6.append("   ║", style="bold bright_cyan")
    banner_lines.append(line6)

    empty = Text()
    empty.append("    ", style="")
    empty.append("║                                                                              ║", style="bold bright_cyan")
    banner_lines.append(empty)

    subtitle = Text()
    subtitle.append("    ", style="")
    subtitle.append("║         ", style="bold bright_cyan")
    subtitle.append("🤖 AI-Powered Security Analysis & Triage", style="bold bright_yellow")
    subtitle.append(" 🛡️                ║", style="bold bright_cyan")
    banner_lines.append(subtitle)

    desc = Text()
    desc.append("    ", style="")
    desc.append("║              ", style="bold bright_cyan")
    desc.append("Intelligent False Positive Reduction", style="bold bright_cyan")
    desc.append("                    ║", style="bold bright_cyan")
    banner_lines.append(desc)

    bottom = Text()
    bottom.append("    ", style="")
    bottom.append("╚══════════════════════════════════════════════════════════╝", style="bold bright_cyan")
    banner_lines.append(bottom)

    # Print banner
    console.print()
    for line in banner_lines:
        console.print(line)
    console.print()


def print_config_panel(target: Path, args, config):
    """Print configuration panel showing all active settings."""
    # Build configuration table with better styling
    config_table = Table(show_header=False, box=None, padding=(0, 2))
    config_table.add_column("Setting", style="bold bright_cyan", width=22)
    config_table.add_column("Value", style="bright_white")

    # Target info
    target_display = str(target)
    if len(target_display) > 60:
        target_display = "..." + target_display[-57:]
    config_table.add_row("📁 Target", f"[bright_white]{target_display}[/]")

    # Semgrep config
    config_table.add_row("📋 Semgrep Config", f"[bright_yellow]{args.config}[/]")

    if hasattr(args, 'rules') and args.rules:
        config_table.add_row("📜 Custom Rules", f"[bright_magenta]{args.rules}[/]")

    # LLM Provider with better formatting
    provider_display = f"[bright_green]{config.provider.upper()}[/] [dim]→[/] [bright_blue]{config.model}[/]"
    config_table.add_row("🤖 LLM Provider", provider_display)

    # Limits and filters
    if hasattr(args, 'limit') and args.limit:
        config_table.add_row("🔢 Finding Limit", f"[bright_yellow]{args.limit}[/]")

    if hasattr(args, 'severity') and args.severity:
        severity_str = ", ".join(s.upper() for s in args.severity)
        config_table.add_row("⚡ Severity Filter", f"[bold bright_red]{severity_str}[/]")

    # Features
    enable_tools = not getattr(args, 'no_tools', False)
    enable_iterative = not getattr(args, 'no_iterative', False)
    max_iterations = getattr(args, 'max_context_iterations', 3)

    tools_status = "[bold bright_green]✓ Enabled[/]" if enable_tools else "[bold bright_red]✗ Disabled[/]"
    config_table.add_row("� Tool Calling", tools_status)

    if enable_iterative:
        iterative_status = f"[bold bright_green]✓ Enabled[/] [dim](max {max_iterations} iterations)[/]"
    else:
        iterative_status = "[bold bright_red]✗ Disabled[/]"
    config_table.add_row("🔄 Iterative Context", iterative_status)

    # Show output path (either custom or auto-generated)
    if args.output:
        config_table.add_row("💾 Output File", args.output)
    else:
        auto_path = generate_output_path(target)
        config_table.add_row("💾 Output File", f"{auto_path} [dim](auto-generated)[/]")

    if args.ui:
        config_table.add_row("🖥️  Interactive UI", "[green]Yes[/]")

    console.print(Panel(
        config_table,
        title="[bold white]⚙️  Configuration[/]",
        border_style="blue",
        box=ROUNDED,
    ))
    console.print()


def print_summary(result: PipelineResult):
    """Print a summary of the analysis results using Rich."""
    s = result.stats

    console.print()

    # Results summary table with enhanced styling
    summary_table = Table(show_header=False, box=None, padding=(0, 2))
    summary_table.add_column("Category", style="bold bright_white", width=20)
    summary_table.add_column("Count", justify="right", style="bold", width=8)
    summary_table.add_column("Visual", width=25)

    # Calculate bar widths for visualization
    total = max(s.total_findings, 1)
    bar_length = 20
    tp_width = int(bar_length * s.true_positives / total)
    fp_width = int(bar_length * s.false_positives / total)
    review_width = int(bar_length * s.needs_review / total)

    # True Positives - Vulnerabilities found
    summary_table.add_row(
        "[bold bright_red]🔴 Vulnerable[/]",
        f"[bold bright_red]{s.true_positives}[/]",
        f"[bright_red]{'█' * tp_width}[/][dim]{'░' * (bar_length - tp_width)}[/]"
    )

    # False Positives - Safe findings
    summary_table.add_row(
        "[bold bright_green]✅ Safe[/]",
        f"[bold bright_green]{s.false_positives}[/]",
        f"[bright_green]{'█' * fp_width}[/][dim]{'░' * (bar_length - fp_width)}[/]"
    )

    # Needs Review
    summary_table.add_row(
        "[bold bright_yellow]⚠️  Needs Review[/]",
        f"[bold bright_yellow]{s.needs_review}[/]",
        f"[bright_yellow]{'█' * review_width}[/][dim]{'░' * (bar_length - review_width)}[/]"
    )

    # Errors (if any)
    if s.analysis_errors > 0:
        summary_table.add_row(
            "[dim]❌ Errors[/]",
            f"[dim]{s.analysis_errors}[/]",
            ""
        )

    # Determine panel color based on results
    if s.true_positives > 0:
        panel_color = "bright_red"
        panel_title = f"[bold bright_white]🎯 Analysis Complete[/] [bright_red]● {s.true_positives} Vulnerable[/]"
    elif s.needs_review > 0:
        panel_color = "bright_yellow"
        panel_title = f"[bold bright_white]🎯 Analysis Complete[/] [bright_yellow]● {s.needs_review} To Review[/]"
    else:
        panel_color = "bright_green"
        panel_title = f"[bold bright_white]🎯 Analysis Complete[/] [bright_green]● All Safe[/]"

    console.print(Panel(
        summary_table,
        title=panel_title,
        subtitle=f"[dim]Total: {s.total_findings} findings analyzed[/]",
        border_style=panel_color,
        box=ROUNDED,
    ))

    # Enhanced metrics table
    metrics_table = Table(show_header=False, box=None, padding=(0, 2))
    metrics_table.add_column("Metric", style="bold bright_cyan", width=22)
    metrics_table.add_column("Value", justify="right", style="bold bright_white")

    # False Positive Reduction Rate with enhanced color coding
    reduction_style = "bold bright_green" if s.reduction_percentage >= 50 else "bold bright_yellow" if s.reduction_percentage >= 30 else "bold bright_red"
    reduction_icon = "🎯" if s.reduction_percentage >= 50 else "📊" if s.reduction_percentage >= 30 else "⚠️"
    metrics_table.add_row(
        f"{reduction_icon} FP Reduction Rate",
        f"[{reduction_style}]{s.reduction_percentage:.1f}%[/{reduction_style}]"
    )

    # Performance metrics with icons
    total_time = s.scan_time_seconds + s.analysis_time_seconds
    metrics_table.add_row("⚡ Total Time", f"[bright_blue]{total_time:.1f}s[/]")
    metrics_table.add_row("  ├─ Semgrep Scan", f"[dim]{s.scan_time_seconds:.1f}s[/]")
    metrics_table.add_row("  └─ AI Analysis", f"[dim]{s.analysis_time_seconds:.1f}s[/]")

    # Resource usage
    metrics_table.add_row("🎫 Tokens Used", f"[bright_magenta]{s.total_tokens_used:,}[/]")
    metrics_table.add_row("🔧 Tool Calls", f"[bright_blue]{s.total_tool_calls}[/]")

    # Context expansion stats (if applicable)
    if s.findings_with_context_expansion > 0:
        metrics_table.add_row("🔄 Context Expansions", f"[bright_yellow]{s.findings_with_context_expansion}[/]")
        metrics_table.add_row("  └─ Total Iterations", f"[dim]{s.total_context_iterations}[/]")

    console.print()
    console.print(Panel(
        metrics_table,
        title="[bold bright_white]� Performance Metrics[/]",
        border_style="bright_cyan",
        box=ROUNDED,
    ))


def print_finding_result(finding_num: int, total: int, rule_id: str, file_path: str,
                         line: int, verdict: str, confidence: float, tool_calls: int = 0):
    """Print a single finding analysis result with enhanced styling."""
    # Improved verdict styling with better colors
    verdict_styles = {
        "TRUE_POSITIVE": ("🔴", "bold bright_red", "VULNERABLE", "red"),
        "FALSE_POSITIVE": ("✅", "bold bright_green", "SAFE", "green"),
        "NEEDS_REVIEW": ("⚠️", "bold bright_yellow", "NEEDS REVIEW", "yellow"),
        "NEEDS_MORE_CONTEXT": ("�", "bold bright_magenta", "MORE CONTEXT", "magenta"),
        "INSUFFICIENT_CONTEXT": ("❓", "dim", "NO CONTEXT", "dim"),
        "ERROR": ("❌", "bold bright_red", "ERROR", "red"),
    }

    icon, style, label, box_color = verdict_styles.get(verdict, ("❓", "white", verdict, "white"))

    # Truncate file path if too long
    max_path_len = 50
    display_path = file_path
    if len(file_path) > max_path_len:
        display_path = "..." + file_path[-(max_path_len-3):]

    # Truncate rule_id if too long
    max_rule_len = 40
    display_rule = rule_id
    if len(rule_id) > max_rule_len:
        display_rule = rule_id[:max_rule_len-3] + "..."

    # Build enhanced output with better formatting
    progress_text = f"[bold bright_cyan]#{finding_num}[/][dim]/{total}[/]"
    verdict_text = f"{icon} [{style}]{label}[/{style}]"

    # Confidence bar visualization
    if confidence:
        conf_percent = int(confidence * 100)
        if conf_percent >= 80:
            conf_color = "bright_green"
        elif conf_percent >= 60:
            conf_color = "bright_yellow"
        else:
            conf_color = "bright_red"
        confidence_text = f"[{conf_color}]{conf_percent}%[/{conf_color}]"
    else:
        confidence_text = ""

    # Tool calls indicator
    if tool_calls > 0:
        tool_text = f"[bright_blue]🔧 {tool_calls} tools[/]"
    else:
        tool_text = ""

    # Create a mini panel for each finding
    finding_info = f"{progress_text}  {verdict_text}"
    if confidence_text:
        finding_info += f"  {confidence_text}"
    if tool_text:
        finding_info += f"  {tool_text}"

    console.print()
    console.print(Panel(
        f"{finding_info}\n[bright_cyan]📋 {display_rule}[/]\n[dim]📄 {display_path}:{line}[/]",
        border_style=box_color,
        padding=(0, 1),
        box=ROUNDED,
    ))



def cmd_scan(args):
    """Run Semgrep scan and analyze findings."""
    # Print banner
    print_banner()

    # Check if target is a Git URL or local path
    target_str = args.target
    git_handler = GitRepositoryHandler(Path.cwd())
    clone_result = None

    if git_handler.is_git_url(target_str):
        # Handle Git repository cloning
        try:
            clone_result = git_handler.clone_repository(
                url=target_str,
                branch=getattr(args, 'branch', None),
                commit=getattr(args, 'commit', None),
                tag=getattr(args, 'tag', None),
                depth=getattr(args, 'depth', 1),
            )
            target = clone_result.local_path
        except ValueError as e:
            console.print(f"[red]❌ {e}[/]")
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            console.print(f"[red]❌ Git clone failed: {e.stderr or e.stdout}[/]")
            sys.exit(1)
        except Exception as e:
            console.print(f"[red]❌ Failed to clone repository: {e}[/]")
            sys.exit(1)
    else:
        # Local path
        target = Path(target_str)
        if not target.exists():
            console.print(f"[red]❌ Error: Target path does not exist: {target}[/]")
            sys.exit(1)

    try:
        config = load_config()
    except ValueError as e:
        console.print(f"[red]❌ Configuration error: {e}[/]")
        # Cleanup clone if exists
        if clone_result:
            clone_result.cleanup()
        sys.exit(1)

    # Set log level - quiet mode for cleaner output unless verbose
    log_level = "DEBUG" if args.verbose else config.log_level
    setup_logging(log_level, config.log_file, quiet=not args.verbose)

    # Print configuration panel
    print_config_panel(target, args, config)

    # Wrap everything in try-finally to ensure cleanup
    try:
        # Get options
        max_findings = getattr(args, 'limit', None)
        enable_tools = not getattr(args, 'no_tools', False)
        enable_iterative = not getattr(args, 'no_iterative', False)
        max_iterations = getattr(args, 'max_context_iterations', 3)

        # Track analysis results for live display
        analysis_results_live = []

        def finding_callback(finding_num: int, total: int, finding: dict, result: dict):
            """Called after each finding is analyzed."""
            print_finding_result(
                finding_num=finding_num,
                total=total,
                rule_id=finding.get('rule_id', 'unknown'),
                file_path=finding.get('file', 'unknown'),
                line=finding.get('line', 0),
                verdict=result.get('verdict', 'UNKNOWN'),
                confidence=result.get('confidence', 0),
                tool_calls=result.get('tool_calls', 0),
            )

        # Stage 1: Semgrep Scan - Enhanced panel
        console.print()
        console.print(Panel(
            "[bold bright_white]Stage 1/3:[/] Running Semgrep static analysis\n[dim]Analyzing code patterns and security rules...[/]",
            title="[bold bright_cyan]🔍 Code Scanning[/]",
            border_style="bright_cyan",
            box=ROUNDED,
        ))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            scan_task = progress.add_task("[cyan]Scanning codebase...", total=None)

            # Create pipeline
            pipeline = Pipeline(
                config=config,
                progress_callback=None,  # We'll use Rich progress instead
                verbose=args.verbose,
                include_context=getattr(args, 'show_context', False),
                enable_tool_calling=enable_tools,
                enable_iterative_context=enable_iterative,
                max_context_iterations=max_iterations,
            )

            # Run semgrep scan only first
            from .semgrep.runner import SemgrepRunner
            scan_start = time.time()
            rules_path = Path(args.rules) if hasattr(args, 'rules') and args.rules else None
            scan_results = pipeline.semgrep_runner.scan(target, config=args.config, rules_path=rules_path)
            scan_time = time.time() - scan_start

            progress.update(scan_task, completed=100, total=100)

        # Filter findings by severity if specified
        severity_filter = getattr(args, 'severity', None)
        original_count = scan_results.finding_count
    
        if severity_filter:
            # Normalize severity levels - Semgrep uses ERROR, WARNING, INFO
            severity_map = {
                'critical': ['ERROR'],
                'high': ['ERROR'],
                'medium': ['WARNING'],
                'low': ['INFO'],
                'error': ['ERROR'],
                'warning': ['WARNING'],
                'info': ['INFO'],
            }
            allowed_severities = set()
            for level in severity_filter:
                allowed_severities.update(severity_map.get(level.lower(), [level.upper()]))
        
            # Filter findings
            filtered_findings = [
                f for f in scan_results.findings 
                if f.severity.upper() in allowed_severities
            ]
            scan_results.findings = filtered_findings
    
        # Show scan results with enhanced formatting
        findings_count = scan_results.finding_count
        console.print()
        if severity_filter and original_count != findings_count:
            console.print(f"  [bold bright_green]✓[/] Found [bold bright_yellow]{original_count}[/] findings → [bold bright_cyan]{findings_count}[/] match filter [dim]({scan_time:.1f}s)[/]")
        elif max_findings and max_findings < findings_count:
            console.print(f"  [bold bright_green]✓[/] Found [bold bright_cyan]{findings_count}[/] findings [dim](analyzing first {max_findings})[/]")
        else:
            console.print(f"  [bold bright_green]✓[/] Found [bold bright_cyan]{findings_count}[/] findings [dim]in {scan_time:.1f}s[/]")
        console.print()

        if findings_count == 0:
            console.print(Panel(
                "[bold bright_green]✨ No security findings detected!\n[/][dim]Your code passed all security checks.[/]",
                title="[bold bright_green]✅ Clean Scan[/]",
                border_style="bright_green",
                box=ROUNDED,
            ))
            console.print("\n[bright_yellow]ℹ️  No report generated[/] [dim]- Zero findings detected[/]")
            console.print("[dim]   Reports are only created when potential vulnerabilities are found[/]")
            return

        # Stage 2: Context Extraction & Analysis - Enhanced panel
        console.print()
        console.print(Panel(
            f"[bold bright_white]Stage 2/3:[/] AI-powered vulnerability analysis\n"
            f"[dim]• Extracting code context and data flows\n"
            f"• Analyzing with [bright_blue]{config.model}[/]\n"
            f"• Checking sanitization patterns[/]",
            title="[bold bright_magenta]🧠 AI Analysis[/]",
            border_style="bright_magenta",
            box=ROUNDED,
        ))
        console.print()

        # Run full pipeline
        analysis_start = time.time()
        rules_path = Path(args.rules) if hasattr(args, 'rules') and args.rules else None
        result = pipeline.run(target, semgrep_config=args.config, semgrep_rules_path=rules_path, max_findings=max_findings)
        analysis_time = time.time() - analysis_start

        # Update stats with timing
        result.stats.analysis_time_seconds = analysis_time
        result.stats.scan_time_seconds = scan_time

        # Stage 3: Results
        console.print()
        console.print(Panel(
            "[bold]Stage 3/3:[/] Aggregating results...",
            title="[bold cyan]📊 Results[/]",
            border_style="cyan",
            box=ROUNDED,
        ))
        console.print()

        # Print findings details
        console.print("[bold]Findings Analysis:[/]")
        console.print()
        for i, ar in enumerate(result.analysis_results, 1):
            print_finding_result(
                finding_num=i,
                total=len(result.analysis_results),
                rule_id=ar.finding.rule_id,
                file_path=ar.finding.file_path,
                line=ar.finding.start_line,
                verdict=ar.verdict.name if hasattr(ar.verdict, 'name') else str(ar.verdict),
                confidence=ar.confidence,
                tool_calls=ar.tool_calls_made,
            )

        # Print summary
        print_summary(result)

        # Save results - always save with automatic path generation
        # If user specified output path, use that; otherwise generate automatic path
        if args.output:
            output_path = Path(args.output)
        else:
            # Generate automatic output path in results folder
            output_path = generate_output_path(target)

        include_context = getattr(args, 'show_context', False)

        # Ensure parent directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Save main results file
        with open(output_path, "w") as f:
            json.dump(result.to_dict(include_context=include_context), f, indent=2)
        console.print(f"[green]✅ Results saved to:[/] {output_path}")
        if include_context:
            console.print(f"   [dim](includes full context extraction details)[/]")

        # Save detailed per-finding results (VulnHalla-style)
        if getattr(args, 'detailed_output', False):
            detailed_dir = output_path.parent / f"{output_path.stem}_detailed"
            result.save_detailed_results(detailed_dir)
            console.print(f"   [dim](detailed per-finding results in {detailed_dir})[/]")

        # Launch UI if requested
        if args.ui:
            console.print(f"\n[cyan]🖥️  Launching interactive UI...[/]")
            from .ui.app import run_ui
            run_ui(result)

            # Final status
            console.print()
            actionable = len(result.get_actionable_findings())

            if actionable > 0:
                console.print(Panel(
                    f"[bold red]{actionable}[/] findings require attention",
                    title="[bold red]⚠️  Action Required[/]",
                    border_style="red",
                ))
                exit_code = 1
            else:
                console.print(Panel(
                    "[bold green]All findings analyzed - no critical vulnerabilities confirmed[/]",
                    title="[bold green]✅ Complete[/]",
                    border_style="green",
                ))
                exit_code = 0

    finally:
        # Cleanup cloned repository if it exists
        if clone_result:
            console.print("\n🧹 [dim]Cleaning up temporary files...[/]")
            try:
                clone_result.cleanup()
                console.print("   [green]✅ Temporary directory deleted[/]")
            except Exception as e:
                console.print(f"   [yellow]⚠️  Warning: Failed to cleanup temp directory: {e}[/]")

    # Exit with appropriate code
    sys.exit(exit_code)


def cmd_view(args):
    """View results from a previous scan."""
    print_banner()

    results_file = Path(args.results_file)
    if not results_file.exists():
        console.print(f"[red]❌ Error: Results file not found: {results_file}[/]")
        sys.exit(1)

    with open(results_file) as f:
        data = json.load(f)

    # Display results summary
    if 'stats' in data:
        stats = data['stats']

        summary_table = Table(title="📊 Results Summary", box=ROUNDED)
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", justify="right", style="bold")

        summary_table.add_row("Total Findings", str(stats.get('total_findings', 0)))
        summary_table.add_row("True Positives", f"[red]{stats.get('true_positives', 0)}[/]")
        summary_table.add_row("False Positives", f"[green]{stats.get('false_positives', 0)}[/]")
        summary_table.add_row("Needs Review", f"[yellow]{stats.get('needs_review', 0)}[/]")
        summary_table.add_row("FP Reduction", f"{stats.get('reduction_percentage', 0):.1f}%")

        console.print(summary_table)
        console.print()

    # Display findings
    if 'analysis_results' in data:
        findings_table = Table(title="🔍 Findings", box=ROUNDED)
        findings_table.add_column("#", style="dim", width=4)
        findings_table.add_column("Verdict", width=12)
        findings_table.add_column("Rule", style="cyan", max_width=35)
        findings_table.add_column("Location", max_width=40)
        findings_table.add_column("Conf.", justify="right", width=6)

        for i, result in enumerate(data['analysis_results'], 1):
            verdict = result.get('verdict', 'UNKNOWN')
            verdict_style = {
                'TRUE_POSITIVE': '[red]🔴 TP[/]',
                'FALSE_POSITIVE': '[green]🟢 FP[/]',
                'NEEDS_REVIEW': '[yellow]🟡 Review[/]',
            }.get(verdict, f'[dim]{verdict}[/]')

            location = f"{result.get('file_path', '?')}:{result.get('line_number', '?')}"
            if len(location) > 40:
                location = "..." + location[-37:]

            confidence = result.get('confidence', 0)
            conf_str = f"{confidence:.0%}" if confidence else "-"

            findings_table.add_row(
                str(i),
                verdict_style,
                result.get('rule_id', 'unknown')[:35],
                location,
                conf_str,
            )

        console.print(findings_table)


def cmd_context(args):
    """Show context extraction for a specific file and line."""
    from .context.extractor import get_extractor_for_file
    from .questions.templates import get_questions_for_rule
    from rich.syntax import Syntax

    print_banner()

    file_path = Path(args.file)
    if not file_path.exists():
        console.print(f"[red]❌ Error: File not found: {file_path}[/]")
        sys.exit(1)

    line = args.line
    rule_id = args.rule or "generic"

    # Get the appropriate extractor
    extractor = get_extractor_for_file(file_path)

    # Extract context
    context = extractor.extract_context(file_path, line)

    # Get guided questions
    questions = get_questions_for_rule(rule_id, str(file_path))

    # Header
    console.print(Panel(
        f"[bold]File:[/] {file_path}\n[bold]Line:[/] {line}\n[bold]Extractor:[/] {extractor.__class__.__name__}",
        title="[bold cyan]📋 Context Extraction[/]",
        border_style="cyan",
    ))
    console.print()

    # Function context
    if context.function_context:
        fc = context.function_context

        info_table = Table(show_header=False, box=None, padding=(0, 2))
        info_table.add_column("Key", style="cyan")
        info_table.add_column("Value")
        info_table.add_row("Function", f"[bold]{fc.name}[/]")
        info_table.add_row("Lines", f"{fc.start_line}-{fc.end_line} ({fc.end_line - fc.start_line + 1} lines)")
        info_table.add_row("Language", fc.language)

        console.print(Panel(info_table, title="[green]✅ Function Found[/]", border_style="green"))

        # Show code with syntax highlighting
        lang_map = {'java': 'java', 'python': 'python', 'javascript': 'javascript', 'typescript': 'typescript'}
        syntax_lang = lang_map.get(fc.language, 'text')
        syntax = Syntax(fc.full_code, syntax_lang, line_numbers=True, start_line=fc.start_line, theme="monokai")
        console.print(Panel(syntax, title="[bold]📝 Code[/]", border_style="blue"))
    else:
        console.print(Panel(
            f"[yellow]Could not extract function context for line {line}[/]",
            title="[yellow]⚠️ Limited Context[/]",
            border_style="yellow",
        ))
    console.print()

    # Additional context
    add_ctx = context.additional_context or {}
    if add_ctx:
        ctx_table = Table(show_header=False, box=None, padding=(0, 2))
        ctx_table.add_column("Key", style="cyan")
        ctx_table.add_column("Value")

        if add_ctx.get("package"):
            ctx_table.add_row("Package", add_ctx['package'])
        if add_ctx.get("class_name"):
            ctx_table.add_row("Class", add_ctx['class_name'])

        imports = add_ctx.get("imports", [])
        if imports:
            imports_str = ", ".join(imports[:5])
            if len(imports) > 5:
                imports_str += f" (+{len(imports) - 5} more)"
            ctx_table.add_row("Imports", imports_str)

        console.print(Panel(ctx_table, title="[bold]📦 Additional Context[/]", border_style="blue"))
        console.print()

    # Guided questions
    if questions:
        questions_text = "\n".join(f"  {i}. {q}" for i, q in enumerate(questions, 1))
        console.print(Panel(
            questions_text,
            title=f"[bold]❓ Guided Questions ({len(questions)})[/]",
            border_style="magenta",
        ))
    console.print()

    # Context gap analysis
    gaps = _analyze_context_gaps(context, str(file_path))
    if gaps:
        gaps_text = "\n".join(f"  ⚠️  {gap}" for gap in gaps)
        console.print(Panel(gaps_text, title="[yellow]🔍 Context Gaps[/]", border_style="yellow"))
    else:
        console.print(Panel(
            "[green]No significant context gaps detected[/]",
            title="[green]✅ Context Complete[/]",
            border_style="green",
        ))


def _analyze_context_gaps(context, file_path: str) -> list[str]:
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
    if file_path.endswith('.java'):
        if '@Valid' not in code and '@Validated' not in code:
            gaps.append("No Bean Validation annotations visible - may exist at class or parameter level")

    # Check for framework-specific security
    if 'spring' in str(context.additional_context.get('imports', [])).lower():
        gaps.append("Spring framework detected - security configurations (WebSecurityConfig, filters) not visible")

    return gaps


def print_help_banner():
    """Print a styled help banner."""
    console.print()
    console.print(Panel(
        Text.from_markup(
            "[bold cyan]🛡️  AutoSAST[/] - LLM-Powered False Positive Reduction\n\n"
            "[dim]Automatically triage Semgrep findings using contextual AI analysis[/]"
        ),
        border_style="cyan",
        box=DOUBLE,
    ))
    console.print()


def main():
    """Main CLI entry point."""
    # Custom help formatter for better display
    class RichHelpFormatter(argparse.HelpFormatter):
        def __init__(self, prog):
            super().__init__(prog, max_help_position=40, width=100)

    parser = argparse.ArgumentParser(
        prog="autosast",
        description="AutoSAST - LLM-Powered False Positive Reduction for Static Analysis",
        formatter_class=RichHelpFormatter,
        epilog="""
Examples:
  # Scan local directory
  python -m src.cli scan ./src --config auto --limit 10
  python -m src.cli scan ./project -o results.json --ui

  # Scan GitHub repository
  python -m src.cli scan https://github.com/user/repo
  python -m src.cli scan https://github.com/user/repo --branch develop

  # Other commands
  python -m src.cli context ./src/UserDAO.java 45 --rule sql-injection
  python -m src.cli view results.json
        """,
    )
    subparsers = parser.add_subparsers(dest="command", title="Commands", metavar="")

    # ============ SCAN COMMAND ============
    scan_parser = subparsers.add_parser(
        "scan",
        help="🔍 Scan codebase and analyze findings",
        formatter_class=RichHelpFormatter,
        description="Run Semgrep scan and analyze findings with LLM-powered triage.",
    )

    # Required arguments
    scan_parser.add_argument(
        "target",
        help="Path to directory/file to scan OR Git repository URL (GitHub, GitLab, Bitbucket, etc.)",
        metavar="TARGET",
    )

    # Git repository options
    git_group = scan_parser.add_argument_group("Git Repository Options")
    git_group.add_argument(
        "--branch",
        help="Git branch to clone (default: repository's default branch)",
        metavar="BRANCH",
    )
    git_group.add_argument(
        "--tag",
        help="Git tag to clone",
        metavar="TAG",
    )
    git_group.add_argument(
        "--commit",
        help="Git commit hash to checkout",
        metavar="COMMIT",
    )
    git_group.add_argument(
        "--depth",
        type=int,
        default=1,
        help="Clone depth for shallow clone (default: 1, use 0 for full history)",
        metavar="N",
    )

    # Semgrep options
    semgrep_group = scan_parser.add_argument_group("Semgrep Options")
    semgrep_group.add_argument(
        "--config", "-c",
        help="Semgrep config: 'auto', 'p/java', 'p/security-audit', or path to rules",
        default="p/security-audit",
        metavar="CONFIG",
    )
    semgrep_group.add_argument(
        "--rules", "-r",
        help="Path to custom Semgrep rules file/directory or URL (can be combined with --config)",
        metavar="RULES_PATH",
    )
    semgrep_group.add_argument(
        "--limit", "-l",
        type=int,
        help="Limit number of findings to analyze (useful for testing)",
        metavar="N",
    )
    semgrep_group.add_argument(
        "--severity", "-s",
        nargs="+",
        choices=["critical", "high", "medium", "low", "error", "warning", "info"],
        help="Filter findings by severity level(s). Semgrep uses: error (high/critical), warning (medium), info (low). Example: --severity high medium",
        metavar="LEVEL",
    )

    # Analysis options
    analysis_group = scan_parser.add_argument_group("Analysis Options")
    analysis_group.add_argument(
        "--no-tools",
        action="store_true",
        help="Disable LLM tool calling (dynamic context retrieval)",
    )
    analysis_group.add_argument(
        "--no-iterative",
        action="store_true",
        help="Disable iterative context expansion",
    )
    analysis_group.add_argument(
        "--max-context-iterations",
        type=int,
        default=3,
        help="Max iterations for context expansion (default: 3)",
        metavar="N",
    )

    # Output options
    output_group = scan_parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--output", "-o",
        help="Custom output path for results JSON file (default: auto-generated in results/ folder)",
        metavar="FILE",
    )
    output_group.add_argument(
        "--detailed-output",
        action="store_true",
        help="Save detailed per-finding analysis (LLM conversation logs)",
    )
    output_group.add_argument(
        "--show-context",
        action="store_true",
        help="Include full code context in JSON output",
    )
    output_group.add_argument(
        "--ui",
        action="store_true",
        help="Launch interactive terminal UI after analysis",
    )
    output_group.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed logging and debug information",
    )

    scan_parser.set_defaults(func=cmd_scan)

    # ============ VIEW COMMAND ============
    view_parser = subparsers.add_parser(
        "view",
        help="📊 View results from a previous scan",
        formatter_class=RichHelpFormatter,
        description="Display analysis results from a saved JSON file.",
    )
    view_parser.add_argument(
        "results_file",
        help="Path to results JSON file",
        metavar="FILE",
    )
    view_parser.set_defaults(func=cmd_view)

    # ============ CONTEXT COMMAND ============
    context_parser = subparsers.add_parser(
        "context",
        help="🔬 Debug context extraction for a specific location",
        formatter_class=RichHelpFormatter,
        description="Show what context AutoSAST extracts for a specific file and line.",
    )
    context_parser.add_argument(
        "file",
        help="Path to the source file",
        metavar="FILE",
    )
    context_parser.add_argument(
        "line",
        type=int,
        help="Line number to extract context for",
        metavar="LINE",
    )
    context_parser.add_argument(
        "--rule", "-r",
        help="Rule ID to show specific guided questions (e.g., 'java.lang.security.audit.sqli')",
        metavar="RULE_ID",
    )
    context_parser.set_defaults(func=cmd_context)

    # Parse arguments
    args = parser.parse_args()

    if args.command is None:
        print_help_banner()

        # Print commands table
        commands_table = Table(title="Available Commands", box=ROUNDED, border_style="cyan")
        commands_table.add_column("Command", style="bold cyan")
        commands_table.add_column("Description")
        commands_table.add_column("Example", style="dim")

        commands_table.add_row(
            "scan",
            "Scan codebase and analyze findings",
            "scan ./src --config auto -l 10"
        )
        commands_table.add_row(
            "view",
            "View results from a previous scan",
            "view results.json"
        )
        commands_table.add_row(
            "context",
            "Debug context extraction for a location",
            "context ./src/UserDAO.java 45"
        )

        console.print(commands_table)
        console.print()
        console.print("[dim]Use 'python -m src.cli <command> --help' for more information on a command.[/]")
        console.print()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()

