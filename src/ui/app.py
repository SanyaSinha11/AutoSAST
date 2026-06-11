"""
Terminal UI for AutoSAST using Textual.

Provides an interactive interface for:
- Viewing scan results
- Browsing findings by verdict
- Examining LLM reasoning
- Exporting filtered results
"""

from typing import Optional
from datetime import datetime

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import Header, Footer, Static, DataTable, Button, Label, RichLog
from textual.binding import Binding
from textual.screen import Screen
from rich.text import Text
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.console import Console

from ..pipeline.orchestrator import PipelineResult
from ..llm.analyzer import AnalysisResult, Verdict


class FindingDetailScreen(Screen):
    """Screen showing detailed analysis of a single finding."""
    
    BINDINGS = [
        Binding("escape", "pop_screen", "Back"),
        Binding("q", "pop_screen", "Back"),
    ]
    
    def __init__(self, result: AnalysisResult):
        super().__init__()
        self.result = result
    
    def compose(self) -> ComposeResult:
        yield Header()
        yield ScrollableContainer(
            Static(self._build_content(), id="detail-content"),
        )
        yield Footer()
    
    def _build_content(self) -> str:
        r = self.result
        f = r.finding
        
        verdict_colors = {
            Verdict.TRUE_POSITIVE: "red",
            Verdict.FALSE_POSITIVE: "green",
            Verdict.NEEDS_REVIEW: "yellow",
            Verdict.INSUFFICIENT_CONTEXT: "blue",
        }
        color = verdict_colors.get(r.verdict, "white")
        
        content = f"""[bold]Finding Details[/bold]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[bold]Rule:[/bold] {f.rule_id}
[bold]Severity:[/bold] {f.severity}
[bold]Location:[/bold] {f.location_str}
[bold]Verdict:[/bold] [{color}]{r.verdict.value.upper()}[/{color}]
[bold]Confidence:[/bold] {r.confidence:.0%}

[bold]Message:[/bold]
{f.message}

[bold]Flagged Code:[/bold]
```
{f.code_snippet}
```

[bold]LLM Reasoning:[/bold]
{r.reasoning}

[bold]Guided Question Answers:[/bold]
"""
        for q, a in r.guided_answers.items():
            content += f"\n[bold]Q:[/bold] {q}\n[bold]A:[/bold] {a}\n"
        
        return content


class AutoSASTApp(App):
    """Main Textual application for AutoSAST."""

    TITLE = "🛡️ AutoSAST - Security Analysis Results"
    SUB_TITLE = "LLM-Powered False Positive Reduction"

    CSS = """
    Screen {
        background: $surface;
    }

    #stats-panel {
        height: 7;
        border: round #00aa00;
        padding: 1 2;
        background: $panel;
        margin-bottom: 1;
    }

    #findings-table {
        height: 1fr;
        border: round $primary;
    }

    .verdict-true-positive {
        color: #ff5555;
        text-style: bold;
    }

    .verdict-false-positive {
        color: #50fa7b;
    }

    .verdict-needs-review {
        color: #f1fa8c;
    }

    #filter-buttons {
        height: 3;
        padding: 0 1;
        margin-bottom: 1;
    }

    Button {
        margin-right: 1;
    }

    #btn-all {
        background: $primary;
    }

    #btn-true {
        background: #ff5555;
    }

    #btn-false {
        background: #50fa7b;
        color: #000;
    }

    #btn-review {
        background: #f1fa8c;
        color: #000;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("escape", "quit", "Quit"),
        Binding("enter", "view_detail", "View Details"),
        Binding("a", "filter_all", "All"),
        Binding("t", "filter_true", "True Positives"),
        Binding("f", "filter_false", "False Positives"),
        Binding("r", "filter_review", "Needs Review"),
        Binding("e", "export", "Export"),
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
    ]

    def __init__(self, result: PipelineResult):
        super().__init__()
        self.result = result
        self.current_filter = "all"
        self.filtered_results = result.analysis_results

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Static(self._build_stats(), id="stats-panel"),
            Horizontal(
                Button("📋 All (A)", id="btn-all", variant="primary"),
                Button("🔴 True Positives (T)", id="btn-true", variant="error"),
                Button("🟢 False Positives (F)", id="btn-false", variant="success"),
                Button("🟡 Needs Review (R)", id="btn-review", variant="warning"),
                Button("💾 Export (E)", id="btn-export"),
                id="filter-buttons",
            ),
            DataTable(id="findings-table"),
        )
        yield Footer()

    def on_mount(self) -> None:
        self._setup_table()
        self._populate_table()

    def _build_stats(self) -> str:
        s = self.result.stats
        return (
            f"[bold cyan]🛡️ AutoSAST Analysis Results[/bold cyan]\n\n"
            f"📊 Total: [bold]{s.total_findings}[/bold]  │  "
            f"[red]● True Positives: {s.true_positives}[/red]  │  "
            f"[green]● False Positives: {s.false_positives}[/green]  │  "
            f"[yellow]● Needs Review: {s.needs_review}[/yellow]  │  "
            f"[bold green]📉 Reduction: {s.reduction_percentage:.1f}%[/bold green]"
        )

    def _setup_table(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.add_columns("", "Verdict", "Confidence", "Rule", "Location", "Severity")
        table.cursor_type = "row"
        table.zebra_stripes = True
    
    def _populate_table(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.clear()

        for result in self.filtered_results:
            # Icon based on verdict
            if result.verdict == Verdict.TRUE_POSITIVE:
                icon = "🔴"
                verdict_text = Text("TRUE POSITIVE")
                verdict_text.stylize("red bold")
            elif result.verdict == Verdict.FALSE_POSITIVE:
                icon = "🟢"
                verdict_text = Text("FALSE POSITIVE")
                verdict_text.stylize("green")
            elif result.verdict == Verdict.NEEDS_REVIEW:
                icon = "🟡"
                verdict_text = Text("NEEDS REVIEW")
                verdict_text.stylize("yellow")
            else:
                icon = "⚪"
                verdict_text = Text("UNKNOWN")

            # Confidence with color
            confidence = result.confidence
            if confidence >= 0.9:
                conf_text = Text(f"{confidence:.0%}")
                conf_text.stylize("green bold")
            elif confidence >= 0.7:
                conf_text = Text(f"{confidence:.0%}")
                conf_text.stylize("yellow")
            else:
                conf_text = Text(f"{confidence:.0%}")
                conf_text.stylize("red")

            # Shorten rule ID for display
            rule_id = result.finding.rule_id.split('.')[-1] if '.' in result.finding.rule_id else result.finding.rule_id

            # Severity with icon
            severity = result.finding.severity.upper()
            if severity == "ERROR" or severity == "HIGH":
                severity_icon = "🔥"
            elif severity == "WARNING" or severity == "MEDIUM":
                severity_icon = "⚠️"
            else:
                severity_icon = "ℹ️"

            table.add_row(
                icon,
                verdict_text,
                conf_text,
                rule_id,
                result.finding.location_str,
                f"{severity_icon} {severity}",
            )
    
    def action_view_detail(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        if table.cursor_row is not None and table.cursor_row < len(self.filtered_results):
            result = self.filtered_results[table.cursor_row]
            self.push_screen(FindingDetailScreen(result))
    
    def _apply_filter(self, verdict: Optional[Verdict]) -> None:
        if verdict is None:
            self.filtered_results = self.result.analysis_results
        else:
            self.filtered_results = [r for r in self.result.analysis_results if r.verdict == verdict]
        self._populate_table()
    
    def action_filter_all(self) -> None:
        self._apply_filter(None)
    
    def action_filter_true(self) -> None:
        self._apply_filter(Verdict.TRUE_POSITIVE)
    
    def action_filter_false(self) -> None:
        self._apply_filter(Verdict.FALSE_POSITIVE)
    
    def action_filter_review(self) -> None:
        self._apply_filter(Verdict.NEEDS_REVIEW)
    
    def action_export(self) -> None:
        import json
        from pathlib import Path
        
        output_path = Path("autosast_results.json")
        with open(output_path, "w") as f:
            json.dump(self.result.to_dict(), f, indent=2)
        self.notify(f"Results exported to {output_path}")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "btn-all":
            self.action_filter_all()
        elif button_id == "btn-true":
            self.action_filter_true()
        elif button_id == "btn-false":
            self.action_filter_false()
        elif button_id == "btn-review":
            self.action_filter_review()
        elif button_id == "btn-export":
            self.action_export()


def run_ui(result: PipelineResult) -> None:
    """Run the terminal UI with the given results."""
    app = AutoSASTApp(result)
    app.run()

