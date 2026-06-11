"""
Semgrep Runner - Executes Semgrep scans and parses results.

This module handles:
- Running Semgrep CLI with various configurations
- Parsing SARIF/JSON output
- Extracting findings with location information
"""

import json
import os
import subprocess
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class SemgrepFinding:
    """Represents a single Semgrep finding."""
    rule_id: str
    message: str
    severity: str
    file_path: str
    start_line: int
    end_line: int
    start_col: int
    end_col: int
    code_snippet: str
    metadata: dict = field(default_factory=dict)
    
    @property
    def location_str(self) -> str:
        return f"{self.file_path}:{self.start_line}-{self.end_line}"


@dataclass 
class SemgrepResults:
    """Container for Semgrep scan results."""
    findings: list[SemgrepFinding]
    errors: list[str]
    scan_time_seconds: float
    
    @property
    def finding_count(self) -> int:
        return len(self.findings)
    
    def findings_by_rule(self) -> dict[str, list[SemgrepFinding]]:
        """Group findings by rule ID."""
        by_rule: dict[str, list[SemgrepFinding]] = {}
        for finding in self.findings:
            if finding.rule_id not in by_rule:
                by_rule[finding.rule_id] = []
            by_rule[finding.rule_id].append(finding)
        return by_rule


class SemgrepRunner:
    """Runs Semgrep scans and parses results."""
    
    def __init__(self, semgrep_path: str = "semgrep"):
        self.semgrep_path = semgrep_path
    
    def scan(
        self,
        target_path: Path,
        config: Optional[str] = None,
        rules_path: Optional[Path] = None,
        exclude: Optional[list[str]] = None,
        include: Optional[list[str]] = None,
        timeout: int = 300,
    ) -> SemgrepResults:
        """
        Run Semgrep scan on target path.
        
        Args:
            target_path: Directory or file to scan
            config: Semgrep config string (e.g., "p/security-audit", "auto")
            rules_path: Path to custom rules file/directory
            exclude: Patterns to exclude
            include: Patterns to include
            timeout: Timeout in seconds
            
        Returns:
            SemgrepResults with all findings
        """
        cmd = [self.semgrep_path, "--json", "--quiet"]
        
        if config:
            cmd.extend(["--config", config])
        elif rules_path:
            cmd.extend(["--config", str(rules_path)])
        else:
            # Default to security audit rules
            cmd.extend(["--config", "p/security-audit"])
        
        if exclude:
            for pattern in exclude:
                cmd.extend(["--exclude", pattern])
        
        if include:
            for pattern in include:
                cmd.extend(["--include", pattern])
        
        cmd.append(str(target_path))
        
        logger.info(f"Running Semgrep: {' '.join(cmd)}")

        try:
            # Ensure pysemgrep is in PATH (required by semgrep binary)
            env = os.environ.copy()
            semgrep_bin_dir = os.path.dirname(self.semgrep_path)
            if semgrep_bin_dir:
                env["PATH"] = semgrep_bin_dir + os.pathsep + env.get("PATH", "")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
            )
            return self._parse_json_output(result.stdout, result.stderr)
        except subprocess.TimeoutExpired:
            logger.error(f"Semgrep scan timed out after {timeout}s")
            return SemgrepResults(findings=[], errors=[f"Scan timed out after {timeout}s"], scan_time_seconds=timeout)
        except Exception as e:
            logger.error(f"Semgrep scan failed: {e}")
            return SemgrepResults(findings=[], errors=[str(e)], scan_time_seconds=0)
    
    def _parse_json_output(self, stdout: str, stderr: str) -> SemgrepResults:
        """Parse Semgrep JSON output into structured results."""
        findings = []
        errors = []
        scan_time = 0.0
        
        if stderr:
            errors.extend(stderr.strip().split("\n"))
        
        if not stdout.strip():
            return SemgrepResults(findings=findings, errors=errors, scan_time_seconds=scan_time)
        
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            errors.append(f"Failed to parse Semgrep output: {e}")
            return SemgrepResults(findings=findings, errors=errors, scan_time_seconds=scan_time)
        
        # Parse timing info if available
        if "time" in data:
            scan_time = data["time"].get("total_time", 0)
        
        # Parse findings
        for result in data.get("results", []):
            finding = SemgrepFinding(
                rule_id=result.get("check_id", "unknown"),
                message=result.get("extra", {}).get("message", ""),
                severity=result.get("extra", {}).get("severity", "WARNING"),
                file_path=result.get("path", ""),
                start_line=result.get("start", {}).get("line", 0),
                end_line=result.get("end", {}).get("line", 0),
                start_col=result.get("start", {}).get("col", 0),
                end_col=result.get("end", {}).get("col", 0),
                code_snippet=result.get("extra", {}).get("lines", ""),
                metadata=result.get("extra", {}).get("metadata", {}),
            )
            findings.append(finding)
        
        # Parse errors from output
        for error in data.get("errors", []):
            errors.append(error.get("message", str(error)))
        
        logger.info(f"Parsed {len(findings)} findings from Semgrep output")
        return SemgrepResults(findings=findings, errors=errors, scan_time_seconds=scan_time)

