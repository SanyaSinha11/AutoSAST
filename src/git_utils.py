"""
Git repository cloning utilities for AutoSAST.

Handles cloning of remote Git repositories (GitHub, GitLab, Bitbucket, etc.)
with automatic cleanup after scanning.
"""

import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Tuple
from dataclasses import dataclass

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()


@dataclass
class GitCloneResult:
    """Result of a git clone operation."""
    local_path: Path
    url: str
    branch: Optional[str]
    commit: Optional[str]
    is_temp: bool
    
    def cleanup(self):
        """Remove the cloned directory."""
        if self.is_temp and self.local_path.exists():
            shutil.rmtree(self.local_path)


class GitRepositoryHandler:
    """Handles Git repository operations for AutoSAST."""
    
    # Git URL patterns
    GIT_URL_PATTERNS = [
        r'^https?://github\.com/[\w\-]+/[\w\-\.]+',
        r'^https?://gitlab\.com/[\w\-]+/[\w\-\.]+',
        r'^https?://bitbucket\.org/[\w\-]+/[\w\-\.]+',
        r'^git@github\.com:[\w\-]+/[\w\-\.]+\.git',
        r'^git@gitlab\.com:[\w\-]+/[\w\-\.]+\.git',
        r'^https?://[\w\.\-]+/[\w\-/]+\.git',  # Generic Git URL
    ]
    
    def __init__(self, project_root: Path):
        """
        Initialize Git handler.
        
        Args:
            project_root: Root directory of AutoSAST project (for tmp/ folder)
        """
        self.project_root = project_root
        self.tmp_dir = project_root / "tmp"
    
    def is_git_url(self, target: str) -> bool:
        """
        Check if target is a Git repository URL.
        
        Args:
            target: Target string (path or URL)
            
        Returns:
            True if target is a Git URL
        """
        return any(re.match(pattern, target) for pattern in self.GIT_URL_PATTERNS)
    
    def validate_git_available(self) -> Tuple[bool, str]:
        """
        Check if git command is available.
        
        Returns:
            Tuple of (is_available, version_or_error)
        """
        try:
            result = subprocess.run(
                ["git", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return True, result.stdout.strip()
            return False, "Git command failed"
        except FileNotFoundError:
            return False, "Git is not installed"
        except Exception as e:
            return False, str(e)
    
    def is_private_repository(self, url: str) -> bool:
        """
        Check if repository is private by attempting a shallow clone.
        
        Args:
            url: Git repository URL
            
        Returns:
            True if repository appears to be private
        """
        # Try to fetch repository info without authentication
        try:
            result = subprocess.run(
                ["git", "ls-remote", "--heads", url],
                capture_output=True,
                text=True,
                timeout=10
            )
            # If we get authentication errors, it's private
            if result.returncode != 0:
                stderr = result.stderr.lower()
                if any(keyword in stderr for keyword in ['authentication', 'permission', 'denied', '403', '404']):
                    return True
            return False
        except:
            # If we can't determine, assume it might be private
            return True
    
    def get_repository_size_estimate(self, url: str) -> Optional[int]:
        """
        Estimate repository size in MB (if possible from GitHub API).
        
        Args:
            url: Git repository URL
            
        Returns:
            Size in MB or None if unable to determine
        """
        # For GitHub repos, try to use API
        github_match = re.match(r'https?://github\.com/([\w\-]+)/([\w\-\.]+)', url)
        if github_match:
            owner, repo = github_match.groups()
            repo = repo.replace('.git', '')
            try:
                import json
                import urllib.request
                api_url = f"https://api.github.com/repos/{owner}/{repo}"
                with urllib.request.urlopen(api_url, timeout=5) as response:
                    data = json.loads(response.read())
                    size_kb = data.get('size', 0)
                    return size_kb // 1024  # Convert to MB
            except:
                pass
        return None

    def clone_repository(
        self,
        url: str,
        branch: Optional[str] = None,
        commit: Optional[str] = None,
        tag: Optional[str] = None,
        depth: int = 1,
        timeout: int = 300,
    ) -> GitCloneResult:
        """
        Clone a Git repository to temporary directory.

        Args:
            url: Git repository URL
            branch: Specific branch to clone (default: repo's default branch)
            commit: Specific commit to checkout
            tag: Specific tag to checkout
            depth: Clone depth (1 for shallow clone)
            timeout: Clone timeout in seconds

        Returns:
            GitCloneResult with local path

        Raises:
            ValueError: If git is not available or repository is private
            subprocess.CalledProcessError: If clone fails
        """
        # Validate git is available
        git_available, git_info = self.validate_git_available()
        if not git_available:
            raise ValueError(
                f"Git is not installed or not in PATH.\n"
                f"Error: {git_info}\n\n"
                f"Please install Git:\n"
                f"  - macOS: brew install git\n"
                f"  - Ubuntu/Debian: sudo apt install git\n"
                f"  - Windows: https://git-scm.com/download/win"
            )

        console.print(f"[dim]Using {git_info}[/]")

        # Check if repository is private
        console.print("🔍 Checking repository accessibility...")
        if self.is_private_repository(url):
            raise ValueError(
                f"❌ Private repository detected: {url}\n\n"
                f"AutoSAST currently supports public repositories only.\n"
                f"For private repositories, please clone manually:\n\n"
                f"  git clone {url} /path/to/local/copy\n"
                f"  python -m src.cli scan /path/to/local/copy\n\n"
                f"Note: This requires manual intervention and appropriate access credentials."
            )

        # Check repository size
        size_mb = self.get_repository_size_estimate(url)
        if size_mb and size_mb > 500:  # Warn for repos > 500MB
            console.print(f"[yellow]⚠️  Warning: Repository is approximately {size_mb} MB[/]")
            console.print(f"[yellow]   Cloning may take several minutes.[/]")

            # Ask for user confirmation
            from rich.prompt import Confirm
            if not Confirm.ask("Do you want to continue?", default=True):
                raise ValueError("Scan cancelled by user")

        # Create tmp directory in project root
        self.tmp_dir.mkdir(exist_ok=True)

        # Create unique temporary directory
        import time
        timestamp = int(time.time())
        import random
        rand_suffix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=6))
        clone_dir = self.tmp_dir / f"clone_{timestamp}_{rand_suffix}"

        try:
            # Build git clone command
            cmd = ["git", "clone"]

            # Add depth for shallow clone
            if depth > 0 and not commit:  # Can't use depth with specific commit
                cmd.extend(["--depth", str(depth)])

            # Add branch if specified
            if branch:
                cmd.extend(["--branch", branch])
            elif tag:
                cmd.extend(["--branch", tag])

            cmd.extend([url, str(clone_dir)])

            # Show what we're doing
            console.print(f"\n📥 [bold cyan]Cloning repository...[/]")
            console.print(f"   [dim]URL:[/] {url}")
            if branch:
                console.print(f"   [dim]Branch:[/] {branch}")
            elif tag:
                console.print(f"   [dim]Tag:[/] {tag}")
            if depth > 0 and not commit:
                console.print(f"   [dim]Mode:[/] Shallow clone (depth={depth})")
            console.print(f"   [dim]Destination:[/] {clone_dir}")

            # Clone with progress
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Cloning...", total=None)

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )

                progress.update(task, completed=True)

            if result.returncode != 0:
                error_msg = result.stderr or result.stdout
                raise subprocess.CalledProcessError(result.returncode, cmd, error_msg)

            # Checkout specific commit if requested
            if commit:
                console.print(f"   [dim]Checking out commit:[/] {commit}")
                checkout_result = subprocess.run(
                    ["git", "checkout", commit],
                    cwd=clone_dir,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if checkout_result.returncode != 0:
                    raise subprocess.CalledProcessError(
                        checkout_result.returncode,
                        ["git", "checkout", commit],
                        checkout_result.stderr
                    )

            console.print(f"   [bold green]✅ Clone complete[/]\n")

            return GitCloneResult(
                local_path=clone_dir,
                url=url,
                branch=branch,
                commit=commit,
                is_temp=True
            )

        except subprocess.TimeoutExpired:
            # Cleanup on timeout
            if clone_dir.exists():
                shutil.rmtree(clone_dir)
            raise ValueError(f"Git clone timed out after {timeout} seconds")
        except Exception as e:
            # Cleanup on error
            if clone_dir.exists():
                shutil.rmtree(clone_dir)
            raise
