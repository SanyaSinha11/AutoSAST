"""
Configuration management for AutoSAST.
Loads environment variables and provides configuration validation.
"""

import os
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


@dataclass
class Config:
    """Configuration settings for AutoSAST."""

    # LLM Provider settings
    provider: str
    model: str
    openai_api_key: Optional[str] = None
    azure_api_key: Optional[str] = None
    azure_endpoint: Optional[str] = None
    azure_api_version: str = "2024-08-01-preview"
    google_api_key: Optional[str] = None
    groq_api_key: Optional[str] = None
    ollama_base_url: Optional[str] = None

    # LLM parameters
    temperature: float = 0.2
    top_p: float = 0.2

    # Semgrep settings
    semgrep_path: str = "semgrep"
    semgrep_rules_path: Optional[str] = None  # Custom rules file/directory/URL

    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = None

    # Output directories
    output_dir: Path = Path("results")
    results_dir: Path = Path("results")

    # AST Parser settings
    use_ast_parser: bool = True  # Use Tree-sitter AST parsing for code extraction
    ast_parser_fallback: bool = True  # Fall back to regex if AST parsing fails
    
    def validate(self) -> list[str]:
        """Validate configuration and return list of errors."""
        errors = []

        if self.provider not in ["openai", "azure", "gemini", "groq", "ollama"]:
            errors.append(f"Invalid provider: {self.provider}. Must be 'openai', 'azure', 'gemini', 'groq', or 'ollama'")

        if self.provider == "openai" and not self.openai_api_key:
            errors.append("OPENAI_API_KEY is required when using OpenAI provider")

        if self.provider == "azure":
            if not self.azure_api_key:
                errors.append("AZURE_OPENAI_API_KEY is required when using Azure provider")
            if not self.azure_endpoint:
                errors.append("AZURE_OPENAI_ENDPOINT is required when using Azure provider")

        if self.provider == "gemini" and not self.google_api_key:
            errors.append("GOOGLE_API_KEY is required when using Gemini provider")

        if self.provider == "groq" and not self.groq_api_key:
            errors.append("GROQ_API_KEY is required when using Groq provider")

        return errors


def load_config() -> Config:
    """Load configuration from environment variables."""
    config = Config(
        provider=os.getenv("PROVIDER", "openai").lower(),
        model=os.getenv("MODEL", "gpt-4o"),
        openai_api_key=os.getenv("OPENAI_API_KEY"),
        azure_api_key=os.getenv("AZURE_OPENAI_API_KEY") or os.getenv("AZURE_API_KEY"),
        azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT") or os.getenv("AZURE_API_BASE"),
        azure_api_version=os.getenv("AZURE_OPENAI_API_VERSION") or os.getenv("AZURE_API_VERSION", "2024-08-01-preview"),
        google_api_key=os.getenv("GOOGLE_API_KEY"),
        groq_api_key=os.getenv("GROQ_API_KEY"),
        ollama_base_url=os.getenv("OLLAMA_BASE_URL"),
        temperature=float(os.getenv("LLM_TEMPERATURE", "0.2")),
        top_p=float(os.getenv("LLM_TOP_P", "0.2")),
        semgrep_path=os.getenv("SEMGREP_PATH", "semgrep"),
        semgrep_rules_path=os.getenv("SEMGREP_RULES_PATH"),
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        log_file=os.getenv("LOG_FILE"),
        output_dir=Path(os.getenv("OUTPUT_DIR", "output")),
        results_dir=Path(os.getenv("RESULTS_DIR", "output/results")),
        use_ast_parser=os.getenv("USE_AST_PARSER", "true").lower() in ("true", "1", "yes"),
        ast_parser_fallback=os.getenv("AST_PARSER_FALLBACK", "true").lower() in ("true", "1", "yes"),
    )

    errors = config.validate()
    if errors:
        error_msg = "\n".join(f"  - {e}" for e in errors)
        raise ValueError(f"Configuration errors:\n{error_msg}")

    return config

