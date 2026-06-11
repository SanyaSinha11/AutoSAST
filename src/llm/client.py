"""
LLM Client - Unified interface for multiple LLM providers.

Supports:
- OpenAI (GPT-4, GPT-4o, etc.)
- Azure OpenAI
- Google Gemini
- Groq (fast inference via OpenAI-compatible API)
- Ollama (local models via OpenAI-compatible API)
- LiteLLM (unified interface with tool calling support)
"""

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class ToolCall:
    """Represents a tool call from the LLM."""
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    """Response from an LLM call."""
    content: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    tool_calls: list[ToolCall] = field(default_factory=list)
    finish_reason: str = "stop"

    @property
    def cost_estimate(self) -> float:
        """Rough cost estimate in USD (varies by model)."""
        # Approximate costs per 1K tokens
        return (self.prompt_tokens * 0.01 + self.completion_tokens * 0.03) / 1000

    @property
    def has_tool_calls(self) -> bool:
        """Whether the response includes tool calls."""
        return len(self.tool_calls) > 0


@dataclass
class Message:
    """A message in a conversation."""
    role: str  # "system", "user", "assistant", "tool"
    content: Optional[str] = None
    tool_calls: Optional[list[dict]] = None
    tool_call_id: Optional[str] = None
    name: Optional[str] = None  # For tool messages

    def to_dict(self) -> dict:
        """Convert to API-compatible dict."""
        d = {"role": self.role}
        if self.content is not None:
            d["content"] = self.content
        if self.tool_calls:
            d["tool_calls"] = self.tool_calls
        if self.tool_call_id:
            d["tool_call_id"] = self.tool_call_id
        if self.name:
            d["name"] = self.name
        return d


class LLMClient(ABC):
    """Abstract base class for LLM clients."""

    @abstractmethod
    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Generate a completion for the given prompt."""
        pass

    def complete_with_tools(
        self,
        messages: list[Message],
        tools: Optional[list[dict]] = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Generate a completion with tool calling support.

        Default implementation falls back to regular completion.
        Subclasses should override for full tool support.
        """
        # Extract the last user message for basic completion
        user_content = ""
        system_content = None
        for msg in messages:
            if msg.role == "system":
                system_content = msg.content
            elif msg.role == "user":
                user_content = msg.content or ""
        return self.complete(user_content, system_content, temperature, max_tokens)


class OpenAIClient(LLMClient):
    """OpenAI API client with tool calling support."""

    def __init__(self, api_key: str, model: str = "gpt-4o"):
        self.api_key = api_key
        self.model = model
        self._client = None

    def _get_client(self):
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(api_key=self.api_key)
        return self._client

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        client = self._get_client()

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        return LLMResponse(
            content=response.choices[0].message.content or "",
            model=self.model,
            prompt_tokens=response.usage.prompt_tokens if response.usage else 0,
            completion_tokens=response.usage.completion_tokens if response.usage else 0,
            total_tokens=response.usage.total_tokens if response.usage else 0,
        )

    def complete_with_tools(
        self,
        messages: list[Message],
        tools: Optional[list[dict]] = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Generate a completion with tool calling support."""
        client = self._get_client()

        api_messages = [msg.to_dict() for msg in messages]

        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": api_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        response = client.chat.completions.create(**kwargs)
        choice = response.choices[0]

        # Parse tool calls if present
        tool_calls = []
        if choice.message.tool_calls:
            for tc in choice.message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    args = {}
                tool_calls.append(ToolCall(
                    id=tc.id,
                    name=tc.function.name,
                    arguments=args
                ))

        return LLMResponse(
            content=choice.message.content or "",
            model=self.model,
            prompt_tokens=response.usage.prompt_tokens if response.usage else 0,
            completion_tokens=response.usage.completion_tokens if response.usage else 0,
            total_tokens=response.usage.total_tokens if response.usage else 0,
            tool_calls=tool_calls,
            finish_reason=choice.finish_reason or "stop",
        )


class AzureOpenAIClient(LLMClient):
    """Azure OpenAI API client with tool calling support."""

    def __init__(self, api_key: str, endpoint: str, model: str, api_version: str = "2024-08-01-preview"):
        self.api_key = api_key
        self.endpoint = endpoint
        self.model = model
        self.api_version = api_version
        self._client = None

    def _get_client(self):
        if self._client is None:
            from openai import AzureOpenAI
            self._client = AzureOpenAI(
                api_key=self.api_key,
                azure_endpoint=self.endpoint,
                api_version=self.api_version,
            )
        return self._client

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        client = self._get_client()

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        return LLMResponse(
            content=response.choices[0].message.content or "",
            model=self.model,
            prompt_tokens=response.usage.prompt_tokens if response.usage else 0,
            completion_tokens=response.usage.completion_tokens if response.usage else 0,
            total_tokens=response.usage.total_tokens if response.usage else 0,
        )

    def complete_with_tools(
        self,
        messages: list[Message],
        tools: Optional[list[dict]] = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Generate a completion with tool calling support."""
        client = self._get_client()

        api_messages = [msg.to_dict() for msg in messages]

        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": api_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        response = client.chat.completions.create(**kwargs)
        choice = response.choices[0]

        # Parse tool calls if present
        tool_calls = []
        if choice.message.tool_calls:
            for tc in choice.message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    args = {}
                tool_calls.append(ToolCall(
                    id=tc.id,
                    name=tc.function.name,
                    arguments=args
                ))

        return LLMResponse(
            content=choice.message.content or "",
            model=self.model,
            prompt_tokens=response.usage.prompt_tokens if response.usage else 0,
            completion_tokens=response.usage.completion_tokens if response.usage else 0,
            total_tokens=response.usage.total_tokens if response.usage else 0,
            tool_calls=tool_calls,
            finish_reason=choice.finish_reason or "stop",
        )


class GeminiClient(LLMClient):
    """Google Gemini API client."""

    def __init__(self, api_key: str, model: str = "gemini-1.5-pro"):
        self.api_key = api_key
        self.model = model
        self._client = None

    def _get_client(self):
        if self._client is None:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            self._client = genai.GenerativeModel(self.model)
        return self._client

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        client = self._get_client()

        full_prompt = prompt
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{prompt}"

        response = client.generate_content(
            full_prompt,
            generation_config={"temperature": temperature, "max_output_tokens": max_tokens},
        )

        # Gemini doesn't provide token counts in the same way
        return LLMResponse(
            content=response.text,
            model=self.model,
            prompt_tokens=0,
            completion_tokens=0,
            total_tokens=0,
        )


class GroqClient(LLMClient):
    """Groq API client with tool calling support via OpenAI-compatible API."""

    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile"):
        self.api_key = api_key
        self.model = model
        self._client = None

    def _get_client(self):
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(
                base_url="https://api.groq.com/openai/v1",
                api_key=self.api_key
            )
        return self._client

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        client = self._get_client()

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        return LLMResponse(
            content=response.choices[0].message.content or "",
            model=self.model,
            prompt_tokens=response.usage.prompt_tokens if response.usage else 0,
            completion_tokens=response.usage.completion_tokens if response.usage else 0,
            total_tokens=response.usage.total_tokens if response.usage else 0,
        )

    def complete_with_tools(
        self,
        messages: list[Message],
        tools: Optional[list[dict]] = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Generate a completion with tool calling support."""
        client = self._get_client()

        api_messages = [msg.to_dict() for msg in messages]

        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": api_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        response = client.chat.completions.create(**kwargs)
        choice = response.choices[0]

        # Parse tool calls if present
        tool_calls = []
        if choice.message.tool_calls:
            for tc in choice.message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    args = {}
                tool_calls.append(ToolCall(
                    id=tc.id,
                    name=tc.function.name,
                    arguments=args
                ))

        return LLMResponse(
            content=choice.message.content or "",
            model=self.model,
            prompt_tokens=response.usage.prompt_tokens if response.usage else 0,
            completion_tokens=response.usage.completion_tokens if response.usage else 0,
            total_tokens=response.usage.total_tokens if response.usage else 0,
            tool_calls=tool_calls,
            finish_reason=choice.finish_reason or "stop",
        )


class OllamaClient(LLMClient):
    """Ollama API client with tool calling support via OpenAI-compatible API."""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "qwen2.5:14b"):
        self.base_url = base_url.rstrip("/") + "/v1"
        self.model = model
        self._client = None

    def _get_client(self):
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(
                base_url=self.base_url,
                api_key="ollama"  # Ollama doesn't require a real API key
            )
        return self._client

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        client = self._get_client()

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        return LLMResponse(
            content=response.choices[0].message.content or "",
            model=self.model,
            prompt_tokens=response.usage.prompt_tokens if response.usage else 0,
            completion_tokens=response.usage.completion_tokens if response.usage else 0,
            total_tokens=response.usage.total_tokens if response.usage else 0,
        )

    def complete_with_tools(
        self,
        messages: list[Message],
        tools: Optional[list[dict]] = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Generate a completion with tool calling support."""
        client = self._get_client()

        api_messages = [msg.to_dict() for msg in messages]

        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": api_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        response = client.chat.completions.create(**kwargs)
        choice = response.choices[0]

        # Parse tool calls if present
        tool_calls = []
        if choice.message.tool_calls:
            for tc in choice.message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    args = {}
                tool_calls.append(ToolCall(
                    id=tc.id,
                    name=tc.function.name,
                    arguments=args
                ))

        return LLMResponse(
            content=choice.message.content or "",
            model=self.model,
            prompt_tokens=response.usage.prompt_tokens if response.usage else 0,
            completion_tokens=response.usage.completion_tokens if response.usage else 0,
            total_tokens=response.usage.total_tokens if response.usage else 0,
            tool_calls=tool_calls,
            finish_reason=choice.finish_reason or "stop",
        )


def create_llm_client(
    provider: str,
    model: str,
    openai_api_key: Optional[str] = None,
    azure_api_key: Optional[str] = None,
    azure_endpoint: Optional[str] = None,
    azure_api_version: str = "2024-08-01-preview",
    google_api_key: Optional[str] = None,
    ollama_base_url: Optional[str] = None,
    groq_api_key: Optional[str] = None,
) -> LLMClient:
    """Factory function to create the appropriate LLM client."""

    if provider == "openai":
        if not openai_api_key:
            raise ValueError("OpenAI API key is required")
        return OpenAIClient(api_key=openai_api_key, model=model)

    elif provider == "azure":
        if not azure_api_key or not azure_endpoint:
            raise ValueError("Azure API key and endpoint are required")
        return AzureOpenAIClient(
            api_key=azure_api_key,
            endpoint=azure_endpoint,
            model=model,
            api_version=azure_api_version,
        )

    elif provider == "gemini":
        if not google_api_key:
            raise ValueError("Google API key is required")
        return GeminiClient(api_key=google_api_key, model=model)

    elif provider == "groq":
        if not groq_api_key:
            raise ValueError("Groq API key is required")
        return GroqClient(api_key=groq_api_key, model=model)

    elif provider == "ollama":
        base_url = ollama_base_url or "http://localhost:11434"
        return OllamaClient(base_url=base_url, model=model)

    else:
        raise ValueError(f"Unknown provider: {provider}")

