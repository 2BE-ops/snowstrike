"""
SnowStrike AI v7.0 - Model Client Factory

Provides a unified interface for Anthropic, OpenAI-compatible, and xAI Grok APIs.
The OpenAI adapter translates Anthropic-style tool_use calls to/from the OpenAI
function calling format so that base_agent.py can work with any provider
transparently.

Grok integration supports:
  - Responses API (stateful multi-turn conversations via previous_response_id)
  - Chat Completions API (standard tool-calling for agents)
  - Streaming via SSE for real-time token output
  - Reasoning models (grok-4.20-reasoning) with encrypted thinking
  - Multi-agent research (grok-4.20-multi-agent) for deep OSINT
  - Structured outputs via JSON schema enforcement
"""

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from config import AVAILABLE_MODELS

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lightweight response objects that mirror the Anthropic SDK shapes
# ---------------------------------------------------------------------------

@dataclass
class TextBlock:
    type: str = "text"
    text: str = ""


@dataclass
class ToolUseBlock:
    type: str = "tool_use"
    id: str = ""
    name: str = ""
    input: dict = field(default_factory=dict)


@dataclass
class ProviderAssistantMessageBlock:
    """Preserve the provider-native assistant payload for lossless replay."""
    type: str = "provider_assistant_message"
    provider: str = "openai_compatible"
    message: dict = field(default_factory=dict)


@dataclass
class UnifiedResponse:
    """Matches the shape of anthropic.types.Message so callers don't branch."""
    content: list = field(default_factory=list)
    stop_reason: str = "end_turn"
    model: str = ""
    usage: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# OpenAI-compatible adapter
# ---------------------------------------------------------------------------

class OpenAICompatibleClient:
    """Wraps an OpenAI-compatible endpoint (Kimi K2, etc.) used for compaction and optionally for tool-calling agents."""

    def __init__(self, api_key: str, base_url: str):
        from openai import OpenAI
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.messages = self  # so client.messages.create(...) works
        self.is_openai_compatible = True

    def create(
        self,
        model: str,
        max_tokens: int = 4096,
        system: str = "",
        tools: list[dict] | None = None,
        messages: list[dict] | None = None,
        **kwargs,
    ) -> UnifiedResponse:
        """Translate Anthropic-style call to OpenAI chat completion and back."""
        oai_messages = self._translate_messages(system, messages or [])
        oai_tools = self._translate_tools(tools) if tools else None

        # Newer OpenAI models (gpt-5.x, o1, o3, etc.) require
        # 'max_completion_tokens' instead of 'max_tokens'.
        token_limit_key = "max_completion_tokens" if self._needs_completion_tokens(model) else "max_tokens"

        create_kwargs: dict[str, Any] = {
            "model": model,
            token_limit_key: max_tokens,
            "messages": oai_messages,
        }
        if oai_tools:
            create_kwargs["tools"] = oai_tools

        # Forward model hyperparameters (temperature, top_p) if provided
        for param in ("temperature", "top_p"):
            if param in kwargs:
                create_kwargs[param] = kwargs[param]

        response = self._call_with_retry(create_kwargs)
        return self._translate_response(response)

    def _call_with_retry(self, create_kwargs: dict, max_retries: int = 3):
        """Call OpenAI API with exponential backoff on transient errors."""
        from openai import APIStatusError, APIConnectionError, RateLimitError

        for attempt in range(max_retries + 1):
            try:
                return self.client.chat.completions.create(**create_kwargs)
            except RateLimitError as e:
                if attempt == max_retries:
                    raise
                wait = min(2 ** attempt * 2, 60)
                logger.warning("Rate limited (attempt %d/%d), retrying in %ds", attempt + 1, max_retries, wait)
                time.sleep(wait)
            except APIStatusError as e:
                if e.status_code in (500, 502, 503, 529) and attempt < max_retries:
                    wait = min(2 ** attempt * 1, 30)
                    logger.warning("Server error %d (attempt %d/%d), retrying in %ds", e.status_code, attempt + 1, max_retries, wait)
                    time.sleep(wait)
                else:
                    raise
            except APIConnectionError as e:
                if attempt == max_retries:
                    raise
                wait = min(2 ** attempt * 1, 30)
                logger.warning("Connection error (attempt %d/%d), retrying in %ds", attempt + 1, max_retries, wait)
                time.sleep(wait)

    # -- parameter compatibility --

    @staticmethod
    def _needs_completion_tokens(model: str) -> bool:
        """Return True if the model requires 'max_completion_tokens' instead of 'max_tokens'."""
        # OpenAI's newer models dropped support for the legacy 'max_tokens' param.
        # Match gpt-5*, o1*, o3*, o4*, and chatgpt-* model IDs.
        m = model.lower()
        for prefix in ("gpt-5", "gpt-4o", "o1", "o3", "o4", "chatgpt-"):
            if m.startswith(prefix):
                return True
        return False

    # -- message format translation --

    @staticmethod
    def _translate_messages(system: str, messages: list[dict]) -> list[dict]:
        """Convert Anthropic message format to OpenAI format."""
        oai: list[dict] = []
        if system:
            oai.append({"role": "system", "content": system})

        for msg in messages:
            role = msg["role"]
            content = msg.get("content", "")

            # Simple string content
            if isinstance(content, str):
                oai.append({"role": role, "content": content})
                continue

            # List content (Anthropic format with tool_use / tool_result blocks)
            if isinstance(content, list):
                # Assistant message with possible tool_calls
                if role == "assistant":
                    raw_message = OpenAICompatibleClient._extract_provider_assistant_message(content)
                    if raw_message is not None:
                        oai.append(raw_message)
                        continue

                    text_parts = []
                    tool_calls = []
                    for block in content:
                        if hasattr(block, "type"):
                            # Anthropic SDK object
                            if block.type == "text":
                                text_parts.append(block.text)
                            elif block.type == "tool_use":
                                tool_calls.append({
                                    "id": block.id,
                                    "type": "function",
                                    "function": {
                                        "name": block.name,
                                        "arguments": json.dumps(block.input),
                                    },
                                })
                        elif isinstance(block, dict):
                            if block.get("type") == "text":
                                text_parts.append(block.get("text", ""))
                            elif block.get("type") == "tool_use":
                                tool_calls.append({
                                    "id": block["id"],
                                    "type": "function",
                                    "function": {
                                        "name": block["name"],
                                        "arguments": json.dumps(block.get("input", {})),
                                    },
                                })

                    entry: dict[str, Any] = {"role": "assistant"}
                    entry["content"] = "\n".join(text_parts) if text_parts else None
                    if tool_calls:
                        entry["tool_calls"] = tool_calls
                    oai.append(entry)

                # User message with tool_result blocks
                elif role == "user":
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "tool_result":
                            oai.append({
                                "role": "tool",
                                "tool_call_id": block.get("tool_use_id", ""),
                                "content": block.get("content", ""),
                            })
                        elif isinstance(block, dict) and block.get("type") == "text":
                            oai.append({"role": "user", "content": block.get("text", "")})
                        elif isinstance(block, str):
                            oai.append({"role": "user", "content": block})

                continue

            oai.append({"role": role, "content": str(content)})

        return oai

    @staticmethod
    def _extract_provider_assistant_message(content: list) -> dict | None:
        """Return a lossless assistant message payload if one was preserved."""
        for block in content:
            if hasattr(block, "type") and getattr(block, "type") == "provider_assistant_message":
                message = getattr(block, "message", None)
                if isinstance(message, dict):
                    return dict(message)
            elif isinstance(block, dict) and block.get("type") == "provider_assistant_message":
                message = block.get("message")
                if isinstance(message, dict):
                    return dict(message)
        return None

    @staticmethod
    def _provider_obj_to_dict(obj: Any) -> Any:
        """Recursively convert provider SDK objects into JSON-safe Python types."""
        if obj is None or isinstance(obj, (str, int, float, bool)):
            return obj
        if isinstance(obj, list):
            return [OpenAICompatibleClient._provider_obj_to_dict(item) for item in obj]
        if isinstance(obj, dict):
            return {
                k: OpenAICompatibleClient._provider_obj_to_dict(v)
                for k, v in obj.items()
            }
        if hasattr(obj, "model_dump"):
            try:
                dumped = obj.model_dump(exclude_none=True)
            except TypeError:
                dumped = obj.model_dump()
            return OpenAICompatibleClient._provider_obj_to_dict(dumped)
        if hasattr(obj, "__dict__"):
            return {
                k: OpenAICompatibleClient._provider_obj_to_dict(v)
                for k, v in vars(obj).items()
                if not k.startswith("_")
            }
        return obj

    @staticmethod
    def _dump_provider_message(message: Any) -> dict:
        """Serialize a provider assistant message so it can be replayed losslessly."""
        dumped = OpenAICompatibleClient._provider_obj_to_dict(message)
        if not isinstance(dumped, dict):
            dumped = {"role": "assistant", "content": getattr(message, "content", None)}
        dumped.setdefault("role", "assistant")
        return dumped

    @staticmethod
    def _translate_tools(tools: list[dict]) -> list[dict]:
        """Convert Anthropic tool schemas to OpenAI function calling format."""
        oai_tools = []
        for tool in tools:
            oai_tools.append({
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": tool.get("input_schema", {"type": "object", "properties": {}}),
                },
            })
        return oai_tools

    @staticmethod
    def _translate_response(response) -> UnifiedResponse:
        """Convert OpenAI response to Anthropic-compatible UnifiedResponse."""
        if not response.choices:
            logger.warning("API returned empty choices list — possible content filter block")
            return UnifiedResponse(
                content=[TextBlock(text="[Error: API returned no response choices]")],
                stop_reason="end_turn",
                model=getattr(response, "model", "unknown"),
                usage={"input_tokens": 0, "output_tokens": 0},
            )
        choice = response.choices[0]
        message = choice.message
        content_blocks: list = []
        raw_message = OpenAICompatibleClient._dump_provider_message(message)

        if raw_message:
            content_blocks.append(ProviderAssistantMessageBlock(message=raw_message))

        if message.content:
            content_blocks.append(TextBlock(text=message.content))

        stop_reason = "end_turn"
        if message.tool_calls:
            stop_reason = "tool_use"
            for tc in message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, TypeError):
                    logger.warning(
                        "Failed to parse tool call arguments for %s: %s",
                        tc.function.name, tc.function.arguments[:200],
                    )
                    args = {"_parse_error": f"Invalid JSON in tool arguments: {tc.function.arguments[:200]}"}
                content_blocks.append(ToolUseBlock(
                    id=tc.id,
                    name=tc.function.name,
                    input=args,
                ))

        return UnifiedResponse(
            content=content_blocks,
            stop_reason=stop_reason,
            model=response.model,
            usage={
                "input_tokens": getattr(response.usage, "prompt_tokens", 0),
                "output_tokens": getattr(response.usage, "completion_tokens", 0),
            },
        )


# ---------------------------------------------------------------------------
# xAI Grok adapter — Responses API + Chat Completions + Streaming
# ---------------------------------------------------------------------------

class GrokClient:
    """Wraps the xAI Grok API with full feature support.

    Capabilities:
        - Responses API for stateful multi-turn conversations
          (saves tokens via previous_response_id instead of resending history)
        - Chat Completions API for standard tool-calling agents
        - SSE streaming for real-time token output
        - Reasoning models with encrypted thinking content
        - Multi-agent research (grok-4.20-multi-agent) for deep OSINT
        - Structured outputs via JSON schema enforcement
        - Conversation chaining with 30-day server-side storage

    The client auto-routes between Responses API and Chat Completions based
    on the model name and whether tools are present.
    """

    GROK_BASE_URL = "https://api.x.ai/v1"

    def __init__(self, api_key: str):
        from openai import OpenAI
        import httpx
        self.client = OpenAI(
            api_key=api_key,
            base_url=self.GROK_BASE_URL,
            timeout=httpx.Timeout(3600.0),  # Reasoning models can take minutes
        )
        self.messages = self  # so client.messages.create(...) works like Anthropic
        self.is_openai_compatible = True
        self.is_grok = True

        # Responses API state: maps conversation_key -> last response_id
        # Enables stateful conversation chaining without resending full history.
        self._response_ids: dict[str, str] = {}

    # -- Model classification helpers --

    @staticmethod
    def is_reasoning_model(model: str) -> bool:
        """Check if this is a Grok reasoning model (needs longer timeouts, supports encrypted thinking)."""
        return "reasoning" in model.lower()

    @staticmethod
    def is_multi_agent_model(model: str) -> bool:
        """Check if this is the multi-agent research model (no client-side tools, uses built-in tools)."""
        return "multi-agent" in model.lower()

    @staticmethod
    def is_responses_capable(model: str) -> bool:
        """Check if this model should use the Responses API (all Grok models support it)."""
        return True

    # -- Public API (matches Anthropic .messages.create() signature) --

    def create(
        self,
        model: str,
        max_tokens: int = 4096,
        system: str = "",
        tools: list[dict] | None = None,
        messages: list[dict] | None = None,
        **kwargs,
    ) -> UnifiedResponse:
        """Route to the best API path based on model and request shape.

        Routing logic:
          - Multi-agent models -> Responses API (no client-side tools allowed)
          - Reasoning models without tools -> Responses API (stateful + encrypted thinking)
          - Models with tools -> Chat Completions (full function calling support)
          - All others -> Chat Completions (standard path)
        """
        conversation_key = kwargs.pop("conversation_key", None)

        if self.is_multi_agent_model(model):
            return self._call_responses_api(
                model, system, messages or [], tools, conversation_key, **kwargs
            )

        if self.is_reasoning_model(model) and not tools:
            return self._call_responses_api(
                model, system, messages or [], tools, conversation_key, **kwargs
            )

        return self._call_chat_completions(
            model, max_tokens, system, tools, messages or [], **kwargs
        )

    # -- Responses API (stateful conversations, multi-agent, reasoning) --

    def _call_responses_api(
        self,
        model: str,
        system: str,
        messages: list[dict],
        tools: list[dict] | None,
        conversation_key: str | None = None,
        **kwargs,
    ) -> UnifiedResponse:
        """Use the xAI Responses API for stateful conversation management.

        Features leveraged:
          - previous_response_id: Continue conversations without resending history
          - reasoning.encrypted_content: Preserve reasoning state across turns
          - Built-in tools (web_search, x_search) for multi-agent models
          - Configurable agent count (4 or 16) for multi-agent
        """
        input_messages = self._build_responses_input(system, messages)

        create_kwargs: dict[str, Any] = {
            "model": model,
            "input": input_messages,
        }

        # Chain conversation if we have a previous response ID
        if conversation_key and conversation_key in self._response_ids:
            create_kwargs["previous_response_id"] = self._response_ids[conversation_key]
            # When chaining, only send new messages (not full history)
            create_kwargs["input"] = self._extract_new_messages(messages)

        # Request encrypted thinking for reasoning models
        if self.is_reasoning_model(model):
            create_kwargs["include"] = ["reasoning.encrypted_content"]

        # Multi-agent: add built-in tools and configure agent count
        if self.is_multi_agent_model(model):
            grok_tools = []
            grok_tools.append({"type": "web_search"})
            grok_tools.append({"type": "x_search"})
            create_kwargs["tools"] = grok_tools
            # Default to 4 agents; use 16 for deep research via kwargs
            agent_effort = kwargs.pop("reasoning_effort", "low")
            create_kwargs["reasoning"] = {"effort": agent_effort}

        response = self._call_responses_with_retry(create_kwargs)

        # Store the response ID for future conversation chaining
        if conversation_key and hasattr(response, "id"):
            self._response_ids[conversation_key] = response.id

        return self._translate_responses_api_response(response, model)

    def _build_responses_input(self, system: str, messages: list[dict]) -> list[dict]:
        """Convert Anthropic-format messages to Responses API input format."""
        input_msgs: list[dict] = []
        if system:
            input_msgs.append({"role": "system", "content": system})

        for msg in messages:
            role = msg["role"]
            content = msg.get("content", "")

            if isinstance(content, str):
                input_msgs.append({"role": role, "content": content})
            elif isinstance(content, list):
                # Flatten list content to string for Responses API
                text_parts = []
                for block in content:
                    if hasattr(block, "type"):
                        if block.type == "text":
                            text_parts.append(block.text)
                    elif isinstance(block, dict):
                        if block.get("type") == "text":
                            text_parts.append(block.get("text", ""))
                        elif block.get("type") == "tool_result":
                            text_parts.append(
                                f"[Tool Result: {block.get('content', '')}]"
                            )
                if text_parts:
                    input_msgs.append({"role": role, "content": "\n".join(text_parts)})
            else:
                input_msgs.append({"role": role, "content": str(content)})

        return input_msgs

    def _extract_new_messages(self, messages: list[dict]) -> list[dict]:
        """When chaining via previous_response_id, only send the latest user message."""
        new_msgs = []
        for msg in reversed(messages):
            role = msg.get("role", "")
            content = msg.get("content", "")
            if isinstance(content, list):
                text_parts = []
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text_parts.append(block.get("text", ""))
                    elif isinstance(block, str):
                        text_parts.append(block)
                    elif hasattr(block, "text"):
                        text_parts.append(block.text)
                content = "\n".join(text_parts) if text_parts else str(content)
            new_msgs.insert(0, {"role": role, "content": content})
            if role == "user":
                break
        return new_msgs

    def _call_responses_with_retry(self, create_kwargs: dict, max_retries: int = 3):
        """Call xAI Responses API with exponential backoff."""
        from openai import APIStatusError, APIConnectionError, RateLimitError

        for attempt in range(max_retries + 1):
            try:
                return self.client.responses.create(**create_kwargs)
            except RateLimitError:
                if attempt == max_retries:
                    raise
                wait = min(2 ** attempt * 2, 60)
                logger.warning(
                    "Grok rate limited (attempt %d/%d), retrying in %ds",
                    attempt + 1, max_retries, wait,
                )
                time.sleep(wait)
            except APIStatusError as e:
                if e.status_code in (500, 502, 503, 529) and attempt < max_retries:
                    wait = min(2 ** attempt * 2, 30)
                    logger.warning(
                        "Grok server error %d (attempt %d/%d), retrying in %ds",
                        e.status_code, attempt + 1, max_retries, wait,
                    )
                    time.sleep(wait)
                else:
                    raise
            except APIConnectionError:
                if attempt == max_retries:
                    raise
                wait = min(2 ** attempt * 2, 30)
                logger.warning(
                    "Grok connection error (attempt %d/%d), retrying in %ds",
                    attempt + 1, max_retries, wait,
                )
                time.sleep(wait)

    def _translate_responses_api_response(self, response, model: str) -> UnifiedResponse:
        """Convert xAI Responses API response to UnifiedResponse."""
        content_blocks: list = []
        text_content = ""

        # Extract text from response output
        if hasattr(response, "output") and response.output:
            for item in response.output:
                item_type = getattr(item, "type", None)
                if item_type == "message":
                    msg_content = getattr(item, "content", [])
                    for block in msg_content:
                        block_type = getattr(block, "type", None)
                        if block_type == "output_text":
                            text_content += getattr(block, "text", "")
                elif item_type == "reasoning":
                    # Reasoning blocks are internal; log but don't surface
                    logger.debug("Grok reasoning block (status: %s)", getattr(item, "status", "unknown"))

        # Fall back to output_text shorthand
        if not text_content and hasattr(response, "output_text"):
            text_content = response.output_text or ""

        if text_content:
            content_blocks.append(TextBlock(text=text_content))

        # Preserve the raw response for lossless replay
        raw_message = {
            "role": "assistant",
            "content": text_content,
        }
        if hasattr(response, "id"):
            raw_message["grok_response_id"] = response.id
        content_blocks.insert(0, ProviderAssistantMessageBlock(
            provider="grok",
            message=raw_message,
        ))

        # Extract usage
        usage = {"input_tokens": 0, "output_tokens": 0}
        if hasattr(response, "usage") and response.usage:
            usage["input_tokens"] = getattr(response.usage, "input_tokens", 0) or 0
            usage["output_tokens"] = getattr(response.usage, "output_tokens", 0) or 0
            # Include reasoning tokens in output count for cost tracking
            reasoning_tokens = getattr(response.usage, "reasoning_tokens", 0) or 0
            if reasoning_tokens:
                usage["output_tokens"] += reasoning_tokens
                usage["reasoning_tokens"] = reasoning_tokens

        return UnifiedResponse(
            content=content_blocks,
            stop_reason="end_turn",
            model=model,
            usage=usage,
        )

    # -- Chat Completions API (tool-calling agents) --

    def _call_chat_completions(
        self,
        model: str,
        max_tokens: int,
        system: str,
        tools: list[dict] | None,
        messages: list[dict],
        **kwargs,
    ) -> UnifiedResponse:
        """Use standard Chat Completions API for tool-calling Grok models."""
        oai_messages = OpenAICompatibleClient._translate_messages(system, messages)
        oai_tools = OpenAICompatibleClient._translate_tools(tools) if tools else None

        create_kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": oai_messages,
        }
        if oai_tools:
            create_kwargs["tools"] = oai_tools

        response = self._call_completions_with_retry(create_kwargs)
        return OpenAICompatibleClient._translate_response(response)

    def _call_completions_with_retry(self, create_kwargs: dict, max_retries: int = 3):
        """Call xAI Chat Completions with exponential backoff."""
        from openai import APIStatusError, APIConnectionError, RateLimitError

        for attempt in range(max_retries + 1):
            try:
                return self.client.chat.completions.create(**create_kwargs)
            except RateLimitError:
                if attempt == max_retries:
                    raise
                wait = min(2 ** attempt * 2, 60)
                logger.warning(
                    "Grok rate limited (attempt %d/%d), retrying in %ds",
                    attempt + 1, max_retries, wait,
                )
                time.sleep(wait)
            except APIStatusError as e:
                if e.status_code in (500, 502, 503, 529) and attempt < max_retries:
                    wait = min(2 ** attempt * 2, 30)
                    logger.warning(
                        "Grok server error %d (attempt %d/%d), retrying in %ds",
                        e.status_code, attempt + 1, max_retries, wait,
                    )
                    time.sleep(wait)
                else:
                    raise
            except APIConnectionError:
                if attempt == max_retries:
                    raise
                wait = min(2 ** attempt * 2, 30)
                logger.warning(
                    "Grok connection error (attempt %d/%d), retrying in %ds",
                    attempt + 1, max_retries, wait,
                )
                time.sleep(wait)

    # -- Streaming (SSE via Chat Completions) --

    def stream(
        self,
        model: str,
        max_tokens: int = 8192,
        system: str = "",
        tools: list[dict] | None = None,
        messages: list[dict] | None = None,
    ):
        """Return a streaming context manager for Grok models.

        Yields delta chunks via SSE. Used by base_agent._call_api_streaming()
        when a Grok model is detected.

        Returns a GrokStreamContext that mimics Anthropic's stream interface:
            with client.messages.stream(...) as stream:
                for text in stream.text_stream:
                    ...
                response = stream.get_final_message()
        """
        oai_messages = OpenAICompatibleClient._translate_messages(system, messages or [])
        oai_tools = OpenAICompatibleClient._translate_tools(tools) if tools else None

        create_kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": oai_messages,
            "stream": True,
        }
        if oai_tools:
            create_kwargs["tools"] = oai_tools

        return GrokStreamContext(self.client, create_kwargs, model)

    # -- Conversation management --

    def get_response_id(self, conversation_key: str) -> str | None:
        """Get the stored response ID for a conversation (for chaining)."""
        return self._response_ids.get(conversation_key)

    def set_response_id(self, conversation_key: str, response_id: str):
        """Store a response ID for conversation chaining."""
        self._response_ids[conversation_key] = response_id

    def clear_response_id(self, conversation_key: str):
        """Clear stored response ID (e.g., on conversation reset)."""
        self._response_ids.pop(conversation_key, None)


class GrokStreamContext:
    """Context manager that mimics Anthropic's messages.stream() interface for Grok.

    Usage:
        with grok_client.messages.stream(model=..., messages=...) as stream:
            for text in stream.text_stream:
                print(text, end="")
            response = stream.get_final_message()
    """

    def __init__(self, openai_client, create_kwargs: dict, model: str):
        self._client = openai_client
        self._create_kwargs = create_kwargs
        self._model = model
        self._stream = None
        self._accumulated_text = ""
        self._accumulated_tool_calls: list = []
        self._usage = {"input_tokens": 0, "output_tokens": 0}
        self._tool_call_buffers: dict[int, dict] = {}  # index -> partial tool call

    def __enter__(self):
        self._stream = self._client.chat.completions.create(**self._create_kwargs)
        return self

    def __exit__(self, *args):
        if self._stream:
            try:
                self._stream.close()
            except Exception:
                pass

    @property
    def text_stream(self):
        """Yield text deltas as they arrive via SSE."""
        if self._stream is None:
            return

        for chunk in self._stream:
            if not chunk.choices:
                continue
            delta = chunk.choices[0].delta

            # Accumulate text content
            if delta and delta.content:
                self._accumulated_text += delta.content
                yield delta.content

            # Accumulate tool calls
            if delta and delta.tool_calls:
                for tc_delta in delta.tool_calls:
                    idx = tc_delta.index
                    if idx not in self._tool_call_buffers:
                        self._tool_call_buffers[idx] = {
                            "id": tc_delta.id or "",
                            "name": "",
                            "arguments": "",
                        }
                    buf = self._tool_call_buffers[idx]
                    if tc_delta.id:
                        buf["id"] = tc_delta.id
                    if tc_delta.function:
                        if tc_delta.function.name:
                            buf["name"] = tc_delta.function.name
                        if tc_delta.function.arguments:
                            buf["arguments"] += tc_delta.function.arguments

            # Capture usage from final chunk
            if hasattr(chunk, "usage") and chunk.usage:
                self._usage["input_tokens"] = getattr(chunk.usage, "prompt_tokens", 0) or 0
                self._usage["output_tokens"] = getattr(chunk.usage, "completion_tokens", 0) or 0

    def get_final_message(self) -> UnifiedResponse:
        """Return the accumulated response in UnifiedResponse format."""
        content_blocks: list = []

        # Preserve raw message for lossless replay
        raw_message: dict[str, Any] = {"role": "assistant", "content": self._accumulated_text or None}
        if self._tool_call_buffers:
            raw_message["tool_calls"] = [
                {
                    "id": buf["id"],
                    "type": "function",
                    "function": {"name": buf["name"], "arguments": buf["arguments"]},
                }
                for buf in sorted(self._tool_call_buffers.values(), key=lambda b: b["id"])
            ]
        content_blocks.append(ProviderAssistantMessageBlock(provider="grok", message=raw_message))

        if self._accumulated_text:
            content_blocks.append(TextBlock(text=self._accumulated_text))

        stop_reason = "end_turn"
        if self._tool_call_buffers:
            stop_reason = "tool_use"
            for buf in self._tool_call_buffers.values():
                try:
                    args = json.loads(buf["arguments"])
                except (json.JSONDecodeError, TypeError):
                    logger.warning(
                        "Failed to parse streamed tool call arguments for %s: %s",
                        buf["name"], buf["arguments"][:200],
                    )
                    args = {"_parse_error": f"Invalid JSON in tool arguments: {buf['arguments'][:200]}"}
                content_blocks.append(ToolUseBlock(
                    id=buf["id"],
                    name=buf["name"],
                    input=args,
                ))

        return UnifiedResponse(
            content=content_blocks,
            stop_reason=stop_reason,
            model=self._model,
            usage=self._usage,
        )


# ---------------------------------------------------------------------------
# Claude Code CLI adapter — uses subscription auth via `claude -p`
# ---------------------------------------------------------------------------

class ClaudeCodeError(Exception):
    """Raised when the Claude Code CLI subprocess fails."""
    pass


class ClaudeCodeClient:
    """Wraps the Claude Code CLI (`claude -p`) as an LLM backend.

    Uses the logged-in Claude Code session (OAuth) instead of API keys,
    so agents can run on a Claude Pro/Max subscription's included usage.

    Tool calling is handled via prompt-engineered XML blocks: the model
    outputs <tool_call> blocks which are parsed into ToolUseBlock objects.
    The base_agent tool_use loop executes tools and feeds results back
    exactly as it does for other providers.
    """

    # Regex to extract <tool_call name="X" id="Y">{json}</tool_call> blocks
    _TOOL_CALL_RE = re.compile(
        r'<tool_call\s+name="([^"]+)"\s+id="([^"]+)">\s*'
        r'(.*?)'
        r'</tool_call>',
        re.DOTALL,
    )

    _TOOL_CALL_INSTRUCTIONS = """\

## Tool Calling Protocol

When you need to use a tool, output one or more tool_call blocks in your response.
Each block must use this exact XML format:

<tool_call name="tool_name" id="call_XXXX">
{"param1": "value1", "param2": "value2"}
</tool_call>

Rules:
- Generate a unique id for each call (e.g. call_001, call_002, ...).
- The body MUST be valid JSON matching the tool's parameter schema.
- You may include multiple tool_call blocks in one response.
- When you are done and want to provide your final answer, respond with
  plain text and NO tool_call blocks.
- After tool results are provided, continue your analysis.
"""

    def __init__(
        self,
        model_id: str = "claude-sonnet-4-6",
        max_budget_usd: float = 5.0,
    ):
        self.model_id = model_id
        self.messages = self  # so client.messages.create(...) works
        self.is_claude_code = True
        self._max_budget_usd = max_budget_usd
        self._active_session_id: str | None = None
        self._timeout = int(os.environ.get("CLAUDE_CODE_TIMEOUT", "300"))
        self._claude_bin = os.environ.get("CLAUDE_CODE_BINARY", "claude")

        # Verify the claude CLI is available
        if not shutil.which(self._claude_bin):
            raise ClaudeCodeError(
                f"Claude Code CLI not found (looked for '{self._claude_bin}'). "
                f"Install it or set CLAUDE_CODE_BINARY to the correct path."
            )

    # -- Public API (matches Anthropic .messages.create() signature) --

    def create(
        self,
        model: str,
        max_tokens: int = 8192,
        system: str = "",
        tools: list[dict] | None = None,
        messages: list[dict] | None = None,
        **kwargs,
    ) -> UnifiedResponse:
        """Call the Claude Code CLI and return an Anthropic-compatible response.

        Flow:
        1. Augment the system prompt with tool schemas + calling instructions.
        2. Format messages into a text prompt (full history or tool results only).
        3. Shell out to `claude -p` with the prompt on stdin.
        4. Parse the JSON output for text + tool_call blocks.
        5. Return a UnifiedResponse with TextBlock / ToolUseBlock content.
        """
        messages = messages or []

        # Detect new conversation vs continuation
        is_new_conversation = (
            len(messages) <= 1
            or self._active_session_id is None
        )
        if is_new_conversation:
            self._active_session_id = None

        # Build the augmented system prompt (only needed for new conversations)
        augmented_system = self._build_augmented_system(system, tools)

        # Format the prompt text from messages
        prompt_text = self._format_prompt(messages, is_new_conversation)

        # Write system prompt to temp file with restrictive permissions
        fd, system_prompt_path = tempfile.mkstemp(suffix=".md", prefix="ss_prompt_")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(augmented_system)
        except Exception:
            os.close(fd)
            raise

        try:
            result_json = self._invoke_cli(
                prompt_text, system_prompt_path, is_new_conversation,
            )
        finally:
            try:
                os.unlink(system_prompt_path)
            except OSError:
                pass

        return self._parse_response(result_json, model)

    # -- System prompt augmentation --

    def _build_augmented_system(
        self, system: str, tools: list[dict] | None,
    ) -> str:
        """Append tool schemas and calling instructions to the system prompt."""
        if not tools:
            return system

        parts = [system, self._TOOL_CALL_INSTRUCTIONS, "\n## Available Tools\n"]

        for tool in tools:
            name = tool.get("name", "unknown")
            desc = tool.get("description", "")
            schema = tool.get("input_schema", {})
            props = schema.get("properties", {})
            required = set(schema.get("required", []))

            parts.append(f"\n### {name}")
            if desc:
                parts.append(desc)

            if props:
                parts.append("\nParameters:")
                for pname, pinfo in props.items():
                    ptype = pinfo.get("type", "string")
                    pdesc = pinfo.get("description", "")
                    req = "required" if pname in required else "optional"
                    line = f"- **{pname}** ({ptype}, {req}): {pdesc}"
                    enum_vals = pinfo.get("enum")
                    if enum_vals:
                        line += f"  [enum: {', '.join(str(v) for v in enum_vals)}]"
                    parts.append(line)
            parts.append("")

        return "\n".join(parts)

    # -- Message formatting --

    def _format_prompt(
        self, messages: list[dict], is_new_conversation: bool,
    ) -> str:
        """Convert the Anthropic-format message list into a text prompt.

        For new conversations: include the full message history.
        For continuations (--resume): only the latest tool results.
        """
        if not messages:
            return ""

        if not is_new_conversation and self._active_session_id:
            # Only send the latest user message (tool results)
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    return self._format_message_content(msg)
            return ""

        # Full history for new conversations
        parts: list[str] = []
        for msg in messages:
            role = msg.get("role", "unknown")
            parts.append(self._format_message_content(msg, role_prefix=role))

        return "\n\n".join(parts)

    def _format_message_content(
        self, msg: dict, role_prefix: str = "",
    ) -> str:
        """Format a single message (user/assistant/tool_result) as text."""
        content = msg.get("content", "")

        # Simple string content
        if isinstance(content, str):
            if role_prefix:
                return f"[{role_prefix.title()}]\n{content}"
            return content

        # List content (Anthropic format)
        if isinstance(content, list):
            parts: list[str] = []
            for block in content:
                if hasattr(block, "type"):
                    # SDK objects (TextBlock, ToolUseBlock)
                    if block.type == "text":
                        parts.append(block.text)
                    elif block.type == "tool_use":
                        parts.append(
                            f'<tool_call name="{block.name}" id="{block.id}">\n'
                            f"{json.dumps(block.input, indent=2)}\n"
                            f"</tool_call>"
                        )
                elif isinstance(block, dict):
                    btype = block.get("type", "")
                    if btype == "text":
                        parts.append(block.get("text", ""))
                    elif btype == "tool_use":
                        parts.append(
                            f'<tool_call name="{block["name"]}" id="{block["id"]}">\n'
                            f'{json.dumps(block.get("input", {}), indent=2)}\n'
                            f"</tool_call>"
                        )
                    elif btype == "tool_result":
                        tool_id = block.get("tool_use_id", "?")
                        result_content = block.get("content", "")
                        is_error = block.get("is_error", False)
                        status = "ERROR" if is_error else "SUCCESS"
                        parts.append(
                            f"[Tool Result ({tool_id}) — {status}]\n{result_content}"
                        )
                    elif btype == "provider_assistant_message":
                        # Skip provider-specific replay blocks
                        continue

            text = "\n\n".join(parts)
            if role_prefix:
                return f"[{role_prefix.title()}]\n{text}"
            return text

        return str(content)

    # -- CLI invocation --

    def _invoke_cli(
        self,
        prompt: str,
        system_prompt_path: str,
        is_new_conversation: bool,
    ) -> dict:
        """Run `claude -p` and return the parsed JSON output."""
        cmd = [
            self._claude_bin, "-p",
            "--output-format", "json",
            "--dangerously-skip-permissions",
            "--system-prompt-file", system_prompt_path,
            "--max-turns", "1",
            "--model", self.model_id,
        ]

        if self._max_budget_usd > 0:
            cmd.extend(["--max-budget-usd", str(self._max_budget_usd)])

        if self._active_session_id and not is_new_conversation:
            cmd.extend(["--resume", self._active_session_id])

        logger.debug(
            "Claude Code CLI invocation: %s (prompt length: %d chars)",
            " ".join(cmd[:6]) + " ...",
            len(prompt),
        )

        # Build a clean environment for the subprocess.
        # Remove ANTHROPIC_API_KEY so the CLI uses its OAuth session
        # (Pro/Max subscription) instead of trying API credit billing.
        env = os.environ.copy()
        env.pop("ANTHROPIC_API_KEY", None)

        try:
            proc = subprocess.run(
                cmd,
                input=prompt,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                env=env,
            )
        except subprocess.TimeoutExpired:
            raise ClaudeCodeError(
                f"Claude Code CLI timed out after {self._timeout}s. "
                f"Increase CLAUDE_CODE_TIMEOUT or reduce task complexity."
            )

        if proc.returncode != 0:
            stderr = proc.stderr.strip()
            stdout_err = proc.stdout.strip()
            # Claude CLI may return error details in JSON on stdout
            error_detail = stderr
            if not error_detail and stdout_err:
                try:
                    err_json = json.loads(stdout_err)
                    if err_json.get("is_error"):
                        error_detail = err_json.get("result", stdout_err[:500])
                    else:
                        error_detail = stdout_err[:500]
                except (json.JSONDecodeError, TypeError):
                    error_detail = stdout_err[:500]
            # Check for common auth issues
            combined = (stderr + " " + stdout_err).lower()
            if "auth" in combined or "login" in combined:
                raise ClaudeCodeError(
                    f"Claude Code CLI auth error: {error_detail}. "
                    f"Run `claude login` to re-authenticate."
                )
            raise ClaudeCodeError(
                f"Claude Code CLI failed (exit {proc.returncode}): {error_detail}"
            )

        stdout = proc.stdout.strip()
        if not stdout:
            raise ClaudeCodeError("Claude Code CLI returned empty output")

        try:
            result = json.loads(stdout)
        except json.JSONDecodeError as e:
            # Sometimes output contains non-JSON preamble; try to find JSON
            json_start = stdout.find("{")
            if json_start > 0:
                try:
                    result = json.loads(stdout[json_start:])
                except json.JSONDecodeError:
                    raise ClaudeCodeError(
                        f"Failed to parse Claude Code CLI output as JSON: {e}\n"
                        f"Raw output (first 500 chars): {stdout[:500]}"
                    )
            else:
                raise ClaudeCodeError(
                    f"Failed to parse Claude Code CLI output as JSON: {e}\n"
                    f"Raw output (first 500 chars): {stdout[:500]}"
                )

        return result

    # -- Response parsing --

    def _parse_response(self, result: dict, model: str) -> UnifiedResponse:
        """Parse CLI JSON output into a UnifiedResponse with text + tool_call blocks."""
        # Store session ID for --resume on next call
        session_id = result.get("session_id")
        if session_id:
            self._active_session_id = session_id

        text = result.get("result", "")
        is_error = result.get("is_error", False)

        if is_error:
            logger.warning("Claude Code CLI returned an error result: %s", text[:200])

        # Extract token usage
        usage = {
            "input_tokens": result.get("input_tokens", 0),
            "output_tokens": result.get("output_tokens", 0),
        }

        # Parse tool_call blocks from the text
        tool_calls = list(self._TOOL_CALL_RE.finditer(text))
        content_blocks: list = []

        if tool_calls:
            # Extract text outside tool_call blocks
            last_end = 0
            for match in tool_calls:
                preceding_text = text[last_end:match.start()].strip()
                if preceding_text:
                    content_blocks.append(TextBlock(text=preceding_text))
                last_end = match.end()

            trailing_text = text[last_end:].strip()
            if trailing_text:
                content_blocks.append(TextBlock(text=trailing_text))

            # Convert tool_call matches to ToolUseBlock objects
            for match in tool_calls:
                name = match.group(1)
                call_id = match.group(2)
                args_str = match.group(3).strip()
                try:
                    args = json.loads(args_str)
                except (json.JSONDecodeError, TypeError):
                    logger.warning(
                        "Failed to parse tool_call args for %s: %s",
                        name, args_str[:100],
                    )
                    args = {}

                content_blocks.append(ToolUseBlock(
                    id=call_id,
                    name=name,
                    input=args,
                ))

            stop_reason = "tool_use"
        else:
            # No tool calls — plain text response
            if text:
                content_blocks.append(TextBlock(text=text))
            stop_reason = "end_turn"

        return UnifiedResponse(
            content=content_blocks,
            stop_reason=stop_reason,
            model=model,
            usage=usage,
        )

    def reset_session(self):
        """Clear the active session, forcing a new conversation on next call."""
        self._active_session_id = None


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_model_client(model_id: str):
    """Return a client (Anthropic, OpenAI-compatible, or Grok) for the given model.

    Returns:
        A client with a `.messages.create(...)` method matching the Anthropic SDK.
    """
    model_info = AVAILABLE_MODELS.get(model_id)
    if not model_info:
        # Fall back to Anthropic for unknown models
        logger.warning("Unknown model '%s', defaulting to Anthropic client", model_id)
        import anthropic
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        return anthropic.Anthropic(api_key=api_key, timeout=120.0)

    provider = model_info["provider"]

    # Claude Code CLI provider — no API key needed (uses OAuth session)
    if provider == "claude_code":
        cli_model = model_info.get("cli_model", "claude-sonnet-4-6")
        max_budget = float(os.environ.get("CLAUDE_CODE_MAX_BUDGET", "5.0"))
        return ClaudeCodeClient(model_id=cli_model, max_budget_usd=max_budget)

    api_key_env = model_info.get("api_key_env", "")
    api_key = os.environ.get(api_key_env, "")

    if not api_key:
        raise ValueError(
            f"API key not set for model '{model_id}'. "
            f"Set the {api_key_env} environment variable."
        )

    if provider == "anthropic":
        import anthropic
        return anthropic.Anthropic(api_key=api_key, timeout=120.0)

    elif provider == "grok":
        return GrokClient(api_key=api_key)

    elif provider == "openai":
        base_url = model_info.get("base_url", "https://api.openai.com/v1")
        return OpenAICompatibleClient(api_key=api_key, base_url=base_url)

    else:
        raise ValueError(f"Unknown provider '{provider}' for model '{model_id}'")


def resolve_model_for_role(role: str, model_config: dict) -> str:
    """Resolve which model ID to use for a given role, given per-engagement config.

    Tier system:
        - "orchestrator" / "planning": Strategic decisions (default: Opus)
        - Agent roles (recon, webapp, attack, etc.): Tool-calling (default: Sonnet)
        - "compaction": Output summarization (default: Kimi K2, fallback Haiku)

    Args:
        role: Agent role key (e.g., "recon", "orchestrator", "compaction").
        model_config: Per-engagement model overrides from the database.

    Returns:
        Model ID string.
    """
    from config import MODELS

    # Check per-engagement override first
    if model_config and role in model_config and model_config[role]:
        return model_config[role]

    # Tier resolution — fallbacks match config.py MODELS defaults
    if role in ("orchestrator", "planning"):
        return MODELS.get("orchestrator", MODELS.get("planning", "claude-opus-4-20250514"))

    if role == "compaction":
        return MODELS.get("compaction", "kimi-k2-0711-preview")

    # All agent roles fall back to the tool_calling tier
    return MODELS.get("tool_calling", "claude-sonnet-4-20250514")
