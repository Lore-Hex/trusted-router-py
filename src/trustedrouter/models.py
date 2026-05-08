"""Typed response models for TrustedRouter.

Every method on `TrustedRouter` and `AsyncTrustedRouter` returns one of
these instead of `dict[str, Any]`. The models are pydantic v2 BaseModels
configured with `model_config = ConfigDict(extra="allow")` so they
forward-compat: the gateway can add new fields and the SDK won't reject
the response, but anything we KNOW about gets typed access + validation.

Typed access pattern (the new way):
    resp = client.chat_completions(messages=[...])
    print(resp.choices[0].message.content)
    print(resp.usage.total_tokens)

Dict access pattern (callers migrating from v0.2):
    resp_dict = resp.model_dump()
    print(resp_dict["choices"][0]["message"]["content"])

We intentionally don't ship dict-like __getitem__ shims — pydantic models
support `.model_dump()` for one-line conversion, and exposing both shapes
makes it tempting to mix them. The README explains the migration path.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# ---- common config ------------------------------------------------------


class _Base(BaseModel):
    """Forward-compatible base: extra fields the gateway might add are
    preserved on `model_dump()` but don't fail validation. Lets us ship
    new gateway fields without an SDK release."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)


# ---- chat completions ---------------------------------------------------


class ChatMessage(_Base):
    role: str
    content: str | None = None
    name: str | None = None
    tool_calls: list[dict[str, Any]] | None = None
    tool_call_id: str | None = None


class ChatChoice(_Base):
    index: int = 0
    message: ChatMessage
    finish_reason: str | None = None
    logprobs: dict[str, Any] | None = None


class ChatUsage(_Base):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ChatCompletion(_Base):
    """OpenAI-shape `chat.completion`. Returned by the non-streaming
    `chat_completions(...)` method (which collects the SSE stream into
    a single result)."""

    id: str = ""
    object: Literal["chat.completion"] = "chat.completion"
    created: int = 0
    model: str = ""
    choices: list[ChatChoice] = Field(default_factory=list)
    usage: ChatUsage | None = None


class ChatChoiceDelta(_Base):
    role: str | None = None
    content: str | None = None
    tool_calls: list[dict[str, Any]] | None = None


class ChatChoiceChunk(_Base):
    index: int = 0
    delta: ChatChoiceDelta = Field(default_factory=ChatChoiceDelta)
    finish_reason: str | None = None


class ChatCompletionChunk(_Base):
    """One SSE frame yielded by `chat_completions_chunk_stream(...)`.
    The streaming text-only helper `chat_completions_stream(...)` yields
    `str` directly so we don't need to expose this for the simple path."""

    id: str = ""
    object: Literal["chat.completion.chunk"] = "chat.completion.chunk"
    created: int = 0
    model: str = ""
    choices: list[ChatChoiceChunk] = Field(default_factory=list)


# ---- catalog (models, providers, regions) -------------------------------


class ModelPricing(_Base):
    prompt: str | None = None
    completion: str | None = None
    prompt_max: str | None = None       # set on `trustedrouter/auto`
    completion_max: str | None = None   # set on `trustedrouter/auto`


class ModelArchitecture(_Base):
    modality: str = "text->text"
    tokenizer: str = "unknown"
    instruct_type: str | None = None


class ModelTopProvider(_Base):
    context_length: int | None = None
    max_completion_tokens: int | None = None
    is_moderated: bool = False


class ModelInfo(_Base):
    """One row of `client.models()`. Mirrors the OpenRouter shape that
    TR emits — same field names so existing OpenRouter-aware tools work
    unchanged."""

    id: str
    name: str = ""
    created: int = 0
    description: str = ""
    context_length: int | None = None
    architecture: ModelArchitecture = Field(default_factory=ModelArchitecture)
    pricing: ModelPricing = Field(default_factory=ModelPricing)
    top_provider: ModelTopProvider = Field(default_factory=ModelTopProvider)
    per_request_limits: dict[str, Any] | None = None
    trustedrouter: dict[str, Any] | None = None  # TR-specific extension block


class ModelList(_Base):
    """Container for `client.models()`. Iterate `.data` to walk the
    catalog; index by id with `.by_id(...)`."""

    data: list[ModelInfo] = Field(default_factory=list)

    def by_id(self, model_id: str) -> ModelInfo | None:
        return next((m for m in self.data if m.id == model_id), None)


class ProviderInfo(_Base):
    id: str
    name: str = ""


class ProviderList(_Base):
    data: list[ProviderInfo] = Field(default_factory=list)


class RegionInfo(_Base):
    id: str


class RegionList(_Base):
    data: list[RegionInfo] = Field(default_factory=list)


# ---- credits + activity --------------------------------------------------


class CreditsBalance(_Base):
    """Returned by `client.credits()`. Field set follows the gateway's
    public shape — exposed verbatim so users can add prepaid/charged
    breakouts as the gateway extends them. `data` is typed Any because
    the gateway uses both a dict (balance fields) and a list shape
    (per-workspace breakout) depending on context."""

    data: Any = Field(default_factory=dict)


class ActivityEvent(_Base):
    """One row of activity. Gateway adds fields over time — `extra=allow`
    keeps them readable on `.model_dump()`."""

    id: str | None = None
    created: int | None = None
    model: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


class ActivityList(_Base):
    data: list[ActivityEvent] = Field(default_factory=list)


# ---- embeddings ---------------------------------------------------------


class Embedding(_Base):
    object: Literal["embedding"] = "embedding"
    index: int = 0
    embedding: list[float] | str = Field(default_factory=list)  # str = base64 form


class EmbeddingResponse(_Base):
    object: Literal["list"] = "list"
    data: list[Embedding] = Field(default_factory=list)
    model: str = ""
    usage: ChatUsage | None = None


# ---- messages (Anthropic shape) -----------------------------------------


class MessageContentBlock(_Base):
    type: str
    text: str | None = None


class MessagesUsage(_Base):
    input_tokens: int = 0
    output_tokens: int = 0


class MessagesResponse(_Base):
    """Anthropic-shape Messages response. Different shape from the
    OpenAI `chat.completion` envelope — `content` is a list of typed
    blocks (text, tool_use, etc.) rather than a single string."""

    id: str = ""
    type: Literal["message"] = "message"
    role: Literal["assistant"] = "assistant"
    model: str = ""
    content: list[MessageContentBlock] = Field(default_factory=list)
    stop_reason: str | None = None
    stop_sequence: str | None = None
    usage: MessagesUsage | None = None


# ---- responses ----------------------------------------------------------


class ResponseUsage(_Base):
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0


class ResponseContentPart(_Base):
    type: str
    text: str | None = None
    annotations: list[dict[str, Any]] | None = None


class ResponseOutputItem(_Base):
    id: str | None = None
    type: str
    role: str | None = None
    content: list[ResponseContentPart] = Field(default_factory=list)
    status: str | None = None


class ResponseObject(_Base):
    """OpenAI Responses API object returned by `client.responses(...)`.

    The SDK keeps this forward-compatible because the full Responses
    surface adds item types over time (reasoning, tool calls, refusals,
    annotations). Unknown fields are preserved on model_dump().
    """

    id: str = ""
    object: Literal["response"] = "response"
    created_at: int = 0
    status: str = ""
    model: str | None = None
    output: list[ResponseOutputItem] = Field(default_factory=list)
    usage: ResponseUsage | None = None


class ResponseInputTokens(_Base):
    input_tokens: int = 0
    total_tokens: int | None = None


# ---- billing + auth ------------------------------------------------------


class CheckoutSession(_Base):
    """Returned by `client.billing_checkout()` / `stablecoin_checkout()`.
    The gateway's response wraps the Stripe session in `data` — we
    expose both so callers can use whichever level of indirection they
    prefer."""

    data: dict[str, Any] = Field(default_factory=dict)


class AuthSession(_Base):
    data: dict[str, Any] = Field(default_factory=dict)


class LogoutResponse(_Base):
    data: dict[str, Any] = Field(default_factory=dict)


# ---- trust release -------------------------------------------------------


class TrustReleaseTLS(_Base):
    mode: str | None = None
    hostname: str | None = None


class TrustReleaseDataPolicy(_Base):
    prompt_output_storage: bool = False
    control_plane_prompt_access: bool = False


class TrustRelease(_Base):
    """Parsed `trust.trustedrouter.com/trust/gcp-release.json`. Returned
    by `fetch_trust_release()` and `client.trust_release()`."""

    platform: str | None = None
    source_repo: str | None = None
    source_repositories: dict[str, str] | None = None
    source_commit: str | None = None
    image_reference: str | None = None
    image_digest: str | None = None
    attestation_issuer: str | None = None
    attestation_audience: str | None = None
    api_base_url: str | None = None
    tls: TrustReleaseTLS | None = None
    data_policy: TrustReleaseDataPolicy | None = None


__all__ = [
    "ActivityEvent",
    "ActivityList",
    "AuthSession",
    "ChatChoice",
    "ChatChoiceChunk",
    "ChatChoiceDelta",
    "ChatCompletion",
    "ChatCompletionChunk",
    "ChatMessage",
    "ChatUsage",
    "CheckoutSession",
    "CreditsBalance",
    "Embedding",
    "EmbeddingResponse",
    "LogoutResponse",
    "MessageContentBlock",
    "MessagesResponse",
    "MessagesUsage",
    "ModelArchitecture",
    "ModelInfo",
    "ModelList",
    "ModelPricing",
    "ModelTopProvider",
    "ProviderInfo",
    "ProviderList",
    "RegionInfo",
    "RegionList",
    "ResponseContentPart",
    "ResponseInputTokens",
    "ResponseObject",
    "ResponseOutputItem",
    "ResponseUsage",
    "TrustRelease",
    "TrustReleaseDataPolicy",
    "TrustReleaseTLS",
]
