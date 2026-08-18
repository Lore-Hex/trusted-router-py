"""Sync client facade (L8): endpoint wrappers only.

Every method here selects a plane (inference pool vs a single-entry
control-plane list), assembles per-call inputs, and delegates to the
transport engine. Zero loops, zero sleeps, zero candidate-index
references live in this module.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Any

import httpx

from trustedrouter._collect import _collect_completion, _with_usage
from trustedrouter._constants import (
    AUTO_MODEL,
    DEFAULT_API_BASE_URL,
    DEFAULT_CONTROL_BASE_URL,
    DEFAULT_FUSION_TIMEOUT_SECONDS,
    DEFAULT_REGION_PROBE_TIMEOUT_SECONDS,
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_STATUS_URL,
    DEFAULT_TRUST_RELEASE_URL,
    FUSION_MODEL,
)
from trustedrouter._errors import TrustedRouterError, _json_or_raise
from trustedrouter._orchestration import (
    ProviderPreferences,
    _move_orchestration_options_into_tools,
    fusion_tool,
)
from trustedrouter._requests import (
    _DEFAULT_USER_AGENT,
    _broadcast_destination_body,
    _build_stream_request,
    _credential_free_request,
    _install_reserved_header_hook,
    _models_path,
    _responses_body,
    _strip_reserved_headers,
)
from trustedrouter._retry import RetryController, _new_idempotency_key
from trustedrouter._routing import BaseUrlPool
from trustedrouter._sse import _delta_text, _iter_sse_chunks, _iter_sse_events
from trustedrouter._telemetry import (
    RequestRecorder,
    TelemetryReporter,
    TelemetrySink,
    endpoint_enum,
    resolve_telemetry_enabled,
    sdk_identity,
)
from trustedrouter._transport import request_with_retry, stream_events
from trustedrouter.models import (
    ActivityList,
    AuthSession,
    ChatCompletion,
    ChatCompletionChunk,
    CheckoutSession,
    CreditsBalance,
    EmbeddingResponse,
    LogoutResponse,
    MessagesResponse,
    ModelList,
    ProviderList,
    RegionList,
    ResponseInputTokens,
    ResponseObject,
    TrustRelease,
)


class TrustedRouter:
    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str | None = None,
        control_base_url: str | None = None,
        timeout: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        headers: Mapping[str, str] | None = None,
        workspace_id: str | None = None,
        client: httpx.Client | None = None,
        max_retries: int = 2,
        regional_failover: bool = True,
        telemetry: bool | None = None,
        telemetry_sample_rate: float = 0.01,
        regional_affinity: bool | None = None,
        region_probe_timeout: float = DEFAULT_REGION_PROBE_TIMEOUT_SECONDS,
        _telemetry_sink: TelemetrySink | None = None,
    ) -> None:
        """Sync TrustedRouter client.

        By default, inference calls use the apex `api.trustedrouter.com/v1`.
        Catalog, account, billing, OAuth, and broadcast calls use
        `control_base_url` instead. Pass `base_url=...` for a custom inference
        endpoint, such as a self-hosted gateway.

        `max_retries` controls automatic retry of 429 / 5xx responses
        with exponential backoff + jitter. Set to 0 to disable retries
        entirely (e.g. inside an outer retry loop).

        The default client probes published regional liveness endpoints once,
        pins the lowest-latency healthy region, and retains the other regions
        plus the apex for idempotent failover. Pass a custom `base_url` or set
        `regional_affinity=False` to disable this selection.

        `telemetry` controls content-free client reliability recording and its
        per-attempt header. It defaults off for custom inference or control
        hosts and honors the documented environment opt-out precedence.
        `telemetry_sample_rate` controls random sampling of otherwise healthy,
        fast, first-attempt calls; failures, retries, and slow calls are always
        retained."""
        use_regional_affinity = base_url is None and (
            client is None if regional_affinity is None else regional_affinity
        )
        if base_url is None:
            base_url = DEFAULT_API_BASE_URL
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.control_base_url = (control_base_url or DEFAULT_CONTROL_BASE_URL).rstrip("/")
        self.workspace_id = workspace_id
        self.max_retries = max(0, int(max_retries))
        self._regional_failover = bool(regional_failover)
        self._telemetry_enabled = resolve_telemetry_enabled(
            telemetry,
            base_url=self.base_url,
            control_base_url=self.control_base_url,
            environ=os.environ,
        )
        self._telemetry_sample_rate = telemetry_sample_rate
        self._telemetry_sink = _telemetry_sink
        self._owns_telemetry_reporter = False
        self._telemetry_lock = threading.Lock()
        default_headers = {"user-agent": _DEFAULT_USER_AGENT}
        if headers:
            default_headers.update(headers)
        # Constructor headers apply even when a caller injects a client; keep a
        # request-local copy rather than mutating that caller-owned client's
        # global defaults.
        _strip_reserved_headers(default_headers)
        self._default_headers = dict(default_headers)
        if client is not None:
            # Caller is responsible for the client's lifecycle (timeouts,
            # transport, cert pinning, etc.). close() becomes a no-op.
            self._client = client
            self._owns_client = False
        else:
            self._client = httpx.Client(timeout=timeout, headers=default_headers)
            self._owns_client = True
        # Terminal layer of the x-tr-client reservation: runs after the caller's
        # Auth and request hooks, which are the only writers the per-attempt
        # scrub above cannot see. Marked SDK requests only.
        _install_reserved_header_hook(self._client, is_async=False)
        self._pool = BaseUrlPool(
            lambda: self._client,
            self.base_url,
            affinity_pending=bool(use_regional_affinity and self._regional_failover),
            probe_timeout=max(0.1, float(region_probe_timeout)),
        )

    def close(self) -> None:
        if self._owns_telemetry_reporter and isinstance(self._telemetry_sink, TelemetryReporter):
            self._telemetry_sink.close()
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> TrustedRouter:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ---- plane selection --------------------------------------------------

    def _controller(self, provider: Callable[[], Sequence[str]]) -> RetryController:
        return RetryController(
            provider,
            max_retries=self.max_retries,
            regional_failover=self._regional_failover,
        )

    def _inference_controller(self) -> RetryController:
        return self._controller(self._pool.current)

    def _recorder(
        self,
        *,
        method: str,
        path: str,
        streaming: bool,
        body: Mapping[str, Any] | None,
        timeout: float | httpx.Timeout | None,
    ) -> RequestRecorder | None:
        if not self._telemetry_enabled:
            return None
        if self._telemetry_sink is None:
            with self._telemetry_lock:
                if self._telemetry_sink is None:
                    self._telemetry_sink = TelemetryReporter(
                        control_base_url=self.control_base_url,
                        api_key_provider=lambda: self.api_key,
                        workspace_id=self.workspace_id,
                        sdk_identity=sdk_identity(),
                        success_sample_rate=self._telemetry_sample_rate,
                    )
                    self._owns_telemetry_reporter = True
        provider = body.get("provider") if body is not None else None
        provider_pinned = isinstance(provider, Mapping) and provider.get("allow_fallbacks") is False
        model = body.get("model") if body is not None else None
        return RequestRecorder(
            self._telemetry_sink,
            endpoint=endpoint_enum(path),
            method=method,
            streaming=streaming,
            provider_pinned=provider_pinned,
            model=model if isinstance(model, str) else None,
            configured_timeout=timeout if timeout is not None else self._client.timeout,
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        api_key: str | None = None,
        workspace_id: str | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        _base_url: str | None = None,
    ) -> dict[str, Any]:
        # The generic escape hatch never invents replay semantics.  Typed
        # billed/mutating helpers mint once at their call boundary; generic
        # callers opt in explicitly with idempotency_key=.
        merged_headers = dict(self._default_headers)
        if headers:
            merged_headers.update(headers)
        if idempotency_key:
            merged_headers["idempotency-key"] = idempotency_key
        selected_workspace_id = workspace_id if workspace_id is not None else self.workspace_id
        if selected_workspace_id:
            merged_headers["x-trustedrouter-workspace"] = selected_workspace_id
        selected_api_key = api_key if api_key is not None else self.api_key
        if selected_api_key:
            merged_headers["authorization"] = f"Bearer {selected_api_key}"
        kwargs: dict[str, Any] = {"json": json, "headers": merged_headers}
        if timeout is not None:
            kwargs["timeout"] = timeout
        # Retry 429 + 5xx with exponential backoff + jitter (in the transport
        # engine). Honors Retry-After when present. An explicit _base_url is a
        # single-entry candidate list: failover structurally cannot engage.
        if _base_url is not None:
            fixed = [_base_url.rstrip("/")]

            def provider() -> list[str]:
                return fixed

            controller = self._controller(provider)
        else:
            controller = self._inference_controller()
        recorder = (
            self._recorder(
                method=method,
                path=path,
                streaming=False,
                body=json,
                timeout=timeout,
            )
            if _base_url is None
            else None
        )
        return _json_or_raise(
            request_with_retry(self._client, controller, method, path, kwargs, recorder=recorder)
        )

    def _control_request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        if kwargs.get("idempotency_key") is None and method.upper() not in {
            "GET",
            "HEAD",
            "OPTIONS",
            "TRACE",
        }:
            kwargs["idempotency_key"] = _new_idempotency_key()
        return self.request(method, path, _base_url=self.control_base_url, **kwargs)

    def _merged_headers(self, headers: Mapping[str, str] | None) -> dict[str, str]:
        merged = dict(self._default_headers)
        if headers:
            merged.update(headers)
        return merged

    def _build_chat_request(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None,
        params: Mapping[str, Any],
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        base_url: str | None = None,
    ) -> dict[str, Any]:
        # Pull our reserved kwargs out of `params` so they aren't sent
        # into the JSON body. (Defensive: callers spreading a dict
        # might inadvertently include these.)
        params_dict = dict(params)
        workspace_id = params_dict.pop("workspace_id", None)
        for reserved in ("extra_headers", "idempotency_key", "timeout", "api_key"):
            params_dict.pop(reserved, None)
        params_dict = _move_orchestration_options_into_tools(model, params_dict)
        body = {"model": model, "messages": messages, "stream": True, **params_dict}
        return _build_stream_request(
            "POST",
            f"{(base_url or self.base_url).rstrip('/')}/chat/completions",
            body=body,
            api_key=api_key if api_key is not None else self.api_key,
            extra_headers=self._merged_headers(extra_headers),
            idempotency_key=idempotency_key,
            workspace_id=workspace_id if workspace_id is not None else self.workspace_id,
            timeout=timeout,
        )

    def chat_completions_stream(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> Iterator[str]:
        """Yield assistant-message text deltas as they arrive. The gateway
        streams every response (text/event-stream) regardless of the
        `stream` request param, so this is the lowest-overhead consumer.

        Pass `api_key` to override the instance-level key for this single
        call. Pass `extra_headers`, `idempotency_key`, or `timeout` to
        tune the single request without recreating the client."""
        request_idempotency_key = idempotency_key or _new_idempotency_key()

        def build_request(base_url: str) -> dict[str, Any]:
            return self._build_chat_request(
                model=model,
                messages=messages,
                api_key=api_key,
                params=params,
                extra_headers=extra_headers,
                idempotency_key=request_idempotency_key,
                timeout=timeout,
                base_url=base_url,
            )

        def iter_body(response: httpx.Response) -> Iterator[str]:
            for chunk in _iter_sse_chunks(response):
                txt = _delta_text(chunk)
                if txt:
                    yield txt

        recorder = self._recorder(
            method="POST",
            path="/chat/completions",
            streaming=True,
            body={"model": model, **params},
            timeout=timeout,
        )
        yield from stream_events(
            self._client,
            self._inference_controller(),
            build_request,
            iter_body,
            recorder=recorder,
        )

    def chat_completions_chunk_stream(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> Iterator[ChatCompletionChunk]:
        """Yield parsed OpenAI chat.completion.chunk frames as typed
        ChatCompletionChunk models. Use this when you need access to
        fields beyond the text delta (e.g. `finish_reason`, `model`,
        `id`) — for instance when translating to a different SSE shape."""
        request_idempotency_key = idempotency_key or _new_idempotency_key()

        def build_request(base_url: str) -> dict[str, Any]:
            return self._build_chat_request(
                model=model,
                messages=messages,
                api_key=api_key,
                params=params,
                extra_headers=extra_headers,
                idempotency_key=request_idempotency_key,
                timeout=timeout,
                base_url=base_url,
            )

        def iter_body(response: httpx.Response) -> Iterator[ChatCompletionChunk]:
            for chunk in _iter_sse_chunks(response):
                yield ChatCompletionChunk.model_validate(chunk)

        recorder = self._recorder(
            method="POST",
            path="/chat/completions",
            streaming=True,
            body={"model": model, **params},
            timeout=timeout,
        )
        yield from stream_events(
            self._client,
            self._inference_controller(),
            build_request,
            iter_body,
            recorder=recorder,
        )

    def chat_completions(
        self,
        *,
        model: str = AUTO_MODEL,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> ChatCompletion:
        """Collect the streamed response into a single typed
        ChatCompletion. Use chat_completions_stream() if you want to
        stream tokens to the user instead."""
        request_idempotency_key = idempotency_key or _new_idempotency_key()
        params = _with_usage(params)

        def build_request(base_url: str) -> dict[str, Any]:
            return self._build_chat_request(
                model=model,
                messages=messages,
                api_key=api_key,
                params=params,
                extra_headers=extra_headers,
                idempotency_key=request_idempotency_key,
                timeout=timeout,
                base_url=base_url,
            )

        recorder = self._recorder(
            method="POST",
            path="/chat/completions",
            streaming=True,
            body={"model": model, **params},
            timeout=timeout,
        )
        chunks = list(
            stream_events(
                self._client,
                self._inference_controller(),
                build_request,
                _iter_sse_chunks,
                recorder=recorder,
            )
        )
        return ChatCompletion.model_validate(_collect_completion(chunks))

    def fusion(
        self,
        *,
        messages: list[Mapping[str, Any]],
        analysis_models: Sequence[str] | None = None,
        model: str | None = None,  # judge / synthesis model
        selection_strategy: str | None = None,
        fallback_judges: Sequence[str] | None = None,
        fallback_final_models: Sequence[str] | None = None,
        max_completion_tokens: int | None = None,
        max_tool_calls: int | None = None,
        preset: str | None = None,
        **params: Any,
    ) -> ChatCompletion:
        """Run a request through TrustedRouter Fusion: fan it across a panel and
        return one answer chosen/synthesized by a judge model. Returns a typed
        ChatCompletion, same as chat_completions. Pass ``fallback_judges`` so a
        single squeamish judge can't sink a prompt."""
        params.setdefault("timeout", DEFAULT_FUSION_TIMEOUT_SECONDS)
        tools = list(params.pop("tools", []))
        tools.append(
            fusion_tool(
                analysis_models=analysis_models,
                model=model,
                selection_strategy=selection_strategy,
                fallback_judges=fallback_judges,
                fallback_final_models=fallback_final_models,
                max_completion_tokens=max_completion_tokens,
                max_tool_calls=max_tool_calls,
                preset=preset,
            )
        )
        return self.chat_completions(model=FUSION_MODEL, messages=messages, tools=tools, **params)

    def models(
        self,
        *,
        open_weights: bool | None = None,
        provider_jurisdiction: str | None = None,
        provider_region: str | None = None,
    ) -> ModelList:
        return ModelList.model_validate(
            self._control_request(
                "GET",
                _models_path(
                    open_weights=open_weights,
                    provider_jurisdiction=provider_jurisdiction,
                    provider_region=provider_region,
                ),
            )
        )

    def providers(self) -> ProviderList:
        return ProviderList.model_validate(self._control_request("GET", "/providers"))

    def regions(self) -> RegionList:
        return RegionList.model_validate(self._control_request("GET", "/regions"))

    def credits(self, *, workspace_id: str | None = None) -> CreditsBalance:
        return CreditsBalance.model_validate(
            self._control_request("GET", "/credits", workspace_id=workspace_id)
        )

    def embeddings(
        self,
        *,
        model: str,
        input: str | list[str] | list[int] | list[list[int]],
        encoding_format: str | None = None,
        dimensions: int | None = None,
        user: str | None = None,
        session_id: str | None = None,
        trace: Mapping[str, Any] | None = None,
        tags: Mapping[str, str] | None = None,
        provider: ProviderPreferences | Mapping[str, Any] | None = None,
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        workspace_id: str | None = None,
        timeout: float | httpx.Timeout | None = None,
    ) -> EmbeddingResponse:
        """OpenAI-compatible embeddings wrapper.

        The hosted TrustedRouter API currently returns a stable
        EndpointNotSupportedError for this route instead of fake vectors.
        The wrapper remains so self-hosted deployments and future hosted
        releases have a typed call site.
        """
        body: dict[str, Any] = {"model": model, "input": input}
        if encoding_format is not None:
            body["encoding_format"] = encoding_format
        if dimensions is not None:
            body["dimensions"] = dimensions
        if user is not None:
            body["user"] = user
        if session_id is not None:
            body["session_id"] = session_id
        if trace is not None:
            body["trace"] = dict(trace)
        if tags is not None:
            body["tags"] = dict(tags)
        if provider is not None:
            body["provider"] = dict(provider)
        return EmbeddingResponse.model_validate(
            self.request(
                "POST",
                "/embeddings",
                json=body,
                headers=extra_headers,
                api_key=api_key,
                workspace_id=workspace_id,
                idempotency_key=idempotency_key or _new_idempotency_key(),
                timeout=timeout,
            )
        )

    def messages(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        max_tokens: int = 1024,
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        workspace_id: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> MessagesResponse:
        """Anthropic-shape Messages endpoint. For providers that expose
        the native Anthropic API (rather than translating to/from
        OpenAI shape), this preserves system prompts, content blocks,
        and tool_use semantics that the OpenAI shape can't carry."""
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            **params,
        }
        return MessagesResponse.model_validate(
            self.request(
                "POST",
                "/messages",
                json=body,
                headers=extra_headers,
                api_key=api_key,
                workspace_id=workspace_id,
                idempotency_key=idempotency_key or _new_idempotency_key(),
                timeout=timeout,
            )
        )

    def responses(
        self,
        *,
        model: str = AUTO_MODEL,
        input: str | list[Mapping[str, Any]],
        instructions: str | None = None,
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        workspace_id: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> ResponseObject:
        """Create a stateless OpenAI Responses API request."""
        request_idempotency_key = idempotency_key or _new_idempotency_key()
        body = _responses_body(
            model=model,
            input=input,
            instructions=instructions,
            stream=False,
            params=params,
        )
        return ResponseObject.model_validate(
            self.request(
                "POST",
                "/responses",
                json=body,
                headers=extra_headers,
                api_key=api_key,
                workspace_id=workspace_id,
                idempotency_key=request_idempotency_key,
                timeout=timeout,
            )
        )

    def _responses_stream_request_builder(
        self,
        *,
        body: Mapping[str, Any],
        api_key: str | None,
        extra_headers: Mapping[str, str] | None,
        idempotency_key: str | None,
        workspace_id: str | None,
        timeout: float | httpx.Timeout | None,
    ) -> Callable[[str], dict[str, Any]]:
        def build_request(base_url: str) -> dict[str, Any]:
            return _build_stream_request(
                "POST",
                f"{base_url}/responses",
                body=body,
                api_key=api_key if api_key is not None else self.api_key,
                extra_headers=self._merged_headers(extra_headers),
                idempotency_key=idempotency_key,
                workspace_id=workspace_id if workspace_id is not None else self.workspace_id,
                timeout=timeout,
            )

        return build_request

    def responses_stream(
        self,
        *,
        model: str = AUTO_MODEL,
        input: str | list[Mapping[str, Any]],
        instructions: str | None = None,
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        workspace_id: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> Iterator[dict[str, Any]]:
        """Yield parsed Responses SSE events as dictionaries."""
        request_idempotency_key = idempotency_key or _new_idempotency_key()
        body = _responses_body(
            model=model,
            input=input,
            instructions=instructions,
            stream=True,
            params=params,
        )
        build_request = self._responses_stream_request_builder(
            body=body,
            api_key=api_key,
            extra_headers=extra_headers,
            idempotency_key=request_idempotency_key,
            workspace_id=workspace_id,
            timeout=timeout,
        )
        recorder = self._recorder(
            method="POST",
            path="/responses",
            streaming=True,
            body=body,
            timeout=timeout,
        )
        yield from stream_events(
            self._client,
            self._inference_controller(),
            build_request,
            _iter_sse_events,
            recorder=recorder,
        )

    def responses_raw_stream(
        self,
        *,
        model: str = AUTO_MODEL,
        input: str | list[Mapping[str, Any]],
        instructions: str | None = None,
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        workspace_id: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> Iterator[bytes]:
        request_idempotency_key = idempotency_key or _new_idempotency_key()
        body = _responses_body(
            model=model,
            input=input,
            instructions=instructions,
            stream=True,
            params=params,
        )
        build_request = self._responses_stream_request_builder(
            body=body,
            api_key=api_key,
            extra_headers=extra_headers,
            idempotency_key=request_idempotency_key,
            workspace_id=workspace_id,
            timeout=timeout,
        )

        def iter_body(response: httpx.Response) -> Iterator[bytes]:
            yield from response.iter_bytes()

        recorder = self._recorder(
            method="POST",
            path="/responses",
            streaming=True,
            body=body,
            timeout=timeout,
        )
        yield from stream_events(
            self._client,
            self._inference_controller(),
            build_request,
            iter_body,
            recorder=recorder,
        )

    def responses_input_tokens(
        self,
        *,
        model: str = AUTO_MODEL,
        input: str | list[Mapping[str, Any]],
        instructions: str | None = None,
        workspace_id: str | None = None,
        idempotency_key: str | None = None,
        **params: Any,
    ) -> ResponseInputTokens:
        body = _responses_body(
            model=model,
            input=input,
            instructions=instructions,
            stream=False,
            params=params,
        )
        return ResponseInputTokens.model_validate(
            self.request(
                "POST",
                "/responses/input_tokens",
                json=body,
                workspace_id=workspace_id,
                idempotency_key=idempotency_key or _new_idempotency_key(),
            )
        )

    def billing_checkout(
        self,
        *,
        amount: int | str,
        payment_method: str | None = None,
        workspace_id: str | None = None,
        success_url: str | None = None,
        cancel_url: str | None = None,
        idempotency_key: str | None = None,
    ) -> CheckoutSession:
        """Create a Stripe checkout session. Pass `idempotency_key=` to
        guarantee at-most-once charge semantics across network retries
        — strongly recommended for production."""
        body: dict[str, Any] = {"amount": amount}
        if payment_method is not None:
            body["payment_method"] = payment_method
        if workspace_id is not None:
            body["workspace_id"] = workspace_id
        if success_url is not None:
            body["success_url"] = success_url
        if cancel_url is not None:
            body["cancel_url"] = cancel_url
        return CheckoutSession.model_validate(
            self._control_request(
                "POST",
                "/billing/checkout",
                json=body,
                workspace_id=workspace_id,
                idempotency_key=idempotency_key,
            )
        )

    def stablecoin_checkout(self, *, amount: int | str, **params: Any) -> CheckoutSession:
        return self.billing_checkout(amount=amount, payment_method="stablecoin", **params)

    def auth_session(self) -> AuthSession:
        return AuthSession.model_validate(self._control_request("GET", "/auth/session"))

    def logout(self) -> LogoutResponse:
        return LogoutResponse.model_validate(self._control_request("POST", "/auth/logout"))

    def activity(self, **params: Any) -> ActivityList:
        """List recent generations for the authenticated key/workspace.
        Pass any subset of {since, until, limit, model, workspace_id};
        None values are dropped from the query string."""
        query = httpx.QueryParams({k: v for k, v in params.items() if v is not None})
        suffix = f"?{query}" if query else ""
        return ActivityList.model_validate(self._control_request("GET", f"/activity{suffix}"))

    def broadcast_destinations(self, *, workspace_id: str | None = None) -> dict[str, Any]:
        return self._control_request("GET", "/broadcast/destinations", workspace_id=workspace_id)

    def create_broadcast_destination(
        self,
        *,
        type: str,
        name: str = "Broadcast destination",
        endpoint: str | None = None,
        enabled: bool = True,
        include_content: bool = False,
        method: str = "POST",
        headers: Mapping[str, str] | None = None,
        api_key: str | None = None,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        body = _broadcast_destination_body(
            type=type,
            name=name,
            endpoint=endpoint,
            enabled=enabled,
            include_content=include_content,
            method=method,
            headers=headers,
            api_key=api_key,
        )
        return self._control_request(
            "POST", "/broadcast/destinations", json=body, workspace_id=workspace_id
        )

    def get_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        return self._control_request(
            "GET",
            f"/broadcast/destinations/{destination_id}",
            workspace_id=workspace_id,
        )

    def update_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
        **patch: Any,
    ) -> dict[str, Any]:
        return self._control_request(
            "PATCH",
            f"/broadcast/destinations/{destination_id}",
            json={key: value for key, value in patch.items() if value is not None},
            workspace_id=workspace_id,
        )

    def delete_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        return self._control_request(
            "DELETE",
            f"/broadcast/destinations/{destination_id}",
            workspace_id=workspace_id,
        )

    def test_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        return self._control_request(
            "POST",
            f"/broadcast/destinations/{destination_id}/test",
            workspace_id=workspace_id,
        )

    def status(self, url: str = DEFAULT_STATUS_URL) -> dict[str, Any]:
        response = _credential_free_request(self._client, "GET", url)
        return _json_or_raise(response)

    def attestation(self) -> bytes:
        """Fetch the gateway's live attestation document. Returns the raw
        JWT bytes (Confidential Space mints an OIDC JWT). Pass to
        `trustedrouter.attestation.verify_gateway_attestation` to verify."""
        # /attestation lives at the API root, not under /v1
        url = self.base_url.rsplit("/v1", 1)[0] + "/attestation"
        response = _credential_free_request(self._client, "GET", url)
        if not response.is_success:
            raise TrustedRouterError(response.status_code, response.text[:240])
        return response.content

    def trust_release(self, url: str = DEFAULT_TRUST_RELEASE_URL) -> TrustRelease:
        response = _credential_free_request(self._client, "GET", url)
        return TrustRelease.model_validate(_json_or_raise(response))


def fetch_trust_release(
    url: str = DEFAULT_TRUST_RELEASE_URL,
    *,
    timeout: float = 30.0,
) -> TrustRelease:
    """Fetch and parse the public trust release. Returns a typed
    `TrustRelease` model (use `.model_dump()` if you need a dict)."""
    with httpx.Client(timeout=timeout) as client:
        return TrustRelease.model_validate(
            _json_or_raise(_credential_free_request(client, "GET", url))
        )
