"""Async client facade (L8): endpoint wrappers only, no policy.

Same surface as the sync facade with coroutines/async iterators; delegates
to the async transport drivers. Zero loops, zero sleeps, zero
candidate-index references live in this module.
"""

from __future__ import annotations

import os
import threading
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
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
    _acredential_free_request,
    _broadcast_destination_body,
    _build_stream_request,
    _install_reserved_header_hook,
    _models_path,
    _responses_body,
    _strip_reserved_headers,
)
from trustedrouter._retry import RetryController, _new_idempotency_key
from trustedrouter._routing import AsyncBaseUrlPool
from trustedrouter._sse import _aiter_sse_chunks, _aiter_sse_events, _delta_text
from trustedrouter._telemetry import (
    RequestRecorder,
    TelemetryReporter,
    TelemetrySink,
    endpoint_enum,
    resolve_telemetry_enabled,
    sdk_identity,
)
from trustedrouter._transport import arequest_with_retry, astream_events
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
)


class AsyncTrustedRouter:
    """Async variant. Same surface as TrustedRouter but every method is a
    coroutine, and the streaming helpers return AsyncIterators. Used by
    asyncio servers (e.g. the Pi's quill-device FastAPI app) so they
    don't block the event loop on a streaming generation call."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str | None = None,
        control_base_url: str | None = None,
        timeout: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        headers: Mapping[str, str] | None = None,
        verify: bool | str = True,
        workspace_id: str | None = None,
        client: httpx.AsyncClient | None = None,
        max_retries: int = 2,
        regional_failover: bool = True,
        telemetry: bool | None = None,
        telemetry_sample_rate: float = 0.01,
        regional_affinity: bool | None = None,
        region_probe_timeout: float = DEFAULT_REGION_PROBE_TIMEOUT_SECONDS,
        _telemetry_sink: TelemetrySink | None = None,
    ) -> None:
        """Async TrustedRouter client.

        The default client probes regional liveness endpoints once and stays
        pinned to the fastest healthy region. Custom `base_url` clients are
        never probed or rewritten. `telemetry` controls content-free client
        reliability recording and its per-attempt header, with custom hosts
        defaulting off and the documented environment opt-outs honored.
        `telemetry_sample_rate` controls random sampling of otherwise healthy,
        fast, first-attempt calls; failures, retries, and slow calls are always
        retained.
        """
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
        # Preserve constructor headers for SDK requests without mutating an
        # injected caller-owned client's global defaults.
        _strip_reserved_headers(default_headers)
        self._default_headers = dict(default_headers)
        if client is not None:
            # Caller is responsible for the client's lifecycle (timeouts,
            # transport, verify, event hooks for cert pinning, etc.).
            # aclose() becomes a no-op.
            self._client = client
            self._owns_client = False
        else:
            self._client = httpx.AsyncClient(
                timeout=timeout, headers=default_headers, verify=verify
            )
            self._owns_client = True
        # Terminal layer of the x-tr-client reservation: runs after the caller's
        # Auth and request hooks, which are the only writers the per-attempt
        # scrub above cannot see. Marked SDK requests only.
        _install_reserved_header_hook(self._client, is_async=True)
        self._pool = AsyncBaseUrlPool(
            lambda: self._client,
            self.base_url,
            affinity_pending=bool(use_regional_affinity and self._regional_failover),
            probe_timeout=max(0.1, float(region_probe_timeout)),
        )

    async def aclose(self) -> None:
        if self._owns_telemetry_reporter and isinstance(self._telemetry_sink, TelemetryReporter):
            self._telemetry_sink.close()
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> AsyncTrustedRouter:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    # ---- plane selection --------------------------------------------------

    def _controller(self, provider: Callable[[], Sequence[str]]) -> RetryController:
        return RetryController(
            provider,
            max_retries=self.max_retries,
            regional_failover=self._regional_failover,
        )

    async def _inference_controller(self) -> RetryController:
        # Resolve the pool (lazy affinity probe + swapped-client detection)
        # once per logical call; the sans-IO controller then re-reads the
        # settled snapshot per attempt.
        await self._pool.current()
        return self._controller(self._pool.snapshot)

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

    async def request(
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
        if _base_url is not None:
            fixed = [_base_url.rstrip("/")]

            def provider() -> list[str]:
                return fixed

            controller = self._controller(provider)
        else:
            controller = await self._inference_controller()
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
            await arequest_with_retry(
                self._client, controller, method, path, kwargs, recorder=recorder
            )
        )

    async def _control_request(
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
        return await self.request(method, path, _base_url=self.control_base_url, **kwargs)

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

    def _chat_request_builder(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None,
        params: Mapping[str, Any],
        extra_headers: Mapping[str, str] | None,
        idempotency_key: str | None,
        timeout: float | httpx.Timeout | None,
    ) -> Callable[[str], dict[str, Any]]:
        def build_request(base_url: str) -> dict[str, Any]:
            return self._build_chat_request(
                model=model,
                messages=messages,
                api_key=api_key,
                params=params,
                extra_headers=extra_headers,
                idempotency_key=idempotency_key,
                timeout=timeout,
                base_url=base_url,
            )

        return build_request

    async def chat_completions_stream(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> AsyncIterator[str]:
        """Yield assistant-message text deltas as they arrive. Pass
        `api_key` to override the instance key for this single call."""
        request_idempotency_key = idempotency_key or _new_idempotency_key()
        build_request = self._chat_request_builder(
            model=model,
            messages=messages,
            api_key=api_key,
            params=params,
            extra_headers=extra_headers,
            idempotency_key=request_idempotency_key,
            timeout=timeout,
        )

        def iter_body(response: httpx.Response) -> AsyncIterator[str]:
            async def gen() -> AsyncIterator[str]:
                async for chunk in _aiter_sse_chunks(response):
                    txt = _delta_text(chunk)
                    if txt:
                        yield txt

            return gen()

        controller = await self._inference_controller()
        recorder = self._recorder(
            method="POST",
            path="/chat/completions",
            streaming=True,
            body={"model": model, **params},
            timeout=timeout,
        )
        async for item in astream_events(
            self._client, controller, build_request, iter_body, recorder=recorder
        ):
            yield item

    async def chat_completions_chunk_stream(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> AsyncIterator[ChatCompletionChunk]:
        """Yield parsed OpenAI chat.completion.chunk frames as typed
        ChatCompletionChunk models."""
        request_idempotency_key = idempotency_key or _new_idempotency_key()
        build_request = self._chat_request_builder(
            model=model,
            messages=messages,
            api_key=api_key,
            params=params,
            extra_headers=extra_headers,
            idempotency_key=request_idempotency_key,
            timeout=timeout,
        )

        def iter_body(response: httpx.Response) -> AsyncIterator[ChatCompletionChunk]:
            async def gen() -> AsyncIterator[ChatCompletionChunk]:
                async for chunk in _aiter_sse_chunks(response):
                    yield ChatCompletionChunk.model_validate(chunk)

            return gen()

        controller = await self._inference_controller()
        recorder = self._recorder(
            method="POST",
            path="/chat/completions",
            streaming=True,
            body={"model": model, **params},
            timeout=timeout,
        )
        async for item in astream_events(
            self._client, controller, build_request, iter_body, recorder=recorder
        ):
            yield item

    async def chat_completions_raw_stream(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> AsyncIterator[bytes]:
        """Pass-through SSE bytes. For relays that need to forward the
        raw `data: {...}\\n\\n` framing without decoding (e.g. an HTTP
        proxy in front of the gateway)."""
        request_idempotency_key = idempotency_key or _new_idempotency_key()
        build_request = self._chat_request_builder(
            model=model,
            messages=messages,
            api_key=api_key,
            params=params,
            extra_headers=extra_headers,
            idempotency_key=request_idempotency_key,
            timeout=timeout,
        )

        def iter_body(response: httpx.Response) -> AsyncIterator[bytes]:
            return response.aiter_bytes()

        controller = await self._inference_controller()
        recorder = self._recorder(
            method="POST",
            path="/chat/completions",
            streaming=True,
            body={"model": model, **params},
            timeout=timeout,
        )
        async for item in astream_events(
            self._client, controller, build_request, iter_body, recorder=recorder
        ):
            yield item

    async def chat_completions(
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
        request_idempotency_key = idempotency_key or _new_idempotency_key()
        params = _with_usage(params)
        build_request = self._chat_request_builder(
            model=model,
            messages=messages,
            api_key=api_key,
            params=params,
            extra_headers=extra_headers,
            idempotency_key=request_idempotency_key,
            timeout=timeout,
        )

        def iter_body(response: httpx.Response) -> AsyncIterator[dict[str, Any]]:
            return _aiter_sse_chunks(response)

        controller = await self._inference_controller()
        recorder = self._recorder(
            method="POST",
            path="/chat/completions",
            streaming=True,
            body={"model": model, **params},
            timeout=timeout,
        )
        chunks = [
            chunk
            async for chunk in astream_events(
                self._client, controller, build_request, iter_body, recorder=recorder
            )
        ]
        return ChatCompletion.model_validate(_collect_completion(chunks))

    async def fusion(
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
        """Async TrustedRouter Fusion — mirror of TrustedRouter.fusion."""
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
        return await self.chat_completions(
            model=FUSION_MODEL, messages=messages, tools=tools, **params
        )

    async def models(
        self,
        *,
        open_weights: bool | None = None,
        provider_jurisdiction: str | None = None,
        provider_region: str | None = None,
    ) -> ModelList:
        return ModelList.model_validate(
            await self._control_request(
                "GET",
                _models_path(
                    open_weights=open_weights,
                    provider_jurisdiction=provider_jurisdiction,
                    provider_region=provider_region,
                ),
            )
        )

    async def providers(self) -> ProviderList:
        return ProviderList.model_validate(await self._control_request("GET", "/providers"))

    async def regions(self) -> RegionList:
        return RegionList.model_validate(await self._control_request("GET", "/regions"))

    async def credits(self, *, workspace_id: str | None = None) -> CreditsBalance:
        return CreditsBalance.model_validate(
            await self._control_request("GET", "/credits", workspace_id=workspace_id)
        )

    async def embeddings(
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
            await self.request(
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

    async def messages(
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
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            **params,
        }
        return MessagesResponse.model_validate(
            await self.request(
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

    async def responses(
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
        request_idempotency_key = idempotency_key or _new_idempotency_key()
        body = _responses_body(
            model=model,
            input=input,
            instructions=instructions,
            stream=False,
            params=params,
        )
        return ResponseObject.model_validate(
            await self.request(
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

    async def responses_stream(
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
    ) -> AsyncIterator[dict[str, Any]]:
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
        controller = await self._inference_controller()
        recorder = self._recorder(
            method="POST",
            path="/responses",
            streaming=True,
            body=body,
            timeout=timeout,
        )
        async for event in astream_events(
            self._client,
            controller,
            build_request,
            _aiter_sse_events,
            recorder=recorder,
        ):
            yield event

    async def responses_raw_stream(
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
    ) -> AsyncIterator[bytes]:
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

        def iter_body(response: httpx.Response) -> AsyncIterator[bytes]:
            return response.aiter_bytes()

        controller = await self._inference_controller()
        recorder = self._recorder(
            method="POST",
            path="/responses",
            streaming=True,
            body=body,
            timeout=timeout,
        )
        async for chunk in astream_events(
            self._client, controller, build_request, iter_body, recorder=recorder
        ):
            yield chunk

    async def responses_input_tokens(
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
            await self.request(
                "POST",
                "/responses/input_tokens",
                json=body,
                workspace_id=workspace_id,
                idempotency_key=idempotency_key or _new_idempotency_key(),
            )
        )

    async def billing_checkout(
        self,
        *,
        amount: int | str,
        payment_method: str | None = None,
        workspace_id: str | None = None,
        success_url: str | None = None,
        cancel_url: str | None = None,
        idempotency_key: str | None = None,
    ) -> CheckoutSession:
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
            await self._control_request(
                "POST",
                "/billing/checkout",
                json=body,
                workspace_id=workspace_id,
                idempotency_key=idempotency_key,
            )
        )

    async def stablecoin_checkout(self, *, amount: int | str, **params: Any) -> CheckoutSession:
        return await self.billing_checkout(amount=amount, payment_method="stablecoin", **params)

    async def auth_session(self) -> AuthSession:
        return AuthSession.model_validate(await self._control_request("GET", "/auth/session"))

    async def logout(self) -> LogoutResponse:
        return LogoutResponse.model_validate(await self._control_request("POST", "/auth/logout"))

    async def activity(self, **params: Any) -> ActivityList:
        query = httpx.QueryParams({k: v for k, v in params.items() if v is not None})
        suffix = f"?{query}" if query else ""
        return ActivityList.model_validate(await self._control_request("GET", f"/activity{suffix}"))

    async def broadcast_destinations(self, *, workspace_id: str | None = None) -> dict[str, Any]:
        return await self._control_request(
            "GET", "/broadcast/destinations", workspace_id=workspace_id
        )

    async def create_broadcast_destination(
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
        return await self._control_request(
            "POST",
            "/broadcast/destinations",
            json=body,
            workspace_id=workspace_id,
        )

    async def get_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        return await self._control_request(
            "GET",
            f"/broadcast/destinations/{destination_id}",
            workspace_id=workspace_id,
        )

    async def update_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
        **patch: Any,
    ) -> dict[str, Any]:
        return await self._control_request(
            "PATCH",
            f"/broadcast/destinations/{destination_id}",
            json={key: value for key, value in patch.items() if value is not None},
            workspace_id=workspace_id,
        )

    async def delete_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        return await self._control_request(
            "DELETE",
            f"/broadcast/destinations/{destination_id}",
            workspace_id=workspace_id,
        )

    async def test_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        return await self._control_request(
            "POST",
            f"/broadcast/destinations/{destination_id}/test",
            workspace_id=workspace_id,
        )

    async def status(self, url: str = DEFAULT_STATUS_URL) -> dict[str, Any]:
        response = await _acredential_free_request(self._client, "GET", url)
        return _json_or_raise(response)

    async def attestation(self) -> bytes:
        url = self.base_url.rsplit("/v1", 1)[0] + "/attestation"
        response = await _acredential_free_request(self._client, "GET", url)
        if not response.is_success:
            raise TrustedRouterError(response.status_code, response.text[:240])
        return response.content
