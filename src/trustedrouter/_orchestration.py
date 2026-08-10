"""Orchestration builders (L7): fusion/advisor/selector/mapreduce/subagent
tool specs, ProviderPreferences, and the option-lifting table.

Wire schemas here are pinned by the cross-SDK parity tests
(tests/test_parity_contract.py) and must not change.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from trustedrouter._constants import (
    ADVISOR_MODEL,
    FUSION_MODEL,
    MAP_REDUCE_MODEL,
    SELECTOR_MODEL,
    SYNTH_MODEL,
)

_ADVISOR_MODELS = {ADVISOR_MODEL}
_FUSION_PRIMITIVE_MODELS = {
    FUSION_MODEL,
    "trustedrouter/fusion-code",
    SYNTH_MODEL,
    "trustedrouter/synth-code",
    SELECTOR_MODEL,
    MAP_REDUCE_MODEL,
}


def fusion_tool(
    *,
    enabled: bool | None = None,
    analysis_models: Sequence[str] | None = None,
    model: str | None = None,  # judge / synthesis model
    selection_strategy: str | None = None,
    fallback_judges: Sequence[str] | None = None,
    fallback_final_models: Sequence[str] | None = None,
    max_completion_tokens: int | None = None,
    max_tool_calls: int | None = None,
    preset: str | None = None,
    panel_prompt: str | None = None,
    synthesis_prompt: str | None = None,
) -> dict[str, Any]:
    """Build a ``trustedrouter:fusion`` tool spec. Fan a request across a panel
    of models and have a judge model pick or synthesize one answer. Omit a field
    to let the gateway default it (``selection_strategy`` defaults to
    ``"synthesize_non_refusals"``)."""
    parameters: dict[str, Any] = {}
    if enabled is not None:
        parameters["enabled"] = enabled
    if preset is not None:
        parameters["preset"] = preset
    if analysis_models is not None:
        parameters["analysis_models"] = list(analysis_models)
    if model is not None:
        parameters["model"] = model
    if selection_strategy is not None:
        parameters["selection_strategy"] = selection_strategy
    if fallback_judges is not None:
        parameters["fallback_judges"] = list(fallback_judges)
    if fallback_final_models is not None:
        parameters["fallback_final_models"] = list(fallback_final_models)
    if max_completion_tokens is not None:
        parameters["max_completion_tokens"] = max_completion_tokens
    if max_tool_calls is not None:
        parameters["max_tool_calls"] = max_tool_calls
    if panel_prompt is not None:
        parameters["panel_prompt"] = panel_prompt
    if synthesis_prompt is not None:
        parameters["synthesis_prompt"] = synthesis_prompt
    return {"type": "trustedrouter:fusion", "parameters": parameters}


def advisor_tool(
    *,
    enabled: bool | None = None,
    depth: int | None = None,
    worker_models: Sequence[str] | None = None,
    advisor_models: Sequence[str] | None = None,
    max_get_advice_calls: int | None = None,
    advisor_max_tokens: int | None = None,
    worker_timeout_ms: int | None = None,
    advisor_timeout_ms: int | None = None,
    auto_initial_advice: bool | None = None,
) -> dict[str, Any]:
    """Build a ``trustedrouter:advisor`` tool spec.

    Advisor orchestration runs a worker model and gives it one private
    zero-argument ``_trustedrouter_get_advice`` tool. The gateway executes that
    internal tool only when the worker asks for help. Most callers should pass
    these options directly to ``chat_completions(model=...)``; the SDK lifts
    them into this tool config.
    """
    parameters: dict[str, Any] = {}
    if enabled is not None:
        parameters["enabled"] = enabled
    if depth is not None:
        parameters["depth"] = depth
    if worker_models is not None:
        parameters["worker_models"] = list(worker_models)
    if advisor_models is not None:
        parameters["advisor_models"] = list(advisor_models)
    if max_get_advice_calls is not None:
        parameters["max_get_advice_calls"] = max_get_advice_calls
    if advisor_max_tokens is not None:
        parameters["advisor_max_tokens"] = advisor_max_tokens
    if worker_timeout_ms is not None:
        parameters["worker_timeout_ms"] = worker_timeout_ms
    if advisor_timeout_ms is not None:
        parameters["advisor_timeout_ms"] = advisor_timeout_ms
    if auto_initial_advice is not None:
        parameters["auto_initial_advice"] = auto_initial_advice
    return {"type": "trustedrouter:advisor", "parameters": parameters}


def selector_tool(
    *,
    enabled: bool | None = None,
    analysis_models: Sequence[str] | None = None,
    selector_models: Sequence[str] | None = None,
    selector_prompt: str | None = None,
    max_completion_tokens: int | None = None,
) -> dict[str, Any]:
    """Build a ``trustedrouter:selector`` tool spec."""
    parameters: dict[str, Any] = {}
    if enabled is not None:
        parameters["enabled"] = enabled
    if analysis_models is not None:
        parameters["analysis_models"] = list(analysis_models)
    if selector_models is not None:
        parameters["selector_models"] = list(selector_models)
    if selector_prompt is not None:
        parameters["selector_prompt"] = selector_prompt
    if max_completion_tokens is not None:
        parameters["max_completion_tokens"] = max_completion_tokens
    return {"type": "trustedrouter:selector", "parameters": parameters}


def map_reduce_tool(
    *,
    enabled: bool | None = None,
    mapper_models: Sequence[str] | None = None,
    parallel_models: Sequence[str] | None = None,
    reducer_models: Sequence[str] | None = None,
    max_parts: int | None = None,
    mapper_prompt: str | None = None,
    parallel_prompt: str | None = None,
    reducer_prompt: str | None = None,
    max_completion_tokens: int | None = None,
) -> dict[str, Any]:
    """Build a ``trustedrouter:mapreduce`` tool spec."""
    parameters: dict[str, Any] = {}
    if enabled is not None:
        parameters["enabled"] = enabled
    for collection_key, collection_value in (
        ("mapper_models", mapper_models),
        ("parallel_models", parallel_models),
        ("reducer_models", reducer_models),
    ):
        if collection_value is not None:
            parameters[collection_key] = list(collection_value)
    for scalar_key, scalar_value in (
        ("max_parts", max_parts),
        ("mapper_prompt", mapper_prompt),
        ("parallel_prompt", parallel_prompt),
        ("reducer_prompt", reducer_prompt),
        ("max_completion_tokens", max_completion_tokens),
    ):
        if scalar_value is not None:
            parameters[scalar_key] = scalar_value
    return {"type": "trustedrouter:mapreduce", "parameters": parameters}


def subagent_tool(
    *,
    enabled: bool | None = None,
    controller_model: str | None = None,
    model: str | None = None,
    instructions: str | None = None,
    depth: int | None = None,
    max_subagent_calls: int | None = None,
    max_completion_tokens: int | None = None,
    temperature: float | None = None,
    reasoning: Any | None = None,
    tools: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a ``trustedrouter:subagent`` tool spec."""
    parameters: dict[str, Any] = {}
    if enabled is not None:
        parameters["enabled"] = enabled
    for key, value in (
        ("controller_model", controller_model),
        ("model", model),
        ("instructions", instructions),
        ("depth", depth),
        ("max_subagent_calls", max_subagent_calls),
        ("max_completion_tokens", max_completion_tokens),
        ("temperature", temperature),
    ):
        if value is not None:
            parameters[key] = value
    if reasoning is not None:
        parameters["reasoning"] = reasoning
    if tools is not None:
        parameters["tools"] = [dict(tool) for tool in tools]
    return {"type": "trustedrouter:subagent", "parameters": parameters}


class ProviderPreferences(dict[str, Any]):
    """Typed provider routing preferences accepted by inference endpoints."""

    _PRIVACY = {"any", "no_store", "zdr", "confidential", "e2e", "e2ee"}
    _SORT = {"price", "latency", "throughput"}

    def __init__(
        self,
        *,
        order: Sequence[str] | None = None,
        only: Sequence[str] | None = None,
        ignore: Sequence[str] | None = None,
        sort: str | None = None,
        allow_fallbacks: bool | None = None,
        require_parameters: bool | None = None,
        data_collection: str | None = None,
        min_privacy: str | None = None,
        jurisdiction: str | None = None,
        usage: str | None = None,
        quantizations: Sequence[str] | None = None,
        max_price: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__()
        for key, value in (("order", order), ("only", only), ("ignore", ignore)):
            if value is not None:
                self[key] = list(value)
        if sort is not None:
            normalized = sort.strip().lower()
            if normalized not in self._SORT:
                raise ValueError("sort must be price, latency, or throughput")
            self["sort"] = normalized
        for boolean_key, boolean_value in (
            ("allow_fallbacks", allow_fallbacks),
            ("require_parameters", require_parameters),
        ):
            if boolean_value is not None:
                self[boolean_key] = boolean_value
        if data_collection is not None:
            normalized = data_collection.strip().lower()
            if normalized not in {"allow", "deny"}:
                raise ValueError("data_collection must be allow or deny")
            self["data_collection"] = normalized
        if min_privacy is not None:
            normalized = min_privacy.strip().lower()
            if normalized not in self._PRIVACY:
                raise ValueError("unsupported min_privacy")
            self["min_privacy"] = normalized
        if jurisdiction is not None:
            normalized = jurisdiction.strip().lower()
            if normalized != "us":
                raise ValueError("jurisdiction currently supports only us")
            self["jurisdiction"] = normalized
        if usage is not None:
            normalized = usage.strip().lower()
            if normalized not in {"credits", "byok"}:
                raise ValueError("usage must be credits or byok")
            self["usage"] = normalized
        if quantizations is not None:
            self["quantizations"] = list(quantizations)
        if max_price is not None:
            self["max_price"] = dict(max_price)

    @classmethod
    def zdr(cls) -> ProviderPreferences:
        return cls(min_privacy="zdr", data_collection="deny")

    @classmethod
    def confidential(cls) -> ProviderPreferences:
        return cls(min_privacy="confidential", data_collection="deny")

    @classmethod
    def us_only(cls) -> ProviderPreferences:
        return cls(jurisdiction="us")


def _move_orchestration_options_into_tools(
    model: str,
    params: dict[str, Any],
) -> dict[str, Any]:
    """Lift SDK orchestration kwargs into gateway tool specs.

    The gateway intentionally ignores top-level helper fields such as
    ``worker_models`` and ``analysis_models``. They must live inside the
    TrustedRouter tool config so direct ``chat_completions(model=...)`` calls
    behave the same as the convenience helpers.
    """

    tools = list(params.pop("tools", []))
    normalized_model = model.strip().lower()

    advisor_keys = {
        "depth",
        "worker_models",
        "advisor_models",
        "max_get_advice_calls",
        "advisor_max_tokens",
        "worker_timeout_ms",
        "advisor_timeout_ms",
        "auto_initial_advice",
    }
    advisor_values: dict[str, Any] = {}
    for key in list(params):
        if key not in advisor_keys:
            continue
        value = params.pop(key)
        if value is not None:
            advisor_values[key] = value
    if advisor_values:
        tools.append(
            advisor_tool(
                depth=advisor_values.get("depth"),
                worker_models=advisor_values.get("worker_models"),
                advisor_models=advisor_values.get("advisor_models"),
                max_get_advice_calls=advisor_values.get("max_get_advice_calls"),
                advisor_max_tokens=advisor_values.get("advisor_max_tokens"),
                worker_timeout_ms=advisor_values.get("worker_timeout_ms"),
                advisor_timeout_ms=advisor_values.get("advisor_timeout_ms"),
                auto_initial_advice=advisor_values.get("auto_initial_advice"),
            )
        )

    fusion_key_map = {
        "analysis_models": "analysis_models",
        "judge_model": "model",
        "selection_strategy": "selection_strategy",
        "fallback_judges": "fallback_judges",
        "fallback_final_models": "fallback_final_models",
        "max_completion_tokens": "max_completion_tokens",
        "max_tool_calls": "max_tool_calls",
        "preset": "preset",
        "panel_prompt": "panel_prompt",
        "synthesis_prompt": "synthesis_prompt",
        "final_prompt": "final_prompt",
        "selector_models": "selector_models",
        "selector_model": "selector_model",
        "selector_prompt": "selector_prompt",
        "mapper_models": "mapper_models",
        "mapper_model": "mapper_model",
        "mapper_prompt": "mapper_prompt",
        "parallel_models": "parallel_models",
        "parallel_model": "parallel_model",
        "parallel_prompt": "parallel_prompt",
        "reducer_models": "reducer_models",
        "reducer_model": "reducer_model",
        "reducer_prompt": "reducer_prompt",
    }
    fusion_values: dict[str, Any] = {}
    for sdk_key, gateway_key in fusion_key_map.items():
        if sdk_key not in params:
            continue
        value = params.pop(sdk_key)
        if value is not None:
            fusion_values[gateway_key] = value
    if fusion_values:
        tools.append({"type": "trustedrouter:fusion", "parameters": fusion_values})

    if tools:
        params["tools"] = tools
    elif normalized_model in _ADVISOR_MODELS or normalized_model in _FUSION_PRIMITIVE_MODELS:
        params.pop("tools", None)

    return params
