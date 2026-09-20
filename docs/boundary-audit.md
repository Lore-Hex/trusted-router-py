# Boundary audit

This table was recorded before implementation. Locations below refer to the original source. “fixed” records the selected repair; verification and current locations are appended after execution. Scope: all 20 library modules.

| Class | Original sites | Verdict | Reason / repair |
|---|---|---|---|
| 1,2 | oauth.py:240-252 | fixed | Validate key, optional user_id/identity/data; require userinfo data, permit nullable sub; preserve unknown metadata. |
| 1,4 | _errors.py:120-149 | fixed | Translate malformed successful JSON into InternalError; existing dict/error attribution guards safe; diagnostic string formatting intentionally unchanged. |
| 1,2 | _sse.py:136-141; _collect.py:37-79,143-181 | fixed | Validate consumed choices/delta/tool structures before indexing/merging, without rejecting pass-through content. |
| 1 | _collect.py:254 | fixed | Validate stream_options supplied through arbitrary keyword arguments. |
| 1,2 | attestation.py:129-154 | fixed | Reject malformed image identity material rather than stringify/filter it. |
| 1 | attestation.py:185-246 | fixed | Guard decoded JWT objects and JWKS keys/n/e; translate decoding and RSA construction errors. |
| 1,2 | attestation.py:262-419 | fixed | Guard nested container, image strings, nonce sequence and hashability; preserve unknown claims. |
| 4 | attestation.py:444-452 | fixed | Translate malformed fetched JWKS JSON to AttestationVerificationError. |
| 1 | receipts.py:268-270,404-406,602 | fixed | Reject non-ASCII kid before constant-time comparison; reject unhashable hash domain/attestation kind with typed errors. |
| 1 | receipts.py:704 | fixed | Compare encoded HTTPS origin strings so non-ASCII input produces a typed issuer mismatch instead of TypeError. |
| 4 | receipts.py:480-484 | fixed | Malformed receipt stream JSON must not disappear as a non-receipt event. |
| 4 | receipts.py:633-636 | already-safe | Broad catch wraps any attestation failure in ReceiptAttestationError; never reports success or retries. |
| 1 | receipts.py:158-415,651-938 | already-safe | JSON mapping checks, required/optional string/mapping/integer guards precede claims consumption; capture defers validation to verify(). |
| 3 | _client_sync.py:139-145,242-243,297-301; _client_async.py:131-137,236-238,291-295 | fixed | Use httpx.Headers for constructor, per-call and streaming merges; retain repeats and case-insensitive override semantics. |
| 3 | _requests.py:199-210; _transport.py:143,212,291,381 | fixed | Keep Headers throughout assembly and retry copies. |
| 3 | _retry.py:83,167,176 | fixed | Normalize arbitrary header casing through the shared _header helper; request stores use httpx.Headers. |
| 3 | session.py:244-279 | already-safe | Wire names normalized to lowercase; duplicate framing fields rejected; Content-Length conversion catches missing/invalid values. Only normalized headers reach connection-close helper. |
| 1,2 | session.py:210-222 | fixed | Narrow dynamic pyOpenSSL recv result to bytes to satisfy strict mypy. |
| 2 | session.py:53,431-436 | fixed | Remove obsolete OpenSSL import ignores; declare private session state instead of attr-defined ignores. |
| 4 | session.py:438-440 | already-safe | Cleanup only; always re-raises original error. |
| 4 | _requests.py:179; _telemetry.py:114 | fixed | Narrow package-version fallback to PackageNotFoundError. |
| 4 | _telemetry.py:1040 | fixed | Narrow JSON policy decode catch and log malformed optional policy; inference must remain independent of telemetry. |
| 4 | _telemetry.py:749,869,907,1139,1158,1187,1198,1204,1600 | intentionally-unchanged | Best-effort telemetry lifecycle/callback isolation; cannot convert inference or verification failures into success. Add invariant reasons to necessary suppressions. |
| 2 | _telemetry.py:240,331-356,426-545,643-659,717-741,941-1022,1259-1587 | intentionally-unchanged | Bounded telemetry serialization/config normalization of internal events; no auth, trust or inference response field is consumed here. Numeric conversions catch invalid values. |
| 1 | _telemetry.py:361-597,1037-1055 | already-safe | Internal event/identity dictionaries, guarded nested attempts and optional Mapping policy; not an inference parser. |
| 1,2 | models.py:33-397 | already-safe | Pydantic validates response model shapes and preserves extras; normal documented Pydantic conversions remain compatible. |
| 2 | models.py:153,157,161 | fixed | Consumed catalog booleans must not turn string false into true. |
| 3 | _requests.py:66-100; _transport.py:72-118; _telemetry.py:989,1078,1262-1267 | already-safe | Reserved/credential stripping and replay detection lowercase every key; response headers are httpx.Headers; telemetry helper compares lowercase. |
| 3 | _requests.py:268 | intentionally-unchanged | Broadcast destination headers are a JSON configuration object sent to the producer, not local HTTP request headers. |
| 1,2 | _client_sync.py; _client_async.py; _orchestration.py; _requests.py | already-safe | Other mappings are typed caller parameters or dictionaries assembled locally; kwargs metadata passes through; response objects go through _json_or_raise/Pydantic or SSE parser. |
| 4 | __main__.py:345,396,437,523 | intentionally-unchanged | CLI top-level catches emit an explicit error envelope and nonzero status; never retry or report success. |
| 1,2 | __main__.py:51,90,161-176,227-259,634; _routing.py; _retry.py | already-safe | Argparse and OS environment strings; bounded numeric header parser; typed internal routing state; narrow transport exception handling. |
| 2 | client.py; __init__.py; _constants.py | already-safe | Exports/constants only; no external decoding, casts or consumed wire values. |

| 4 | session.py:326,328,332; __main__.py:354,405,532,534,537 | already-safe | suppress(Exception) is limited to resource cleanup; it never encloses decoded shape consumption or changes the already determined result. |

No typing.cast calls or bare except clauses existed in the original library. All existing library type ignores were removed by the typing repairs above. No environment or storage JSON loader exists beyond the JSON decoding sites inventoried here; environment values are os.environ strings.

## Mechanical whole-source inventory (original locations)

Every attribute lookup of get/items/values, indexed access, iteration, JSON decode, scalar conversion, catch, cast or ignore is included below, grouped by function. Annotation-only subscriptions are excluded. The boundary-specific verdicts above take precedence; remaining sites operate on the typed/internal state described above. This inventory deliberately searches the defect class rather than only guard syntax.

| File / function | Candidate locations | Disposition |
|---|---|---|
| __main__.py / _jsonable | 51 | intentionally-unchanged: argparse/environment strings and validated SDK results; terminal errors emit nonzero exit status; cleanup only; specific repairs listed above. |
| __main__.py / _emit_error | 90, 94, 96 | intentionally-unchanged: argparse/environment strings and validated SDK results; terminal errors emit nonzero exit status; cleanup only; specific repairs listed above. |
| __main__.py / _bearer | 161, 162 | intentionally-unchanged: argparse/environment strings and validated SDK results; terminal errors emit nonzero exit status; cleanup only; specific repairs listed above. |
| __main__.py / _client | 171, 172, 175, 176 | intentionally-unchanged: argparse/environment strings and validated SDK results; terminal errors emit nonzero exit status; cleanup only; specific repairs listed above. |
| __main__.py / _stdin_prompt | 227, 229 | intentionally-unchanged: argparse/environment strings and validated SDK results; terminal errors emit nonzero exit status; cleanup only; specific repairs listed above. |
| __main__.py / _non_negative_int | 252 | intentionally-unchanged: argparse/environment strings and validated SDK results; terminal errors emit nonzero exit status; cleanup only; specific repairs listed above. |
| __main__.py / _positive_int | 259 | intentionally-unchanged: argparse/environment strings and validated SDK results; terminal errors emit nonzero exit status; cleanup only; specific repairs listed above. |
| __main__.py / _cmd_chat | 274, 275, 296, 319, 321, 325, 335, 339, 345, 349 | intentionally-unchanged: argparse/environment strings and validated SDK results; terminal errors emit nonzero exit status; cleanup only; specific repairs listed above. |
| __main__.py / _cmd_list | 376, 380, 386, 390, 396, 400 | intentionally-unchanged: argparse/environment strings and validated SDK results; terminal errors emit nonzero exit status; cleanup only; specific repairs listed above. |
| __main__.py / _cmd_trust | 417, 421, 427, 431, 437, 441 | intentionally-unchanged: argparse/environment strings and validated SDK results; terminal errors emit nonzero exit status; cleanup only; specific repairs listed above. |
| __main__.py / _cmd_attest | 476, 503, 507, 513, 517, 523, 527 | intentionally-unchanged: argparse/environment strings and validated SDK results; terminal errors emit nonzero exit status; cleanup only; specific repairs listed above. |
| __main__.py / _build_parser | 596 | intentionally-unchanged: argparse/environment strings and validated SDK results; terminal errors emit nonzero exit status; cleanup only; specific repairs listed above. |
| __main__.py / main | 623, 625, 634 | intentionally-unchanged: argparse/environment strings and validated SDK results; terminal errors emit nonzero exit status; cleanup only; specific repairs listed above. |
| _client_async.py / __init__ | 119, 120, 156 | fixed: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_async.py / _recorder | 210, 211, 212 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_async.py / request | 240, 243, 246, 249 | fixed: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_async.py / _control_request | 282, 288 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_async.py / _build_chat_request | 314 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_async.py / gen | 380, 426 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_async.py / chat_completions_stream | 395 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_async.py / chat_completions_chunk_stream | 439 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_async.py / chat_completions_raw_stream | 480 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_async.py / embeddings | 609, 611, 613, 615, 617, 619, 621 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_async.py / responses_stream | 762 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_async.py / responses_raw_stream | 812 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_async.py / billing_checkout | 856, 858, 860, 862 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_async.py / activity | 883 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_async.py / update_broadcast_destination | 944 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_async.py / attestation | 977, 980 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_sync.py / __init__ | 127, 128, 162 | fixed: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_sync.py / _recorder | 212, 213, 214 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_sync.py / request | 245, 248, 251, 254 | fixed: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_sync.py / _control_request | 288, 294 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_sync.py / _build_chat_request | 320 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_sync.py / iter_body | 368, 418 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_sync.py / embeddings | 573, 575, 577, 579, 581, 583, 585 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_sync.py / billing_checkout | 832, 834, 836, 838 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_sync.py / activity | 862 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_sync.py / update_broadcast_destination | 918 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _client_sync.py / attestation | 955, 958 | already-safe: typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths; specific repairs listed above. |
| _collect.py / _collect_completion | 30, 31, 33, 34, 37, 40, 43, 60, 62, 64, 70, 71, 73, 76, 78, 80, 84, 85, 86, 92, 93, 94, 95, 96, 98, 99, 100, 101, 103, 104, 105, 107, 110, 116, 119, 125, 127, 128, 132, 134 | fixed: Mapping/list checks precede traversal; accumulated choice/tool state initialized locally; opaque metadata copied; specific repairs listed above. |
| _collect.py / _merge_tool_call_deltas | 141, 144, 154, 156, 157, 159, 161, 163 | fixed: Mapping/list checks precede traversal; accumulated choice/tool state initialized locally; opaque metadata copied; specific repairs listed above. |
| _collect.py / _merge_function_call_delta | 169, 170, 172, 174 | fixed: Mapping/list checks precede traversal; accumulated choice/tool state initialized locally; opaque metadata copied; specific repairs listed above. |
| _collect.py / _collect_trustedrouter_metadata | 188, 189, 192, 207, 212, 213, 225, 228, 230 | already-safe: Mapping/list checks precede traversal; accumulated choice/tool state initialized locally; opaque metadata copied; specific repairs listed above. |
| _collect.py / _trustedrouter_synth_event_detail | 236, 240, 242 | already-safe: Mapping/list checks precede traversal; accumulated choice/tool state initialized locally; opaque metadata copied; specific repairs listed above. |
| _collect.py / _with_usage | 252, 254 | fixed: Mapping/list checks precede traversal; accumulated choice/tool state initialized locally; opaque metadata copied; specific repairs listed above. |
| _errors.py / __init__ | 28 | already-safe: Mapping guards before extraction; string rendering is diagnostic only; raw payload retained; specific repairs listed above. |
| _errors.py / _optional_error_string | 38 | already-safe: Mapping guards before extraction; string rendering is diagnostic only; raw payload retained; specific repairs listed above. |
| _errors.py / _json_or_raise | 123, 124, 128 | fixed: Mapping guards before extraction; string rendering is diagnostic only; raw payload retained; specific repairs listed above. |
| _errors.py / _error_message | 145, 147, 148, 149 | already-safe: Mapping guards before extraction; string rendering is diagnostic only; raw payload retained; specific repairs listed above. |
| _errors.py / _raise_for_stream_response | 158 | already-safe: Mapping guards before extraction; string rendering is diagnostic only; raw payload retained; specific repairs listed above. |
| _errors.py / _araise_for_stream_response | 168 | already-safe: Mapping guards before extraction; string rendering is diagnostic only; raw payload retained; specific repairs listed above. |
| _orchestration.py / fusion_tool | 52, 54, 56, 58, 60, 62, 64, 66, 68, 70, 72 | already-safe: caller configuration, local dictionaries and typed builder arguments; no decoded response access; specific repairs listed above. |
| _orchestration.py / advisor_tool | 98, 100, 102, 104, 106, 108, 110, 112, 114 | already-safe: caller configuration, local dictionaries and typed builder arguments; no decoded response access; specific repairs listed above. |
| _orchestration.py / selector_tool | 129, 131, 133, 135, 137 | already-safe: caller configuration, local dictionaries and typed builder arguments; no decoded response access; specific repairs listed above. |
| _orchestration.py / map_reduce_tool | 156, 157, 163, 164, 172 | already-safe: caller configuration, local dictionaries and typed builder arguments; no decoded response access; specific repairs listed above. |
| _orchestration.py / subagent_tool | 192, 193, 203, 205, 207 | already-safe: caller configuration, local dictionaries and typed builder arguments; no decoded response access; specific repairs listed above. |
| _orchestration.py / <module> | 211 | already-safe: caller configuration, local dictionaries and typed builder arguments; no decoded response access; specific repairs listed above. |
| _orchestration.py / __init__ | 234, 236, 241, 242, 247, 252, 257, 262, 267, 269, 271 | already-safe: caller configuration, local dictionaries and typed builder arguments; no decoded response access; specific repairs listed above. |
| _orchestration.py / _move_orchestration_options_into_tools | 312, 317, 321, 322, 323, 324, 325, 326, 327, 328, 358, 363, 368 | already-safe: caller configuration, local dictionaries and typed builder arguments; no decoded response access; specific repairs listed above. |
| _requests.py / _strip_reserved_headers | 73, 75 | already-safe: local request dictionaries; key-lowercasing credential/reserved removal; broadcast headers are JSON configuration; specific repairs listed above. |
| _requests.py / _strip_credentials | 79, 81 | already-safe: local request dictionaries; key-lowercasing credential/reserved removal; broadcast headers are JSON configuration; specific repairs listed above. |
| _requests.py / _enforce_reserved_headers | 92, 95, 98, 99 | already-safe: local request dictionaries; key-lowercasing credential/reserved removal; broadcast headers are JSON configuration; specific repairs listed above. |
| _requests.py / _credential_free_request | 151, 152 | already-safe: local request dictionaries; key-lowercasing credential/reserved removal; broadcast headers are JSON configuration; specific repairs listed above. |
| _requests.py / _acredential_free_request | 166, 167 | already-safe: local request dictionaries; key-lowercasing credential/reserved removal; broadcast headers are JSON configuration; specific repairs listed above. |
| _requests.py / _user_agent | 179 | fixed: local request dictionaries; key-lowercasing credential/reserved removal; broadcast headers are JSON configuration; specific repairs listed above. |
| _requests.py / _build_stream_request | 206, 208, 210, 219 | fixed: local request dictionaries; key-lowercasing credential/reserved removal; broadcast headers are JSON configuration; specific repairs listed above. |
| _requests.py / _responses_body | 232, 243 | already-safe: local request dictionaries; key-lowercasing credential/reserved removal; broadcast headers are JSON configuration; specific repairs listed above. |
| _requests.py / _broadcast_destination_body | 266, 268, 270 | already-safe: local request dictionaries; key-lowercasing credential/reserved removal; broadcast headers are JSON configuration; specific repairs listed above. |
| _requests.py / _models_path | 282, 284, 286 | already-safe: local request dictionaries; key-lowercasing credential/reserved removal; broadcast headers are JSON configuration; specific repairs listed above. |
| _retry.py / _should_retry_header | 83 | fixed: typed controller state; bounded numeric header parsing catches invalid values; jitter is not cryptographic; specific repairs listed above. |
| _retry.py / _retry_after_seconds | 167, 171, 176, 181 | fixed: typed controller state; bounded numeric header parsing catches invalid values; jitter is not cryptographic; specific repairs listed above. |
| _retry.py / current_base_url | 277 | already-safe: typed controller state; bounded numeric header parsing catches invalid values; jitter is not cryptographic; specific repairs listed above. |
| _routing.py / measure | 93, 96, 132, 135 | already-safe: local lists and pools; only HTTP status consumed; narrow HTTPError catches; specific repairs listed above. |
| _routing.py / _select_regions_sync | 106, 112 | already-safe: local lists and pools; only HTTP status consumed; narrow HTTPError catches; specific repairs listed above. |
| _routing.py / _select_regions_async | 146, 152 | already-safe: local lists and pools; only HTTP status consumed; narrow HTTPError catches; specific repairs listed above. |
| _sse.py / _sse_data | 22 | already-safe: decoded object checked; generic SSE events intentionally wrap non-object data as opaque metadata; specific repairs listed above. |
| _sse.py / _parse_sse_line | 39, 40, 47 | already-safe: decoded object checked; generic SSE events intentionally wrap non-object data as opaque metadata; specific repairs listed above. |
| _sse.py / _event_from_sse_frame | 58, 60, 62, 67, 68 | already-safe: decoded object checked; generic SSE events intentionally wrap non-object data as opaque metadata; specific repairs listed above. |
| _sse.py / _iter_sse_events | 78 | already-safe: decoded object checked; generic SSE events intentionally wrap non-object data as opaque metadata; specific repairs listed above. |
| _sse.py / _aiter_sse_events | 108 | already-safe: decoded object checked; generic SSE events intentionally wrap non-object data as opaque metadata; specific repairs listed above. |
| _sse.py / _delta_text | 136, 139, 140 | fixed: decoded object checked; generic SSE events intentionally wrap non-object data as opaque metadata; specific repairs listed above. |
| _sse.py / _iter_sse_chunks | 149 | already-safe: decoded object checked; generic SSE events intentionally wrap non-object data as opaque metadata; specific repairs listed above. |
| _sse.py / _aiter_sse_chunks | 166 | already-safe: decoded object checked; generic SSE events intentionally wrap non-object data as opaque metadata; specific repairs listed above. |
| _telemetry.py / _os_enum | 84 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / sdk_identity | 114 | fixed: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _scheme_host | 141 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / host_enum | 161, 163, 166 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / endpoint_enum | 185, 186 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / latency_bucket | 240, 241, 242, 246 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / timeout_floor_met | 267 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / resolve_telemetry_enabled | 281, 286 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _bounded_int | 333, 334 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _bounded_optional_int | 342, 343 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _float_value | 355 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _normalise_sdk_identity | 362, 364, 365, 371, 372, 374, 375, 377, 378, 380, 381, 383 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _normalise_counter_key | 426, 432, 433 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _merge_histogram | 440, 444 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _merge_counter_increment | 448, 449, 450, 451, 453 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _wire_attempt | 457, 460, 463, 466, 469, 473, 476, 480, 482, 483, 485, 487, 489, 491 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _wire_event | 496, 499, 502, 504, 505, 507, 510, 513, 516, 518, 519, 522, 525, 535, 536, 541, 543, 544, 545, 548 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _counter_row | 560, 561, 562, 563, 564, 565, 566, 567, 568, 569, 570, 571, 573, 576, 578, 579 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / __init__ | 614 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _sample_rate | 645 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _flush_interval | 655 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _sample_reason | 714, 716, 717, 718, 721 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _drop_buffered_event_locked | 734, 741 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _append_event_locked | 749, 751 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _folded_counter_key | 771, 773 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _counter_target_locked | 786, 795, 804, 813 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _merge_counters_locked | 820 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / on_request | 844, 845, 850, 869 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _window_size | 873 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _prune_windows_locked | 898 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _api_key | 907 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _select_batch_locked | 925, 941, 946, 947, 948, 963, 972, 973, 975, 976 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _retry_after | 989, 994 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _remove_selected_locked | 1022, 1025, 1027, 1028, 1029 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _apply_policy_locked | 1039, 1040, 1042, 1046, 1050, 1053 | fixed: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _handle_response | 1078 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _flush_once | 1127, 1134, 1139, 1142 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / flush_now | 1158, 1159 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _worker | 1187, 1188 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _close_http_client | 1198 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _final_flush | 1204, 1205 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _close_reporters | 1234 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _duration_ms | 1259 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _header | 1264 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / header_value | 1327, 1353, 1355, 1361 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _store_attempt | 1368, 1369 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / on_response | 1407 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / on_transport_error | 1440 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / on_moved | 1463 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / on_aborted | 1474, 1490 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _configured_timeout_ms | 1508 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / _finish | 1513, 1519, 1559, 1560, 1565, 1567, 1587 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _telemetry.py / finish | 1600, 1601 | intentionally-unchanged: internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success; specific repairs listed above. |
| _transport.py / _has_idempotency_key | 73 | already-safe: SDK-built kwargs and replay controller state; HTTPX response headers; narrow transport errors or cleanup rethrows; specific repairs listed above. |
| _transport.py / _apply_reserved_headers | 113, 117, 118, 119, 120 | already-safe: SDK-built kwargs and replay controller state; HTTPX response headers; narrow transport errors or cleanup rethrows; specific repairs listed above. |
| _transport.py / request_with_retry | 143, 144, 148, 159, 192 | fixed: SDK-built kwargs and replay controller state; HTTPX response headers; narrow transport errors or cleanup rethrows; specific repairs listed above. |
| _transport.py / arequest_with_retry | 212, 213, 214, 225, 258 | fixed: SDK-built kwargs and replay controller state; HTTPX response headers; narrow transport errors or cleanup rethrows; specific repairs listed above. |
| _transport.py / stream_events | 291, 292, 302, 306, 319, 328, 335, 342, 344, 356 | fixed: SDK-built kwargs and replay controller state; HTTPX response headers; narrow transport errors or cleanup rethrows; specific repairs listed above. |
| _transport.py / astream_events | 381, 382, 392, 396, 405, 414, 421, 428, 430, 442 | fixed: SDK-built kwargs and replay controller state; HTTPX response headers; narrow transport errors or cleanup rethrows; specific repairs listed above. |
| attestation.py / pins_image_identity | 83 | already-safe: JWT and JWKS checked before use; claims constraints fail closed; trusted crypto/time outputs; specific repairs listed above. |
| attestation.py / policy_from_trust_release | 136, 137, 139, 143, 144, 147 | fixed: JWT and JWKS checked before use; claims constraints fail closed; trusted crypto/time outputs; specific repairs listed above. |
| attestation.py / _jwt_split | 195, 196, 198 | fixed: JWT and JWKS checked before use; claims constraints fail closed; trusted crypto/time outputs; specific repairs listed above. |
| attestation.py / _verify_rs256 | 214, 220, 222, 224, 225, 226, 231, 235, 236, 237, 245 | fixed: JWT and JWKS checked before use; claims constraints fail closed; trusted crypto/time outputs; specific repairs listed above. |
| attestation.py / _check_claims | 262, 263, 269, 273, 277, 279, 281, 287, 290, 312, 313, 314, 340, 341, 385, 386, 415, 416, 419 | fixed: JWT and JWKS checked before use; claims constraints fail closed; trusted crypto/time outputs; specific repairs listed above. |
| attestation.py / _find_cert_in_nonces | 432 | already-safe: JWT and JWKS checked before use; claims constraints fail closed; trusted crypto/time outputs; specific repairs listed above. |
| attestation.py / _fetch_jwks | 447, 449 | fixed: JWT and JWKS checked before use; claims constraints fail closed; trusted crypto/time outputs; specific repairs listed above. |
| models.py / open_weights | 153 | fixed: Pydantic validates known shapes and preserves extras; internal attributes have validated container types; specific repairs listed above. |
| models.py / us_provider_available | 157 | fixed: Pydantic validates known shapes and preserves extras; internal attributes have validated container types; specific repairs listed above. |
| models.py / eu_focused_provider_available | 161 | fixed: Pydantic validates known shapes and preserves extras; internal attributes have validated container types; specific repairs listed above. |
| oauth.py / _callback_url_with_state | 133 | already-safe: URL encoding of typed caller arguments; HTTP parsing delegated to _json_or_raise and identity guards; specific repairs listed above. |
| oauth.py / oauth_authorize_url | 169, 171, 173, 175, 177, 179, 181, 183, 186 | already-safe: URL encoding of typed caller arguments; HTTP parsing delegated to _json_or_raise and identity guards; specific repairs listed above. |
| oauth.py / _exchange_body | 234, 236 | already-safe: URL encoding of typed caller arguments; HTTP parsing delegated to _json_or_raise and identity guards; specific repairs listed above. |
| oauth.py / _token_from_payload | 241, 243, 244 | fixed: URL encoding of typed caller arguments; HTTP parsing delegated to _json_or_raise and identity guards; specific repairs listed above. |
| oauth.py / _userinfo_data | 251 | fixed: URL encoding of typed caller arguments; HTTP parsing delegated to _json_or_raise and identity guards; specific repairs listed above. |
| oauth.py / fetch_userinfo | 329, 332 | already-safe: URL encoding of typed caller arguments; HTTP parsing delegated to _json_or_raise and identity guards; specific repairs listed above. |
| oauth.py / fetch_userinfo_async | 350, 353 | already-safe: URL encoding of typed caller arguments; HTTP parsing delegated to _json_or_raise and identity guards; specific repairs listed above. |
| receipts.py / _json_object_no_duplicates | 151, 154 | already-safe: decoded mappings and required string/integer guards before use; trust failures typed; capture postpones full verification; specific repairs listed above. |
| receipts.py / _load_json | 160, 161 | already-safe: decoded mappings and required string/integer guards before use; trust failures typed; capture postpones full verification; specific repairs listed above. |
| receipts.py / _b64url_decode | 174 | already-safe: decoded mappings and required string/integer guards before use; trust failures typed; capture postpones full verification; specific repairs listed above. |
| receipts.py / _parse_envelope | 190, 215, 222 | already-safe: decoded mappings and required string/integer guards before use; trust failures typed; capture postpones full verification; specific repairs listed above. |
| receipts.py / _parse_header | 240, 242, 244, 247, 249, 252, 256, 261, 262, 268 | fixed: decoded mappings and required string/integer guards before use; trust failures typed; capture postpones full verification; specific repairs listed above. |
| receipts.py / _verify_signature | 281, 282, 286, 293 | already-safe: decoded mappings and required string/integer guards before use; trust failures typed; capture postpones full verification; specific repairs listed above. |
| receipts.py / _required_mapping | 304 | already-safe: decoded mappings and required string/integer guards before use; trust failures typed; capture postpones full verification; specific repairs listed above. |
| receipts.py / _required_str | 311 | already-safe: decoded mappings and required string/integer guards before use; trust failures typed; capture postpones full verification; specific repairs listed above. |
| receipts.py / _optional_str | 322 | already-safe: decoded mappings and required string/integer guards before use; trust failures typed; capture postpones full verification; specific repairs listed above. |
| receipts.py / _canonical_https_origin | 334, 355 | already-safe: decoded mappings and required string/integer guards before use; trust failures typed; capture postpones full verification; specific repairs listed above. |
| receipts.py / _digest_claim | 392, 395, 400, 401, 404, 408 | fixed: decoded mappings and required string/integer guards before use; trust failures typed; capture postpones full verification; specific repairs listed above. |
| receipts.py / _decode_sse_event | 429, 431, 438, 440, 447, 449, 456, 458 | already-safe: decoded mappings and required string/integer guards before use; trust failures typed; capture postpones full verification; specific repairs listed above. |
| receipts.py / _next_sse_event | 477 | already-safe: decoded mappings and required string/integer guards before use; trust failures typed; capture postpones full verification; specific repairs listed above. |
| receipts.py / _embedded_receipt | 482, 483, 487 | fixed: decoded mappings and required string/integer guards before use; trust failures typed; capture postpones full verification; specific repairs listed above. |
| receipts.py / _attestation_status | 600, 601, 620, 633, 635 | fixed: decoded mappings and required string/integer guards before use; trust failures typed; capture postpones full verification; specific repairs listed above. |
| receipts.py / verify_receipt | 688, 700, 725, 740, 743, 748, 767, 768 | fixed: decoded mappings and required string/integer guards before use; trust failures typed; capture postpones full verification; specific repairs listed above. |
| receipts.py / <module> | 874 | already-safe: decoded mappings and required string/integer guards before use; trust failures typed; capture postpones full verification; specific repairs listed above. |
| receipts.py / _refresh_receipt | 912 | already-safe: decoded mappings and required string/integer guards before use; trust failures typed; capture postpones full verification; specific repairs listed above. |
| session.py / _load_pyopenssl | 54 | fixed: typed socket/crypto adapter values; lowercase wire header names; duplicate framing detection; cleanup rethrows; specific repairs listed above. |
| session.py / _verify_callback | 69 | already-safe: typed socket/crypto adapter values; lowercase wire header names; duplicate framing detection; cleanup rethrows; specific repairs listed above. |
| session.py / _dnsname_matches | 84, 91, 95, 96 | already-safe: typed socket/crypto adapter values; lowercase wire header names; duplicate framing detection; cleanup rethrows; specific repairs listed above. |
| session.py / _ip_literal | 103, 106 | already-safe: typed socket/crypto adapter values; lowercase wire header names; duplicate framing detection; cleanup rethrows; specific repairs listed above. |
| session.py / _assert_cert_matches_hostname | 113, 122 | already-safe: typed socket/crypto adapter values; lowercase wire header names; duplicate framing detection; cleanup rethrows; specific repairs listed above. |
| session.py / _ssl_call | 170, 172, 174, 176 | already-safe: typed socket/crypto adapter values; lowercase wire header names; duplicate framing detection; cleanup rethrows; specific repairs listed above. |
| session.py / _ssl_send_all | 197 | already-safe: typed socket/crypto adapter values; lowercase wire header names; duplicate framing detection; cleanup rethrows; specific repairs listed above. |
| session.py / _recv_or_fail | 218 | fixed: typed socket/crypto adapter values; lowercase wire header names; duplicate framing detection; cleanup rethrows; specific repairs listed above. |
| session.py / _read_http_response | 243, 246, 254, 256, 257, 261, 264, 273 | already-safe: typed socket/crypto adapter values; lowercase wire header names; duplicate framing detection; cleanup rethrows; specific repairs listed above. |
| session.py / _connection_close_requested | 279 | already-safe: typed socket/crypto adapter values; lowercase wire header names; duplicate framing detection; cleanup rethrows; specific repairs listed above. |
| session.py / _parse_base_url | 319 | already-safe: typed socket/crypto adapter values; lowercase wire header names; duplicate framing detection; cleanup rethrows; specific repairs listed above. |
| session.py / verify_gateway_session | 438 | fixed: typed socket/crypto adapter values; lowercase wire header names; duplicate framing detection; cleanup rethrows; specific repairs listed above. |

## Static gate and compatibility

CI and release validation now run Ruff, the stdlib boundary checker, `uv run mypy`, pytest, then the mutation runner. The configured mypy strict flags apply only to `trustedrouter.*`; tests retain `check_untyped_defs`. Global redundant-cast checking is enabled because mypy does not permit that flag per module. `uv run mypy --strict src/trustedrouter` also passes independently (21 modules). The original 47 errors are fixed through explicit reexports, declared session state and runtime narrowing of the dynamic TLS receive result. No library type ignores remain.

Ruff selects E, F, I, UP, B, S, BLE001, PGH003, PGH004, RUF and TRY. All stable rules in those selections apply equally to library and tests. Exclusions:

| Rule | Original churn | Reason |
|---|---:|---|
| TRY003 | 197 findings | Contextual exception messages belong at the failure sites; moving them into exception constructors adds structural churn without detecting malformed boundaries. All other TRY rules enabled. |
| S101 | 984 assertions (981 tests, 3 source) | Tests use assertions; the three source assertions follow explicit validation of the flattened receipt tuple and only communicate the established invariant to mypy. Existing exclusion retained. |

Other newly enabled baseline findings were fixed: TRY300 (5), TRY301 (1), RUF100 (5), RUF022 (2), RUF012 (2), RUF043 (1). One BLE001 test-thread catch remains with its explicit relay-to-parent-test invariant. No blanket ignores were introduced. Preview-only Ruff rules are not enabled.

`boundary_check.py` adds BND001 (decode into `object`, forcing mypy narrowing), BND002 (no casts/inline consumed-field coercion), BND003 (no lossy header copies or case-sensitive reads of mapping headers), and BND004 (specific noqa plus a reason). Its documented exceptions are diagnostic message rendering, SDK-owned telemetry serialization, internally assembled transport methods, numeric Content-Length parsing, normalized session framing headers and broadcast JSON configuration. This is a syntactic supplement, not whole-program taint analysis: explicit Any remains for opaque metadata and the optional TLS adapter. The runtime guards and their mutations cover the audited dynamic boundaries; arbitrary future Any flows still require review.

Producer compatibility: `/auth/keys` requires only its consumed string key, checks optional exposed fields if present, and does not require `data`. Identity fields `sub`/`email` may be null; unknown fields remain unchanged. `/auth/userinfo` requires its consumed object `data`, including real legacy `{sub: null, workspace_id}` data. The prior invented flat-userinfo fallback test now expects a typed error, matching the shared producer fixture. No fixture or parity contract was edited. Public response model types remain unchanged. Session private attributes are declared only under TYPE_CHECKING so the original four GatewaySession dataclass fields, constructor and serialization remain unchanged (verified by inspecting dataclasses.fields). The uv lock update reconciles the already-declared receipts extra; no new runtime dependency was added.

The retry helper uses case-insensitive string comparison rather than constructing Headers during reads, preserving its tested behavior on arbitrary Unicode values. Outgoing header stores and retry copies use httpx.Headers and preserve repeated values. Security checks reject malformed trust material instead of filtering or stringifying it.

## Suppressions (final locations)

| Site | Suppression | Invariant / reason |
|---|---|---|
| scripts/mutation_check.py:54 | `# noqa: S603 -- Fixed Python module argv, shell disabled.` | As stated inline. |
| src/trustedrouter/__main__.py:345 | `# noqa: BLE001 -- CLI boundary emits a nonzero error envelope for arbitrary command failures.` | As stated inline. |
| src/trustedrouter/__main__.py:397 | `# noqa: BLE001 -- CLI boundary emits a nonzero error envelope for arbitrary command failures.` | As stated inline. |
| src/trustedrouter/__main__.py:439 | `# noqa: BLE001 -- CLI boundary emits a nonzero error envelope for arbitrary command failures.` | As stated inline. |
| src/trustedrouter/__main__.py:526 | `# noqa: BLE001 -- CLI boundary emits a nonzero error envelope for arbitrary command failures.` | As stated inline. |
| src/trustedrouter/_retry.py:196 | `# noqa: S311  not crypto` | As stated inline. |
| src/trustedrouter/_telemetry.py:751 | `# noqa: BLE001 -- Best-effort telemetry must never alter the inference result.` | As stated inline. |
| src/trustedrouter/_telemetry.py:871 | `# noqa: BLE001 -- Best-effort telemetry must never alter the inference result.` | As stated inline. |
| src/trustedrouter/_telemetry.py:909 | `# noqa: BLE001 -- Best-effort telemetry must never alter the inference result.` | As stated inline. |
| src/trustedrouter/_telemetry.py:1201 | `# noqa: BLE001 -- Best-effort telemetry must never alter the inference result.` | As stated inline. |
| tests/test_async_wrappers.py:24 | `type: ignore[no-untyped-def]` | Dynamic test helper intentionally accepts mock callables/crypto objects; tests retain their existing looser typing. |
| tests/test_async_wrappers.py:28 | `type: ignore[no-untyped-def]` | Dynamic test helper intentionally accepts mock callables/crypto objects; tests retain their existing looser typing. |
| tests/test_attestation.py:40 | `type: ignore[no-untyped-def]` | Dynamic test helper intentionally accepts mock callables/crypto objects; tests retain their existing looser typing. |
| tests/test_attestation.py:44 | `type: ignore[no-untyped-def]` | Dynamic test helper intentionally accepts mock callables/crypto objects; tests retain their existing looser typing. |
| tests/test_attestation.py:59 | `type: ignore[no-untyped-def]` | Dynamic test helper intentionally accepts mock callables/crypto objects; tests retain their existing looser typing. |
| tests/test_attestation.py:101 | `type: ignore[arg-type]` | Test passes a dynamic override dictionary into the typed policy constructor. |
| tests/test_cli.py:19 | `type: ignore[no-untyped-def]` | Dynamic test helper intentionally accepts mock callables/crypto objects; tests retain their existing looser typing. |
| tests/test_cli.py:23 | `type: ignore[no-untyped-def]` | Dynamic test helper intentionally accepts mock callables/crypto objects; tests retain their existing looser typing. |
| tests/test_oauth.py:39 | `type: ignore[no-untyped-def]` | Dynamic test helper intentionally accepts mock callables/crypto objects; tests retain their existing looser typing. |
| tests/test_oauth.py:181 | `type: ignore[no-untyped-def]` | Dynamic test helper intentionally accepts mock callables/crypto objects; tests retain their existing looser typing. |
| tests/test_oauth.py:306 | `type: ignore[attr-defined]` | Test asserts an SDK error attribute through the existing broader caught-error type. |
| tests/test_session.py:616 | `# noqa: BLE001 -- Relay thread failures to test assertions.` | As stated inline. |
| tests/test_sync_wrappers.py:15 | `type: ignore[no-untyped-def]` | Dynamic test helper intentionally accepts mock callables/crypto objects; tests retain their existing looser typing. |
| tests/test_sync_wrappers.py:140 | `type: ignore[no-untyped-def]` | Dynamic test helper intentionally accepts mock callables/crypto objects; tests retain their existing looser typing. |
| tests/test_sync_wrappers.py:147 | `type: ignore[assignment,misc]` | Test swaps and restores the httpx constructor factory at its existing patch seam. |
| tests/test_sync_wrappers.py:151 | `type: ignore[assignment,misc]` | Test swaps and restores the httpx constructor factory at its existing patch seam. |

Broad catches without Ruff suppressions are also deliberate: session cleanup always rethrows; receipt attestation wraps failures into ReceiptAttestationError; telemetry lifecycle catches log, return explicit telemetry failure or conditionally rethrow in strict mode. CLI/session `suppress(Exception)` blocks only close resources after their result/error has already been determined. They do not parse shapes or change trust results.

## Mutation proof results

The runner uses a temporary copy, checks every recorded pattern and every focused baseline, then restores original bytes held in memory in `finally`. A surviving mutant, stale/ambiguous pattern, timeout, collection/import error, or non-test failure exits nonzero. Tests separately exercise interruption restoration, stale-pattern rejection and survivor/invalid-proof rejection. Focused invocations use `pytest -q file::test` with the full-suite coverage threshold disabled only for those focused runs. CI's full pytest retains the 87% gate.

Final complete run: **73 / 73 killed**, **9 / 9 static probes rejected**, **58.83 seconds** including focused baselines, copying and static proofs. Each result is a genuine pytest test failure, not a collection failure.

| Mutation | Source location | Focused test | Result / wall seconds |
|---|---|---|---|
| oauth-exchange | src/trustedrouter/oauth.py:241 | `tests/test_oauth.py::test_auth_wire_fixtures` | killed / 1.276 |
| oauth-userinfo | src/trustedrouter/oauth.py:256 | `tests/test_oauth.py::test_auth_wire_fixtures` | killed / 0.452 |
| json-error | src/trustedrouter/_errors.py:132 | `tests/test_deep_hardening.py::test_successful_malformed_json_is_typed` | killed / 0.473 |
| text-delta | src/trustedrouter/_sse.py:136 | `tests/test_deep_hardening.py::test_text_delta_shapes` | killed / 0.496 |
| collector-choices | src/trustedrouter/_collect.py:37 | `tests/test_deep_hardening.py::test_collector_shapes` | killed / 0.449 |
| collector-delta | src/trustedrouter/_collect.py:64 | `tests/test_deep_hardening.py::test_collector_shapes` | killed / 0.418 |
| collector-tools | src/trustedrouter/_collect.py:139 | `tests/test_deep_hardening.py::test_collector_tool_shapes` | killed / 0.420 |
| collector-tool-function | src/trustedrouter/_collect.py:159 | `tests/test_deep_hardening.py::test_collector_tool_shapes` | killed / 0.410 |
| collector-tool-arguments | src/trustedrouter/_collect.py:166 | `tests/test_deep_hardening.py::test_collector_tool_shapes` | killed / 0.411 |
| collector-function | src/trustedrouter/_collect.py:178 | `tests/test_deep_hardening.py::test_collector_tool_shapes` | killed / 0.410 |
| collector-function-arguments | src/trustedrouter/_collect.py:184 | `tests/test_deep_hardening.py::test_collector_tool_shapes` | killed / 0.412 |
| stream-options | src/trustedrouter/_collect.py:268 | `tests/test_deep_hardening.py::test_stream_options_shape` | killed / 0.422 |
| _client_sync.py-default-headers | src/trustedrouter/_client_sync.py:139 | `tests/test_deep_hardening.py::test_header_merges_sync` | killed / 0.474 |
| _client_sync.py-retain-headers | src/trustedrouter/_client_sync.py:146 | `tests/test_deep_hardening.py::test_header_merges_sync` | killed / 0.454 |
| _client_sync.py-request-headers | src/trustedrouter/_client_sync.py:241 | `tests/test_deep_hardening.py::test_header_merges_sync` | killed / 0.466 |
| _client_sync.py-stream-headers | src/trustedrouter/_client_sync.py:297 | `tests/test_deep_hardening.py::test_header_merges_sync` | killed / 0.461 |
| _client_async.py-default-headers | src/trustedrouter/_client_async.py:131 | `tests/test_deep_hardening.py::test_header_merges_async` | killed / 0.476 |
| _client_async.py-retain-headers | src/trustedrouter/_client_async.py:137 | `tests/test_deep_hardening.py::test_header_merges_async` | killed / 0.510 |
| _client_async.py-request-headers | src/trustedrouter/_client_async.py:236 | `tests/test_deep_hardening.py::test_header_merges_async` | killed / 0.512 |
| _client_async.py-stream-headers | src/trustedrouter/_client_async.py:291 | `tests/test_deep_hardening.py::test_header_merges_async` | killed / 0.552 |
| stream-assembly | src/trustedrouter/_requests.py:200 | `tests/test_deep_hardening.py::test_stream_header_assembly` | killed / 0.744 |
| retry-verdict | src/trustedrouter/_retry.py:85 | `tests/test_deep_hardening.py::test_retry_headers_any_case` | killed / 1.304 |
| retry-ms | src/trustedrouter/_retry.py:169 | `tests/test_deep_hardening.py::test_retry_headers_any_case` | killed / 0.914 |
| retry-seconds | src/trustedrouter/_retry.py:178 | `tests/test_deep_hardening.py::test_retry_headers_any_case` | killed / 0.540 |
| telemetry-policy-catch | src/trustedrouter/_telemetry.py:1041 | `tests/test_telemetry_reporter.py::test_policy_does_not_swallow_programming_errors` | killed / 0.440 |
| open_weights | src/trustedrouter/models.py:161 | `tests/test_models.py::test_catalog_boolean_metadata` | killed / 0.439 |
| us_provider_available | src/trustedrouter/models.py:165 | `tests/test_models.py::test_catalog_boolean_metadata` | killed / 0.516 |
| eu_focused_provider_available | src/trustedrouter/models.py:169 | `tests/test_models.py::test_catalog_boolean_metadata` | killed / 0.418 |
| release-pins | src/trustedrouter/attestation.py:135 | `tests/test_attestation.py::test_release_pin_shapes` | killed / 0.505 |
| jwt-shapes | src/trustedrouter/attestation.py:203 | `tests/test_attestation.py::test_jwt_object_shapes` | killed / 0.449 |
| jwt-encoding | src/trustedrouter/attestation.py:201 | `tests/test_attestation.py::test_jwt_non_ascii_encoding` | killed / 0.486 |
| jwks-shapes | src/trustedrouter/attestation.py:229 | `tests/test_attestation.py::test_jwks_shapes` | killed / 0.621 |
| jwk-numbers | src/trustedrouter/attestation.py:245 | `tests/test_attestation.py::test_jwk_numbers` | killed / 0.501 |
| rsa-numbers | src/trustedrouter/attestation.py:257 | `tests/test_attestation.py::test_jwk_numbers` | killed / 0.442 |
| hardware-shape | src/trustedrouter/attestation.py:299 | `tests/test_attestation.py::test_nested_claim_shapes` | killed / 0.492 |
| container-shapes | src/trustedrouter/attestation.py:330 | `tests/test_attestation.py::test_nested_claim_shapes` | killed / 0.491 |
| nonce-shapes | src/trustedrouter/attestation.py:366 | `tests/test_attestation.py::test_nested_claim_shapes` | killed / 0.470 |
| jwks-json | src/trustedrouter/attestation.py:481 | `tests/test_attestation.py::test_jwks_malformed_json` | killed / 0.487 |
| receipt-kid | src/trustedrouter/receipts.py:272 | `tests/test_receipts.py::test_receipt_untrusted_scalar_shapes` | killed / 0.491 |
| receipt-domain | src/trustedrouter/receipts.py:412 | `tests/test_receipts.py::test_receipt_untrusted_scalar_shapes` | killed / 0.505 |
| receipt-kind | src/trustedrouter/receipts.py:608 | `tests/test_receipts.py::test_receipt_untrusted_scalar_shapes` | killed / 0.517 |
| receipt-json | src/trustedrouter/receipts.py:489 | `tests/test_receipts.py::test_embedded_receipt_malformed_json` | killed / 0.513 |
| receipt-issuer | src/trustedrouter/receipts.py:700 | `tests/test_receipts.py::test_unicode_issuer_is_typed` | killed / 0.612 |
| tls-recv | src/trustedrouter/session.py:235 | `tests/test_session.py::test_recv_requires_bytes` | killed / 1.447 |
| transport-request-sync | src/trustedrouter/_transport.py:143 | `tests/test_deep_hardening.py::test_header_merges_sync` | killed / 1.125 |
| transport-stream-sync | src/trustedrouter/_transport.py:291 | `tests/test_deep_hardening.py::test_header_merges_sync` | killed / 0.573 |
| transport-request-async | src/trustedrouter/_transport.py:212 | `tests/test_deep_hardening.py::test_header_merges_async` | killed / 0.480 |
| transport-stream-async | src/trustedrouter/_transport.py:381 | `tests/test_deep_hardening.py::test_header_merges_async` | killed / 0.459 |
| header-helper-case | src/trustedrouter/_headers.py:8 | `tests/test_deep_hardening.py::test_retry_headers_any_case` | killed / 0.436 |
| metadata-catch-_requests.py | src/trustedrouter/_requests.py:180 | `tests/test_deep_hardening.py::test_metadata_fallback_is_narrow` | killed / 0.451 |
| metadata-catch-_telemetry.py | src/trustedrouter/_telemetry.py:116 | `tests/test_deep_hardening.py::test_metadata_fallback_is_narrow` | killed / 0.469 |
| wire-must-not-require-data | src/trustedrouter/oauth.py:250 | `tests/test_oauth.py::test_auth_wire_fixtures` | killed / 0.535 |
| oauth-guard-key | src/trustedrouter/oauth.py:242 | `tests/test_oauth.py::test_auth_wire_fixtures` | killed / 1.128 |
| oauth-guard-user-id | src/trustedrouter/oauth.py:245 | `tests/test_oauth.py::test_auth_wire_fixtures` | killed / 1.402 |
| oauth-guard-identity-object | src/trustedrouter/oauth.py:260 | `tests/test_oauth.py::test_auth_wire_fixtures` | killed / 0.435 |
| oauth-guard-identity-strings | src/trustedrouter/oauth.py:265 | `tests/test_oauth.py::test_auth_wire_fixtures` | killed / 0.463 |
| trust-guard-release-object | src/trustedrouter/attestation.py:135 | `tests/test_attestation.py::test_release_pin_shapes` | killed / 0.464 |
| trust-guard-release-scalar | src/trustedrouter/attestation.py:169 | `tests/test_attestation.py::test_release_pin_shapes` | killed / 0.458 |
| trust-guard-release-list | src/trustedrouter/attestation.py:176 | `tests/test_attestation.py::test_release_pin_shapes` | killed / 0.493 |
| trust-guard-jwks-object | src/trustedrouter/attestation.py:232 | `tests/test_attestation.py::test_jwks_shapes` | killed / 0.637 |
| trust-guard-jwks-list | src/trustedrouter/attestation.py:235 | `tests/test_attestation.py::test_jwks_shapes` | killed / 0.805 |
| trust-guard-submods | src/trustedrouter/attestation.py:331 | `tests/test_attestation.py::test_nested_claim_shapes` | killed / 1.153 |
| trust-guard-container | src/trustedrouter/attestation.py:334 | `tests/test_attestation.py::test_nested_claim_shapes` | killed / 1.106 |
| trust-guard-image-strings | src/trustedrouter/attestation.py:338 | `tests/test_attestation.py::test_nested_claim_shapes` | killed / 0.509 |
| trust-guard-kid | src/trustedrouter/attestation.py:230 | `tests/test_attestation.py::test_jwks_kid_shape` | killed / 0.510 |
| oauth-data-guard | src/trustedrouter/oauth.py:250 | `tests/test_oauth.py::test_auth_wire_fixtures` | killed / 0.438 |
| text-choices-guard | src/trustedrouter/_sse.py:137 | `tests/test_deep_hardening.py::test_text_delta_shapes` | killed / 0.462 |
| text-first-choice-guard | src/trustedrouter/_sse.py:142 | `tests/test_deep_hardening.py::test_text_delta_shapes` | killed / 0.512 |
| text-delta-guard | src/trustedrouter/_sse.py:145 | `tests/test_deep_hardening.py::test_text_delta_shapes` | killed / 0.599 |
| collector-choices-guard | src/trustedrouter/_collect.py:38 | `tests/test_deep_hardening.py::test_collector_shapes` | killed / 1.059 |
| collector-choice-guard | src/trustedrouter/_collect.py:41 | `tests/test_deep_hardening.py::test_collector_shapes` | killed / 0.850 |
| collector-tool-array-guard | src/trustedrouter/_collect.py:141 | `tests/test_deep_hardening.py::test_collector_tool_shapes` | killed / 0.852 |
| collector-tool-item-guard | src/trustedrouter/_collect.py:144 | `tests/test_deep_hardening.py::test_collector_tool_shapes` | killed / 0.453 |

| Reintroduced static defect | Expected diagnostic | Result |
|---|---|---|
| unproven-object | attr-defined | rejected |
| untyped-decode | BND001 | rejected |
| cast-laundering | BND002 | rejected |
| scalar-laundering | BND002 | rejected |
| plain-header-read | BND003 | rejected |
| plain-header-copy | BND003 | rejected |
| blind-except | BLE001 | rejected |
| blanket-type-ignore | PGH003 | rejected |
| blanket-noqa | PGH004 | rejected |

## Wire fixture and verification

Fixture SHA-256: `ba492afe81f7616bca062ab7ed35f70d42042e6f6f60794ac9e2a599574df1d2`. The copied file and the supplied shared source are byte-identical. `test_auth_wire_fixtures` executes all accepts/rejects through real sync and async HTTP parsing paths and verifies full exchange-payload retention and unwrapped identity retention. The `wire-must-not-require-data` mutation fails on the literal minimal producer payload.

Final full pytest: **522 passed, 1 skipped**, **88.48%** branch-inclusive coverage, gate **87%**. Cross-repo conformance: **25 checks, 25 passed, 0 failed, 0 skipped**. The sandbox can bind loopback; conformance is not sandbox-blocked. One pytest test skips intentionally because it only applies when pyOpenSSL is absent and that dependency is installed.

Local environment: uv's default user cache is sandbox-denied, so commands use `UV_CACHE_DIR=/tmp/tr-uv-cache` and `$HOME/.local/bin` on PATH. The preselected Anaconda Python 3.10.9 crashed launching pytest; the environment was rebuilt with the installed `/opt/homebrew/bin/python3.12`. Python 3.10 remains the declared/checked language target. The first conformance launch omitted the cache override and all drivers were blocked on that cache; rerunning with the override passed all 25. No network/bind skips were hidden.

## Changed-file index (final source locations)

Each line below lists every changed hunk's new starting line, plus all added files. Locations in the original audit table intentionally remain pre-change locations.

| File | Changed hunk starts | Purpose |
|---|---|---|
| .github/workflows/ci.yml | 19, 22 | CI order and new gates |
| .github/workflows/release.yml | 26, 29 | CI order and new gates |
| pyproject.toml | 55, 74, 85 | Strict source typing, expanded Ruff and 87% coverage |
| src/trustedrouter/__init__.py | 129, 133, 170, 171, 174, 178, 191, 218, 223, 224, 231, 234 | explicit public reexports; no external parsing |
| src/trustedrouter/__main__.py | 23, 225, 230, 320, 345, 352, 376, 397, 404, 418, 439, 446, 505, 526, 533 | argparse/environment strings and validated SDK results; terminal errors emit nonzero exit status; cleanup only |
| src/trustedrouter/_client_async.py | 131, 137, 236, 291 | typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths |
| src/trustedrouter/_client_sync.py | 139, 146, 241, 297 | typed caller parameters/local kwargs; response parsing delegated to guarded JSON/SSE/Pydantic paths |
| src/trustedrouter/_collect.py | 37, 39, 42, 64, 139, 141, 145, 160, 166, 178, 180, 184, 268 | Mapping/list checks precede traversal; accumulated choice/tool state initialized locally; opaque metadata copied |
| src/trustedrouter/_errors.py | 123, 132 | Mapping guards before extraction; string rendering is diagnostic only; raw payload retained |
| src/trustedrouter/_orchestration.py | 11, 214 | caller configuration, local dictionaries and typed builder arguments; no decoded response access |
| src/trustedrouter/_requests.py | 14, 180, 200, 203 | local request dictionaries; key-lowercasing credential/reserved removal; broadcast headers are JSON configuration |
| src/trustedrouter/_retry.py | 71, 85, 169, 178 | typed controller state; bounded numeric header parsing catches invalid values; jitter is not cryptographic |
| src/trustedrouter/_sse.py | 39, 67, 136, 141 | decoded object checked; generic SSE events intentionally wrap non-object data as opaque metadata |
| src/trustedrouter/_telemetry.py | 22, 52, 116, 751, 871, 909, 1041, 1142, 1161, 1190, 1201, 1207, 1264, 1596 | internal telemetry/config normalization and guarded policy Mapping; optional diagnostics cannot determine inference success |
| src/trustedrouter/_transport.py | 53, 72, 76, 88, 143, 212, 291, 381 | SDK-built kwargs and replay controller state; HTTPX response headers; narrow transport errors or cleanup rethrows |
| src/trustedrouter/attestation.py | 27, 36, 135, 167, 198, 201, 203, 230, 245, 250, 257, 299, 303, 330, 366, 447, 451, 481, 575, 580 | JWT and JWKS checked before use; claims constraints fail closed; trusted crypto/time outputs |
| src/trustedrouter/client.py | 1, 137 | compatibility reexports; no external parsing |
| src/trustedrouter/models.py | 29, 153, 161, 165, 169 | Pydantic validates known shapes and preserves extras; internal attributes have validated container types |
| src/trustedrouter/oauth.py | 42, 241, 248, 256 | URL encoding of typed caller arguments; HTTP parsing delegated to _json_or_raise and identity guards |
| src/trustedrouter/receipts.py | 158, 160, 163, 272, 412, 488, 608, 700 | decoded mappings and required string/integer guards before use; trust failures typed; capture postpones full verification |
| src/trustedrouter/session.py | 13, 17, 22, 29, 33, 55, 68, 235, 418, 447, 456, 509 | typed socket/crypto adapter values; lowercase wire header names; duplicate framing detection; cleanup rethrows |
| tests/test_attestation.py | 508 | Focused regression coverage / lint compliance |
| tests/test_attestation_properties.py | 185 | Focused regression coverage / lint compliance |
| tests/test_deep_hardening.py | 256 | Focused regression coverage / lint compliance |
| tests/test_models.py | 6, 202 | Focused regression coverage / lint compliance |
| tests/test_oauth.py | 287, 290, 390 | Focused regression coverage / lint compliance |
| tests/test_receipts.py | 720, 812 | Focused regression coverage / lint compliance |
| tests/test_session.py | 616, 663 | Focused regression coverage / lint compliance |
| tests/test_telemetry_reporter.py | 551 | Focused regression coverage / lint compliance |
| uv.lock | 999, 1019, 1024 | Synchronize existing receipts extra metadata |
| src/trustedrouter/_headers.py | 1 (new file) | Shared case-insensitive read helper |
| scripts/boundary_check.py | 1 (new file) | Syntactic static boundary checks |
| scripts/mutation_check.py | 1 (new file) | Isolated fail-closed mutation runner |
| scripts/mutations.json | 1 (new file) | Exact source mutations and focused tests |
| tests/test_mutation_check.py | 1 (new file) | Runner failure and restoration safety tests |
| tests/fixtures/auth-wire-fixtures.json | 1 (new file) | Verbatim shared producer payloads |
| docs/boundary-audit.md | 1 (new file) | Pre-change audit and final evidence |

Final locally green command sequence (with `UV_CACHE_DIR=/tmp/tr-uv-cache` and the installed uv on PATH):

```sh
uv run python scripts/boundary_check.py
uv run ruff check . && uv run mypy && uv run pytest -q && uv run python scripts/mutation_check.py
```

The final recorded mutation run added `--report /tmp/router-mutation-results.json` to retain per-case timings; its checks are identical. A separate `uv run mypy --strict src/trustedrouter` also passed. `git diff --check` passed. Changes remain uncommitted in the worktree.
