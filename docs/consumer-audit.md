# Consumer artifact and CLI audit

This wave changes packaging, documentation, and tests; no SDK/CLI implementation
or runtime dependency changed. Tests are intentionally excluded from both release
artifacts. The sdist remains sufficient to build the wheel.

## Published contents: before and after

| Artifact | Before | After |
|---|---|---|
| Wheel | [27 files](consumer-artifacts/before-wheel.txt) | [27 files](consumer-artifacts/after-wheel.txt) |
| Sdist | [76 files](consumer-artifacts/before-sdist.txt) | [27 files](consumer-artifacts/after-sdist.txt) |

Both wheels contain the same 21 Python modules and `py.typed`. The README is
embedded in METADATA; the license is included under `.dist-info/licenses/LICENSE`.

Before, the sdist shipped tests, receipt/auth fixtures, scripts, workflows,
CODEOWNERS, docs, changelog, security policy, uv.lock, and .gitignore.
After, it contains only those 22 package files, LICENSE, README.md,
pyproject.toml, PKG-INFO, and .gitignore. No tests, fixtures, scripts, CI or scratch ship.

The build backend remains hatchling. The wheel selects `src/trustedrouter` with
`packages`; the sdist selects it with `only-include`. Hatchling automatically adds
required metadata and `.gitignore`, which its sdist builder always includes.
The tests build using `uv build` (sdist then wheel from that sdist) and independently
assert exact archive allowlists, including `py.typed`. The mutation copy retains
`.gitignore` so it verifies the same layout as the worktree build.

Commands used from the repository root, both before and after:

```sh
export PATH="$HOME/.local/bin:$PATH"
export UV_CACHE_DIR=/private/tmp/trustedrouter-uv-cache
uv sync --group dev
uv build
unzip -l dist/*.whl
tar tzf dist/*.tar.gz
```

The sandbox denies uv's default user cache, so the cache is under /private/tmp.
The development interpreter is the installed `/opt/homebrew/bin/python3.12`;
the language minimum remains 3.10. The declared Python versions are 3.10–3.14;
this local verification uses 3.12, not a five-interpreter matrix.

## Metadata diff

| Field | Before | After |
|---|---|---|
| Description | Official Python SDK and CLI for TrustedRouter. | Unchanged, verified in wheel |
| License | Apache-2.0 plus legacy license classifier | SPDX Apache-2.0, explicit LICENSE file; obsolete classifier removed |
| Python minimum | >=3.10 | Unchanged, verified |
| Keywords | Absent | trustedrouter, llm, sdk, attestation, openai |
| URLs | Homepage, Repository, Trust | Adds Documentation (repository README) and Issues |
| Python classifiers | Generic Python 3 / Only | Adds 3.10, 3.11, 3.12, 3.13, 3.14 |
| Typing | Typing :: Typed, py.typed | Retained; wheel metadata, file list and strict external consumer verified |

## Command × option coverage

Before: source-tree unit tests existed, but **zero installed-artifact CLI tests**.
After: **72 cases × 2 entry points = 144 subprocess tests**, each launched from
an external temporary directory. Both `python -m trustedrouter` and the generated
`trustedrouter` script execute the installed wheel.

Every row below had no installed-wheel coverage before and has both-entry-point
coverage now. Root options and each subcommand's help aliases are exercised
explicitly, not inferred from parser construction.

| Command | Options / input covered | Output and failure checks |
|---|---|---|
| Root | `-h`, `--help`, `--version`, `--json`, `--retries 0/1/-1` | Help, plain/JSON version, missing/unknown command, invalid retries; actual retry counted |
| chat | `-h`, `--help`, `--json` before/after command, `-m`, `--model`, `--max-tokens`, `--stream` | Plain text, full completion JSON, exact JSONL delta/done records; chosen model and token limit on wire |
| chat input | positional prompt, implicit stdin, explicit `-`, empty/mixed stdin | Preserved whitespace, input errors, blank model, zero max tokens, missing key, HTTP 401/500 |
| regions | `-h`, `--help`, global/local `--json` | Plain catalog, envelope and data ID, HTTP 401/500 |
| providers | `-h`, `--help`, global/local `--json` | Plain catalog, envelope and data ID, HTTP 401/500 |
| models | `-h`, `--help`, global/local `--json` | Plain catalog, envelope and data ID, HTTP 401/500 |
| trust | `-h`, `--help`, global/local `--json` | Plain trust release, envelope/image digest, HTTP 401/500 |
| attest | `-h`, `--help`, global/local `--json` | Raw signed JWT, document envelope, HTTP 401/500 |
| attest verify | `--verify`, global/local `--json` | Real RSA/JWKS/identity verification and serialized result, HTTP failures |
| attest session | `--session`, `--connect-ip`, global/local `--json` | Attestation/followup/exporter schema, plain diagnostics, session failure; IP requires session and cannot be empty |

JSON successes use stdout, JSON errors stderr; tests assert the other stream is
empty. Exit codes 0, 1, 2, 3 are checked. Existing behavior is preserved: raw
attestation's HTTP failures, including 401, surface as `trusted_router_error`
with exit 1, while chat/catalog/trust HTTP 401 gives authentication_error/3.

HTTPX MockTransport handles requests in the installed subprocess. Attestation
and receipt examples use locally generated signatures and actual SDK verification.
Only live TLS session establishment/followup is replaced with a small test double;
these tests prove CLI dispatch and serialization, not a real TLS exporter.
Wave 1 and conformance retain their separate protocol checks.

## Documentation execution

All fenced examples in README.md and recursively under docs are discovered at
test collection. All 17 README Python blocks compile and execute against the
installed wheel and fake HTTPX transport. Independent snippets receive an open
client/response and explicitly supplied application context (OAuth redirect/store
callbacks, user/order IDs, and a signed receipt). Top-level await is wrapped in
an async function; the original code is compiled first. No library methods are
stubbed in these examples.

JSON blocks are parsed; all shell blocks are compiled with `bash -n`. Installation
and development shell examples are deliberately not run recursively. Unknown
fence languages fail instead of silently skipping examples.

Fixed examples: an Ellipsis message and idempotency key, missing logging/time
imports, invalid JSON ellipsis, and attestation's unsent nonce/separate-socket
binding claim. The attestation example now verifies signed workload identity
and points readers to the session API/CLI for live binding. Contributing commands
now match the CI gates and 87% coverage threshold.

## Exact scratch consumer commands

These commands were executed, not just proposed. The copied consumer imports the
public sync/async clients, typed response and routing preferences, OAuth helper,
and fusion builder. It checks editor-visible method documentation, type-checks
strictly and makes sync/async calls through MockTransport. No fake transport
startup module or repository source path is used for this separate smoke.

```sh
export PATH="$HOME/.local/bin:$PATH"
export UV_CACHE_DIR=/private/tmp/trustedrouter-uv-cache
uv build
uv venv --python /opt/homebrew/bin/python3.12 /private/tmp/trustedrouter-audit/consumer
uv pip install --python /private/tmp/trustedrouter-audit/consumer/bin/python "$PWD/dist/trusted_router_py-0.7.0-py3-none-any.whl" mypy
cp tests/consumer/smoke.py /private/tmp/trustedrouter-audit/consumer/smoke.py
cd /private/tmp/trustedrouter-audit/consumer
env -u PYTHONPATH -u MYPYPATH ./bin/python -m mypy --strict smoke.py
env -u PYTHONPATH -u MYPYPATH ./bin/python smoke.py
env -u PYTHONPATH ./bin/python -c 'import trustedrouter; print(trustedrouter.__file__)'
```

Results: mypy succeeds; runtime prints `installed consumer passed`; import origin
is `/private/tmp/trustedrouter-audit/consumer/lib/python3.12/site-packages/trustedrouter/__init__.py`.
The automated fixture repeats this in a fresh external venv, asserts that origin,
and builds/installs only the local artifact.

## Mutation proofs and verification

The full suite passed **697 tests, with 1 intentional skip**, at **88.48%**
branch-inclusive coverage (required: 87%). The skip checks behavior when pyOpenSSL
is absent; the dev environment installs it. Ruff, mypy, the static boundary gate,
uv build, and git diff --check passed. Conformance passed **25/25**, with no
skips or loopback binding restriction.

The first full run encountered Hypothesis's generation-speed health check during
concurrent CPU-heavy test runs. A complete rerun passed. No test settings or coverage requirements were relaxed.

[Wave 1's final log](consumer-artifacts/wave1-mutations.txt) records **73 killed
mutants and 9 rejected static probes**. The
[final conformance log](consumer-artifacts/conformance.txt) records each scenario.

The consumer mutation gate runs baselines first, requires pytest assertion failures
(exit 1, never setup/collection errors), checks every CLI node in both mutation
passes, and restores original bytes in finally. All work occurs in a temporary
copy. The checked-in runner is also in both CI and release workflows.

**All 27 consumer mutation scenarios were killed**, producing 314 expected assertion
failures after a green 175-check baseline. [The complete transcript](consumer-artifacts/consumer-mutations.txt) names every one of the 144 CLI cases
under both wrong-exit and wrong-output mutations. Both wheel and sdist rejected
the injected package stray file independently. Every mutation restored its
original bytes. The final minimum-version mutant relaxes the requirement to
>=3.9 (so installation still works on Python 3.10); its focused proof also passed.

| Mutation | Expected failing test nodes | Result |
|---|---:|---|
| artifact-stray | 2 | killed |
| metadata-keywords | 1 | killed |
| typed-marker | 1 | killed |
| consumer-type | 1 | killed |
| consumer-runtime | 1 | killed |
| readme-python | 1 | killed |
| readme-shell | 1 | killed |
| readme-json | 1 | killed |
| cli-exit-every-case | 144 | killed |
| cli-output-every-case | 144 | killed |
| metadata-description | 1 | killed |
| metadata-minimum-python | 1 | killed |
| metadata-license | 1 | killed |
| metadata-license-file | 1 | killed |
| metadata-typing-classifier | 1 | killed |
| metadata-homepage-url | 1 | killed |
| metadata-documentation-url | 1 | killed |
| metadata-issues-url | 1 | killed |
| metadata-repository-url | 1 | killed |
| metadata-trust-url | 1 | killed |
| metadata-python-3.10 | 1 | killed |
| metadata-python-3.11 | 1 | killed |
| metadata-python-3.12 | 1 | killed |
| metadata-python-3.13 | 1 | killed |
| metadata-python-3.14 | 1 | killed |
| metadata-readme | 1 | killed |
| consumer-docstrings | 1 | killed |

Commands verified locally: `uv sync --group dev`, `uv run ruff check .`,
`uv run python scripts/boundary_check.py`, `uv run mypy`, `uv run pytest`,
`uv run python scripts/mutation_check.py`,
`uv run python scripts/consumer_mutation_check.py`, and `uv build`.
The hatchling revision reran the harness as `/private/tmp/claude-501/-Users-jperla-josh/733bc505-7008-406e-bff3-ff2a10df6555/scratchpad/sdk-conformance/.venv/bin/tr-conformance --sdk python --sdk-root python="$PWD"`.
The strict scratch commands and literal before/after listings are above.
Changes remain uncommitted in the worktree.

## Changed-file index

All changed files and each edited README/configuration region are indexed here.
New files are linked at line 1, with key test locations called out separately.

| File:line | Change |
|---|---|
| `pyproject.toml:8` | Explicit license file and keywords |
| `pyproject.toml:16` | Remove deprecated license classifier; retain Python-only and Typed; enumerate Python 3.10–3.14 |
| `pyproject.toml:32` | Documentation and issue URLs |
| `pyproject.toml:40` | Retain hatchling; wheel package selection and sdist only-include |
| `README.md:227` | Imports and executable messages in typed-error example |
| `README.md:360` | Executable workload identity attestation example |
| `README.md:378` | Explain live-session binding separately |
| `README.md:479` | Valid machine-readable JSON example |
| `README.md:535` | Concrete string idempotency key |
| `README.md:569` | Full CI command set and actual 87% coverage threshold |
| `tests/test_consumer.py:1` | Artifact fixture, command matrix and example extraction suite |
| `tests/test_consumer.py:61` | Build and install into a fresh external project |
| `tests/test_consumer.py:90` | Independent exact wheel/sdist file lists |
| `tests/test_consumer.py:113` | Wheel metadata and embedded README |
| `tests/test_consumer.py:137` | Strict consumer types, documentation, runtime and installed import origin |
| `tests/test_consumer.py:164` | Every command/option matrix; 72 cases and two entry points |
| `tests/test_consumer.py:221` | Exit, output envelopes/JSONL, stream separation and wire option assertions |
| `tests/test_consumer.py:278` | Automatic README/docs extraction, compile/execute, shell syntax and JSON parsing |
| `tests/consumer/smoke.py:1` | Copyable strict sync/async public-API consumer, no optional runtime extras |
| `tests/consumer/sitecustomize.py:1` | Offline HTTPX, real signed JWT/JWK and receipt fixtures |
| `tests/consumer/sitecustomize.py:143` | Explicit live TLS test boundary |
| `scripts/consumer_mutation_check.py:1` | Temporary-copy fail-closed mutation proofs and restoration |
| `.github/workflows/ci.yml:23` | Run consumer mutation gate |
| `.github/workflows/release.yml:30` | Gate releases on the same consumer mutation proofs |
| `docs/consumer-artifacts/before-wheel.txt:1` | Literal pre-change unzip listing |
| `docs/consumer-artifacts/before-sdist.txt:1` | Literal pre-change tar listing |
| `docs/consumer-artifacts/after-wheel.txt:1` | Literal final unzip listing |
| `docs/consumer-artifacts/after-sdist.txt:1` | Literal final tar listing |
| `docs/consumer-audit.md:1` | Audit, coverage matrix, scratch commands, results and source index |

| Additional evidence file:line | Contents |
|---|---|
| `docs/consumer-artifacts/wave1-mutations.txt:1` | Every final Wave 1 mutation/static rejection |
| `docs/consumer-artifacts/conformance.txt:1` | All 25 passing conformance scenarios |
| `docs/consumer-artifacts/consumer-mutations.txt:1` | All 27 consumer mutations and every CLI node rejection |
