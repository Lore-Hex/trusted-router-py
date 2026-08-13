"""Property tests for the attestation policy boundary.

The law we care about is a soundness statement about `_check_claims`:

    for every claims set K and policy P,
        _check_claims(K, P) succeeds  =>  K's image identity was in P's accepted set

Before the non-vacuity guard this was false, and falsifiably so: a trust
release that failed to carry any image field (a truncated body, an error page
that parsed as JSON, a schema change) produced a policy whose accepted sets
were both empty, and both image checks in `_check_claims` are guarded on a
non-empty accepted set. Verification then passed for *any* genuinely-attested
Confidential Space workload while reporting success, so the client believed it
had pinned a build and had not.

`test_verified_digest_is_always_in_the_accepted_set` is the law itself.
`test_policy_from_release_never_returns_a_vacuous_policy` covers the input path
that made it reachable. The rest pin the pieces those two rest on.
"""

from __future__ import annotations

import time
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from trustedrouter.attestation import (
    AttestationPolicy,
    AttestationVerificationError,
    _check_claims,
    policy_from_trust_release,
)

# Identifiers are opaque to the policy layer, so the alphabet only needs to be
# wide enough to produce collisions and near-misses cheaply.
digests = st.text(alphabet="abcdef0123456789:", min_size=1, max_size=12)
references = st.text(alphabet="abcxyz./:-0123456789", min_size=1, max_size=16)

CERT_SHA = "a" * 64


def _claims(
    *,
    image_digest: str = "sha256:pinned",
    image_reference: str = "registry/img:pinned",
    audience: str = "quill-cloud",
) -> dict[str, Any]:
    """A claims set that passes every check *except* the image checks, so a
    property failure can only be attributed to image identity."""
    return {
        "exp": int(time.time()) + 3600,
        "iss": "https://confidentialcomputing.googleapis.com",
        "dbgstat": "disabled-since-boot",
        "swname": "CONFIDENTIAL_SPACE",
        "secboot": True,
        "hwmodel": "GCP_AMD_SEV",
        "aud": audience,
        "submods": {
            "container": {
                "image_digest": image_digest,
                "image_reference": image_reference,
            }
        },
        "tls_cert_sha256": CERT_SHA,
    }


def _verify(claims: dict[str, Any], policy: AttestationPolicy) -> Any:
    return _check_claims(
        claims,
        policy=policy,
        nonce_hex=None,
        tls_cert_der=None,
        tls_exporter=None,
    )


# ---------------------------------------------------------------- the law ---


@given(
    accepted=st.lists(digests, min_size=1, max_size=4),
    workload=digests,
)
@settings(max_examples=400)
def test_verified_digest_is_always_in_the_accepted_set(
    accepted: list[str], workload: str
) -> None:
    """Soundness: accepting implies the workload digest was pinned.

    Stated as an implication rather than as a pair of positive/negative
    examples, because the defect was precisely a policy shape under which the
    implication held vacuously.
    """
    policy = AttestationPolicy(expected_image_digests=tuple(accepted))
    claims = _claims(image_digest=workload)

    try:
        result = _verify(claims, policy)
    except AttestationVerificationError:
        return  # rejection is always sound

    assert workload in accepted
    assert result.image_digest == workload


@given(
    accepted=st.lists(references, min_size=1, max_size=4),
    workload=references,
)
@settings(max_examples=400)
def test_verified_reference_is_always_in_the_accepted_set(
    accepted: list[str], workload: str
) -> None:
    policy = AttestationPolicy(expected_image_references=tuple(accepted))
    claims = _claims(image_reference=workload)

    try:
        _verify(claims, policy)
    except AttestationVerificationError:
        return

    assert workload in accepted


# ------------------------------------------------- non-vacuity of policies ---


@given(
    release=st.dictionaries(
        keys=st.sampled_from(
            [
                "image_digest",
                "accepted_image_digests",
                "image_reference",
                "accepted_image_references",
                "unrelated",
            ]
        ),
        values=st.one_of(
            st.none(),
            st.text(max_size=8),
            st.integers(),
            st.booleans(),
            st.lists(st.one_of(st.text(max_size=8), st.integers(), st.none()), max_size=3),
            st.dictionaries(st.text(max_size=3), st.text(max_size=3), max_size=2),
        ),
        max_size=5,
    )
)
@settings(max_examples=500)
def test_policy_from_release_never_returns_a_vacuous_policy(
    release: dict[str, Any],
) -> None:
    """A policy is either refused or pins image identity — never neither.

    Quantifies over malformed releases specifically: wrong types, nulls, empty
    lists and lists of non-strings are all shapes a degraded HTTP response can
    take, and each one used to silently produce an unpinned policy.
    """
    try:
        policy = policy_from_trust_release(release=release)
    except AttestationVerificationError:
        return

    assert policy.pins_image_identity


def test_empty_release_is_refused() -> None:
    with pytest.raises(AttestationVerificationError, match="pins no image identity"):
        policy_from_trust_release(release={})


def test_release_with_only_empty_lists_is_refused() -> None:
    with pytest.raises(AttestationVerificationError, match="pins no image identity"):
        policy_from_trust_release(
            release={"accepted_image_digests": [], "accepted_image_references": []}
        )


def test_release_whose_accepted_lists_hold_no_strings_is_refused() -> None:
    """The list filter drops non-strings, which can empty a non-empty list."""
    with pytest.raises(AttestationVerificationError, match="pins no image identity"):
        policy_from_trust_release(release={"accepted_image_digests": [None, 7, ""]})


def test_verification_refuses_a_hand_built_vacuous_policy() -> None:
    """Defence in depth: the guard does not depend on going through the builder."""
    with pytest.raises(AttestationVerificationError, match="pins no image identity"):
        _verify(_claims(), AttestationPolicy())


def test_cert_only_policy_is_refused() -> None:
    """Pinning the TLS cert alone says nothing about *which build* answered."""
    with pytest.raises(AttestationVerificationError, match="pins no image identity"):
        _verify(_claims(), AttestationPolicy(expected_cert_sha256=CERT_SHA))


# ------------------------------------------------------- pins_image_identity ---


@given(
    digest=st.one_of(st.none(), digests),
    digest_set=st.lists(digests, max_size=2),
    reference=st.one_of(st.none(), references),
    reference_set=st.lists(references, max_size=2),
)
def test_pins_image_identity_agrees_with_the_checks_it_guards(
    digest: str | None,
    digest_set: list[str],
    reference: str | None,
    reference_set: list[str],
) -> None:
    """`pins_image_identity` must be exactly the disjunction of the two
    conditions that enable the image checks, or the guard and the checks can
    disagree and the hole reopens."""
    policy = AttestationPolicy(
        expected_image_digest=digest,
        expected_image_digests=tuple(digest_set),
        expected_image_reference=reference,
        expected_image_references=tuple(reference_set),
    )

    digest_check_runs = bool(policy.expected_image_digests or policy.expected_image_digest)
    reference_check_runs = bool(
        policy.expected_image_references or policy.expected_image_reference
    )

    assert policy.pins_image_identity == (digest_check_runs or reference_check_runs)
