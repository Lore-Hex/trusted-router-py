"""Verify signed release membership separately from the live gateway evidence."""

from __future__ import annotations

import hashlib
import json
import re

from trustedrouter.attestation import AttestationPolicy, AttestationVerificationError

_IDENTITY = (
    "https://github.com/Lore-Hex/quill-cloud-proxy/"
    ".github/workflows/publish-trust-gcp.yml@refs/heads/main"
)
_ISSUER = "https://token.actions.githubusercontent.com"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate signed policy field")
        result[key] = value
    return result


def verify_signed_gcp_release(
    document: bytes,
    bundle: bytes,
    checkpoint: str,
    digest: str,
) -> AttestationPolicy:
    if not (
        0 < len(document) <= 65536
        and 0 < len(bundle) <= 262144
        and hashlib.sha256(document).hexdigest() == checkpoint
        and _DIGEST.fullmatch(digest)
    ):
        raise AttestationVerificationError("GCP release checkpoint, digest or size is invalid")
    try:
        from sigstore.errors import Error
        from sigstore.models import Bundle
        from sigstore.verify import Verifier
        from sigstore.verify.policy import Identity
    except ImportError as exc:
        raise AttestationVerificationError("install trustedrouter[provenance]") from exc
    try:
        proof = Bundle.from_json(bundle)
        Verifier.production().verify_artifact(
            input_=document,
            bundle=proof,
            policy=Identity(identity=_IDENTITY, issuer=_ISSUER),
        )
        _check_membership(document, digest)
    except (ValueError, Error, RecursionError) as exc:
        raise AttestationVerificationError("GCP release provenance verification failed") from exc
    return AttestationPolicy(expected_image_digest=digest)


def _check_membership(document: bytes, digest: str) -> None:
    policy: object = json.loads(document.decode("utf-8"), object_pairs_hook=_unique)
    if (
        not isinstance(policy, dict)
        or policy.get("schema") != "tr.stage-d-accepted/1"
        or policy.get("plane") != "gcp"
        or policy.get("kind") not in ("final", "transitional")
        or type(policy.get("sequence")) is not int
        or policy["sequence"] < 1
    ):
        raise ValueError("unexpected GCP policy schema or sequence")
    images = policy.get("image_digests")
    if (
        not isinstance(images, list)
        or digest not in images
        or not all(isinstance(i, str) and _DIGEST.fullmatch(i) for i in images)
    ):
        raise ValueError("selected image not in signed GCP policy")
