import hashlib
from pathlib import Path

import pytest
from sigstore.verify import Verifier

from trustedrouter import _release_provenance
from trustedrouter.attestation import AttestationVerificationError, policy_from_signed_gcp_release

# Public artifacts signed at Lore-Hex/quill-cloud-proxy@c7b93ab28f45.
FIXTURES = Path(__file__).parent / "fixtures"
CHECKPOINT = "33011aa4a6d7629b3bd53091e2b9315b3e9a6e5e6b5d642241859b539f1447d7"
IMAGE = "sha256:b2a25b3e06a43927dd8f4ed194d6878543647fe542b279a8512ec53c4e24c016"


@pytest.mark.parametrize(
    "case",
    [
        "valid",
        "old checkpoint",
        "other image",
        "substitution",
        "wrong workflow",
        "wrong issuer",
        "missing bundle",
    ],
)
def test_signed_release(case, monkeypatch):
    original = Verifier.production
    monkeypatch.setattr(Verifier, "production", lambda: original(offline=True))
    if case == "wrong workflow":
        monkeypatch.setattr(_release_provenance, "_IDENTITY", "unapproved-workflow")
    if case == "wrong issuer":
        monkeypatch.setattr(_release_provenance, "_ISSUER", "unapproved-issuer")
    doc = (FIXTURES / "stage-d-accepted.json").read_bytes()
    bundle = (FIXTURES / "stage-d-accepted.json.bundle").read_bytes()
    checkpoint = CHECKPOINT
    if case == "substitution":
        doc += b" "
        checkpoint = hashlib.sha256(doc).hexdigest()

    def verify():
        return policy_from_signed_gcp_release(
            doc,
            b"" if case == "missing bundle" else bundle,
            expected_policy_sha256="wrong" if case == "old checkpoint" else checkpoint,
            expected_image_digest="sha256:" + "a" * 64 if case == "other image" else IMAGE,
        )

    if case == "valid":
        p = verify()
        assert p.expected_image_digest == IMAGE
        assert not p.expected_image_digests  # Never import the entire transitional list.
    else:
        with pytest.raises(AttestationVerificationError):
            verify()
