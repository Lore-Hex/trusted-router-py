from trustedrouter.attestation import (
    AttestationVerificationError,
    GatewayAttestation,
    verify_gateway_attestation,
)
from trustedrouter.client import (
    AUTO_MODEL,
    DEFAULT_API_BASE_URL,
    DEFAULT_TRUST_RELEASE_URL,
    REGION_HOSTS,
    AsyncTrustedRouter,
    AuthenticationError,
    BadRequestError,
    InternalError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    TrustedRouter,
    TrustedRouterError,
    fetch_trust_release,
    region_base_url,
)

__version__ = "0.2.0"

__all__ = [
    "AUTO_MODEL",
    "AsyncTrustedRouter",
    "AttestationVerificationError",
    "AuthenticationError",
    "BadRequestError",
    "DEFAULT_API_BASE_URL",
    "DEFAULT_TRUST_RELEASE_URL",
    "GatewayAttestation",
    "InternalError",
    "NotFoundError",
    "PermissionDeniedError",
    "REGION_HOSTS",
    "RateLimitError",
    "TrustedRouter",
    "TrustedRouterError",
    "__version__",
    "fetch_trust_release",
    "region_base_url",
    "verify_gateway_attestation",
]
