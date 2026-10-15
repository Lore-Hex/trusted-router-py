# Security Policy

## Reporting a vulnerability

Use GitHub's **[private vulnerability reporting](../../security/advisories/new)**
for this repository. Reports stay visible only to maintainers while they are
investigated, and the same thread carries the fix and any advisory.

Please do not open a public issue for a suspected vulnerability.

Include what you can — affected version or commit, reproduction steps, and the
impact you believe it has. A partial report sent early is more useful than a
complete one sent late.

## What to expect

- **Acknowledgement within 72 hours.**
- An assessment of severity and affected components within 5 business days.
- Notification when a fix ships, and credit in the advisory unless you ask us
  not to.

There is no bug bounty programme.

We treat any suspected exposure of customer content as the highest severity by
default, and we notify affected users without waiting for a root-cause analysis
to finish.

## Scope

This policy covers the code in this repository.

For the **hosted TrustedRouter service** rather than this source, report through
private vulnerability reporting on
[Lore-Hex/quill-router](https://github.com/Lore-Hex/quill-router/security/advisories/new).
The service runs inside hardware-attested confidential computing environments;
published measurements and how to verify them are at
https://trustedrouter.com/trust

## Attestation guarantees

Every gateway attestation this SDK verifies reports a `binding`, and the
claim is exactly that strong:

| `binding` | Checked beyond the token itself |
|---|---|
| `"tls-exporter"` | The token commits to the RFC 9266 exporter of the caller's own TLS session (`verify_gateway_session`). |
| `"tls-cert"` | The token commits to the SHA-256 of the DER certificate the caller supplied from its connection. |
| `"none"` | Nothing about the connection. `verify_gateway_attestation_document` requires a fresh caller nonce in `eat_nonce`. |

The token checks under every binding are Google's signature, issuer,
audience, expiry, the production Confidential Space claims, and the image
pins from the published trust release.

In scope: a verifier that returns when any of those checks should fail, or
that reports a stronger `binding` than it checked. Out of scope: the
documented limit of `binding: "none"` — anything that can reach the gateway
can obtain a valid document for your nonce and still handle your traffic
itself.

## Safe harbour

We will not pursue or support legal action against anyone who reports a
vulnerability in good faith, avoids privacy violations and service degradation,
and gives us reasonable time to respond before disclosing.
