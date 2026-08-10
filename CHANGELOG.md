# Changelog

## Unreleased

- Restructured the internals into the harmonized layered architecture
  (policy kernel / plane router / transport engine / attempt assembly /
  stream codec / error taxonomy / orchestration builders / facades), with
  `trustedrouter.client` kept as a full compatibility re-export shim. The
  public API and import paths are unchanged.
- Behavior change: streaming methods now gate the transport-error domain
  advance on `regional_failover`, matching `request()` and the documented
  intent ("`regional_failover=False` is an instruction, not a hint").
  Previously the 11 streaming loops could move a `regional_failover=False`
  client onto an alias domain after a connection failure.

## 0.4.0

- Changed the default inference API base to `https://api.trustedrouter.com/v1`.
- Added `DEFAULT_CONTROL_BASE_URL` and `control_base_url=` for control-plane calls.
- Routed catalog, account, billing, OAuth, and broadcast calls to the control
  plane at `https://trustedrouter.com/v1` by default.
- Kept `base_url=` scoped to inference-plane calls; overriding `base_url` no
  longer affects catalog, account, billing, OAuth, or broadcast calls.
- Changed regional failover to re-request the global load-balancer apex and
  removed per-region hostnames.
