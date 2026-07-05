# Changelog

## 0.4.0

- Changed the default inference API base to `https://api.trustedrouter.com/v1`.
- Added `DEFAULT_CONTROL_BASE_URL` and `control_base_url=` for control-plane calls.
- Routed catalog, account, billing, OAuth, and broadcast calls to the control
  plane at `https://trustedrouter.com/v1` by default.
- Kept `base_url=` scoped to inference-plane calls; overriding `base_url` no
  longer affects catalog, account, billing, OAuth, or broadcast calls.
- Changed regional failover to re-request the global load-balancer apex and
  removed per-region hostnames.
