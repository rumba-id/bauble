# Changelog

## v1.0.0 — 2026-08-12

Initial release. An open-source, implementation-independent LDAP RFC
conformance test suite.

### Conformance coverage

- **14 RFCs** covered (4511, 4512, 4514–4519, 2696, 2891, 3062, 4532)
- **59 assertions** — 57 testable (all PASS on OpenLDAP), 2 UNTESTABLE
  (abandon — intrinsic timing dependence)
- Base profile: must(A) 53/53 CONFORMANT
- Standard profile: must(A) 4/4 CONFORMANT

### Core architecture

- Assertion-driven model with severity/testability split. A `MUST` with no
  portable test is surfaced as `UNTESTABLE`, not silently dropped.
- Registry-based auto-discovery: add an RFC suite by dropping a module.
- Profiles and scenarios are selections over the registry, not separate code.
- Capability declaration drives AUTO_PASS for unsupported features.

### Client layers

- High-level `ldap3`-backed Session for positive-path and most negative-path
  assertions (constructible controls, readable result codes/matchedDN/
  referrals).
- Raw wire-layer Session (stdlib-only BER + socket, zero additional
  dependencies) for assertions the high-level client cannot reach: unknown
  protocol versions, empty-password binds, malformed PDUs, control-value BER.

### Test target

- Podman container with OpenLDAP, deterministic seed DIT preloaded via
  `slapadd` at build time. Long-lived container with self-cleaning mutations;
  fresh-per-run is opt-in.

### Reporting

- Four output formats: text (stdout), journal (JSON lines — source of truth),
  summary (per-RFC + per-profile verdict), junit (CI XML).
- Conformance verdict: conformant iff every MUST class-A assertion is PASS
  or AUTO_PASS.

### CLI

```bash
uv run bauble run --profile base --target --reporter summary
uv run bauble run --rfc 4511 --server ldap://host:389 --reporter journal
```
