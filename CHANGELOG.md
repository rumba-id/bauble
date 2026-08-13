# Changelog

All notable changes to bauble. Entries describe what changed; they do not
restate coverage totals. Run `bauble coverage` for current figures.

## v2.0.0 — 2026-08-13

Three-layer conformance architecture. Each assertion is classified by the
kind of conformance it establishes: Wire (protocol-unit correctness),
Semantic (operation meaning), or Capability (advertised vs. behavior). The
`Layer` field flows through the model, the journal record, and the summary
reporter, which gains a per-layer rollup and a per-OID capability table.

A stdlib-only raw BER+socket wire layer reaches protocol-unit edges that
ldap3 cannot construct or parse: malformed BER, indefinite-length encoding,
messageID semantics. RFC 4511 gained wire and semantic assertions —
messageID echo, indefinite-length rejection, malformed-filter handling,
filter evaluation, matching-rule behavior, DN attribute-name case,
ModifyDN newSuperior, alias dereferencing, referral handling.

Honest `UNTESTABLE` records replaced placeholder behavior for requirements
with no portable test.

Coverage figures now live only in `bauble coverage`, not in committed docs.

## v1.4.0 — 2026-08-12

389 Directory Server test target. The same seed DIT loads into a second
implementation, enabling cross-implementation comparison. The runner gains
`--target-type 389ds`.

## v1.3.0 — 2026-08-12

RFC 4513 StartTLS security assertions. The runner gains `--starttls`.

## v1.2.0 — 2026-08-12

Formal assertion record: `preconditions`, `stimulus`, and
`expected_observables` fields on every assertion, tying each test to the
observable it verifies. Renamed `AUTO_PASS` to `NOT_APPLICABLE` and
reorganized profiles into Interop, Core, and Extended tiers.

## v1.1.0 — 2026-08-12

Extended conformance coverage across additional RFCs. Feature gates on
`MUST`/`SHALL` requirements were removed: an advertised feature that fails
at runtime now reports `FAIL` with detail instead of `NOT_APPLICABLE`,
which surfaced real server gaps. The advertise-then-test pattern drives
`NOT_APPLICABLE` only when the server genuinely does not claim support.
Added raw wire helpers (assertion, matched-values, pre/post-read control
BER) and `RawConnection` methods (`bind_then_send`, `modify_increment`,
`raw_send`).

## v1.0.0 — 2026-08-12

Initial release. Assertion-driven conformance model with a
severity/testability split; registry-based auto-discovery (one RFC = one
self-registering module); profiles and scenarios as selections over the
registry; capability-driven `NOT_APPLICABLE`. A high-level ldap3-backed
`Session` for positive and most negative paths, and a raw stdlib BER+socket
layer for protocol-unit edges. Podman OpenLDAP target with a deterministic
seed DIT. Reporters: text, journal (JSON lines, source of truth), summary,
junit.
