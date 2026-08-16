# Changelog

All notable changes to bauble. Entries describe what changed; they do not
restate coverage totals. Run `bauble coverage` for current figures.

## v2.3.1 — 2026-08-16

Version-field and documentation reconciliation. No code changes. The v2.x
releases advanced the architecture but never bumped the packaging metadata:
`pyproject.toml` still declared 2.0.0 (last bumped for the v2.0.0 tag) and
`bauble.__version__` still declared 1.0.0. Both now match this tag, `uv.lock`
is regenerated, and the README version badge is corrected.

The README refresh that landed on main after v2.3.0 — documentation index,
operator-guide and server-findings links, current badge, target examples —
is folded into this release.

## v2.3.0 — 2026-08-13

Continuous verification. The full core profile's verdict set is now a
committed contract per target (`ci/golden/<target>.txt`), and CI runs it
against all four implementations — OpenLDAP, 389 DS, OpenDJ, LLDAP. A
live run whose assertion-to-status mapping drifts from the golden fails
the job, so a new FAIL, a lost PASS, or a classification change requires
an intentional, reviewed golden update. Conformance journals are uploaded
as per-target build artifacts; every green commit on main carries an
auditable report.

Standing the gate up surfaced and fixed real suite defects:

- The RFC 4528 assertion control used the double-SEQUENCE controls wire
  form OpenLDAP does not honor (the same bug class as the v2.1 4527
  fix), so FALSE assertions silently returned success on OpenLDAP and
  OpenDJ. The single-SEQUENCE form fixed it; the assertions now pass on
  all servers.
- The 3045 NO-USER-MODIFICATION check modified the root DSE through
  ldap3, which refuses empty DNs client-side; it now uses the raw layer
  and passes on 389 DS and OpenDJ.
- Two advertise checks (4528.2.1, 6171.3.1) were class B with real
  runners that could never run; promoted to class A. Per-target
  UNTESTABLE dropped 5 -> 3.
- 5020.2.4 / 4512.3.2 crashed on ldap3's client-side schema check for
  servers without entryDN / creatorsName; now clean FAIL / NOT_APPLICABLE.

The wire-completeness conditional (v2.5) was evaluated: the three
wire-testable class-B assertions (the abandon pair and caseExactMatch)
were implemented with a minimal raw session — no full raw `Session` is
justified. New findings recorded: OpenLDAP disconnects on abandons whose
unknown messageID exceeds an internal bound (~2^15) instead of silently
discarding them (RFC 4511 §4.11); LLDAP's filter parser lacks
extensible-match filters. The remaining three untestable requirements
(messageID uniqueness, BER BOOLEAN encoding, controls-field position) are
client-side statements with recorded reasons.

## v2.2.0 — 2026-08-13

Coverage & capability. Coverage is now three-state: a requirement can be
split into independently-testable obligations, and `bauble coverage`
reports COVERED / PARTIALLY_COVERED / UNCOVERED per RFC with a
per-obligation detail section. The first obligations come from the v2.1
fidelity review's PARTIAL candidates — a requirement whose easy half is
tested can no longer read as fully covered.

The eight SHOULD-advertise requirements gained capability-layer
assertions (PASS when advertised, NOT_APPLICABLE otherwise).

The capability model gained `supported_features` and
`supported_sasl_mechanisms`; the completion fixed a real gating bug —
the RFC 4525 increment assertions passed bare OIDs that the capability
never matched, so they had been permanently NOT_APPLICABLE since v2.0.0
and never ran live. They now run and pass. Both fixtures ship capability
statements declared from live probes, and `bauble run --target` applies
the fixture's own admin credentials automatically.

The 389 DS finding investigation resolved each suspected deviation:
genuine ones are asserted and documented in `docs/server-findings.md`
(empty-filter rejection, auth-choice protocolError, language
range-on-add acceptance, no `@objectclass` expansion); three suspected
deviations (entryDN case sensitivity, caseIgnore seed assumption,
integerMatch ordering) were suite bugs and are fixed.

Two new test targets land — the two ends of the conformance spectrum:
OpenDJ (Java, enterprise) and LLDAP (Rust, minimal read-mostly LDAP
interface), both podman fixtures with `--target-type`, capability
statements, and live tests. The suite now spans four implementations;
each surfaced its own findings.

`docs/operator-guide.md` covers loading the seed into a non-fixture
server and declaring capability.

## v2.1.0 — 2026-08-13

Assertion-fidelity audit. Every testable assertion now carries the auditable
chain — preconditions, stimulus, expected_observables — and the new
`bauble audit` command reads that chain per requirement: cross-RFC links,
per-requirement audit status, and a rollup.

The requirement corpus was expanded to cover RFC 4511's operation sections,
whose assertions previously had no corpus requirements behind them.

The fidelity audit caught and fixed real defects:

- Two assertions were vacuously passing: their raw searches used a malformed
  present filter that matched no entries, so they passed on the result code
  alone. The raw layer gained SearchResultEntry parsing, and the
  matched-values (RFC 3876) and `@objectclass` (RFC 4529) assertions now
  verify actual returned content.
- The Pre/Post-Read assertions now verify the response control is present
  instead of only that the update applied.
- Password Modify now proves the password actually changed, not just that the
  operation returned success.
- Who-Am-I verifies the returned authorization identity and the empty
  anonymous case.
- Vendor-info assertions now enforce NO-USER-MODIFICATION.
- An assertion filed under RFC 4511 was moved to RFC 4512, where the
  normative statements (objectClass protection, operational-attribute
  read-only) actually live.
- The unrecognized-extended-request check was tightened to the protocolError
  result code the standard requires.

The audit surfaced a genuine server finding: 389 DS does not implement RFC
4529 `@objectclass` expansion. `docs/v2.1-fidelity-review.md` records the
method, the fixes, and the PARTIAL candidates that seed the v2.2 coverage
work.

The requirements model gained a `note` field; accepted cross-RFC links and
intrinsic untestability reasons are now documented in the corpus and shown by
the audit.

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
