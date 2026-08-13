# v2.x Roadmap — Toward a Fully Auditable Conformance Suite

Synthesis of two external reviews of bauble. The first (pre-2.0) validated the
architecture — assertion-as-atomic-unit, prerequisite graph (`BLOCKED`), the
`Session` protocol seam, isolation semantics, profiles-as-selections, and
self-validation via the golden fake — and named cross-implementation
validation as the next milestone. The second (post-2.0) validated v2.0.0 —
the requirements corpus making coverage measurable, the three-layer
Wire/Semantic/Capability model, multi-implementation, and the corpus catching
our own 4516 → 4512 misattribution — and shifted the danger:

> "Does each assertion faithfully cover the normative requirement it claims to
> cover?"

Both reviews converge on the same end state: a suite whose verdicts are
**auditable** — each assertion traces through
*RFC statement → formalized assertion → preconditions → stimulus →
observable(s) → oracle → verdict*, coverage is measured against the
specification, and the whole thing is continuously verified.

This roadmap lays out the 2.x releases in dependency order. Each release
delivers a prerequisite for the next.

| Release | Theme | Delivers |
|---|---|---|
| 2.1 | Fidelity & auditability | assertion-requirement fidelity audit; auditable assertion metadata; intrinsic-gap reasons | **shipped in v2.1.0** |
| 2.2 | Coverage & capability | PARTIALLY_COVERED ontology; advertise-check coverage growth; capability model completion | **shipped in v2.2.0** |
| 2.3 | Continuous verification | full-suite CI against all targets; verdict-regression gate; journal artifacts | **shipped in v2.3.0** |
| 2.4 | Broad applicability | third test target; seed-DIT portability | third target + portability shipped in v2.2.0's cycle |
| 2.5 | Wire completeness (conditional) | raw `Session` if the wire-UNTESTABLE count justifies it | **decision recorded in v2.3.0: no raw Session; count was small and the existing layer sufficed** |

---

## v2.1 — Fidelity & auditability

The prerequisite for everything after: assertions must provably cover the
requirements they claim to cover, and that chain must be readable.

1. **Assertion-fidelity audit.** For each requirement, verify its
   `covered_by` assertion(s) exercise the full normative statement. Same pass
   that caught 4516 → 4512; expect more of those classes (wrong-RFC
   attribution, misinterpreted requirement, non-normative assumption,
   conflated requirements, ignored conditions). Fix mis-covers; list
   under-covered requirements as the `PARTIALLY_COVERED` candidates for 2.2.
2. **Auditable assertion metadata.** Populate `preconditions`,
   `stimulus`, and `expected_observables` on the audited assertions. Today
   only a small minority carry them; the reviewers' chain is
   not yet readable from the data model.
3. **Intrinsic-gap reasons.** The class-B requirements that are genuinely
   untestable (atomicity, uniqueness, client-side) get their reason recorded
   on the requirement, so `bauble coverage` shows *why* they are uncovered.

Done when: an audit report is committed; every mis-cover is fixed or
explicitly accepted; the audited assertions carry the full chain metadata.

**Shipped in v2.1.0.** The audit command, the corpus expansion to the RFC
4511 operation sections, the chain metadata on every testable assertion, the
intrinsic-gap notes, and the fidelity review (which caught and fixed two
vacuous assertions and moved the RFC 4511→4512 misattribution) are all in.
Findings and the PARTIAL candidates for 2.2 live in
`docs/v2.1-fidelity-review.md`.

## v2.2 — Coverage & capability

Grow coverage against the audited corpus, and complete the applicability
model so new assertions gate correctly.

1. **PARTIALLY_COVERED ontology.** Each requirement gains explicit
   independently-testable obligations, each with its own `covered_by`.
   `bauble coverage` reports COVERED / PARTIALLY_COVERED / UNCOVERED.
   Sequenced after 2.1 so the obligation split is grounded in the audit.
2. **Coverage growth.** Eight SHOULD-advertise requirements are testable via
   the existing advertise-check pattern (2696, 2891, 3062, 3866, 4512, 4527,
   4529, 4532) — done, all eight land with capability-layer assertions.
   The 389 DS-specific finding investigation is also done; genuine
   deviations (RFC 4526 empty filters, auth-choice `protocolError`,
   language range-on-add acceptance, no `@objectclass` expansion) are
   asserted and documented in `docs/server-findings.md`, and three suspected
   deviations (entryDN, caseIgnoreMatch, integerMatch) were resolved as
   suite bugs and fixed.
3. **Capability model completion.** The capability file gains
   `supported_sasl_mechanisms` (deferred from Phase 7, never landed) and
   `supported_features:<oid>` — done. The completion also fixed a real
   gating bug: the RFC 4525 increment assertions passed bare OIDs to
   `requires_features`, which the capability never matched, so they were
   permanently NOT_APPLICABLE since v2.0.0 and had never run live; they now
   run and pass on OpenLDAP. Both fixtures ship capability statements
   declared from live root-DSE probes, and `bauble run --target` loads the
   fixture's statement by default.

Done when: `bauble coverage` reports the three coverage states; the advertise
assertions land and pass on both targets; SASL/feature applicability is
capability-gated.

**Shipped in v2.2.0.** All three items done. Coverage reports the three
states; the PARTIALLY_COVERED obligations are rendered by
`bauble coverage`; genuine per-server deviations are asserted and recorded
in `docs/server-findings.md`. The v2.4 target work (OpenDJ + LLDAP
fixtures, operator guide) landed in the same cycle.

## v2.3 — Continuous verification

Make the conformance reports a CI artifact instead of a manually generated
snapshot. Today CI runs only the smoke tests (`test_live.py`,
`test_live_389ds.py`); the full suite is never CI-verified against either
target.

1. Run the full suite against OpenLDAP and 389 DS in CI and fail on verdict
   regression (new FAILs, new UNTESTABLEs, coverage drops).
2. Emit and archive the journals/summaries as build artifacts so every commit
   has an auditable conformance report attached.

Done when: CI is green only if all targets' full reports match the expected
verdict set.

**Shipped in v2.3.0.** The four live CI jobs (one per target) run the smoke test
plus the verdict-regression gate: the full core profile's assertion ->
status set must equal `ci/golden/<target>.txt`. Journals are uploaded as
build artifacts per target. Goldens regenerate intentionally with
`BAUBLE_UPDATE_GOLDEN=1`; drift detection caught and fixed a real bug on
the way in (RFC 4528's assertion control used the double-SEQUENCE wire
form OpenLDAP does not honor, so FALSE assertions silently succeeded on
OpenLDAP and OpenDJ).

## v2.4 — Broad applicability

Demonstrate the "any LDAPv3 implementation" claim beyond two servers, and
make the seed a portable input rather than a harness-only convention.

1. **Third test target** — OpenDJ and LLDAP landed as podman fixtures
   (fixtures/opendj.py, fixtures/lldap.py, capability statements, live
   tests, `--target-type opendj|lldap`). OpenDJ is the enterprise Java
   endpoint; LLDAP is the minimal read-mostly interface. Both surfaced
   new findings recorded in docs/server-findings.md.
2. **Seed-DIT portability** — the operator guide
   (docs/operator-guide.md) covers loading the seed into a non-fixture
   server, the capability statement as the declared lever, and the
   per-server adjustments (admin DN, anonymous-read policy, schema
   gaps, subschema discovery).
2. **Seed-DIT portability** — the base seed is a bauble convention; real
   servers differ (ACL policy, subschema location, schema). Document how an
   operator loads the seed and adjusts for these; the capability file is the
   declared lever, and the 389 DS work (anonymous-read, subschema discovery)
   is the template.

Done when: three targets run the full suite in CI; an operator guide covers
loading the seed into a non-fixture server.

## v2.5 — Wire completeness (conditional)

Re-run the UNTESTABLE-due-to-wire count after 2.1–2.4. If the count justifies
it, build the raw `Session` implementing the `Session` protocol (the seam the
pre-2.0 review praised) so wire-level assertions stop depending on what ldap3
can express. If not, record the decision with the count, as the pre-2.0
review recommended. No raw layer is built on speculation.

**Shipped in v2.3.0. Decision (recorded): no full raw `Session`.** The wire-UNTESTABLE count
was 3 of 6 class-B assertions (the abandon pair and caseExactMatch). All
three were implementable with the existing raw layer plus a minimal
`RawSession` (a persistent socket for bind + abandon + follow-up — a dozen
lines, not the full `Session` protocol): `4511.4.11.1` (abandon in-progress,
now passes on all four targets), `4511.4.11.2` (abandon unknown messageID,
passes everywhere except OpenLDAP's large-messageID disconnect — a genuine
finding), `4517.4.6` (caseExactMatch via an extensible-match filter, passes
except LLDAP's missing extensible-match support — a genuine finding). The
remaining three untestable (messageID uniqueness, BER BOOLEAN encoding,
controls-field position) are client-side statements — not wire limitations,
and no raw `Session` could test them.

---

## Non-goals

- A dedicated Security profile.
- Replication / content-sync (RFC 3384, 3928, 4533) and transaction (5805)
  suites.
- LDAPv2 (RFC 1777) testing.
- GUI.

## Definition of done for the series

A reviewer can pick any assertion and trace *RFC statement → assertion →
preconditions → stimulus → observable → oracle → verdict*; `bauble coverage`
reports covered/partially-covered/uncovered against an audited corpus; CI
attaches a full conformance report for four implementations to every green
commit.

**Met with v2.3.0.** The remaining untestable requirements are client-side
statements with recorded reasons; the wire-UNTESTABLE count is zero.
