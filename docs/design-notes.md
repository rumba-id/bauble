# Design Notes

Rationale for bauble's conformance-testing model. These notes explain the
decisions behind the assertion model, profiles, selection, execution, and
reporting so contributors understand why the suite is shaped the way it is.

## Assertion as the atomic unit

Every test maps to one normative requirement from an RFC, stated as an
assertion. Each assertion carries:

- **ID** — a structured identifier (see below).
- **Test class** — whether the requirement can be tested portably.
- **Severity** — the requirement strength from RFC 2119.
- **Profile** — which capability tier the assertion belongs to.
- **Text** — the requirement, stated in plain language.
- **Section** — the RFC section the assertion verifies.
- **Strategy** — how the test is realized, including a
  `PROCEDURE / INPUT / EXPECTED` block where useful.

Asserting at the requirement level — rather than writing free-form tests —
keeps coverage traceable to the RFC text and makes gaps visible. A reader
can answer "which RFC requirements does this suite verify?" by reading the
assertion list.

## Assertion IDs

IDs are dotted-decimal `w.x.y.z`:

- `w` identifies the source RFC.
- `x.y` is the section and subsection of that RFC.
- `z` is the assertion number within that section.

A structured ID lets assertions be grouped, selected, and cross-referenced
without parsing prose, and lets a conformance report point back to the exact
RFC section it is making a claim about. bauble uses the RFC 4510 series as
its `w` namespace.

## Testability is separate from severity

RFCs express requirement strength with RFC 2119 keywords
(`MUST` / `SHOULD` / `MAY`). But many requirements — even `MUST` ones —
cannot be tested portably. They depend on server-internal timing, on state a
network client cannot observe, or on access to protocol units (PDUs) below
what a client library exposes. Examples include "abandon an in-flight
operation", "generate an unsolicited notification", or "every entry has an
objectClass".

If severity and testability shared one axis, the suite would either
over-claim coverage (marking untestable requirements as passing) or lose
them (silently dropping them). So bauble tracks two independent axes:

- **Severity** — `MUST` / `SHOULD` / `MAY`.
- **Test class** — testable vs. untestable.

A `MUST` requirement with no portable test is recorded as `UNTESTABLE` with
the reason, not silently omitted. The conformance report then states
honestly what was actually verified.

## Coverage boundary

bauble drives the server under test through a high-level LDAP client for
most operations. That choice buys portability and a small dependency
surface. Most negative paths are reachable, because an error can usually
be triggered with a *valid operation on bad data*: binding with wrong
credentials (`invalidCredentials`), adding a duplicate entry
(`entryAlreadyExists`), comparing a missing attribute (`noSuchAttribute`),
or attaching an unknown-critical control (the client lets you build a
control with any OID and criticality and attach it to a search,
exercising `unavailableCriticalExtension`). Result codes, the `matchedDN`
field, and referral fields are all readable on the response.

What the client library genuinely cannot do is send a *structurally
invalid* protocol unit. For that class bauble ships a stdlib-only raw
BER+socket layer (`bauble.raw`, added in v2.0.0): malformed BER,
indefinite-length encodings, arbitrary protocol versions, empty-DN
modifies, control-carrying PDUs ldap3 will not construct, and multi-step
wire sequences (bind + abandon on one session). Wire-format malformation
is therefore testable, and the wire assertions carry `layer = WIRE`.

The remaining `UNTESTABLE` records are *intrinsic* — requirements no
client can verify portably because they are client-side statements,
exhaustiveness claims over all entries, or unobservable server-internal
behavior (see the corpus `note` fields for the recorded reasons). A raw
sender would not help those either.

Unreachable requirements are not silently dropped. Each is recorded as
`UNTESTABLE` with the reason, and reporters surface the `UNTESTABLE` count
per profile and per layer so the boundary is visible in every report.

## Profiles

Three profiles organize assertions into increasing capability tiers:

- **Interop** — minimum needed to interoperate: simple bind; search, add,
  delete, modify, modify DN; over TCP.
- **Core** — the main LDAPv3 conformance surface: root DSE, operational
  attributes, controls, extended operations, language features.
- **Extended** — optional extensions such as read-entry controls.

Interop is a prerequisite for Core: a server that fails core operations
cannot be meaningfully judged on the extended surface.

## Profiles and scenarios are selections, not code

A profile or scenario is a set of assertion IDs. The same assertion can
belong to many selections. Tests are written once; selections only decide
which to run. This avoids duplicating test logic per profile and keeps the
registry flat. An operator can also build an ad-hoc selection (a single RFC,
a single assertion, a category) without writing new tests.

## Capability declaration

Some requirements only apply if the server advertises a feature — a root-DSE
attribute, a supported control, or a supported extended operation. bauble
takes a capability statement from the operator declaring which optional
features the target server implements.

When a feature is declared unsupported, its presence test auto-passes. The
server genuinely does not implement the feature, so its absence is
conformant, not a failure. Assertions declare their applicability with
`requires_features` (currently the RFC 4525 increment assertions gate on
the advertised feature OID); a bare `--server` run starts from a
non-writable statement so mutations require `--allow-mutation` or an
explicit `writable = true`.

## Execution model: prerequisites and blocked propagation

LDAP operations depend on one another. A server that cannot bind cannot be
meaningfully tested for search; a server whose add fails cannot be tested
for modify. bauble models assertions and RFCs as a prerequisite graph that
mirrors the RFC dependency tree. Tests run in dependency order, and when a
prerequisite fails its dependents are marked `BLOCKED` rather than `FAIL`.
A single early failure then produces one real failure plus a set of
honestly-blocked dependents, not a cascade of misleading failures.

## Test isolation

Conformance assertions are destructive: add, modify, modify-DN, and delete
mutate the directory, and LDAP has no baseline transactions (RFC 5805
transactions are optional and out of scope for Interop). Left unmanaged, one
assertion's leftover entry changes another's outcome, and two runs of the
same suite disagree because the directory drifted between them.

bauble distinguishes two kinds of target:

- **Test target** — a disposable server the operator owns (typically a
  containerized instance). The harness seeds it and can reset it freely.
- **Server under test** — a real server whose data must not be touched
  destructively. bauble treats it as read-only by default.

Isolation then rests on three guarantees:

- **Known DIT at run start (test target only).** The harness seeds a fixed
  base directory before a run and can reset it between runs, so every run
  starts from identical state. Reset is authoritative — subtree wipe and
  reseed, or a container restart for the disposable target — never
  best-effort, because a leftover entry would make the next run drift and
  false-fail.
- **Self-cleaning mutations (always).** Each mutating assertion creates the
  entry it needs, asserts, and removes it in a `finally` block, so it never
  pollutes sibling assertions within a run — even against a server that
  cannot be reset.
- **Capability gating.** The capability statement carries `writable` and
  `resettable` flags. When `writable` is false, mutating assertions
  `NOT_APPLICABLE`. Seed and reset run only against a target whose `resettable`
  is true.

Safety boundary: bauble never seeds or wipes a server it does not own.
  Running mutating assertions against a live server under test requires an
  explicit `--allow-mutation` opt-in; even then bauble does per-assertion
  cleanup but performs no whole-DIT reset, so the conformance verdict for the
  mutating surface against a live server is best-effort, not authoritative.

## Result statuses

- **PASS** — assertion holds.
- **FAIL** — assertion violated.
- **NOT_APPLICABLE** — requirement conditional on an unimplemented
  optional feature the server does not claim to support.
- **SKIP** — excluded by the operator's selection.
- **BLOCKED** — a prerequisite failed.
- **UNTESTABLE** — no portable test exists.

A conformance verdict for a profile: every mandatory, testable assertion in
the profile is `PASS` or `NOT_APPLICABLE`, with no `FAIL`. Optional (`SHOULD`/
`MAY`) failures are reported as warnings, not conformance failures.
## Reporting

bauble emits four reporters over one record format:

- A **journal** — JSON lines, the raw machine-readable record of every
  assertion and its result, denormalized so it is self-contained. This is
  the source of truth, suitable for archival and for diffing results
  across runs or server versions.
- A **summary** — human rollup: per-RFC and per-profile verdicts, a
  per-layer rollup, a per-OID capability table, and an overall verdict.
- **text** — per-assertion lines plus a status count.
- **junit** — JUnit XML for CI integration.

The journal is primary; the summary is derived from it. CI gates verdicts
against per-target goldens (`ci/golden/`), so a verdict change requires an
intentional, reviewed golden update.

## Core-profile fixtures

Core-profile assertions need a richer directory than Interop. The base
seed (`src/bauble/fixtures/seed.ldif`) provides it:

- An **alias entry** (`uid=alice-alias` → `uid=alice`) for the
  derefAliases assertions.
- A **referral entry** (`ou=remote`, pointing at a URL the server does
  not manage) for the continuation-reference assertion — the client
  inspects the returned reference and does not follow it.

No second server is required: the referral target is never contacted.
The seed is a bauble convention (RFCs define no minimal DIT);
`docs/operator-guide.md` covers loading it into a non-fixture server.

## Requirements corpus and coverage

The assertion registry answers "what does bauble test?" but not "what does the
RFC require?" or "what is still uncovered?". The requirements corpus closes
that gap.

For each RFC, a TOML file under `src/bauble/requirements/` lists every
normative statement (MUST/SHOULD/MAY) with its section, severity, testability
class, the requirement text, and the assertion ids that verify it
(`covered_by`). Coverage is then measurable as the intersection of assertions
and requirements: a requirement with no covering assertion is a surfaced gap,
not a silent omission. SHALL is normalized to MUST (RFC 2119). The corpus owns
the link — assertions are not edited to point at requirements — so changing an
assertion never silently breaks a requirement link, and a test fails if a
`covered_by` id names an assertion that no longer exists.

`bauble coverage` is the single, live source of these facts. It prints
assertion counts (by class, severity, layer, profile, RFC) and, from the
corpus, per-RFC requirement coverage plus the list of uncovered requirements.
Nothing is committed to the docs: the registry and corpus are the source of
truth and the command reads them at run time, so the figures can never drift
or go stale.

## What bauble targets

- The modern RFC 4510-4519 series.
- Python with `ldap3` as the LDAP client engine.
- A single `bauble` CLI; no external test controller.
- MIT-licensed and open-source.
