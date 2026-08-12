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
- **Ref** — the RFC section the assertion verifies.
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

## Profiles

Three profiles organize assertions into increasing capability tiers:

- **BASE** — core operations: simple bind, search, add, delete, modify,
  modify DN; over TCP and TLS.
- **STANDARD** — builds on BASE: root DSE, alias dereferencing, operational
  attributes, controls, extended operations, referrals, continuation
  references.
- **ADVANCED** — optional surfaces such as SASL controls and the
  extensibleObject object class.

Base is a prerequisite for Standard: a server that fails core operations
cannot be meaningfully judged on the advanced surface.

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
conformant, not a failure. The capability statement also lets bauble target
extended-operation tests at OIDs the server actually supports.

## Execution model: prerequisites and blocked propagation

LDAP operations depend on one another. A server that cannot bind cannot be
meaningfully tested for search; a server whose add fails cannot be tested
for modify. bauble models assertions and RFCs as a prerequisite graph that
mirrors the RFC dependency tree. Tests run in dependency order, and when a
prerequisite fails its dependents are marked `BLOCKED` rather than `FAIL`.
A single early failure then produces one real failure plus a set of
honestly-blocked dependents, not a cascade of misleading failures.

## Result statuses

- **PASS** — assertion holds.
- **FAIL** — assertion violated.
- **AUTO_PASS** — requirement does not apply (feature declared unsupported).
- **SKIP** — excluded by the operator's selection.
- **BLOCKED** — a prerequisite failed.
- **UNTESTABLE** — no portable test exists.
- **NA** — server feature not advertised.

A conformance verdict for a profile: every mandatory, testable assertion in
the profile is `PASS` or `AUTO_PASS`, with no `FAIL`. Optional (`SHOULD`/
`MAY`) failures are reported as warnings, not conformance failures.

## Reporting

bauble emits two outputs:

- A **journal** — the raw, machine-readable record of every assertion and
  its result. This is the source of truth and is suitable for archival and
  for diffing results across runs or server versions.
- A **summary** — a human-readable rollup: per-assertion, per-RFC, and
  per-profile, ending in an overall conformance verdict.

The journal is primary; the summary is derived from it.

## Standard-profile fixtures

Standard-profile assertions need a richer directory than Base:

- **Schema extensions** beyond the core — additional attribute and object
  classes so schema-handling assertions have something to exercise.
- **Referral entries** the server returns for naming contexts it does not
  manage. The client inspects the returned URL but does not follow it.
- **Continuation references**, which require a second server holding a
  subordinate branch configured as a knowledge reference. Again the client
  inspects the reference without following it.

bauble's harness seeds these fixtures and documents the optional
second-server setup so an operator can run the Standard profile without
guessing at the DIT shape.

## What bauble targets

- The modern RFC 4510-4519 series.
- Python with `ldap3` as the LDAP client engine.
- A single `bauble` CLI; no external test controller.
- MIT-licensed and open-source.
