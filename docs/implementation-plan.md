# Implementation Plan

Build plan for bauble: an open-source, implementation-independent LDAP RFC
conformance test suite.

This plan captures the agreed architecture and breaks it into reviewable
phases. Each phase ends with a green test suite, a clean commit, and a
working slice of the full path (`bauble run ... -> journal + summary`).

## Design principles

1. **Assertions are the atomic unit.** Every test maps to one normative
   requirement stated as an assertion, identified by a dotted-decimal ID
   `w.x.y.z` that ties it back to the RFC section it verifies.
2. **Severity and testability are orthogonal.** Severity comes from RFC 2119
   (`MUST`/`SHOULD`/`MAY`). Testability records whether a portable test
   exists. A `MUST` requirement can still be untestable.
3. **Profiles and scenarios are selections over a flat registry**, never
   duplicated test logic. A scenario is a manifest of assertion IDs.
4. **The RFC dependency tree is the prerequisite graph.** A failed
   prerequisite marks dependents `BLOCKED`, not `FAIL`.
5. **Capability declaration drives auto-pass.** Operators declare which
   optional features a server implements; presence tests for unsupported
   features `AUTO_PASS`.
6. **One RFC = one module, self-registering.** Adding an RFC suite means
   dropping a file. No central manifest to edit.

See `docs/references.md` for the full RFC dependency tree and
`docs/design-notes.md` for the rationale behind the conformance model.

## Phases

### Phase 0 — Refactor the scaffold onto the new model

The current `src/bauble/` has procedural `base_profile.py` /
`standard_profile.py` that collapse profile selection and test logic. Replace
them with the registry-driven structure. Nothing is deleted until the new
path runs end to end.

Deliverables:

- `src/bauble/model.py` — `Severity`, `TestClass`, `Status`, `Profile`,
  `Assertion`, `Result` dataclasses (frozen).
- `src/bauble/registry.py` — assertion registry with lookup by id, rfc,
  profile, scenario.
- `src/bauble/suites/__init__.py` — auto-discovery via importlib.
- `src/bauble/suites/_base.py` — `assertion()` decorator and section helpers.
- Remove `base_profile.py`, `standard_profile.py`, and the old `assertions.py`
  once `model.py` covers them.

Exit criteria: `uv run pytest` green, `ruff check`, `ruff format --check`,
and `pyright` clean.

### Phase 1 — Selection, capability, and runner core

Make the registry selectable and runnable without real LDAP traffic. Tests
use stub assertions.

Deliverables:

- `src/bauble/scenarios.py` — `BASE`, `STANDARD`, `ADVANCED` profile ID sets,
  plus named scenarios (`search`, `bind`, ...).
- `src/bauble/capability.py` — parse a TOML conformance statement.
- `src/bauble/selector.py` — build a `Selector` from CLI args
  (`--profile`, `--rfc`, `--scenario`, `--assertion`, `--category`,
  `--exclude`, `--severity`, `--test-class`) and filter the registry.
- `src/bauble/runner.py` — topological sort over prerequisites; emit
  `BLOCKED`, `AUTO_PASS`, `UNTESTABLE`, `SKIP` correctly; collect results.

Exit criteria: a stub suite under `suites/` lets `bauble run --profile base`
produce a result list with correct statuses, run against an in-memory fake.

### Phase 2 — Harness and connection lifecycle

Wire the real LDAP client in behind the same interfaces.

Deliverables:

- `src/bauble/harness.py` — connection lifecycle (open, bind, unbind),
  shared fixtures, test-data seeding and teardown, DIT root configuration.
- Replace the `client.py` placeholder with the harness-backed connection
  factory. Confirm `ldap3` parameter usage (`use_ssl`, `fast_decoder`,
  `connect_timeout` on `Server`).

Exit criteria: `bauble run` opens a real connection to a target server,
binds, and closes cleanly. A `--dry-run` flag exercises selection and
ordering without sending traffic.

### Phase 3 — Reporters

Produce the suite's outputs: a raw journal and a human summary.

Deliverables:

- `src/bauble/reporter.py` — pluggable reporters.
  - `text` — per-assertion and per-profile rollup to stdout.
  - `journal` — raw machine-readable journal (JSON lines) for archival.
  - `summary` — human conformance summary derived from the journal.
  - `junit` — JUnit XML for CI integration.

Exit criteria: `bauble run --reporter summary` prints a verdict line per
profile and per RFC, plus an overall conformance verdict.

### Phase 4 — First real suite: RFC 4511 (protocol) Bind

The first end-to-end slice of real conformance testing.

Deliverables:

- `src/bauble/suites/rfc4511/__init__.py` — registers the RFC package.
- `src/bauble/suites/rfc4511/bind.py` — assertions covering `§4.2`
  (anonymous bind, simple bind with valid/invalid credentials, result codes,
  re-bind semantics).
- Each assertion carries its `TestClass`, `Severity`, `Profile`, `text`,
  `strategy`, and `requires`.
- Test-data fixtures for the bind cases.

Exit criteria: `bauble run --profile base --rfc 4511` against a reference
server (OpenLDAP in a container) returns real pass/fail/auto-pass verdicts.

### Phase 5 — Core operations (RFC 4511 remainder)

Extend the protocol suite to cover the rest of RFC 4511.

Deliverables — one module per operation:

- `compare.py` (`§4.10`)
- `search.py` (`§4.5`)
- `modify.py` (`§4.6`)
- `add.py` (`§4.7`)
- `delete.py` (`§4.8`)
- `moddn.py` (`§4.9`)
- `abandon.py` (`§4.11`)
- `extended.py` (`§4.12`)

Exit criteria: the full Base profile protocol surface runs and reports.

### Phase 6 — Representation and schema RFCs

The non-protocol parts of Base/Standard.

Deliverables:

- `rfc4512.py` — directory information models.
- `rfc4514.py` — DN string representation.
- `rfc4515.py` — filter string representation.
- `rfc4516.py` — URL format.
- `rfc4517.py` — syntaxes and matching rules.
- `rfc4518.py` — internationalized string preparation.
- `rfc4519.py` — user-application schema.

Exit criteria: Standard profile coverage matches its defined scope.

### Phase 7 — Controls, extended operations, referrals

The Advanced surface and the Standard-profile control/extension features.

Deliverables:

- `controls/` — `rfc2696` (paged results), `rfc2891` (sorting), plus the
  RFC 4511 assertion-level controls (`§4.1.12`).
- `extended/` — `rfc3062` (password modify), `rfc4532` (who am I), and
  others from the dependency tree.
- Referral and continuation-reference tests, including the second-server
  continuation setup the Standard profile requires.

Exit criteria: Advanced profile runs; Standard profile conformance matches
its defined scope, including optional-feature auto-pass.

### Phase 8 — Packaging, CI, and documentation

Deliverables:

- `bauble` console-script entry point in `pyproject.toml`.
- GitHub Actions workflow: `ruff`, `pyright`, `pytest`, and a real
  conformance run against a containerized OpenLDAP.
- README rewrite with quickstart, profile table, and capability-file
  reference.
- `docs/assertion-coverage.md` tracking implemented vs. pending assertions
  against the full assertion list.

Exit criteria: a contributor can add an RFC suite by following documented
steps; CI is green; a tagged release runs Base and Standard profiles.

## Module dependency order

Build and land in this order so each module only imports what already exists:

1. `model.py`
2. `suites/_base.py`
3. `registry.py`
4. `suites/__init__.py` (discovery)
5. `scenarios.py`
6. `capability.py`
7. `selector.py`
8. `runner.py`
9. `harness.py`
10. `reporter.py`
11. `suites/rfc4511/*` and the rest

## Out of scope (for now)

- LDAPv2 (RFC 1777) testing. bauble targets LDAPv3.
- Replication and LCUP suites (RFC 3384, RFC 3928).
- SASL mechanism conformance beyond what RFC 4513 mandates.
- A GUI. CLI + reports only.
