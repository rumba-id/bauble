# Implementation Plan

Build plan for bauble: an open-source, implementation-independent LDAP RFC
conformance test suite.

This plan captures the agreed architecture and breaks it into reviewable
phases. Each phase ends with a green test suite, a clean commit, and a
working slice of the full path
(`uv run python -m bauble run ... -> journal + summary`).

## Design principles

1. **Assertions are the atomic unit.** Every test maps to one normative
   requirement stated as an assertion, identified by a dotted-decimal ID
   `w.x.y.z`, where `w` is the RFC number. `--rfc 4511` is then a trivial
   filter on `w`.
2. **Severity and testability are orthogonal.** Severity comes from RFC 2119
   (`MUST`/`SHOULD`/`MAY`). Testability records whether a portable test
   exists. A `MUST` requirement can still be untestable.
3. **Profiles and scenarios are selections over a flat registry**, never
   duplicated test logic. A profile derives from each assertion's `profiles`
   tag; a named scenario is a filter over the registry.
4. **The RFC dependency tree is the prerequisite graph.** A failed
   prerequisite marks dependents `BLOCKED`, not `FAIL`.
5. **Capability declaration drives auto-pass.** Operators declare which
   optional features a server implements (including whether it is writable);
   presence tests for unsupported features `AUTO_PASS`.
6. **One RFC = one module, self-registering.** Adding an RFC suite means
   dropping a file. No central manifest to edit.
7. **Isolation is explicit.** The harness guarantees a known DIT at the start
   of each run; each mutating assertion cleans up the entries it creates so it
   does not pollute siblings.
8. **Honest coverage boundary.** bauble uses a high-level client (ldap3), so
   negative-path assertions that need malformed PDUs or raw byte inspection
   are `UNTESTABLE` and surfaced — not silently dropped.

See `docs/references.md` for the full RFC dependency tree and
`docs/design-notes.md` for the rationale behind the conformance model.

## Invocation

Before Phase 8 the package has no `bauble` console script, so the dev
invocation is `uv run python -m bauble run ...`. Phase 8 adds the
`[project.scripts]` entry point, after which the canonical form is
`uv run bauble run ...`. Exit criteria below use the pre-Phase-8 form until
Phase 8.

## Phases

### Phase 0 — Model, registry, and the session contract

The current `src/bauble/` has procedural `base_profile.py` /
`standard_profile.py` that collapse profile selection and test logic. Lay the
registry-driven foundation and, crucially, pin the contract every assertion
relies on.

Deliverables:

- `src/bauble/model.py` — `Severity`, `TestClass`, `Status`, `Profile`,
  `Category`, `Assertion`, `Result` dataclasses (frozen). `Assertion` carries
  `id`, `rfc` (number, used as `w`), `section`, `category`, `severity`,
  `test_class`, `profiles`, `text`, `strategy`, `requires`, `mutates`,
  `requires_features`.
- `src/bauble/session.py` — a `Session` `Protocol` defining the exact surface
  an assertion may call (bind, search, add, modify, delete, compare, ...).
  Both the Phase 1 fake and the Phase 2 real harness implement it.
- `src/bauble/registry.py` — assertion registry with lookup by id, rfc,
  profile, category, scenario.
- `src/bauble/suites/__init__.py` — auto-discovery via importlib.
- `src/bauble/suites/_base.py` — `assertion()` decorator and section helpers.
- Keep the old `base_profile.py`, `standard_profile.py`, `assertions.py`, and
  `runner.py` until Phase 1's new runner replaces the CLI path.

Exit criteria: `uv run pytest` green, `uv run ruff check`,
`uv run ruff format --check`, and `uv run pyright` clean. A trivial stub
suite registers one assertion through the decorator and the registry finds it.

### Phase 1 — Selection, capability, and runner core

Make the registry selectable and runnable without real LDAP traffic, against
an in-memory fake `Session`.

Deliverables:

- `src/bauble/scenarios.py` — named scenario filters (`search`, `bind`, ...).
  Profiles are not hardcoded ID lists; a profile selection derives from each
  assertion's `profiles` tag, so adding an assertion tagged BASE automatically
  includes it in BASE.
- `src/bauble/capability.py` — parse a TOML conformance statement, including a
  `writable` flag (default true) and optional-feature declarations.
- `src/bauble/selector.py` — build a `Selector` from CLI args
  (`--profile`, `--rfc`, `--scenario`, `--assertion`, `--category`,
  `--exclude`, `--severity`, `--test-class`) and filter the registry.
  Combine semantics: AND across dimensions, OR within a dimension.
- `src/bauble/runner.py` — topological sort over prerequisites; emit
  `BLOCKED`, `AUTO_PASS` (incl. for non-writable servers and unsupported
  features), `UNTESTABLE`, `SKIP` correctly; collect results. Callable both
  as a library (takes a `Session`) and via CLI.
- `src/bauble/_fake.py` — an in-memory, scriptable fake `Session` for tests.
- Remove the old `base_profile.py`, `standard_profile.py`, `assertions.py`,
  and the old `runner.py` now that the new runner drives the CLI.

Exit criteria:

- `uv run pytest` green, `uv run ruff check`, `uv run ruff format --check`,
  and `uv run pyright` clean.
- The runner, invoked as a library with a `FakeSession` and
  `Selector(profile=BASE)`, produces a result list with correct statuses.
  (The CLI is validated against a real server in Phase 2.)
- A **golden "broken fake" test**: a fake that returns wrong result codes
  causes the suite to emit `FAIL`, and a deliberately-failed prerequisite
  causes its dependents to be reported `BLOCKED`. This proves the verdict
  logic, not just that code runs.

### Phase 2 — Harness, test target, and isolation

Wire the real LDAP client behind the `Session` contract and stand up the
server every later phase depends on.

Deliverables:

- `src/bauble/harness.py` — connection lifecycle (open, bind, unbind) backed
  by ldap3, implementing `Session`. Confirm ldap3 parameter usage
  (`use_ssl`, `fast_decoder`, `connect_timeout` on `Server`).
- `src/bauble/fixtures/` — a containerized OpenLDAP **test target** for local
  dev and CI: a known base seed LDIF, schema extensions, and a start/stop
  helper. This is the dev-time server; Phase 8 only wraps it in a CI workflow.
- **Isolation model**: distinguish a disposable *test target* (operator-owned,
  seedable and resettable) from a *server under test* (read-only by default).
  The harness seeds a known DIT and resets it between runs only against a
  target whose capability `resettable` is true; reset is authoritative
  (subtree wipe + reseed, or container restart), never best-effort. Each
  mutating assertion self-cleans in a `finally`. Mutating assertions are gated
  on `writable` and `AUTO_PASS` when false. Running mutations against a live
  server under test requires explicit `--allow-mutation`; bauble then
  self-cleans per assertion but performs no whole-DIT reset, so that verdict
  is best-effort.
- `--dry-run` flag that exercises selection and ordering without traffic.

Exit criteria: `uv run python -m bauble run` opens a real connection to the
containerized OpenLDAP, binds, runs a no-op selection, and closes cleanly.
Re-running yields identical results (isolation holds).

### Phase 3 — Reporters

Produce the suite's outputs: a raw journal and a human summary.

Deliverables:

- `src/bauble/reporter.py` — pluggable reporters.
  - `text` — per-assertion and per-profile rollup to stdout.
  - `journal` — raw machine-readable journal (JSON lines) for archival.
  - `summary` — human conformance summary derived from the journal.
  - `junit` — JUnit XML for CI integration.
- Reporters surface `UNTESTABLE` counts per RFC so the coverage boundary is
  visible.

Exit criteria: `uv run python -m bauble run --reporter summary` prints a
verdict line per profile and per RFC, plus an overall conformance verdict,
against stub results.

### Phase 4 — First real suite: RFC 4511 (protocol) Bind

The first end-to-end slice of real conformance testing.

Deliverables:

- `src/bauble/suites/rfc4511/__init__.py` — registers the RFC package.
- `src/bauble/suites/rfc4511/bind.py` — assertions covering `§4.2`
  (anonymous bind, simple bind with valid/invalid credentials, result codes,
  re-bind semantics).
- Each assertion carries its `TestClass`, `Severity`, `Profile`, `Category`,
  `text`, `strategy`, and `requires`.
- Bind fixtures (test entries and credentials).
- Negative-path assertions that ldap3 cannot express are recorded as
  `UNTESTABLE` with the reason.

Exit criteria: `uv run python -m bauble run --profile base --rfc 4511` against
the containerized OpenLDAP returns real pass/fail/auto-pass verdicts.

### Phase 5 — Core operations (RFC 4511 remainder), one PR per operation

Extend the protocol suite to cover the rest of RFC 4511. Each operation is its
own increment and lands as its own PR, in dependency order:

- `add.py` (`§4.7`) — needed before modify/delete fixtures.
- `delete.py` (`§4.8`)
- `modify.py` (`§4.6`)
- `moddn.py` (`§4.9`)
- `compare.py` (`§4.10`)
- `search.py` (`§4.5`)
- `abandon.py` (`§4.11`) — mostly `UNTESTABLE` (timing); record honestly.
- `extended.py` (`§4.12`)

At the end of Phase 5, count `UNTESTABLE`-due-to-wire-format assertions and
decide whether the optional raw-protocol `Session` earns its keep (see
Constraints).

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
  RFC 4511 assertion-level controls (`§4.1.12`). Unknown-critical-control
  assertions are `UNTESTABLE` under ldap3-only.
- `extended/` — `rfc3062` (password modify), `rfc4532` (who am I), and
  others from the dependency tree.
- Referral and continuation-reference tests, including the second-server
  continuation setup the Standard profile requires.
- `supported_sasl_mechanisms` capability flag lands here with the auth
  surface (deferred from Phase 1).

Exit criteria: Advanced profile runs; Standard profile conformance matches
its defined scope, including optional-feature auto-pass.

### Phase 8 — Packaging, CI, and documentation

Deliverables:

- `bauble` console-script entry point in `pyproject.toml`
  (`[project.scripts]`). After this phase the canonical invocation is
  `uv run bauble run ...`.
- GitHub Actions workflow: `uv run ruff check`, `uv run ruff format --check`,
  `uv run pyright`, `uv run pytest`, and a real
  conformance run against the containerized OpenLDAP from Phase 2.
- README rewrite with quickstart, profile table, and capability-file
  reference.
- `docs/assertion-coverage.md` tracking implemented vs. `UNTESTABLE` vs.
  pending assertions per RFC.

Exit criteria: a contributor can add an RFC suite by following documented
steps; CI is green; a tagged release runs Base and Standard profiles.

## Module dependency order

Build and land in this order so each module only imports what already exists:

1. `model.py`
2. `session.py` (the Protocol)
3. `suites/_base.py`
4. `registry.py`
5. `suites/__init__.py` (discovery)
6. `scenarios.py`
7. `capability.py`
8. `selector.py`
9. `runner.py`
10. `_fake.py` (fake Session for tests)
11. `harness.py` (real Session)
12. `fixtures/` (containerized test target)
13. `reporter.py`
14. `suites/rfc4511/*` and the rest

## Constraints

- **Client**: ldap3 only for now. Most negative paths are reachable (trigger
  the error with a valid op on bad data; controls/result codes/matchedDN are
  accessible). Only wire-format malformation is `UNTESTABLE`, surfaced per
  RFC. The `Session` contract is the seam for an optional raw layer; the
  build/no-build call is deferred to end of Phase 5 with real
  `UNTESTABLE`-due-to-wire counts.
- **Isolation**: disposable test target (seed + authoritative reset,
  `resettable=true`) vs. server under test (read-only by default).
  Mutating assertions self-clean in `finally`; gated on `writable`
  (`AUTO_PASS` when false). Mutations against a live SUT require
  `--allow-mutation` and get best-effort verdicts (no whole-DIT reset).

## Out of scope (for now)

- LDAPv2 (RFC 1777) testing. bauble targets LDAPv3.
- A raw-protocol sender for higher negative-path coverage (revisit later as an
  optional layer).
- Replication and LCUP suites (RFC 3384, RFC 3928).
- SASL mechanism conformance beyond what RFC 4513 mandates.
- A GUI. CLI + reports only.
