# Conformance Reference Notes

Analysis of the industry reference LDAP conformance model that informed
bauble's design.

The reference suite is the established conformance model. It is proprietary
(Java over a third-party test controller) and tied to the older RFC 2251-2256
series. bauble mirrors its structure with open-source Python and targets the
modern RFC 4510-4519 series.

## Assertion schema

Every test maps to one assertion with these fields:

- **ID** — dotted-decimal `w.x.y.z`.
  - `w` = source document: RFC2251=1, RFC2252=2, RFC2253=3, RFC2254=4,
    RFC2255=5, RFC2256=6, RFC2459=7, SSLv3=8.
  - `x.y` = section and subsection of document `w`.
  - `z` = assertion number within that section.
- **Class** — ISO 1003.3 testability, orthogonal to severity.
  - `A` mandatory, testable
  - `B` mandatory, untestable (portably)
  - `C` optional, testable
  - `D` optional, untestable
- **Profile** — `BASE`, `STANDARD`, `ADVANCED`, or `NONE`.
- **Text** — the requirement statement.
- **Ref** — RFC section reference, e.g. `rfc2251#4.2`.
- **Strategy** — implementation notes. Either a referenced prior test
  procedure (e.g. `BLITS 3.3.4.2.1`) or an explicit
  `PROCEDURE / INPUT / EXPECTED` block.

The Strategy field is the directly-translatable material for Python tests.

## Testability is separate from severity

Severity in RFCs is RFC 2119 (`MUST`/`SHOULD`/`MAY`). A large fraction of
`MUST` assertions in the reference suite are Class B (untestable). Recorded
reasons include:

- "can not portably test assertions which rely on operation processing time"
- "Access to PDU not portably testable"
- "Can not portably generate an unsolicited notification"
- "Not able to portably force a server to require a rebind"
- "`Every` statements require exhaustive testing"

Consequence: bauble tracks `TestClass` separately from `Severity`. A `MUST`
assertion can be Class B and surface as `UNTESTABLE` rather than silently
omitted.

## Profiles

Three profiles, not two:

- **BASE** — core operations: simple bind, search, add, delete, modify,
  modify DN; TCP and SSL transport.
- **STANDARD** — builds on BASE: root DSE, alias dereferencing, operational
  attributes, controls, extended operations, referrals, continuation
  references.
- **ADVANCED** — SASL controls, extensibleObject, and other optional
  surfaces.

Base certification is a prerequisite for Standard.

## Scenarios are selections, not code

The reference suite's scenarios (`search`, `extensibleMatch`, ...) are lists
of assertion IDs. One assertion can appear in many scenarios. Scenarios are
manifests. This validates the design choice that profiles and scenarios are
selection sets over a flat assertion registry.

## Capability declaration

The Standard profile exposes optional server features as capability flags
the operator declares. The operator states which of the following the server
implements:

- `altServer`
- `namingContext`
- `supportedExtension`
- the OID of a supported extended operation

Rule: if a feature is not supported, its presence test auto-passes. bauble
mirrors this with a TOML capability file and an `AUTO_PASS` status.

## Harness mechanics

- Tests are source files under the suite's test sources directory, one
  assertion ID each.
- The controller runs `build`, `execute`, `clean` phases over a scenario.
- Configuration is via profile-specific config files.
- Raw results are **journal** files; a `report` program summarizes them.
- Certification submission = journal + signed summary.

bauble replaces the third-party controller with a Python runner and
pluggable reporters, but keeps the journal-plus-summary output shape.

## Standard profile test setup

From the configuration guide:

- Schema extensions: add `friends` and `roomNumber` attributes.
- Referral testing: server returns a reference for a base DN it does not
  manage. The test client parses the returned URL but does not follow it.
- Continuation references: a second slave server manages
  `ou=Servers,o=IMC,c=US` as a subordinate knowledge reference. Again the
  client parses but does not follow.
- Test data: import `Alias.ldif` and `Cert-Standard.ldif` on top of the
  Base profile data.

bauble's harness must seed equivalent fixtures and document the optional
second-server setup.

## What bauble changes

- Modern RFC series (4510-4519) instead of 2251-2256.
- Python instead of Java; `ldap3` as the client engine.
- No third-party test controller dependency; a single `bauble` command.
- Open-source (MIT) instead of proprietary.
- Assertion IDs extended to the 4510 series namespace.
