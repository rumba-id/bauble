# bauble, the platform independent LDAP RFC conformance test suite

<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/rumba.id.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/assets/rumba.id.svg">
  <img alt="Rumba Identity Platform" src="docs/assets/rumba.id.svg" width="200">
</picture>

A free, open-source, implementation-independent LDAP RFC conformance test suite,
built to validate the [Rumba Identity Platform](https://rumba.id) and suitable
for any modern LDAPv3 implementation.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.13+](https://img.shields.io/badge/Python-3.13+-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Version: 2.3.1](https://img.shields.io/badge/version-2.3.1-3776AB.svg?style=flat)](CHANGELOG.md)
</div>

---

## Documentation

- [Implementation plan](docs/implementation-plan.md)
- [Design notes](docs/design-notes.md)
- [RFC reference tree](docs/references.md)
- [v2.x roadmap](docs/v2-roadmap.md)
- [Full LDAPv3 coverage plan](docs/full-coverage-plan.md)
- [Server findings](docs/server-findings.md)
- [Operator guide](docs/operator-guide.md)
- [v2.1 fidelity review](docs/v2.1-fidelity-review.md)
- [v2.0 plan](docs/v2.0-plan.md)
- [v1.1 plan](docs/v1.1-plan.md)

Current coverage facts are never committed to the docs. Run `bauble coverage`
to print them live from the registry and requirements corpus — per-RFC
requirement coverage (COVERED / PARTIALLY_COVERED / UNCOVERED), not just
assertion counts. See the
[design notes](docs/design-notes.md).

## Goal

Point `bauble` at any LDAPv3 server and get a conformance report: which RFC
requirements it satisfies, which it violates, and which cannot be tested
portably. MIT-licensed and server-independent.

## Scope

Targets the LDAPv3 RFC series and extensions:

### Core protocol (RFC 4510-4519)

- **RFC 4510** — Technical Specification Road Map
- **RFC 4511** — The Protocol
- **RFC 4512** — Directory Information Models
- **RFC 4513** — Authentication Methods and Security Mechanisms
- **RFC 4514** — String Representation of Distinguished Names
- **RFC 4515** — String Representation of Search Filters
- **RFC 4516** — Uniform Resource Locator
- **RFC 4517** — Syntaxes and Matching Rules
- **RFC 4518** — Internationalized String Preparation
- **RFC 4519** — Schema for User Applications

### Operational attribute extensions

- **RFC 4530** — entryUUID
- **RFC 5020** — entryDN
- **RFC 3296** — Named Subordinate References
- **RFC 3671** — Collective Attributes
- **RFC 3672** — Subentries
- **RFC 3673** — All Operational Attributes

### Matching rule extensions

- **RFC 3698** — Additional Matching Rules
- **RFC 3687** — Component Matching Rules

### Control and operation extensions

- **RFC 2696** — Simple Paged Results
- **RFC 2891** — Server-Side Sorting
- **RFC 3045** — Vendor Information in root DSE
- **RFC 3062** — Password Modify
- **RFC 3829** — Authorization Identity Controls
- **RFC 3866** — Language Tags and Ranges
- **RFC 3876** — Matched Values Control
- **RFC 3909** — Cancel Operation
- **RFC 2589** — Dynamic Directory Services
- **RFC 4370** — Proxied Authorization Control
- **RFC 4522** — Binary Encoding Option
- **RFC 4525** — Modify-Increment
- **RFC 4526** — Absolute True/False Filters
- **RFC 4527** — Read Entry Controls
- **RFC 4528** — Assertion Control
- **RFC 4529** — Attributes by Object Class
- **RFC 4531** — Turn Operation
- **RFC 4532** — Who Am I?
- **RFC 4533** — Content Synchronization Operation
- **RFC 5805** — Transactions
- **RFC 6171** — Don't Use Copy Control

### Schema-presence checks

Schema-definition RFCs are verified by subschema publication: when a server
loads a schema, its defining object classes and attribute types must be
published. The four GSER/ASN.1 encoding RFCs (3641, 3642, 3727, 4792) define no
schema elements.

- **RFC 2079** — URI Attribute — `labeledURI`
- **RFC 2247** — Domains in DNs — `domain`, `dcObject`
- **RFC 2307** — NIS Schema — `posixAccount`, `posixGroup`
- **RFC 2713** — Java Objects Schema
- **RFC 2714** — CORBA Objects Schema
- **RFC 2739** — Calendar Attributes
- **RFC 2798** — inetOrgPerson
- **RFC 2926** — SLP Templates
- **RFC 2985** — PKCS #9
- **RFC 3112** — Authentication Password Schema
- **RFC 3703** — Policy Core Schema
- **RFC 4104** — Policy Core Extension Schema
- **RFC 4403** — UDDIv3 Schema
- **RFC 4523** — X.509 Certificate Schema
- **RFC 4524** — COSINE Schema
- **RFC 4876** — Configuration Profile Schema
- **RFC 5803** — SCRAM Secrets Schema
- **RFC 7612** — Printer Services Schema
- **RFC 8284** — XMPP White Pages Schema

Replication and transaction RFCs with no mainstream implementation (3928 LCUP,
4373 LBURP, 2649 Operation Signatures) are recorded in the requirements corpus
with untestable-class notes.

## Profiles

Three tiers. A profile is a selection of assertions, not separate code:

- **Interop** — minimum needed to interoperate: simple bind; search, add,
  delete, modify, modify DN; over TCP.
- **Core** — the main LDAPv3 conformance surface: root DSE, operational
  attributes, controls, extended operations, language features.
- **Extended** — optional extensions such as read-entry controls.

## Model

Every test is an assertion tied to one RFC requirement. Severity (RFC 2119
`MUST`/`SHOULD`/`MAY`) and testability (ISO 1003.3 class A/B/C/D) are
tracked independently: a `MUST` with no portable test is reported
`UNTESTABLE`, not silently dropped. Feature-specific assertions follow
the advertise-then-test pattern: if the server doesn't claim support,
`NOT_APPLICABLE`; if it claims support but fails, `FAIL` with detail.
Behavioral assertions that any conformant server must satisfy regardless
of advertisement (for example, RFC 4511 §4.1.11 criticality handling) run
unconditionally. See the [design notes](docs/design-notes.md).

Each assertion is also classified by the kind of conformance it establishes
— Wire (protocol-unit correctness), Semantic (operation meaning), or
Capability (advertised vs. behavior) — so reports can distinguish what a
pass actually proves.

LDAP access uses [ldap3](https://github.com/cannatag/ldap3) for most
operations and a stdlib-only raw BER+socket layer for edge-case PDUs
that ldap3 cannot construct or parse.

## Usage

Start the podman OpenLDAP test target once, then run any selection:

```bash
# start the test target (stays running for reuse)
uv run bauble run --target

# print current coverage facts (assertions per RFC, class, layer, profile)
uv run bauble coverage

# run the Interop profile and get a conformance summary
uv run bauble run --profile interop --target --reporter summary

# run a single RFC
uv run bauble run --rfc 4511 --target --reporter text

# run against an external server
uv run bauble run --profile interop --server ldap://host:389 --reporter journal

# write output to a file
uv run bauble run --profile interop --target --reporter journal --out run.jsonl
```

Use `--fresh-target` to force a fresh container (opt-in, slower).

### Additional targets

The OpenLDAP target is the default. Additional targets are available for
cross-implementation checks:

```bash
# 389 Directory Server
uv run bauble run --target --target-type 389ds

# OpenDJ
uv run bauble run --target --target-type opendj

# LLDAP
uv run bauble run --target --target-type lldap
```

Its admin DN differs (`cn=Directory Manager`). Override credentials and the
base DN with `BAUBLE_ADMIN_DN`, `BAUBLE_ADMIN_PW`, and `BAUBLE_TEST_BASE`.

### Capability file

Optional features the server supports are declared in a TOML file:

```toml
[server]
writable = true

[features]
alt_server = false
naming_context = true
supported_extension = []
supported_control = []
```

Pass it with `--capability bauble.toml`. Unsupported features auto-pass.

## Development

Python 3.13+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync                       # install dependencies
uv run pytest                 # tests
uv run ruff check             # lint
uv run ruff format --check    # format check
uv run pyright                # type check
```

## Author

[Daniel S. Reichenbach](https://github.com/danielsreichenbach)

## License

MIT — see [LICENSE](LICENSE).
