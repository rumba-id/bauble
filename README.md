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
</div>

---

## Documentation

- [Implementation plan](docs/implementation-plan.md)
- [Design notes](docs/design-notes.md)
- [RFC reference tree](docs/references.md)

Current coverage facts are never committed to the docs. Run `bauble coverage`
to print them live from the registry.

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

### Control and operation extensions

- **RFC 2696** — Simple Paged Results
- **RFC 2891** — Server-Side Sorting
- **RFC 3045** — Vendor Information in root DSE
- **RFC 3062** — Password Modify
- **RFC 3829** — Authorization Identity Controls
- **RFC 3866** — Language Tags and Ranges
- **RFC 3876** — Matched Values Control
- **RFC 4525** — Modify-Increment
- **RFC 4526** — Absolute True/False Filters
- **RFC 4527** — Read Entry Controls
- **RFC 4528** — Assertion Control
- **RFC 4529** — Attributes by Object Class
- **RFC 4532** — Who Am I?
- **RFC 6171** — Don't Use Copy Control

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
`UNTESTABLE`, not silently dropped. Controls and extension assertions
follow the advertise-then-test pattern: if the server doesn't claim
support, `NOT_APPLICABLE`; if it claims support but fails, `FAIL` with
detail. See the [design notes](docs/design-notes.md).

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

The OpenLDAP target is the default. A 389 Directory Server target is also
available for cross-implementation checks:

```bash
uv run bauble run --target --target-type 389ds
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
