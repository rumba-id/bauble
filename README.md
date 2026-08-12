# bauble

An open-source, implementation-independent LDAP RFC conformance test suite.

## Status

In design. The conformance model, profiles, and an eight-phase
implementation plan are settled; Phases 0-4 are approved and implementation
has not started. bauble does not test any server yet.

- [Implementation plan](docs/implementation-plan.md)
- [Design notes](docs/design-notes.md)
- [RFC reference tree](docs/references.md)

## Goal

Point bauble at any LDAPv3 server and get a conformance report: which RFC
requirements it satisfies, which it violates, and which cannot be tested
portably. MIT-licensed and server-independent.

## Scope

Targets the LDAPv3 RFC series (4510-4519):

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

## Current coverage

RFC 4511 (The Protocol) — 31 assertions across 9 operations:

- **§4.2 Bind** (8) — anonymous, valid/invalid credentials, empty password,
  serverSaslCreds, re-bind, bad protocol version, malformed PDU
- **§4.5 Search** (4) — base/one-level/subtree scope, filter match, no such object
- **§4.6 Modify** (3) — replace, add value, non-existent entry
- **§4.7 Add** (4) — valid, duplicate, missing parent, schema violation
- **§4.8 Delete** (3) — leaf, non-existent, with children
- **§4.9 ModifyDN** (2) — rename, rename-to-existing
- **§4.10 Compare** (4) — true, false, missing attribute, non-existent entry
- **§4.11 Abandon** (2) — UNTESTABLE (timing-dependent)
- **§4.12 Extended** (1) — unrecognized OID returns error

Of 31 assertions: 29 testable (29/29 PASS on OpenLDAP), 2 UNTESTABLE (intrinsic).

## Profiles

Three tiers. A profile is a selection of assertions, not separate code:

- **Base** — simple bind; search, add, delete, modify, modify DN; over TCP
  and TLS.
- **Standard** — root DSE, alias dereferencing, operational attributes,
  controls, extended operations, referrals, continuation references.
- **Advanced** — optional surfaces such as SASL controls and
  extensibleObject.

Base is a prerequisite for Standard.

## Model

Every test is an assertion tied to one RFC requirement. Severity (RFC 2119
`MUST`/`SHOULD`/`MAY`) and testability are tracked independently: a `MUST`
with no portable test is reported `UNTESTABLE`, not silently dropped. See the
[design notes](docs/design-notes.md). LDAP access uses
[ldap3](https://github.com/cannatag/ldap3).

## Usage (planned)

Not implemented yet. Intended invocation once the CLI lands:

```bash
uv run bauble run --profile base --server ldaps://host --capability bauble.toml
```

Before Phase 8 the form is `uv run python -m bauble run ...`.

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
