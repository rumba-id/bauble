# bauble

An open-source, implementation-independent LDAP RFC conformance test suite.

## Status

v1.1.0 — 97 assertions across 27 RFCs, 90 class A, 7 class B.
On OpenLDAP: Base CONFORMANT (55/55), Standard with 2 known gaps
(assertion control advertised but not processed). See [assertion
coverage](docs/assertion-coverage.md).

- [Implementation plan](docs/implementation-plan.md)
- [Design notes](docs/design-notes.md)
- [RFC reference tree](docs/references.md)
- [Assertion coverage](docs/assertion-coverage.md)

## Goal

Point bauble at any LDAPv3 server and get a conformance report: which RFC
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

## Current coverage

### RFC 4511 — The Protocol (33 assertions)

- **§4.1.12 Controls** (2) — known/critical controls
- **§4.2 Bind** (8) — anonymous, valid/invalid credentials, empty password,
  serverSaslCreds, re-bind, bad protocol version, malformed PDU
- **§4.5 Search** (4) — base/one-level/subtree scope, filter match
- **§4.6 Modify** (3) — replace, add value, non-existent entry
- **§4.7 Add** (4) — valid, duplicate, missing parent, schema violation
- **§4.8 Delete** (3) — leaf, non-existent, with children
- **§4.9 ModifyDN** (2) — rename, rename-to-existing
- **§4.10 Compare** (4) — true, false, missing attribute, non-existent entry
- **§4.11 Abandon** (2) — UNTESTABLE (timing-dependent)
- **§4.12 Extended** (1) — unrecognized OID returns error

### Schema and representation (16 assertions)

- **RFC 4512** (4) — root DSE, subschema, entries have objectClass
- **RFC 4514** (2) — DN parsing, case preservation
- **RFC 4515** (3) — AND/OR/NOT filter evaluation
- **RFC 4516** (1) — supportedLDAPVersion advertised
- **RFC 4517** (2) — ldapSyntaxes + matchingRules advertised
- **RFC 4518** (1) — case-insensitive matching
- **RFC 4519** (3) — inetOrgPerson/OU/dc advertised in subschema

### Operational attributes (8 assertions)

- **RFC 4530** (4) — entryUUID present, single-value, valid format, immutable
- **RFC 5020** (4) — entryDN present, equals DN, single-value, searchable

### Controls and extensions (40 assertions)

- **RFC 2696** (1) — simple paged results
- **RFC 2891** (1) — server-side sorting
- **RFC 3045** (2) — vendorName/vendorVersion in root DSE
- **RFC 3062** (1) — password modify
- **RFC 3829** (2) — authorization identity request/response controls
- **RFC 3866** (5) — language tag add/search, language range matching
- **RFC 3876** (2) — matched values filter, control advertisement
- **RFC 4513 §4.1** (2) — anonymous initial state, pre-bind operations
- **RFC 4525** (4) — modify-increment (value, multi-value error, non-int error)
- **RFC 4526** (3) — absolute true (&), absolute false (|), advertisement
- **RFC 4527** (2) — pre-read on modify, post-read on add
- **RFC 4528** (5) — TRUE/FALSE/Delete/Search with assertion, advertisement
- **RFC 4529** (2) — @person attribute list, unknown @OID
- **RFC 4532** (1) — who am I?
- **RFC 6171** (1) — don't use copy advertisement

## Profiles

Three tiers. A profile is a selection of assertions, not separate code:

- **Base** — simple bind; search, add, delete, modify, modify DN; over TCP.
- **Standard** — root DSE, operational attributes, controls, extended
  operations, language features.
- **Advanced** — optional surfaces such as read-entry controls.

| Profile | MUST(A) | Verdict |
|---------|---------|---------|
| Base | 55/55 | CONFORMANT |
| Standard | 24 PASS, 2 FAIL, 7 AUTO_PASS, 4 UNTESTABLE | 2 gaps |
| Advanced | 2/2 | CONFORMANT |

The 2 Standard gaps are RFC 4528 assertion control — OpenLDAP advertises
the control but ignores it at runtime.

## Model

Every test is an assertion tied to one RFC requirement. Severity (RFC 2119
`MUST`/`SHOULD`/`MAY`) and testability (ISO 1003.3 class A/B/C/D) are
tracked independently: a `MUST` with no portable test is reported
`UNTESTABLE`, not silently dropped. Controls and extension assertions
follow the advertise-then-test pattern: if the server doesn't claim
support, AUTO_PASS; if it claims support but fails, FAIL with detail.
See the [design notes](docs/design-notes.md).

LDAP access uses [ldap3](https://github.com/cannatag/ldap3) for most
operations and a stdlib-only raw BER+socket layer for edge-case PDUs
that ldap3 cannot construct or parse.

## Usage

Start the podman OpenLDAP test target once, then run any selection:

```bash
# start the test target (stays running for reuse)
uv run bauble run --target

# run the Base profile and get a conformance summary
uv run bauble run --profile base --target --reporter summary

# run a single RFC
uv run bauble run --rfc 4511 --target --reporter text

# run against an external server
uv run bauble run --profile base --server ldap://host:389 --reporter journal

# write output to a file
uv run bauble run --profile base --target --reporter journal --out run.jsonl
```

Use `--fresh-target` to force a fresh container (opt-in, slower).

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
