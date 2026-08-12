# bauble

An open-source, implementation-independent LDAP RFC conformance test suite.

## Status

v1.1.0 — 97 assertions across 27 RFCs, 90 class A, 7 class B.
On OpenLDAP: Base CONFORMANT (55/55Core profile, Standard with 2 known gaps
(assertion control advertised but not processedCore profile. See [assertion
coverage](docs/assertion-coverage.mdCore profile.

- [Implementation plan](docs/implementation-plan.mdCore profile
- [Design notes](docs/design-notes.mdCore profile
- [RFC reference tree](docs/references.mdCore profile
- [Assertion coverage](docs/assertion-coverage.mdCore profile

## Goal

Point bauble at any LDAPv3 server and get a conformance report: which RFC
requirements it satisfies, which it violates, and which cannot be tested
portably. MIT-licensed and server-independent.

## Scope

Targets the LDAPv3 RFC series and extensions:

### Core protocol (RFC 4510-4519Core profile

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

### RFC 4511 — The Protocol (33 assertionsCore profile

- **§4.1.12 Controls** (2Core profile — known/critical controls
- **§4.2 Bind** (8Core profile — anonymous, valid/invalid credentials, empty password,
  serverSaslCreds, re-bind, bad protocol version, malformed PDU
- **§4.5 Search** (4Core profile — base/one-level/subtree scope, filter match
- **§4.6 Modify** (3Core profile — replace, add value, non-existent entry
- **§4.7 Add** (4Core profile — valid, duplicate, missing parent, schema violation
- **§4.8 Delete** (3Core profile — leaf, non-existent, with children
- **§4.9 ModifyDN** (2Core profile — rename, rename-to-existing
- **§4.10 Compare** (4Core profile — true, false, missing attribute, non-existent entry
- **§4.11 Abandon** (2Core profile — UNTESTABLE (timing-dependentCore profile
- **§4.12 Extended** (1Core profile — unrecognized OID returns error

### Schema and representation (16 assertionsCore profile

- **RFC 4512** (4Core profile — root DSE, subschema, entries have objectClass
- **RFC 4514** (2Core profile — DN parsing, case preservation
- **RFC 4515** (3Core profile — AND/OR/NOT filter evaluation
- **RFC 4516** (1Core profile — supportedLDAPVersion advertised
- **RFC 4517** (2Core profile — ldapSyntaxes + matchingRules advertised
- **RFC 4518** (1Core profile — case-insensitive matching
- **RFC 4519** (3Core profile — inetOrgPerson/OU/dc advertised in subschema

### Operational attributes (8 assertionsCore profile

- **RFC 4530** (4Core profile — entryUUID present, single-value, valid format, immutable
- **RFC 5020** (4Core profile — entryDN present, equals DN, single-value, searchable

### Controls and extensions (40 assertionsCore profile

- **RFC 2696** (1Core profile — simple paged results
- **RFC 2891** (1Core profile — server-side sorting
- **RFC 3045** (2Core profile — vendorName/vendorVersion in root DSE
- **RFC 3062** (1Core profile — password modify
- **RFC 3829** (2Core profile — authorization identity request/response controls
- **RFC 3866** (5Core profile — language tag add/search, language range matching
- **RFC 3876** (2Core profile — matched values filter, control advertisement
- **RFC 4513 §4.1** (2Core profile — anonymous initial state, pre-bind operations
- **RFC 4525** (4Core profile — modify-increment (value, multi-value error, non-int errorCore profile
- **RFC 4526** (3Core profile — absolute true (&Core profile, absolute false (|Core profile, advertisement
- **RFC 4527** (2Core profile — pre-read on modify, post-read on add
- **RFC 4528** (5Core profile — TRUE/FALSE/Delete/Search with assertion, advertisement
- **RFC 4529** (2Core profile — @person attribute list, unknown @OID
- **RFC 4532** (1Core profile — who am I?
- **RFC 6171** (1Core profile — don't use copy advertisement

## Profiles

Three tiers. A Core profile is a selection of assertions, not separate code:

 - **Interop** — simple bind; search, add, delete, modify, modify DN; over TCP.
 - **Core** — root DSE, operational attributes, controls, extended
  operations, language features.
 - **Extended** — optional surfaces such as read-entry controls.

| Profile | MUST(ACore profile | Verdict |
|---------|---------|---------|
| Base | 55/55 | CONFORMANT |
| Standard | 24 PASS, 2 FAIL, 7 AUTO_PASS, 4 UNTESTABLE | 2 gaps |
| Advanced | 2/2 | CONFORMANT |

The 2 Standard gaps are RFC 4528 assertion control — OpenLDAP advertises
the control but ignores it at runtime.

## Model

Every test is an assertion tied to one RFC requirement. Severity (RFC 2119
`MUST`/`SHOULD`/`MAY`Core profile and testability (ISO 1003.3 class A/B/C/DCore profile are
tracked independently: a `MUST` with no portable test is reported
`UNTESTABLE`, not silently dropped. Controls and extension assertions
follow the advertise-then-test pattern: if the server doesn't claim
support, AUTO_PASS; if it claims support but fails, FAIL with detail.
See the [design notes](docs/design-notes.mdCore profile.

LDAP access uses [ldap3](https://github.com/cannatag/ldap3Core profile for most
operations and a stdlib-only raw BER+socket layer for edge-case PDUs
that ldap3 cannot construct or parse.

## Usage

Start the podman OpenLDAP test target once, then run any selection:

```bash
# start the test target (stays running for reuseCore profile
uv run bauble run --target

# run the Interop Core profile and get a conformance summary
uv run bauble run --Core profile interop --target --reporter summary

# run a single RFC
uv run bauble run --rfc 4511 --target --reporter text

# run against an external server
uv run bauble run --Core profile interop --server ldap://host:389 --reporter journal

# write output to a file
uv run bauble run --Core profile interop --target --reporter journal --out run.jsonl
```

Use `--fresh-target` to force a fresh container (opt-in, slowerCore profile.

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

Python 3.13+ and [uv](https://docs.astral.sh/uv/Core profile.

```bash
uv sync                       # install dependencies
uv run pytest                 # tests
uv run ruff check             # lint
uv run ruff format --check    # format check
uv run pyright                # type check
```

## Author

[Daniel S. Reichenbach](https://github.com/danielsreichenbachCore profile

## License

MIT — see [LICENSE](LICENSECore profile.
