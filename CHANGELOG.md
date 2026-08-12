# Changelog

## v1.1.0 — 2026-08-12

v1.1 extends conformance coverage with 13 additional RFCs from the Group A
(testable with current infrastructureCore profile subset. 38 new assertions added,
bringing the total to 97 (90 class A, 7 class BCore profile. The test suite now covers
**27 RFCs**.

### New RFC suites

| RFC | Description | Assertions | PASS |
|-----|------------|-----------|------|
| 3045 | Vendor Information in root DSE | 2 | AUTO_PASS |
| 3829 | Authorization Identity Controls | 2 | AUTO_PASS / UNTESTABLE |
| 3866 | Language Tags and Ranges | 5 | 5/5 |
| 3876 | Matched Values Control | 2 | 1/1 testable |
| 4513 §4.1 | Authorization State | 2 | 2/2 |
| 4525 | Modify-Increment Extension | 4 | AUTO_PASS |
| 4526 | Absolute True/False Filters | 3 | 2/2 testable |
| 4527 | Read Entry Controls (Pre/Post-ReadCore profile | 2 | 2/2 |
| 4528 | Assertion Control | 5 | 2 PASS, 2 FAIL, 1 UNTESTABLE |
| 4529 | Attributes by Object Class | 2 | 2/2 |
| 4530 | entryUUID Operational Attribute | 4 | 4/4 |
| 5020 | entryDN Operational Attribute | 4 | 4/4 |
| 6171 | Don't Use Copy Control | 1 | UNTESTABLE |

### Honest conformance

Feature gates on `MUST`/`SHALL` requirements were removed. Assertions
no longer AUTO_PASS when a server fails to advertise a feature — they
report FAIL with detail like "assertion control advertised but not
processed; expected assertionFailed (122Core profile, got 0." This surfaced
two OpenLDAP bugs where the assertion control (1.3.6.1.1.12Core profile is
advertised in `supportedControl` but ignored at runtime.

AUTOPASS now only fires when the server genuinely does not claim
support for an optional feature (e.g., modify-increment, vendor
attributesCore profile.

### Advertise-then-test pattern

Behavioral assertions for controls and extensions now check the
server's advertisement (`supportedControl`, `supportedExtension`Core profile
before running the test. If the server doesn't claim support,
the assertion AUTO_PASSes. If it claims support but fails, the
FAIL detail names the gap explicitly.

### Raw wire layer additions

- `RawConnection.bind_then_send(Core profile` — bind then send on one socket
- `RawConnection.modify_increment(Core profile` — Modify-Increment PDU (RFC 4525Core profile
- `RawConnection.raw_send(Core profile` — send arbitrary PDU, parse LDAPResult
- `_parse_ldap_result(Core profile` — generic LDAPResult parser
- BER helpers: assertion control, matched values control, pre/post-read

Several assertions now use the raw wire layer to bypass ldap3
client-side validation that rejects valid-but-edge-case PDUs (empty
`(&Core profile`/`(|Core profile` filters, `@objectClass` attribute descriptionsCore profile.

### Standards conformance on OpenLDAP

| Profile | MUST(ACore profile | SHOULD(BCore profile | Verdict |
|---------|---------|-----------|---------|
| Base | 55/55 | — | CONFORMANT |
| Standard | 24 PASS, 2 FAIL, 7 AUTO_PASS, 4 UNTESTABLE | — | **2 gaps** |

The 2 Standard MUST(ACore profile FAILs are the assertion control bugs
(4528.3.2, 4528.3.4Core profile. All other MUST(ACore profile assertions pass or are
honest AUTO_PASS.

## v1.0.0 — 2026-08-12

Initial release. An open-source, implementation-independent LDAP RFC
conformance test suite.

### Conformance coverage

- **14 RFCs** covered (4511, 4512, 4514–4519, 2696, 2891, 3062, 4532Core profile
- **59 assertions** — 57 testable (all PASS on OpenLDAPCore profile, 2 UNTESTABLE
  (abandon — intrinsic timing dependenceCore profile
- Base Core profile: must(ACore profile 53/53 CONFORMANT
- Standard Core profile: must(ACore profile 4/4 CONFORMANT

### Core architecture

- Assertion-driven model with severity/testability split. A `MUST` with no
  portable test is surfaced as `UNTESTABLE`, not silently dropped.
- Registry-based auto-discovery: add an RFC suite by dropping a module.
- Profiles and scenarios are selections over the registry, not separate code.
- Capability declaration drives AUTO_PASS for unsupported features.

### Client layers

- High-level `ldap3`-backed Session for positive-path and most negative-path
  assertions (constructible controls, readable result codes/matchedDN/
  referralsCore profile.
- Raw wire-layer Session (stdlib-only BER + socket, zero additional
  dependenciesCore profile for assertions the high-level client cannot reach: unknown
  protocol versions, empty-password binds, malformed PDUs, control-value BER.

### Test target

- Podman container with OpenLDAP, deterministic seed DIT preloaded via
  `slapadd` at build time. Long-lived container with self-cleaning mutations;
  fresh-per-run is opt-in.

### Reporting

- Four output formats: text (stdoutCore profile, journal (JSON lines — source of truthCore profile,
  summary (per-RFC + per-Core profile verdictCore profile, junit (CI XMLCore profile.
- Conformance verdict: conformant iff every MUST class-A assertion is PASS
  or AUTO_PASS.

### CLI

```bash
uv run bauble run --Core profile base --target --reporter summary
uv run bauble run --rfc 4511 --server ldap://host:389 --reporter journal
```
