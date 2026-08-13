# Server Findings

Genuine per-implementation deviations from the normative requirements,
each with the assertion that surfaces it. The live verdicts are the
authority — run the named assertion against the target to reproduce.

A "finding" here is a server behavior that differs from what the
requirement mandates. A "not a finding" row records a suspected deviation
that the investigation resolved as a suite bug instead.

## 389 Directory Server

| Finding | Evidence | Verdict |
|---|---|---|
| Rejects empty AND/OR filters | RFC 4526 §2: "SHALL allow 'and' and 'or' filter choices with zero elements"; (&) and (|) are protocolError (2) instead of true/false. | `4526.2.1`, `4526.2.2` FAIL |
| Unsupported AuthenticationChoice returns protocolError instead of authMethodNotSupported | RFC 4511 §4.2: "Servers that do not support a choice supplied by a client return a BindResponse with the resultCode set to authMethodNotSupported." 389 DS returns 2. | `4511.4.2.10` FAIL |
| Accepts a language RANGE option on add | RFC 3866 §3: "Any attempt to add or update an attribute description with a language range option SHALL be treated as an undefined attribute type and result in an error." 389 DS accepts the add. | `3866.3.3` FAIL |
| Does not implement `@objectclass` attribute selection | RFC 4529: `@person` in an attribute list must request the object class's attributes; 389 DS's own ldapsearch returns zero attributes for `@person`. | `4529.3.1` FAIL |
| Does not implement language ranges | RFC 3866 §3: range support is SHOULD, so non-implementation is not a conformance failure; a `description;lang-en-` request echoes the literal option. | `3866.3.1.1`, `3866.3.1.2` NOT_APPLICABLE |
| uidNumber lacks an ORDERING rule | RFC 2307 defines `ORDERING integerOrderingMatch` on uidNumber; 389 DS's schema omits it, so greaterOrEqual filters on uidNumber silently match nothing. Documented, not asserted — the corpus requirement is about integerMatch equality. | — |
| Does not advertise absolute-filter / language / @objectclass feature OIDs | 1.3.6.1.4.1.4203.1.5.2/.3/.4/.5 absent from supportedFeatures; the SHOULD-advertise checks report NOT_APPLICABLE. | `4526.2.3`, `3866.4.1`, `4529.3.3` NOT_APPLICABLE |

## OpenLDAP

| Finding | Evidence | Verdict |
|---|---|---|
| Does not implement the authzId controls | 2.16.840.1.113730.3.4.16/.15 absent from supportedControl; a bind carrying the request control gets no response control. | `3829.4.1` NOT_APPLICABLE |
| Does not advertise the server-side sort control OIDs | 1.2.840.113556.1.4.473/.474 absent from supportedControl, though the sort operation itself works. | `2891.2.2` NOT_APPLICABLE |
| Requires a non-empty AttributeSelection in Pre/Post-Read controls | An empty selection yields strongAuthRequired rather than a response control (probed against `ldapmodify -e preread`). | `4527.3.1.1`/`4527.3.2.1` behavior note |

## Investigated and resolved as suite bugs (not findings)

- **389 DS "missing entryDN"** — 389 DS implements entryDN under its
  canonical lowercase name `entrydn`; the assertions were case-sensitive.
  Fixed with a case-insensitive lookup; `5020.2.1`–`5020.2.4` pass on both
  targets.
- **389 DS "caseIgnoreMatch fails"** — the assertion filtered on
  `cn=ALICE ANDERSON`, which matches only the OpenLDAP seed; 389 DS's alice
  is `cn: Alice`. Fixed to `uid=ALICE`, identical on both seeds.
- **389 DS "integerMatch fails"** — the assertion used greaterOrEqual,
  which needs an ordering rule 389 DS's uidNumber lacks; the requirement is
  integerMatch *equality*. Fixed to numeric equality (`uidNumber=0100`).
- **Advertise assertions never ran** — `4526.2.3`, `3829.2.1`, `3876.7.1`
  were class B, so the runner always reported them untestable; made class A
  with NOT_APPLICABLE for non-advertised OIDs.
- **3866 range FAIL vs NOT_APPLICABLE** — range non-implementation is
  allowed (SHOULD) and now reports NOT_APPLICABLE; range-on-add acceptance
  is a SHALL violation and now FAILs.
