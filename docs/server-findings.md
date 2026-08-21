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
| Subtree search over a referral entry returns entries, not a continuation reference | RFC 4511 §4.5.3: a search crossing a subordinate referral returns a SearchResultReference; 389 DS returns the referral entry itself as a normal entry (deref of `ou=remote` yields no referral URI). | `4511.4.5.7` FAIL |
| Rejects empty AND/OR filters | RFC 4526 §2: "SHALL allow 'and' and 'or' filter choices with zero elements"; (&) and (|) are protocolError (2) instead of true/false. | `4526.2.1`, `4526.2.2` FAIL |
| Unsupported AuthenticationChoice returns protocolError instead of authMethodNotSupported | RFC 4511 §4.2: "Servers that do not support a choice supplied by a client return a BindResponse with the resultCode set to authMethodNotSupported." 389 DS returns 2. | `4511.4.2.10` FAIL |
| Accepts a language RANGE option on add | RFC 3866 §3: "Any attempt to add or update an attribute description with a language range option SHALL be treated as an undefined attribute type and result in an error." 389 DS accepts the add. | `3866.3.3` FAIL |
| Does not implement `@objectclass` attribute selection | RFC 4529: `@person` in an attribute list must request the object class's attributes; 389 DS's own ldapsearch returns zero attributes for `@person`. | `4529.3.1` FAIL |
| Sort control reports unwillingToPerform for an unknown sort attribute | RFC 2891 §1.1: an unrecognized attribute in the sort key yields sortResult noSuchAttribute (16) and the search proceeds; 389 DS returns sortResult 53. | `2891.2.3` FAIL |
| Does not implement language ranges | RFC 3866 §3: range support is SHOULD, so non-implementation is not a conformance failure; a `description;lang-en-` request echoes the literal option. | `3866.3.1.1`, `3866.3.1.2` NOT_APPLICABLE |
| uidNumber lacks an ORDERING rule | RFC 2307 defines `ORDERING integerOrderingMatch` on uidNumber; 389 DS's schema omits it, so greaterOrEqual filters on uidNumber silently match nothing. | `3698.2.7` FAIL |
| Does not return a referral entry under ManageDsaIT | RFC 3296 §3: ManageDsaIT suppresses referral processing so the referral entry is returned as a normal entry; a base-scope search of `ou=remote` with ManageDsaIT returns no entry. | `3296.2.1` FAIL |
| Does not advertise absolute-filter / language / @objectclass feature OIDs | 1.3.6.1.4.1.4203.1.5.2/.3/.4/.5 absent from supportedFeatures; the SHOULD-advertise checks report NOT_APPLICABLE. | `4526.2.3`, `3866.4.1`, `4529.3.3` NOT_APPLICABLE |

## OpenLDAP

| Finding | Evidence | Verdict |
|---|---|---|
| Does not implement the authzId controls | 2.16.840.1.113730.3.4.16/.15 absent from supportedControl; a bind carrying the request control gets no response control. | `3829.4.1` NOT_APPLICABLE |
| Does not advertise the server-side sort control OIDs | 1.2.840.113556.1.4.473/.474 absent from supportedControl, though the sort operation itself works. | `2891.2.2` NOT_APPLICABLE |
| Abandon with a large unknown messageID disconnects instead of discarding | RFC 4511 §4.11: servers MUST discard unknown messageIDs, and abandon has no response; OpenLDAP sends a Notice of Disconnection (protocolError) for messageIDs above its internal bound (~2^15) and closes the session. Small unknown IDs are discarded correctly. | `4511.4.11.2` FAIL |
| Requires a non-empty AttributeSelection in Pre/Post-Read controls | An empty selection yields strongAuthRequired rather than a response control (probed against `ldapmodify -e preread`). | `4527.3.1.1`/`4527.3.2.1` behavior note |

## OpenDJ

| Finding | Evidence | Verdict |
|---|---|---|
| Anonymous Who-Am-I returns `dn:` instead of an empty response field | RFC 4532 §3: the anonymous response field "is present but empty"; OpenDJ returns the authzId `dn:` (empty DN). | `4532.1.1` FAIL |
| Accepts a language RANGE option on add | RFC 3866 §3 SHALL reject; OpenDJ accepts. Same deviation as 389 DS. | `3866.3.3` FAIL |
| Increment with multiple values returns noSuchObject instead of protocolError | RFC 4525: protocolError. OpenDJ returns 32. | `4525.2.3` FAIL |
| Increment on a non-incrementable attribute returns invalidAttributeSyntax instead of constraintViolation | RFC 4525: constraintViolation or another appropriate error; 21 is arguably appropriate — flag for review. | `4525.2.4` FAIL |
| AuthzId response control not implemented | 2.16.840.1.113730.3.4.16 advertised, .15 (response) not; no response control returned. | `3829.2.1`, `3829.4.1` NOT_APPLICABLE |
| Language ranges not implemented | `description;lang-en-` echoes the literal option (SHOULD-level, allowed). | `3866.3.1.1`, `3866.3.1.2` NOT_APPLICABLE |
| Maintains 2 of the 4 operational attributes on the seed entry | creatorsName/createTimestamp yes; modifiersName/modifyTimestamp absent. | `4512.3.2` NOT_APPLICABLE |
| ref attribute not returned under ManageDsaIT | RFC 3296: the referral entry's ref attribute is readable with ManageDsaIT; OpenDJ returns the entry without the ref attribute. | `3296.2.1` FAIL |
| Rejects a request carrying an unrecognized trailing SEQUENCE component | RFC 4511 §4.1.1: servers MUST ignore trailing SEQUENCE components whose tags they do not recognize; OpenDJ returns protocolError (2). | `4511.4.1.1.4` FAIL |

## LLDAP

The minimal end of the spectrum: an LDAPv3 interface over an identity
store, read-mostly, no request controls, no SASL. Full-profile verdicts:
most write-path assertions are NOT_APPLICABLE (the interface is not
client-writable), the wire basics pass, and the gaps below are the
interface's actual limits.

| Finding | Evidence | Verdict |
|---|---|---|
| Rejects anonymous binds | RFC 4513: anonymous bind is a valid request; LLDAP returns inappropriateAuthentication (48). | `4511.4.2.1` FAIL |
| Unrecognized extended request returns unwillingToPerform, not protocolError | RFC 4511 §4.12: protocolError. LLDAP returns 53. | `4511.4.12.1` FAIL |
| Who-Am-I returns an empty response even for an authenticated user | RFC 4532: the authzId of the bound identity; LLDAP returns empty for alice. | `4532.1.1` FAIL |
| `+` selector returns no operational attributes | RFC 3673: '+' MUST return all operational attributes; LLDAP returns none. entryUUID is only exposed under '*'. | `3673.2.1`, `4530.2.4.1` FAIL |
| No entryDN attribute | RFC 5020: entryDN is not provided at all. | `5020.2.1`, `5020.2.2`, `5020.2.4` FAIL |
| Empty AND/OR filters not evaluated | RFC 4526 SHALL allow; LLDAP denies the search (50). | `4526.2.1`, `4526.2.2` FAIL |
| Ignores the criticality flag on an unrecognized control | RFC 4511 §4.1.11: a critical control the server does not support must be rejected with unavailableCriticalExtension; LLDAP processes the compare (compareTrue) instead. | `3876.2.2` FAIL |
| Rejects searches that carry a control it does not implement | RFC 4511 §4.1.11: an unrecognized NON-critical control MUST be ignored and the operation proceed; LLDAP denies the search (50). | `2696.2.1`, `2696.2.2`, `2891.2.1`, `3673.2.2` FAIL |
| `@objectclass` raw searches denied | The @person attribute selection is not honored (50). | `4529.3.1`, `4529.3.2` FAIL |
| Extensible-match filters not supported | RFC 4511 §4.5.1.7 defines the extensibleMatch filter choice; LLDAP's filter parser does not implement it, so (uid:caseExactMatch:=alice) matches nothing. | `4517.4.6` FAIL |
| Password Modify ignores oldPasswd | RFC 3062: an incorrect oldPasswd must fail and leave the password unchanged; LLDAP changes it anyway. | `3062.3.3` FAIL |

## Rumba (rumbad)

Verified against rumbad, 2026-08-21. Project policy: where AD and
RFC behavior conflict, Rumba implements the AD behavior.

| Finding | Evidence | Verdict |
|---|---|---|
| `alias` and `referral` object classes not in schema | RFC 4511 §4.5.3 alias dereferencing and continuation references require these classes. AD's schema does not define them; Rumba rejects adds with these classes as unknown object class. Declared `alias_entries = false` / `referral_entries = false` in the capability statement. | `4511.4.5.6`, `4511.4.5.7` NOT_APPLICABLE |
| `person` lists `sn` as MAY | RFC 4519 §3 requires `sn` (MUST) on person; Rumba's schema follows MS-ADSC, where person has sn in MAY. An inetOrgPerson add without sn is accepted. Declared `person_sn_must = false`. | `4511.4.7.4`, `4512.4.5` NOT_APPLICABLE |
| Anonymous simple bind rejected by default | `allow_anonymous_bind = false` (rumbad default) returns 50. RFC 4513 permits anonymous simple bind. Configuration, not deviation; the conformance deployment enables it. | `4511.4.2.1` behavior note |
| Search base outside all naming contexts returns a referral | A base-scope search for a DN under no hosted naming context returns result 10 with `ldap://<dc-host>/`, matching AD's partition-routing behavior. Bases inside a naming context return noSuchObject (32) with a matchedDN. | behavior note |
| Bind version != 3 closes the connection without a response | RFC 4511 §4.2 requires a BindResponse with protocolError (2). Rumba drops the connection. Bug. | `4511.4.2.7` FAIL |
| Unsupported SASL mechanism returns protocolError (2) | RFC 4511 §4.2 requires authMethodNotSupported (7). AD returns 7. Bug. | `4511.4.2.9`, `4511.4.2.10` FAIL |
| Search result DNs use uppercase RDN types for AD classes | CN, OU, DC, O, L, ST, C are uppercased; other types (uid) keep stored casing. DN case is not significant (RFC 4514). | behavior note |
| Seed's `referral` entry rejected at load | Consequence of the missing referral class above; assertion 4511.4.5.4 cannot run against Rumba. | `4511.4.5.4` environment |

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
- **Assertion control (RFC 4528) never applied** — the raw control used the
  double-SEQUENCE wrapper OpenLDAP does not honor, so FALSE assertions
  silently returned success; single-SEQUENCE form fixed, `4528.3.2`/
  `4528.3.4` pass on all servers.
- **3045 root-DSE modify crashed ldap3** — ldap3 refuses empty DNs for
  modify; the NO-USER-MODIFICATION check now uses the raw layer and passes
  on 389 DS and OpenDJ (OpenLDAP stays NOT_APPLICABLE: no vendorName).
  the entryDN filter on LLDAP; now a clean FAIL ('entryDN not in schema').
- **3876 "critical control processed, not rejected" (all targets)** — the
  Compare carrying the matched-values control used the double-SEQUENCE
  controls wrapper (the same class as the 4528 bug below): servers could
  not see the control at all, so the compare simply proceeded. With the
  single-SEQUENCE form OpenLDAP, 389 DS, and OpenDJ correctly return
  unavailableCriticalExtension; only LLDAP's genuine criticality-ignored
  deviation remains.
- **2891.2.3 never exercised the sort control** — its raw search combined
  an empty present filter (`\x87\x00`, the vacuous-filter class the v2.1
  review fixed elsewhere) with the same double-SEQUENCE wrapper; every
  server failed the search itself, so the assertion could only FAIL. With
  a valid filter and advertise-gating, OpenDJ passes and 389 DS surfaces a
  genuine sortResult deviation.
- **3062.3.4 "anonymous password modify succeeded" (OpenDJ, LLDAP)** —
  ldap3's rebind(user=None) re-sends the previous identity's credentials
  (its truthiness guard skips None), so the "anonymous" rebind stayed
  authenticated and the operation legitimately succeeded. The harness now
  establishes a true anonymous bind; LLDAP rejects anonymous binds and the
  assertion reports that honestly.
