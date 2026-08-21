# Full LDAPv3 Coverage Plan

Status: planned. Scope decision: **everything** — behavior RFCs, replication and
transaction RFCs, schema-presence checks, and RFC 2649. This plan supersedes the
v2.x roadmap's non-goals for replication, content-sync, and transactions.

## Goal

Cover every non-deprecated LDAPv3 standard. The corpus is the current tier of
`docs/references.md`. Coverage facts stay live: run `bauble coverage`. This
document records scope and backlog only — no committed counts.

## Corpus

Four tiers, per `docs/references.md`:

- **Core protocol** — RFC 4511–4519 (RFC 4510 is an informational road map).
- **Protocol/operational extensions** — controls, extended operations,
  operational attributes, matching rules, encodings.
- **Replication / transactions** — RFC 3928, 4373, 4533, 5805.
- **Schema-only** — object class and attribute type definitions.

## Principles

- One RFC = one suite module + one requirements TOML.
- Advertise-then-test: capability-layer assertions gate on advertised OIDs.
- A feature no mainstream server implements still gets a full requirements
  corpus plus a capability assertion (honest `NOT_APPLICABLE`). Coverage is
  measured against the specification, not against fixture availability.
- Class-B (intrinsically untestable) requirements are recorded with reasons,
  never silently dropped.

## Work streams

### 1. New behavior RFC suites

| RFC | Title | Assertions (approx.) | Key infra needed | Effort |
|---|---|---|---|---|
| 4516 | LDAP URL | 3 — URL syntax in `namingContexts`/`ref` values | none | S |
| 4522 | Binary Encoding Option | 2–3 — `;binary` transfer returns BER octet string | certificate-syntax attribute in the fixture (RFC 4523); jpegPhoto is not binary-transfer-required | M |
| 3698 | Additional Matching Rules | 3–4 — extensible-match substring rules | extensible-match builder exists | S–M |
| 3687 | Component Matching Rules | 2–3 — `componentFilterMatch` | component-filter value BER | M |
| 3909 | Cancel | 3–4 — cancel in-flight op, `tooLate` branch | slow-search + `RawSession` (abandon template exists) | M |
| 4370 | Proxied Authorization | 3 — proxy bind + Who-Am-I identity check | none (RFC 4532 covered) | M |
| 4531 | Turn | 2 — advertise-then-test | none | S–M |
| 3296 | Named Subordinate References | 3–4 — `referral` class, `ref` attribute, continuation | `referral_entries` capability exists | M |
| 3672 | Subentries | 3–4 — subentries control returns the subentry | subentry seed + control OID | L |
| 3671 | Collective Attributes | 3–4 — collective attribute, visibility control | collective seed + control OID | L |
| 2589 | Dynamic Directory Services | 3 — `dynamicObject` + `entryTtl` expiry | dynamicObject seed | M–L |

Note: RFC 3698's matching rules are absorbed by RFC 4517 (which updates
3698); a separate suite would duplicate 4517. The distinct 3698 surface is
the ordering rules (integerOrderingMatch, octetStringOrderingMatch). RFC 3687
(componentFilterMatch) is distinct and gets its own suite.

### 2. Replication and transactions

Full corpus for each; live semantic tests only where a fixture implements the
feature.

| RFC | Title | Live-test reality | Deliverable |
|---|---|---|---|
| 4533 | Content Synchronization Operation | OpenLDAP with the syncprov overlay can serve sync | full suite: sync request, state, cookie, modify + re-sync, syncInfo |
| 3928 | LDAP Client Update Protocol (LCUP) | no mainstream implementation | corpus + advertise assertion (honest `NOT_APPLICABLE`) |
| 4373 | LDAP Bulk Update/Replication Protocol (LBURP) | no mainstream implementation | corpus + advertise assertion |
| 5805 | LDAP Transactions | no mainstream implementation | corpus + advertise assertion |

### 3. Schema-presence checks (23 schema RFCs)

A data table of (RFC, defining object classes / attribute types) drives one
assertion per RFC: when the subschema declares any of that RFC's elements, it
must declare all of them. `NOT_APPLICABLE` when the server loads none of the
schema (absence of an optional schema is conformant); `FAIL` when partial. RFC
2798 (inetOrgPerson) folds into RFC 4519's presence check.

RFCs: 2247, 2798, 2926, 2985, 3112, 4524 · 2079, 2307, 2713, 2714, 2739, 3641,
3642, 3703, 3727, 4104, 4403, 4523, 4792, 4876, 5803, 7612, 8284.

### 4. RFC 2649 (Operation Signatures)

Corpus + advertise assertion. No mainstream server implements the signed
operation control; a live semantic test is not possible today.

### 5. Class-A partial closures

| Requirement | Missing obligation | Effort |
|---|---|---|
| 4528:3:3 | assertion control on Add/Modify/ModifyDN (Delete only today) | S |
| 4528:3:4 | "no entries returned" (resultCode only today) | S |
| 4511:4.2:9 | re-bind proves the new identity via Who-Am-I | S |
| 4513:3:4 | client-side SHOULD — re-attribute to class D, or accept | S |
| 3829:4:1 | authzId value + anonymous-empty branch | M |
| 4527:3:1 / 3:2 | parse SearchResultEntry inside the response control | M — BER parser |
| 3045:2:1 / 2:2 | subschema declares NO-USER-MODIFICATION | M |
| 3673:2:1 | `+` returns *all* operational attributes | M (partly intrinsic) |

### 6. Corpus, infrastructure, and documentation

- One requirements TOML per new RFC, matching `requirements/rfc4530.toml`.
- Reason-audit the class-B uncovered requirements; every one carries a `note`.
- BER entry-in-control parser in `raw.py` (prerequisite for 4527 content).
- Binary seed attribute (`jpegPhoto` or `userCertificate`) for RFC 4522.
- Capability OIDs for cancel, proxied authorization, turn, subentries,
  collective attributes, dynamic services, content sync — into the fixture
  statements and the operator guide.
- README Scope: re-add RFC 4516 to core; add the new extension RFCs.
- v2.x roadmap: replication/transaction non-goals are superseded by this plan.

## Phases

| Phase | Content | Done when |
|---|---|---|
| 0 — Infra | BER entry parser, binary seed attribute, capability OIDs, reason-audit | infra green, no new assertions |
| 1 — Core + small | 4516, 4522, 3698, 3687 | suites + corpus live, goldens green |
| 2 — Controls/exops | 3909, 4370, 4531, 3296 | suites + corpus live, goldens green |
| 3 — DIT features | 3672, 3671, 2589 | suites + corpus live, goldens green |
| 4 — Partials | the class-A items above | `bauble coverage` shows zero class-A partial/uncovered in the covered corpus |
| 5 — Schema presence | the 23 schema RFCs | presence checks live, goldens green |
| 6 — Replication/transactions | 4533 suite; 3928/4373/5805 corpus + advertise; 2649 | corpus + advertise live; 4533 suite live where the fixture supports sync |

**Phase 1 shipped.** RFC 4516 (LDAP URL), 4522 (Binary Encoding Option), 3698
(ordering rules), and 3687 (component matching) all have suites + corpora,
live-verified on OpenLDAP. Phase 0's raw-layer `build_add_request` landed with
RFC 4522.

**Phase 2 shipped.** RFC 3909 (Cancel), 4370 (Proxied Authorization), 4531
(Turn), and 3296 (Named Subordinate References) have suites + corpora,
verified against all four targets. Behaviorals for optional extensions are
gated on advertisement (NOT_APPLICABLE when the OID is absent). Three new
findings documented in server-findings.md; goldens regenerated for all
targets.

**Phase 3 shipped.** RFC 3672 (Subentries), 3671 (Collective Attributes), and
2589 (Dynamic Directory Services) have suites + corpora with capability-layer
advertise assertions plus behavioral tests for RFC 3672 (subentry hide/show) and
RFC 2589 (dynamicObject entryTtl decrement), unlocked by fixture schema work:
the OpenLDAP target now loads the dds overlay (dds-default-ttl 2), collective.schema,
and a subentry schema for the collectiveAttributeSubentry objectClass. RFC 3671
stays class-B: OpenLDAP loads the collective schema but does not evaluate
collective attributes.

**Phase 4 shipped.** All class-A partially-covered requirements are closed:
4528 assertion-on-Add/Modify/ModifyDN, 4527 Pre/Post-Read content parsing, 4511
re-bind identity, 3829 authzId value + anonymous, 3045 subschema declaration.
Intrinsic/client-side obligations (messageID-0 notification, client-side TLS
refresh, '+' exhaustive op-attr set) were re-attributed as requirement notes.
`bauble coverage` now reports zero class-A partial/uncovered.

**Phase 5 shipped.** Data-driven subschema-presence checks (suites/schema.py)
cover the 19 schema-definition RFCs: when a schema is loaded, its defining
object classes and attribute types must be published. The four GSER/ASN.1
encoding RFCs (3641, 3642, 3727, 4792) are recorded as class-B (no schema
elements). Surfaced a finding: 389 DS loads a partial COSINE schema.

**Phase 6 shipped.** RFC 4533 (Content Synchronization) suite: syncprov overlay
loaded in the OpenLDAP fixture; advertise + refreshOnly syncRequest behavioral
(syncDone with a cookie). RFC 5805 (Transactions) advertise; RFC 3928 (LCUP),
4373 (LBURP), and 2649 (Operation Signatures) recorded as class-B corpus
entries. Finding: OpenLDAP advertises txnStart but returns protocolError —
advertises without implementing.

**Series complete.** Every current-tier RFC in references.md (74) has a corpus
TOML. 57 have suites with live assertions; the remaining 17 are corpus-only
class-B: the informational/BCP/format tier (1823, 2377, 2820, 2849, 3352, 3384,
3494, 4510, 4520, 4521 — no testable server requirements), the GSER/ASN.1
encoding specs (3641, 3642, 3727, 4792), and the unimplemented replication/
transaction/signature RFCs (3928, 4373, 2649). `bauble coverage` reports zero
class-A partial/uncovered; every uncovered requirement is class-B with a
recorded reason.

## Definition of done

Every RFC in `docs/references.md` current tier has a corpus TOML; every RFC
with testable server behavior additionally has a suite module. `bauble coverage`
reports zero class-A UNCOVERED and zero PARTIALLY_COVERED across the corpus; the
only uncovered requirements remaining are class-B with recorded reasons. CI
goldens pass on all four targets. README Scope, the roadmap, and the operator
guide match the implemented surface.
