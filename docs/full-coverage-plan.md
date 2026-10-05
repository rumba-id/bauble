# Full LDAPv3 Coverage Plan

Status: **executed** (Phases 1–6 shipped; see the phase notes). Scope decision:
**everything** — behavior RFCs, replication and transaction RFCs, schema-presence
checks, and RFC 2649. This plan supersedes the v2.x roadmap's non-goals for
replication, content-sync, and transactions. It is a historical record plus a
residual-work list; the authoritative RFC enumeration is `docs/references.md`
and the authoritative coverage facts are live in `bauble coverage`.

## Corpus

Five tiers, per `docs/references.md`:

- **Core protocol** — RFC 4511–4519 (RFC 4510 is an informational road map).
- **Protocol/operational extensions** — controls, extended operations,
  operational attributes, matching rules, encodings.
- **Replication / transactions** — RFC 3928, 4373, 4533, 5805.
- **Schema-only** — object class and attribute type definitions.
- **Informational / BCP / format** — RFC 1823, 2377, 2820, 2849, 3352, 3384,
  3494, 4510, 4520, 4521: no testable directory-server requirements (LDIF is a
  tool-side file format; the BCPs govern IANA and extension authors; the rest
  are informational or status-change documents). Recorded as corpus-only
  class-B so the corpus enumerates the whole current tier.

## Principles

- One RFC = one suite module + one requirements TOML; RFCs with no testable
  server behavior get the TOML only.
- Advertise-then-test: behaviorals for optional extensions gate on the **live
  root DSE** advertisement and return `NOT_APPLICABLE` when the OID is absent.
- A feature no mainstream server implements still gets a full requirements
  corpus (honest `NOT_APPLICABLE`), measured against the specification.
- Class-B (intrinsically untestable) requirements are recorded with reasons,
  never silently dropped.

## Delivered

### Behavior RFC suites

RFC 4516 (LDAP URL: continuation-reference URI and `ref` validity),
4522 (Binary Encoding: certificate-syntax `;binary` transfer), 3698
(integerOrderingMatch), 3687 (component/rdnMatch advertise), 3909 (Cancel:
advertise + unknown-ID `noSuchOperation`), 4370 (Proxied Authorization:
advertise + criticality-MUST + positive identity via Who-Am-I-with-control),
4531 (Turn: advertise), 3296 (referral objectClass + `ref`), 3672 (Subentries:
advertise + hide/show), 3671 (Collective: advertise), 2589 (Dynamic: advertise +
entryTtl decrement), 4533 (Content Sync: advertise + refreshOnly cookie +
incremental re-sync with syncState), 5805 (Transactions: advertise), 2649
(corpus only).

### Schema presence

`suites/schema.py`: a data table drives one subschema-publication assertion per
schema-definition RFC — PASS when the schema is fully published, FAIL when
partial, NOT_APPLICABLE when not loaded. The four GSER/ASN.1 encoding RFCs
(3641, 3642, 3727, 4792) define no schema elements and are corpus-only class-B.

### Class-A partial closures

4528 assertion-control on Add/Modify/ModifyDN and no-entries; 4527 Pre/Post-Read
response-control content (a bare-SearchResultEntry parser in `raw.py`);
4511 re-bind identity via Who-Am-I; 3829 authzId value + anonymous branch;
3045 subschema NO-USER-MODIFICATION declaration. Intrinsic/client-side
obligations (messageID-0 notification, client-side TLS refresh, `+` exhaustive
set) were re-attributed as requirement notes.

### Divergences from the original plan

- Phase 0 never ran as a phase: `build_add_request`, the response-control
  parsers, and `build_control`/`build_extended_request` landed incrementally
  with the suites that needed them.
- Fixture gating reads the live root DSE, so the promised fixture capability
  statements / operator-guide OID updates were not needed and were not done.
- The 4522 fixture prerequisite is a committed self-signed certificate
  (PEM→DER via `ssl`), not a binary seed attribute.
- 3671's behavioral stayed class-B after fixture work: OpenLDAP loads the
  collective schema but does not evaluate collective attributes.
- 4516's original "URL syntax in namingContexts" item was wrong —
  `namingContexts` values are DNs, not URLs; the suite covers referral URIs
  and the `ref` attribute instead.

## Phases

| Phase | Content | Done when |
|---|---|---|
| 1 — Core + small | 4516, 4522, 3698, 3687 | suites + corpus live, goldens green |
| 2 — Controls/exops | 3909, 4370, 4531, 3296 | suites + corpus live, goldens green |
| 3 — DIT features | 3672, 3671, 2589 | suites + corpus live, goldens green |
| 4 — Partials | the class-A items above | zero class-A partial/uncovered |
| 5 — Schema presence | the schema tier | presence checks live, goldens green |
| 6 — Replication/transactions | 4533; 3928/4373/5805/2649 corpus | corpus + advertise live |

**Phase 1.** RFC 4516, 4522, 3698, 3687 — suites + corpora, live-verified on
OpenLDAP. Surfaced: `;binary` requires a certificate-syntax attribute
(jpegPhoto may be omitted per RFC 4522 §5–6), and a latent BER bug in
`build_search_request`'s default present filter.

**Phase 2.** RFC 3909, 4370, 4531, 3296 — verified against all four targets.
Established the advertise-gating convention (behaviorals return NOT_APPLICABLE
when the OID is absent). Findings: OpenLDAP honors a non-critical proxy-authz
control (RFC 4370 §3 deviation); 389 DS ManageDsaIT and uidNumber-ORDERING
deviations (the latter now asserted by 3698.2.7); OpenDJ omits `ref`.

**Phase 3.** RFC 3672, 3671, 2589 — advertise assertions plus behaviorals for
3672 (subentry hide/show, via the raw layer: OpenLDAP carries the subentries
control value as BOOLEAN TRUE and ldap3's encoding is rejected) and 2589
(entryTtl is NO-USER-MODIFICATION; the dds overlay assigns it, `dds-default-ttl 2`).
3671 stays class-B. Fixture: dds + syncprov + collective.schema + subentry.schema.

**Phase 4.** Zero class-A partial/uncovered.

**Phase 5.** Schema-presence checks for the schema tier; finding: 389 DS loads
a partial COSINE schema (`account` without `pilotPerson`).

**Phase 6.** RFC 4533 suite (syncprov in the fixture; refreshOnly cookie +
incremental re-sync with syncState add/entryUUID), 5805 advertise (finding:
OpenLDAP advertises txnStart but returns protocolError), 3928/4373/2649
corpus-only class-B.

**Completion.** Every current-tier RFC in `docs/references.md` has a corpus
TOML; every RFC with testable server behavior additionally has a suite module.
`bauble coverage` reports zero class-A uncovered and zero partially covered;
every uncovered requirement is class-B with a recorded reason. CI goldens pass
on all four targets; the README Scope matches the suites bidirectionally.

## Residual work

Genuinely remaining, in rough value order:

- 4533 refreshAndPersist streaming and the syncInfo intermediate response
  (class-B: needs a concurrent second client).
- 3909 in-flight cancel / `tooLate` branch (class-B: timing-racy).
- 4370:3:3 policy-denial branch (resultCode 123): needs a fixture account
  denied proxy rights.
- 3671 collective evaluation: blocked on a server that implements it
  (no mainstream server does).
- Fixture capability statements / operator guide do not enumerate the new
  control OIDs — harmless today (gating reads the live root DSE) but worth
  reconciling if capability-file gating returns.
- Pre-existing mado lint defects in `server-findings.md` (a `|` inside a
  quoted cell) and the older plan documents.

## Definition of done

Every RFC in `docs/references.md` current tier has a corpus TOML; every RFC
with testable server behavior additionally has a suite module. `bauble coverage`
reports zero class-A UNCOVERED and zero PARTIALLY_COVERED across the corpus; the
only uncovered requirements remaining are class-B with recorded reasons. CI
goldens pass on all four targets. README Scope, the roadmap, and the operator
guide match the implemented surface.
