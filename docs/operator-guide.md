# Running bauble against your own LDAP server

bauble's podman fixtures (OpenLDAP, 389 DS, OpenDJ, LLDAP) are for
development and CI. The same suite runs against any LDAPv3 server with
`--server`. This guide covers what the suite assumes about the server,
how to load the seed, and how to declare the server's capabilities so
verdicts stay honest.

## The base seed

The seed (`src/bauble/fixtures/seed.ldif`) is the DIT the assertions
assume exists. It is six entries under `dc=bauble,dc=test`:

| Entry | Purpose |
|---|---|
| `dc=bauble,dc=test` | the base; subtree/base-object search anchors |
| `ou=people,dc=bauble,dc=test` | the search population (assertions page and sort over it) |
| `uid=alice,ou=people,dc=bauble,dc=test` (password `alice-secret`) | the canonical test identity: binds, compares, reads, whoami |
| `uid=bob,ou=people,dc=bauble,dc=test` (password `bob-secret`) | second identity for re-bind, password-modify, or-filter tests |
| `uid=alice-alias,ou=people,dc=bauble,dc=test` | alias entry for the derefAliases assertion |
| `ou=remote,dc=bauble,dc=test` | referral entry for the continuation-reference assertion |

The seed's naming convention matters: assertions address the people
branch as `ou=people,dc=bauble,dc=test` (override with the
`BAUBLE_TEST_BASE` env) and the identities by `uid` (override the
`dc=bauble,dc=test` suffix in the fixture files if you must). Assertions
deliberately avoid `cn` for identity matching — the 389 DS seed uses
different `cn` values than OpenLDAP's, so `uid` is the portable handle.

## Loading the seed

The fixtures load the seed automatically: OpenLDAP via `slapadd` at
build, 389 DS via its entrypoint, OpenDJ via `ldapmodify` after the
image's first-run setup, LLDAP via its own bootstrap mechanism (LLDAP
does not accept LDAP adds — its users are created through its GraphQL
API; the fixture ships user-config JSONs).

On your own server:

```sh
ldapadd -x -H ldap://host:389 -D "$BAUBLE_ADMIN_DN" -w "$BAUBLE_ADMIN_PW" \
  -f src/bauble/fixtures/seed.ldif
```

Adjustments you may need:

- **Referrals and aliases are optional.** If your server cannot store
  the `referral` or `alias` object classes, omit `ou=remote` and
  `uid=alice-alias`; only the two assertions that use them will be
  affected.
- **Passwords.** The seed stores `userPassword` in cleartext; servers
  hash on add. If your server rejects cleartext, use `{SSHA}` hashes or
  load via your admin tool.
- **Base suffix.** If your server's suffix is not `dc=bauble,dc=test`,
  rewrite the DNs in the seed and set `BAUBLE_TEST_BASE` to your people
  branch for the run.

## Declaring capability

The runner gates assertions on a capability statement (a TOML file,
defaulting to the fixture's statement under `--target`). Point `--server`
runs at the default statement, which declares nothing — so for a real
server, write one. It is the declared lever the suite uses to decide
between FAIL (server claims or should have the feature) and
NOT_APPLICABLE (server genuinely does not implement it).

Probe your server's root DSE first:

```sh
ldapsearch -x -H ldap://host:389 -D "$BAUBLE_ADMIN_DN" -w "$BAUBLE_ADMIN_PW" \
  -b "" -s base "(objectClass=*)" \
  supportedControl supportedExtension supportedFeatures supportedSASLMechanisms namingContexts
```

Then write `capability.toml`:

```toml
[server]
writable = true        # false if the LDAP interface is read-only (LLDAP)
resettable = false

[features]
naming_context = true
alt_server = false
supported_extension = ["1.3.6.1.4.1.4203.1.11.1", "1.3.6.1.4.1.4203.1.11.3"]
supported_features = ["1.3.6.1.4.1.4203.1.5.1"]
supported_control = ["1.2.840.113556.1.4.319"]
supported_sasl_mechanisms = ["EXTERNAL", "PLAIN"]
```

Run with it:

```sh
BAUBLE_ADMIN_DN="cn=Manager,dc=example,dc=com" \
BAUBLE_ADMIN_PW="secret" \
uv run bauble run --server ldap://host:389 --capability capability.toml \
  --profile core --reporter summary
```

`writable = false` makes every mutating assertion NOT_APPLICABLE instead
of failing against a read-only server — and a bare `--server` run
without a capability file starts non-writable, so mutations need
`writable = true` in the file or the `--allow-mutation` flag.
`supported_features` gates the feature-dependent assertions (the
RFC 4525 increment pair). The advertise assertions (for example
`2891.2.2`, `3062.3.2`) probe the server's live root DSE directly and
report NOT_APPLICABLE when the OID is absent; `supported_control`,
`supported_extension`, and `supported_sasl_mechanisms` are declaration
fields for the runner's applicability model — no current assertion gates
on them.

## Adjustments the suite makes for you

These were the 389 DS lessons, now built into the suite:

- **Anonymous-read policy.** Assertions that read entries bind as the
  admin identity (`BAUBLE_ADMIN_DN` / `BAUBLE_ADMIN_PW`); a server that
  denies anonymous reads (389 DS, LLDAP) works without changes.
- **Subschema location.** The subschema subentry DN (`cn=Subschema` on
  OpenLDAP, `cn=schema` on 389 DS) is discovered from the root DSE's
  `subschemaSubentry`; you do not configure it.
- **Attribute-name case.** Attribute types are case-insensitive; servers
  return them under different casing (LLDAP lowercases `entryUUID` to
  `entryuuid`). The suite's attribute lookup is case-insensitive.
- **Schema gaps.** Several mutating assertions create temporary entries
  using `inetOrgPerson` and, for the increment / integer-syntax checks,
  `posixAccount` — the seed itself does not contain posixAccount entries.
  If your schema lacks them, either add the schema or exclude the
  affected assertions. 389 DS's `uidNumber` lacks the ordering rule, so
  greaterOrEqual on it matches nothing; the integerMatch assertion tests
  numeric equality instead.
- **Admin DN.** `BAUBLE_ADMIN_DN` defaults to OpenLDAP's admin; set it
  to your server's admin (e.g. `cn=Directory Manager`).

## Reading the verdicts

- `PASS` / `FAIL` — conformance judgment with detail.
- `NOT_APPLICABLE` — the capability statement or a live probe shows the
  server does not implement the feature; absence is not a failure.
- `BLOCKED` — a prerequisite assertion was not satisfied (e.g. a test
  that needs a working simple bind ran without it in the selection).
- `UNTESTABLE` — the requirement has no portable test; the corpus notes
  why.

A summary report (`--reporter summary`) aggregates verdicts per RFC,
profile, and layer. A `FAIL` in a complete profile run is a finding about
your server; genuine deviations across implementations are recorded in
`docs/server-findings.md`, which doubles as the list of behaviors the
suite has already seen and classified.
