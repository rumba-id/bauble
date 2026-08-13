# Conformance Matrix

Bauble results against multiple LDAP implementations. The same seed DIT
(`dc=bauble,dc=test`) is loaded into each server; results are comparable
across implementations.

## v2.0.0 — OpenLDAP vs 389 Directory Server

### Interop profile, per layer

| Layer | OpenLDAP | 389 DS |
|-------|----------|--------|
| Wire | 5/5 | 5/5 |
| Semantic | 58/58 | 43/58 (15 fail) |
| Capability | 1/1 | 1/1 |

### 389 DS semantic failures (15)

| Cause | Count | RFCs |
|-------|-------|------|
| Subschema subentry not published at `cn=Subschema` | 8 | 4512, 4517, 4519 |
| Anonymous compare/search denied by default ACL | 7 | 4511, 4515, 4517 |

### Notes

- **Subschema (8 failures)** is a genuine RFC 4512 gap. 389 DS does not
  publish the subschema subentry where RFC 4512 §4.2 requires it.
- **Anonymous access (7 failures)** is a configuration difference, not a
  protocol violation. RFC 4513 §4.1 mandates treating unauthenticated
  operations as anonymous, but access control policy is a local matter.
  389 DS ships with stricter default ACLs than OpenLDAP.

### Wire layer — conformant on both

Both servers correctly decode/encode LDAPMessage BER, echo messageIDs,
reject bad protocol versions, and handle malformed PDUs.

## Running against 389 DS

```bash
# start the 389 DS target (ports 3390 LDAP, 3637 LDAPS)
uv run bauble run --target --target-type 389ds

# run with the 389 DS admin credentials
BAUBLE_ADMIN_DN="cn=Directory Manager" BAUBLE_ADMIN_PW="bauble-admin" \
  uv run bauble run --profile interop --target --target-type 389ds
```

The admin DN differs per implementation:
- OpenLDAP: `cn=admin,dc=bauble,dc=test`
- 389 DS: `cn=Directory Manager`

Override via `BAUBLE_ADMIN_DN` / `BAUBLE_ADMIN_PW` / `BAUBLE_TEST_BASE`
environment variables.
