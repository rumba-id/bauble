# Conformance Matrix

Bauble results against multiple LDAP implementations. The same seed DIT
(`dc=bauble,dc=test`) is loaded into each server; results are comparable
across implementations.

## v1.3.0 — OpenLDAP vs 389 Directory Server

| RFC | Description | OpenLDAP | 389 DS |
|-----|-------------|----------|--------|
| 2696 | Simple Paged Results | CONFORMANT | CONFORMANT |
| 2891 | Server-Side Sorting | CONFORMANT | CONFORMANT |
| 3045 | Vendor Info in root DSE | CONFORMANT | CONFORMANT |
| 3062 | Password Modify | CONFORMANT | NON-CONFORMANT |
| 3829 | Authz Identity Controls | NON-CONFORMANT | NON-CONFORMANT |
| 3866 | Language Tags and Ranges | CONFORMANT | NON-CONFORMANT |
| 3876 | Matched Values Control | CONFORMANT | CONFORMANT |
| 4512 | Directory Information Models | CONFORMANT | NON-CONFORMANT |
| 4513 | Auth Methods / Auth State | CONFORMANT | NON-CONFORMANT |
| 4515 | Search Filter Representation | CONFORMANT | NON-CONFORMANT |
| 4517 | Syntaxes and Matching Rules | CONFORMANT | NON-CONFORMANT |
| 4519 | User-Application Schema | CONFORMANT | NON-CONFORMANT |
| 4525 | Modify-Increment | CONFORMANT | NON-CONFORMANT |
| 4526 | True/False Filters | CONFORMANT | NON-CONFORMANT |
| 4528 | Assertion Control | NON-CONFORMANT | NON-CONFORMANT |
| 4529 | Attributes by Object Class | CONFORMANT | CONFORMANT |
| 4530 | entryUUID | CONFORMANT | CONFORMANT |
| 4532 | Who Am I? | CONFORMANT | CONFORMANT |
| 5020 | entryDN | CONFORMANT | NON-CONFORMANT |

### Core profile verdict

| Server | must(A) PASS | Verdict |
|--------|--------------|---------|
| OpenLDAP | 24/33 | NON-CONFORMANT (2 assertion-control gaps) |
| 389 DS | 15/33 | NON-CONFORMANT |

### Notable 389 DS gaps

- **Subschema subentry** (RFC 4512 §4.2, RFC 4517, RFC 4519): 389 DS does
  not publish the subschema subentry at `cn=Subschema`, causing 8 related
  assertions to fail with resultCode 32 (noSuchObject).
- **Anonymous subtree search** (RFC 4513 §4.1): 389 DS denies anonymous
  subtree search by default.
- **entryDN** (RFC 5020): 3 of 4 assertions fail — 389 DS does not expose
  entryDN with `+` operational attribute requests.
- **Language tags** (RFC 3866): 3 of 5 fail.

## Running against 389 DS

```bash
# start the 389 DS target (ports 3390 LDAP, 3637 LDAPS)
uv run bauble run --target --target-type 389ds

# run with the 389 DS admin credentials
BAUBLE_ADMIN_DN="cn=Directory Manager" BAUBLE_ADMIN_PW="bauble-admin" \
  uv run bauble run --profile core --target --target-type 389ds
```

The admin DN differs per implementation:
- OpenLDAP: `cn=admin,dc=bauble,dc=test`
- 389 DS: `cn=Directory Manager`

Override via `BAUBLE_ADMIN_DN` / `BAUBLE_ADMIN_PW` / `BAUBLE_TEST_BASE`
environment variables.
