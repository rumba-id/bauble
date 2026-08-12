# Assertion Coverage

Summary of implemented assertions per RFC. v1.0.0 — 57 testable, 2 UNTESTABLE.

## RFC 4511 — The Protocol (39 assertions)

| § | Operation | Assertions | Testable | UNTESTABLE |
|---|---|---|---|---|
| §4.1.12 | Controls | 2 | 2 | 0 |
| §4.2 | Bind | 8 | 8 | 0 |
| §4.5 | Search | 4 | 4 | 0 |
| §4.6 | Modify | 3 | 3 | 0 |
| §4.7 | Add | 4 | 4 | 0 |
| §4.8 | Delete | 3 | 3 | 0 |
| §4.9 | ModifyDN | 2 | 2 | 0 |
| §4.10 | Compare | 4 | 4 | 0 |
| §4.11 | Abandon | 2 | 0 | 2 |
| §4.12 | Extended | 1 | 1 | 0 |

## Schema and representation (16 assertions)

| RFC | Description | Assertions | Testable | UNTESTABLE |
|---|---|---|---|---|
| 4512 | Directory Information Models | 4 | 4 | 0 |
| 4514 | DN String Representation | 2 | 2 | 0 |
| 4515 | LDAP Filter Representation | 3 | 3 | 0 |
| 4516 | LDAP URL Format | 1 | 1 | 0 |
| 4517 | Syntaxes and Matching Rules | 2 | 2 | 0 |
| 4518 | Internationalized String Preparation | 1 | 1 | 0 |
| 4519 | User-Application Schema | 3 | 3 | 0 |

## Controls and extended operations (4 assertions)

| RFC | Description | Assertions | Testable | UNTESTABLE |
|---|---|---|---|---|
| 2696 | Simple Paged Results | 1 | 1 | 0 |
| 2891 | Server-Side Sorting | 1 | 1 | 0 |
| 3062 | Password Modify | 1 | 1 | 0 |
| 4532 | Who Am I | 1 | 1 | 0 |

## Summary

- **Total assertions:** 59
- **Testable:** 57 (all PASS on OpenLDAP)
- **UNTESTABLE:** 2 (RFC 4511 §4.11 Abandon — timing-dependent, intrinsic)
