# Assertion Coverage

Summary of implemented assertions per RFC. v1.1.0 — 97 assertions, 90 class A, 7 class B.

## RFC 4511 — The Protocol (33 assertions)

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

## Operational attribute extensions (8 assertions)

| RFC | Description | Assertions | Testable | UNTESTABLE |
|---|---|---|---|---|
| 4530 | entryUUID | 4 | 4 | 0 |
| 5020 | entryDN | 4 | 4 | 0 |

## Controls and extended operations (40 assertions)

| RFC | Description | Assertions | Testable | UNTESTABLE |
|---|---|---|---|---|
| 2696 | Simple Paged Results | 1 | 1 | 0 |
| 2891 | Server-Side Sorting | 1 | 1 | 0 |
| 3045 | Vendor Information in root DSE | 2 | 2 | 0 |
| 3062 | Password Modify | 1 | 1 | 0 |
| 3829 | Authorization Identity Controls | 2 | 1 | 1 |
| 3866 | Language Tags and Ranges | 5 | 5 | 0 |
| 3876 | Matched Values Control | 2 | 1 | 1 |
| 4513 §4.1 | Authorization State | 2 | 2 | 0 |
| 4525 | Modify-Increment | 4 | 4 | 0 |
| 4526 | Absolute True and False Filters | 3 | 2 | 1 |
| 4527 | Read Entry Controls | 2 | 2 | 0 |
| 4528 | Assertion Control | 5 | 4 | 1 |
| 4529 | Attributes by Object Class | 2 | 2 | 0 |
| 4532 | Who Am I | 1 | 1 | 0 |
| 6171 | Don't Use Copy Control | 1 | 0 | 1 |

## OpenLDAP conformance (standard profile)

| Status | Count | Detail |
|--------|-------|--------|
| PASS | 24 | Server conforms |
| AUTO_PASS | 7 | Feature not supported (vendor attrs, modify-increment, authzId) |
| FAIL | 2 | RFC 4528 assertion control — advertised but not processed |
| UNTESTABLE | 4 | Class B (SHOULD requirements, no portable test) |

## Summary

- **Total assertions:** 97
- **Class A (MUST/SHOULD/MAY, testable):** 90
- **Class B (MUST/SHOULD, untestable portably):** 7
- **RFCs covered:** 27
- **OpenLDAP Base profile:** 55/55 CONFORMANT
- **OpenLDAP Standard profile:** 2 known gaps (assertion control)
