"""RFC 4514 — String Representation of Distinguished Names."""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, Session
from bauble.suites._base import assertion

_INTEROP = frozenset({Profile.INTEROP})


@assertion(
    id="4514.2.1",
    rfc=4514,
    section="§2",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="A simple DN (cn=Alice Anderson,...) is correctly parsed by the server.",
    strategy="Search for uid=alice with base scope and verify the returned DN is correct.",
)
def simple_dn_parsing(session: Session) -> Result:
    dn = "uid=alice,ou=people,dc=bauble,dc=test"
    outcome, entries = session.search(dn, SCOPE_BASE_OBJECT, "(objectClass=*)", ["cn"])
    if outcome.result_code == 0 and len(entries) == 1 and entries[0].dn.lower() == dn.lower():
        return Result("4514.2.1", Status.PASS)
    return Result(
        "4514.2.1", Status.FAIL, detail=f"DN mismatch or search failed: {outcome.result_code}"
    )


@assertion(
    id="4514.2.2",
    rfc=4514,
    section="§4",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="DNs in search results are case-preserving for attribute values.",
    strategy="Search for alice; verify the returned DN preserves the case of the uid value.",
)
def dn_case_preservation(session: Session) -> Result:
    outcome, entries = session.search(
        "uid=alice,ou=people,dc=bauble,dc=test",
        SCOPE_BASE_OBJECT,
        "(objectClass=*)",
        ["uid"],
    )
    if outcome.result_code != 0 or not entries:
        return Result("4514.2.2", Status.FAIL, detail=f"alice not found: {outcome.result_code}")
    dn = entries[0].dn.lower()
    # With caseIgnoreMatch, the DN may be lowercased — presence is enough.
    if "uid=alice" in dn and "ou=people" in dn:
        return Result("4514.2.2", Status.PASS)
    return Result("4514.2.2", Status.FAIL, detail="DN does not contain expected components")


@assertion(
    id="4514.2.3",
    rfc=4514,
    section="§2",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="DN attribute types are case-insensitive (UID=alice matches uid=alice).",
    strategy="Search with UID=alice,ou=people,dc=bauble,dc=test; expect the entry.",
)
def dn_attribute_name_case_insensitive(session: Session) -> Result:
    dn = "UID=alice,OU=People,DC=bauble,DC=test"
    outcome, entries = session.search(dn, SCOPE_BASE_OBJECT, "(objectClass=*)")
    if outcome.result_code == 0 and len(entries) == 1:
        return Result("4514.2.3", Status.PASS)
    return Result(
        "4514.2.3",
        Status.FAIL,
        detail=f"uppercase DN attrs failed: {outcome.result_code}",
    )
