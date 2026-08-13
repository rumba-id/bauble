"""RFC 4517 — Syntaxes and Matching Rules."""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, SCOPE_WHOLE_SUBTREE, Session
from bauble.suites._base import assertion

_INTEROP = frozenset({Profile.INTEROP})
_CORE = frozenset({Profile.CORE})
_SUBSCHEMA = "cn=Subschema"


@assertion(
    id="4517.4.1",
    rfc=4517,
    section="§4.1",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="The subschema advertises ldapSyntaxes.",
    strategy="Search cn=Subschema for ldapSyntaxes; verify it has values.",
)
def ldap_syntaxes_present(session: Session) -> Result:
    outcome, entries = session.search(
        _SUBSCHEMA,
        SCOPE_BASE_OBJECT,
        "(objectClass=*)",
        ["ldapSyntaxes"],
    )
    if outcome.result_code != 0 or not entries:
        return Result(
            "4517.4.1", Status.FAIL, detail=f"subschema not found: {outcome.result_code}"
        )
    attr = entries[0].attributes.get("ldapSyntaxes")
    if attr and len(attr) > 0:
        return Result("4517.4.1", Status.PASS)
    return Result("4517.4.1", Status.FAIL, detail="ldapSyntaxes absent or empty")


@assertion(
    id="4517.4.2",
    rfc=4517,
    section="§4.2",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="The subschema advertises matchingRules.",
    strategy="Search cn=Subschema for matchingRules; verify it has values.",
)
def matching_rules_present(session: Session) -> Result:
    outcome, entries = session.search(
        _SUBSCHEMA,
        SCOPE_BASE_OBJECT,
        "(objectClass=*)",
        ["matchingRules"],
    )
    if outcome.result_code != 0 or not entries:
        return Result(
            "4517.4.2", Status.FAIL, detail=f"subschema not found: {outcome.result_code}"
        )
    attr = entries[0].attributes.get("matchingRules")
    if attr and len(attr) > 0:
        return Result("4517.4.2", Status.PASS)
    return Result("4517.4.2", Status.FAIL, detail="matchingRules absent or empty")


@assertion(
    id="4517.4.3",
    rfc=4517,
    section="§4.2",
    category=Category.SCHEMA,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="caseIgnoreMatch compares attribute values case-insensitively.",
    strategy="Search (cn=ALICE ANDERSON); expect Alice Anderson matches.",
)
def case_ignore_match(session: Session) -> Result:
    outcome, entries = session.search(
        "dc=bauble,dc=test", SCOPE_WHOLE_SUBTREE, "(cn=ALICE ANDERSON)"
    )
    if outcome.result_code == 0 and any(e.dn.startswith("uid=alice") for e in entries):
        return Result("4517.4.3", Status.PASS)
    return Result("4517.4.3", Status.FAIL, detail="caseIgnoreMatch failed")


@assertion(
    id="4517.4.4",
    rfc=4517,
    section="§4.2",
    category=Category.SCHEMA,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="integerMatch compares attribute values numerically.",
    strategy="Add entry with uidNumber=100, search (uidNumber>=50); expect it returned.",
    mutates=True,
)
def integer_match(session: Session) -> Result:
    from bauble.suites._helpers import TEST_BASE, bind_admin, cleanup

    bind_admin(session)
    dn = f"uid=intmatch,{TEST_BASE}"
    cleanup(session, dn)
    attrs: dict[str, list[str | bytes]] = {
        "objectClass": ["inetOrgPerson", "posixAccount"],
        "cn": ["IntMatch"],
        "sn": ["Match"],
        "uid": ["intmatch"],
        "uidNumber": ["100"],
        "gidNumber": ["100"],
        "homeDirectory": ["/home/intmatch"],
    }
    add_outcome = session.add(dn, attrs)
    if add_outcome.result_code != 0:
        return Result(
            "4517.4.4",
            Status.FAIL,
            detail=f"posixAccount add failed: {add_outcome.result_code}",
        )
    try:
        outcome, entries = session.search(TEST_BASE, SCOPE_WHOLE_SUBTREE, "(uidNumber>=50)")
        if outcome.result_code == 0 and any(e.dn == dn for e in entries):
            return Result("4517.4.4", Status.PASS)
        return Result("4517.4.4", Status.FAIL, detail="integerMatch >= failed")
    finally:
        cleanup(session, dn)


@assertion(
    id="4517.4.5",
    rfc=4517,
    section="§4.2",
    category=Category.SCHEMA,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="generalizedTimeMatch compares timestamps chronologically.",
    strategy="Search (modifyTimestamp>=20200101000000Z); expect recently-added entries.",
)
def generalized_time_match(session: Session) -> Result:
    outcome, entries = session.search(
        "dc=bauble,dc=test",
        SCOPE_WHOLE_SUBTREE,
        "(modifyTimestamp>=20200101000000Z)",
        ["modifyTimestamp"],
    )
    if outcome.result_code == 0 and len(entries) >= 2:
        return Result("4517.4.5", Status.PASS)
    return Result("4517.4.5", Status.FAIL, detail="generalizedTimeMatch failed")
