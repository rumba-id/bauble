"""RFC 4517 — Syntaxes and Matching Rules."""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, Session
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
