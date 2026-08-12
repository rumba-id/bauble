"""RFC 4512 — Directory Information Models."""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, SCOPE_WHOLE_SUBTREE, Session
from bauble.suites._base import assertion

_INTEROP = frozenset({Profile.INTEROP})
_CORE = frozenset({Profile.CORE})
_SUBSCHEMA = "cn=Subschema"


@assertion(
    id="4512.4.1",
    rfc=4512,
    section="§4.1",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="The root DSE is accessible and returns entries.",
    strategy="Search the root DSE (base scope) with (objectClass=*); expect at least 1 entry.",
)
def root_dse_accessible(session: Session) -> Result:
    outcome, entries = session.search("", SCOPE_BASE_OBJECT, "(objectClass=*)")
    if outcome.result_code == 0 and len(entries) >= 1:
        return Result("4512.4.1", Status.PASS)
    return Result(
        "4512.4.1",
        Status.FAIL,
        detail=f"expected >=1 entry / code 0, got {len(entries)} / {outcome.result_code}",
    )


@assertion(
    id="4512.4.2",
    rfc=4512,
    section="§4.2",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="The subschema subentry is accessible and carries objectClasses.",
    strategy="Search cn=Subschema; verify objectClasses attribute has values.",
)
def subschema_has_object_classes(session: Session) -> Result:
    outcome, entries = session.search(
        _SUBSCHEMA,
        SCOPE_BASE_OBJECT,
        "(objectClass=*)",
        ["objectClasses"],
    )
    if outcome.result_code != 0 or not entries:
        return Result(
            "4512.4.2", Status.FAIL, detail=f"subschema not found: {outcome.result_code}"
        )
    attr = entries[0].attributes.get("objectClasses")
    if attr and len(attr) > 0:
        return Result("4512.4.2", Status.PASS)
    return Result("4512.4.2", Status.FAIL, detail="objectClasses absent or empty")


@assertion(
    id="4512.4.3",
    rfc=4512,
    section="§4.2",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="The subschema subentry carries attributeTypes.",
    strategy="Search cn=Subschema; verify attributeTypes attribute has values.",
)
def subschema_has_attribute_types(session: Session) -> Result:
    outcome, entries = session.search(
        _SUBSCHEMA,
        SCOPE_BASE_OBJECT,
        "(objectClass=*)",
        ["attributeTypes"],
    )
    if outcome.result_code != 0 or not entries:
        return Result(
            "4512.4.3", Status.FAIL, detail=f"subschema not found: {outcome.result_code}"
        )
    attr = entries[0].attributes.get("attributeTypes")
    if attr and len(attr) > 0:
        return Result("4512.4.3", Status.PASS)
    return Result("4512.4.3", Status.FAIL, detail="attributeTypes absent or empty")


@assertion(
    id="4512.4.4",
    rfc=4512,
    section="§3.2",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="Every searchable entry has an objectClass attribute.",
    strategy="Search the base DIT subtree; verify every entry has objectClass.",
)
def entries_have_object_class(session: Session) -> Result:
    outcome, entries = session.search(
        "dc=bauble,dc=test",
        SCOPE_WHOLE_SUBTREE,
        "(objectClass=*)",
        ["objectClass"],
    )
    if outcome.result_code != 0:
        return Result("4512.4.4", Status.FAIL, detail=f"search failed: {outcome.result_code}")
    for entry in entries:
        if "objectClass" not in entry.attributes or not entry.attributes["objectClass"]:
            return Result("4512.4.4", Status.FAIL, detail=f"entry {entry.dn} missing objectClass")
    return Result("4512.4.4", Status.PASS)
