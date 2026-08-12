"""RFC 2891 — Server-Side Sorting of Search Results."""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.raw import sort_control_value
from bauble.session import SCOPE_WHOLE_SUBTREE, Control, Session
from bauble.suites._base import assertion

_CORE = frozenset({Profile.CORE})

_SORT_OID = "1.2.840.113556.1.4.473"


@assertion(
    id="2891.2.1",
    rfc=2891,
    section="§2",
    category=Category.CONTROL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="A search with the server-side sorting control returns sorted results.",
    strategy="Search people with sort control on uid; expect alice before bob.",
)
def sort_control_returns_sorted(session: Session) -> Result:
    outcome, results = session.search(
        "ou=people,dc=bauble,dc=test",
        SCOPE_WHOLE_SUBTREE,
        "(objectClass=inetOrgPerson)",
        ["uid"],
        controls=(
            Control(
                oid=_SORT_OID,
                value=sort_control_value(["uid"]),
                criticality=False,
            ),
        ),
    )
    if outcome.result_code != 0:
        return Result("2891.2.1", Status.FAIL, detail=f"search failed: {outcome.result_code}")
    uids = [e.attributes.get("uid", [""])[0].lower() for e in results if e.attributes.get("uid")]
    if uids == sorted(uids):
        return Result("2891.2.1", Status.PASS)
    return Result("2891.2.1", Status.FAIL, detail=f"not sorted: {uids}")
