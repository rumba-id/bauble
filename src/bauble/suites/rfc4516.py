"""RFC 4516 — The LDAP URL Format."""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, Session
from bauble.suites._base import assertion

_INTEROP = frozenset({Profile.INTEROP})


def _safe_int(value: object) -> int:
    """Return int(value), or 0 if not an integer."""
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0


@assertion(
    id="4516.1.1",
    rfc=4516,
    section="§1",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="The root DSE advertises supportedLDAPVersion including version 3.",
    strategy="Search the root DSE for supportedLDAPVersion; expect value 3.",
)
def supported_ldap_version(session: Session) -> Result:
    outcome, entries = session.search(
        "",
        SCOPE_BASE_OBJECT,
        "(objectClass=*)",
        ["supportedLDAPVersion"],
    )
    if outcome.result_code != 0 or not entries:
        return Result("4516.1.1", Status.FAIL, detail=f"root DSE not found: {outcome.result_code}")
    versions = entries[0].attributes.get("supportedLDAPVersion", [])
    if 3 in [_safe_int(v) for v in versions]:
        return Result("4516.1.1", Status.PASS)
    return Result("4516.1.1", Status.FAIL, detail=f"version 3 not in {versions}")
