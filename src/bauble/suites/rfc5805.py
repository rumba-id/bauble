"""RFC 5805 — LDAP Transactions."""

from __future__ import annotations

from bauble.model import Category, Layer, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, Session
from bauble.suites._base import assertion

_EXTENDED = frozenset({Profile.EXTENDED})

_TXN_START_OID = "1.3.6.1.1.21.1"


@assertion(
    id="5805.2.1",
    rfc=5805,
    section="§2",
    category=Category.EXTENDED,
    severity=Severity.SHOULD,
    test_class=TestClass.A,
    profiles=_EXTENDED,
    layer=Layer.CAPABILITY,
    oid=_TXN_START_OID,
    text="The server advertises the transaction extended operations in supportedExtension.",
    strategy="Read the root DSE supportedExtension and check for the transaction OIDs.",
    preconditions="Root DSE is readable.",
    stimulus="Search the root DSE for supportedExtension.",
    expected_observables="1.3.6.1.1.21.1 present, or NOT_APPLICABLE if not advertised.",
)
def transactions_advertised(session: Session) -> Result:
    outcome, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedExtension"]
    )
    if outcome.result_code != 0 or not entries:
        return Result("5805.2.1", Status.NOT_APPLICABLE, detail="root DSE not readable")
    extensions = entries[0].attributes.get("supportedExtension", [])
    if _TXN_START_OID in extensions:
        return Result("5805.2.1", Status.PASS)
    return Result("5805.2.1", Status.NOT_APPLICABLE, detail="transaction OIDs not advertised")
