"""Phase 0 wiring stub.

Registers one trivial assertion to prove the decorator + discovery + registry
path end to end. This module is removed once real suites land (Phase 4+).
"""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import Session
from bauble.suites._base import assertion


@assertion(
    id="0.0.0.1",
    rfc=0,
    section="—",
    category=Category.PROTOCOL,
    severity=Severity.MAY,
    test_class=TestClass.A,
    profiles=frozenset({Profile.NONE}),
    text="bauble wiring self-check: the registry discovers and stores assertions.",
)
def wiring_self_check(session: Session) -> Result:
    return Result(assertion_id="0.0.0.1", status=Status.PASS)
