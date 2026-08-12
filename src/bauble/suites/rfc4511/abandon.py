"""RFC 4511 §4.11 — Abandon operation.

Both requirements are timing-dependent and cannot be portably tested. They
are recorded as UNTESTABLE (Class B) with the reason.
"""

from __future__ import annotations

from bauble.model import Assertion, Category, Profile, Severity, TestClass
from bauble.registry import default_registry

_INTEROP = frozenset({Profile.INTEROP})

default_registry().register(
    Assertion(
        id="4511.4.11.1",
        rfc=4511,
        section="§4.11",
        category=Category.PROTOCOL,
        severity=Severity.MUST,
        test_class=TestClass.B,
        profiles=_INTEROP,
        text="Abandon of an in-progress operation ceases the operation.",
        strategy="Cannot portably test timing-dependent behavior.",
    )
)

default_registry().register(
    Assertion(
        id="4511.4.11.2",
        rfc=4511,
        section="§4.11",
        category=Category.PROTOCOL,
        severity=Severity.MUST,
        test_class=TestClass.B,
        profiles=_INTEROP,
        text="Abandon of an unknown messageID is silently discarded.",
        strategy="Cannot portably verify non-receipt of a response.",
    )
)
