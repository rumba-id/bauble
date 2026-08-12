"""RFC 6171 — Don't Use Copy Control."""

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, Session
from bauble.suites._base import assertion

_STANDARD = frozenset({Profile.STANDARD})

_DONT_USE_COPY_OID = "1.3.6.1.1.22"


@assertion(
    id="6171.3.1",
    rfc=6171,
    section="§3",
    category=Category.CONTROL,
    severity=Severity.SHOULD,
    test_class=TestClass.B,
    profiles=_STANDARD,
    text="Server SHOULD publish 1.3.6.1.1.22 in supportedControl.",
    strategy="Read root DSE supportedControl and check for the OID.",
)
def dont_use_copy_advertised(session: Session) -> Result:
    outcome, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedControl"]
    )
    if outcome.result_code != 0 or not entries:
        return Result("6171.3.1", Status.UNTESTABLE, detail="root DSE not readable")
    controls = entries[0].attributes.get("supportedControl", [])
    if _DONT_USE_COPY_OID in controls:
        return Result("6171.3.1", Status.PASS)
    return Result("6171.3.1", Status.UNTESTABLE, detail="OID not advertised")
