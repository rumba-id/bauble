"""RFC 3671 — Collective Attributes in the Lightweight Directory Access Protocol.

RFC 3671 defines no LDAP control. Its conformance surface is the
collective attribute schema (c-l, c-ou, ...; §2) and the inheritance
requirement (§3): entries within the scope of a collective attribute
subentry see the collective attributes as their own. No reference
server evaluated collectives at the time of writing (the RFC 3671
inheritance requirement is recorded as class-B in the corpus), so the
only portable check is subschema publication of the collective
attribute definitions — servers that load the collective schema must
publish it (RFC 4512 §4.2).
"""

from __future__ import annotations

from bauble.model import Category, Layer, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, Session
from bauble.suites._base import assertion
from bauble.suites._helpers import bind_admin, subschema_dn

_CORE = frozenset({Profile.CORE})

#: RFC 3671 §2.3 — the operational attribute identifying the collective
#: attribute subentries that affect an entry.
_COLLECTIVE_SUBENTRIES_ATTR = "collectiveAttributeSubentries"


@assertion(
    id="3671.2.1",
    rfc=3671,
    section="§2",
    category=Category.DATA_MODEL,
    severity=Severity.SHOULD,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.CAPABILITY,
    text="When the collective schema is loaded, the subschema publishes its defining attributes.",
    strategy=(
        "Read the subschema attributeTypes and check for the collective attribute "
        "definitions (c-l, c-ou) and the collectiveAttributeSubentries operational attribute."
    ),
    preconditions="Admin bound; the subschema subentry is advertised.",
    stimulus="Search the subschema requesting attributeTypes.",
    expected_observables=(
        "The collective attribute definitions are present, or NOT_APPLICABLE "
        "if the schema is not loaded."
    ),
)
def collective_schema_published(session: Session) -> Result:
    bind_admin(session)
    dn = subschema_dn(session)
    if dn is None:
        return Result("3671.2.1", Status.NOT_APPLICABLE, detail="subschemaSubentry not advertised")
    outcome, entries = session.search(
        dn, SCOPE_BASE_OBJECT, "(objectClass=*)", ["attributeTypes"]
    )
    if outcome.result_code != 0 or not entries:
        return Result("3671.2.1", Status.NOT_APPLICABLE, detail="subschema not readable")
    definitions = " ".join(
        str(v) for v in entries[0].attributes.get("attributeTypes", [])
    ).lower()
    if not definitions:
        return Result("3671.2.1", Status.NOT_APPLICABLE, detail="schema not loaded")
    elements = ("c-l", "c-ou", _COLLECTIVE_SUBENTRIES_ATTR)
    present = [e for e in elements if f"'{e}'" in definitions]
    if present and len(present) == len(elements):
        return Result("3671.2.1", Status.PASS)
    if not present:
        # The collective schema is not loaded; the SHOULD does not apply.
        return Result("3671.2.1", Status.NOT_APPLICABLE, detail="collective schema not loaded")
    return Result(
        "3671.2.1", Status.FAIL, detail=f"partial collective schema: missing {set(elements) - set(present)}"
    )
