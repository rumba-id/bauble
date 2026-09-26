"""Schema-presence checks for schema-definition RFCs (Phase 5).

A schema RFC defines object classes and attribute types (data), not protocol
behavior. The only conformance-relevant surface is subschema publication
(RFC 4512 §4.2): when a server loads a schema, it must publish that schema's
defining elements. These assertions verify that publication.

Five RFCs in the schema tier define no object classes or attribute
types — the GSER/ASN.1 encoding specifications (3641, 3642, 3727, 4792)
and RFC 5803 (a usage profile of authPassword for SCRAM secrets). They
are recorded as class-B in the corpus, not presence-checked.
"""

from __future__ import annotations

from bauble.model import Category, Layer, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, Session
from bauble.suites._base import assertion
from bauble.suites._helpers import bind_admin, subschema_dn

_CORE = frozenset({Profile.CORE})

#: RFC -> defining object class / attribute type names.
_SCHEMA_ELEMENTS: dict[int, tuple[str, ...]] = {
    2079: ("labeledURI",),
    2247: ("dcObject", "domain", "dc"),
    2307: ("posixAccount", "posixGroup", "uidNumber", "gidNumber"),
    2713: ("javaObject", "javaClassName"),
    2714: ("corbaObject", "corbaIor"),
    2739: ("calEntry",),
    2798: ("inetOrgPerson",),
    2926: ("slpService", "template-url-syntax"),
    2985: ("friendlyCountryName",),
    3112: ("authPassword",),
    # RFC 3703/4104 map the X.500 PolicyGroup to the LDAP pcimGroup.
    3703: ("pcimGroup",),
    4104: ("pcimGroup",),
    4403: ("uddiBusinessEntity",),
    4523: ("pkiUser", "userCertificate"),
    4524: ("pilotPerson", "account"),
    4876: ("DUAConfigProfile",),
    7612: ("printerService",),
    8284: ("JIDObject", "jid"),
}


def _declared(definitions: str, name: str) -> bool:
    """True when the subschema definitions declare ``name`` (case-insensitive).

    Matches the name in any NAME list position: single-name
    ``NAME 'x'`` and multi-name ``NAME ( 'x' 'y' )`` both quote every
    name, so a quoted occurrence is a declaration.
    """
    n = name.lower()
    return f"'{n}'" in definitions


def _check_schema_presence(session: Session, elements: tuple[str, ...], aid: str) -> Result:
    bind_admin(session)
    dn = subschema_dn(session)
    if dn is None:
        return Result(aid, Status.NOT_APPLICABLE, detail="subschemaSubentry not advertised")
    outcome, entries = session.search(
        dn, SCOPE_BASE_OBJECT, "(objectClass=*)", ["objectClasses", "attributeTypes"]
    )
    if outcome.result_code != 0 or not entries:
        return Result(aid, Status.NOT_APPLICABLE, detail="subschema not readable")
    attrs = entries[0].attributes
    definitions = " ".join(
        str(v) for v in attrs.get("objectClasses", []) + attrs.get("attributeTypes", [])
    ).lower()
    present = [e for e in elements if _declared(definitions, e)]
    if not present:
        return Result(aid, Status.NOT_APPLICABLE, detail="schema not loaded")
    missing = [e for e in elements if e not in present]
    if missing:
        return Result(aid, Status.FAIL, detail=f"partial schema: missing {missing}")
    return Result(aid, Status.PASS)


def _register(rfc: int, elements: tuple[str, ...]) -> None:
    """Register one schema-presence assertion for ``rfc``."""

    def runner(session: Session) -> Result:
        return _check_schema_presence(session, elements, f"{rfc}.1")

    assertion(
        id=f"{rfc}.1",
        rfc=rfc,
        section="§schema",
        category=Category.SCHEMA,
        severity=Severity.MUST,
        test_class=TestClass.A,
        profiles=_CORE,
        layer=Layer.CAPABILITY,
        text=f"The subschema publishes the defining schema elements of RFC {rfc}.",
        strategy="Read the subschema objectClasses and attributeTypes and check for the RFC's defining elements.",
        preconditions="Admin bound; the subschema subentry is advertised.",
        stimulus="Search the subschema requesting objectClasses and attributeTypes.",
        expected_observables=(
            "All defining elements present, or NOT_APPLICABLE if the schema is not loaded."
        ),
    )(runner)


for _rfc, _elements in sorted(_SCHEMA_ELEMENTS.items()):
    _register(_rfc, _elements)
