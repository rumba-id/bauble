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


@assertion(
    id="4512.4.5",
    rfc=4512,
    section="§4.1",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="An entry missing a MUST attribute is rejected.",
    strategy="Add inetOrgPerson without sn (surname); expect objectClassViolation (65).",
    mutates=True,
)
def must_attribute_enforced(session: Session) -> Result:
    from bauble.suites._helpers import TEST_BASE, bind_admin, cleanup

    bind_admin(session)
    dn = f"uid=musttest,{TEST_BASE}"
    cleanup(session, dn)
    attrs: dict[str, list[str | bytes]] = {
        "objectClass": ["inetOrgPerson"],
        "cn": ["Missing Sn"],
        "uid": ["musttest"],
        # sn (surname) is a MUST attribute of inetOrgPerson, deliberately omitted.
    }
    outcome = session.add(dn, attrs)
    if outcome.result_code != 0:
        return Result("4512.4.5", Status.PASS)
    cleanup(session, dn)
    return Result("4512.4.5", Status.FAIL, detail="missing sn accepted")


@assertion(
    id="4512.4.6",
    rfc=4512,
    section="§2.3",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="Attribute values are validated against their syntax.",
    strategy="Add posixAccount with non-numeric uidNumber; expect invalidAttributeSyntax (21).",
    mutates=True,
)
def attribute_syntax_validated(session: Session) -> Result:
    from bauble.suites._helpers import ADMIN_DN, ADMIN_PW, TEST_BASE, bind_admin, cleanup

    bind_admin(session)
    dn = f"uid=syntaxtest,{TEST_BASE}"
    cleanup(session, dn)
    from bauble.raw import RawConnection

    attrs: dict[str, list[str | bytes]] = {
        "objectClass": ["inetOrgPerson", "posixAccount"],
        "cn": ["Syntax"],
        "sn": ["Test"],
        "uid": ["syntaxtest"],
        "uidNumber": ["not-a-number"],  # invalid integer syntax
        "gidNumber": ["100"],
        "homeDirectory": ["/home/syntaxtest"],
    }

    # Build a raw AddRequest to bypass ldap3 client-side syntax validation.
    def _len(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        if n < 0x100:
            return bytes([0x81, n])
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])

    def _int(v: int) -> bytes:
        if v == 0:
            return b"\x02\x01\x00"
        p = v.to_bytes((v.bit_length() + 8) // 8, "big")
        if v > 0 and p[0] & 0x80:
            p = b"\x00" + p
        return b"\x02" + _len(len(p)) + p

    def _oct(s: str) -> bytes:
        b = s.encode()
        return b"\x04" + _len(len(b)) + b

    def _seq(c: bytes) -> bytes:
        return b"\x30" + _len(len(c)) + c

    attrs_ber = b""
    for key, vals in attrs.items():
        val_ber = b"".join(_oct(str(v)) for v in vals)
        attr_set = b"\x31" + _len(len(val_ber)) + val_ber
        attrs_ber += _seq(_oct(key) + attr_set)
    attr_list = _seq(attrs_ber)
    object_dn = _oct(dn)
    add_contents = object_dn + attr_list
    add_request = b"\x68" + _len(len(add_contents)) + add_contents
    payload = _seq(_int(1) + add_request)

    raw = RawConnection(session.host, session.port)
    outcome = raw.bind_then_send(payload, ADMIN_DN, ADMIN_PW)
    if outcome.result_code != 0:
        return Result("4512.4.6", Status.PASS)
    cleanup(session, dn)
    return Result("4512.4.6", Status.FAIL, detail="invalid uidNumber syntax accepted")


@assertion(
    id="4512.5.1.1",
    rfc=4512,
    section="§5.1",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="The root DSE advertises supportedLDAPVersion including version 3.",
    strategy="Search the root DSE for supportedLDAPVersion; expect value 3.",
)
def supported_ldap_version(session: Session) -> Result:
    outcome, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedLDAPVersion"]
    )
    if outcome.result_code != 0 or not entries:
        return Result(
            "4512.5.1.1", Status.FAIL, detail=f"root DSE not found: {outcome.result_code}"
        )
    versions = entries[0].attributes.get("supportedLDAPVersion", [])
    has_v3 = any(
        (isinstance(v, int) and v == 3) or (isinstance(v, str) and v.isdigit() and int(v) == 3)
        for v in versions
    )
    if has_v3:
        return Result("4512.5.1.1", Status.PASS)
    return Result("4512.5.1.1", Status.FAIL, detail=f"version 3 not in {versions}")
