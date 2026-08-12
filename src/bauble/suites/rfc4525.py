"""RFC 4525 — Modify-Increment Extension."""

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, Session
from bauble.suites._base import assertion
from bauble.suites._helpers import TEST_BASE, bind_admin, cleanup, test_entry_attrs

_CORE = frozenset({Profile.CORE})

_INCREMENT_FEATURE_OID = "1.3.6.1.1.14"


@assertion(
    id="4525.2.1",
    rfc=4525,
    section="§2",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="Server publishes 1.3.6.1.1.14 in supportedFeatures if increment is supported.",
    strategy="Read root DSE supportedFeatures and check for the OID.",
    requires_features=(_INCREMENT_FEATURE_OID,),
)
def increment_feature_advertised(session: Session) -> Result:
    from bauble.session import SCOPE_BASE_OBJECT

    outcome, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedFeatures"]
    )
    if outcome.result_code != 0 or not entries:
        return Result("4525.2.1", Status.NOT_APPLICABLE, detail="root DSE not readable")
    features = entries[0].attributes.get("supportedFeatures", [])
    if _INCREMENT_FEATURE_OID in features:
        return Result("4525.2.1", Status.PASS)
    return Result("4525.2.1", Status.NOT_APPLICABLE, detail="feature OID not advertised")


@assertion(
    id="4525.2.2",
    rfc=4525,
    section="§2",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="Increment operation adds specified value to existing attribute values.",
    strategy="Add entry with uidNumber=1000, increment by 1, read back uidNumber=1001.",
    mutates=True,
    requires_features=(_INCREMENT_FEATURE_OID,),
)
def increment_adds_to_value(session: Session) -> Result:
    from bauble.raw import RawConnection

    bind_admin(session)
    dn = f"uid=incr-test,{TEST_BASE}"
    cleanup(session, dn)

    attrs = test_entry_attrs("incr-test")
    attrs["uidNumber"] = ["1000"]
    session.add(dn, attrs)
    try:
        raw = RawConnection(session.host, session.port)
        outcome = raw.modify_increment(dn, "uidNumber", 1, message_id=1)
        if outcome.result_code != 0:
            return Result(
                "4525.2.2",
                Status.FAIL,
                detail=f"increment failed: {outcome.result_code} {outcome.message}",
            )

        # Read back and verify.
        _, entries = session.search(dn, SCOPE_BASE_OBJECT, "(objectClass=*)", ["uidNumber"])
        if not entries:
            return Result("4525.2.2", Status.FAIL, detail="could not read back entry")
        uid_numbers = entries[0].attributes.get("uidNumber", [])
        if uid_numbers != ["1001"]:
            return Result(
                "4525.2.2",
                Status.FAIL,
                detail=f"expected uidNumber=['1001'], got {uid_numbers}",
            )
        return Result("4525.2.2", Status.PASS)
    finally:
        cleanup(session, dn)


@assertion(
    id="4525.2.3",
    rfc=4525,
    section="§2",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="Increment with multiple values returns protocolError.",
    strategy="Send increment with two values via raw layer; expect protocolError (2).",
    mutates=True,
    requires_features=(_INCREMENT_FEATURE_OID,),
)
def increment_multiple_values_error(session: Session) -> Result:
    from bauble.raw import RawConnection

    bind_admin(session)
    dn = f"uid=incr-multi,{TEST_BASE}"
    cleanup(session, dn)

    attrs = test_entry_attrs("incr-multi")
    attrs["uidNumber"] = ["1000"]
    session.add(dn, attrs)
    try:
        # Build a ModifyRequest with operation=3 (increment) and two values.
        raw = RawConnection(session.host, session.port)
        from bauble.raw import _parse_ldap_result  # type: ignore[reportPrivateUsage]

        # Inline BER helpers (avoids importing private functions from raw.py).
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

        val1 = _oct("1")
        val2 = _oct("2")
        attr_set = b"\x31" + _len(len(val1 + val2)) + val1 + val2
        mod = _seq(_oct("uidNumber") + attr_set)
        op_enum = b"\x0a\x01\x03"
        change = _seq(op_enum + mod)
        changes = _seq(change)
        object_dn = _oct(dn)
        modify_contents = object_dn + changes
        modify_request = b"\x66" + _len(len(modify_contents)) + modify_contents
        payload = _seq(_int(2) + modify_request)

        response = raw._send_and_receive(payload)  # type: ignore[reportPrivateUsage]
        outcome = _parse_ldap_result(response)
        if outcome is None:
            return Result("4525.2.3", Status.FAIL, detail="no valid response")
        # protocolError = 2
        if outcome.result_code != 2:
            return Result(
                "4525.2.3",
                Status.FAIL,
                detail=f"expected protocolError (2), got {outcome.result_code}",
            )
        return Result("4525.2.3", Status.PASS)
    finally:
        cleanup(session, dn)


@assertion(
    id="4525.2.4",
    rfc=4525,
    section="§2",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="Increment on non-incrementable attribute returns constraintViolation or appropriate error.",
    strategy="Try increment on cn (Directory String); expect constraintViolation (19) or similar.",
    mutates=True,
    requires_features=(_INCREMENT_FEATURE_OID,),
)
def increment_non_integer_error(session: Session) -> Result:
    from bauble.raw import RawConnection

    bind_admin(session)
    dn = f"uid=incr-str,{TEST_BASE}"
    cleanup(session, dn)

    session.add(dn, test_entry_attrs("incr-str"))
    try:
        raw = RawConnection(session.host, session.port)
        outcome = raw.modify_increment(dn, "cn", 1, message_id=1)
        # constraintViolation = 19, objectClassViolation = 65, unwillingToPerform = 53
        if outcome.result_code == 0:
            return Result("4525.2.4", Status.FAIL, detail="increment on cn succeeded")
        if outcome.result_code not in (19, 53, 65):
            return Result(
                "4525.2.4",
                Status.FAIL,
                detail=f"expected constraintViolation (19), got {outcome.result_code}",
            )
        return Result("4525.2.4", Status.PASS)
    finally:
        cleanup(session, dn)
