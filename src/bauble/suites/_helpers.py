"""Shared helpers for assertion runners."""

import os

from bauble.session import SCOPE_BASE_OBJECT, Session

__all__ = [
    "ADMIN_DN",
    "ADMIN_PW",
    "TEST_BASE",
    "bind_admin",
    "cleanup",
    "subschema_dn",
    "test_entry_attrs",
]

ADMIN_DN = os.environ.get("BAUBLE_ADMIN_DN", "cn=admin,dc=bauble,dc=test")
ADMIN_PW = os.environ.get("BAUBLE_ADMIN_PW", "bauble-admin")
TEST_BASE = os.environ.get("BAUBLE_TEST_BASE", "ou=people,dc=bauble,dc=test")


def bind_admin(session: Session) -> None:
    """Bind as the directory admin for mutating assertions."""
    session.bind(ADMIN_DN, ADMIN_PW)


def cleanup(session: Session, dn: str) -> None:
    """Best-effort delete; ignores errors (entry may not exist)."""
    try:
        session.delete(dn)
    except Exception:  # noqa: BLE001, S110  cleanup must not mask the test result
        pass


def test_entry_attrs(uid: str, cn: str = "Test", sn: str = "Test") -> dict[str, list[str | bytes]]:
    """Standard test-entry attributes for an inetOrgPerson."""
    return {
        "objectClass": ["inetOrgPerson"],
        "cn": [cn],
        "sn": [sn],
        "uid": [uid],
        "userPassword": ["x"],
    }


def subschema_dn(session: Session) -> str | None:
    """The subschema subentry DN advertised in the root DSE, or None.

    RFC 4512 §4.2: the subschema location is published via the entry's
    ``subschemaSubentry`` attribute; it is not fixed at ``cn=Subschema``
    (OpenLDAP uses cn=Subschema, 389 DS uses cn=schema).
    """
    outcome, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["subschemaSubentry"]
    )
    if outcome.result_code != 0 or not entries:
        return None
    vals = entries[0].attributes.get("subschemaSubentry")
    if not vals:
        return None
    v = vals[0]
    return v if isinstance(v, str) else None
