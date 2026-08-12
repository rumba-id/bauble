"""Shared helpers for assertion runners."""

from __future__ import annotations

from bauble.session import Session

__all__ = [
    "ADMIN_DN",
    "ADMIN_PW",
    "TEST_BASE",
    "bind_admin",
    "cleanup",
    "test_entry_attrs",
]

ADMIN_DN = "cn=admin,dc=bauble,dc=test"
ADMIN_PW = "bauble-admin"
TEST_BASE = "ou=people,dc=bauble,dc=test"


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
