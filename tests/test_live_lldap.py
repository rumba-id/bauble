"""Live integration test against the podman LLDAP target.

Skipped unless ``BAUBLE_LIVE=1`` and ``podman`` is on PATH, so the default
gate (``uv run pytest``) never builds a container. Run with::

    BAUBLE_LIVE=1 uv run pytest -q tests/test_live_lldap.py

LLDAP's LDAP interface is read-mostly over its own user store: users are
created by the fixture's bootstrap (alice/bob), binds work for those
users, and the admin bind DN is ``cn=admin,ou=people,dc=bauble,dc=test``.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterator

import pytest

from bauble.fixtures.lldap import LLDAPTarget
from bauble.harness import LdapSession
from bauble.session import SCOPE_BASE_OBJECT

_LIVE = bool(os.environ.get("BAUBLE_LIVE")) and shutil.which("podman") is not None
_REASON = "set BAUBLE_LIVE=1 with podman on PATH"


@pytest.fixture(scope="module")
def target() -> Iterator[LLDAPTarget]:
    tgt = LLDAPTarget()
    tgt.start()
    yield tgt
    tgt.stop()


@pytest.mark.skipif(not _LIVE, reason=_REASON)
def test_connectivity_smoke(target: LLDAPTarget) -> None:
    """Bind the admin, search a seeded user, and bind as that user."""
    session = LdapSession(target.server_config())
    assert session.bind(target.admin_dn, target.admin_pw).result_code == 0

    outcome, entries = session.search(
        "uid=alice,ou=people,dc=bauble,dc=test", SCOPE_BASE_OBJECT, "(objectClass=*)", ["uid"]
    )
    assert outcome.result_code == 0
    assert len(entries) == 1
    assert entries[0].attributes["uid"] == ["alice"]

    assert session.bind("uid=alice,ou=people,dc=bauble,dc=test", "alice-secret").result_code == 0
