"""harness: pure mapper unit tests (ldap3 wiring is covered by the live test)."""

from __future__ import annotations

import ldap3

from bauble.harness import ldap3_changes, outcome_from_result
from bauble.session import Modification

_RESULT_SUCCESS = {"result": 0, "description": "success", "dn": "", "referrals": None}


def test_outcome_maps_fields() -> None:
    raw = {
        "result": 32,
        "description": "noSuchObject",
        "dn": "ou=people,dc=bauble,dc=test",
        "referrals": ["ldap://elsewhere/dc=bauble,dc=test"],
    }
    outcome = outcome_from_result(raw)
    assert outcome.result_code == 32
    assert outcome.matched_dn == "ou=people,dc=bauble,dc=test"
    assert outcome.referrals == ("ldap://elsewhere/dc=bauble,dc=test",)
    assert outcome.message == "noSuchObject"


def test_outcome_handles_missing_fields() -> None:
    outcome = outcome_from_result({})
    assert outcome.result_code == -1
    assert outcome.matched_dn == ""
    assert outcome.referrals == ()
    assert outcome.message == ""


def test_outcome_success() -> None:
    outcome = outcome_from_result(_RESULT_SUCCESS)
    assert outcome.result_code == 0
    assert outcome.referrals == ()


def test_changes_map_to_ldap3_constants() -> None:
    changes = [
        Modification(operation=0, attribute="cn", values=["alice"]),
        Modification(operation=2, attribute="sn", values=["Anderson"]),
    ]
    mapped = ldap3_changes(changes)
    assert mapped["cn"] == [(ldap3.MODIFY_ADD, ["alice"])]
    assert mapped["sn"] == [(ldap3.MODIFY_REPLACE, ["Anderson"])]
