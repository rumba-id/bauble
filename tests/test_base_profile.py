"""Tests for the base profile module."""

from __future__ import annotations

from bauble.assertions import Assertion, AssertionResult


def test_assertion_dataclass():
    """Assertion is a frozen dataclass."""
    assertion = Assertion(
        id="test-1",
        description="Test assertion",
        rfc="RFC 4511 §4.2",
        check=lambda x: True,
    )
    assert assertion.id == "test-1"
    assert assertion.rfc == "RFC 4511 §4.2"


def test_assertion_result_dataclass():
    """AssertionResult tracks pass/fail status."""
    assertion = Assertion(
        id="test-2",
        description="Test assertion",
        rfc="RFC 4511 §4.2",
        check=lambda x: True,
    )
    result = AssertionResult(assertion, passed=True)
    assert result.passed is True
    assert result.error is None
