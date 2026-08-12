"""RFC-based test assertions for LDAP conformance."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = ["Assertion", "AssertionResult"]


@dataclass(frozen=True)
class Assertion:
    """A single RFC-based assertion to be verified against server responses."""

    id: str
    """Unique identifier for this assertion."""
    description: str
    """Human-readable description."""
    rfc: str
    """RFC reference, e.g. 'RFC 4511 §6.2'."""
    check: Any
    """Callable that receives the server response and returns True/False."""


@dataclass
class AssertionResult:
    """Result of executing a single assertion."""

    assertion: Assertion
    passed: bool
    error: str | None = None
