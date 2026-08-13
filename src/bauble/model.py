"""Core data model for bauble's conformance assertions.

Every test maps to one normative requirement from an RFC, stated as an
:class:`Assertion`. Severity (RFC 2119) and testability (ISO 1003.3 class)
are tracked independently: a ``MUST`` requirement can still be untestable.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bauble.session import Session

__all__ = [
    "Assertion",
    "Category",
    "Layer",
    "Profile",
    "Result",
    "Runner",
    "Severity",
    "Status",
    "TestClass",
]


class Severity(Enum):
    """RFC 2119 requirement strength."""

    MUST = "must"
    SHOULD = "should"
    MAY = "may"


class TestClass(Enum):
    """ISO 1003.3 testability, orthogonal to :class:`Severity`.

    Members:
        A: mandatory, testable
        B: mandatory, untestable (portably)
        C: optional, testable
        D: optional, untestable
    """

    # pytest must not collect this domain enum as a test class.
    __test__ = False

    A = "A"
    B = "B"
    C = "C"
    D = "D"


class Status(Enum):
    """Outcome of running, or deciding not to run, an assertion.

    Members:
        PASS: tested and demonstrated conformant.
        FAIL: tested and violated.
        NOT_APPLICABLE: requirement conditional on an unimplemented
            optional feature the server does not claim to support.
        SKIP: not selected for this run.
        BLOCKED: a prerequisite failed.
        UNTESTABLE: applicable, but no portable test exists.
        NA: not applicable for other reasons.
    """

    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    SKIP = "skip"
    BLOCKED = "blocked"
    UNTESTABLE = "untestable"
    NA = "na"


class Profile(Enum):
    """Conformance capability tier. A profile is a selection of assertions.

    Members:
        INTEROP: minimum needed to interoperate — bind, CRUD, over TCP.
        CORE: the main LDAPv3 conformance surface — root DSE, operational
            attributes, controls, extended operations, language features.
        EXTENDED: optional extensions such as read-entry controls.
        NONE: no profile restriction.
    """

    INTEROP = "interop"
    CORE = "core"
    EXTENDED = "extended"
    NONE = "none"


class Layer(Enum):
    """The conformance layer an assertion establishes.

    Members:
        WIRE: protocol-unit correctness (BER, PDU structure, result codes).
        SEMANTIC: operation meaning (DIT state, matching, schema constraints).
        CAPABILITY: advertised-feature implementation (advertised vs. behavior).
    """

    WIRE = "wire"
    SEMANTIC = "semantic"
    CAPABILITY = "capability"


class Category(Enum):
    """The surface an assertion exercises."""

    PROTOCOL = "protocol"
    DATA_MODEL = "data_model"
    SCHEMA = "schema"
    AUTH = "auth"
    CONTROL = "control"
    EXTENDED = "extended"
    TRANSPORT = "transport"


#: A runner executes one assertion against a :class:`~bauble.session.Session`.
Runner = Callable[["Session"], "Result"]


@dataclass(frozen=True)
class Assertion:
    """One normative requirement from an RFC, stated as a testable assertion.

    Pure data: the runner that executes it is registered separately (see
    :mod:`bauble.registry`). Class B/D assertions have no runner and yield
    ``Status.UNTESTABLE``.
    """

    id: str
    """Dotted-decimal id ``w.x.y.z`` where ``w`` is the RFC number."""

    rfc: int
    """Source RFC number; equals ``w`` in :attr:`id`."""

    section: str
    """RFC section reference, e.g. ``§4.2``."""

    category: Category
    severity: Severity
    test_class: TestClass

    profiles: frozenset[Profile]
    """Profiles this assertion belongs to; drives self-maintaining selection."""

    text: str
    """The requirement in plain language."""

    layer: Layer = Layer.SEMANTIC
    """Conformance layer this assertion establishes."""

    strategy: str = ""
    """How the test is realized (PROCEDURE/INPUT/EXPECTED where useful)."""

    requires: tuple[str, ...] = ()
    """Ids of assertions that must pass before this one runs."""

    mutates: bool = False
    """Whether the assertion mutates the DIT (gated on the writable capability)."""

    requires_features: tuple[str, ...] = ()
    """Capability feature names that must be supported for this to apply."""

    preconditions: str = ""
    """What must be true before the test runs (e.g. 'entry exists', 'session is anonymous')."""

    stimulus: str = ""
    """The operation being performed (e.g. 'ModifyRequest with assertion control')."""

    expected_observables: str = ""
    """What to verify beyond a result code (e.g. 'entryUUID unchanged', 'response control present')."""


@dataclass(frozen=True)
class Result:
    """Outcome of a single assertion."""

    assertion_id: str
    status: Status
    detail: str | None = None
