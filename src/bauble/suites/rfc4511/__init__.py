"""RFC 4511 — Lightweight Directory Access Protocol: The Protocol."""

from . import bind  # registers §4.2 assertions via decorator side effects

del bind  # side-effect import; name not needed in the package namespace
