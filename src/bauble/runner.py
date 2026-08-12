"""Test harness and CLI entry point."""

from __future__ import annotations

import argparse
import sys

from .assertions import AssertionResult
from .base_profile import run_base_profile
from .client import ServerConfig, create_connection
from .standard_profile import run_standard_profile

__all__ = ["main"]


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for the conformance test suite."""
    parser = argparse.ArgumentParser(description="LDAP RFC conformance test suite")
    parser.add_argument(
        "--server",
        required=True,
        help="LDAP server URI (e.g. ldap://localhost:389)",
    )
    parser.add_argument(
        "--base-dn",
        required=True,
        help="Base DN for tests",
    )
    parser.add_argument(
        "--bind-dn",
        help="Bind DN for authentication",
    )
    parser.add_argument(
        "--bind-password",
        help="Bind password for authentication",
    )
    parser.add_argument(
        "--profile",
        choices=["base", "standard", "all"],
        default="all",
        help="Which profile to run",
    )
    parser.add_argument(
        "--tls",
        action="store_true",
        help="Use TLS for connection",
    )

    args = parser.parse_args(argv)

    # Parse server URI
    server_config = _parse_uri(args.server, args.tls)

    # Create connection
    try:
        conn = create_connection(server_config)
    except (ConnectionError, OSError) as exc:
        print(f"Failed to connect to {args.server}: {exc}", file=sys.stderr)
        return 1

    results: list[AssertionResult] = []

    if args.profile in ("base", "all"):
        print("Running Base Profile...")
        results.extend(
            run_base_profile(
                conn, args.base_dn, (args.bind_dn, args.bind_password) if args.bind_dn else None
            )
        )

    if args.profile in ("standard", "all"):
        print("Running Standard Profile...")
        results.extend(run_standard_profile(conn, args.base_dn))

    # Print summary
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed

    print(f"\nResults: {passed} passed, {failed} failed out of {len(results)} assertions")

    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(f"  [{status}] {result.assertion.id}: {result.assertion.description}")
        if result.error:
            print(f"         Error: {result.error}")

    return 0 if failed == 0 else 1


def _parse_uri(uri: str, use_tls: bool) -> ServerConfig:
    """Parse an LDAP URI into a ServerConfig."""
    from urllib.parse import urlparse

    parsed = urlparse(uri)
    host = parsed.hostname or "localhost"
    port = parsed.port or (636 if use_tls else 389)

    return ServerConfig(
        host=host,
        port=port,
        use_tls=use_tls or parsed.scheme == "ldaps",
    )
