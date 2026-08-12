"""The execution engine and CLI: select, order, run, report verdicts.

Library entry :func:`run` takes a :class:`~bauble.session.Session` and is used
by tests with :class:`~bauble._fake.FakeSession`. The CLI (:func:`main`)
supports ``--dry-run`` plus live runs against ``--server <uri>`` or the podman
test target via ``--target`` (Phase 2); results route through a chosen
reporter (Phase 3).
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import cast
from urllib.parse import urlparse

from bauble.capability import Capability, load_capability
from bauble.harness import LdapSession, ServerConfig
from bauble.model import Assertion, Category, Profile, Result, Severity, Status, TestClass
from bauble.registry import Registry, default_registry
from bauble.reporter import get_reporter, to_records
from bauble.selector import Selector
from bauble.session import Session

__all__ = ["main", "run"]


def run(
    selector: Selector,
    registry: Registry,
    capability: Capability,
    session: Session,
) -> list[Result]:
    """Run the selected assertions in dependency order, returning Results."""
    selected = [a for a in registry.all() if selector.matches(a)]
    ordered = _topo_sort(selected)
    results: dict[str, Result] = {}
    out: list[Result] = []
    for assertion in ordered:
        result = _decide(assertion, registry, capability, selector, session, results)
        results[assertion.id] = result
        out.append(result)
    return out


def _decide(
    assertion: Assertion,
    registry: Registry,
    capability: Capability,
    selector: Selector,
    session: Session,
    results: dict[str, Result],
) -> Result:
    for req in assertion.requires:
        prior = results.get(req)
        if prior is None or prior.status not in (Status.PASS, Status.AUTO_PASS):
            return Result(assertion.id, Status.BLOCKED, detail=f"prerequisite {req} not satisfied")
    runner = registry.runner(assertion.id)
    if assertion.test_class in (TestClass.B, TestClass.D) or runner is None:
        return Result(assertion.id, Status.UNTESTABLE, detail="no portable test")
    if assertion.mutates and not capability.writable and not selector.allow_mutation:
        return Result(assertion.id, Status.AUTO_PASS, detail="server not writable")
    for feature in assertion.requires_features:
        if not capability.supports(feature):
            return Result(
                assertion.id, Status.AUTO_PASS, detail=f"feature {feature} not supported"
            )
    try:
        return runner(session)
    except Exception as exc:  # noqa: BLE001  a buggy runner must not abort the suite
        return Result(assertion.id, Status.FAIL, detail=f"runner raised: {exc!r}")


def _topo_sort(assertions: list[Assertion]) -> list[Assertion]:
    by_id = {a.id: a for a in assertions}
    done: set[str] = set()
    in_progress: set[str] = set()
    out: list[Assertion] = []

    def visit(node: Assertion) -> None:
        if node.id in done or node.id in in_progress:
            return
        in_progress.add(node.id)
        for req in node.requires:
            dep = by_id.get(req)
            if dep is not None:
                visit(dep)
        in_progress.discard(node.id)
        done.add(node.id)
        out.append(node)

    for assertion in assertions:
        visit(assertion)
    return out


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point: ``bauble run [--profile ...] [--dry-run|--server ...|--target]``."""
    args = _parse(argv)
    if args.command != "run":
        return 2
    selector = _selector_from_args(args)
    capability = load_capability(args.capability) if args.capability else Capability()
    # Importing the suites package registers assertions; discover() is idempotent.
    from bauble.suites import discover

    discover()
    registry = default_registry()
    if args.dry_run:
        selected = [a for a in registry.all() if selector.matches(a)]
        for a in selected:
            print(f"{a.id}  [{a.test_class.value}/{a.severity.value}]  {a.text}")
        print(f"{len(selected)} assertion(s) selected")
        return 0
    if args.target:
        from bauble.fixtures.container import OpenLDAPTarget

        target = OpenLDAPTarget()
        target.build()
        target.start()
        try:
            session = LdapSession(target.server_config(use_start_tls=args.starttls))
            try:
                results = run(selector, registry, capability, session)
            finally:
                session.unbind()
        finally:
            target.stop()
        _render(results, registry, args.reporter, args.out)
        return 0
    if args.server:
        session = LdapSession(_server_config_from_uri(args.server, args.starttls))
        try:
            results = run(selector, registry, capability, session)
        finally:
            session.unbind()
        _render(results, registry, args.reporter, args.out)
        return 0
    print("specify --server <uri> or --target for a live run", file=sys.stderr)
    return 2


def _render(
    results: list[Result],
    registry: Registry,
    reporter_name: str,
    out_path: str | None,
) -> None:
    """Route results through the chosen reporter to a file or stdout."""
    records = to_records(results, registry)
    reporter = get_reporter(reporter_name)
    if out_path:
        try:
            with open(out_path, "w", encoding="utf-8") as handle:
                reporter.render(records, handle)
        except OSError as exc:
            print(f"cannot write {out_path}: {exc}", file=sys.stderr)
    else:
        reporter.render(records, sys.stdout)


def _server_config_from_uri(uri: str, starttls: bool) -> ServerConfig:
    parsed = urlparse(uri)
    scheme = (parsed.scheme or "ldap").lower()
    return ServerConfig(
        host=parsed.hostname or "127.0.0.1",
        port=parsed.port or (636 if scheme == "ldaps" else 389),
        use_ssl=scheme == "ldaps",
        use_start_tls=starttls,
    )


def _parse(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="bauble", description="LDAP RFC conformance test suite")
    sub = parser.add_subparsers(dest="command", required=True)
    run_parser = sub.add_parser("run", help="run a selection of assertions")
    run_parser.add_argument("--profile", action="append", choices=[e.value for e in Profile])
    run_parser.add_argument("--rfc", action="append", type=int)
    run_parser.add_argument("--scenario", action="append")
    run_parser.add_argument("--assertion", action="append", dest="assertions")
    run_parser.add_argument("--category", action="append", choices=[e.value for e in Category])
    run_parser.add_argument("--exclude", action="append")
    run_parser.add_argument("--severity", action="append", choices=[e.value for e in Severity])
    run_parser.add_argument(
        "--test-class",
        action="append",
        dest="test_classes",
        choices=[e.value for e in TestClass],
    )
    run_parser.add_argument("--capability", help="path to a capability TOML file")
    run_parser.add_argument("--allow-mutation", action="store_true")
    run_parser.add_argument("--dry-run", action="store_true")
    run_parser.add_argument("--server", help="LDAP server URI (e.g. ldap://host:389)")
    run_parser.add_argument(
        "--target", action="store_true", help="start the podman OpenLDAP test target"
    )
    run_parser.add_argument(
        "--starttls", action="store_true", help="issue StartTLS after connecting"
    )
    run_parser.add_argument(
        "--reporter",
        choices=["text", "journal", "summary", "junit"],
        default="text",
        help="output format (default: text)",
    )
    run_parser.add_argument("--out", help="write output to a file (default: stdout)")
    return parser.parse_args(argv)


def _selector_from_args(args: argparse.Namespace) -> Selector:
    profile = cast(list[str] | None, args.profile)
    rfcs = cast(list[int] | None, args.rfc)
    scenario = cast(list[str] | None, args.scenario)
    assertions = cast(list[str] | None, args.assertions)
    category = cast(list[str] | None, args.category)
    severity = cast(list[str] | None, args.severity)
    test_classes = cast(list[str] | None, args.test_classes)
    exclude = cast(list[str] | None, args.exclude)
    return Selector(
        profiles=frozenset(Profile(p) for p in (profile or [])),
        rfcs=frozenset(rfcs or []),
        scenarios=frozenset(scenario or []),
        assertions=frozenset(assertions or []),
        categories=frozenset(Category(c) for c in (category or [])),
        severities=frozenset(Severity(s) for s in (severity or [])),
        test_classes=frozenset(TestClass(t) for t in (test_classes or [])),
        exclude=frozenset(exclude or []),
        allow_mutation=bool(cast(bool, args.allow_mutation)),
    )
