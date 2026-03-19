"""CLI entry point for the prototype."""

from __future__ import annotations

import argparse

from .formatter import format_report
from .i18n import tr
from .parser import ComposeParseError, load_project
from .scanner import scan_project
from .scoring import build_score_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hostveil")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("path")
    scan_parser.add_argument("--no-color", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        try:
            project = load_project(args.path)
        except ComposeParseError as error:
            print(tr("cli.parser_error", message=str(error)))
            return 1
        findings = scan_project(project)
        report = build_score_report(findings)
        print(
            format_report(
                report,
                findings,
                str(project.primary_file),
                color=not args.no_color,
            )
        )
        return 0

    parser.error(f"Unknown command: {args.command}")
    return 2
