"""CLI entry point for the prototype."""

from __future__ import annotations

import argparse

from .i18n import tr
from .parser import ComposeParseError, load_project


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hostveil")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("path")

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
        print(tr("cli.scan_complete", service_count=len(project.services), path=str(project.primary_file)))
        return 0

    parser.error(f"Unknown command: {args.command}")
    return 2
