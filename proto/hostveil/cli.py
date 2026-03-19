"""CLI entry point for the prototype."""

from __future__ import annotations

import argparse

from .fixes import apply_safe_fixes, load_fix_context, preview_safe_fixes
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

    fix_parser = subparsers.add_parser("fix")
    fix_parser.add_argument("path")
    fix_parser.add_argument("--dry-run", action="store_true")
    fix_parser.add_argument("--yes", action="store_true")
    fix_parser.add_argument("--no-color", action="store_true")

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

    if args.command == "fix":
        try:
            bundle, findings = load_fix_context(args.path)
        except ComposeParseError as error:
            print(tr("cli.parser_error", message=str(error)))
            return 1

        preview = preview_safe_fixes(bundle, findings)
        if not preview.changed:
            print(tr("cli.safe_fix_none"))
            return 0

        print(tr("cli.safe_fix_plan", count=len(preview.applied)))
        print(preview.diff)
        if args.dry_run:
            print(tr("cli.safe_fix_dry_run"))
            return 0

        if not args.yes:
            answer = input(tr("cli.safe_fix_prompt", count=len(preview.applied), path=str(bundle.primary_path)))
            if answer.strip().lower() not in {"y", "yes"}:
                print(tr("cli.safe_fix_cancelled"))
                return 0

        result = apply_safe_fixes(bundle, findings)
        if result.backup_path is not None:
            print(tr("cli.safe_fix_backup", path=str(result.backup_path)))
        for applied in result.applied:
            print(tr("cli.safe_fix_applied", summary=applied.summary))
        return 0

    parser.error(f"Unknown command: {args.command}")
    return 2
