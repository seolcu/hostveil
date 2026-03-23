"""CLI entry point for the prototype."""

from __future__ import annotations

import argparse

from .fixes import (
    AllFixesResult,
    apply_all_fixes,
    apply_safe_fixes,
    load_fix_context,
    preview_all_fixes,
    preview_safe_fixes,
)
from .formatter import (
    enable_ansi_if_windows,
    format_report,
    format_unified_diff,
    should_use_color,
)
from .i18n import tr
from .parser import ComposeParseError, load_project
from .scanner import scan_project
from .scoring import build_score_report


def _all_fix_plan_summary(preview: AllFixesResult) -> str:
    parts: list[str] = []
    if preview.safe_applied:
        parts.append(tr("cli.all_fix_part_safe", count=len(preview.safe_applied)))
    if preview.guided_changed:
        parts.append(tr("cli.all_fix_part_guided"))
    return ", ".join(parts)


def _add_common_output_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--no-color",
        action="store_true",
        help=tr("cli.help.no_color"),
    )


def _add_common_fix_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path")
    parser.add_argument(
        "--preview-changes",
        action="store_true",
        help=tr("cli.help.preview_changes"),
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help=tr("cli.help.yes"),
    )
    _add_common_output_arguments(parser)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hostveil")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help=tr("cli.help.scan"),
        description=tr("cli.help.scan"),
    )
    scan_parser.add_argument("path")
    _add_common_output_arguments(scan_parser)

    quick_fix_parser = subparsers.add_parser(
        "quick-fix",
        help=tr("cli.help.quick_fix"),
        description=tr("cli.help.quick_fix"),
    )
    _add_common_fix_arguments(quick_fix_parser)

    fix_parser = subparsers.add_parser(
        "fix",
        help=tr("cli.help.fix"),
        description=tr("cli.help.fix"),
    )
    _add_common_fix_arguments(fix_parser)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    enable_ansi_if_windows()

    if args.command == "scan":
        try:
            project = load_project(args.path)
        except ComposeParseError as error:
            print(tr("cli.parser_error", message=str(error)))
            return 1
        findings = scan_project(project)
        report = build_score_report(findings)
        use_color = should_use_color(no_color_cli_flag=args.no_color)
        print(
            format_report(
                report,
                findings,
                str(project.primary_file),
                color=use_color,
            )
        )
        return 0

    if args.command == "quick-fix":
        try:
            bundle, findings = load_fix_context(args.path)
        except ComposeParseError as error:
            print(tr("cli.parser_error", message=str(error)))
            return 1

        preview = preview_safe_fixes(bundle, findings)
        if not preview.changed:
            print(tr("cli.safe_fix_none"))
            return 0

        use_color = should_use_color(no_color_cli_flag=args.no_color)
        print(tr("cli.safe_fix_plan", count=len(preview.applied)))
        print(format_unified_diff(preview.diff, color=use_color))
        if args.preview_changes:
            print(tr("cli.safe_fix_preview_only"))
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

    if args.command == "fix":
        try:
            bundle, findings = load_fix_context(args.path)
        except ComposeParseError as error:
            print(tr("cli.parser_error", message=str(error)))
            return 1

        preview = preview_all_fixes(bundle, findings)
        if not preview.changed:
            print(tr("cli.all_fix_none"))
            return 0

        use_color = should_use_color(no_color_cli_flag=args.no_color)
        print(tr("cli.all_fix_plan", summary=_all_fix_plan_summary(preview)))
        print(format_unified_diff(preview.diff, color=use_color))
        if args.preview_changes:
            print(tr("cli.all_fix_preview_only"))
            return 0

        if not args.yes:
            answer = input(tr("cli.all_fix_prompt", path=str(bundle.primary_path)))
            if answer.strip().lower() not in {"y", "yes"}:
                print(tr("cli.all_fix_cancelled"))
                return 0

        result = apply_all_fixes(bundle, findings)
        if result.backup_path is not None:
            print(tr("cli.safe_fix_backup", path=str(result.backup_path)))
        for applied in result.safe_applied:
            print(tr("cli.safe_fix_applied", summary=applied.summary))
        if result.guided_changed:
            print(tr("cli.all_fix_guided_applied"))
        return 0

    parser.error(f"Unknown command: {args.command}")
    return 2
