"""Quick-fix helpers for the hostveil prototype."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from difflib import unified_diff
from io import StringIO
from pathlib import Path
from shutil import copy2
from typing import Any

from .i18n import tr
from .models import Finding
from .parser import ComposeBundle, load_bundle, load_project, yaml


@dataclass(slots=True, frozen=True)
class SafeFixProposal:
    service: str
    summary: str


@dataclass(slots=True, frozen=True)
class SafeFixResult:
    changed: bool
    diff: str
    applied: tuple[SafeFixProposal, ...]
    backup_path: Path | None = None


@dataclass(slots=True, frozen=True)
class GuidedFixResult:
    changed: bool
    diff: str


@dataclass(slots=True, frozen=True)
class AllFixesResult:
    changed: bool
    diff: str
    safe_applied: tuple[SafeFixProposal, ...]
    guided_changed: bool
    backup_path: Path | None = None


def load_fix_context(path: str | Path) -> tuple[ComposeBundle, list[Finding]]:
    bundle = load_bundle(path)
    project = load_project(path)
    from .scanner import scan_project

    return bundle, scan_project(project)


def preview_safe_fixes(bundle: ComposeBundle, findings: list[Finding]) -> SafeFixResult:
    working_data = deepcopy(bundle.primary_data)
    applied = _apply_safe_fixes_to_data(working_data, findings)
    if not applied:
        return SafeFixResult(changed=False, diff="", applied=())
    updated_text = dump_compose(working_data)
    diff = build_diff(bundle.primary_path, bundle.primary_text, updated_text)
    return SafeFixResult(changed=True, diff=diff, applied=tuple(applied))


def apply_safe_fixes(bundle: ComposeBundle, findings: list[Finding]) -> SafeFixResult:
    result = preview_safe_fixes(bundle, findings)
    if not result.changed:
        return result

    backup_path = bundle.primary_path.with_suffix(bundle.primary_path.suffix + ".bak")
    copy2(bundle.primary_path, backup_path)
    working_data = deepcopy(bundle.primary_data)
    _apply_safe_fixes_to_data(working_data, findings)
    bundle.primary_path.write_text(dump_compose(working_data), encoding="utf-8")
    return SafeFixResult(
        changed=True,
        diff=result.diff,
        applied=result.applied,
        backup_path=backup_path,
    )


def preview_guided_fixes(bundle: ComposeBundle, findings: list[Finding]) -> GuidedFixResult:
    working_data = deepcopy(bundle.primary_data)
    changed = _apply_guided_fixes_to_data(working_data, findings)
    if not changed:
        return GuidedFixResult(changed=False, diff="")
    updated_text = dump_compose(working_data)
    diff = build_diff(bundle.primary_path, bundle.primary_text, updated_text)
    return GuidedFixResult(changed=True, diff=diff)


def preview_all_fixes(bundle: ComposeBundle, findings: list[Finding]) -> AllFixesResult:
    working_data = deepcopy(bundle.primary_data)
    safe_applied = _apply_safe_fixes_to_data(working_data, findings)
    guided_changed = _apply_guided_fixes_to_data(working_data, findings)
    if not safe_applied and not guided_changed:
        return AllFixesResult(
            changed=False,
            diff="",
            safe_applied=(),
            guided_changed=False,
        )
    updated_text = dump_compose(working_data)
    diff = build_diff(bundle.primary_path, bundle.primary_text, updated_text)
    return AllFixesResult(
        changed=True,
        diff=diff,
        safe_applied=tuple(safe_applied),
        guided_changed=guided_changed,
    )


def apply_all_fixes(bundle: ComposeBundle, findings: list[Finding]) -> AllFixesResult:
    preview = preview_all_fixes(bundle, findings)
    if not preview.changed:
        return preview

    backup_path = bundle.primary_path.with_suffix(bundle.primary_path.suffix + ".bak")
    copy2(bundle.primary_path, backup_path)
    working_data = deepcopy(bundle.primary_data)
    _apply_safe_fixes_to_data(working_data, findings)
    _apply_guided_fixes_to_data(working_data, findings)
    bundle.primary_path.write_text(dump_compose(working_data), encoding="utf-8")
    return AllFixesResult(
        changed=True,
        diff=preview.diff,
        safe_applied=preview.safe_applied,
        guided_changed=preview.guided_changed,
        backup_path=backup_path,
    )


def dump_compose(data: Any) -> str:
    stream = StringIO()
    yaml.dump(data, stream)
    return stream.getvalue()


def build_diff(path: Path, before: str, after: str) -> str:
    diff_lines = unified_diff(
        before.splitlines(),
        after.splitlines(),
        fromfile=str(path),
        tofile=str(path),
        lineterm="",
    )
    return "\n".join(diff_lines)


def _apply_safe_fixes_to_data(
    data: Any, findings: list[Finding]
) -> list[SafeFixProposal]:
    services = data.get("services", {}) if isinstance(data, dict) else {}
    applied: list[SafeFixProposal] = []
    finding_ids_by_service = _group_findings(findings)

    for service_name, service_data in services.items():
        if not isinstance(service_data, dict):
            continue
        finding_ids = finding_ids_by_service.get(service_name, set())

        if "updates.no_tag" in finding_ids and str(service_data.get("image", "")) == "nginx":
            service_data["image"] = "nginx:stable"
            applied.append(
                SafeFixProposal(
                    service=service_name,
                    summary=tr("fix.safe.nginx_stable", service=service_name),
                )
            )

        if "exposure.public_binding" not in finding_ids:
            continue
        ports = service_data.get("ports")
        if not isinstance(ports, list):
            continue
        for index, port in enumerate(list(ports)):
            rewritten = _rewrite_public_port(port)
            if rewritten is None:
                continue
            ports[index] = rewritten
            applied.append(
                SafeFixProposal(
                    service=service_name,
                    summary=tr(
                        "fix.safe.bind_localhost",
                        service=service_name,
                        port=str(port),
                    ),
                )
            )
    return applied


def _apply_guided_fixes_to_data(data: Any, findings: list[Finding]) -> bool:
    services = data.get("services", {}) if isinstance(data, dict) else {}
    finding_ids_by_service = _group_findings(findings)
    changed = False

    for service_name, service_data in services.items():
        if not isinstance(service_data, dict):
            continue
        if "permissions.privileged" not in finding_ids_by_service.get(service_name, set()):
            continue
        if not service_data.get("privileged"):
            continue

        keys = list(service_data.keys())
        insert_at = keys.index("privileged") if "privileged" in keys else len(keys)
        del service_data["privileged"]
        cap_add_values = list(service_data.get("cap_add", []))
        if "NET_BIND_SERVICE" not in cap_add_values:
            cap_add_values.append("NET_BIND_SERVICE")
        if "cap_add" in service_data:
            service_data["cap_add"] = cap_add_values
        else:
            service_data.insert(insert_at, "cap_add", cap_add_values)
        if hasattr(service_data, "yaml_set_comment_before_after_key"):
            service_data.yaml_set_comment_before_after_key(
                "cap_add",
                before=tr("fix.guided.privileged_comment"),
            )
        changed = True
    return changed


def _group_findings(findings: list[Finding]) -> dict[str, set[str]]:
    grouped: dict[str, set[str]] = {}
    for finding in findings:
        grouped.setdefault(finding.affected_service, set()).add(finding.check_id)
    return grouped


def _rewrite_public_port(port: Any) -> Any | None:
    if isinstance(port, dict):
        host_ip = port.get("host_ip")
        published = port.get("published")
        if published is None or host_ip in {"127.0.0.1", "::1", "localhost"}:
            return None
        port["host_ip"] = "127.0.0.1"
        return port

    if not isinstance(port, str):
        return None

    protocol = ""
    body = port
    if "/" in port:
        body, suffix = port.rsplit("/", 1)
        protocol = f"/{suffix}"

    parts = body.split(":")
    if len(parts) == 3:
        host_ip, host_port, container_port = parts
        if host_ip in {"127.0.0.1", "::1", "localhost"}:
            return None
        return f"127.0.0.1:{host_port}:{container_port}{protocol}"
    if len(parts) == 2:
        host_port, container_port = parts
        return f"127.0.0.1:{host_port}:{container_port}{protocol}"
    return None
