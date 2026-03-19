"""Excessive permission checks."""

from __future__ import annotations

from ..i18n import tr
from ..models import Axis, ComposeProject, Finding, Severity, VolumeMount


ROOT_USERS = {"root", "0", "0:0"}
SENSITIVE_EXACT_PATHS = {"/", "/var/run/docker.sock"}
SENSITIVE_PREFIXES = ("/etc", "/home")
SAFE_ETC_PATHS = {"/etc/localtime", "/etc/timezone"}


def scan_permission_risk(project: ComposeProject) -> list[Finding]:
    findings: list[Finding] = []
    for service in project.services.values():
        if service.privileged:
            findings.append(
                Finding(
                    check_id="permissions.privileged",
                    axis=Axis.EXCESSIVE_PERMISSIONS,
                    severity=Severity.CRITICAL,
                    title=tr("finding.permissions.privileged.title"),
                    description=tr(
                        "finding.permissions.privileged.description", service=service.name
                    ),
                    why_risky=tr("finding.permissions.privileged.why"),
                    how_to_fix=tr("finding.permissions.privileged.fix"),
                    affected_service=service.name,
                )
            )

        if service.user is None:
            findings.append(
                Finding(
                    check_id="permissions.implicit_root",
                    axis=Axis.EXCESSIVE_PERMISSIONS,
                    severity=Severity.MEDIUM,
                    title=tr("finding.permissions.implicit_root.title"),
                    description=tr(
                        "finding.permissions.implicit_root.description", service=service.name
                    ),
                    why_risky=tr("finding.permissions.implicit_root.why"),
                    how_to_fix=tr("finding.permissions.implicit_root.fix"),
                    affected_service=service.name,
                )
            )
        elif service.user.strip().lower() in ROOT_USERS:
            findings.append(
                Finding(
                    check_id="permissions.root_user",
                    axis=Axis.EXCESSIVE_PERMISSIONS,
                    severity=Severity.HIGH,
                    title=tr("finding.permissions.root.title"),
                    description=tr(
                        "finding.permissions.root.description", service=service.name
                    ),
                    why_risky=tr("finding.permissions.root.why"),
                    how_to_fix=tr("finding.permissions.root.fix"),
                    affected_service=service.name,
                    context={"user": service.user},
                )
            )

        if service.network_mode == "host":
            findings.append(
                Finding(
                    check_id="permissions.host_network",
                    axis=Axis.EXCESSIVE_PERMISSIONS,
                    severity=Severity.HIGH,
                    title=tr("finding.permissions.host_network.title"),
                    description=tr(
                        "finding.permissions.host_network.description", service=service.name
                    ),
                    why_risky=tr("finding.permissions.host_network.why"),
                    how_to_fix=tr("finding.permissions.host_network.fix"),
                    affected_service=service.name,
                )
            )

        for mount in service.volumes:
            sensitive_path = classify_sensitive_mount(mount)
            if not sensitive_path:
                continue
            findings.append(
                Finding(
                    check_id="permissions.sensitive_mount",
                    axis=Axis.EXCESSIVE_PERMISSIONS,
                    severity=_mount_severity(sensitive_path),
                    title=tr("finding.permissions.sensitive_mount.title"),
                    description=tr(
                        "finding.permissions.sensitive_mount.description",
                        service=service.name,
                        path=sensitive_path,
                    ),
                    why_risky=tr("finding.permissions.sensitive_mount.why"),
                    how_to_fix=tr("finding.permissions.sensitive_mount.fix"),
                    affected_service=service.name,
                    context={"path": sensitive_path},
                )
            )
    return findings


def classify_sensitive_mount(mount: VolumeMount) -> str | None:
    if mount.mount_type != "bind" or not mount.source:
        return None
    source = mount.source.rstrip("/") or "/"
    if source in SAFE_ETC_PATHS:
        return None
    if source in SENSITIVE_EXACT_PATHS:
        return source
    if any(source == prefix or source.startswith(f"{prefix}/") for prefix in SENSITIVE_PREFIXES):
        return source
    return None


def _mount_severity(path: str) -> Severity:
    if path in SENSITIVE_EXACT_PATHS:
        return Severity.CRITICAL
    return Severity.HIGH
