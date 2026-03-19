"""Sensitive data exposure checks."""

from __future__ import annotations

from pathlib import Path

from ..i18n import tr
from ..models import Axis, ComposeProject, Finding, Severity


SECRET_KEYWORDS = (
    "password",
    "passwd",
    "token",
    "secret",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
)
DEFAULT_SECRET_VALUES = {"", "password", "admin", "changeme", "default", "root", "secret"}


def scan_sensitive_data(project: ComposeProject) -> list[Finding]:
    findings: list[Finding] = []
    for service in project.services.values():
        for variable, value in service.environment.items():
            if not _is_secret_key(variable):
                continue
            if value is None or variable.endswith("_FILE"):
                continue
            normalized = value.strip()
            if _is_interpolated(normalized):
                continue
            if normalized.lower() in DEFAULT_SECRET_VALUES:
                findings.append(
                    Finding(
                        check_id="sensitive.default_credential",
                        axis=Axis.SENSITIVE_DATA,
                        severity=Severity.CRITICAL,
                        title=tr("finding.sensitive.default_credential.title"),
                        description=tr(
                            "finding.sensitive.default_credential.description",
                            service=service.name,
                            variable=variable,
                        ),
                        why_risky=tr("finding.sensitive.default_credential.why"),
                        how_to_fix=tr("finding.sensitive.default_credential.fix"),
                        affected_service=service.name,
                        context={"variable": variable},
                    )
                )
                continue
            findings.append(
                Finding(
                    check_id="sensitive.inline_secret",
                    axis=Axis.SENSITIVE_DATA,
                    severity=Severity.HIGH,
                    title=tr("finding.sensitive.inline_secret.title"),
                    description=tr(
                        "finding.sensitive.inline_secret.description",
                        service=service.name,
                        variable=variable,
                    ),
                    why_risky=tr("finding.sensitive.inline_secret.why"),
                    how_to_fix=tr("finding.sensitive.inline_secret.fix"),
                    affected_service=service.name,
                    context={"variable": variable},
                )
            )

        for env_file in service.env_files:
            env_path = (project.working_dir / env_file).resolve()
            secret_keys = _collect_plaintext_secret_keys(env_path)
            if not secret_keys:
                continue
            findings.append(
                Finding(
                    check_id="sensitive.env_file_plaintext",
                    axis=Axis.SENSITIVE_DATA,
                    severity=Severity.HIGH,
                    title=tr("finding.sensitive.env_file_secret.title"),
                    description=tr(
                        "finding.sensitive.env_file_secret.description",
                        service=service.name,
                        env_file=env_file,
                    ),
                    why_risky=tr("finding.sensitive.env_file_secret.why"),
                    how_to_fix=tr("finding.sensitive.env_file_secret.fix"),
                    affected_service=service.name,
                    context={"env_file": env_file, "variables": ",".join(secret_keys)},
                )
            )
    return findings


def _collect_plaintext_secret_keys(path: Path) -> list[str]:
    if not path.exists():
        return []
    secret_keys: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        if key.endswith("_FILE") or not _is_secret_key(key):
            continue
        normalized = value.strip()
        if not normalized or _is_interpolated(normalized):
            continue
        secret_keys.append(key)
    return secret_keys


def _is_secret_key(key: str) -> bool:
    lowered = key.lower()
    return any(keyword in lowered for keyword in SECRET_KEYWORDS)


def _is_interpolated(value: str) -> bool:
    return value.startswith("${") and value.endswith("}")
