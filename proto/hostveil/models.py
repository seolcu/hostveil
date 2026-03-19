"""Domain models used by the Python prototype."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class Axis(StrEnum):
    SENSITIVE_DATA = "sensitive_data"
    EXCESSIVE_PERMISSIONS = "permissions"
    UNNECESSARY_EXPOSURE = "exposure"
    UPDATE_RISK = "updates"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


@dataclass(slots=True, frozen=True)
class PortBinding:
    raw: str
    host_ip: str | None
    host_port: str | None
    container_port: str
    protocol: str
    short_syntax: bool = True


@dataclass(slots=True, frozen=True)
class VolumeMount:
    raw: str
    source: str | None
    target: str | None
    mode: str | None
    mount_type: str


@dataclass(slots=True, frozen=True)
class ComposeService:
    name: str
    image: str | None
    ports: tuple[PortBinding, ...]
    volumes: tuple[VolumeMount, ...]
    environment: dict[str, str | None]
    env_files: tuple[str, ...]
    networks: tuple[str, ...]
    user: str | None
    privileged: bool
    cap_add: tuple[str, ...]
    network_mode: str | None
    source_files: tuple[Path, ...]


@dataclass(slots=True, frozen=True)
class ComposeProject:
    primary_file: Path
    loaded_files: tuple[Path, ...]
    services: dict[str, ComposeService]
    working_dir: Path


@dataclass(slots=True)
class Finding:
    check_id: str
    axis: Axis
    severity: Severity
    title: str
    description: str
    why_risky: str
    how_to_fix: str
    affected_service: str
    context: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True, frozen=True)
class ScoreReport:
    overall: int
    axis_scores: dict[Axis, int]
    finding_counts: dict[Severity, int]
