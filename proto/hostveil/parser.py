"""Compose parser with semantic override merging."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from .i18n import tr
from .models import ComposeProject, ComposeService, PortBinding, VolumeMount


yaml = YAML()
yaml.preserve_quotes = True
yaml.width = 4096

DEFAULT_COMPOSE_FILES = ("docker-compose.yml", "docker-compose.yaml")
DEFAULT_OVERRIDE_FILES = (
    "docker-compose.override.yml",
    "docker-compose.override.yaml",
)


class ComposeParseError(ValueError):
    """Raised when a compose file cannot be parsed."""


@dataclass(slots=True, frozen=True)
class ComposeBundle:
    primary_path: Path
    override_paths: tuple[Path, ...]
    primary_data: dict[str, Any]
    override_data: tuple[dict[str, Any], ...]
    primary_text: str

    @property
    def loaded_files(self) -> tuple[Path, ...]:
        return (self.primary_path, *self.override_paths)


def load_bundle(path: str | Path, include_override: bool = True) -> ComposeBundle:
    primary_path = _resolve_compose_path(Path(path))
    override_paths = _discover_override_paths(primary_path) if include_override else ()
    primary_text = primary_path.read_text(encoding="utf-8")
    primary_data = _load_yaml(primary_path, primary_text)
    override_data = tuple(
        _load_yaml(override_path, override_path.read_text(encoding="utf-8"))
        for override_path in override_paths
    )
    return ComposeBundle(
        primary_path=primary_path,
        override_paths=override_paths,
        primary_data=primary_data,
        override_data=override_data,
        primary_text=primary_text,
    )


def load_project(path: str | Path, include_override: bool = True) -> ComposeProject:
    bundle = load_bundle(path, include_override=include_override)
    services = _merge_services(
        bundle.primary_path,
        bundle.override_paths,
        bundle.primary_data,
        bundle.override_data,
    )
    if not services:
        raise ComposeParseError(
            tr("parser.missing_services", path=str(bundle.primary_path))
        )
    return ComposeProject(
        primary_file=bundle.primary_path,
        loaded_files=bundle.loaded_files,
        services=services,
        working_dir=bundle.primary_path.parent,
    )


def _resolve_compose_path(path: Path) -> Path:
    if not path.exists():
        raise ComposeParseError(tr("parser.compose_path_missing", path=str(path)))
    if path.is_dir():
        for filename in DEFAULT_COMPOSE_FILES:
            candidate = path / filename
            if candidate.exists():
                return candidate
        raise ComposeParseError(tr("parser.compose_file_not_found", path=str(path)))
    return path


def _discover_override_paths(primary_path: Path) -> tuple[Path, ...]:
    overrides: list[Path] = []
    for filename in DEFAULT_OVERRIDE_FILES:
        candidate = primary_path.parent / filename
        if candidate.exists() and candidate != primary_path:
            overrides.append(candidate)
    return tuple(overrides)


def _load_yaml(path: Path, text: str) -> dict[str, Any]:
    try:
        data = yaml.load(text) or {}
    except YAMLError as error:
        raise ComposeParseError(
            tr("parser.malformed_yaml", path=str(path), message=str(error))
        ) from error
    if not isinstance(data, dict):
        raise ComposeParseError(
            tr("parser.malformed_yaml", path=str(path), message="top-level mapping expected")
        )
    return data


def _merge_services(
    primary_path: Path,
    override_paths: tuple[Path, ...],
    primary_data: dict[str, Any],
    override_data: tuple[dict[str, Any], ...],
) -> dict[str, ComposeService]:
    merged_services: dict[str, dict[str, Any]] = {}
    origin_files: dict[str, list[Path]] = {}
    all_sources = ((primary_path, primary_data), *zip(override_paths, override_data, strict=True))
    for source_file, source in all_sources:
        services = source.get("services", {}) or {}
        if not isinstance(services, dict):
            continue
        for service_name, service_data in services.items():
            if not isinstance(service_data, dict):
                continue
            target = merged_services.setdefault(service_name, {})
            _merge_service_dict(target, service_data)
            origin_files.setdefault(service_name, []).append(source_file)

    project_services: dict[str, ComposeService] = {}
    for service_name, service_data in merged_services.items():
        project_services[service_name] = _build_service(
            service_name,
            service_data,
            tuple(origin_files.get(service_name, [])),
        )
    return project_services


def _merge_service_dict(target: dict[str, Any], source: dict[str, Any]) -> None:
    for key, value in source.items():
        if key in {"ports", "volumes", "env_file", "cap_add"}:
            existing = list(target.get(key, []))
            existing.extend(_coerce_list(value))
            target[key] = existing
        elif key == "environment":
            merged_env = _coerce_environment(target.get(key))
            merged_env.update(_coerce_environment(value))
            target[key] = merged_env
        elif key == "networks":
            existing_networks = list(_coerce_networks(target.get(key)))
            for network in _coerce_networks(value):
                if network not in existing_networks:
                    existing_networks.append(network)
            target[key] = existing_networks
        else:
            target[key] = value


def _build_service(
    name: str, service_data: dict[str, Any], source_files: tuple[Path, ...]
) -> ComposeService:
    return ComposeService(
        name=name,
        image=_coerce_string(service_data.get("image")),
        ports=tuple(_parse_ports(service_data.get("ports"))),
        volumes=tuple(_parse_volumes(service_data.get("volumes"))),
        environment=_coerce_environment(service_data.get("environment")),
        env_files=tuple(_coerce_env_files(service_data.get("env_file"))),
        networks=tuple(_coerce_networks(service_data.get("networks"))),
        user=_coerce_string(service_data.get("user")),
        privileged=bool(service_data.get("privileged", False)),
        cap_add=tuple(_coerce_list(service_data.get("cap_add"))),
        network_mode=_coerce_string(service_data.get("network_mode")),
        source_files=source_files,
    )


def _coerce_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    return [value]


def _coerce_string(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _coerce_environment(value: Any) -> dict[str, str | None]:
    env: dict[str, str | None] = {}
    if value is None:
        return env
    if isinstance(value, dict):
        for key, item in value.items():
            env[str(key)] = None if item is None else str(item)
        return env
    if isinstance(value, list):
        for item in value:
            if not isinstance(item, str):
                continue
            if "=" not in item:
                env[item] = None
                continue
            key, raw_value = item.split("=", 1)
            env[key] = raw_value
    return env


def _coerce_env_files(value: Any) -> list[str]:
    return [str(item) for item in _coerce_list(value)]


def _coerce_networks(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        return [str(key) for key in value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _parse_ports(value: Any) -> list[PortBinding]:
    ports: list[PortBinding] = []
    for item in _coerce_list(value):
        if isinstance(item, dict):
            protocol = str(item.get("protocol", "tcp"))
            container_port = str(item.get("target"))
            host_port = None if item.get("published") is None else str(item.get("published"))
            host_ip = None if item.get("host_ip") is None else str(item.get("host_ip"))
            ports.append(
                PortBinding(
                    raw=str(item),
                    host_ip=host_ip,
                    host_port=host_port,
                    container_port=container_port,
                    protocol=protocol,
                    short_syntax=False,
                )
            )
            continue
        if not isinstance(item, str):
            continue
        port_spec, protocol = _split_protocol(item)
        parts = port_spec.split(":")
        host_ip: str | None = None
        host_port: str | None = None
        container_port = ""
        if len(parts) == 3:
            host_ip, host_port, container_port = parts
        elif len(parts) == 2:
            host_port, container_port = parts
        elif len(parts) == 1:
            container_port = parts[0]
        else:
            host_ip = parts[0]
            host_port = parts[-2]
            container_port = parts[-1]
        ports.append(
            PortBinding(
                raw=item,
                host_ip=host_ip,
                host_port=host_port,
                container_port=container_port,
                protocol=protocol,
            )
        )
    return ports


def _split_protocol(port_spec: str) -> tuple[str, str]:
    if "/" not in port_spec:
        return port_spec, "tcp"
    base, protocol = port_spec.rsplit("/", 1)
    return base, protocol


def _parse_volumes(value: Any) -> list[VolumeMount]:
    mounts: list[VolumeMount] = []
    for item in _coerce_list(value):
        if isinstance(item, dict):
            source = item.get("source")
            target = item.get("target")
            mode = item.get("read_only")
            mounts.append(
                VolumeMount(
                    raw=str(item),
                    source=None if source is None else str(source),
                    target=None if target is None else str(target),
                    mode="ro" if mode else None,
                    mount_type=str(item.get("type", "volume")),
                )
            )
            continue
        if not isinstance(item, str):
            continue
        parts = item.split(":")
        source: str | None = None
        target: str | None = None
        mode: str | None = None
        if len(parts) >= 2:
            source = parts[0]
            target = parts[1]
        if len(parts) >= 3:
            mode = parts[2]
        mount_type = _detect_mount_type(source)
        mounts.append(
            VolumeMount(
                raw=item,
                source=source,
                target=target,
                mode=mode,
                mount_type=mount_type,
            )
        )
    return mounts


def _detect_mount_type(source: str | None) -> str:
    if not source:
        return "anonymous"
    if source.startswith(("/", "./", "../", "~/")):
        return "bind"
    return "volume"
