"""Minimal i18n layer for the prototype."""

from __future__ import annotations

from typing import Any


DEFAULT_LOCALE = "en"

MESSAGES = {
    "en": {
        "cli.parser_error": "Failed to parse compose file: {message}",
        "cli.scan_complete": "Parsed {service_count} service(s) from {path}.",
        "parser.compose_file_not_found": "Could not find docker-compose.yml or docker-compose.yaml in {path}.",
        "parser.compose_path_missing": "Compose path does not exist: {path}",
        "parser.malformed_yaml": "Malformed YAML in {path}: {message}",
        "parser.missing_services": "No services were defined in {path}.",
        "finding.updates.latest.title": "Image uses the latest tag",
        "finding.updates.latest.description": "{service} uses {image}, which tracks a moving target instead of a stable version.",
        "finding.updates.latest.why": "A moving tag makes deployments harder to reproduce and can pull breaking changes without warning.",
        "finding.updates.latest.fix": "Pin the image to a specific version or digest before the next deploy.",
        "finding.updates.no_tag.title": "Image is missing an explicit tag",
        "finding.updates.no_tag.description": "{service} uses {image} without an explicit tag.",
        "finding.updates.no_tag.why": "Images without a tag implicitly resolve to latest-like behavior and make updates unpredictable.",
        "finding.updates.no_tag.fix": "Add a stable, explicit tag such as a pinned release version.",
        "finding.updates.major_only.title": "Image is only pinned to a major version",
        "finding.updates.major_only.description": "{service} uses {image}, which pins only the major version.",
        "finding.updates.major_only.why": "Major-only tags can still move to new minor or patch releases with behavior changes.",
        "finding.updates.major_only.fix": "Pin at least a minor or patch version for predictable rollouts.",
        "finding.exposure.public_bind.title": "Service is published on a public interface",
        "finding.exposure.public_bind.description": "{service} publishes {port} on a publicly reachable host interface.",
        "finding.exposure.public_bind.why": "Public bindings increase the attack surface and can bypass a safer localhost-only or reverse-proxy setup.",
        "finding.exposure.public_bind.fix": "Bind the port to 127.0.0.1 unless the service truly needs direct external access.",
        "finding.exposure.admin_public.title": "Admin interface is exposed publicly",
        "finding.exposure.admin_public.description": "{service} exposes an administrative interface on {port}.",
        "finding.exposure.admin_public.why": "Public admin panels are high-value targets for brute force, enumeration, and exploit attempts.",
        "finding.exposure.admin_public.fix": "Put the admin interface behind a private network or reverse proxy with authentication.",
        "finding.exposure.reverse_proxy.title": "Service should sit behind a reverse proxy",
        "finding.exposure.reverse_proxy.description": "{service} is directly published on {port} even though it is usually safer behind a reverse proxy.",
        "finding.exposure.reverse_proxy.why": "Directly publishing user-facing apps makes TLS, auth hardening, and access control easier to miss.",
        "finding.exposure.reverse_proxy.fix": "Route the service through a reverse proxy and remove the direct public port where possible.",
        "finding.permissions.privileged.title": "Container runs in privileged mode",
        "finding.permissions.privileged.description": "{service} enables privileged mode.",
        "finding.permissions.privileged.why": "Privileged containers get broad kernel and device access that sharply increases breakout impact.",
        "finding.permissions.privileged.fix": "Drop privileged mode and grant only the minimal capabilities the service actually needs.",
        "finding.permissions.root.title": "Container runs as root",
        "finding.permissions.root.description": "{service} is configured to run as root.",
        "finding.permissions.root.why": "A compromised root container has a larger blast radius and makes host escapes more dangerous.",
        "finding.permissions.root.fix": "Configure the service to run as a non-root UID/GID where supported.",
        "finding.permissions.implicit_root.title": "Container does not set a user",
        "finding.permissions.implicit_root.description": "{service} does not set a user, so it likely runs as root by default.",
        "finding.permissions.implicit_root.why": "Many images default to root, which grants more filesystem and process access than needed.",
        "finding.permissions.implicit_root.fix": "Set an explicit non-root user in the compose file when the image supports it.",
        "finding.permissions.host_network.title": "Container uses host networking",
        "finding.permissions.host_network.description": "{service} uses network_mode: host.",
        "finding.permissions.host_network.why": "Host networking removes network isolation and can expose more ports and traffic than intended.",
        "finding.permissions.host_network.fix": "Use bridge networking unless the service has a strong, documented need for host mode.",
        "finding.permissions.sensitive_mount.title": "Container mounts a sensitive host path",
        "finding.permissions.sensitive_mount.description": "{service} mounts the sensitive host path {path}.",
        "finding.permissions.sensitive_mount.why": "Mounting sensitive host paths can expose secrets, host control sockets, or broad filesystem access to the container.",
        "finding.permissions.sensitive_mount.fix": "Remove the mount or replace it with a narrower path that exposes only the required data.",
    }
}


def tr(key: str, locale: str = DEFAULT_LOCALE, **kwargs: Any) -> str:
    try:
        template = MESSAGES[locale][key]
    except KeyError as error:
        raise KeyError(f"Missing translation for {locale}:{key}") from error
    return template.format(**kwargs)
