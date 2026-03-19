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
    }
}


def tr(key: str, locale: str = DEFAULT_LOCALE, **kwargs: Any) -> str:
    try:
        template = MESSAGES[locale][key]
    except KeyError as error:
        raise KeyError(f"Missing translation for {locale}:{key}") from error
    return template.format(**kwargs)
