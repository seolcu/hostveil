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
    }
}


def tr(key: str, locale: str = DEFAULT_LOCALE, **kwargs: Any) -> str:
    try:
        template = MESSAGES[locale][key]
    except KeyError as error:
        raise KeyError(f"Missing translation for {locale}:{key}") from error
    return template.format(**kwargs)
