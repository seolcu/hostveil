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
    }
}


def tr(key: str, locale: str = DEFAULT_LOCALE, **kwargs: Any) -> str:
    try:
        template = MESSAGES[locale][key]
    except KeyError as error:
        raise KeyError(f"Missing translation for {locale}:{key}") from error
    return template.format(**kwargs)
