"""External exposure checks."""

from __future__ import annotations

from ..i18n import tr
from ..models import Axis, ComposeProject, Finding, PortBinding, Severity


ADMIN_SERVICE_HINTS = ("adminer", "pgadmin", "phpmyadmin", "portainer", "traefik")
REVERSE_PROXY_HINTS = ("vaultwarden", "nextcloud", "gitea", "immich")
LOCAL_ONLY_HOSTS = {"127.0.0.1", "::1", "localhost"}
PUBLIC_HOSTS = {None, "0.0.0.0", "::", "[::]"}


def scan_exposure_risk(project: ComposeProject) -> list[Finding]:
    findings: list[Finding] = []
    for service in project.services.values():
        public_ports = [port for port in service.ports if is_public_port(port)]
        if not public_ports:
            continue

        first_public = public_ports[0]
        findings.append(
            Finding(
                check_id="exposure.public_binding",
                axis=Axis.UNNECESSARY_EXPOSURE,
                severity=Severity.MEDIUM,
                title=tr("finding.exposure.public_bind.title"),
                description=tr(
                    "finding.exposure.public_bind.description",
                    service=service.name,
                    port=first_public.raw,
                ),
                why_risky=tr("finding.exposure.public_bind.why"),
                how_to_fix=tr("finding.exposure.public_bind.fix"),
                affected_service=service.name,
                context={
                    "port": first_public.raw,
                    "host_ip": first_public.host_ip or "0.0.0.0",
                    "host_port": first_public.host_port or "",
                    "container_port": first_public.container_port,
                },
            )
        )

        if _matches_known_service(service.name, service.image, ADMIN_SERVICE_HINTS):
            findings.append(
                Finding(
                    check_id="exposure.admin_interface_public",
                    axis=Axis.UNNECESSARY_EXPOSURE,
                    severity=Severity.CRITICAL,
                    title=tr("finding.exposure.admin_public.title"),
                    description=tr(
                        "finding.exposure.admin_public.description",
                        service=service.name,
                        port=first_public.raw,
                    ),
                    why_risky=tr("finding.exposure.admin_public.why"),
                    how_to_fix=tr("finding.exposure.admin_public.fix"),
                    affected_service=service.name,
                    context={"port": first_public.raw},
                )
            )

        if _matches_known_service(service.name, service.image, REVERSE_PROXY_HINTS):
            findings.append(
                Finding(
                    check_id="exposure.reverse_proxy_expected",
                    axis=Axis.UNNECESSARY_EXPOSURE,
                    severity=Severity.HIGH,
                    title=tr("finding.exposure.reverse_proxy.title"),
                    description=tr(
                        "finding.exposure.reverse_proxy.description",
                        service=service.name,
                        port=first_public.raw,
                    ),
                    why_risky=tr("finding.exposure.reverse_proxy.why"),
                    how_to_fix=tr("finding.exposure.reverse_proxy.fix"),
                    affected_service=service.name,
                    context={"port": first_public.raw},
                )
            )
    return findings


def is_public_port(port: PortBinding) -> bool:
    if port.host_ip in LOCAL_ONLY_HOSTS:
        return False
    return port.host_ip in PUBLIC_HOSTS


def _matches_known_service(
    service_name: str, image: str | None, hints: tuple[str, ...]
) -> bool:
    haystack = f"{service_name} {image or ''}".lower()
    return any(hint in haystack for hint in hints)
