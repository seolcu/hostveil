"""Update and maintenance risk checks."""

from __future__ import annotations

import re

from ..i18n import tr
from ..models import Axis, ComposeProject, Finding, Severity


MAJOR_ONLY_TAG = re.compile(r"^v?\d+$")


def scan_update_risk(project: ComposeProject) -> list[Finding]:
    findings: list[Finding] = []
    for service in project.services.values():
        if not service.image:
            continue
        repository, tag = split_image_reference(service.image)
        if tag is None:
            findings.append(
                Finding(
                    check_id="updates.no_tag",
                    axis=Axis.UPDATE_RISK,
                    severity=Severity.MEDIUM,
                    title=tr("finding.updates.no_tag.title"),
                    description=tr(
                        "finding.updates.no_tag.description",
                        service=service.name,
                        image=service.image,
                    ),
                    why_risky=tr("finding.updates.no_tag.why"),
                    how_to_fix=tr("finding.updates.no_tag.fix"),
                    affected_service=service.name,
                    context={"image": service.image, "repository": repository},
                )
            )
            continue
        if tag == "latest":
            findings.append(
                Finding(
                    check_id="updates.latest_tag",
                    axis=Axis.UPDATE_RISK,
                    severity=Severity.HIGH,
                    title=tr("finding.updates.latest.title"),
                    description=tr(
                        "finding.updates.latest.description",
                        service=service.name,
                        image=service.image,
                    ),
                    why_risky=tr("finding.updates.latest.why"),
                    how_to_fix=tr("finding.updates.latest.fix"),
                    affected_service=service.name,
                    context={"image": service.image, "repository": repository, "tag": tag},
                )
            )
            continue
        if MAJOR_ONLY_TAG.match(tag):
            findings.append(
                Finding(
                    check_id="updates.major_only_tag",
                    axis=Axis.UPDATE_RISK,
                    severity=Severity.LOW,
                    title=tr("finding.updates.major_only.title"),
                    description=tr(
                        "finding.updates.major_only.description",
                        service=service.name,
                        image=service.image,
                    ),
                    why_risky=tr("finding.updates.major_only.why"),
                    how_to_fix=tr("finding.updates.major_only.fix"),
                    affected_service=service.name,
                    context={"image": service.image, "repository": repository, "tag": tag},
                )
            )
    return findings


def split_image_reference(image: str) -> tuple[str, str | None]:
    if "@" in image:
        return image.split("@", 1)[0], None
    last_slash = image.rfind("/")
    last_colon = image.rfind(":")
    if last_colon <= last_slash:
        return image, None
    return image[:last_colon], image[last_colon + 1 :]
