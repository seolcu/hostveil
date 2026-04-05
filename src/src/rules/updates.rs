use std::collections::BTreeMap;

use crate::compose::ComposeProject;
use crate::domain::{Axis, Finding, RemediationKind, Severity};

use super::{ServiceFindingText, service_finding, service_finding_with_remediation};

pub fn scan_update_risk(project: &ComposeProject) -> Vec<Finding> {
    let mut findings = Vec::new();

    for service in project.services.values() {
        let Some(image) = service.image.as_deref() else {
            continue;
        };

        let (repository, tag) = split_image_reference(image);
        match tag.as_deref() {
            None => findings.push(service_finding_with_remediation(
                "updates.no_tag",
                Axis::UpdateSupplyChainRisk,
                Severity::Medium,
                &service.name,
                ServiceFindingText {
                    title: t!("finding.updates.no_tag.title").into_owned(),
                    description: t!(
                        "finding.updates.no_tag.description",
                        service = service.name.as_str(),
                        image = image
                    )
                    .into_owned(),
                    why_risky: t!("finding.updates.no_tag.why").into_owned(),
                    how_to_fix: t!("finding.updates.no_tag.fix").into_owned(),
                },
                BTreeMap::from([
                    (String::from("image"), image.to_owned()),
                    (String::from("repository"), repository.clone()),
                ]),
                if is_safe_nginx_repository(&repository) {
                    RemediationKind::Safe
                } else {
                    RemediationKind::None
                },
            )),
            Some("latest") => findings.push(service_finding(
                "updates.latest_tag",
                Axis::UpdateSupplyChainRisk,
                Severity::High,
                &service.name,
                ServiceFindingText {
                    title: t!("finding.updates.latest.title").into_owned(),
                    description: t!(
                        "finding.updates.latest.description",
                        service = service.name.as_str(),
                        image = image
                    )
                    .into_owned(),
                    why_risky: t!("finding.updates.latest.why").into_owned(),
                    how_to_fix: t!("finding.updates.latest.fix").into_owned(),
                },
                BTreeMap::from([
                    (String::from("image"), image.to_owned()),
                    (String::from("repository"), repository.clone()),
                    (String::from("tag"), String::from("latest")),
                ]),
            )),
            Some(tag) if is_major_only_tag(tag) => findings.push(service_finding(
                "updates.major_only_tag",
                Axis::UpdateSupplyChainRisk,
                Severity::Low,
                &service.name,
                ServiceFindingText {
                    title: t!("finding.updates.major_only.title").into_owned(),
                    description: t!(
                        "finding.updates.major_only.description",
                        service = service.name.as_str(),
                        image = image
                    )
                    .into_owned(),
                    why_risky: t!("finding.updates.major_only.why").into_owned(),
                    how_to_fix: t!("finding.updates.major_only.fix").into_owned(),
                },
                BTreeMap::from([
                    (String::from("image"), image.to_owned()),
                    (String::from("repository"), repository.clone()),
                    (String::from("tag"), tag.to_owned()),
                ]),
            )),
            Some(_) => {}
        }
    }

    findings
}

pub fn split_image_reference(image: &str) -> (String, Option<String>) {
    if let Some((repository, _digest)) = image.split_once('@') {
        return (repository.to_owned(), None);
    }

    let last_slash = image.rfind('/').unwrap_or(0);
    let last_colon = image.rfind(':').unwrap_or(0);
    if last_colon <= last_slash {
        return (image.to_owned(), None);
    }

    (
        image[..last_colon].to_owned(),
        Some(image[last_colon + 1..].to_owned()),
    )
}

fn is_major_only_tag(tag: &str) -> bool {
    let candidate = tag.strip_prefix('v').unwrap_or(tag);
    !candidate.is_empty()
        && candidate
            .chars()
            .all(|character| character.is_ascii_digit())
}

fn is_safe_nginx_repository(repository: &str) -> bool {
    matches!(
        repository,
        "nginx" | "library/nginx" | "docker.io/nginx" | "docker.io/library/nginx"
    )
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::compose::ComposeParser;

    use super::*;

    fn fixture() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../proto/tests/fixtures/rules/update-risk.yml")
            .canonicalize()
            .expect("fixture should exist")
    }

    #[test]
    fn detects_expected_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture()).expect("project should parse");

        let findings = scan_update_risk(&project);

        assert_eq!(
            findings
                .iter()
                .map(|finding| (
                    finding.id.as_str(),
                    finding.related_service.as_deref().unwrap_or_default()
                ))
                .collect::<Vec<_>>(),
            vec![
                ("updates.latest_tag", "latest"),
                ("updates.no_tag", "no_tag"),
                ("updates.major_only_tag", "major_only"),
            ]
        );
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.severity)
                .collect::<Vec<_>>(),
            vec![Severity::High, Severity::Medium, Severity::Low]
        );
    }

    #[test]
    fn skips_pinned_images() {
        let project =
            ComposeParser::parse_path_without_override(fixture()).expect("project should parse");

        let findings = scan_update_risk(&project);

        assert!(
            findings
                .iter()
                .all(|finding| finding.related_service.as_deref() != Some("pinned"))
        );
    }

    #[test]
    fn marks_nginx_missing_tag_as_safe_remediation() {
        let project =
            ComposeParser::parse_path_without_override(fixture()).expect("project should parse");

        let finding = scan_update_risk(&project)
            .into_iter()
            .find(|finding| finding.related_service.as_deref() == Some("no_tag"))
            .expect("missing tag finding should exist");

        assert_eq!(finding.remediation, crate::domain::RemediationKind::Safe);
    }
}
