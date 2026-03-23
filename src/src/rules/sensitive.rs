use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::compose::ComposeProject;
use crate::domain::{Axis, Finding, Severity};

use super::{ServiceFindingText, service_finding};

const SECRET_KEYWORDS: [&str; 8] = [
    "password",
    "passwd",
    "token",
    "secret",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
];

const DEFAULT_SECRET_VALUES: [&str; 7] = [
    "", "password", "admin", "changeme", "default", "root", "secret",
];

pub fn scan_sensitive_data(project: &ComposeProject) -> Vec<Finding> {
    let mut findings = Vec::new();

    for service in project.services.values() {
        for (variable, value) in &service.environment {
            if !is_secret_key(variable) || variable.ends_with("_FILE") {
                continue;
            }

            let Some(value) = value.as_deref() else {
                continue;
            };
            let normalized = value.trim();
            if is_interpolated(normalized) {
                continue;
            }

            if DEFAULT_SECRET_VALUES.contains(&normalized.to_lowercase().as_str()) {
                findings.push(service_finding(
                    "sensitive.default_credential",
                    Axis::SensitiveData,
                    Severity::Critical,
                    &service.name,
                    ServiceFindingText {
                        title: t!("finding.sensitive.default_credential.title").into_owned(),
                        description: t!(
                            "finding.sensitive.default_credential.description",
                            service = service.name.as_str(),
                            variable = variable.as_str()
                        )
                        .into_owned(),
                        why_risky: t!("finding.sensitive.default_credential.why").into_owned(),
                        how_to_fix: t!("finding.sensitive.default_credential.fix").into_owned(),
                    },
                    BTreeMap::from([(String::from("variable"), variable.clone())]),
                ));
            } else {
                findings.push(service_finding(
                    "sensitive.inline_secret",
                    Axis::SensitiveData,
                    Severity::High,
                    &service.name,
                    ServiceFindingText {
                        title: t!("finding.sensitive.inline_secret.title").into_owned(),
                        description: t!(
                            "finding.sensitive.inline_secret.description",
                            service = service.name.as_str(),
                            variable = variable.as_str()
                        )
                        .into_owned(),
                        why_risky: t!("finding.sensitive.inline_secret.why").into_owned(),
                        how_to_fix: t!("finding.sensitive.inline_secret.fix").into_owned(),
                    },
                    BTreeMap::from([(String::from("variable"), variable.clone())]),
                ));
            }
        }

        for env_file in &service.env_files {
            let env_path = project.working_dir.join(env_file);
            let secret_keys = collect_plaintext_secret_keys(&env_path);
            if secret_keys.is_empty() {
                continue;
            }

            findings.push(service_finding(
                "sensitive.env_file_plaintext",
                Axis::SensitiveData,
                Severity::High,
                &service.name,
                ServiceFindingText {
                    title: t!("finding.sensitive.env_file_secret.title").into_owned(),
                    description: t!(
                        "finding.sensitive.env_file_secret.description",
                        service = service.name.as_str(),
                        env_file = env_file.as_str()
                    )
                    .into_owned(),
                    why_risky: t!("finding.sensitive.env_file_secret.why").into_owned(),
                    how_to_fix: t!("finding.sensitive.env_file_secret.fix").into_owned(),
                },
                BTreeMap::from([
                    (String::from("env_file"), env_file.clone()),
                    (String::from("variables"), secret_keys.join(",")),
                ]),
            ));
        }
    }

    findings
}

fn collect_plaintext_secret_keys(path: &Path) -> Vec<String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(_) => return Vec::new(),
    };

    let mut keys = BTreeSet::new();
    for line in text.lines() {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') || !stripped.contains('=') {
            continue;
        }

        let Some((key, value)) = stripped.split_once('=') else {
            continue;
        };
        if key.ends_with("_FILE") || !is_secret_key(key) {
            continue;
        }

        let normalized = value.trim();
        if normalized.is_empty() || is_interpolated(normalized) {
            continue;
        }

        keys.insert(key.to_owned());
    }

    keys.into_iter().collect()
}

fn is_secret_key(key: &str) -> bool {
    let lowered = key.to_lowercase();
    SECRET_KEYWORDS
        .iter()
        .any(|keyword| lowered.contains(keyword))
}

fn is_interpolated(value: &str) -> bool {
    value.starts_with("${") && value.ends_with('}')
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::compose::ComposeParser;

    use super::*;

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../proto/tests/fixtures/rules/sensitive-risk")
            .canonicalize()
            .expect("fixture should exist")
    }

    #[test]
    fn detects_expected_findings() {
        let project = ComposeParser::parse_path_without_override(fixture_root())
            .expect("project should parse");

        let findings = scan_sensitive_data(&project);

        assert_eq!(
            findings
                .iter()
                .map(|finding| (
                    finding.id.as_str(),
                    finding.related_service.as_deref().unwrap_or_default()
                ))
                .collect::<Vec<_>>(),
            vec![
                ("sensitive.inline_secret", "inline_secret"),
                ("sensitive.default_credential", "default_credential"),
                ("sensitive.env_file_plaintext", "env_file_secret"),
            ]
        );
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.severity)
                .collect::<Vec<_>>(),
            vec![Severity::High, Severity::Critical, Severity::High]
        );
    }

    #[test]
    fn skips_interpolated_and_secret_file_values() {
        let project = ComposeParser::parse_path_without_override(fixture_root())
            .expect("project should parse");

        let findings = scan_sensitive_data(&project);

        assert!(
            findings
                .iter()
                .all(|finding| finding.related_service.as_deref() != Some("safe"))
        );
    }
}
