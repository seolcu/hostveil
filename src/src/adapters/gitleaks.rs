use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::Deserialize;

use crate::adapters::command;
use crate::domain::{AdapterStatus, Axis, Finding, RemediationKind, Scope, Severity, Source};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitleaksScanOutput {
    pub status: AdapterStatus,
    pub findings: Vec<Finding>,
    pub warnings: Vec<String>,
}

pub fn scan(
    compose_root: Option<&Path>,
    loaded_files: &[PathBuf],
    timeout: Duration,
) -> GitleaksScanOutput {
    scan_with_command(compose_root, loaded_files, "gitleaks", timeout)
}

fn scan_with_command(
    compose_root: Option<&Path>,
    loaded_files: &[PathBuf],
    command_name: &str,
    timeout: Duration,
) -> GitleaksScanOutput {
    let mut output = GitleaksScanOutput {
        status: AdapterStatus::Skipped(t!("adapter.reason.no_project_root").into_owned()),
        findings: Vec::new(),
        warnings: Vec::new(),
    };

    let Some(compose_root) = compose_root else {
        return output;
    };

    match detect_gitleaks_with_command(command_name, timeout) {
        GitleaksAvailability::Missing => {
            output.status = AdapterStatus::Missing;
            return output;
        }
        GitleaksAvailability::Available => {
            output.status = AdapterStatus::Available;
        }
        GitleaksAvailability::Failed(detail) => {
            output.status = AdapterStatus::Failed(detail);
            return output;
        }
    }

    match scan_dir_with_command(command_name, compose_root, timeout) {
        Ok(entries) => {
            output.findings = entries_to_findings(entries, compose_root, loaded_files);
        }
        Err(error) => {
            output.status = AdapterStatus::Failed(error);
        }
    }

    output
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GitleaksAvailability {
    Available,
    Missing,
    Failed(String),
}

fn detect_gitleaks_with_command(command_name: &str, timeout: Duration) -> GitleaksAvailability {
    let mut command = Command::new(command_name);
    command.arg("version").env("NO_COLOR", "1");
    match command::run_with_timeout(command, timeout) {
        Ok(output) if output.status.success() => GitleaksAvailability::Available,
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let detail = if !stderr.trim().is_empty() {
                stderr.trim().to_owned()
            } else {
                stdout.trim().to_owned()
            };
            GitleaksAvailability::Failed(command::truncate(&detail, 200))
        }
        Err(error) if error.is_not_found() => GitleaksAvailability::Missing,
        Err(error) => GitleaksAvailability::Failed(command::truncate(&error.detail(), 200)),
    }
}

fn scan_dir_with_command(
    command_name: &str,
    compose_root: &Path,
    timeout: Duration,
) -> Result<Vec<GitleaksFinding>, String> {
    let mut command = Command::new(command_name);
    command
        .args(gitleaks_dir_args(compose_root, timeout))
        .env("NO_COLOR", "1");

    let output = command::run_with_timeout(command, timeout).map_err(|error| error.detail())?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = if !stderr.trim().is_empty() {
            stderr.trim().to_owned()
        } else {
            stdout.trim().to_owned()
        };
        return Err(command::truncate(&detail, 240));
    }

    serde_json::from_slice(&output.stdout)
        .map_err(|error| crate::i18n::tr_adapter_json_parse_failed("Gitleaks", &error.to_string()))
}

fn gitleaks_dir_args(compose_root: &Path, timeout: Duration) -> Vec<String> {
    vec![
        String::from("dir"),
        compose_root.display().to_string(),
        String::from("--no-banner"),
        String::from("--no-color"),
        String::from("--redact=100"),
        String::from("--log-level=error"),
        String::from("--report-format=json"),
        String::from("--report-path=-"),
        String::from("--exit-code=0"),
        String::from("--timeout"),
        timeout.as_secs().max(1).to_string(),
    ]
}

fn entries_to_findings(
    entries: Vec<GitleaksFinding>,
    compose_root: &Path,
    loaded_files: &[PathBuf],
) -> Vec<Finding> {
    let excluded_paths = excluded_loaded_paths(compose_root, loaded_files);
    let mut grouped = BTreeMap::<String, AggregatedFileFinding>::new();

    for entry in entries {
        let Some(relative_path) = relative_file_path(compose_root, &entry.file) else {
            continue;
        };
        if should_skip_path(&relative_path, &excluded_paths) {
            continue;
        }

        let bucket =
            grouped
                .entry(relative_path.clone())
                .or_insert_with(|| AggregatedFileFinding {
                    path: relative_path.clone(),
                    match_count: 0,
                    rule_ids: BTreeSet::new(),
                    start_lines: BTreeSet::new(),
                });
        bucket.match_count += 1;
        bucket.rule_ids.insert(entry.rule_id);
        bucket.start_lines.insert(entry.start_line);
    }

    grouped.into_values().map(aggregated_to_finding).collect()
}

fn excluded_loaded_paths(compose_root: &Path, loaded_files: &[PathBuf]) -> BTreeSet<String> {
    loaded_files
        .iter()
        .filter_map(|path| relative_file_path(compose_root, path))
        .collect()
}

fn relative_file_path(compose_root: &Path, file: &Path) -> Option<String> {
    let absolute = if file.is_absolute() {
        file.to_path_buf()
    } else {
        compose_root.join(file)
    };

    absolute.strip_prefix(compose_root).ok().map(normalize_path)
}

fn normalize_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn should_skip_path(path: &str, excluded_loaded_paths: &BTreeSet<String>) -> bool {
    excluded_loaded_paths.contains(path) || looks_like_env_file(path)
}

fn looks_like_env_file(path: &str) -> bool {
    let Some(file_name) = Path::new(path).file_name().and_then(|name| name.to_str()) else {
        return false;
    };

    file_name == ".env"
        || file_name.starts_with(".env.")
        || file_name.ends_with(".env")
        || file_name.contains(".env.")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AggregatedFileFinding {
    path: String,
    match_count: usize,
    rule_ids: BTreeSet<String>,
    start_lines: BTreeSet<usize>,
}

fn aggregated_to_finding(summary: AggregatedFileFinding) -> Finding {
    let rule_ids = summary.rule_ids.iter().cloned().collect::<Vec<_>>();
    let lines = summary
        .start_lines
        .iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();

    Finding {
        id: format!("gitleaks.project_secret_leak.{}", slug(&summary.path)),
        axis: Axis::SensitiveData,
        severity: Severity::High,
        scope: Scope::Project,
        source: Source::Gitleaks,
        subject: summary.path.clone(),
        related_service: None,
        title: t!("finding.gitleaks.project_secret_leak.title").into_owned(),
        description: t!(
            "finding.gitleaks.project_secret_leak.description",
            path = summary.path.as_str(),
            count = summary.match_count
        )
        .into_owned(),
        why_risky: t!("finding.gitleaks.project_secret_leak.why").into_owned(),
        how_to_fix: t!("finding.gitleaks.project_secret_leak.fix").into_owned(),
        evidence: BTreeMap::from([
            (String::from("path"), summary.path),
            (String::from("match_count"), summary.match_count.to_string()),
            (String::from("rule_ids"), rule_ids.join(",")),
            (String::from("lines"), lines.join(",")),
        ]),
        remediation: RemediationKind::Manual,
    }
}

fn slug(value: &str) -> String {
    let mut slug = String::with_capacity(value.len());
    let mut last_was_separator = false;

    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            last_was_separator = false;
        } else if !last_was_separator {
            slug.push('_');
            last_was_separator = true;
        }
    }

    slug.trim_matches('_').to_owned()
}

#[derive(Debug, Clone, Deserialize)]
struct GitleaksFinding {
    #[serde(rename = "RuleID")]
    rule_id: String,
    #[serde(rename = "StartLine")]
    start_line: usize,
    #[serde(rename = "File")]
    file: PathBuf,
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use super::*;

    #[test]
    fn builds_expected_gitleaks_command_args() {
        let args = gitleaks_dir_args(Path::new("/srv/demo"), Duration::from_secs(45));

        assert!(args.contains(&String::from("dir")));
        assert!(args.contains(&String::from("/srv/demo")));
        assert!(args.contains(&String::from("--report-format=json")));
        assert!(args.contains(&String::from("--report-path=-")));
        assert!(args.contains(&String::from("--exit-code=0")));
        assert!(args.contains(&String::from("--log-level=error")));
        assert!(args.contains(&String::from("45")));
    }

    #[test]
    fn filters_compose_and_env_files_from_gitleaks_findings() {
        let entries = vec![
            GitleaksFinding {
                rule_id: String::from("github-pat"),
                start_line: 1,
                file: PathBuf::from("/srv/demo/docker-compose.yml"),
            },
            GitleaksFinding {
                rule_id: String::from("aws-access-token"),
                start_line: 2,
                file: PathBuf::from("/srv/demo/.env.production"),
            },
            GitleaksFinding {
                rule_id: String::from("github-pat"),
                start_line: 3,
                file: PathBuf::from("/srv/demo/scripts/bootstrap.sh"),
            },
            GitleaksFinding {
                rule_id: String::from("generic-api-key"),
                start_line: 9,
                file: PathBuf::from("/srv/demo/scripts/bootstrap.sh"),
            },
        ];

        let findings = entries_to_findings(
            entries,
            Path::new("/srv/demo"),
            &[PathBuf::from("/srv/demo/docker-compose.yml")],
        );

        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.source, Source::Gitleaks);
        assert_eq!(finding.axis, Axis::SensitiveData);
        assert_eq!(finding.scope, Scope::Project);
        assert_eq!(finding.subject, "scripts/bootstrap.sh");
        assert_eq!(
            finding.evidence.get("match_count"),
            Some(&String::from("2"))
        );
        assert_eq!(
            finding.evidence.get("rule_ids"),
            Some(&String::from("generic-api-key,github-pat"))
        );
    }

    #[test]
    fn aggregated_finding_does_not_expose_raw_secret_material() {
        let findings = entries_to_findings(
            vec![GitleaksFinding {
                rule_id: String::from("github-pat"),
                start_line: 14,
                file: PathBuf::from("/srv/demo/notes/secrets.txt"),
            }],
            Path::new("/srv/demo"),
            &[],
        );

        let finding = &findings[0];
        assert!(!finding.title.contains("REDACTED"));
        assert!(!finding.description.contains("REDACTED"));
        assert!(
            !finding
                .evidence
                .values()
                .any(|value| value.contains("REDACTED"))
        );
        assert_eq!(finding.evidence.get("lines"), Some(&String::from("14")));
    }

    #[test]
    fn parses_gitleaks_json_fixture() {
        let entries: Vec<GitleaksFinding> = serde_json::from_str(include_str!(
            "../../tests/fixtures/adapters/gitleaks-dir-report.json"
        ))
        .expect("fixture should parse");

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].rule_id, "github-pat");
        assert_eq!(entries[0].file, PathBuf::from("scripts/bootstrap.sh"));
    }

    #[test]
    fn missing_project_root_skips_scan() {
        let output = scan_with_command(None, &[], "gitleaks", Duration::from_secs(1));
        assert_eq!(
            output.status,
            AdapterStatus::Skipped(
                t!("adapter.reason.no_project_root", locale = "en").into_owned()
            )
        );
        assert!(output.findings.is_empty());
    }

    #[test]
    fn missing_binary_marks_adapter_missing() {
        let output = scan_with_command(
            Some(Path::new("/srv/demo")),
            &[],
            "definitely-not-a-real-gitleaks-binary",
            Duration::from_secs(1),
        );
        assert_eq!(output.status, AdapterStatus::Missing);
    }

    #[test]
    fn empty_findings_list_produces_no_findings() {
        let findings = entries_to_findings(vec![], Path::new("/srv/demo"), &[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn findings_from_compose_file_are_filtered_out() {
        let entries = vec![
            GitleaksFinding {
                rule_id: String::from("github-pat"),
                start_line: 1,
                file: PathBuf::from("/srv/demo/docker-compose.yml"),
            },
            GitleaksFinding {
                rule_id: String::from("aws-key"),
                start_line: 2,
                file: PathBuf::from("/srv/demo/src/main.rs"),
            },
        ];

        let findings = entries_to_findings(
            entries,
            Path::new("/srv/demo"),
            &[PathBuf::from("/srv/demo/docker-compose.yml")],
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].subject, "src/main.rs");
    }

    #[test]
    fn findings_from_env_files_are_filtered_out() {
        let entries = vec![
            GitleaksFinding {
                rule_id: String::from("generic-secret"),
                start_line: 1,
                file: PathBuf::from("/srv/demo/.env"),
            },
            GitleaksFinding {
                rule_id: String::from("generic-secret"),
                start_line: 2,
                file: PathBuf::from("/srv/demo/.env.local"),
            },
            GitleaksFinding {
                rule_id: String::from("generic-secret"),
                start_line: 3,
                file: PathBuf::from("/srv/demo/.env.production"),
            },
            GitleaksFinding {
                rule_id: String::from("aws-key"),
                start_line: 4,
                file: PathBuf::from("/srv/demo/config.yml"),
            },
        ];

        let findings = entries_to_findings(entries, Path::new("/srv/demo"), &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].subject, "config.yml");
    }

    #[test]
    fn multiple_findings_same_file_are_aggregated() {
        let entries = vec![
            GitleaksFinding {
                rule_id: String::from("github-pat"),
                start_line: 10,
                file: PathBuf::from("/srv/demo/notes.txt"),
            },
            GitleaksFinding {
                rule_id: String::from("aws-key"),
                start_line: 20,
                file: PathBuf::from("/srv/demo/notes.txt"),
            },
            GitleaksFinding {
                rule_id: String::from("github-pat"),
                start_line: 30,
                file: PathBuf::from("/srv/demo/notes.txt"),
            },
        ];

        let findings = entries_to_findings(entries, Path::new("/srv/demo"), &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].evidence.get("match_count"),
            Some(&String::from("3"))
        );
        assert_eq!(
            findings[0].evidence.get("rule_ids"),
            Some(&String::from("aws-key,github-pat"))
        );
        assert_eq!(
            findings[0].evidence.get("lines"),
            Some(&String::from("10,20,30"))
        );
    }

    #[test]
    fn finding_severity_is_high() {
        let entries = vec![GitleaksFinding {
            rule_id: String::from("github-pat"),
            start_line: 1,
            file: PathBuf::from("/srv/demo/secret.txt"),
        }];

        let findings = entries_to_findings(entries, Path::new("/srv/demo"), &[]);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn finding_subject_is_relative_to_project_root() {
        let entries = vec![GitleaksFinding {
            rule_id: String::from("generic-api-key"),
            start_line: 5,
            file: PathBuf::from("/srv/demo/src/config/keys.rs"),
        }];

        let findings = entries_to_findings(entries, Path::new("/srv/demo"), &[]);
        assert_eq!(findings[0].subject, "src/config/keys.rs");
    }

    #[test]
    fn finding_evidence_contains_rule_ids() {
        let entries = vec![GitleaksFinding {
            rule_id: String::from("github-pat"),
            start_line: 1,
            file: PathBuf::from("/srv/demo/secret.txt"),
        }];

        let findings = entries_to_findings(entries, Path::new("/srv/demo"), &[]);
        assert_eq!(
            findings[0].evidence.get("rule_ids"),
            Some(&String::from("github-pat"))
        );
    }

    #[test]
    fn gitleaks_command_includes_timeout() {
        let args = gitleaks_dir_args(Path::new("/tmp/project"), Duration::from_secs(120));
        assert!(args.contains(&String::from("120")));
    }

    #[test]
    fn gitleaks_command_sets_zero_exit_code() {
        let args = gitleaks_dir_args(Path::new("/tmp/project"), Duration::from_secs(10));
        assert!(args.contains(&String::from("--exit-code=0")));
    }

    #[test]
    fn gitleaks_command_sets_error_log_level() {
        let args = gitleaks_dir_args(Path::new("/tmp/project"), Duration::from_secs(10));
        assert!(args.contains(&String::from("--log-level=error")));
    }

    #[test]
    fn detect_gitleaks_reports_missing_for_unknown_binary() {
        let status =
            detect_gitleaks_with_command("hostveil-nonexistent-gitleaks", Duration::from_secs(1));
        assert_eq!(status, GitleaksAvailability::Missing);
    }

    #[test]
    fn detect_gitleaks_reports_failed_for_non_zero_command() {
        let status = detect_gitleaks_with_command("false", Duration::from_secs(1));
        assert!(matches!(status, GitleaksAvailability::Failed(_)));
    }

    #[test]
    fn detect_gitleaks_reports_available_for_true_command() {
        let status = detect_gitleaks_with_command("true", Duration::from_secs(1));
        assert_eq!(status, GitleaksAvailability::Available);
    }

    #[test]
    fn gitleaks_args_include_exit_code_zero() {
        let args = gitleaks_dir_args(Path::new("/path"), Duration::from_secs(120));
        assert!(args.contains(&String::from("--exit-code=0")));
    }

    #[test]
    fn gitleaks_args_include_report_json_stdout() {
        let args = gitleaks_dir_args(Path::new("/path"), Duration::from_secs(120));
        assert!(args.contains(&String::from("--report-format=json")));
        assert!(args.contains(&String::from("--report-path=-")));
    }
}
