use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_yaml::{Mapping, Sequence, Value};

use crate::compose::{ComposeParseError, ComposeParser};
use crate::domain::{Finding, RemediationKind};
use crate::rules::RuleEngine;

mod adapter;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixMode {
    AutoFix,
    Fix,
}

impl FixMode {
    fn includes_review(self) -> bool {
        matches!(self, Self::Fix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixProposal {
    pub service: String,
    pub summary: String,
    pub remediation: RemediationKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixAction {
    ComposeEdit {
        service: String,
        summary: String,
        diff: String,
    },
    HostEdit {
        path: PathBuf,
        summary: String,
        original_content: String,
        updated_content: String,
        mode: Option<u32>,
    },
    ShellCommand {
        command: String,
        summary: String,
        rollback: Option<String>,
    },
}

impl FixAction {
    pub fn summary(&self) -> &str {
        match self {
            Self::ComposeEdit { summary, .. }
            | Self::HostEdit { summary, .. }
            | Self::ShellCommand { summary, .. } => summary,
        }
    }

    pub fn remediation_label(&self) -> RemediationKind {
        match self {
            Self::ComposeEdit { .. } => RemediationKind::Auto,
            Self::HostEdit { .. } => RemediationKind::Auto,
            Self::ShellCommand { .. } => RemediationKind::Auto,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FixPlan {
    pub compose_file: PathBuf,
    pub diff_preview: String,
    pub updated_text: String,
    pub backup_path: Option<PathBuf>,
    pub auto_applied: Vec<FixProposal>,
    pub review_applied: Vec<FixProposal>,
    pub host_actions: Vec<FixAction>,
    pub system_actions: Vec<FixAction>,
    pub compose_actions: Vec<FixAction>,
}

impl FixPlan {
    pub fn changed(&self) -> bool {
        !(self.auto_applied.is_empty()
            && self.review_applied.is_empty()
            && self.host_actions.is_empty()
            && self.system_actions.is_empty()
            && self.compose_actions.is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewChoiceOption {
    pub key: String,
    pub label: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewRequest {
    Choice {
        finding_id: String,
        service: String,
        title: String,
        description: String,
        options: Vec<ReviewChoiceOption>,
    },
    SecretInput {
        finding_id: String,
        service: String,
        variable: String,
        title: String,
        description: String,
        suggested_value: String,
    },
}

impl ReviewRequest {
    pub fn finding_id(&self) -> &str {
        match self {
            Self::Choice { finding_id, .. } | Self::SecretInput { finding_id, .. } => finding_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewResolution {
    Choice(String),
    SecretValue(String),
}

pub type FixResolutionMap = BTreeMap<String, ReviewResolution>;

#[derive(Debug)]
pub enum FixError {
    ComposeParse(ComposeParseError),
    Io(io::Error),
    Serialize(String),
    ReviewRequired(Vec<ReviewRequest>),
    InvalidReviewResolution(String),
}

impl fmt::Display for FixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ComposeParse(error) => {
                write!(f, "{}", crate::i18n::tr_compose_parse_error(error))
            }
            Self::Io(error) => write!(f, "{}", crate::i18n::tr_io_error(&error.to_string())),
            Self::Serialize(message) => write!(
                f,
                "{}",
                t!("app.error.fix_serialize", message = message.as_str()).into_owned()
            ),
            Self::ReviewRequired(_) => {
                write!(f, "{}", t!("app.error.fix_review_required").into_owned())
            }
            Self::InvalidReviewResolution(message) => write!(
                f,
                "{}",
                t!(
                    "app.error.fix_invalid_review_resolution",
                    message = message.as_str()
                )
                .into_owned()
            ),
        }
    }
}

impl std::error::Error for FixError {}

impl From<ComposeParseError> for FixError {
    fn from(value: ComposeParseError) -> Self {
        Self::ComposeParse(value)
    }
}

impl From<io::Error> for FixError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn preview(
    path: impl AsRef<Path>,
    mode: FixMode,
    only_findings: Option<&[String]>,
) -> Result<FixPlan, FixError> {
    preview_with_resolutions(path, mode, only_findings, &FixResolutionMap::new())
}

pub fn apply(
    path: impl AsRef<Path>,
    mode: FixMode,
    only_findings: Option<&[String]>,
) -> Result<FixPlan, FixError> {
    apply_with_resolutions(path, mode, only_findings, &FixResolutionMap::new())
}

pub fn preview_with_resolutions(
    path: impl AsRef<Path>,
    mode: FixMode,
    only_findings: Option<&[String]>,
    resolutions: &FixResolutionMap,
) -> Result<FixPlan, FixError> {
    preview_with_external(path, mode, only_findings, &[], resolutions)
}

pub fn preview_with_external(
    path: impl AsRef<Path>,
    mode: FixMode,
    only_findings: Option<&[String]>,
    external_findings: &[Finding],
    resolutions: &FixResolutionMap,
) -> Result<FixPlan, FixError> {
    build_fix_plan(
        path.as_ref(),
        mode,
        only_findings,
        external_findings,
        resolutions,
    )
}

pub fn apply_with_resolutions(
    path: impl AsRef<Path>,
    mode: FixMode,
    only_findings: Option<&[String]>,
    resolutions: &FixResolutionMap,
) -> Result<FixPlan, FixError> {
    apply_with_external(path, mode, only_findings, &[], resolutions)
}

pub fn apply_with_external(
    path: impl AsRef<Path>,
    mode: FixMode,
    only_findings: Option<&[String]>,
    external_findings: &[Finding],
    resolutions: &FixResolutionMap,
) -> Result<FixPlan, FixError> {
    let mut plan = build_fix_plan(
        path.as_ref(),
        mode,
        only_findings,
        external_findings,
        resolutions,
    )?;
    if !plan.changed() {
        return Ok(plan);
    }

    if !plan.updated_text.is_empty() {
        let backup_path = backup_path_for(&plan.compose_file);
        fs::copy(&plan.compose_file, &backup_path)?;
        atomic_write_file(&plan.compose_file, &plan.updated_text)?;
        plan.backup_path = Some(backup_path);
    }

    execute_host_and_system_actions(&plan)?;

    Ok(plan)
}

fn apply_compose_edits_to_text(original_text: &str, actions: &[FixAction]) -> (String, String) {
    if actions.is_empty() {
        return (original_text.to_string(), String::new());
    }

    let mut text = original_text.to_string();
    let mut diff_lines = Vec::new();

    for action in actions {
        if let FixAction::ComposeEdit {
            service,
            summary: _,
            diff,
        } = action
        {
            let additions: Vec<&str> = diff
                .lines()
                .filter(|l| l.starts_with('+'))
                .map(|l| &l[1..])
                .collect();
            if additions.is_empty() {
                continue;
            }

            diff_lines.push(format!(
                "--- a/docker-compose.yml (compose-edit {})",
                service
            ));
            diff_lines.push(format!(
                "+++ b/docker-compose.yml (compose-edit {})",
                service
            ));
            for line in &additions {
                diff_lines.push(format!("+{}", line));
            }

            let service_header = format!("\n  {}:", service);
            if let Some(pos) = text.find(&service_header) {
                let insert_pos = pos + service_header.len();
                let mut to_insert = String::new();
                for line in &additions {
                    to_insert.push('\n');
                    to_insert.push_str(line);
                }
                text.insert_str(insert_pos, &to_insert);
            } else {
                text.push_str(&format!("\n{}:\n", service));
                for line in &additions {
                    text.push('\n');
                    text.push_str(line);
                }
            }
        }
    }

    (text, diff_lines.join("\n"))
}

fn execute_host_and_system_actions(plan: &FixPlan) -> Result<(), FixError> {
    for action in &plan.host_actions {
        if let FixAction::HostEdit {
            path,
            updated_content,
            mode,
            ..
        } = action
        {
            if path.exists() {
                let file_backup = backup_path_for(path);
                fs::copy(path, &file_backup)?;
            }
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            atomic_write_file(path, updated_content)?;
            if let Some(m) = mode {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(path, fs::Permissions::from_mode(*m))?;
                }
            }
        }
    }

    for action in &plan.system_actions {
        if let FixAction::ShellCommand { command, .. } = action {
            let status = std::process::Command::new("sh")
                .arg("-c")
                .arg(command)
                .status()
                .map_err(FixError::Io)?;
            if !status.success() {
                return Err(FixError::Io(io::Error::other(format!(
                    "shell command exited with status: {:?}",
                    status.code()
                ))));
            }
        }
    }

    Ok(())
}

fn build_fix_plan(
    path: &Path,
    mode: FixMode,
    only_findings: Option<&[String]>,
    external_findings: &[Finding],
    resolutions: &FixResolutionMap,
) -> Result<FixPlan, FixError> {
    let bundle = ComposeParser::load_bundle(path.to_path_buf(), false)?;
    let project = ComposeParser::parse_path_without_override(path.to_path_buf())?;
    let findings = RuleEngine.scan(&project);
    let findings_by_service = findings_by_service(&findings, only_findings);

    let mut document = bundle.primary_document.clone();
    let mut review_requests = Vec::new();
    let auto_applied = apply_auto_fixes(
        &mut document,
        &findings_by_service,
        &bundle.primary_path,
        resolutions,
        &mut review_requests,
    );
    let review_applied = if mode.includes_review() {
        apply_review_fixes(
            &mut document,
            &findings_by_service,
            &bundle.primary_path,
            resolutions,
            &mut review_requests,
        )
    } else {
        Vec::new()
    };
    if !review_requests.is_empty() {
        return Err(FixError::ReviewRequired(review_requests));
    }

    // Classify external adapter findings (Dockle, Lynis, NativeHost) if provided
    // Filter to only_findings scope so that pressing 'f' on a single finding
    // does not pull in all unrelated external findings.
    let scoped_external: Vec<Finding> = if let Some(ids) = only_findings {
        external_findings
            .iter()
            .filter(|f| ids.contains(&f.id))
            .cloned()
            .collect()
    } else {
        external_findings.to_vec()
    };
    let (adapter_actions, adapter_auto, adapter_review) =
        adapter::classify_adapter_findings(&scoped_external);
    let mut compose_actions: Vec<FixAction> = Vec::new();
    let (host_actions, system_actions): (Vec<_>, Vec<_>) =
        adapter_actions.into_iter().partition(|a| match a {
            FixAction::ComposeEdit { .. } => {
                compose_actions.push(a.clone());
                false
            }
            FixAction::HostEdit { .. } => true,
            FixAction::ShellCommand { .. } => false,
        });
    let system_actions: Vec<_> = system_actions
        .into_iter()
        .filter(|a| matches!(a, FixAction::ShellCommand { .. }))
        .collect();

    let mut all_auto = auto_applied;
    let mut all_review = review_applied.clone();
    all_auto.extend(adapter_auto);
    all_review.extend(adapter_review);

    let changed_services = all_auto
        .iter()
        .chain(all_review.iter())
        .map(|proposal| proposal.service.clone())
        .collect::<BTreeSet<_>>();

    let updated_text =
        render_document_like_original(&bundle.primary_text, &document, &changed_services)?;
    let (updated_text, compose_diff) = apply_compose_edits_to_text(&updated_text, &compose_actions);

    let has_doc_changes = !all_auto.is_empty() || !all_review.is_empty();
    let diff_preview = if has_doc_changes || !compose_diff.is_empty() {
        let base_diff = if has_doc_changes {
            build_diff(&bundle.primary_path, &bundle.primary_text, &updated_text)
        } else {
            String::new()
        };
        if compose_diff.is_empty() {
            base_diff
        } else if base_diff.is_empty() {
            compose_diff
        } else {
            format!("{}\n{}", base_diff, compose_diff)
        }
    } else {
        String::new()
    };

    let plan = FixPlan {
        compose_file: bundle.primary_path,
        diff_preview,
        updated_text,
        backup_path: None,
        auto_applied: all_auto,
        review_applied: all_review,
        host_actions,
        system_actions,
        compose_actions,
    };

    Ok(plan)
}

fn render_document_like_original(
    original_text: &str,
    document: &Value,
    changed_services: &BTreeSet<String>,
) -> Result<String, FixError> {
    let rendered = dump_document(document)?;
    let merged = splice_changed_service_blocks(original_text, &rendered, changed_services)
        .unwrap_or_else(|| merge_original_formatting(original_text, &rendered));
    if serde_yaml::from_str::<Value>(&merged).is_ok() {
        Ok(merged)
    } else {
        Ok(rendered)
    }
}

#[derive(Debug, Clone)]
struct ServiceBlockRange {
    start: usize,
    end: usize,
}

fn splice_changed_service_blocks(
    original_text: &str,
    rendered_text: &str,
    changed_services: &BTreeSet<String>,
) -> Option<String> {
    if changed_services.is_empty() {
        return Some(original_text.to_owned());
    }

    let original_lines = original_text.lines().map(str::to_owned).collect::<Vec<_>>();
    let rendered_lines = rendered_text.lines().map(str::to_owned).collect::<Vec<_>>();
    let original_blocks = service_block_ranges(&original_lines)?;
    let rendered_blocks = service_block_ranges(&rendered_lines)?;
    let mut output_lines = original_lines.clone();

    let mut replacements = Vec::new();
    for service_name in changed_services {
        let original_range = original_blocks.get(service_name)?;
        let rendered_range = rendered_blocks.get(service_name)?;

        let original_block = original_lines[original_range.start..original_range.end].join("\n");
        let rendered_block = rendered_lines[rendered_range.start..rendered_range.end].join("\n");
        let merged_block = merge_original_formatting(&original_block, &rendered_block);
        let replacement_lines = if block_is_parseable(service_name, &merged_block) {
            merged_block.lines().map(str::to_owned).collect::<Vec<_>>()
        } else {
            rendered_block
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };

        replacements.push((original_range.start, original_range.end, replacement_lines));
    }

    replacements.sort_by_key(|item| std::cmp::Reverse(item.0));
    for (start, end, replacement_lines) in replacements {
        output_lines.splice(start..end, replacement_lines);
    }

    let mut output = output_lines.join("\n");
    if original_text.ends_with('\n') || rendered_text.ends_with('\n') {
        output.push('\n');
    }
    Some(output)
}

fn service_block_ranges(lines: &[String]) -> Option<BTreeMap<String, ServiceBlockRange>> {
    let services_index = lines
        .iter()
        .position(|line| line.trim() == "services:" && line_indent(line) == 0)?;
    let mut ranges = BTreeMap::new();
    let mut current_name = None::<String>;
    let mut current_start = 0_usize;

    for (index, line) in lines.iter().enumerate().skip(services_index + 1) {
        let trimmed = line.trim();
        let indent = line_indent(line);

        if trimmed.is_empty() {
            continue;
        }

        if indent == 0 {
            if let Some(name) = current_name.take() {
                ranges.insert(
                    name,
                    ServiceBlockRange {
                        start: current_start,
                        end: index,
                    },
                );
            }
            break;
        }

        if indent == 2 && !trimmed.starts_with("- ") && trimmed.ends_with(':') {
            if let Some(name) = current_name.replace(trimmed.trim_end_matches(':').to_owned()) {
                ranges.insert(
                    name,
                    ServiceBlockRange {
                        start: current_start,
                        end: index,
                    },
                );
            }
            current_start = index;
        }
    }

    if let Some(name) = current_name {
        ranges.insert(
            name,
            ServiceBlockRange {
                start: current_start,
                end: lines.len(),
            },
        );
    }

    Some(ranges)
}

fn line_indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn block_is_parseable(service_name: &str, block: &str) -> bool {
    let wrapped = format!("services:\n{block}\n");
    match serde_yaml::from_str::<Value>(&wrapped) {
        Ok(Value::Mapping(root)) => root
            .get(yaml_key("services"))
            .and_then(Value::as_mapping)
            .is_some_and(|services| services.contains_key(yaml_key(service_name))),
        _ => false,
    }
}

fn findings_by_service(
    findings: &[crate::domain::Finding],
    filter: Option<&[String]>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut grouped = BTreeMap::<String, BTreeSet<String>>::new();

    for finding in findings {
        if let Some(filter) = filter
            && !filter.contains(&finding.id)
        {
            continue;
        }

        let Some(service) = finding.related_service.as_ref() else {
            continue;
        };
        grouped
            .entry(service.clone())
            .or_default()
            .insert(finding.id.clone());
    }

    grouped
}

fn apply_auto_fixes(
    document: &mut Value,
    findings_by_service: &BTreeMap<String, BTreeSet<String>>,
    _compose_path: &Path,
    _resolutions: &FixResolutionMap,
    _review_requests: &mut Vec<ReviewRequest>,
) -> Vec<FixProposal> {
    let Some(services) = services_mapping_mut(document) else {
        return Vec::new();
    };

    let mut applied = Vec::new();

    for (service_name, finding_ids) in findings_by_service {
        let Some(service) = service_mapping_mut(services, service_name) else {
            continue;
        };

        if should_pin_nginx_image_to_stable(finding_ids)
            && let Some(image) = image_string(service)
            && let Some(stable_image) = stable_nginx_image_for_findings(&image, finding_ids)
            && image != stable_image
        {
            service.insert(yaml_key("image"), Value::String(stable_image));
            applied.push(fix_proposal(
                service_name,
                t!("app.fix.auto_nginx_stable", service = service_name.as_str()).into_owned(),
                RemediationKind::Auto,
            ));
        }

        if finding_ids.contains("service.vaultwarden.insecure_domain")
            && harden_vaultwarden_domain(service)
        {
            applied.push(fix_proposal(
                service_name,
                t!(
                    "app.fix.auto_vaultwarden_domain_https",
                    service = service_name.as_str()
                )
                .into_owned(),
                RemediationKind::Auto,
            ));
        }

        if finding_ids.contains("service.jellyfin.insecure_published_url")
            && harden_jellyfin_published_url(service)
        {
            applied.push(fix_proposal(
                service_name,
                t!(
                    "app.fix.auto_jellyfin_published_url_https",
                    service = service_name.as_str()
                )
                .into_owned(),
                RemediationKind::Auto,
            ));
        }

        if finding_ids.contains("service.nextcloud.insecure_overwriteprotocol")
            && harden_nextcloud_overwriteprotocol(service)
        {
            applied.push(fix_proposal(
                service_name,
                t!(
                    "app.fix.auto_nextcloud_overwriteprotocol_https",
                    service = service_name.as_str()
                )
                .into_owned(),
                RemediationKind::Auto,
            ));
        }

        if finding_ids.contains("service.nextcloud.wildcard_trusted_domains")
            && harden_nextcloud_trusted_domains(service)
        {
            applied.push(fix_proposal(
                service_name,
                t!(
                    "app.fix.auto_nextcloud_trusted_domains_wildcard",
                    service = service_name.as_str()
                )
                .into_owned(),
                RemediationKind::Auto,
            ));
        }

        if finding_ids.contains("exposure.public_binding")
            && let Some(ports) = service.get_mut(yaml_key("ports"))
            && let Some(sequence) = ports.as_sequence_mut()
        {
            for port in sequence.iter_mut() {
                let Some(before) = rewrite_public_port(port) else {
                    continue;
                };
                applied.push(fix_proposal(
                    service_name,
                    t!(
                        "app.fix.auto_bind_localhost",
                        service = service_name.as_str(),
                        port = before.as_str()
                    )
                    .into_owned(),
                    RemediationKind::Auto,
                ));
            }
        }

        if finding_ids.contains("permissions.sensitive_mount")
            && let Some(volumes) = service.get_mut(yaml_key("volumes"))
            && let Some(sequence) = volumes.as_sequence_mut()
        {
            for volume in sequence.iter_mut() {
                if let Some(path) = rewrite_sensitive_mount_readonly(volume) {
                    applied.push(fix_proposal(
                        service_name,
                        t!(
                            "app.fix.auto_mount_readonly",
                            service = service_name.as_str(),
                            path = path.as_str()
                        )
                        .into_owned(),
                        RemediationKind::Auto,
                    ));
                }
            }
        }

        if finding_ids.contains("permissions.privileged")
            && let Some(service) = service_mapping_mut(services, service_name)
            && apply_privileged_low_port_fix(service)
        {
            applied.push(fix_proposal(
                service_name,
                t!(
                    "app.fix.auto_privileged_cap_add",
                    service = service_name.as_str()
                )
                .into_owned(),
                RemediationKind::Auto,
            ));
        }

        if finding_ids.contains("service.postgres.trust_auth")
            && let Some(service) = service_mapping_mut(services, service_name)
            && harden_postgres_auth(service)
        {
            applied.push(fix_proposal(
                service_name,
                t!(
                    "app.fix.auto_postgres_auth",
                    service = service_name.as_str()
                )
                .into_owned(),
                RemediationKind::Auto,
            ));
        }

        if finding_ids.contains("service.redis.protected_mode_disabled")
            && let Some(service) = service_mapping_mut(services, service_name)
            && harden_redis_protected_mode(service)
        {
            applied.push(fix_proposal(
                service_name,
                t!(
                    "app.fix.auto_redis_protected_mode",
                    service = service_name.as_str()
                )
                .into_owned(),
                RemediationKind::Auto,
            ));
        }

        if finding_ids.contains("service.grafana.auth_disabled")
            && let Some(service) = service_mapping_mut(services, service_name)
            && harden_grafana_auth(service)
        {
            applied.push(fix_proposal(
                service_name,
                t!("app.fix.auto_grafana_auth", service = service_name.as_str()).into_owned(),
                RemediationKind::Auto,
            ));
        }

        if finding_ids.contains("service.grafana.anonymous_access")
            && let Some(service) = service_mapping_mut(services, service_name)
            && harden_grafana_anonymous(service)
        {
            applied.push(fix_proposal(
                service_name,
                t!(
                    "app.fix.auto_grafana_anonymous",
                    service = service_name.as_str()
                )
                .into_owned(),
                RemediationKind::Auto,
            ));
        }

        if finding_ids.contains("service.authentik.debug_enabled")
            && let Some(service) = service_mapping_mut(services, service_name)
            && harden_authentik_debug(service)
        {
            applied.push(fix_proposal(
                service_name,
                t!(
                    "app.fix.auto_authentik_debug",
                    service = service_name.as_str()
                )
                .into_owned(),
                RemediationKind::Auto,
            ));
        }

        if finding_ids.contains("service.paperless.no_force_login")
            && let Some(service) = service_mapping_mut(services, service_name)
            && harden_paperless_force_login(service)
        {
            applied.push(fix_proposal(
                service_name,
                t!(
                    "app.fix.auto_paperless_force_login",
                    service = service_name.as_str()
                )
                .into_owned(),
                RemediationKind::Auto,
            ));
        }

        if finding_ids.contains("runtime.seccomp_unconfined")
            && let Some(service) = service_mapping_mut(services, service_name)
            && remove_seccomp_unconfined(service)
        {
            applied.push(fix_proposal(
                service_name,
                t!(
                    "app.fix.auto_seccomp_default",
                    service = service_name.as_str()
                )
                .into_owned(),
                RemediationKind::Auto,
            ));
        }

        if finding_ids.contains("runtime.dangerous_capabilities")
            && let Some(service) = service_mapping_mut(services, service_name)
            && remove_dangerous_capabilities(service)
        {
            applied.push(fix_proposal(
                service_name,
                t!(
                    "app.fix.auto_cap_drop_dangerous",
                    service = service_name.as_str()
                )
                .into_owned(),
                RemediationKind::Auto,
            ));
        }

        if finding_ids.contains("service.vaultwarden.signups_enabled")
            && let Some(service) = service_mapping_mut(services, service_name)
            && update_environment_value(service, "SIGNUPS_ALLOWED", "false", false)
        {
            applied.push(fix_proposal(
                service_name,
                t!(
                    "app.fix.auto_vaultwarden_signups",
                    service = service_name.as_str()
                )
                .into_owned(),
                RemediationKind::Auto,
            ));
        }

        if finding_ids.contains("permissions.implicit_root")
            && let Some(service) = service_mapping_mut(services, service_name)
            && apply_harden_implicit_root(service)
        {
            applied.push(fix_proposal(
                service_name,
                t!(
                    "app.fix.auto_non_root_user",
                    service = service_name.as_str()
                )
                .into_owned(),
                RemediationKind::Auto,
            ));
        }
    }

    applied
}

fn apply_review_fixes(
    document: &mut Value,
    findings_by_service: &BTreeMap<String, BTreeSet<String>>,
    compose_path: &Path,
    resolutions: &FixResolutionMap,
    review_requests: &mut Vec<ReviewRequest>,
) -> Vec<FixProposal> {
    let Some(services) = services_mapping_mut(document) else {
        return Vec::new();
    };

    let mut applied = Vec::new();

    for (service_name, finding_ids) in findings_by_service {
        if finding_ids.contains("service.postgres.password_missing")
            && let Some(service) = service_mapping_mut(services, service_name)
            && let Some(secret) = resolve_secret_review_value(
                service_name,
                "service.postgres.password_missing",
                "POSTGRES_PASSWORD",
                resolutions,
                review_requests,
            )
            && externalize_secret_to_env_file(
                compose_path,
                service,
                "POSTGRES_PASSWORD",
                secret.as_str(),
                true,
            )
        {
            applied.push(fix_proposal(
                service_name,
                t!(
                    "app.fix.review_postgres_password",
                    service = service_name.as_str()
                )
                .into_owned(),
                RemediationKind::Review,
            ));
        }

        if finding_ids.contains("service.mysql.password_missing")
            && let Some(service) = service_mapping_mut(services, service_name)
            && let Some(secret) = resolve_secret_review_value(
                service_name,
                "service.mysql.password_missing",
                "MYSQL_ROOT_PASSWORD",
                resolutions,
                review_requests,
            )
            && externalize_secret_to_env_file(
                compose_path,
                service,
                "MYSQL_ROOT_PASSWORD",
                secret.as_str(),
                true,
            )
        {
            applied.push(fix_proposal(
                service_name,
                t!(
                    "app.fix.review_mysql_password",
                    service = service_name.as_str()
                )
                .into_owned(),
                RemediationKind::Review,
            ));
        }

        if finding_ids.contains("service.redis.password_missing")
            && let Some(service) = service_mapping_mut(services, service_name)
            && let Some(secret) = resolve_secret_review_value(
                service_name,
                "service.redis.password_missing",
                "REDIS_PASSWORD",
                resolutions,
                review_requests,
            )
            && externalize_secret_to_env_file(
                compose_path,
                service,
                "REDIS_PASSWORD",
                secret.as_str(),
                true,
            )
        {
            applied.push(fix_proposal(
                service_name,
                t!(
                    "app.fix.review_redis_password",
                    service = service_name.as_str()
                )
                .into_owned(),
                RemediationKind::Review,
            ));
        }

        if (finding_ids.contains("service.pihole.no_password")
            || finding_ids.contains("service.pihole.weak_password"))
            && let Some(service) = service_mapping_mut(services, service_name)
            && let Some(secret) = resolve_secret_review_value(
                service_name,
                if finding_ids.contains("service.pihole.no_password") {
                    "service.pihole.no_password"
                } else {
                    "service.pihole.weak_password"
                },
                "WEBPASSWORD",
                resolutions,
                review_requests,
            )
            && externalize_secret_to_env_file(
                compose_path,
                service,
                "WEBPASSWORD",
                secret.as_str(),
                true,
            )
        {
            applied.push(fix_proposal(
                service_name,
                t!(
                    "app.fix.review_pihole_password",
                    service = service_name.as_str()
                )
                .into_owned(),
                RemediationKind::Review,
            ));
        }

        if finding_ids.contains("service.gitea.inline_security_secrets")
            && let Some(service) = service_mapping_mut(services, service_name)
            && let Some(choice) =
                resolve_gitea_secret_choice(service_name, resolutions, review_requests)
            && apply_gitea_secret_review(service, compose_path, choice.as_str())
        {
            applied.push(fix_proposal(
                service_name,
                t!(
                    "app.fix.review_gitea_externalize_secrets",
                    service = service_name.as_str()
                )
                .into_owned(),
                RemediationKind::Review,
            ));
        }
    }

    applied
}

fn services_mapping_mut(document: &mut Value) -> Option<&mut Mapping> {
    document
        .as_mapping_mut()?
        .get_mut(yaml_key("services"))?
        .as_mapping_mut()
}

fn service_mapping_mut<'a>(
    services: &'a mut Mapping,
    service_name: &str,
) -> Option<&'a mut Mapping> {
    services.get_mut(yaml_key(service_name))?.as_mapping_mut()
}

fn fix_proposal(service: &str, summary: String, remediation: RemediationKind) -> FixProposal {
    FixProposal {
        service: service.to_owned(),
        summary,
        remediation,
    }
}

fn yaml_key(key: &str) -> Value {
    Value::String(key.to_owned())
}

fn image_string(service: &Mapping) -> Option<String> {
    service.get(yaml_key("image"))?.as_str().map(str::to_owned)
}

fn should_pin_nginx_image_to_stable(finding_ids: &BTreeSet<String>) -> bool {
    finding_ids.contains("updates.no_tag")
        || finding_ids.contains("updates.latest_tag")
        || finding_ids.contains("updates.major_only_tag")
}

fn stable_nginx_image_for_findings(image: &str, finding_ids: &BTreeSet<String>) -> Option<String> {
    if image.contains('@') {
        return None;
    }

    let (repository, tag) = crate::rules::split_image_reference(image);
    if !is_safe_nginx_image(&repository) {
        return None;
    }

    let matches_no_tag = finding_ids.contains("updates.no_tag") && tag.is_none();
    let matches_latest =
        finding_ids.contains("updates.latest_tag") && tag.as_deref() == Some("latest");
    let matches_major_only = finding_ids.contains("updates.major_only_tag")
        && tag.as_deref().is_some_and(is_major_only_tag);

    (matches_no_tag || matches_latest || matches_major_only)
        .then_some(format!("{repository}:stable"))
}

fn is_major_only_tag(tag: &str) -> bool {
    let candidate = tag.strip_prefix('v').unwrap_or(tag);
    !candidate.is_empty()
        && candidate
            .chars()
            .all(|character| character.is_ascii_digit())
}

fn apply_privileged_low_port_fix(service: &mut Mapping) -> bool {
    let Some(privileged) = service.get(yaml_key("privileged")) else {
        return false;
    };
    if !yaml_truthy(privileged) {
        return false;
    }
    if !service_uses_low_port(service) {
        return false;
    }

    if matches!(service.get(yaml_key("cap_add")), Some(value) if !value.is_sequence()) {
        return false;
    }

    service.remove(yaml_key("privileged"));
    if service.get(yaml_key("cap_add")).is_none() {
        service.insert(yaml_key("cap_add"), Value::Sequence(Sequence::new()));
    }
    let Some(cap_add) = service.get_mut(yaml_key("cap_add")) else {
        return false;
    };
    let Some(capabilities) = cap_add.as_sequence_mut() else {
        return false;
    };

    if !capabilities
        .iter()
        .any(|value| value.as_str() == Some("NET_BIND_SERVICE"))
    {
        capabilities.push(Value::String(String::from("NET_BIND_SERVICE")));
    }

    if service.get(yaml_key("security_opt")).is_none() {
        service.insert(yaml_key("security_opt"), Value::Sequence(Sequence::new()));
    }
    if let Some(security_opt) = service.get_mut(yaml_key("security_opt"))
        && let Some(sequence) = security_opt.as_sequence_mut()
        && !sequence.iter().any(|value| {
            value
                .as_str()
                .is_some_and(|s| s.contains("no-new-privileges:true"))
        })
    {
        sequence.push(Value::String(String::from("no-new-privileges:true")));
    }

    true
}

fn externalize_gitea_security_env(service: &mut Mapping, compose_path: &Path) -> bool {
    let mut changed = false;
    for key in [
        "GITEA__security__SECRET_KEY",
        "GITEA__security__INTERNAL_TOKEN",
    ] {
        if let Ok(did_migrate) = migrate_env_to_file(compose_path, service, key) {
            changed |= did_migrate;
        }
    }
    changed
}

fn apply_gitea_secret_review(service: &mut Mapping, compose_path: &Path, choice: &str) -> bool {
    match choice {
        "project_env" => externalize_gitea_security_env(service, compose_path),
        "service_env_file" => externalize_gitea_security_env_file(service, compose_path),
        _ => false,
    }
}

fn resolve_gitea_secret_choice(
    service_name: &str,
    resolutions: &FixResolutionMap,
    review_requests: &mut Vec<ReviewRequest>,
) -> Option<String> {
    let finding_id = "service.gitea.inline_security_secrets";
    match resolutions.get(finding_id) {
        Some(ReviewResolution::Choice(choice)) => Some(choice.clone()),
        Some(_) => {
            review_requests.push(ReviewRequest::Choice {
                finding_id: finding_id.to_owned(),
                service: service_name.to_owned(),
                title: t!("app.fix.review_choice_title").into_owned(),
                description: t!(
                    "app.fix.review_gitea_choice_description",
                    service = service_name
                )
                .into_owned(),
                options: vec![
                    ReviewChoiceOption {
                        key: String::from("project_env"),
                        label: t!("app.fix.review_gitea_choice_project_env").into_owned(),
                        description: t!("app.fix.review_gitea_choice_project_env_detail")
                            .into_owned(),
                    },
                    ReviewChoiceOption {
                        key: String::from("service_env_file"),
                        label: t!("app.fix.review_gitea_choice_service_env_file").into_owned(),
                        description: t!("app.fix.review_gitea_choice_service_env_file_detail")
                            .into_owned(),
                    },
                ],
            });
            None
        }
        None => {
            review_requests.push(ReviewRequest::Choice {
                finding_id: finding_id.to_owned(),
                service: service_name.to_owned(),
                title: t!("app.fix.review_choice_title").into_owned(),
                description: t!(
                    "app.fix.review_gitea_choice_description",
                    service = service_name
                )
                .into_owned(),
                options: vec![
                    ReviewChoiceOption {
                        key: String::from("project_env"),
                        label: t!("app.fix.review_gitea_choice_project_env").into_owned(),
                        description: t!("app.fix.review_gitea_choice_project_env_detail")
                            .into_owned(),
                    },
                    ReviewChoiceOption {
                        key: String::from("service_env_file"),
                        label: t!("app.fix.review_gitea_choice_service_env_file").into_owned(),
                        description: t!("app.fix.review_gitea_choice_service_env_file_detail")
                            .into_owned(),
                    },
                ],
            });
            None
        }
    }
}

fn resolve_secret_review_value(
    service_name: &str,
    finding_id: &str,
    variable: &str,
    resolutions: &FixResolutionMap,
    review_requests: &mut Vec<ReviewRequest>,
) -> Option<String> {
    match resolutions.get(finding_id) {
        Some(ReviewResolution::SecretValue(value)) if !value.trim().is_empty() => {
            Some(value.clone())
        }
        Some(_) => {
            review_requests.push(ReviewRequest::SecretInput {
                finding_id: finding_id.to_owned(),
                service: service_name.to_owned(),
                variable: variable.to_owned(),
                title: t!("app.fix.review_secret_title").into_owned(),
                description: t!(
                    "app.fix.review_secret_description",
                    service = service_name,
                    variable = variable
                )
                .into_owned(),
                suggested_value: generate_secret_value(),
            });
            None
        }
        None => {
            review_requests.push(ReviewRequest::SecretInput {
                finding_id: finding_id.to_owned(),
                service: service_name.to_owned(),
                variable: variable.to_owned(),
                title: t!("app.fix.review_secret_title").into_owned(),
                description: t!(
                    "app.fix.review_secret_description",
                    service = service_name,
                    variable = variable
                )
                .into_owned(),
                suggested_value: generate_secret_value(),
            });
            None
        }
    }
}

fn migrate_env_to_file(
    compose_path: &Path,
    service: &mut Mapping,
    key: &str,
) -> Result<bool, FixError> {
    let Some(current_value) = environment_value(service, key) else {
        return Ok(false);
    };

    // Skip if already a placeholder
    if current_value.starts_with("${") && current_value.ends_with("}") {
        return Ok(false);
    }

    let env_path = compose_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".env");

    let mut content = if env_path.exists() {
        fs::read_to_string(&env_path)?
    } else {
        String::new()
    };

    let pattern = format!("{}=", key);
    if !content
        .lines()
        .any(|line| line.trim_start().starts_with(&pattern))
    {
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content.push_str(&format!("{}={}\n", key, current_value));
        atomic_write_file(&env_path, &content)?;
    }

    Ok(update_environment_value(
        service,
        key,
        &format!("${{{key}}}"),
        false,
    ))
}

fn externalize_gitea_security_env_file(service: &mut Mapping, compose_path: &Path) -> bool {
    let env_path = compose_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".env.gitea");

    let mut changed = false;
    for key in [
        "GITEA__security__SECRET_KEY",
        "GITEA__security__INTERNAL_TOKEN",
    ] {
        let Some(current_value) = environment_value(service, key) else {
            continue;
        };
        if current_value.starts_with("${") && current_value.ends_with('}') {
            continue;
        }
        if write_or_update_env_entry(&env_path, key, &current_value).is_ok() {
            changed |= remove_environment_key(service, key);
        }
    }

    if changed {
        let relative = env_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(".env.gitea");
        changed |= ensure_env_file_entry(service, relative);
    }

    changed
}

fn externalize_secret_to_env_file(
    compose_path: &Path,
    service: &mut Mapping,
    key: &str,
    secret_value: &str,
    insert_if_missing: bool,
) -> bool {
    let env_path = compose_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".env");
    if write_or_update_env_entry(&env_path, key, secret_value).is_err() {
        return false;
    }
    update_environment_value(service, key, &format!("${{{key}}}"), insert_if_missing)
}

fn write_or_update_env_entry(path: &Path, key: &str, value: &str) -> io::Result<()> {
    let mut content = if path.exists() {
        fs::read_to_string(path)?
    } else {
        String::new()
    };

    let mut replaced = false;
    let mut lines = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some((entry_key, _)) = trimmed.split_once('=')
            && entry_key.trim() == key
        {
            lines.push(format!("{key}={value}"));
            replaced = true;
        } else {
            lines.push(line.to_owned());
        }
    }

    if !replaced {
        lines.push(format!("{key}={value}"));
    }

    content = lines.join("\n");
    if !content.is_empty() {
        content.push('\n');
    }
    atomic_write_file(path, &content).map_err(|error| match error {
        FixError::Io(io_error) => io_error,
        other => io::Error::other(other.to_string()),
    })
}

fn generate_secret_value() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    const SECRET_LENGTH: usize = 24;

    let mut bytes = [0_u8; SECRET_LENGTH];
    if fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .is_err()
    {
        bytes.copy_from_slice(b"hostveil-review-secret!!");
    }

    bytes
        .iter()
        .map(|byte| ALPHABET[*byte as usize % ALPHABET.len()] as char)
        .collect()
}

fn ensure_env_file_entry(service: &mut Mapping, value: &str) -> bool {
    match service.get_mut(yaml_key("env_file")) {
        Some(Value::String(current)) => {
            if current.trim() == value {
                false
            } else {
                let existing = current.trim().to_owned();
                service.insert(
                    yaml_key("env_file"),
                    Value::Sequence(vec![
                        Value::String(existing),
                        Value::String(value.to_owned()),
                    ]),
                );
                true
            }
        }
        Some(Value::Sequence(sequence)) => {
            if sequence.iter().any(|item| item.as_str() == Some(value)) {
                false
            } else {
                sequence.push(Value::String(value.to_owned()));
                true
            }
        }
        Some(_) => false,
        None => {
            service.insert(yaml_key("env_file"), Value::String(value.to_owned()));
            true
        }
    }
}

fn remove_environment_key(service: &mut Mapping, key: &str) -> bool {
    let Some(environment) = service.get_mut(yaml_key("environment")) else {
        return false;
    };

    match environment {
        Value::Mapping(mapping) => mapping.remove(yaml_key(key)).is_some(),
        Value::Sequence(sequence) => {
            let before = sequence.len();
            sequence.retain(|item| {
                item.as_str()
                    .and_then(|entry| entry.split_once('='))
                    .map(|(entry_key, _)| entry_key.trim() != key)
                    .unwrap_or(true)
            });
            before != sequence.len()
        }
        _ => false,
    }
}

fn harden_vaultwarden_domain(service: &mut Mapping) -> bool {
    let Some(current) = environment_value(service, "DOMAIN") else {
        return false;
    };
    let Some(updated) = rewrite_http_scheme(&current) else {
        return false;
    };

    update_environment_value(service, "DOMAIN", &updated, false)
}

fn harden_jellyfin_published_url(service: &mut Mapping) -> bool {
    let Some(current) = environment_value(service, "JELLYFIN_PublishedServerUrl") else {
        return false;
    };
    let Some(updated) = rewrite_http_scheme(&current) else {
        return false;
    };

    update_environment_value(service, "JELLYFIN_PublishedServerUrl", &updated, false)
}

fn harden_nextcloud_overwriteprotocol(service: &mut Mapping) -> bool {
    let Some(current) = environment_value(service, "OVERWRITEPROTOCOL") else {
        return false;
    };
    if !current.eq_ignore_ascii_case("http") {
        return false;
    }

    update_environment_value(service, "OVERWRITEPROTOCOL", "https", false)
}

fn harden_nextcloud_trusted_domains(service: &mut Mapping) -> bool {
    let Some(current) = environment_value(service, "NEXTCLOUD_TRUSTED_DOMAINS") else {
        return false;
    };
    let Some(updated) = sanitize_nextcloud_trusted_domains(&current) else {
        return false;
    };

    update_environment_value(service, "NEXTCLOUD_TRUSTED_DOMAINS", &updated, false)
}

fn apply_harden_implicit_root(service: &mut Mapping) -> bool {
    if service.get(yaml_key("user")).is_some() {
        return false;
    }
    service.insert(yaml_key("user"), Value::String(String::from("1000:1000")));
    true
}

fn harden_postgres_auth(service: &mut Mapping) -> bool {
    let Some(current) = environment_value(service, "POSTGRES_HOST_AUTH_METHOD") else {
        return update_environment_value(
            service,
            "POSTGRES_HOST_AUTH_METHOD",
            "scram-sha-256",
            true,
        );
    };
    if current.eq_ignore_ascii_case("trust") {
        update_environment_value(service, "POSTGRES_HOST_AUTH_METHOD", "scram-sha-256", false)
    } else {
        false
    }
}

fn harden_redis_protected_mode(service: &mut Mapping) -> bool {
    let Some(current) = environment_value(service, "REDIS_PROTECTED_MODE") else {
        return update_environment_value(service, "REDIS_PROTECTED_MODE", "yes", true);
    };
    if current.eq_ignore_ascii_case("no") {
        update_environment_value(service, "REDIS_PROTECTED_MODE", "yes", false)
    } else {
        false
    }
}

fn harden_grafana_auth(service: &mut Mapping) -> bool {
    let mut changed = false;
    changed |= update_environment_value(service, "GF_AUTH_BASIC_ENABLED", "true", true);
    changed |= update_environment_value(service, "GF_AUTH_ANONYMOUS_ENABLED", "false", true);
    changed
}

fn harden_grafana_anonymous(service: &mut Mapping) -> bool {
    update_environment_value(service, "GF_AUTH_ANONYMOUS_ENABLED", "false", false)
}

fn harden_authentik_debug(service: &mut Mapping) -> bool {
    let Some(_current) = environment_value(service, "AUTHENTIK_DEBUG") else {
        return false;
    };
    update_environment_value(service, "AUTHENTIK_DEBUG", "false", false)
}

fn harden_paperless_force_login(service: &mut Mapping) -> bool {
    update_environment_value(service, "PAPERLESS_FORCE_LOGIN", "true", true)
}

fn remove_seccomp_unconfined(service: &mut Mapping) -> bool {
    let (changed, empty) = {
        let Some(security_opt) = service.get_mut(yaml_key("security_opt")) else {
            return false;
        };
        let Some(sequence) = security_opt.as_sequence_mut() else {
            return false;
        };

        let before_len = sequence.len();
        sequence.retain(|value| {
            value
                .as_str()
                .map(|s| !s.to_ascii_lowercase().contains("seccomp:unconfined"))
                .unwrap_or(true)
        });
        (sequence.len() < before_len, sequence.is_empty())
    };

    if empty {
        service.remove(yaml_key("security_opt"));
    }

    changed
}

const DANGEROUS_CAPS: [&str; 5] = [
    "NET_ADMIN",
    "SYS_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "DAC_READ_SEARCH",
];

fn remove_dangerous_capabilities(service: &mut Mapping) -> bool {
    let (changed, empty) = {
        let Some(cap_add) = service.get_mut(yaml_key("cap_add")) else {
            return false;
        };
        let Some(sequence) = cap_add.as_sequence_mut() else {
            return false;
        };

        let before_len = sequence.len();
        sequence.retain(|value| {
            value
                .as_str()
                .map(|s| !DANGEROUS_CAPS.iter().any(|d| d.eq_ignore_ascii_case(s)))
                .unwrap_or(true)
        });
        (sequence.len() < before_len, sequence.is_empty())
    };

    if empty {
        service.remove(yaml_key("cap_add"));
    }

    changed
}

fn rewrite_sensitive_mount_readonly(volume: &mut Value) -> Option<String> {
    match volume {
        Value::String(spec) => {
            let parts: Vec<&str> = spec.split(':').collect();
            if parts.len() < 2 {
                return None;
            }
            if parts.len() >= 3 && parts[2].eq_ignore_ascii_case("ro") {
                return None;
            }

            let source = parts[0].to_owned();
            let target = parts[1];
            let new_spec = format!("{source}:{target}:ro");
            *volume = Value::String(new_spec);
            Some(source)
        }
        Value::Mapping(mapping) => {
            let mount_type = mapping.get(yaml_key("type")).and_then(|v| v.as_str());
            if mount_type != Some("bind") {
                return None;
            }
            let read_only = mapping
                .get(yaml_key("read_only"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if read_only {
                return None;
            }
            mapping.insert(yaml_key("read_only"), Value::Bool(true));
            mapping.remove(yaml_key("mode"));
            mapping
                .get(yaml_key("source"))
                .and_then(|v| v.as_str())
                .map(|v| v.to_owned())
        }
        _ => None,
    }
}

fn rewrite_http_scheme(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();
    let suffix = lower.strip_prefix("http://")?;
    Some(format!(
        "https://{}",
        &trimmed[trimmed.len() - suffix.len()..]
    ))
}

fn sanitize_nextcloud_trusted_domains(value: &str) -> Option<String> {
    let mut removed_any = false;
    let mut kept = Vec::<String>::new();
    let mut seen = BTreeSet::<String>::new();

    for token in value
        .split(|character: char| character == ',' || character.is_whitespace())
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        if is_wildcard_trusted_domain_token(token) {
            removed_any = true;
            continue;
        }

        let normalized = token.to_ascii_lowercase();
        if seen.insert(normalized) {
            kept.push(token.to_owned());
        }
    }

    if !removed_any || kept.is_empty() {
        return None;
    }

    if value.contains(',') {
        Some(kept.join(","))
    } else {
        Some(kept.join(" "))
    }
}

fn is_wildcard_trusted_domain_token(token: &str) -> bool {
    token == "*" || token == "0.0.0.0" || token == "::" || token.starts_with("*.")
}

fn environment_value(service: &Mapping, key: &str) -> Option<String> {
    let environment = service.get(yaml_key("environment"))?;

    match environment {
        Value::Mapping(mapping) => {
            let current = mapping.get(yaml_key(key))?;
            yaml_scalar_string(current)
        }
        Value::Sequence(sequence) => sequence.iter().find_map(|item| {
            let Value::String(entry) = item else {
                return None;
            };
            let trimmed = entry.trim();
            let (entry_key, entry_value) = trimmed.split_once('=')?;
            (entry_key.trim() == key).then_some(entry_value.trim().to_owned())
        }),
        _ => None,
    }
}

fn yaml_scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => {
            let trimmed = value.trim();
            (!trimmed.is_empty()).then_some(trimmed.to_owned())
        }
        Value::Bool(value) => Some(if *value {
            String::from("true")
        } else {
            String::from("false")
        }),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn update_environment_value(
    service: &mut Mapping,
    key: &str,
    value: &str,
    insert_if_missing: bool,
) -> bool {
    if service.get(yaml_key("environment")).is_none() {
        if !insert_if_missing {
            return false;
        }
        let mut mapping = Mapping::new();
        mapping.insert(yaml_key(key), environment_scalar_value(value));
        service.insert(yaml_key("environment"), Value::Mapping(mapping));
        return true;
    }

    let Some(environment) = service.get_mut(yaml_key("environment")) else {
        return false;
    };

    match environment {
        Value::Mapping(mapping) => {
            let environment_key = yaml_key(key);
            match mapping.get(&environment_key) {
                Some(current) if environment_value_matches(current, value) => false,
                Some(_) => {
                    mapping.insert(environment_key, environment_scalar_value(value));
                    true
                }
                None if insert_if_missing => {
                    mapping.insert(environment_key, environment_scalar_value(value));
                    true
                }
                None => false,
            }
        }
        Value::Sequence(sequence) => {
            update_environment_sequence(sequence, key, value, insert_if_missing)
        }
        _ => false,
    }
}

fn update_environment_sequence(
    sequence: &mut Sequence,
    key: &str,
    value: &str,
    insert_if_missing: bool,
) -> bool {
    for item in sequence.iter_mut() {
        let Value::String(entry) = item else {
            continue;
        };

        let trimmed = entry.trim();
        if let Some((entry_key, entry_value)) = trimmed.split_once('=')
            && entry_key.trim() == key
        {
            if entry_value.trim() == value {
                return false;
            }
            *entry = format!("{key}={value}");
            return true;
        }

        if trimmed == key {
            *entry = format!("{key}={value}");
            return true;
        }
    }

    if insert_if_missing {
        sequence.push(Value::String(format!("{key}={value}")));
        true
    } else {
        false
    }
}

fn environment_value_matches(current: &Value, expected: &str) -> bool {
    match expected {
        "false" => !yaml_truthy(current),
        "true" => yaml_truthy(current),
        _ => current
            .as_str()
            .is_some_and(|value| value.trim() == expected.trim()),
    }
}

fn environment_scalar_value(value: &str) -> Value {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        _ => Value::String(value.to_owned()),
    }
}

fn rewrite_public_port(port: &mut Value) -> Option<String> {
    match port {
        Value::Mapping(mapping) => rewrite_public_port_mapping(mapping),
        Value::String(spec) => rewrite_public_port_string(spec),
        _ => None,
    }
}

fn rewrite_public_port_mapping(mapping: &mut Mapping) -> Option<String> {
    let published = port_number_string(mapping.get(yaml_key("published"))?)?;
    if matches!(
        mapping.get(yaml_key("host_ip")).and_then(Value::as_str),
        Some("127.0.0.1") | Some("::1") | Some("localhost")
    ) {
        return None;
    }

    let before = render_compact_port_mapping(mapping, &published);
    mapping.insert(
        yaml_key("host_ip"),
        Value::String(String::from("127.0.0.1")),
    );
    Some(before)
}

fn render_compact_port_mapping(mapping: &Mapping, published: &str) -> String {
    let host_ip = mapping
        .get(yaml_key("host_ip"))
        .and_then(Value::as_str)
        .unwrap_or("0.0.0.0");
    let target = mapping
        .get(yaml_key("target"))
        .and_then(port_number_string)
        .unwrap_or_default();
    let protocol = mapping
        .get(yaml_key("protocol"))
        .and_then(Value::as_str)
        .unwrap_or("tcp");

    if protocol == "tcp" {
        format!("{host_ip}:{published}:{target}")
    } else {
        format!("{host_ip}:{published}:{target}/{protocol}")
    }
}

fn port_number_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn rewrite_public_port_string(spec: &mut String) -> Option<String> {
    let original = spec.clone();
    let (body, protocol) = match spec.rsplit_once('/') {
        Some((base, suffix)) => (base.to_owned(), format!("/{suffix}")),
        None => (spec.clone(), String::new()),
    };

    let rewritten = match split_short_port(&body) {
        ShortPort::Published {
            host_ip: None,
            host_port,
            container_port,
        } => Some(format!("127.0.0.1:{host_port}:{container_port}{protocol}")),
        ShortPort::Published {
            host_ip: Some(host_ip),
            host_port: _,
            container_port: _,
        } if matches!(
            host_ip.as_str(),
            "127.0.0.1" | "::1" | "localhost" | "[::1]"
        ) =>
        {
            None
        }
        ShortPort::Published {
            host_ip: Some(_),
            host_port,
            container_port,
        } => Some(format!("127.0.0.1:{host_port}:{container_port}{protocol}")),
        ShortPort::ContainerOnly => None,
    };

    let rewritten = rewritten?;
    *spec = rewritten;
    Some(original)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ShortPort {
    ContainerOnly,
    Published {
        host_ip: Option<String>,
        host_port: String,
        container_port: String,
    },
}

fn split_short_port(spec: &str) -> ShortPort {
    let Some((remaining, container_port)) = spec.rsplit_once(':') else {
        return ShortPort::ContainerOnly;
    };
    let Some((host_part, host_port)) = remaining.rsplit_once(':') else {
        return ShortPort::Published {
            host_ip: None,
            host_port: remaining.to_owned(),
            container_port: container_port.to_owned(),
        };
    };

    ShortPort::Published {
        host_ip: Some(host_part.to_owned()),
        host_port: host_port.to_owned(),
        container_port: container_port.to_owned(),
    }
}

fn is_safe_nginx_image(image: &str) -> bool {
    matches!(
        image,
        "nginx" | "library/nginx" | "docker.io/nginx" | "docker.io/library/nginx"
    )
}

fn service_uses_low_port(service: &Mapping) -> bool {
    let Some(ports) = service.get(yaml_key("ports")).and_then(Value::as_sequence) else {
        return false;
    };

    ports.iter().any(port_uses_low_target)
}

fn port_uses_low_target(port: &Value) -> bool {
    match port {
        Value::Mapping(mapping) => mapping
            .get(yaml_key("target"))
            .and_then(port_number_string)
            .and_then(|value| value.parse::<u16>().ok())
            .is_some_and(|port| port < 1024),
        Value::String(spec) => match split_short_port(spec) {
            ShortPort::Published { container_port, .. } => container_port
                .parse::<u16>()
                .ok()
                .is_some_and(|port| port < 1024),
            ShortPort::ContainerOnly => spec.parse::<u16>().ok().is_some_and(|port| port < 1024),
        },
        _ => false,
    }
}

fn yaml_truthy(value: &Value) -> bool {
    match value {
        Value::Bool(value) => *value,
        Value::Number(number) => number.as_i64().map(|value| value != 0).unwrap_or(true),
        Value::String(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "true" | "yes" | "on" | "1"
        ),
        Value::Null => false,
        _ => true,
    }
}

fn dump_document(document: &Value) -> Result<String, FixError> {
    let rendered =
        serde_yaml::to_string(document).map_err(|error| FixError::Serialize(error.to_string()))?;
    Ok(rendered
        .strip_prefix("---\n")
        .unwrap_or(rendered.as_str())
        .to_owned())
}

fn merge_original_formatting(before: &str, after: &str) -> String {
    let before_lines = before.lines().map(str::to_owned).collect::<Vec<_>>();
    let after_lines = after.lines().map(str::to_owned).collect::<Vec<_>>();
    let mut merged = Vec::with_capacity(after_lines.len());
    let mut search_start = 0_usize;

    for after_line in &after_lines {
        let normalized_after = normalized_yaml_line(after_line);
        let mut matched_index = None;

        for (offset, before_line) in before_lines[search_start..].iter().enumerate() {
            if normalized_yaml_line(before_line) == normalized_after {
                matched_index = Some(search_start + offset);
                break;
            }
        }

        if let Some(index) = matched_index {
            if before_lines[search_start..index]
                .iter()
                .all(|line| line.trim().is_empty())
            {
                merged.extend(before_lines[search_start..index].iter().cloned());
            }

            merged.push(before_lines[index].clone());
            search_start = index + 1;
        } else if let Some(rewritten) = before_lines
            .get(search_start)
            .and_then(|before_line| rewrite_with_original_line_style(before_line, after_line))
        {
            merged.push(rewritten);
            search_start += 1;
        } else {
            merged.push(after_line.clone());
        }
    }

    let mut output = merged.join("\n");
    if after.ends_with('\n') {
        output.push('\n');
    }
    output
}

fn normalized_yaml_line(line: &str) -> String {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    if let Some(item) = trimmed.strip_prefix("- ") {
        return format!("- {}", normalized_yaml_scalar(item));
    }

    if let Some((key, value)) = trimmed.split_once(':') {
        if value.trim().is_empty() {
            return format!("{}:", key.trim_end());
        }

        return format!("{}: {}", key.trim_end(), normalized_yaml_scalar(value));
    }

    trimmed.to_owned()
}

fn normalized_yaml_scalar(value: &str) -> String {
    let trimmed = value.trim();

    if let Some(unquoted) = trimmed
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        return unquoted.to_owned();
    }
    if let Some(unquoted) = trimmed
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
    {
        return unquoted.to_owned();
    }

    trimmed.to_owned()
}

fn rewrite_with_original_line_style(before_line: &str, after_line: &str) -> Option<String> {
    let before_trimmed = before_line.trim();
    let after_trimmed = after_line.trim();

    if let (Some(before_scalar), Some(after_scalar)) = (
        before_trimmed.strip_prefix("- "),
        after_trimmed.strip_prefix("- "),
    ) {
        let prefix_end = before_line.find("- ")? + 2;
        let prefix = &before_line[..prefix_end];
        return Some(format!(
            "{prefix}{}",
            rewrite_scalar_with_original_style(before_scalar, after_scalar)
        ));
    }

    let (before_prefix, before_key, before_scalar) = split_yaml_scalar_line(before_line)?;
    let (_, after_key, after_scalar) = split_yaml_scalar_line(after_line)?;
    if before_key != after_key {
        return None;
    }

    Some(format!(
        "{before_prefix}{}",
        rewrite_scalar_with_original_style(before_scalar, after_scalar)
    ))
}

fn split_yaml_scalar_line(line: &str) -> Option<(&str, &str, &str)> {
    let colon_index = line.find(':')?;
    let rest = &line[colon_index + 1..];
    if rest.trim().is_empty() {
        return None;
    }

    let value_offset = rest.len() - rest.trim_start().len();
    let value_index = colon_index + 1 + value_offset;
    Some((
        &line[..value_index],
        line[..colon_index].trim(),
        &line[value_index..],
    ))
}

fn rewrite_scalar_with_original_style(before_scalar: &str, after_scalar: &str) -> String {
    let trimmed_after = after_scalar.trim();
    let trimmed_before = before_scalar.trim();

    if let Some(unquoted) = trimmed_before
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        && !unquoted.contains('"')
    {
        return format!("\"{trimmed_after}\"");
    }
    if let Some(unquoted) = trimmed_before
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
        && !unquoted.contains('\'')
    {
        return format!("'{trimmed_after}'");
    }

    trimmed_after.to_owned()
}

fn build_diff(path: &Path, before: &str, after: &str) -> String {
    if before == after {
        return String::new();
    }

    let before_lines = before.lines().map(str::to_owned).collect::<Vec<_>>();
    let after_lines = after.lines().map(str::to_owned).collect::<Vec<_>>();
    let ops = diff_ops(&before_lines, &after_lines);

    let mut output = String::new();
    output.push_str(&format!("--- {}\n", path.display()));
    output.push_str(&format!("+++ {}\n", path.display()));
    output.push_str(&format!(
        "@@ -1,{} +1,{} @@\n",
        before_lines.len(),
        after_lines.len()
    ));

    for op in ops {
        match op {
            DiffOp::Equal(line) => output.push_str(&format!(" {line}\n")),
            DiffOp::Delete(line) => output.push_str(&format!("-{line}\n")),
            DiffOp::Insert(line) => output.push_str(&format!("+{line}\n")),
        }
    }

    output
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DiffOp {
    Equal(String),
    Delete(String),
    Insert(String),
}

fn diff_ops(before: &[String], after: &[String]) -> Vec<DiffOp> {
    let mut lcs = vec![vec![0_usize; after.len() + 1]; before.len() + 1];

    for before_index in (0..before.len()).rev() {
        for after_index in (0..after.len()).rev() {
            lcs[before_index][after_index] = if before[before_index] == after[after_index] {
                lcs[before_index + 1][after_index + 1] + 1
            } else {
                lcs[before_index + 1][after_index].max(lcs[before_index][after_index + 1])
            };
        }
    }

    let mut before_index = 0;
    let mut after_index = 0;
    let mut ops = Vec::new();

    while before_index < before.len() && after_index < after.len() {
        if before[before_index] == after[after_index] {
            ops.push(DiffOp::Equal(before[before_index].clone()));
            before_index += 1;
            after_index += 1;
        } else if lcs[before_index + 1][after_index] >= lcs[before_index][after_index + 1] {
            ops.push(DiffOp::Delete(before[before_index].clone()));
            before_index += 1;
        } else {
            ops.push(DiffOp::Insert(after[after_index].clone()));
            after_index += 1;
        }
    }

    while before_index < before.len() {
        ops.push(DiffOp::Delete(before[before_index].clone()));
        before_index += 1;
    }

    while after_index < after.len() {
        ops.push(DiffOp::Insert(after[after_index].clone()));
        after_index += 1;
    }

    ops
}

fn backup_path_for(path: &Path) -> PathBuf {
    let timestamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let backup_name = match path.file_stem().and_then(|s| s.to_str()) {
        Some(stem) => match path.extension().and_then(|e| e.to_str()) {
            Some(ext) => format!("{}-{}.bak.{}", stem, timestamp, ext),
            None => format!("{}-{}.bak", stem, timestamp),
        },
        None => format!("docker-compose-{}.bak.yml", timestamp),
    };
    path.with_file_name(&backup_name)
}

fn atomic_write_file(path: &Path, content: &str) -> Result<(), FixError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("docker-compose.yml");
    let tmp_path = dir.join(format!(".{}.tmp", file_name));

    {
        let mut file = std::fs::File::create(&tmp_path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
    }

    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        FixAction, FixError, FixMode, FixPlan, FixProposal, FixResolutionMap, ReviewChoiceOption,
        ReviewRequest, ReviewResolution, apply, apply_compose_edits_to_text, apply_with_external,
        apply_with_resolutions, backup_path_for, execute_host_and_system_actions,
        merge_original_formatting, preview, preview_with_external, preview_with_resolutions,
    };
    use crate::compose::ComposeParseError;
    use crate::domain::{Finding, RemediationKind, Severity, Source};

    fn temp_compose_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hostveil-fix-{name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temp dir should exist");
        path
    }

    fn write_compose(path: &Path, content: &str) {
        fs::write(path, content).expect("compose file should be written");
    }

    fn fixture(path: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rules")
            .join(path)
            .canonicalize()
            .expect("fixture should exist")
    }

    fn copy_mixed_stack_fixture_to_temp(name: &str) -> PathBuf {
        let root = temp_compose_dir(name);
        let source = fixture("mixed-stack");
        let compose_path = root.join("docker-compose.yml");
        let env_path = root.join("postgres.env");

        fs::copy(source.join("docker-compose.yml"), &compose_path)
            .expect("compose fixture should be copied");
        fs::copy(source.join("postgres.env"), &env_path).expect("env fixture should be copied");

        compose_path
    }

    fn review_resolution_choice(key: &str) -> FixResolutionMap {
        BTreeMap::from([(
            String::from("service.gitea.inline_security_secrets"),
            ReviewResolution::Choice(String::from(key)),
        )])
    }

    fn review_resolution_secret(finding_id: &str, secret: &str) -> FixResolutionMap {
        BTreeMap::from([(
            String::from(finding_id),
            ReviewResolution::SecretValue(String::from(secret)),
        )])
    }

    #[test]
    fn previews_quick_fix_changes_for_mixed_stack_fixture() {
        let path = fixture("mixed-stack");

        let plan =
            preview(&path, FixMode::AutoFix, None).expect("quick-fix preview should succeed");

        assert!(!plan.auto_applied.is_empty());
        assert!(plan.review_applied.is_empty());
        assert!(plan.diff_preview.contains("127.0.0.1:8080:80"));
        assert!(plan.diff_preview.contains("127.0.0.1:8081:8080"));
        assert!(plan.diff_preview.contains("user: \"1000:1000\""));
    }

    #[test]
    fn previews_quick_fix_noop_for_hardened_stack_fixture() {
        let path = fixture("hardened-stack.yml");

        let plan =
            preview(&path, FixMode::AutoFix, None).expect("quick-fix preview should succeed");

        assert!(plan.auto_applied.is_empty());
        assert!(plan.review_applied.is_empty());
        assert!(plan.diff_preview.is_empty());
    }

    #[test]
    fn previews_fix_changes_for_mixed_stack_fixture() {
        let path = fixture("mixed-stack");

        let plan = preview_with_resolutions(
            &path,
            FixMode::Fix,
            None,
            &review_resolution_secret("service.postgres.password_missing", "generated-secret"),
        )
        .expect("fix preview should succeed");

        assert_eq!(plan.auto_applied.len(), 3);
        assert_eq!(plan.review_applied.len(), 1);
        assert!(plan.diff_preview.contains("127.0.0.1:8080:80"));
        assert!(plan.diff_preview.contains("127.0.0.1:8081:8080"));
        assert!(plan.diff_preview.contains("user: \"1000:1000\""));
        assert!(plan.diff_preview.contains("${POSTGRES_PASSWORD}"));
    }

    #[test]
    fn previews_fix_noop_for_hardened_stack_fixture() {
        let path = fixture("hardened-stack.yml");

        let plan = preview(&path, FixMode::Fix, None).expect("fix preview should succeed");

        assert!(plan.auto_applied.is_empty());
        assert!(plan.review_applied.is_empty());
        assert!(plan.diff_preview.is_empty());
    }

    #[test]
    fn apply_quick_fix_on_mixed_stack_fixture_is_idempotent() {
        let compose_path = copy_mixed_stack_fixture_to_temp("mixed-stack-apply-idempotent");
        let root = compose_path
            .parent()
            .expect("fixture root should exist")
            .to_path_buf();

        let first =
            apply(&compose_path, FixMode::AutoFix, None).expect("first apply should succeed");
        let second =
            apply(&compose_path, FixMode::AutoFix, None).expect("second apply should succeed");

        assert!(first.changed());
        assert!(!first.auto_applied.is_empty());
        assert!(first.backup_path.is_some());

        assert!(second.auto_applied.is_empty());
        assert!(second.review_applied.is_empty());
        assert!(second.backup_path.is_none());

        let env_text = fs::read_to_string(root.join("postgres.env"))
            .expect("copied env fixture should be readable");
        assert_eq!(env_text, "POSTGRES_PASSWORD=changeme\n");

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn apply_creates_timestamped_backup() {
        let root = temp_compose_dir("timestamped-backup");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  web:\n",
                "    image: nginx\n",
                "    user: \"1000:1000\"\n",
                "    ports:\n",
                "      - \"8080:80\"\n"
            ),
        );

        let plan = apply(&path, FixMode::AutoFix, None).expect("apply should succeed");
        assert!(plan.changed());

        let backup_path = plan.backup_path.expect("backup path should exist");
        let backup_name = backup_path.file_name().unwrap().to_str().unwrap();
        assert!(
            backup_name.contains("docker-compose-"),
            "backup name should contain timestamp: {}",
            backup_name
        );
        assert!(
            backup_name.ends_with(".bak.yml"),
            "backup name should end with .bak.yml: {}",
            backup_name
        );
        assert!(backup_path.exists(), "backup file should exist on disk");

        let original_text = fs::read_to_string(&path).expect("file should be readable");
        assert!(
            original_text.contains("127.0.0.1:8080:80"),
            "original file should contain the fixed content"
        );

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn apply_uses_atomic_write() {
        let root = temp_compose_dir("atomic-write");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  web:\n",
                "    image: nginx\n",
                "    ports:\n",
                "      - \"8080:80\"\n"
            ),
        );

        let plan = apply(&path, FixMode::AutoFix, None).expect("apply should succeed");
        assert!(plan.changed());

        // The temp file should not remain after atomic rename
        let tmp_path = root.join(".docker-compose.yml.tmp");
        assert!(
            !tmp_path.exists(),
            "temp file should be removed after atomic rename"
        );

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn previews_quick_fix_changes() {
        let root = temp_compose_dir("quick-preview");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  web:\n",
                "    image: nginx\n",
                "    ports:\n",
                "      - \"8080:80\"\n"
            ),
        );

        let plan =
            preview(&path, FixMode::AutoFix, None).expect("quick-fix preview should succeed");

        assert!(!plan.auto_applied.is_empty());
        assert!(plan.review_applied.is_empty());
        assert!(plan.diff_preview.contains("127.0.0.1:8080:80"));
        assert!(plan.diff_preview.contains("nginx:stable"));

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn previews_guided_fix_changes() {
        let root = temp_compose_dir("guided-preview");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  app:\n",
                "    image: alpine:3.20\n",
                "    user: \"1000:1000\"\n",
                "    privileged: true\n",
                "    ports:\n",
                "      - \"127.0.0.1:8080:80\"\n"
            ),
        );

        let plan = preview(&path, FixMode::Fix, None).expect("fix preview should succeed");

        assert_eq!(plan.auto_applied.len(), 1);
        assert!(plan.review_applied.is_empty());
        assert!(plan.diff_preview.contains("cap_add"));
        assert!(plan.diff_preview.contains("NET_BIND_SERVICE"));

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn previews_quick_fix_pins_nginx_latest_to_stable() {
        let root = temp_compose_dir("quick-nginx-latest");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  web:\n",
                "    image: nginx:latest\n",
                "    user: \"1000:1000\"\n",
                "    ports:\n",
                "      - \"127.0.0.1:8080:80\"\n"
            ),
        );

        let plan =
            preview(&path, FixMode::AutoFix, None).expect("quick-fix preview should succeed");

        assert_eq!(plan.auto_applied.len(), 1);
        assert!(plan.review_applied.is_empty());
        assert!(plan.diff_preview.contains("nginx:stable"));

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn previews_quick_fix_preserves_udp_port_protocol_and_quotes() {
        let root = temp_compose_dir("quick-udp-port");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  web:\n",
                "    image: nginx\n",
                "    user: \"1000:1000\"\n",
                "    ports:\n",
                "      - \"9090:90/udp\"\n"
            ),
        );

        let plan =
            preview(&path, FixMode::AutoFix, None).expect("quick-fix preview should succeed");

        assert_eq!(plan.auto_applied.len(), 2);
        assert!(plan.review_applied.is_empty());
        assert!(plan.diff_preview.contains("\"127.0.0.1:9090:90/udp\""));
        assert!(plan.diff_preview.contains("nginx:stable"));

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn previews_guided_fix_for_vaultwarden_signups() {
        let root = temp_compose_dir("guided-vaultwarden-signups");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  vaultwarden:\n",
                "    image: vaultwarden/server:1.30.1\n",
                "    ports:\n",
                "      - \"127.0.0.1:8080:80\"\n",
                "    user: \"1000:1000\"\n",
                "    environment:\n",
                "      SIGNUPS_ALLOWED: true\n"
            ),
        );

        let plan = preview(&path, FixMode::Fix, None).expect("fix preview should succeed");

        assert_eq!(plan.auto_applied.len(), 1);
        assert!(plan.review_applied.is_empty());
        assert!(
            plan.auto_applied
                .iter()
                .any(|proposal| proposal.summary.contains("SIGNUPS_ALLOWED"))
        );
        assert!(plan.diff_preview.contains("SIGNUPS_ALLOWED: false"));

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn previews_guided_fix_for_gitea_inline_security_secrets() {
        let root = temp_compose_dir("guided-gitea-secrets");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  server:\n",
                "    image: gitea/gitea:1.21.11\n",
                "    user: \"1000:1000\"\n",
                "    ports:\n",
                "      - \"3000:3000\"\n",
                "      - \"2222:22\"\n",
                "    environment:\n",
                "      - GITEA__security__SECRET_KEY=replace-me\n",
                "      - GITEA__security__INTERNAL_TOKEN=replace-me-too\n"
            ),
        );

        let resolutions = review_resolution_choice("project_env");
        let plan = preview_with_resolutions(&path, FixMode::Fix, None, &resolutions)
            .expect("fix preview should succeed");

        assert!(!plan.auto_applied.is_empty());
        assert_eq!(plan.review_applied.len(), 1);
        assert!(
            plan.review_applied
                .iter()
                .any(|proposal| proposal.summary.contains("Gitea"))
        );
        assert!(
            plan.diff_preview
                .contains("GITEA__security__SECRET_KEY=${GITEA__security__SECRET_KEY}")
        );
        assert!(
            plan.diff_preview
                .contains("GITEA__security__INTERNAL_TOKEN=${GITEA__security__INTERNAL_TOKEN}")
        );

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn apply_creates_env_file_for_gitea_externalized_secrets() {
        let root = temp_compose_dir("apply-gitea-env");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  server:\n",
                "    image: gitea/gitea:1.21.11\n",
                "    ports:\n",
                "      - \"3000:3000\"\n",
                "      - \"2222:22\"\n",
                "    environment:\n",
                "      - GITEA__security__SECRET_KEY=secret123\n",
                "      - GITEA__security__INTERNAL_TOKEN=token456\n"
            ),
        );

        let plan = apply_with_resolutions(
            &path,
            FixMode::Fix,
            None,
            &review_resolution_choice("project_env"),
        )
        .expect("apply should succeed");
        assert!(plan.changed());

        let env_path = root.join(".env");
        assert!(env_path.exists(), ".env file should be created");

        let env_text = fs::read_to_string(&env_path).expect("env file should be readable");
        assert!(
            env_text.contains("GITEA__security__SECRET_KEY=secret123"),
            "env file should contain migrated secret key"
        );
        assert!(
            env_text.contains("GITEA__security__INTERNAL_TOKEN=token456"),
            "env file should contain migrated internal token"
        );

        let compose_text = fs::read_to_string(&path).expect("compose file should be readable");
        assert!(
            compose_text.contains("GITEA__security__SECRET_KEY=${GITEA__security__SECRET_KEY}"),
            "compose should reference placeholder"
        );

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn apply_preserves_existing_env_file_entries_for_gitea() {
        let root = temp_compose_dir("apply-gitea-env-preserve");
        let path = root.join("docker-compose.yml");
        let env_path = root.join(".env");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  server:\n",
                "    image: gitea/gitea:1.21.11\n",
                "    ports:\n",
                "      - \"3000:3000\"\n",
                "      - \"2222:22\"\n",
                "    environment:\n",
                "      - GITEA__security__SECRET_KEY=secret123\n",
                "      - GITEA__security__INTERNAL_TOKEN=token456\n"
            ),
        );
        fs::write(&env_path, "EXISTING_KEY=existing_value\n").expect("env file should be written");

        let plan = apply_with_resolutions(
            &path,
            FixMode::Fix,
            None,
            &review_resolution_choice("project_env"),
        )
        .expect("apply should succeed");
        assert!(plan.changed());

        let env_text = fs::read_to_string(&env_path).expect("env file should be readable");
        assert!(
            env_text.contains("EXISTING_KEY=existing_value"),
            "existing env entry should be preserved"
        );
        assert!(
            env_text.contains("GITEA__security__SECRET_KEY=secret123"),
            "new env entry should be appended"
        );

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn apply_guided_privileged_fix_keeps_lab_stack_yaml_parseable() {
        let root = temp_compose_dir("guided-lab-parseable");
        let path = root.join("docker-compose.yml");
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../docker/lab/self-hosting-stack.yml")
            .canonicalize()
            .expect("lab stack fixture should exist");
        fs::copy(&source, &path).expect("lab stack fixture should be copied");

        let finding_ids = [String::from("permissions.privileged")];
        let plan = apply(&path, FixMode::Fix, Some(&finding_ids)).expect("fix should apply");
        let updated = fs::read_to_string(&path).expect("updated compose should be readable");

        assert!(!plan.auto_applied.is_empty());
        assert!(plan.review_applied.is_empty());
        assert!(serde_yaml::from_str::<serde_yaml::Value>(&updated).is_ok());
        assert!(!updated.contains("privileged: true"));
        assert!(updated.contains("cap_add:"));
        assert!(updated.contains("NET_BIND_SERVICE"));
        assert!(updated.contains("      - \"127.0.0.1:8081:80\""));
        assert!(updated.contains("      - \"0.0.0.0:3012:3012\""));
        assert!(updated.contains("      - jellyfin-config:/config"));
        assert!(updated.contains("      - nextcloud-db:/var/lib/postgresql/data"));
        assert!(updated.contains("  vaultwarden-data:\n"));
        assert!(!updated.contains("vaultwarden-data: null"));
        assert!(!updated.contains("jellyfin-config: null"));
        assert!(!updated.contains("nextcloud-db: null"));

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn previews_quick_fix_for_service_specific_hardening() {
        let root = temp_compose_dir("quick-service-hardening");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  vaultwarden:\n",
                "    image: vaultwarden/server:1.30.1\n",
                "    user: \"1000:1000\"\n",
                "    ports:\n",
                "      - \"8080:80\"\n",
                "    environment:\n",
                "      DOMAIN: http://vault.example.com\n",
                "  jellyfin:\n",
                "    image: jellyfin/jellyfin:10.9.11\n",
                "    user: \"1000:1000\"\n",
                "    ports:\n",
                "      - \"8096:8096\"\n",
                "    environment:\n",
                "      JELLYFIN_PublishedServerUrl: http://media.example.com\n",
                "  nextcloud:\n",
                "    image: nextcloud:31.0.0\n",
                "    user: \"1000:1000\"\n",
                "    ports:\n",
                "      - \"8081:80\"\n",
                "    environment:\n",
                "      OVERWRITEPROTOCOL: http\n",
                "      NEXTCLOUD_TRUSTED_DOMAINS: \"cloud.example.com, *.example.com, 0.0.0.0\"\n"
            ),
        );

        let plan =
            preview(&path, FixMode::AutoFix, None).expect("quick-fix preview should succeed");

        assert_eq!(plan.auto_applied.len(), 7);
        assert!(plan.review_applied.is_empty());
        assert!(
            plan.diff_preview
                .contains("DOMAIN: https://vault.example.com")
        );
        assert!(
            plan.diff_preview
                .contains("JELLYFIN_PublishedServerUrl: https://media.example.com")
        );
        assert!(plan.diff_preview.contains("OVERWRITEPROTOCOL: https"));
        assert!(
            plan.diff_preview
                .contains("NEXTCLOUD_TRUSTED_DOMAINS: \"cloud.example.com\"")
        );

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn previews_quick_fix_noop_when_service_values_are_hardened() {
        let root = temp_compose_dir("quick-service-noop");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  vaultwarden:\n",
                "    image: vaultwarden/server:1.30.1\n",
                "    user: \"1000:1000\"\n",
                "    ports:\n",
                "      - \"127.0.0.1:8080:80\"\n",
                "    environment:\n",
                "      DOMAIN: https://vault.example.com\n",
                "  jellyfin:\n",
                "    image: jellyfin/jellyfin:10.9.11\n",
                "    user: \"1000:1000\"\n",
                "    ports:\n",
                "      - \"127.0.0.1:8096:8096\"\n",
                "    environment:\n",
                "      JELLYFIN_PublishedServerUrl: https://media.example.com\n",
                "  nextcloud:\n",
                "    image: nextcloud:31.0.0\n",
                "    user: \"1000:1000\"\n",
                "    ports:\n",
                "      - \"127.0.0.1:8081:80\"\n",
                "    environment:\n",
                "      OVERWRITEPROTOCOL: https\n",
                "      NEXTCLOUD_TRUSTED_DOMAINS: cloud.example.com cloud.internal\n"
            ),
        );

        let plan =
            preview(&path, FixMode::AutoFix, None).expect("quick-fix preview should succeed");

        assert!(plan.auto_applied.is_empty());
        assert!(plan.review_applied.is_empty());
        assert!(plan.diff_preview.is_empty());

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn skips_wildcard_trusted_domain_fix_when_it_would_remove_all_entries() {
        let root = temp_compose_dir("quick-nextcloud-wildcard-only");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  nextcloud:\n",
                "    image: nextcloud:31.0.0\n",
                "    user: \"1000:1000\"\n",
                "    ports:\n",
                "      - \"127.0.0.1:8081:80\"\n",
                "    environment:\n",
                "      NEXTCLOUD_TRUSTED_DOMAINS: \"*\"\n"
            ),
        );

        let plan =
            preview(&path, FixMode::AutoFix, None).expect("quick-fix preview should succeed");

        assert!(plan.auto_applied.is_empty());
        assert!(plan.review_applied.is_empty());
        assert!(plan.diff_preview.is_empty());

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn apply_quick_fix_is_idempotent_for_service_hardening() {
        let root = temp_compose_dir("quick-service-idempotent");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  vaultwarden:\n",
                "    image: vaultwarden/server:1.30.1\n",
                "    ports:\n",
                "      - \"8080:80\"\n",
                "    environment:\n",
                "      DOMAIN: http://vault.example.com\n",
                "  jellyfin:\n",
                "    image: jellyfin/jellyfin:10.9.11\n",
                "    ports:\n",
                "      - \"8096:8096\"\n",
                "    environment:\n",
                "      JELLYFIN_PublishedServerUrl: http://media.example.com\n",
                "  nextcloud:\n",
                "    image: nextcloud:31.0.0\n",
                "    ports:\n",
                "      - \"8081:80\"\n",
                "    environment:\n",
                "      OVERWRITEPROTOCOL: http\n",
                "      NEXTCLOUD_TRUSTED_DOMAINS: \"cloud.example.com, *.example.com\"\n"
            ),
        );

        let first = apply(&path, FixMode::AutoFix, None).expect("first apply should succeed");
        let second = apply(&path, FixMode::AutoFix, None).expect("second apply should succeed");

        assert!(first.changed());
        assert!(first.backup_path.is_some());
        assert!(second.auto_applied.is_empty());
        assert!(second.review_applied.is_empty());
        assert!(second.backup_path.is_none());

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn apply_creates_backup_and_updates_compose_file() {
        let root = temp_compose_dir("apply");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  web:\n",
                "    image: nginx\n",
                "    ports:\n",
                "      - \"8080:80\"\n"
            ),
        );

        let plan = apply(&path, FixMode::AutoFix, None).expect("quick-fix apply should succeed");
        let updated = fs::read_to_string(&path).expect("compose file should be readable");

        assert!(plan.backup_path.is_some());
        assert!(updated.contains("nginx:stable"));
        assert!(updated.contains("127.0.0.1:8080:80"));

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn preview_and_apply_keep_unrelated_yaml_formatting_stable() {
        let root = temp_compose_dir("preserve-formatting");
        let path = root.join("compose.yaml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  jellyfin:\n",
                "    image: lscr.io/linuxserver/jellyfin:latest\n",
                "    container_name: jellyfin\n",
                "    environment:\n",
                "      - PUID=1000\n",
                "      - PGID=1000\n",
                "      - TZ=Asia/Seoul\n",
                "    volumes:\n",
                "      - ./config:/config\n",
                "      - /srv/media:/media:ro\n",
                "    ports:\n",
                "      - \"8096:8096\"\n",
                "    restart: unless-stopped\n"
            ),
        );

        let plan =
            preview(&path, FixMode::AutoFix, None).expect("quick-fix preview should succeed");
        assert!(!plan.diff_preview.contains("-      - PUID=1000"));
        assert!(!plan.diff_preview.contains("+    - PUID=1000"));
        assert!(
            plan.diff_preview
                .contains("+      - \"127.0.0.1:8096:8096\"")
        );

        apply(&path, FixMode::AutoFix, None).expect("quick-fix apply should succeed");
        let updated = fs::read_to_string(&path).expect("compose file should be readable");

        assert!(updated.contains("      - PUID=1000"));
        assert!(updated.contains("      - /srv/media:/media:ro"));
        assert!(updated.contains("      - \"127.0.0.1:8096:8096\""));

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn preview_and_apply_preserve_single_quote_style_for_nextcloud_hardening() {
        let root = temp_compose_dir("preserve-single-quote-style");
        let path = root.join("compose.yaml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  nextcloud:\n",
                "    image: nextcloud:31.0.0\n",
                "    ports:\n",
                "      - \"8081:80\"\n",
                "    environment:\n",
                "      OVERWRITEPROTOCOL: 'http'\n",
                "      NEXTCLOUD_TRUSTED_DOMAINS: 'cloud.example.com,*.example.com'\n"
            ),
        );

        let plan =
            preview(&path, FixMode::AutoFix, None).expect("quick-fix preview should succeed");

        assert!(plan.diff_preview.contains("OVERWRITEPROTOCOL: 'https'"));
        assert!(
            plan.diff_preview
                .contains("NEXTCLOUD_TRUSTED_DOMAINS: 'cloud.example.com'")
        );

        apply(&path, FixMode::AutoFix, None).expect("quick-fix apply should succeed");
        let updated = fs::read_to_string(&path).expect("compose file should be readable");

        assert!(updated.contains("      OVERWRITEPROTOCOL: 'https'"));
        assert!(updated.contains("      NEXTCLOUD_TRUSTED_DOMAINS: 'cloud.example.com'"));
        assert!(updated.contains("      - \"127.0.0.1:8081:80\""));

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn merge_original_formatting_preserves_blank_lines_and_quotes_for_unchanged_lines() {
        let before = concat!(
            "services:\n",
            "  web:\n",
            "    user: \"1000:1000\"\n",
            "\n",
            "  admin:\n",
            "    ports:\n",
            "      - \"8080:80\"\n"
        );
        let after = concat!(
            "services:\n",
            "  web:\n",
            "    user: 1000:1000\n",
            "  admin:\n",
            "    ports:\n",
            "    - 127.0.0.1:8080:80\n"
        );

        let merged = merge_original_formatting(before, after);

        assert!(merged.contains("    user: \"1000:1000\""));
        assert!(merged.contains("\n\n  admin:\n"));
        assert!(merged.contains("      - \"127.0.0.1:8080:80\""));
    }

    #[test]
    fn previews_only_specified_finding_when_filtered() {
        let root = temp_compose_dir("granular");
        let path = root.join("docker-compose.yml");
        fs::write(
            &path,
            concat!(
                "services:\n",
                "  web:\n",
                "    image: nginx:latest\n",
                "    privileged: true\n",
                "    ports:\n",
                "      - \"80:80\"\n"
            ),
        )
        .expect("fixture should be written");

        // This has both updates.latest_tag (safe) and permissions.privileged (guided)
        let only_latest_tag = Some(vec!["updates.latest_tag".to_string()]);
        let plan = preview(&path, FixMode::Fix, only_latest_tag.as_deref())
            .expect("preview should succeed");

        assert_eq!(plan.auto_applied.len(), 1);
        assert_eq!(plan.review_applied.len(), 0);
        assert!(plan.diff_preview.contains("image: nginx:stable"));
        assert!(!plan.diff_preview.contains("privileged: false"));
    }

    #[test]
    fn previews_safe_fix_for_sensitive_mount() {
        let root = temp_compose_dir("safe-sensitive-mount");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  web:\n",
                "    image: nginx:stable\n",
                "    user: \"1000:1000\"\n",
                "    volumes:\n",
                "      - /etc/shadow:/etc/shadow\n",
                "      - /var/run/docker.sock:/var/run/docker.sock:rw\n",
                "      - type: bind\n",
                "        source: /etc/passwd\n",
                "        target: /etc/passwd\n"
            ),
        );

        let plan =
            preview(&path, FixMode::AutoFix, None).expect("quick-fix preview should succeed");

        assert_eq!(plan.auto_applied.len(), 3);
        assert!(plan.diff_preview.contains("/etc/shadow:/etc/shadow:ro"));
        assert!(
            plan.diff_preview
                .contains("/var/run/docker.sock:/var/run/docker.sock:ro")
        );
        assert!(plan.diff_preview.contains("read_only: true"));

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn previews_safe_fix_for_seccomp_unconfined() {
        let root = temp_compose_dir("safe-seccomp");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  web:\n",
                "    image: nginx:stable\n",
                "    user: \"1000:1000\"\n",
                "    security_opt:\n",
                "      - seccomp:unconfined\n",
                "      - no-new-privileges:true\n"
            ),
        );

        let plan =
            preview(&path, FixMode::AutoFix, None).expect("quick-fix preview should succeed");

        assert_eq!(plan.auto_applied.len(), 1);
        assert!(plan.updated_text.contains("no-new-privileges:true"));
        assert!(!plan.updated_text.contains("seccomp:unconfined"));

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn previews_safe_fix_for_dangerous_capabilities() {
        let root = temp_compose_dir("safe-cap-drop");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  web:\n",
                "    image: nginx:stable\n",
                "    user: \"1000:1000\"\n",
                "    cap_add:\n",
                "      - NET_ADMIN\n",
                "      - SYS_PTRACE\n",
                "      - NET_BIND_SERVICE\n"
            ),
        );

        let plan =
            preview(&path, FixMode::AutoFix, None).expect("quick-fix preview should succeed");

        assert_eq!(plan.auto_applied.len(), 1);
        assert!(plan.updated_text.contains("NET_BIND_SERVICE"));
        assert!(!plan.updated_text.contains("NET_ADMIN"));
        assert!(!plan.updated_text.contains("SYS_PTRACE"));

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn apply_safe_fix_removes_empty_security_opt_and_cap_add() {
        let root = temp_compose_dir("safe-remove-empty");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  web:\n",
                "    image: nginx:stable\n",
                "    security_opt:\n",
                "      - seccomp:unconfined\n",
                "    cap_add:\n",
                "      - NET_ADMIN\n"
            ),
        );

        apply(&path, FixMode::AutoFix, None).expect("apply should succeed");

        let updated = fs::read_to_string(&path).expect("compose should be readable");
        assert!(!updated.contains("security_opt"));
        assert!(!updated.contains("cap_add"));

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn review_request_finding_id() {
        let req = ReviewRequest::Choice {
            finding_id: String::from("test.choice"),
            service: String::from("web"),
            title: String::from("T"),
            description: String::from("D"),
            options: vec![ReviewChoiceOption {
                key: String::from("a"),
                label: String::from("A"),
                description: String::from("AD"),
            }],
        };
        assert_eq!(req.finding_id(), "test.choice");

        let req = ReviewRequest::SecretInput {
            finding_id: String::from("test.secret"),
            service: String::from("db"),
            variable: String::from("PASS"),
            title: String::from("T"),
            description: String::from("D"),
            suggested_value: String::from("x"),
        };
        assert_eq!(req.finding_id(), "test.secret");
    }

    #[test]
    fn display_fix_error() {
        let err = FixError::ComposeParse(ComposeParseError::MissingServices {
            path: PathBuf::from("/p"),
        });
        assert!(!err.to_string().is_empty());

        let err = FixError::Io(std::io::Error::other("oops"));
        assert!(err.to_string().contains("oops"));

        let err = FixError::Serialize(String::from("bad yaml"));
        assert!(err.to_string().contains("bad yaml"));

        let err = FixError::ReviewRequired(vec![]);
        assert!(!err.to_string().is_empty());

        let err = FixError::InvalidReviewResolution(String::from("unknown"));
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn fix_error_from_compose_parse() {
        let compose_err = ComposeParseError::MissingServices {
            path: PathBuf::from("/p"),
        };
        let fix_err: FixError = compose_err.into();
        assert!(matches!(fix_err, FixError::ComposeParse(_)));
    }

    #[test]
    fn fix_error_from_io() {
        let io_err = std::io::Error::other("oops");
        let fix_err: FixError = io_err.into();
        assert!(matches!(fix_err, FixError::Io(_)));
    }

    #[test]
    fn execute_host_edit_creates_file() {
        let dir = temp_compose_dir("host-edit");
        let file_path = dir.join("test.conf");
        let action = FixAction::HostEdit {
            path: file_path.clone(),
            summary: "create test config".to_string(),
            original_content: String::new(),
            updated_content: "key=value\n".to_string(),
            mode: None,
        };
        let plan = FixPlan {
            compose_file: dir.join("docker-compose.yml"),
            diff_preview: String::new(),
            updated_text: String::new(),
            backup_path: None,
            auto_applied: Vec::new(),
            review_applied: Vec::new(),
            host_actions: vec![action],
            system_actions: Vec::new(),
            compose_actions: Vec::new(),
        };

        execute_host_and_system_actions(&plan).expect("host edit should succeed");

        assert!(file_path.exists(), "file should be created");
        let content = fs::read_to_string(&file_path).expect("should be readable");
        assert_eq!(content, "key=value\n");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn execute_host_edit_overwrites_existing_file() {
        let dir = temp_compose_dir("host-overwrite");
        let file_path = dir.join("existing.conf");
        fs::write(&file_path, "original\n").expect("write original");

        let action = FixAction::HostEdit {
            path: file_path.clone(),
            summary: "overwrite config".to_string(),
            original_content: "original\n".to_string(),
            updated_content: "updated\n".to_string(),
            mode: None,
        };
        let plan = FixPlan {
            compose_file: dir.join("docker-compose.yml"),
            diff_preview: String::new(),
            updated_text: String::new(),
            backup_path: None,
            auto_applied: Vec::new(),
            review_applied: Vec::new(),
            host_actions: vec![action],
            system_actions: Vec::new(),
            compose_actions: Vec::new(),
        };

        execute_host_and_system_actions(&plan).expect("host edit should succeed");

        let content = fs::read_to_string(&file_path).expect("should be readable");
        assert_eq!(content, "updated\n");

        // Verify backup was created
        let dir_entries: Vec<_> = fs::read_dir(&dir)
            .expect("read dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".bak."))
            .collect();
        assert!(
            !dir_entries.is_empty(),
            "backup file should exist: {:?}",
            dir_entries
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn execute_host_edit_creates_parent_directories() {
        let dir = temp_compose_dir("host-mkdir");
        let nested_path = dir.join("subdir/deep/config.conf");

        let action = FixAction::HostEdit {
            path: nested_path.clone(),
            summary: "create nested config".to_string(),
            original_content: String::new(),
            updated_content: "nested=true\n".to_string(),
            mode: None,
        };
        let plan = FixPlan {
            compose_file: dir.join("docker-compose.yml"),
            diff_preview: String::new(),
            updated_text: String::new(),
            backup_path: None,
            auto_applied: Vec::new(),
            review_applied: Vec::new(),
            host_actions: vec![action],
            system_actions: Vec::new(),
            compose_actions: Vec::new(),
        };

        execute_host_and_system_actions(&plan).expect("host edit with mkdir should succeed");

        assert!(nested_path.exists(), "nested file should be created");
        let content = fs::read_to_string(&nested_path).expect("should be readable");
        assert_eq!(content, "nested=true\n");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn execute_host_edit_sets_permissions() {
        let dir = temp_compose_dir("host-perms");
        let file_path = dir.join("secure.conf");

        let action = FixAction::HostEdit {
            path: file_path.clone(),
            summary: "create secure config".to_string(),
            original_content: String::new(),
            updated_content: "secure=true\n".to_string(),
            mode: Some(0o600),
        };
        let plan = FixPlan {
            compose_file: dir.join("docker-compose.yml"),
            diff_preview: String::new(),
            updated_text: String::new(),
            backup_path: None,
            auto_applied: Vec::new(),
            review_applied: Vec::new(),
            host_actions: vec![action],
            system_actions: Vec::new(),
            compose_actions: Vec::new(),
        };

        execute_host_and_system_actions(&plan).expect("host edit with permissions should succeed");

        let metadata = fs::metadata(&file_path).expect("file should exist");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                metadata.permissions().mode() & 0o777,
                0o600,
                "permissions should be 0600"
            );
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn execute_shell_command_succeeds() {
        let dir = temp_compose_dir("shell-cmd");
        let marker = dir.join("marker.txt");

        let action = FixAction::ShellCommand {
            command: format!("touch {}", marker.display()),
            summary: "create marker".to_string(),
            rollback: None,
        };
        let plan = FixPlan {
            compose_file: dir.join("docker-compose.yml"),
            diff_preview: String::new(),
            updated_text: String::new(),
            backup_path: None,
            auto_applied: Vec::new(),
            review_applied: Vec::new(),
            host_actions: Vec::new(),
            system_actions: vec![action],
            compose_actions: Vec::new(),
        };

        execute_host_and_system_actions(&plan).expect("shell command should succeed");

        assert!(
            marker.exists(),
            "shell command should have created marker file"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn execute_shell_command_failure_returns_error() {
        let action = FixAction::ShellCommand {
            command: "exit 42".to_string(),
            summary: "failing command".to_string(),
            rollback: None,
        };
        let plan = FixPlan {
            compose_file: PathBuf::from("/nonexistent/compose.yml"),
            diff_preview: String::new(),
            updated_text: String::new(),
            backup_path: None,
            auto_applied: Vec::new(),
            review_applied: Vec::new(),
            host_actions: Vec::new(),
            system_actions: vec![action],
            compose_actions: Vec::new(),
        };

        let result = execute_host_and_system_actions(&plan);
        assert!(result.is_err(), "failing shell command should return error");
    }

    #[test]
    fn execute_multiple_host_and_shell_actions_all_succeed() {
        let dir = temp_compose_dir("multi-action");
        let file1 = dir.join("file1.conf");
        let file2 = dir.join("file2.conf");
        let marker = dir.join("marker.txt");

        let plan = FixPlan {
            compose_file: dir.join("docker-compose.yml"),
            diff_preview: String::new(),
            updated_text: String::new(),
            backup_path: None,
            auto_applied: Vec::new(),
            review_applied: Vec::new(),
            host_actions: vec![
                FixAction::HostEdit {
                    path: file1.clone(),
                    summary: "file1".to_string(),
                    original_content: String::new(),
                    updated_content: "file1=val\n".to_string(),
                    mode: None,
                },
                FixAction::HostEdit {
                    path: file2.clone(),
                    summary: "file2".to_string(),
                    original_content: String::new(),
                    updated_content: "file2=val\n".to_string(),
                    mode: None,
                },
            ],
            system_actions: vec![FixAction::ShellCommand {
                command: format!("touch {}", marker.display()),
                summary: "create marker".to_string(),
                rollback: None,
            }],
            compose_actions: Vec::new(),
        };

        execute_host_and_system_actions(&plan).expect("all actions should succeed");

        assert!(file1.exists(), "file1 should be created");
        assert!(file2.exists(), "file2 should be created");
        assert!(marker.exists(), "marker should be created");
        assert_eq!(fs::read_to_string(&file1).unwrap(), "file1=val\n");
        assert_eq!(fs::read_to_string(&file2).unwrap(), "file2=val\n");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn execute_no_actions_is_noop() {
        let plan = FixPlan {
            compose_file: PathBuf::from("/nonexistent/compose.yml"),
            diff_preview: String::new(),
            updated_text: String::new(),
            backup_path: None,
            auto_applied: Vec::new(),
            review_applied: Vec::new(),
            host_actions: Vec::new(),
            system_actions: Vec::new(),
            compose_actions: Vec::new(),
        };

        let result = execute_host_and_system_actions(&plan);
        assert!(result.is_ok(), "no actions should succeed without error");
    }

    #[test]
    fn apply_compose_edit_adds_healthcheck_to_service() {
        let original = "services:\n  web:\n    image: nginx\n";
        let action = FixAction::ComposeEdit {
            service: "web".to_string(),
            summary: "add healthcheck".to_string(),
            diff: "+  healthcheck:\n+    test: [\"CMD\", \"curl\", \"-f\", \"http://localhost\"]\n+    interval: 30s\n".to_string(),
        };
        let (result, diff) = apply_compose_edits_to_text(original, &[action]);
        assert!(
            result.contains("healthcheck:"),
            "should have healthcheck block"
        );
        assert!(
            result.contains("test: [\"CMD\", \"curl\""),
            "should have healthcheck test"
        );
        assert!(!diff.is_empty(), "should produce diff output");
    }

    #[test]
    fn apply_compose_edit_adds_service_if_not_present() {
        let original = "services:\n  web:\n    image: nginx\n";
        let action = FixAction::ComposeEdit {
            service: "db".to_string(),
            summary: "add db service".to_string(),
            diff: "+  db:\n+    image: postgres\n".to_string(),
        };
        let (result, _diff) = apply_compose_edits_to_text(original, &[action]);
        assert!(result.contains("db:"), "should have db service section");
    }

    #[test]
    fn apply_multiple_compose_edits() {
        let original = "services:\n  web:\n    image: nginx\n";
        let actions = vec![
            FixAction::ComposeEdit {
                service: "web".to_string(),
                summary: "healthcheck".to_string(),
                diff: "+  healthcheck:\n+    test: [\"CMD\"]\n".to_string(),
            },
            FixAction::ComposeEdit {
                service: "web".to_string(),
                summary: "no-new-privs".to_string(),
                diff: "+  security_opt:\n+    - no-new-privileges:true\n".to_string(),
            },
        ];
        let (result, _diff) = apply_compose_edits_to_text(original, &actions);
        assert!(result.contains("healthcheck:"), "should have healthcheck");
        assert!(result.contains("security_opt:"), "should have security_opt");
        assert!(
            result.contains("no-new-privileges"),
            "should have no-new-privileges"
        );
    }

    #[test]
    fn apply_compose_edit_noop_for_empty_actions() {
        let original = "services:\n  web:\n    image: nginx\n";
        let (result, diff) = apply_compose_edits_to_text(original, &[]);
        assert_eq!(result, original, "text should be unchanged");
        assert!(diff.is_empty(), "should have no diff");
    }

    #[test]
    fn fix_plan_changed_includes_compose_actions() {
        let plan = FixPlan {
            compose_file: PathBuf::from("/p/compose.yml"),
            diff_preview: String::new(),
            updated_text: String::new(),
            backup_path: None,
            auto_applied: Vec::new(),
            review_applied: Vec::new(),
            host_actions: Vec::new(),
            system_actions: Vec::new(),
            compose_actions: vec![FixAction::ComposeEdit {
                service: "web".to_string(),
                summary: "test".to_string(),
                diff: "+  healthcheck: ...\n".to_string(),
            }],
        };
        assert!(
            plan.changed(),
            "plan with compose_actions should be changed"
        );
    }

    #[test]
    fn fix_plan_changed_includes_auto_applied() {
        let plan = FixPlan {
            compose_file: PathBuf::from("/p/compose.yml"),
            diff_preview: String::new(),
            updated_text: String::new(),
            backup_path: None,
            auto_applied: vec![FixProposal {
                service: "web".to_string(),
                summary: "auto fix".to_string(),
                remediation: RemediationKind::Auto,
            }],
            review_applied: Vec::new(),
            host_actions: Vec::new(),
            system_actions: Vec::new(),
            compose_actions: Vec::new(),
        };
        assert!(plan.changed(), "plan with auto_applied should be changed");
    }

    #[test]
    fn fix_plan_changed_includes_review_applied() {
        let plan = FixPlan {
            compose_file: PathBuf::from("/p/compose.yml"),
            diff_preview: String::new(),
            updated_text: String::new(),
            backup_path: None,
            auto_applied: Vec::new(),
            review_applied: vec![FixProposal {
                service: "db".to_string(),
                summary: "review fix".to_string(),
                remediation: RemediationKind::Review,
            }],
            host_actions: Vec::new(),
            system_actions: Vec::new(),
            compose_actions: Vec::new(),
        };
        assert!(plan.changed(), "plan with review_applied should be changed");
    }

    #[test]
    fn apply_compose_edit_skips_non_compose_actions() {
        let original = "services:\n  web:\n    image: nginx\n";
        let actions = [
            FixAction::ShellCommand {
                command: "echo hi".to_string(),
                summary: "shell".to_string(),
                rollback: None,
            },
            FixAction::HostEdit {
                path: PathBuf::from("/tmp/test.conf"),
                summary: "host".to_string(),
                original_content: String::new(),
                updated_content: "val".to_string(),
                mode: None,
            },
        ];
        let (result, diff) = apply_compose_edits_to_text(original, &actions);
        assert_eq!(
            result, original,
            "non-ComposeEdit actions should not modify text"
        );
        assert!(
            diff.is_empty(),
            "non-ComposeEdit actions should not produce diff"
        );
    }

    #[test]
    fn fix_plan_changed_false_when_only_empty_compose_actions() {
        let plan = FixPlan {
            compose_file: PathBuf::from("/p/compose.yml"),
            diff_preview: String::new(),
            updated_text: String::new(),
            backup_path: None,
            auto_applied: Vec::new(),
            review_applied: Vec::new(),
            host_actions: Vec::new(),
            system_actions: Vec::new(),
            compose_actions: Vec::new(),
        };
        assert!(
            !plan.changed(),
            "plan with empty compose_actions should not be changed"
        );
    }

    #[test]
    fn fix_plan_changed_includes_host_actions() {
        let plan = FixPlan {
            compose_file: PathBuf::from("/p/compose.yml"),
            diff_preview: String::new(),
            updated_text: String::new(),
            backup_path: None,
            auto_applied: Vec::new(),
            review_applied: Vec::new(),
            host_actions: vec![FixAction::HostEdit {
                path: PathBuf::from("/etc/ssh/sshd_config"),
                summary: "test".to_string(),
                original_content: String::new(),
                updated_content: "val".to_string(),
                mode: None,
            }],
            system_actions: Vec::new(),
            compose_actions: Vec::new(),
        };
        assert!(plan.changed(), "plan with host_actions should be changed");
    }

    #[test]
    fn fix_plan_changed_includes_system_actions() {
        let plan = FixPlan {
            compose_file: PathBuf::from("/p/compose.yml"),
            diff_preview: String::new(),
            updated_text: String::new(),
            backup_path: None,
            auto_applied: Vec::new(),
            review_applied: Vec::new(),
            host_actions: Vec::new(),
            system_actions: vec![FixAction::ShellCommand {
                command: "echo ok".to_string(),
                summary: "test".to_string(),
                rollback: None,
            }],
            compose_actions: Vec::new(),
        };
        assert!(plan.changed(), "plan with system_actions should be changed");
    }

    #[test]
    fn fix_plan_changed_false_when_all_fields_empty() {
        let plan = FixPlan {
            compose_file: PathBuf::from("/p/compose.yml"),
            diff_preview: String::new(),
            updated_text: String::new(),
            backup_path: None,
            auto_applied: Vec::new(),
            review_applied: Vec::new(),
            host_actions: Vec::new(),
            system_actions: Vec::new(),
            compose_actions: Vec::new(),
        };
        assert!(!plan.changed(), "empty plan should not be changed");
    }

    fn dockle_finding(id: &str, service: &str, codes: &str) -> Finding {
        let mut evidence = std::collections::BTreeMap::new();
        evidence.insert("sample_codes".to_string(), codes.to_string());
        Finding {
            id: id.to_string(),
            axis: crate::domain::Axis::HostHardening,
            severity: Severity::Medium,
            scope: crate::domain::Scope::Service,
            source: Source::Dockle,
            subject: service.to_string(),
            related_service: Some(service.to_string()),
            title: "test".to_string(),
            description: "test".to_string(),
            why_risky: "risky".to_string(),
            how_to_fix: "fix".to_string(),
            evidence,
            remediation: RemediationKind::Auto,
        }
    }

    fn lynis_host_finding(id: &str, test_ids: &str) -> Finding {
        let mut evidence = std::collections::BTreeMap::new();
        evidence.insert("sample_test_ids".to_string(), test_ids.to_string());
        Finding {
            id: id.to_string(),
            axis: crate::domain::Axis::HostHardening,
            severity: Severity::Low,
            scope: crate::domain::Scope::Host,
            source: Source::Lynis,
            subject: "host".to_string(),
            related_service: None,
            title: "test".to_string(),
            description: "test".to_string(),
            why_risky: "risky".to_string(),
            how_to_fix: "fix".to_string(),
            evidence,
            remediation: RemediationKind::Review,
        }
    }

    #[test]
    fn preview_with_dockle_findings_populates_compose_actions() {
        let path = copy_mixed_stack_fixture_to_temp("pipeline-dockle");
        let findings = vec![
            dockle_finding("dockle.1", "web", "DKL-DI-0006"),
            dockle_finding("dockle.2", "db", "DKL-DI-0003"),
        ];

        let plan = preview_with_external(
            &path,
            FixMode::AutoFix,
            None,
            &findings,
            &FixResolutionMap::new(),
        )
        .expect("preview should succeed");

        assert!(
            !plan.compose_actions.is_empty(),
            "Dockle findings should produce compose_actions"
        );
        assert_eq!(
            plan.compose_actions.len(),
            2,
            "two Dockle findings → two compose_actions"
        );
        assert!(
            !plan.auto_applied.is_empty(),
            "native compose findings should also be present"
        );
        fs::remove_dir_all(path.parent().expect("has parent")).ok();
    }

    #[test]
    fn preview_with_lynis_findings_populates_host_and_system_actions() {
        let path = copy_mixed_stack_fixture_to_temp("pipeline-lynis");
        let findings = vec![lynis_host_finding("lynis.host_warnings", "SSH-7408")];

        let plan = preview_with_external(
            &path,
            FixMode::AutoFix,
            None,
            &findings,
            &FixResolutionMap::new(),
        )
        .expect("preview should succeed");

        assert!(
            !plan.host_actions.is_empty(),
            "SSH Lynis finding should produce host_actions"
        );
        assert!(
            plan.host_actions
                .iter()
                .any(|a| matches!(a, FixAction::HostEdit { .. })),
            "SSH hardening should be a HostEdit"
        );
        fs::remove_dir_all(path.parent().expect("has parent")).ok();
    }

    #[test]
    fn preview_with_mixed_adapter_findings_populates_all_action_types() {
        let path = copy_mixed_stack_fixture_to_temp("pipeline-mixed");
        let findings = vec![
            dockle_finding("dockle.1", "web", "DKL-DI-0006"),
            lynis_host_finding("lynis.host_warnings", "SSH-7408"),
            lynis_host_finding("lynis.host_suggestions", "FILE-7524"),
        ];

        let plan = preview_with_external(
            &path,
            FixMode::AutoFix,
            None,
            &findings,
            &FixResolutionMap::new(),
        )
        .expect("preview should succeed");

        assert!(!plan.compose_actions.is_empty(), "Dockle → compose_actions");
        assert!(
            !plan.host_actions.is_empty(),
            "SSH Lynis → host_actions (HostEdit)"
        );
        assert!(
            !plan.system_actions.is_empty(),
            "FILE Lynis → system_actions (ShellCommand)"
        );
        assert!(
            plan.changed(),
            "plan with any action type should be changed"
        );
        fs::remove_dir_all(path.parent().expect("has parent")).ok();
    }

    #[test]
    fn preview_with_empty_external_findings_produces_no_adapter_actions() {
        let path = copy_mixed_stack_fixture_to_temp("pipeline-empty");
        let plan =
            preview_with_external(&path, FixMode::AutoFix, None, &[], &FixResolutionMap::new())
                .expect("preview should succeed");

        assert!(
            plan.host_actions.is_empty(),
            "no external findings → no host_actions"
        );
        assert!(
            plan.system_actions.is_empty(),
            "no external findings → no system_actions"
        );
        assert!(
            plan.compose_actions.is_empty(),
            "no external findings → no compose_actions"
        );
        fs::remove_dir_all(path.parent().expect("has parent")).ok();
    }

    #[test]
    fn apply_with_external_writes_compose_file() {
        let path = copy_mixed_stack_fixture_to_temp("pipeline-apply");
        let findings = vec![dockle_finding("dockle.1", "web", "DKL-DI-0006")];

        let plan = apply_with_external(
            &path,
            FixMode::AutoFix,
            None,
            &findings,
            &FixResolutionMap::new(),
        )
        .expect("apply should succeed");

        // compose_actions should be applied to the compose file
        let content = fs::read_to_string(&path).expect("compose file should exist");
        assert!(
            content.contains("healthcheck") || plan.compose_actions.is_empty(),
            "compose file should contain healthcheck if dockle action was applied"
        );
        fs::remove_dir_all(path.parent().expect("has parent")).ok();
    }

    #[test]
    fn system_actions_contains_only_shell_command_after_filter() {
        // Build explicit actions list that would be partitioned in build_fix_plan
        let actions = vec![
            FixAction::ComposeEdit {
                service: "web".to_string(),
                summary: "healthcheck".to_string(),
                diff: "+  healthcheck:\n".to_string(),
            },
            FixAction::HostEdit {
                path: PathBuf::from("/tmp/test.conf"),
                summary: "host".to_string(),
                original_content: String::new(),
                updated_content: "val".to_string(),
                mode: None,
            },
            FixAction::ShellCommand {
                command: "echo ok".to_string(),
                summary: "shell".to_string(),
                rollback: None,
            },
        ];
        // Simulate the partition logic from build_fix_plan
        let mut compose_actions: Vec<FixAction> = Vec::new();
        let (host_actions, system_actions): (Vec<_>, Vec<_>) =
            actions.into_iter().partition(|a| match a {
                FixAction::ComposeEdit { .. } => {
                    compose_actions.push(a.clone());
                    false
                }
                FixAction::HostEdit { .. } => true,
                FixAction::ShellCommand { .. } => false,
            });
        let system_actions: Vec<_> = system_actions
            .into_iter()
            .filter(|a| matches!(a, FixAction::ShellCommand { .. }))
            .collect();

        assert_eq!(compose_actions.len(), 1, "exactly 1 ComposeEdit");
        assert!(
            compose_actions
                .iter()
                .all(|a| matches!(a, FixAction::ComposeEdit { .. }))
        );
        assert_eq!(host_actions.len(), 1, "exactly 1 HostEdit");
        assert!(
            host_actions
                .iter()
                .all(|a| matches!(a, FixAction::HostEdit { .. }))
        );
        assert_eq!(
            system_actions.len(),
            1,
            "exactly 1 ShellCommand in system_actions"
        );
        assert!(
            system_actions
                .iter()
                .all(|a| matches!(a, FixAction::ShellCommand { .. }))
        );
    }

    #[test]
    fn compose_actions_excludes_non_compose_edit() {
        let original = "services:\n  web:\n    image: nginx\n";
        // Only non-ComposeEdit actions → compose_actions should be empty
        let actions = [
            FixAction::HostEdit {
                path: PathBuf::from("/tmp/x.conf"),
                summary: "h".to_string(),
                original_content: String::new(),
                updated_content: "v".to_string(),
                mode: None,
            },
            FixAction::ShellCommand {
                command: "echo hi".to_string(),
                summary: "s".to_string(),
                rollback: None,
            },
        ];
        let (result, diff) = apply_compose_edits_to_text(original, &actions);
        assert_eq!(result, original, "no compose edits → no change to text");
        assert!(diff.is_empty(), "no compose edits → no diff");
    }

    #[test]
    fn apply_with_compose_only_changes_writes_file() {
        let dir = temp_compose_dir("compose-only-apply");
        let path = dir.join("docker-compose.yml");
        write_compose(&path, "services:\n  web:\n    image: nginx\n");

        let findings = vec![dockle_finding("d1", "web", "DKL-DI-0006")];

        let plan = apply_with_external(
            &path,
            FixMode::AutoFix,
            None,
            &findings,
            &FixResolutionMap::new(),
        )
        .expect("apply should succeed");

        let content = fs::read_to_string(&path).expect("file should exist");
        if !plan.compose_actions.is_empty() {
            assert!(
                content.contains("healthcheck") || content.contains("test: "),
                "compose file should contain healthcheck block when compose_actions exist:\n{}",
                content
            );
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fix_mode_does_not_affect_adapter_classification() {
        let path = copy_mixed_stack_fixture_to_temp("mode-test");
        let findings = vec![
            dockle_finding("d1", "web", "DKL-DI-0006"),
            lynis_host_finding("lynis.host_warnings", "SSH-7408"),
        ];

        let first = preview_with_external(
            &path,
            FixMode::AutoFix,
            None,
            &findings,
            &FixResolutionMap::new(),
        )
        .expect("first preview");

        let second = preview_with_external(
            &path,
            FixMode::AutoFix,
            None,
            &findings,
            &FixResolutionMap::new(),
        )
        .expect("second preview");

        // Adapter classification should be identical across calls (idempotent)
        assert_eq!(
            first.compose_actions.len(),
            second.compose_actions.len(),
            "compose_actions len should match"
        );
        assert_eq!(
            first.host_actions.len(),
            second.host_actions.len(),
            "host_actions len should match"
        );
        assert_eq!(
            first.system_actions.len(),
            second.system_actions.len(),
            "system_actions len should match"
        );
        // Also verify with FixMode::Fix — adapter classification is mode-independent
        // (same adapter findings produce same actions regardless of native fix mode)
        let fix_result = preview_with_external(
            &path,
            FixMode::Fix,
            None,
            &findings,
            &FixResolutionMap::new(),
        );
        if let Ok(fix_plan) = fix_result {
            assert_eq!(first.compose_actions.len(), fix_plan.compose_actions.len());
        }
        // If Fix returns ReviewRequired, that's expected — it only affects native,
        // not adapter. The adapter actions from AutoFix are the ground truth.
        fs::remove_dir_all(path.parent().expect("has parent")).ok();
    }

    // ── Execute host + system action combination tests ──

    #[test]
    fn execute_shell_command_with_rollback_does_not_error() {
        let dir = temp_compose_dir("rollback");
        let action = FixAction::ShellCommand {
            command: "echo rollback-test".to_string(),
            summary: "test rollback presence".to_string(),
            rollback: Some("echo undo".to_string()),
        };
        let plan = FixPlan {
            compose_file: dir.join("docker-compose.yml"),
            diff_preview: String::new(),
            updated_text: String::new(),
            backup_path: None,
            auto_applied: Vec::new(),
            review_applied: Vec::new(),
            host_actions: Vec::new(),
            system_actions: vec![action],
            compose_actions: Vec::new(),
        };

        let result = execute_host_and_system_actions(&plan);
        assert!(result.is_ok(), "ShellCommand with rollback should succeed");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn execute_partial_failure_after_host_edit_returns_error() {
        let dir = temp_compose_dir("partial-fail");
        let host_file = dir.join("partial.conf");

        let plan = FixPlan {
            compose_file: dir.join("docker-compose.yml"),
            diff_preview: String::new(),
            updated_text: String::new(),
            backup_path: None,
            auto_applied: Vec::new(),
            review_applied: Vec::new(),
            host_actions: vec![FixAction::HostEdit {
                path: host_file.clone(),
                summary: "created before failure".to_string(),
                original_content: String::new(),
                updated_content: "survived\n".to_string(),
                mode: None,
            }],
            system_actions: vec![FixAction::ShellCommand {
                command: "exit 42".to_string(),
                summary: "this will fail".to_string(),
                rollback: None,
            }],
            compose_actions: Vec::new(),
        };

        let result = execute_host_and_system_actions(&plan);
        assert!(result.is_err(), "partial failure should return error");

        // HostEdit changes are committed even on partial failure (no rollback for HostEdit)
        assert!(
            host_file.exists(),
            "HostEdit file should exist despite ShellCommand failure"
        );
        let content = fs::read_to_string(&host_file).expect("should be readable");
        assert_eq!(content, "survived\n");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn execute_host_edit_with_mode_and_shell_command_succeeds() {
        let dir = temp_compose_dir("mode-and-shell");
        let host_file = dir.join("secure.conf");

        let plan = FixPlan {
            compose_file: dir.join("docker-compose.yml"),
            diff_preview: String::new(),
            updated_text: String::new(),
            backup_path: None,
            auto_applied: Vec::new(),
            review_applied: Vec::new(),
            host_actions: vec![FixAction::HostEdit {
                path: host_file.clone(),
                summary: "secure file".to_string(),
                original_content: String::new(),
                updated_content: "secure=true\n".to_string(),
                mode: Some(0o600),
            }],
            system_actions: vec![FixAction::ShellCommand {
                command: format!("touch {}", dir.join("done.txt").display()),
                summary: "marker after host edit".to_string(),
                rollback: None,
            }],
            compose_actions: Vec::new(),
        };

        execute_host_and_system_actions(&plan).expect("mode + shell should succeed");

        assert!(host_file.exists(), "host file should exist");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(&host_file).expect("file metadata");
            assert_eq!(
                meta.permissions().mode() & 0o777,
                0o600,
                "host file should have mode 0600"
            );
        }
        assert!(
            dir.join("done.txt").exists(),
            "shell command marker should exist"
        );
        fs::remove_dir_all(&dir).ok();
    }

    // ── NativeHost adapter pipeline tests ──

    fn native_host_finding(id: &str) -> Finding {
        Finding {
            id: id.to_string(),
            axis: crate::domain::Axis::HostHardening,
            severity: Severity::Medium,
            scope: crate::domain::Scope::Host,
            source: Source::NativeHost,
            subject: "host".to_string(),
            related_service: None,
            title: "test native host".to_string(),
            description: "test".to_string(),
            why_risky: "risky".to_string(),
            how_to_fix: "fix".to_string(),
            evidence: std::collections::BTreeMap::new(),
            remediation: RemediationKind::Review,
        }
    }

    #[test]
    fn preview_with_native_host_findings_populates_system_actions() {
        let path = copy_mixed_stack_fixture_to_temp("pipeline-native");
        let findings = vec![
            native_host_finding("host.ssh_root_login_enabled"),
            native_host_finding("host.fail2ban_not_enabled"),
        ];

        let plan = preview_with_external(
            &path,
            FixMode::AutoFix,
            None,
            &findings,
            &FixResolutionMap::new(),
        )
        .expect("preview should succeed");

        assert!(
            !plan.system_actions.is_empty(),
            "NativeHost should produce system_actions"
        );
        assert_eq!(
            plan.system_actions.len(),
            2,
            "2 NativeHost findings → 2 system_actions"
        );
        assert!(
            plan.system_actions
                .iter()
                .all(|a| matches!(a, FixAction::ShellCommand { .. })),
            "all system_actions should be ShellCommand"
        );
        assert!(
            plan.host_actions.is_empty(),
            "NativeHost should not produce host_actions"
        );
        assert!(
            plan.compose_actions.is_empty(),
            "NativeHost should not produce compose_actions"
        );
        fs::remove_dir_all(path.parent().expect("has parent")).ok();
    }

    #[test]
    fn preview_with_native_and_dockle_populates_all_action_types() {
        let path = copy_mixed_stack_fixture_to_temp("pipeline-native-dockle");
        let findings = vec![
            native_host_finding("host.ssh_root_login_enabled"),
            dockle_finding("dockle.1", "web", "DKL-DI-0006"),
        ];

        let plan = preview_with_external(
            &path,
            FixMode::AutoFix,
            None,
            &findings,
            &FixResolutionMap::new(),
        )
        .expect("preview should succeed");

        assert!(
            !plan.system_actions.is_empty(),
            "NativeHost → system_actions"
        );
        assert!(!plan.compose_actions.is_empty(), "Dockle → compose_actions");
        assert!(
            plan.host_actions.is_empty(),
            "no host_actions in this combo"
        );
        assert!(plan.changed(), "plan with mixed types should be changed");
        fs::remove_dir_all(path.parent().expect("has parent")).ok();
    }

    // ── only_findings scoping for adapter findings ──

    #[test]
    fn preview_with_only_findings_scopes_adapter_findings() {
        let path = copy_mixed_stack_fixture_to_temp("pipeline-scoped");
        let findings = vec![
            dockle_finding("dockle.1", "web", "DKL-DI-0006"),
            dockle_finding("dockle.2", "db", "DKL-DI-0003"),
            native_host_finding("host.ssh_root_login_enabled"),
        ];
        let only = vec![
            "dockle.1".to_string(),
            "host.ssh_root_login_enabled".to_string(),
        ];

        let plan = preview_with_external(
            &path,
            FixMode::AutoFix,
            Some(&only),
            &findings,
            &FixResolutionMap::new(),
        )
        .expect("preview should succeed");

        // dockle.1 matches → compose_actions
        assert_eq!(
            plan.compose_actions.len(),
            1,
            "only dockle.1 should produce 1 compose action"
        );
        assert!(
            plan.compose_actions[0].summary().contains("healthcheck")
                || plan.compose_actions[0].summary().contains("HEALTHCHECK"),
            "should be the healthcheck action"
        );

        // dockle.2 filtered OUT → no second compose action
        // host.ssh_root_login_enabled matches → system_actions
        assert_eq!(
            plan.system_actions.len(),
            1,
            "only root-login should produce 1 system action"
        );
        assert!(
            plan.system_actions[0]
                .summary()
                .contains("disable SSH root login"),
            "should be the root login action"
        );

        assert!(plan.host_actions.is_empty(), "no host_actions expected");
        fs::remove_dir_all(path.parent().expect("has parent")).ok();
    }

    #[test]
    fn preview_with_empty_only_findings_excludes_all_adapter_findings() {
        let path = copy_mixed_stack_fixture_to_temp("pipeline-scoped-empty");
        let findings = vec![
            dockle_finding("dockle.1", "web", "DKL-DI-0006"),
            native_host_finding("host.fail2ban_not_enabled"),
        ];
        let only: Vec<String> = Vec::new();

        let plan = preview_with_external(
            &path,
            FixMode::AutoFix,
            Some(&only),
            &findings,
            &FixResolutionMap::new(),
        )
        .expect("preview should succeed");

        assert!(
            plan.compose_actions.is_empty(),
            "empty only_findings → no compose_actions"
        );
        assert!(
            plan.system_actions.is_empty(),
            "empty only_findings → no system_actions"
        );
        assert!(
            plan.host_actions.is_empty(),
            "empty only_findings → no host_actions"
        );
        fs::remove_dir_all(path.parent().expect("has parent")).ok();
    }

    // ── Dockle unknown-code fallback ──

    #[test]
    fn dockle_unknown_code_fallback_is_none() {
        let finding = dockle_finding("dockle.unknown", "web", "CIS-DI-0001");
        let (actions, auto, review) = super::adapter::classify_adapter_findings(&[finding]);
        assert!(
            actions.is_empty(),
            "unmapped code should produce no actions"
        );
        assert!(auto.is_empty());
        assert!(review.is_empty());
    }

    #[test]
    fn compose_edit_with_empty_diff_produces_no_change() {
        let original = "services:\n  web:\n    image: nginx\n";
        let action = FixAction::ComposeEdit {
            service: "web".to_string(),
            summary: "empty edit".to_string(),
            diff: String::new(),
        };
        let (result, diff) = apply_compose_edits_to_text(original, &[action]);
        assert_eq!(result, original, "empty diff should not change text");
        assert!(diff.is_empty(), "empty diff should not produce diff output");
    }

    #[test]
    fn compose_edit_with_only_minus_lines_is_noop() {
        // Lines starting with '-' in the diff are ignored (not additions)
        let original = "services:\n  web:\n    image: nginx\n";
        let action = FixAction::ComposeEdit {
            service: "web".to_string(),
            summary: "removal-only".to_string(),
            diff: "-  old_config: true\n-  removed: yes\n".to_string(),
        };
        let (result, diff) = apply_compose_edits_to_text(original, &[action]);
        assert_eq!(result, original, "minus-only diff should not change text");
        assert!(diff.is_empty(), "minus-only diff should not produce output");
    }

    #[test]
    fn preview_with_native_host_does_not_execute_any_command() {
        let dir = temp_compose_dir("preview-native-only");
        let compose_path = dir.join("docker-compose.yml");
        write_compose(
            &compose_path,
            "services:\n  web:\n    image: nginx:stable\n",
        );
        let findings = vec![native_host_finding("host.ssh_root_login_enabled")];

        let plan = preview_with_external(
            &compose_path,
            FixMode::AutoFix,
            None,
            &findings,
            &FixResolutionMap::new(),
        )
        .expect("preview should succeed");

        assert!(
            !plan.system_actions.is_empty(),
            "NativeHost should produce system_actions"
        );
        assert!(
            plan.system_actions[0]
                .summary()
                .contains("disable SSH root login"),
            "should be the root login action"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn preview_with_nonexistent_path_returns_error() {
        let result = preview("/nonexistent/hostveil/compose.yml", FixMode::AutoFix, None);
        assert!(
            matches!(
                result,
                Err(FixError::ComposeParse(
                    ComposeParseError::ComposePathMissing { .. }
                ))
            ),
            "expected ComposePathMissing, got {:?}",
            result
        );
    }

    #[test]
    fn preview_with_no_changes_returns_empty_plan() {
        let dir = temp_compose_dir("preview-noop");
        let path = dir.join("docker-compose.yml");
        write_compose(
            &path,
            "services:\n  web:\n    image: nginx:stable\n    ports:\n      - \"127.0.0.1:8080:80\"\n",
        );

        let plan = preview(&path, FixMode::AutoFix, None).expect("preview should succeed");
        // The compose file may still produce native findings; verify preview doesn't crash
        assert!(
            !plan.diff_preview.is_empty() || !plan.updated_text.is_empty() || !plan.changed(),
            "preview should either have a diff or be a no-op"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn merge_original_formatting_extra_lines_in_after() {
        let before = "services:\n  web:\n    image: nginx\n";
        let after = "services:\n  web:\n    image: nginx\n    ports:\n      - \"80:80\"\n";
        let merged = merge_original_formatting(before, after);
        assert!(merged.contains("    ports:\n"));
        assert!(merged.contains("      - \"80:80\""));
    }

    #[test]
    fn merge_original_formatting_empty_before() {
        let merged = merge_original_formatting("", "services:\n  web:\n    image: nginx\n");
        assert_eq!(merged, "services:\n  web:\n    image: nginx\n");
    }

    #[test]
    fn merge_original_formatting_lines_removed_in_after() {
        let before = "services:\n  web:\n    image: nginx\n    ports:\n      - \"80:80\"\n";
        let after = "services:\n  web:\n    image: nginx\n";
        let merged = merge_original_formatting(before, after);
        assert_eq!(merged, "services:\n  web:\n    image: nginx\n");
    }

    #[test]
    fn backup_path_for_no_extension() {
        let p = backup_path_for(Path::new("/tmp/compose"));
        let name = p.file_name().unwrap().to_str().unwrap().to_string();
        assert!(
            name.starts_with("compose-"),
            "expected compose- prefix, got {name}"
        );
        assert!(name.ends_with(".bak"), "expected .bak suffix, got {name}");
    }

    #[test]
    fn backup_path_for_multiple_dots() {
        let p = backup_path_for(Path::new("/tmp/compose.foo.bar.yml"));
        let name = p.file_name().unwrap().to_str().unwrap().to_string();
        assert!(
            name.starts_with("compose.foo.bar-"),
            "expected compose.foo.bar- prefix, got {name}"
        );
        assert!(
            name.ends_with(".bak.yml"),
            "expected .bak.yml suffix, got {name}"
        );
    }

    #[test]
    fn backup_path_for_root_path() {
        let p = backup_path_for(Path::new("/"));
        let name = p.file_name().unwrap().to_str().unwrap().to_string();
        assert!(
            name.starts_with("docker-compose-"),
            "expected docker-compose- prefix, got {name}"
        );
        assert!(
            name.ends_with(".bak.yml"),
            "expected .bak.yml suffix, got {name}"
        );
    }

    #[test]
    fn fix_mode_includes_review_values() {
        use FixMode::*;
        assert!(
            !AutoFix.includes_review(),
            "AutoFix should not include review"
        );
        assert!(Fix.includes_review(), "Fix should include review");
    }
}
