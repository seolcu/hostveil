use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_yaml::{Mapping, Sequence, Value};

use crate::compose::{ComposeParseError, ComposeParser};
use crate::rules::RuleEngine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixMode {
    QuickFix,
    Fix,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixProposal {
    pub service: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FixPlan {
    pub compose_file: PathBuf,
    pub diff_preview: String,
    pub backup_path: Option<PathBuf>,
    pub safe_applied: Vec<FixProposal>,
    pub guided_applied: Vec<FixProposal>,
}

impl FixPlan {
    pub fn changed(&self) -> bool {
        !(self.safe_applied.is_empty() && self.guided_applied.is_empty())
    }
}

#[derive(Debug)]
pub enum FixError {
    ComposeParse(ComposeParseError),
    Io(io::Error),
    Serialize(String),
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
    build_fix_plan(path.as_ref(), mode, only_findings)
}

pub fn apply(
    path: impl AsRef<Path>,
    mode: FixMode,
    only_findings: Option<&[String]>,
) -> Result<FixPlan, FixError> {
    let mut plan = build_fix_plan(path.as_ref(), mode, only_findings)?;
    if !plan.changed() {
        return Ok(plan);
    }

    let updated_text = render_updated_text(path.as_ref(), mode, only_findings)?;
    let backup_path = backup_path_for(&plan.compose_file);
    fs::copy(&plan.compose_file, &backup_path)?;
    fs::write(&plan.compose_file, updated_text)?;
    plan.backup_path = Some(backup_path);
    Ok(plan)
}

fn build_fix_plan(
    path: &Path,
    mode: FixMode,
    only_findings: Option<&[String]>,
) -> Result<FixPlan, FixError> {
    let bundle = ComposeParser::load_bundle(path.to_path_buf(), false)?;
    let project = ComposeParser::parse_path_without_override(path.to_path_buf())?;
    let findings = RuleEngine.scan(&project);
    let findings_by_service = findings_by_service(&findings, only_findings);

    let mut document = bundle.primary_document.clone();
    let safe_applied = apply_safe_fixes(&mut document, &findings_by_service);
    let guided_applied = if mode == FixMode::Fix {
        apply_guided_fixes(&mut document, &findings_by_service)
    } else {
        Vec::new()
    };

    let diff_preview = if safe_applied.is_empty() && guided_applied.is_empty() {
        String::new()
    } else {
        let updated_text = render_document_like_original(&bundle.primary_text, &document)?;
        build_diff(&bundle.primary_path, &bundle.primary_text, &updated_text)
    };

    Ok(FixPlan {
        compose_file: bundle.primary_path,
        diff_preview,
        backup_path: None,
        safe_applied,
        guided_applied,
    })
}

fn render_updated_text(
    path: &Path,
    mode: FixMode,
    only_findings: Option<&[String]>,
) -> Result<String, FixError> {
    let bundle = ComposeParser::load_bundle(path.to_path_buf(), false)?;
    let project = ComposeParser::parse_path_without_override(path.to_path_buf())?;
    let findings = RuleEngine.scan(&project);
    let findings_by_service = findings_by_service(&findings, only_findings);

    let mut document = bundle.primary_document;
    apply_safe_fixes(&mut document, &findings_by_service);
    if mode == FixMode::Fix {
        apply_guided_fixes(&mut document, &findings_by_service);
    }

    render_document_like_original(&bundle.primary_text, &document)
}

fn render_document_like_original(
    original_text: &str,
    document: &Value,
) -> Result<String, FixError> {
    let rendered = dump_document(document)?;
    Ok(merge_original_formatting(original_text, &rendered))
}

fn findings_by_service(
    findings: &[crate::domain::Finding],
    filter: Option<&[String]>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut grouped = BTreeMap::<String, BTreeSet<String>>::new();

    for finding in findings {
        if let Some(filter) = filter {
            if !filter.contains(&finding.id) {
                continue;
            }
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

fn apply_safe_fixes(
    document: &mut Value,
    findings_by_service: &BTreeMap<String, BTreeSet<String>>,
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
            applied.push(FixProposal {
                service: service_name.clone(),
                summary: t!("app.fix.safe_nginx_stable", service = service_name.as_str())
                    .into_owned(),
            });
        }

        if finding_ids.contains("service.vaultwarden.insecure_domain")
            && harden_vaultwarden_domain(service)
        {
            applied.push(FixProposal {
                service: service_name.clone(),
                summary: t!(
                    "app.fix.safe_vaultwarden_domain_https",
                    service = service_name.as_str()
                )
                .into_owned(),
            });
        }

        if finding_ids.contains("service.jellyfin.insecure_published_url")
            && harden_jellyfin_published_url(service)
        {
            applied.push(FixProposal {
                service: service_name.clone(),
                summary: t!(
                    "app.fix.safe_jellyfin_published_url_https",
                    service = service_name.as_str()
                )
                .into_owned(),
            });
        }

        if finding_ids.contains("service.nextcloud.insecure_overwriteprotocol")
            && harden_nextcloud_overwriteprotocol(service)
        {
            applied.push(FixProposal {
                service: service_name.clone(),
                summary: t!(
                    "app.fix.safe_nextcloud_overwriteprotocol_https",
                    service = service_name.as_str()
                )
                .into_owned(),
            });
        }

        if finding_ids.contains("service.nextcloud.wildcard_trusted_domains")
            && harden_nextcloud_trusted_domains(service)
        {
            applied.push(FixProposal {
                service: service_name.clone(),
                summary: t!(
                    "app.fix.safe_nextcloud_trusted_domains_wildcard",
                    service = service_name.as_str()
                )
                .into_owned(),
            });
        }

        if finding_ids.contains("exposure.public_binding")
            && let Some(ports) = service.get_mut(yaml_key("ports"))
            && let Some(sequence) = ports.as_sequence_mut()
        {
            for port in sequence.iter_mut() {
                let Some(before) = rewrite_public_port(port) else {
                    continue;
                };
                applied.push(FixProposal {
                    service: service_name.clone(),
                    summary: t!(
                        "app.fix.safe_bind_localhost",
                        service = service_name.as_str(),
                        port = before.as_str()
                    )
                    .into_owned(),
                });
            }
        }

        if finding_ids.contains("permissions.sensitive_mount")
            && let Some(volumes) = service.get_mut(yaml_key("volumes"))
            && let Some(sequence) = volumes.as_sequence_mut()
        {
            for volume in sequence.iter_mut() {
                if let Some(path) = rewrite_sensitive_mount_readonly(volume) {
                    applied.push(FixProposal {
                        service: service_name.clone(),
                        summary: t!(
                            "app.fix.safe_mount_readonly",
                            service = service_name.as_str(),
                            path = path.as_str()
                        )
                        .into_owned(),
                    });
                }
            }
        }
    }

    applied
}

fn apply_guided_fixes(
    document: &mut Value,
    findings_by_service: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<FixProposal> {
    let Some(services) = services_mapping_mut(document) else {
        return Vec::new();
    };

    let mut applied = Vec::new();

    for (service_name, finding_ids) in findings_by_service {
        if finding_ids.contains("permissions.privileged")
            && let Some(service) = service_mapping_mut(services, service_name)
            && apply_guided_privileged_low_port_fix(service)
        {
            applied.push(FixProposal {
                service: service_name.clone(),
                summary: t!(
                    "app.fix.guided_privileged_cap_add",
                    service = service_name.as_str()
                )
                .into_owned(),
            });
        }

        if finding_ids.contains("service.vaultwarden.signups_enabled")
            && let Some(service) = service_mapping_mut(services, service_name)
            && update_environment_value(service, "SIGNUPS_ALLOWED", "false", false)
        {
            applied.push(FixProposal {
                service: service_name.clone(),
                summary: t!(
                    "app.fix.guided_vaultwarden_signups",
                    service = service_name.as_str()
                )
                .into_owned(),
            });
        }

        if finding_ids.contains("service.gitea.inline_security_secrets")
            && let Some(service) = service_mapping_mut(services, service_name)
            && externalize_gitea_security_env(service)
        {
            applied.push(FixProposal {
                service: service_name.clone(),
                summary: t!(
                    "app.fix.guided_gitea_externalize_secrets",
                    service = service_name.as_str()
                )
                .into_owned(),
            });
        }

        if finding_ids.contains("updates.latest_tag")
            && let Some(service) = service_mapping_mut(services, service_name)
            && let Some(image) = image_string(service)
            && let Some(stable_image) = stable_nginx_image_for_findings(&image, finding_ids)
            && image != stable_image
        {
            service.insert(yaml_key("image"), Value::String(stable_image));
            applied.push(FixProposal {
                service: service_name.clone(),
                summary: t!(
                    "app.fix.guided_nginx_stable",
                    service = service_name.as_str()
                )
                .into_owned(),
            });
        }

        if finding_ids.contains("permissions.implicit_root")
            && let Some(service) = service_mapping_mut(services, service_name)
            && apply_harden_implicit_root(service)
        {
            applied.push(FixProposal {
                service: service_name.clone(),
                summary: t!(
                    "app.fix.guided_non_root_user",
                    service = service_name.as_str()
                )
                .into_owned(),
            });
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

fn apply_guided_privileged_low_port_fix(service: &mut Mapping) -> bool {
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

    true
}

fn externalize_gitea_security_env(service: &mut Mapping) -> bool {
    let mut changed = false;
    for key in [
        "GITEA__security__SECRET_KEY",
        "GITEA__security__INTERNAL_TOKEN",
    ] {
        let placeholder = format!("${{{key}}}");
        changed |= update_environment_value(service, key, &placeholder, false);
    }

    changed
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
    match path.extension().and_then(|value| value.to_str()) {
        Some(extension) => path.with_extension(format!("{extension}.bak")),
        None => path.with_extension("bak"),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{FixMode, apply, merge_original_formatting, preview};

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

    #[test]
    fn previews_quick_fix_changes_for_mixed_stack_fixture() {
        let path = fixture("mixed-stack");

        let plan = preview(&path, FixMode::QuickFix, None).expect("quick-fix preview should succeed");

        assert_eq!(plan.safe_applied.len(), 2);
        assert!(plan.guided_applied.is_empty());
        assert!(plan.diff_preview.contains("127.0.0.1:8080:80"));
        assert!(plan.diff_preview.contains("127.0.0.1:8081:8080"));
    }

    #[test]
    fn previews_quick_fix_noop_for_hardened_stack_fixture() {
        let path = fixture("hardened-stack.yml");

        let plan = preview(&path, FixMode::QuickFix, None).expect("quick-fix preview should succeed");

        assert!(plan.safe_applied.is_empty());
        assert!(plan.guided_applied.is_empty());
        assert!(plan.diff_preview.is_empty());
    }

    #[test]
    fn previews_fix_changes_for_mixed_stack_fixture() {
        let path = fixture("mixed-stack");

        let plan = preview(&path, FixMode::Fix, None).expect("fix preview should succeed");

        assert_eq!(plan.safe_applied.len(), 2);
        assert_eq!(plan.guided_applied.len(), 1); // implicit_root for postgres
        assert!(plan.diff_preview.contains("127.0.0.1:8080:80"));
        assert!(plan.diff_preview.contains("127.0.0.1:8081:8080"));
    }

    #[test]
    fn previews_fix_noop_for_hardened_stack_fixture() {
        let path = fixture("hardened-stack.yml");

        let plan = preview(&path, FixMode::Fix, None).expect("fix preview should succeed");

        assert!(plan.safe_applied.is_empty());
        assert!(plan.guided_applied.is_empty());
        assert!(plan.diff_preview.is_empty());
    }

    #[test]
    fn apply_quick_fix_on_mixed_stack_fixture_is_idempotent() {
        let compose_path = copy_mixed_stack_fixture_to_temp("mixed-stack-apply-idempotent");
        let root = compose_path
            .parent()
            .expect("fixture root should exist")
            .to_path_buf();

        let first = apply(&compose_path, FixMode::QuickFix, None).expect("first apply should succeed");
        let second = apply(&compose_path, FixMode::QuickFix, None).expect("second apply should succeed");

        assert!(first.changed());
        assert_eq!(first.safe_applied.len(), 2);
        assert!(first.backup_path.is_some());

        assert!(second.safe_applied.is_empty());
        assert!(second.guided_applied.is_empty());
        assert!(second.backup_path.is_none());

        let env_text = fs::read_to_string(root.join("postgres.env"))
            .expect("copied env fixture should be readable");
        assert_eq!(env_text, "POSTGRES_PASSWORD=changeme\n");

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

        let plan = preview(&path, FixMode::QuickFix, None).expect("quick-fix preview should succeed");

        assert_eq!(plan.safe_applied.len(), 2);
        assert!(plan.guided_applied.is_empty());
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
                "    privileged: true\n",
                "    ports:\n",
                "      - \"127.0.0.1:8080:80\"\n"
            ),
        );

        let plan = preview(&path, FixMode::Fix, None).expect("fix preview should succeed");

        assert!(plan.safe_applied.is_empty());
        assert_eq!(plan.guided_applied.len(), 2); // privileged + implicit_root
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
                "    ports:\n",
                "      - \"127.0.0.1:8080:80\"\n"
            ),
        );

        let plan = preview(&path, FixMode::QuickFix, None).expect("quick-fix preview should succeed");

        assert_eq!(plan.safe_applied.len(), 1);
        assert!(plan.guided_applied.is_empty());
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
                "    ports:\n",
                "      - \"9090:90/udp\"\n"
            ),
        );

        let plan = preview(&path, FixMode::QuickFix, None).expect("quick-fix preview should succeed");

        assert_eq!(plan.safe_applied.len(), 2);
        assert!(plan.guided_applied.is_empty());
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
                "      - \"8080:80\"\n",
                "    environment:\n",
                "      SIGNUPS_ALLOWED: true\n"
            ),
        );

        let plan = preview(&path, FixMode::Fix, None).expect("fix preview should succeed");

        assert_eq!(plan.guided_applied.len(), 2); // signups_enabled + implicit_root
        assert!(
            plan.guided_applied
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
                "    ports:\n",
                "      - \"3000:3000\"\n",
                "      - \"2222:22\"\n",
                "    environment:\n",
                "      - GITEA__security__SECRET_KEY=replace-me\n",
                "      - GITEA__security__INTERNAL_TOKEN=replace-me-too\n"
            ),
        );

        let plan = preview(&path, FixMode::Fix, None).expect("fix preview should succeed");

        assert_eq!(plan.guided_applied.len(), 2); // gitea secrets + implicit_root
        assert!(
            plan.guided_applied
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
    fn previews_quick_fix_for_service_specific_hardening() {
        let root = temp_compose_dir("quick-service-hardening");
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
                "      NEXTCLOUD_TRUSTED_DOMAINS: \"cloud.example.com, *.example.com, 0.0.0.0\"\n"
            ),
        );

        let plan = preview(&path, FixMode::QuickFix, None).expect("quick-fix preview should succeed");

        assert_eq!(plan.safe_applied.len(), 7);
        assert!(plan.guided_applied.is_empty());
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
                "    ports:\n",
                "      - \"127.0.0.1:8080:80\"\n",
                "    environment:\n",
                "      DOMAIN: https://vault.example.com\n",
                "  jellyfin:\n",
                "    image: jellyfin/jellyfin:10.9.11\n",
                "    ports:\n",
                "      - \"127.0.0.1:8096:8096\"\n",
                "    environment:\n",
                "      JELLYFIN_PublishedServerUrl: https://media.example.com\n",
                "  nextcloud:\n",
                "    image: nextcloud:31.0.0\n",
                "    ports:\n",
                "      - \"127.0.0.1:8081:80\"\n",
                "    environment:\n",
                "      OVERWRITEPROTOCOL: https\n",
                "      NEXTCLOUD_TRUSTED_DOMAINS: cloud.example.com cloud.internal\n"
            ),
        );

        let plan = preview(&path, FixMode::QuickFix, None).expect("quick-fix preview should succeed");

        assert!(plan.safe_applied.is_empty());
        assert!(plan.guided_applied.is_empty());
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
                "    ports:\n",
                "      - \"127.0.0.1:8081:80\"\n",
                "    environment:\n",
                "      NEXTCLOUD_TRUSTED_DOMAINS: \"*\"\n"
            ),
        );

        let plan = preview(&path, FixMode::QuickFix, None).expect("quick-fix preview should succeed");

        assert!(plan.safe_applied.is_empty());
        assert!(plan.guided_applied.is_empty());
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

        let first = apply(&path, FixMode::QuickFix, None).expect("first apply should succeed");
        let second = apply(&path, FixMode::QuickFix, None).expect("second apply should succeed");

        assert!(first.changed());
        assert!(first.backup_path.is_some());
        assert!(second.safe_applied.is_empty());
        assert!(second.guided_applied.is_empty());
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

        let plan = apply(&path, FixMode::QuickFix, None).expect("quick-fix apply should succeed");
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

        let plan = preview(&path, FixMode::QuickFix, None).expect("quick-fix preview should succeed");
        assert!(!plan.diff_preview.contains("-      - PUID=1000"));
        assert!(!plan.diff_preview.contains("+    - PUID=1000"));
        assert!(
            plan.diff_preview
                .contains("+      - \"127.0.0.1:8096:8096\"")
        );

        apply(&path, FixMode::QuickFix, None).expect("quick-fix apply should succeed");
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

        let plan = preview(&path, FixMode::QuickFix, None).expect("quick-fix preview should succeed");

        assert!(plan.diff_preview.contains("OVERWRITEPROTOCOL: 'https'"));
        assert!(
            plan.diff_preview
                .contains("NEXTCLOUD_TRUSTED_DOMAINS: 'cloud.example.com'")
        );

        apply(&path, FixMode::QuickFix, None).expect("quick-fix apply should succeed");
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
        ).expect("fixture should be written");
        
        // This has both updates.latest_tag (safe) and permissions.privileged (guided)
        let only_latest_tag = Some(vec!["updates.latest_tag".to_string()]);
        let plan = preview(&path, FixMode::Fix, only_latest_tag.as_deref()).expect("preview should succeed");
        
        assert_eq!(plan.safe_applied.len(), 1);
        assert_eq!(plan.guided_applied.len(), 0);
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
                "    volumes:\n",
                "      - /etc/shadow:/etc/shadow\n",
                "      - /var/run/docker.sock:/var/run/docker.sock:rw\n",
                "      - type: bind\n",
                "        source: /etc/passwd\n",
                "        target: /etc/passwd\n"
            ),
        );

        let plan = preview(&path, FixMode::QuickFix, None).expect("quick-fix preview should succeed");

        assert_eq!(plan.safe_applied.len(), 3);
        assert!(plan.diff_preview.contains("/etc/shadow:/etc/shadow:ro"));
        assert!(plan.diff_preview.contains("/var/run/docker.sock:/var/run/docker.sock:ro"));
        assert!(plan.diff_preview.contains("read_only: true"));

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }
}
