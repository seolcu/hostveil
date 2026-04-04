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
            Self::ComposeParse(error) => write!(f, "{}", crate::i18n::tr_compose_parse_error(error)),
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

pub fn preview(path: impl AsRef<Path>, mode: FixMode) -> Result<FixPlan, FixError> {
    build_fix_plan(path.as_ref(), mode)
}

pub fn apply(path: impl AsRef<Path>, mode: FixMode) -> Result<FixPlan, FixError> {
    let mut plan = build_fix_plan(path.as_ref(), mode)?;
    if !plan.changed() {
        return Ok(plan);
    }

    let updated_text = render_updated_text(path.as_ref(), mode)?;
    let backup_path = backup_path_for(&plan.compose_file);
    fs::copy(&plan.compose_file, &backup_path)?;
    fs::write(&plan.compose_file, updated_text)?;
    plan.backup_path = Some(backup_path);
    Ok(plan)
}

fn build_fix_plan(path: &Path, mode: FixMode) -> Result<FixPlan, FixError> {
    let bundle = ComposeParser::load_bundle(path.to_path_buf(), false)?;
    let project = ComposeParser::parse_path_without_override(path.to_path_buf())?;
    let findings = RuleEngine.scan(&project);
    let findings_by_service = findings_by_service(&findings);

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
        let updated_text = dump_document(&document)?;
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

fn render_updated_text(path: &Path, mode: FixMode) -> Result<String, FixError> {
    let bundle = ComposeParser::load_bundle(path.to_path_buf(), false)?;
    let project = ComposeParser::parse_path_without_override(path.to_path_buf())?;
    let findings = RuleEngine.scan(&project);
    let findings_by_service = findings_by_service(&findings);

    let mut document = bundle.primary_document;
    apply_safe_fixes(&mut document, &findings_by_service);
    if mode == FixMode::Fix {
        apply_guided_fixes(&mut document, &findings_by_service);
    }

    dump_document(&document)
}

fn findings_by_service(findings: &[crate::domain::Finding]) -> BTreeMap<String, BTreeSet<String>> {
    let mut grouped = BTreeMap::<String, BTreeSet<String>>::new();

    for finding in findings {
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

        if finding_ids.contains("updates.no_tag")
            && let Some(image) = image_string(service)
            && is_safe_nginx_image(&image)
        {
            service.insert(
                yaml_key("image"),
                Value::String(format!("{image}:stable")),
            );
            applied.push(FixProposal {
                service: service_name.clone(),
                summary: t!("app.fix.safe_nginx_stable", service = service_name.as_str()).into_owned(),
            });
        }

        if !finding_ids.contains("exposure.public_binding") {
            continue;
        }

        let Some(ports) = service.get_mut(yaml_key("ports")) else {
            continue;
        };
        let Some(sequence) = ports.as_sequence_mut() else {
            continue;
        };

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
        if !finding_ids.contains("permissions.privileged") {
            continue;
        }

        let Some(service) = service_mapping_mut(services, service_name) else {
            continue;
        };
        let Some(privileged) = service.get(yaml_key("privileged")) else {
            continue;
        };
        if !yaml_truthy(privileged) {
            continue;
        }
        if !service_uses_low_port(service) {
            continue;
        }

        if matches!(service.get(yaml_key("cap_add")), Some(value) if !value.is_sequence()) {
            continue;
        }

        service.remove(yaml_key("privileged"));
        if service.get(yaml_key("cap_add")).is_none() {
            service.insert(yaml_key("cap_add"), Value::Sequence(Sequence::new()));
        }
        let Some(cap_add) = service.get_mut(yaml_key("cap_add")) else {
            continue;
        };
        let Some(capabilities) = cap_add.as_sequence_mut() else {
            continue;
        };

        if !capabilities.iter().any(|value| value.as_str() == Some("NET_BIND_SERVICE")) {
            capabilities.push(Value::String(String::from("NET_BIND_SERVICE")));
        }

        applied.push(FixProposal {
            service: service_name.clone(),
            summary: t!(
                "app.fix.guided_privileged_cap_add",
                service = service_name.as_str()
            )
            .into_owned(),
        });
    }

    applied
}

fn services_mapping_mut(document: &mut Value) -> Option<&mut Mapping> {
    document
        .as_mapping_mut()?
        .get_mut(yaml_key("services"))?
        .as_mapping_mut()
}

fn service_mapping_mut<'a>(services: &'a mut Mapping, service_name: &str) -> Option<&'a mut Mapping> {
    services.get_mut(yaml_key(service_name))?.as_mapping_mut()
}

fn yaml_key(key: &str) -> Value {
    Value::String(key.to_owned())
}

fn image_string(service: &Mapping) -> Option<String> {
    service.get(yaml_key("image"))?.as_str().map(str::to_owned)
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
    mapping.insert(yaml_key("host_ip"), Value::String(String::from("127.0.0.1")));
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
            host_port,
            container_port,
        } if matches!(host_ip.as_str(), "127.0.0.1" | "::1" | "localhost" | "[::1]") => None,
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
    let rendered = serde_yaml::to_string(document)
        .map_err(|error| FixError::Serialize(error.to_string()))?;
    Ok(rendered
        .strip_prefix("---\n")
        .unwrap_or(rendered.as_str())
        .to_owned())
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

    use super::{FixMode, apply, preview};

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

        let plan = preview(&path, FixMode::QuickFix).expect("quick-fix preview should succeed");

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
                "      - \"8080:80\"\n"
            ),
        );

        let plan = preview(&path, FixMode::Fix).expect("fix preview should succeed");

        assert!(plan.safe_applied.is_empty());
        assert_eq!(plan.guided_applied.len(), 1);
        assert!(plan.diff_preview.contains("cap_add"));
        assert!(plan.diff_preview.contains("NET_BIND_SERVICE"));

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

        let plan = apply(&path, FixMode::QuickFix).expect("quick-fix apply should succeed");
        let updated = fs::read_to_string(&path).expect("compose file should be readable");

        assert!(plan.backup_path.is_some());
        assert!(updated.contains("nginx:stable"));
        assert!(updated.contains("127.0.0.1:8080:80"));

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }
}
