use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use serde_yaml::{Mapping, Value};

use super::{ComposeBundle, ComposeProject, ComposeService, PortBinding, VolumeMount};

const DEFAULT_COMPOSE_FILES: [&str; 2] = ["docker-compose.yml", "docker-compose.yaml"];
const DEFAULT_OVERRIDE_FILES: [&str; 2] = [
    "docker-compose.override.yml",
    "docker-compose.override.yaml",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeParser;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposeParseError {
    ComposePathMissing { path: PathBuf },
    ComposeFileNotFound { path: PathBuf },
    MalformedYaml { path: PathBuf, message: String },
    MissingServices { path: PathBuf },
    Io { path: PathBuf, message: String },
}

impl fmt::Display for ComposeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ComposePathMissing { path } => {
                write!(f, "compose path does not exist: {}", path.display())
            }
            Self::ComposeFileNotFound { path } => write!(
                f,
                "compose file was not found in directory: {}",
                path.display()
            ),
            Self::MalformedYaml { path, message } => {
                write!(f, "failed to parse YAML in {}: {message}", path.display())
            }
            Self::MissingServices { path } => {
                write!(f, "no services were found in {}", path.display())
            }
            Self::Io { path, message } => {
                write!(f, "failed to read {}: {message}", path.display())
            }
        }
    }
}

impl std::error::Error for ComposeParseError {}

impl ComposeParser {
    pub fn load_bundle(
        path: impl Into<PathBuf>,
        include_override: bool,
    ) -> Result<ComposeBundle, ComposeParseError> {
        let primary_path = resolve_compose_path(&path.into())?;
        let override_paths = if include_override {
            discover_override_paths(&primary_path)
        } else {
            Vec::new()
        };

        let primary_text = read_text(&primary_path)?;
        let primary_document = load_yaml(&primary_path, &primary_text)?;

        let mut override_documents = Vec::with_capacity(override_paths.len());
        for override_path in &override_paths {
            let text = read_text(override_path)?;
            override_documents.push(load_yaml(override_path, &text)?);
        }

        Ok(ComposeBundle {
            primary_path,
            override_paths,
            primary_document,
            override_documents,
            primary_text,
        })
    }

    pub fn parse_path(path: impl Into<PathBuf>) -> Result<ComposeProject, ComposeParseError> {
        Self::parse_path_with_override(path, true)
    }

    pub fn parse_path_without_override(
        path: impl Into<PathBuf>,
    ) -> Result<ComposeProject, ComposeParseError> {
        Self::parse_path_with_override(path, false)
    }

    pub fn parse_path_with_override(
        path: impl Into<PathBuf>,
        include_override: bool,
    ) -> Result<ComposeProject, ComposeParseError> {
        let bundle = Self::load_bundle(path, include_override)?;
        let services = merge_services(&bundle);

        if services.is_empty() {
            return Err(ComposeParseError::MissingServices {
                path: bundle.primary_path.clone(),
            });
        }

        Ok(ComposeProject {
            primary_file: bundle.primary_path.clone(),
            loaded_files: bundle.loaded_files(),
            services,
            working_dir: bundle
                .primary_path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from(".")),
        })
    }
}

#[derive(Debug, Default)]
struct ServiceAccumulator {
    image: Option<String>,
    ports: Vec<Value>,
    volumes: Vec<Value>,
    environment: BTreeMap<String, Option<String>>,
    env_files: Vec<String>,
    networks: Vec<String>,
    user: Option<String>,
    privileged: bool,
    cap_add: Vec<String>,
    network_mode: Option<String>,
    source_files: Vec<PathBuf>,
}

impl ServiceAccumulator {
    fn apply_service(&mut self, source: &Mapping, source_file: &Path) {
        self.source_files.push(source_file.to_path_buf());

        if let Some(value) = mapping_get(source, "image") {
            self.image = coerce_string(value);
        }
        if let Some(value) = mapping_get(source, "ports") {
            self.ports.extend(coerce_list(value));
        }
        if let Some(value) = mapping_get(source, "volumes") {
            self.volumes.extend(coerce_list(value));
        }
        if let Some(value) = mapping_get(source, "environment") {
            self.environment.extend(coerce_environment(value));
        }
        if let Some(value) = mapping_get(source, "env_file") {
            self.env_files.extend(coerce_env_files(value));
        }
        if let Some(value) = mapping_get(source, "networks") {
            for network in coerce_networks(value) {
                if !self.networks.contains(&network) {
                    self.networks.push(network);
                }
            }
        }
        if let Some(value) = mapping_get(source, "user") {
            self.user = coerce_string(value);
        }
        if let Some(value) = mapping_get(source, "privileged") {
            self.privileged = coerce_bool(value);
        }
        if let Some(value) = mapping_get(source, "cap_add") {
            self.cap_add.extend(coerce_string_list(value));
        }
        if let Some(value) = mapping_get(source, "network_mode") {
            self.network_mode = coerce_string(value);
        }
    }

    fn build(self, name: String) -> ComposeService {
        ComposeService {
            name,
            image: self.image,
            ports: parse_ports(&self.ports),
            volumes: parse_volumes(&self.volumes),
            environment: self.environment,
            env_files: self.env_files,
            networks: self.networks,
            user: self.user,
            privileged: self.privileged,
            cap_add: self.cap_add,
            network_mode: self.network_mode,
            source_files: self.source_files,
        }
    }
}

fn resolve_compose_path(path: &Path) -> Result<PathBuf, ComposeParseError> {
    if !path.exists() {
        return Err(ComposeParseError::ComposePathMissing {
            path: path.to_path_buf(),
        });
    }

    if path.is_dir() {
        for filename in DEFAULT_COMPOSE_FILES {
            let candidate = path.join(filename);
            if candidate.exists() {
                return Ok(candidate);
            }
        }

        return Err(ComposeParseError::ComposeFileNotFound {
            path: path.to_path_buf(),
        });
    }

    Ok(path.to_path_buf())
}

fn discover_override_paths(primary_path: &Path) -> Vec<PathBuf> {
    let mut overrides = Vec::new();

    for filename in DEFAULT_OVERRIDE_FILES {
        let candidate = primary_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(filename);
        if candidate.exists() && candidate != primary_path {
            overrides.push(candidate);
        }
    }

    overrides
}

fn read_text(path: &Path) -> Result<String, ComposeParseError> {
    fs::read_to_string(path).map_err(|error| ComposeParseError::Io {
        path: path.to_path_buf(),
        message: error.to_string(),
    })
}

fn load_yaml(path: &Path, text: &str) -> Result<Value, ComposeParseError> {
    match serde_yaml::from_str::<Value>(text) {
        Ok(Value::Null) => Ok(Value::Mapping(Mapping::new())),
        Ok(Value::Mapping(mapping)) => Ok(Value::Mapping(mapping)),
        Ok(_) => Err(ComposeParseError::MalformedYaml {
            path: path.to_path_buf(),
            message: String::from("top-level mapping expected"),
        }),
        Err(error) => Err(ComposeParseError::MalformedYaml {
            path: path.to_path_buf(),
            message: error.to_string(),
        }),
    }
}

fn merge_services(bundle: &ComposeBundle) -> IndexMap<String, ComposeService> {
    let mut merged = IndexMap::<String, ServiceAccumulator>::new();

    for (source_file, document) in service_sources(bundle) {
        let Some(services) = top_level_services(document) else {
            continue;
        };

        for (service_name, service_value) in services {
            let Some(service_data) = service_value.as_mapping() else {
                continue;
            };

            let key = yaml_value_to_string(service_name);
            merged
                .entry(key)
                .or_default()
                .apply_service(service_data, source_file);
        }
    }

    merged
        .into_iter()
        .map(|(name, service)| {
            let built = service.build(name.clone());
            (name, built)
        })
        .collect()
}

fn service_sources(bundle: &ComposeBundle) -> Vec<(&Path, &Value)> {
    let mut sources = Vec::with_capacity(1 + bundle.override_paths.len());
    sources.push((bundle.primary_path.as_path(), &bundle.primary_document));

    for (path, document) in bundle
        .override_paths
        .iter()
        .zip(bundle.override_documents.iter())
    {
        sources.push((path.as_path(), document));
    }

    sources
}

fn top_level_services(document: &Value) -> Option<&Mapping> {
    document
        .as_mapping()
        .and_then(|mapping| mapping_get(mapping, "services"))
        .and_then(Value::as_mapping)
}

fn mapping_get<'a>(mapping: &'a Mapping, key: &str) -> Option<&'a Value> {
    mapping.get(Value::String(key.to_owned()))
}

fn coerce_list(value: &Value) -> Vec<Value> {
    match value {
        Value::Null => Vec::new(),
        Value::Sequence(sequence) => sequence.clone(),
        other => vec![other.clone()],
    }
}

fn coerce_string(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        other => Some(yaml_value_to_string(other)),
    }
}

fn coerce_bool(value: &Value) -> bool {
    match value {
        Value::Bool(value) => *value,
        Value::Number(number) => number.as_i64().map(|value| value != 0).unwrap_or(true),
        Value::String(value) => {
            let normalized = value.trim().to_ascii_lowercase();
            matches!(normalized.as_str(), "true" | "yes" | "on" | "1")
        }
        Value::Null => false,
        _ => true,
    }
}

fn coerce_string_list(value: &Value) -> Vec<String> {
    coerce_list(value)
        .into_iter()
        .map(|item| yaml_value_to_string(&item))
        .collect()
}

fn coerce_environment(value: &Value) -> BTreeMap<String, Option<String>> {
    let mut environment = BTreeMap::new();

    match value {
        Value::Mapping(mapping) => {
            for (key, item) in mapping {
                environment.insert(yaml_value_to_string(key), coerce_string(item));
            }
        }
        Value::Sequence(sequence) => {
            for item in sequence {
                let Value::String(item) = item else {
                    continue;
                };

                if let Some((key, raw_value)) = item.split_once('=') {
                    environment.insert(key.to_owned(), Some(raw_value.to_owned()));
                } else {
                    environment.insert(item.clone(), None);
                }
            }
        }
        _ => {}
    }

    environment
}

fn coerce_env_files(value: &Value) -> Vec<String> {
    coerce_list(value)
        .into_iter()
        .map(|item| yaml_value_to_string(&item))
        .collect()
}

fn coerce_networks(value: &Value) -> Vec<String> {
    match value {
        Value::Null => Vec::new(),
        Value::Mapping(mapping) => mapping.keys().map(yaml_value_to_string).collect(),
        Value::Sequence(sequence) => sequence.iter().map(yaml_value_to_string).collect(),
        other => vec![yaml_value_to_string(other)],
    }
}

fn parse_ports(values: &[Value]) -> Vec<PortBinding> {
    values
        .iter()
        .filter_map(|item| match item {
            Value::Mapping(mapping) => Some(parse_object_port(mapping, item)),
            Value::String(spec) => Some(parse_short_port(spec)),
            _ => None,
        })
        .collect()
}

fn parse_object_port(mapping: &Mapping, raw: &Value) -> PortBinding {
    PortBinding {
        raw: render_yaml_value(raw),
        host_ip: mapping_get(mapping, "host_ip").and_then(coerce_string),
        host_port: mapping_get(mapping, "published").and_then(coerce_string),
        container_port: mapping_get(mapping, "target")
            .and_then(coerce_string)
            .unwrap_or_default(),
        protocol: mapping_get(mapping, "protocol")
            .and_then(coerce_string)
            .unwrap_or_else(|| String::from("tcp")),
        short_syntax: false,
    }
}

fn parse_short_port(spec: &str) -> PortBinding {
    let (base, protocol) = split_protocol(spec);
    let parts: Vec<&str> = base.split(':').collect();

    let (host_ip, host_port, container_port) = match parts.as_slice() {
        [container_port] => (None, None, (*container_port).to_owned()),
        [host_port, container_port] => (
            None,
            Some((*host_port).to_owned()),
            (*container_port).to_owned(),
        ),
        [host_ip, host_port, container_port] => (
            Some((*host_ip).to_owned()),
            Some((*host_port).to_owned()),
            (*container_port).to_owned(),
        ),
        _ => (
            parts.first().map(|value| (*value).to_owned()),
            parts
                .get(parts.len().saturating_sub(2))
                .map(|value| (*value).to_owned()),
            parts.last().copied().unwrap_or_default().to_owned(),
        ),
    };

    PortBinding {
        raw: spec.to_owned(),
        host_ip,
        host_port,
        container_port,
        protocol,
        short_syntax: true,
    }
}

fn split_protocol(port_spec: &str) -> (String, String) {
    match port_spec.rsplit_once('/') {
        Some((base, protocol)) => (base.to_owned(), protocol.to_owned()),
        None => (port_spec.to_owned(), String::from("tcp")),
    }
}

fn parse_volumes(values: &[Value]) -> Vec<VolumeMount> {
    values
        .iter()
        .filter_map(|item| match item {
            Value::Mapping(mapping) => Some(parse_object_volume(mapping, item)),
            Value::String(spec) => Some(parse_short_volume(spec)),
            _ => None,
        })
        .collect()
}

fn parse_object_volume(mapping: &Mapping, raw: &Value) -> VolumeMount {
    let read_only = mapping_get(mapping, "read_only")
        .map(coerce_bool)
        .unwrap_or(false);

    VolumeMount {
        raw: render_yaml_value(raw),
        source: mapping_get(mapping, "source").and_then(coerce_string),
        target: mapping_get(mapping, "target").and_then(coerce_string),
        mode: read_only.then(|| String::from("ro")),
        mount_type: mapping_get(mapping, "type")
            .and_then(coerce_string)
            .unwrap_or_else(|| String::from("volume")),
    }
}

fn parse_short_volume(spec: &str) -> VolumeMount {
    let parts: Vec<&str> = spec.split(':').collect();

    let source = if parts.len() >= 2 {
        Some(parts[0].to_owned())
    } else {
        None
    };
    let target = if parts.len() >= 2 {
        Some(parts[1].to_owned())
    } else {
        None
    };
    let mode = if parts.len() >= 3 {
        Some(parts[2].to_owned())
    } else {
        None
    };
    let mount_type = detect_mount_type(source.as_deref());

    VolumeMount {
        raw: spec.to_owned(),
        source,
        target,
        mode,
        mount_type,
    }
}

fn detect_mount_type(source: Option<&str>) -> String {
    match source {
        None | Some("") => String::from("anonymous"),
        Some(source)
            if source.starts_with('/')
                || source.starts_with("./")
                || source.starts_with("../")
                || source.starts_with("~/") =>
        {
            String::from("bind")
        }
        Some(_) => String::from("volume"),
    }
}

fn yaml_value_to_string(value: &Value) -> String {
    match value {
        Value::Null => String::from("null"),
        Value::Bool(value) => value.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(value) => value.clone(),
        Value::Sequence(_) | Value::Mapping(_) | Value::Tagged(_) => render_yaml_value(value),
    }
}

fn render_yaml_value(value: &Value) -> String {
    serde_yaml::to_string(value)
        .unwrap_or_else(|_| format!("{value:?}"))
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{ComposeParseError, ComposeParser, detect_mount_type, split_protocol};

    fn parser_fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../proto/tests/fixtures/parser")
            .canonicalize()
            .expect("parser fixture root should exist")
    }

    fn temp_compose_dir(test_name: &str) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hostveil-rust-parser-{test_name}-{}-{timestamp}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temporary directory should be created");
        path
    }

    #[test]
    fn parse_path_merges_override_values() {
        let fixture = parser_fixture_root().join("docker-compose.yml");

        let project = ComposeParser::parse_path(&fixture).expect("project should parse");

        let web = project
            .services
            .get("web")
            .expect("web service should exist");
        let app = project
            .services
            .get("app")
            .expect("app service should exist");

        assert_eq!(project.loaded_files.len(), 2);
        assert_eq!(web.image.as_deref(), Some("nginx"));
        assert_eq!(
            web.ports
                .iter()
                .map(|port| port.raw.as_str())
                .collect::<Vec<_>>(),
            vec!["8080:80", "127.0.0.1:8443:443"]
        );
        assert_eq!(
            web.environment
                .get("APP_ENV")
                .and_then(|value| value.as_deref()),
            Some("production")
        );
        assert_eq!(
            web.environment
                .get("SHARED")
                .and_then(|value| value.as_deref()),
            Some("override")
        );
        assert_eq!(
            web.environment
                .get("DEBUG")
                .and_then(|value| value.as_deref()),
            Some("true")
        );
        assert!(app.privileged);
        assert_eq!(app.cap_add, vec![String::from("NET_ADMIN")]);
    }

    #[test]
    fn parse_path_accepts_directory_path() {
        let project =
            ComposeParser::parse_path(parser_fixture_root()).expect("project should parse");

        assert_eq!(
            project
                .primary_file
                .file_name()
                .and_then(|value| value.to_str()),
            Some("docker-compose.yml")
        );
    }

    #[test]
    fn load_bundle_preserves_primary_text() {
        let bundle =
            ComposeParser::load_bundle(parser_fixture_root().join("docker-compose.yml"), true)
                .expect("bundle should load");

        assert!(bundle.primary_text.contains("services:"));
        assert_eq!(
            bundle.override_paths[0]
                .file_name()
                .and_then(|value| value.to_str()),
            Some("docker-compose.override.yml")
        );
    }

    #[test]
    fn parse_path_reports_missing_path() {
        let error = ComposeParser::parse_path(parser_fixture_root().join("missing.yml"))
            .expect_err("missing path should fail");

        assert!(matches!(
            error,
            ComposeParseError::ComposePathMissing { .. }
        ));
    }

    #[test]
    fn parse_path_reports_malformed_yaml() {
        let temp_dir = temp_compose_dir("malformed");
        let path = temp_dir.join("docker-compose.yml");
        fs::write(&path, "services:\n  api: [\n").expect("fixture should be written");

        let error = ComposeParser::parse_path(&path).expect_err("malformed yaml should fail");

        assert!(matches!(error, ComposeParseError::MalformedYaml { .. }));

        fs::remove_dir_all(temp_dir).expect("temporary directory should be removed");
    }

    #[test]
    fn parse_path_reports_missing_services() {
        let temp_dir = temp_compose_dir("missing-services");
        let path = temp_dir.join("docker-compose.yml");
        fs::write(&path, "name: demo\n").expect("fixture should be written");

        let error = ComposeParser::parse_path(&path).expect_err("missing services should fail");

        assert!(matches!(error, ComposeParseError::MissingServices { .. }));

        fs::remove_dir_all(temp_dir).expect("temporary directory should be removed");
    }

    #[test]
    fn parse_path_without_override_keeps_primary_only() {
        let fixture = parser_fixture_root().join("docker-compose.yml");

        let project = ComposeParser::parse_path_without_override(&fixture)
            .expect("project should parse without override");
        let web = project
            .services
            .get("web")
            .expect("web service should exist");
        let app = project
            .services
            .get("app")
            .expect("app service should exist");

        assert_eq!(project.loaded_files.len(), 1);
        assert_eq!(web.ports.len(), 1);
        assert!(!app.privileged);
    }

    #[test]
    fn parser_normalizes_environment_ports_and_volumes() {
        let temp_dir = temp_compose_dir("normalization");
        let path = temp_dir.join("docker-compose.yml");

        fs::write(
            &path,
            concat!(
                "services:\n",
                "  demo:\n",
                "    image: example/demo\n",
                "    environment:\n",
                "      - APP_ENV=dev\n",
                "      - FLAG\n",
                "    ports:\n",
                "      - target: 8080\n",
                "        published: 18080\n",
                "        protocol: tcp\n",
                "        host_ip: 127.0.0.1\n",
                "      - \"9090:90/udp\"\n",
                "    volumes:\n",
                "      - type: bind\n",
                "        source: ./data\n",
                "        target: /data\n",
                "        read_only: true\n",
                "      - cache:/cache\n"
            ),
        )
        .expect("fixture should be written");

        let project = ComposeParser::parse_path(&path).expect("project should parse");
        let demo = project
            .services
            .get("demo")
            .expect("demo service should exist");

        assert_eq!(
            demo.environment
                .get("APP_ENV")
                .and_then(|value| value.as_deref()),
            Some("dev")
        );
        assert_eq!(demo.environment.get("FLAG"), Some(&None));
        assert_eq!(demo.ports[0].host_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(demo.ports[0].host_port.as_deref(), Some("18080"));
        assert_eq!(demo.ports[0].container_port, "8080");
        assert!(!demo.ports[0].short_syntax);
        assert_eq!(demo.ports[1].protocol, "udp");
        assert_eq!(demo.volumes[0].mode.as_deref(), Some("ro"));
        assert_eq!(demo.volumes[0].mount_type, "bind");
        assert_eq!(demo.volumes[1].mount_type, "volume");

        fs::remove_dir_all(temp_dir).expect("temporary directory should be removed");
    }

    #[test]
    fn split_protocol_defaults_to_tcp() {
        assert_eq!(
            split_protocol("8080:80"),
            (String::from("8080:80"), String::from("tcp"))
        );
        assert_eq!(
            split_protocol("8080:80/udp"),
            (String::from("8080:80"), String::from("udp"))
        );
    }

    #[test]
    fn detect_mount_type_matches_prototype_behavior() {
        assert_eq!(detect_mount_type(None), "anonymous");
        assert_eq!(detect_mount_type(Some("")), "anonymous");
        assert_eq!(detect_mount_type(Some("./data")), "bind");
        assert_eq!(detect_mount_type(Some("named-volume")), "volume");
    }
}
