use std::collections::BTreeMap;
use std::path::PathBuf;

use indexmap::IndexMap;
use serde_yaml::Value;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PortBinding {
    pub raw: String,
    pub host_ip: Option<String>,
    pub host_port: Option<String>,
    pub container_port: String,
    pub protocol: String,
    pub short_syntax: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VolumeMount {
    pub raw: String,
    pub source: Option<String>,
    pub target: Option<String>,
    pub mode: Option<String>,
    pub mount_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ComposeService {
    pub name: String,
    pub image: Option<String>,
    pub ports: Vec<PortBinding>,
    pub volumes: Vec<VolumeMount>,
    pub environment: BTreeMap<String, Option<String>>,
    pub env_files: Vec<String>,
    pub networks: Vec<String>,
    pub user: Option<String>,
    pub privileged: bool,
    pub cap_add: Vec<String>,
    pub network_mode: Option<String>,
    pub security_opt: Vec<String>,
    pub command: Option<String>,
    pub source_files: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ComposeProject {
    pub primary_file: PathBuf,
    pub loaded_files: Vec<PathBuf>,
    pub services: IndexMap<String, ComposeService>,
    pub working_dir: PathBuf,
    pub networks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeBundle {
    pub primary_path: PathBuf,
    pub override_paths: Vec<PathBuf>,
    pub primary_document: Value,
    pub override_documents: Vec<Value>,
    pub primary_text: String,
}

impl ComposeBundle {
    pub fn loaded_files(&self) -> Vec<PathBuf> {
        let mut files = Vec::with_capacity(1 + self.override_paths.len());
        files.push(self.primary_path.clone());
        files.extend(self.override_paths.iter().cloned());
        files
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_binding_default() {
        let port = PortBinding::default();
        assert!(port.raw.is_empty());
        assert!(port.host_ip.is_none());
        assert!(port.host_port.is_none());
        assert!(port.container_port.is_empty());
        assert!(port.protocol.is_empty());
        assert!(!port.short_syntax);
    }

    #[test]
    fn volume_mount_default() {
        let vol = VolumeMount::default();
        assert!(vol.raw.is_empty());
        assert!(vol.source.is_none());
        assert!(vol.target.is_none());
        assert!(vol.mode.is_none());
        assert!(vol.mount_type.is_empty());
    }

    #[test]
    fn compose_service_default() {
        let svc = ComposeService::default();
        assert!(svc.name.is_empty());
        assert!(svc.image.is_none());
        assert!(svc.ports.is_empty());
        assert!(svc.volumes.is_empty());
        assert!(svc.environment.is_empty());
        assert!(!svc.privileged);
        assert!(svc.cap_add.is_empty());
        assert!(svc.security_opt.is_empty());
    }

    #[test]
    fn compose_project_default() {
        let proj = ComposeProject::default();
        assert!(proj.primary_file.as_os_str().is_empty());
        assert!(proj.services.is_empty());
        assert!(proj.networks.is_empty());
    }

    #[test]
    fn compose_bundle_loaded_files() {
        let bundle = ComposeBundle {
            primary_path: PathBuf::from("/a/docker-compose.yml"),
            override_paths: vec![PathBuf::from("/a/docker-compose.override.yml")],
            primary_document: Value::Null,
            override_documents: vec![Value::Null],
            primary_text: String::new(),
        };
        let files = bundle.loaded_files();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0], PathBuf::from("/a/docker-compose.yml"));
        assert_eq!(files[1], PathBuf::from("/a/docker-compose.override.yml"));
    }
}
