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
    pub source_files: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ComposeProject {
    pub primary_file: PathBuf,
    pub loaded_files: Vec<PathBuf>,
    pub services: IndexMap<String, ComposeService>,
    pub working_dir: PathBuf,
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
