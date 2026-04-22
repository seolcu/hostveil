use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::domain::{DiscoveredProjectSummary, DockerDiscoveryStatus};

const DOCKER_PS_FORMAT: &str = "{{.Label \"com.docker.compose.project\"}}\t{{.Label \"com.docker.compose.service\"}}\t{{.Label \"com.docker.compose.project.working_dir\"}}\t{{.Label \"com.docker.compose.project.config_files\"}}\t{{.Image}}";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredContainerService {
    pub name: String,
    pub image: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredComposeProject {
    pub name: String,
    pub compose_path: Option<PathBuf>,
    pub working_dir: Option<PathBuf>,
    pub services: Vec<DiscoveredContainerService>,
    pub source: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerDiscoveryResult {
    pub status: DockerDiscoveryStatus,
    pub projects: Vec<DiscoveredComposeProject>,
    pub warnings: Vec<String>,
}

pub fn discover_running_compose_projects() -> DockerDiscoveryResult {
    let output = match Command::new("docker")
        .args(["ps", "--format", DOCKER_PS_FORMAT])
        .output()
    {
        Ok(output) => output,
        Err(_) => {
            return DockerDiscoveryResult {
                status: DockerDiscoveryStatus::Missing,
                projects: Vec::new(),
                warnings: vec![crate::i18n::tr_discovery_docker_cli_missing_fallback()],
            };
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let status = if is_permission_denied(&stderr) {
            DockerDiscoveryStatus::PermissionDenied
        } else {
            DockerDiscoveryStatus::Failed(stderr.clone())
        };
        return DockerDiscoveryResult {
            status,
            projects: Vec::new(),
            warnings: vec![if stderr.is_empty() {
                crate::i18n::tr_discovery_docker_failed_fallback()
            } else {
                crate::i18n::tr_discovery_docker_failed_detail(&stderr)
            }],
        };
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let projects = parse_docker_ps_output(&stdout);
    let warnings = if projects.is_empty() {
        vec![crate::i18n::tr_discovery_no_projects_current_dir()]
    } else {
        Vec::new()
    };

    DockerDiscoveryResult {
        status: DockerDiscoveryStatus::Available,
        projects,
        warnings,
    }
}

pub fn parse_docker_ps_output(output: &str) -> Vec<DiscoveredComposeProject> {
    let mut projects = BTreeMap::<String, DiscoveredComposeProject>::new();

    for raw_line in output.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        let mut fields = line.splitn(5, '\t');
        let project_name = fields.next().unwrap_or_default().trim();
        let service_name = fields.next().unwrap_or_default().trim();
        let working_dir = normalize_optional_path(fields.next().unwrap_or_default());
        let config_files = fields.next().unwrap_or_default().trim();
        let image = normalize_optional_string(fields.next().unwrap_or_default());

        if project_name.is_empty() || service_name.is_empty() {
            continue;
        }

        let compose_path = discover_compose_path(config_files, working_dir.as_deref());
        let project =
            projects
                .entry(project_name.to_owned())
                .or_insert_with(|| DiscoveredComposeProject {
                    name: project_name.to_owned(),
                    compose_path: compose_path.clone(),
                    working_dir: working_dir.clone(),
                    services: Vec::new(),
                    source: "docker",
                });

        if project.compose_path.is_none() {
            project.compose_path = compose_path;
        }
        if project.working_dir.is_none() {
            project.working_dir = working_dir.clone();
        }
        if project
            .services
            .iter()
            .all(|service| service.name != service_name)
        {
            project.services.push(DiscoveredContainerService {
                name: service_name.to_owned(),
                image,
            });
        }
    }

    projects.into_values().collect()
}

pub fn project_summary(project: &DiscoveredComposeProject) -> DiscoveredProjectSummary {
    DiscoveredProjectSummary {
        name: project.name.clone(),
        source: project.source.to_owned(),
        compose_path: project.compose_path.clone(),
        working_dir: project.working_dir.clone(),
        service_count: project.services.len(),
    }
}

fn discover_compose_path(config_files: &str, working_dir: Option<&Path>) -> Option<PathBuf> {
    let first_config = config_files
        .split(',')
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(PathBuf::from);

    if first_config.is_some() {
        return first_config;
    }

    working_dir.map(Path::to_path_buf)
}

fn normalize_optional_path(value: &str) -> Option<PathBuf> {
    normalize_optional_string(value).map(PathBuf::from)
}

fn normalize_optional_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn is_permission_denied(stderr: &str) -> bool {
    let lowered = stderr.to_ascii_lowercase();
    lowered.contains("permission denied") || lowered.contains("cannot connect to the docker daemon")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_running_services_into_projects() {
        let output = concat!(
            "vaultwarden\tapp\t/srv/vw\t/srv/vw/docker-compose.yml\tvaultwarden/server:1.30.1\n",
            "vaultwarden\tbackup\t/srv/vw\t/srv/vw/docker-compose.yml\tbusybox:1.36\n",
            "gitea\tweb\t/srv/gitea\t\tgitea/gitea:1.21\n",
            "\t\t\t\tnginx:latest\n"
        );

        let projects = parse_docker_ps_output(output);

        assert_eq!(projects.len(), 2);
        assert_eq!(projects[0].name, "gitea");
        assert_eq!(projects[0].services.len(), 1);
        assert_eq!(projects[0].compose_path, Some(PathBuf::from("/srv/gitea")));
        assert_eq!(projects[1].name, "vaultwarden");
        assert_eq!(projects[1].services.len(), 2);
        assert_eq!(
            projects[1].compose_path,
            Some(PathBuf::from("/srv/vw/docker-compose.yml"))
        );
    }

    #[test]
    fn project_summary_captures_display_data() {
        let project = DiscoveredComposeProject {
            name: String::from("immich"),
            compose_path: Some(PathBuf::from("/srv/immich/docker-compose.yml")),
            working_dir: Some(PathBuf::from("/srv/immich")),
            services: vec![DiscoveredContainerService {
                name: String::from("server"),
                image: Some(String::from("ghcr.io/immich-app/immich-server:v2.1.0")),
            }],
            source: "docker",
        };

        let summary = project_summary(&project);

        assert_eq!(summary.name, "immich");
        assert_eq!(summary.source, "docker");
        assert_eq!(summary.service_count, 1);
    }

    #[test]
    fn detects_permission_denied_errors() {
        assert!(is_permission_denied(
            "permission denied while trying to connect to the Docker daemon socket"
        ));
        assert!(is_permission_denied(
            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
        ));
    }
}
