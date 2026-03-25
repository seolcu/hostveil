mod docker;

pub use docker::{
    DiscoveredComposeProject, DiscoveredContainerService, DockerDiscoveryResult,
    discover_running_compose_projects, parse_docker_ps_output, project_summary,
};
