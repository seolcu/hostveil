use std::collections::BTreeMap;
use std::fs;

use crate::compose::{ComposeProject, ComposeService};
use crate::domain::{Axis, Finding, Severity};

use super::exposure::is_public_port;
use super::{ServiceFindingText, service_finding};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceKind {
    Vaultwarden,
    Jellyfin,
    Gitea,
    Nextcloud,
    Immich,
    Traefik,
    Portainer,
    HomeAssistant,
    Pihole,
    Grafana,
    Npm,
    Authentik,
    Paperless,
}

pub fn scan_service_aware_risk(project: &ComposeProject) -> Vec<Finding> {
    let mut findings = Vec::new();

    for service in project.services.values() {
        let Some(kind) = detect_service_kind(service) else {
            continue;
        };

        match kind {
            ServiceKind::Vaultwarden => findings.extend(scan_vaultwarden_risk(service)),
            ServiceKind::Jellyfin => findings.extend(scan_jellyfin_risk(service)),
            ServiceKind::Gitea => findings.extend(scan_gitea_risk(service)),
            ServiceKind::Nextcloud => findings.extend(scan_nextcloud_risk(service)),
            ServiceKind::Immich => findings.extend(scan_immich_risk(project, service)),
            ServiceKind::Traefik => findings.extend(scan_traefik_risk(service)),
            ServiceKind::Portainer => findings.extend(scan_portainer_risk(service)),
            ServiceKind::HomeAssistant => findings.extend(scan_home_assistant_risk(service)),
            ServiceKind::Pihole => findings.extend(scan_pihole_risk(service)),
            ServiceKind::Grafana => findings.extend(scan_grafana_risk(service)),
            ServiceKind::Npm => findings.extend(scan_npm_risk(service)),
            ServiceKind::Authentik => findings.extend(scan_authentik_risk(service)),
            ServiceKind::Paperless => findings.extend(scan_paperless_risk(service)),
        }
    }

    findings
}

fn detect_service_kind(service: &ComposeService) -> Option<ServiceKind> {
    let service_name = service.name.to_lowercase();
    let image = service.image.as_deref().unwrap_or_default().to_lowercase();
    let haystack = format!("{service_name} {image}");

    if haystack.contains("vaultwarden") {
        Some(ServiceKind::Vaultwarden)
    } else if haystack.contains("jellyfin") {
        Some(ServiceKind::Jellyfin)
    } else if haystack.contains("gitea") {
        Some(ServiceKind::Gitea)
    } else if image.contains("nextcloud") || service_name == "nextcloud" {
        Some(ServiceKind::Nextcloud)
    } else if service_name.contains("immich-server") || haystack.contains("immich-server") {
        Some(ServiceKind::Immich)
    } else if haystack.contains("traefik") {
        Some(ServiceKind::Traefik)
    } else if haystack.contains("portainer") {
        Some(ServiceKind::Portainer)
    } else if haystack.contains("homeassistant") || haystack.contains("home-assistant") {
        Some(ServiceKind::HomeAssistant)
    } else if haystack.contains("pihole") || haystack.contains("pi-hole") {
        Some(ServiceKind::Pihole)
    } else if haystack.contains("grafana") {
        Some(ServiceKind::Grafana)
    } else if haystack.contains("nginx-proxy-manager")
        || haystack.contains("jc21/nginx-proxy-manager")
    {
        Some(ServiceKind::Npm)
    } else if haystack.contains("authentik") {
        Some(ServiceKind::Authentik)
    } else if haystack.contains("paperless") {
        Some(ServiceKind::Paperless)
    } else {
        None
    }
}

fn scan_vaultwarden_risk(service: &ComposeService) -> Vec<Finding> {
    let mut findings = Vec::new();
    let publicly_exposed = service.ports.iter().any(is_public_port);

    if env_truthy(service, "SIGNUPS_ALLOWED") {
        findings.push(service_finding(
            "service.vaultwarden.signups_enabled",
            Axis::UnnecessaryExposure,
            Severity::Medium,
            &service.name,
            ServiceFindingText {
                title: t!("finding.vaultwarden.signups_enabled.title").into_owned(),
                description: t!(
                    "finding.vaultwarden.signups_enabled.description",
                    service = service.name.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.vaultwarden.signups_enabled.why").into_owned(),
                how_to_fix: t!("finding.vaultwarden.signups_enabled.fix").into_owned(),
            },
            BTreeMap::from([(String::from("variable"), String::from("SIGNUPS_ALLOWED"))]),
        ));
    }

    if publicly_exposed && admin_token_configured(service) {
        findings.push(service_finding(
            "service.vaultwarden.admin_surface_public",
            Axis::UnnecessaryExposure,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.vaultwarden.admin_surface_public.title").into_owned(),
                description: t!(
                    "finding.vaultwarden.admin_surface_public.description",
                    service = service.name.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.vaultwarden.admin_surface_public.why").into_owned(),
                how_to_fix: t!("finding.vaultwarden.admin_surface_public.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("variable"), String::from("ADMIN_TOKEN")),
                (
                    String::from("public_port_count"),
                    service.ports.len().to_string(),
                ),
            ]),
        ));
    }

    if publicly_exposed
        && let Some(domain) = env_value(service, "DOMAIN")
        && domain.starts_with("http://")
    {
        findings.push(service_finding(
            "service.vaultwarden.insecure_domain",
            Axis::UnnecessaryExposure,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.vaultwarden.insecure_domain.title").into_owned(),
                description: t!(
                    "finding.vaultwarden.insecure_domain.description",
                    service = service.name.as_str(),
                    domain = domain
                )
                .into_owned(),
                why_risky: t!("finding.vaultwarden.insecure_domain.why").into_owned(),
                how_to_fix: t!("finding.vaultwarden.insecure_domain.fix").into_owned(),
            },
            BTreeMap::from([(String::from("domain"), domain.to_owned())]),
        ));
    }

    findings
}

fn scan_jellyfin_risk(service: &ComposeService) -> Vec<Finding> {
    let mut findings = Vec::new();
    let publicly_exposed = service.ports.iter().any(is_public_port);

    if publicly_exposed
        && let Some(url) = env_value(service, "JELLYFIN_PublishedServerUrl")
        && url.starts_with("http://")
    {
        findings.push(service_finding(
            "service.jellyfin.insecure_published_url",
            Axis::UnnecessaryExposure,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.jellyfin.insecure_published_url.title").into_owned(),
                description: t!(
                    "finding.jellyfin.insecure_published_url.description",
                    service = service.name.as_str(),
                    url = url
                )
                .into_owned(),
                why_risky: t!("finding.jellyfin.insecure_published_url.why").into_owned(),
                how_to_fix: t!("finding.jellyfin.insecure_published_url.fix").into_owned(),
            },
            BTreeMap::from([(String::from("url"), url.to_owned())]),
        ));
    }

    if let Some(port) = service.ports.iter().find(|port| {
        port.container_port == "7359" && port.protocol == "udp" && is_public_port(port)
    }) {
        findings.push(service_finding(
            "service.jellyfin.discovery_public",
            Axis::UnnecessaryExposure,
            Severity::Medium,
            &service.name,
            ServiceFindingText {
                title: t!("finding.jellyfin.discovery_public.title").into_owned(),
                description: t!(
                    "finding.jellyfin.discovery_public.description",
                    service = service.name.as_str(),
                    port = port.raw.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.jellyfin.discovery_public.why").into_owned(),
                how_to_fix: t!("finding.jellyfin.discovery_public.fix").into_owned(),
            },
            BTreeMap::from([(String::from("port"), port.raw.clone())]),
        ));
    }

    if let Some(path) = writable_media_mount(service) {
        findings.push(service_finding(
            "service.jellyfin.media_mount_writable",
            Axis::ExcessivePermissions,
            Severity::Low,
            &service.name,
            ServiceFindingText {
                title: t!("finding.jellyfin.media_mount_writable.title").into_owned(),
                description: t!(
                    "finding.jellyfin.media_mount_writable.description",
                    service = service.name.as_str(),
                    path = path
                )
                .into_owned(),
                why_risky: t!("finding.jellyfin.media_mount_writable.why").into_owned(),
                how_to_fix: t!("finding.jellyfin.media_mount_writable.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), path.to_owned())]),
        ));
    }

    findings
}

fn scan_gitea_risk(service: &ComposeService) -> Vec<Finding> {
    let mut findings = Vec::new();
    let web_public = service.ports.iter().any(|port| {
        port.container_port == "3000" && port.protocol == "tcp" && is_public_port(port)
    });
    let ssh_public = service
        .ports
        .iter()
        .find(|port| port.container_port == "22" && port.protocol == "tcp" && is_public_port(port));

    if web_public && ssh_public.is_some() {
        findings.push(service_finding(
            "service.gitea.web_and_ssh_public",
            Axis::UnnecessaryExposure,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.gitea.web_and_ssh_public.title").into_owned(),
                description: t!(
                    "finding.gitea.web_and_ssh_public.description",
                    service = service.name.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.gitea.web_and_ssh_public.why").into_owned(),
                how_to_fix: t!("finding.gitea.web_and_ssh_public.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("web_port"), String::from("3000")),
                (String::from("ssh_port"), String::from("22")),
            ]),
        ));
    }

    if let Some(port) = ssh_public {
        findings.push(service_finding(
            "service.gitea.ssh_published_public",
            Axis::UnnecessaryExposure,
            Severity::Medium,
            &service.name,
            ServiceFindingText {
                title: t!("finding.gitea.ssh_published_public.title").into_owned(),
                description: t!(
                    "finding.gitea.ssh_published_public.description",
                    service = service.name.as_str(),
                    port = port.raw.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.gitea.ssh_published_public.why").into_owned(),
                how_to_fix: t!("finding.gitea.ssh_published_public.fix").into_owned(),
            },
            BTreeMap::from([(String::from("port"), port.raw.clone())]),
        ));
    }

    let security_keys = inline_env_keys(
        service,
        &[
            "GITEA__security__SECRET_KEY",
            "GITEA__security__INTERNAL_TOKEN",
        ],
    );
    if !security_keys.is_empty() {
        findings.push(service_finding(
            "service.gitea.inline_security_secrets",
            Axis::SensitiveData,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.gitea.inline_security_secrets.title").into_owned(),
                description: t!(
                    "finding.gitea.inline_security_secrets.description",
                    service = service.name.as_str(),
                    variables = security_keys.join(", ")
                )
                .into_owned(),
                why_risky: t!("finding.gitea.inline_security_secrets.why").into_owned(),
                how_to_fix: t!("finding.gitea.inline_security_secrets.fix").into_owned(),
            },
            BTreeMap::from([(String::from("variables"), security_keys.join(","))]),
        ));
    }

    findings
}

fn scan_nextcloud_risk(service: &ComposeService) -> Vec<Finding> {
    let mut findings = Vec::new();
    let publicly_exposed = service.ports.iter().any(is_public_port);

    if publicly_exposed
        && let Some(overwrite_protocol) = env_value(service, "OVERWRITEPROTOCOL")
        && overwrite_protocol.eq_ignore_ascii_case("http")
    {
        findings.push(service_finding(
            "service.nextcloud.insecure_overwriteprotocol",
            Axis::UnnecessaryExposure,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.nextcloud.insecure_overwriteprotocol.title").into_owned(),
                description: t!(
                    "finding.nextcloud.insecure_overwriteprotocol.description",
                    service = service.name.as_str(),
                    protocol = overwrite_protocol
                )
                .into_owned(),
                why_risky: t!("finding.nextcloud.insecure_overwriteprotocol.why").into_owned(),
                how_to_fix: t!("finding.nextcloud.insecure_overwriteprotocol.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("variable"), String::from("OVERWRITEPROTOCOL")),
                (String::from("value"), overwrite_protocol.to_owned()),
            ]),
        ));
    }

    if let Some(trusted_domains) = env_value(service, "NEXTCLOUD_TRUSTED_DOMAINS")
        && contains_wildcard_trusted_domain(trusted_domains)
    {
        findings.push(service_finding(
            "service.nextcloud.wildcard_trusted_domains",
            Axis::UnnecessaryExposure,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.nextcloud.wildcard_trusted_domains.title").into_owned(),
                description: t!(
                    "finding.nextcloud.wildcard_trusted_domains.description",
                    service = service.name.as_str(),
                    trusted_domains = trusted_domains
                )
                .into_owned(),
                why_risky: t!("finding.nextcloud.wildcard_trusted_domains.why").into_owned(),
                how_to_fix: t!("finding.nextcloud.wildcard_trusted_domains.fix").into_owned(),
            },
            BTreeMap::from([(String::from("trusted_domains"), trusted_domains.to_owned())]),
        ));
    }

    if has_default_nextcloud_admin_credentials(service) {
        findings.push(service_finding(
            "service.nextcloud.default_admin_credentials",
            Axis::SensitiveData,
            Severity::Critical,
            &service.name,
            ServiceFindingText {
                title: t!("finding.nextcloud.default_admin_credentials.title").into_owned(),
                description: t!(
                    "finding.nextcloud.default_admin_credentials.description",
                    service = service.name.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.nextcloud.default_admin_credentials.why").into_owned(),
                how_to_fix: t!("finding.nextcloud.default_admin_credentials.fix").into_owned(),
            },
            BTreeMap::from([
                (
                    String::from("user_variable"),
                    String::from("NEXTCLOUD_ADMIN_USER"),
                ),
                (
                    String::from("password_variable"),
                    String::from("NEXTCLOUD_ADMIN_PASSWORD"),
                ),
            ]),
        ));
    }

    findings
}

fn scan_pihole_risk(service: &ComposeService) -> Vec<Finding> {
    let mut findings = Vec::new();
    let publicly_exposed = service.ports.iter().any(is_public_port);

    if publicly_exposed
        && let Some(port) = service.ports.iter().find(|port| {
            (port.container_port == "80"
                || port.container_port == "443"
                || port.container_port == "8080")
                && (port.protocol == "tcp" || port.protocol == "udp")
                && is_public_port(port)
        })
    {
        findings.push(service_finding(
            "service.pihole.admin_public",
            Axis::UnnecessaryExposure,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.pihole.admin_public.title").into_owned(),
                description: t!(
                    "finding.pihole.admin_public.description",
                    service = service.name.as_str(),
                    port = port.raw.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.pihole.admin_public.why").into_owned(),
                how_to_fix: t!("finding.pihole.admin_public.fix").into_owned(),
            },
            BTreeMap::from([(String::from("port"), port.raw.clone())]),
        ));
    }

    if let Some(webpassword) = env_value(service, "WEBPASSWORD") {
        if webpassword.is_empty() || is_weak_pihole_password(webpassword) {
            findings.push(service_finding(
                "service.pihole.weak_password",
                Axis::SensitiveData,
                Severity::High,
                &service.name,
                ServiceFindingText {
                    title: t!("finding.pihole.weak_password.title").into_owned(),
                    description: t!(
                        "finding.pihole.weak_password.description",
                        service = service.name.as_str()
                    )
                    .into_owned(),
                    why_risky: t!("finding.pihole.weak_password.why").into_owned(),
                    how_to_fix: t!("finding.pihole.weak_password.fix").into_owned(),
                },
                BTreeMap::from([(String::from("variable"), String::from("WEBPASSWORD"))]),
            ));
        }
    } else {
        findings.push(service_finding(
            "service.pihole.no_password",
            Axis::SensitiveData,
            Severity::Critical,
            &service.name,
            ServiceFindingText {
                title: t!("finding.pihole.no_password.title").into_owned(),
                description: t!(
                    "finding.pihole.no_password.description",
                    service = service.name.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.pihole.no_password.why").into_owned(),
                how_to_fix: t!("finding.pihole.no_password.fix").into_owned(),
            },
            BTreeMap::from([(String::from("variable"), String::from("WEBPASSWORD"))]),
        ));
    }

    if publicly_exposed
        && let Some(port) = service.ports.iter().find(|port| {
            port.container_port == "53"
                && (port.protocol == "tcp" || port.protocol == "udp")
                && is_public_port(port)
        })
    {
        findings.push(service_finding(
            "service.pihole.dns_public",
            Axis::UnnecessaryExposure,
            Severity::Medium,
            &service.name,
            ServiceFindingText {
                title: t!("finding.pihole.dns_public.title").into_owned(),
                description: t!(
                    "finding.pihole.dns_public.description",
                    service = service.name.as_str(),
                    port = port.raw.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.pihole.dns_public.why").into_owned(),
                how_to_fix: t!("finding.pihole.dns_public.fix").into_owned(),
            },
            BTreeMap::from([(String::from("port"), port.raw.clone())]),
        ));
    }

    findings
}

fn is_weak_pihole_password(password: &str) -> bool {
    let lower = password.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "password" | "admin" | "pihole" | "123456" | "12345678" | "changeme" | ""
    )
}

fn scan_home_assistant_risk(service: &ComposeService) -> Vec<Finding> {
    let mut findings = Vec::new();
    let publicly_exposed = service.ports.iter().any(is_public_port);

    if publicly_exposed
        && let Some(port) = service.ports.iter().find(|port| {
            port.container_port == "8123" && port.protocol == "tcp" && is_public_port(port)
        })
    {
        findings.push(service_finding(
            "service.homeassistant.ui_public",
            Axis::UnnecessaryExposure,
            Severity::Medium,
            &service.name,
            ServiceFindingText {
                title: t!("finding.homeassistant.ui_public.title").into_owned(),
                description: t!(
                    "finding.homeassistant.ui_public.description",
                    service = service.name.as_str(),
                    port = port.raw.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.homeassistant.ui_public.why").into_owned(),
                how_to_fix: t!("finding.homeassistant.ui_public.fix").into_owned(),
            },
            BTreeMap::from([(String::from("port"), port.raw.clone())]),
        ));
    }

    if service.network_mode.as_deref() == Some("host") {
        findings.push(service_finding(
            "service.homeassistant.host_network",
            Axis::UnnecessaryExposure,
            Severity::Medium,
            &service.name,
            ServiceFindingText {
                title: t!("finding.homeassistant.host_network.title").into_owned(),
                description: t!(
                    "finding.homeassistant.host_network.description",
                    service = service.name.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.homeassistant.host_network.why").into_owned(),
                how_to_fix: t!("finding.homeassistant.host_network.fix").into_owned(),
            },
            BTreeMap::new(),
        ));
    }

    if let Some(device_path) = service.volumes.iter().find_map(|mount| {
        let source = mount.source.as_deref()?;
        if source.starts_with("/dev/") {
            Some(source)
        } else {
            None
        }
    }) {
        findings.push(service_finding(
            "service.homeassistant.device_mount",
            Axis::ExcessivePermissions,
            Severity::Low,
            &service.name,
            ServiceFindingText {
                title: t!("finding.homeassistant.device_mount.title").into_owned(),
                description: t!(
                    "finding.homeassistant.device_mount.description",
                    service = service.name.as_str(),
                    path = device_path
                )
                .into_owned(),
                why_risky: t!("finding.homeassistant.device_mount.why").into_owned(),
                how_to_fix: t!("finding.homeassistant.device_mount.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), device_path.to_owned())]),
        ));
    }

    findings
}

fn scan_portainer_risk(service: &ComposeService) -> Vec<Finding> {
    let mut findings = Vec::new();
    let publicly_exposed = service.ports.iter().any(is_public_port);

    if publicly_exposed
        && let Some(port) = service.ports.iter().find(|port| {
            (port.container_port == "8000"
                || port.container_port == "9000"
                || port.container_port == "9443")
                && port.protocol == "tcp"
                && is_public_port(port)
        })
    {
        findings.push(service_finding(
            "service.portainer.admin_ui_public",
            Axis::UnnecessaryExposure,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.portainer.admin_ui_public.title").into_owned(),
                description: t!(
                    "finding.portainer.admin_ui_public.description",
                    service = service.name.as_str(),
                    port = port.raw.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.portainer.admin_ui_public.why").into_owned(),
                how_to_fix: t!("finding.portainer.admin_ui_public.fix").into_owned(),
            },
            BTreeMap::from([(String::from("port"), port.raw.clone())]),
        ));
    }

    let has_docker_socket = service.volumes.iter().any(|mount| {
        mount.source.as_deref() == Some("/var/run/docker.sock")
            || mount.source.as_deref() == Some("/run/docker.sock")
    });
    if has_docker_socket {
        findings.push(service_finding(
            "service.portainer.docker_socket_mounted",
            Axis::ExcessivePermissions,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.portainer.docker_socket_mounted.title").into_owned(),
                description: t!(
                    "finding.portainer.docker_socket_mounted.description",
                    service = service.name.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.portainer.docker_socket_mounted.why").into_owned(),
                how_to_fix: t!("finding.portainer.docker_socket_mounted.fix").into_owned(),
            },
            BTreeMap::from([(String::from("mount"), String::from("/var/run/docker.sock"))]),
        ));
    }

    let no_auth = service
        .command
        .as_deref()
        .is_some_and(|cmd| cmd.contains("--no-auth"));
    if no_auth {
        findings.push(service_finding(
            "service.portainer.auth_disabled",
            Axis::SensitiveData,
            Severity::Critical,
            &service.name,
            ServiceFindingText {
                title: t!("finding.portainer.auth_disabled.title").into_owned(),
                description: t!(
                    "finding.portainer.auth_disabled.description",
                    service = service.name.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.portainer.auth_disabled.why").into_owned(),
                how_to_fix: t!("finding.portainer.auth_disabled.fix").into_owned(),
            },
            BTreeMap::from([(String::from("flag"), String::from("--no-auth"))]),
        ));
    }

    findings
}

fn scan_traefik_risk(service: &ComposeService) -> Vec<Finding> {
    let mut findings = Vec::new();
    let publicly_exposed = service.ports.iter().any(is_public_port);

    if env_truthy(service, "TRAEFIK_API_INSECURE") {
        findings.push(service_finding(
            "service.traefik.insecure_api_enabled",
            Axis::UnnecessaryExposure,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.traefik.insecure_api_enabled.title").into_owned(),
                description: t!(
                    "finding.traefik.insecure_api_enabled.description",
                    service = service.name.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.traefik.insecure_api_enabled.why").into_owned(),
                how_to_fix: t!("finding.traefik.insecure_api_enabled.fix").into_owned(),
            },
            BTreeMap::from([(
                String::from("variable"),
                String::from("TRAEFIK_API_INSECURE"),
            )]),
        ));
    }

    if publicly_exposed && env_truthy(service, "TRAEFIK_API_DASHBOARD") {
        findings.push(service_finding(
            "service.traefik.dashboard_public",
            Axis::UnnecessaryExposure,
            Severity::Medium,
            &service.name,
            ServiceFindingText {
                title: t!("finding.traefik.dashboard_public.title").into_owned(),
                description: t!(
                    "finding.traefik.dashboard_public.description",
                    service = service.name.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.traefik.dashboard_public.why").into_owned(),
                how_to_fix: t!("finding.traefik.dashboard_public.fix").into_owned(),
            },
            BTreeMap::from([
                (
                    String::from("variable"),
                    String::from("TRAEFIK_API_DASHBOARD"),
                ),
                (
                    String::from("public_port_count"),
                    service.ports.len().to_string(),
                ),
            ]),
        ));
    }

    findings
}

fn scan_immich_risk(project: &ComposeProject, service: &ComposeService) -> Vec<Finding> {
    let mut findings = Vec::new();
    let shared_secret_env_files = shared_secret_env_files(project, "immich");

    if !shared_secret_env_files.is_empty() {
        findings.push(service_finding(
            "service.immich.shared_secret_env_file",
            Axis::SensitiveData,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.immich.shared_secret_env_file.title").into_owned(),
                description: t!(
                    "finding.immich.shared_secret_env_file.description",
                    service = service.name.as_str(),
                    env_file = shared_secret_env_files.join(", ")
                )
                .into_owned(),
                why_risky: t!("finding.immich.shared_secret_env_file.why").into_owned(),
                how_to_fix: t!("finding.immich.shared_secret_env_file.fix").into_owned(),
            },
            BTreeMap::from([(String::from("env_files"), shared_secret_env_files.join(","))]),
        ));
    }

    if immich_default_db_password(project) {
        findings.push(service_finding(
            "service.immich.default_db_password",
            Axis::SensitiveData,
            Severity::Critical,
            &service.name,
            ServiceFindingText {
                title: t!("finding.immich.default_db_password.title").into_owned(),
                description: t!(
                    "finding.immich.default_db_password.description",
                    service = service.name.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.immich.default_db_password.why").into_owned(),
                how_to_fix: t!("finding.immich.default_db_password.fix").into_owned(),
            },
            BTreeMap::from([(String::from("variable"), String::from("DB_PASSWORD"))]),
        ));
    }

    findings
}

fn env_truthy(service: &ComposeService, key: &str) -> bool {
    env_value(service, key).is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "true" | "yes" | "on" | "1"
        )
    })
}

fn env_value<'a>(service: &'a ComposeService, key: &str) -> Option<&'a str> {
    service
        .environment
        .get(key)
        .and_then(|value| value.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn admin_token_configured(service: &ComposeService) -> bool {
    env_value(service, "ADMIN_TOKEN").is_some() || env_value(service, "ADMIN_TOKEN_FILE").is_some()
}

fn writable_media_mount(service: &ComposeService) -> Option<&str> {
    service.volumes.iter().find_map(|mount| {
        let target = mount.target.as_deref()?;
        if mount.mount_type == "bind"
            && target.starts_with("/media")
            && mount.mode.as_deref() != Some("ro")
        {
            Some(target)
        } else {
            None
        }
    })
}

fn inline_env_keys(service: &ComposeService, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .filter_map(|key| env_value(service, key).map(|_| (*key).to_owned()))
        .collect()
}

fn contains_wildcard_trusted_domain(value: &str) -> bool {
    value
        .split(|ch: char| ch == ',' || ch.is_whitespace())
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .any(|token| token == "*" || token == "0.0.0.0" || token == "::" || token.starts_with("*."))
}

fn has_default_nextcloud_admin_credentials(service: &ComposeService) -> bool {
    let Some(admin_user) = env_value(service, "NEXTCLOUD_ADMIN_USER") else {
        return false;
    };
    let Some(admin_password) = env_value(service, "NEXTCLOUD_ADMIN_PASSWORD") else {
        return false;
    };

    if !admin_user.eq_ignore_ascii_case("admin") {
        return false;
    }

    matches!(
        admin_password.to_ascii_lowercase().as_str(),
        "admin" | "password" | "nextcloud" | "changeme" | "123456" | "12345678"
    )
}

fn shared_secret_env_files(project: &ComposeProject, service_prefix: &str) -> Vec<String> {
    let mut usages = BTreeMap::<String, usize>::new();

    for service in project.services.values() {
        if !service.name.starts_with(service_prefix) {
            continue;
        }

        for env_file in &service.env_files {
            let values = env_file_values(project, env_file);
            if values
                .keys()
                .any(|key| key.contains("PASSWORD") || key.contains("SECRET"))
            {
                *usages.entry(env_file.clone()).or_default() += 1;
            }
        }
    }

    usages
        .into_iter()
        .filter_map(|(env_file, count)| (count > 1).then_some(env_file))
        .collect()
}

fn immich_default_db_password(project: &ComposeProject) -> bool {
    let mut values = BTreeMap::<String, String>::new();

    for service in project.services.values() {
        if service.name.starts_with("immich-") {
            for env_file in &service.env_files {
                values.extend(env_file_values(project, env_file));
            }
        }

        for (key, value) in &service.environment {
            if let Some(value) = value.as_deref() {
                values.insert(key.clone(), value.trim().to_owned());
            }
        }
    }

    values
        .get("DB_PASSWORD")
        .is_some_and(|value| value == "postgres")
        || values
            .get("POSTGRES_PASSWORD")
            .is_some_and(|value| value == "postgres")
}

fn env_file_values(project: &ComposeProject, env_file: &str) -> BTreeMap<String, String> {
    let path = project.working_dir.join(env_file);
    let Ok(text) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };

    let mut values = BTreeMap::new();
    for line in text.lines() {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }

        let Some((key, value)) = stripped.split_once('=') else {
            continue;
        };
        values.insert(key.trim().to_owned(), value.trim().to_owned());
    }

    values
}

fn scan_grafana_risk(service: &ComposeService) -> Vec<Finding> {
    let mut findings = Vec::new();
    let publicly_exposed = service.ports.iter().any(is_public_port);

    if publicly_exposed
        && let Some(port) = service.ports.iter().find(|port| {
            port.container_port == "3000" && port.protocol == "tcp" && is_public_port(port)
        })
    {
        findings.push(service_finding(
            "service.grafana.admin_public",
            Axis::UnnecessaryExposure,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.grafana.admin_public.title").into_owned(),
                description: t!(
                    "finding.grafana.admin_public.description",
                    service = service.name.as_str(),
                    port = port.raw.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.grafana.admin_public.why").into_owned(),
                how_to_fix: t!("finding.grafana.admin_public.fix").into_owned(),
            },
            BTreeMap::from([(String::from("port"), port.raw.clone())]),
        ));
    }

    if env_truthy(service, "GF_AUTH_DISABLE_LOGIN_FORM") {
        findings.push(service_finding(
            "service.grafana.auth_disabled",
            Axis::UnnecessaryExposure,
            Severity::Critical,
            &service.name,
            ServiceFindingText {
                title: t!("finding.grafana.auth_disabled.title").into_owned(),
                description: t!(
                    "finding.grafana.auth_disabled.description",
                    service = service.name.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.grafana.auth_disabled.why").into_owned(),
                how_to_fix: t!("finding.grafana.auth_disabled.fix").into_owned(),
            },
            BTreeMap::from([(
                String::from("variable"),
                String::from("GF_AUTH_DISABLE_LOGIN_FORM"),
            )]),
        ));
    }

    if env_truthy(service, "GF_AUTH_ANONYMOUS_ENABLED") {
        findings.push(service_finding(
            "service.grafana.anonymous_access",
            Axis::UnnecessaryExposure,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.grafana.anonymous_access.title").into_owned(),
                description: t!(
                    "finding.grafana.anonymous_access.description",
                    service = service.name.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.grafana.anonymous_access.why").into_owned(),
                how_to_fix: t!("finding.grafana.anonymous_access.fix").into_owned(),
            },
            BTreeMap::from([(
                String::from("variable"),
                String::from("GF_AUTH_ANONYMOUS_ENABLED"),
            )]),
        ));
    }

    findings
}

fn scan_npm_risk(service: &ComposeService) -> Vec<Finding> {
    let mut findings = Vec::new();
    let publicly_exposed = service.ports.iter().any(is_public_port);

    if publicly_exposed
        && let Some(port) = service.ports.iter().find(|port| {
            (port.container_port == "81" || port.container_port == "443")
                && port.protocol == "tcp"
                && is_public_port(port)
        })
    {
        findings.push(service_finding(
            "service.npm.admin_public",
            Axis::UnnecessaryExposure,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.npm.admin_public.title").into_owned(),
                description: t!(
                    "finding.npm.admin_public.description",
                    service = service.name.as_str(),
                    port = port.raw.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.npm.admin_public.why").into_owned(),
                how_to_fix: t!("finding.npm.admin_public.fix").into_owned(),
            },
            BTreeMap::from([(String::from("port"), port.raw.clone())]),
        ));
    }

    findings
}

fn scan_authentik_risk(service: &ComposeService) -> Vec<Finding> {
    let mut findings = Vec::new();
    let publicly_exposed = service.ports.iter().any(is_public_port);

    if publicly_exposed
        && let Some(port) = service.ports.iter().find(|port| {
            (port.container_port == "9000" || port.container_port == "9443")
                && port.protocol == "tcp"
                && is_public_port(port)
        })
    {
        findings.push(service_finding(
            "service.authentik.admin_public",
            Axis::UnnecessaryExposure,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.authentik.admin_public.title").into_owned(),
                description: t!(
                    "finding.authentik.admin_public.description",
                    service = service.name.as_str(),
                    port = port.raw.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.authentik.admin_public.why").into_owned(),
                how_to_fix: t!("finding.authentik.admin_public.fix").into_owned(),
            },
            BTreeMap::from([(String::from("port"), port.raw.clone())]),
        ));
    }

    if env_truthy(service, "AUTHENTIK_DEBUG") {
        findings.push(service_finding(
            "service.authentik.debug_enabled",
            Axis::UnnecessaryExposure,
            Severity::Medium,
            &service.name,
            ServiceFindingText {
                title: t!("finding.authentik.debug_enabled.title").into_owned(),
                description: t!(
                    "finding.authentik.debug_enabled.description",
                    service = service.name.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.authentik.debug_enabled.why").into_owned(),
                how_to_fix: t!("finding.authentik.debug_enabled.fix").into_owned(),
            },
            BTreeMap::from([(String::from("variable"), String::from("AUTHENTIK_DEBUG"))]),
        ));
    }

    findings
}

fn scan_paperless_risk(service: &ComposeService) -> Vec<Finding> {
    let mut findings = Vec::new();
    let publicly_exposed = service.ports.iter().any(is_public_port);

    if publicly_exposed
        && let Some(port) = service.ports.iter().find(|port| {
            port.container_port == "8000" && port.protocol == "tcp" && is_public_port(port)
        })
    {
        findings.push(service_finding(
            "service.paperless.ui_public",
            Axis::UnnecessaryExposure,
            Severity::Medium,
            &service.name,
            ServiceFindingText {
                title: t!("finding.paperless.ui_public.title").into_owned(),
                description: t!(
                    "finding.paperless.ui_public.description",
                    service = service.name.as_str(),
                    port = port.raw.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.paperless.ui_public.why").into_owned(),
                how_to_fix: t!("finding.paperless.ui_public.fix").into_owned(),
            },
            BTreeMap::from([(String::from("port"), port.raw.clone())]),
        ));
    }

    if !env_truthy(service, "PAPERLESS_FORCE_LOGIN") {
        findings.push(service_finding(
            "service.paperless.no_force_login",
            Axis::UnnecessaryExposure,
            Severity::Medium,
            &service.name,
            ServiceFindingText {
                title: t!("finding.paperless.no_force_login.title").into_owned(),
                description: t!(
                    "finding.paperless.no_force_login.description",
                    service = service.name.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.paperless.no_force_login.why").into_owned(),
                how_to_fix: t!("finding.paperless.no_force_login.fix").into_owned(),
            },
            BTreeMap::from([(
                String::from("variable"),
                String::from("PAPERLESS_FORCE_LOGIN"),
            )]),
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::compose::ComposeParser;

    use super::scan_service_aware_risk;

    fn fixture(service: &str, path: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/services")
            .join(service)
            .join(path)
            .canonicalize()
            .expect("fixture should exist")
    }

    #[test]
    fn vaultwarden_baseline_avoids_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("vaultwarden", "baseline.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn vaultwarden_vulnerable_fixture_triggers_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("vaultwarden", "vulnerable.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "service.vaultwarden.signups_enabled",
                "service.vaultwarden.admin_surface_public",
                "service.vaultwarden.insecure_domain",
            ]
        );
    }

    #[test]
    fn jellyfin_baseline_avoids_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("jellyfin", "baseline.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn jellyfin_vulnerable_fixture_triggers_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("jellyfin", "vulnerable.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "service.jellyfin.insecure_published_url",
                "service.jellyfin.discovery_public",
                "service.jellyfin.media_mount_writable",
            ]
        );
    }

    #[test]
    fn gitea_baseline_avoids_service_specific_findings() {
        let project = ComposeParser::parse_path_without_override(fixture("gitea", "baseline.yml"))
            .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn gitea_vulnerable_fixture_triggers_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("gitea", "vulnerable.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "service.gitea.web_and_ssh_public",
                "service.gitea.ssh_published_public",
                "service.gitea.inline_security_secrets",
            ]
        );
    }

    #[test]
    fn immich_baseline_avoids_service_specific_findings() {
        let project = ComposeParser::parse_path_without_override(fixture("immich", "baseline.yml"))
            .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn immich_vulnerable_fixture_triggers_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("immich", "vulnerable.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "service.immich.shared_secret_env_file",
                "service.immich.default_db_password",
            ]
        );
    }

    #[test]
    fn nextcloud_baseline_avoids_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("nextcloud", "baseline.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn nextcloud_vulnerable_fixture_triggers_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("nextcloud", "vulnerable.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "service.nextcloud.insecure_overwriteprotocol",
                "service.nextcloud.wildcard_trusted_domains",
                "service.nextcloud.default_admin_credentials",
            ]
        );
    }

    #[test]
    fn traefik_baseline_avoids_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("traefik", "baseline.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn traefik_vulnerable_fixture_triggers_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("traefik", "vulnerable.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "service.traefik.insecure_api_enabled",
                "service.traefik.dashboard_public",
            ]
        );
    }

    #[test]
    fn portainer_baseline_avoids_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("portainer", "baseline.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn portainer_vulnerable_fixture_triggers_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("portainer", "vulnerable.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "service.portainer.admin_ui_public",
                "service.portainer.docker_socket_mounted",
                "service.portainer.auth_disabled",
            ]
        );
    }

    #[test]
    fn homeassistant_baseline_avoids_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("homeassistant", "baseline.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn homeassistant_vulnerable_fixture_triggers_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("homeassistant", "vulnerable.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "service.homeassistant.ui_public",
                "service.homeassistant.host_network",
                "service.homeassistant.device_mount",
            ]
        );
    }

    #[test]
    fn pihole_baseline_avoids_service_specific_findings() {
        let project = ComposeParser::parse_path_without_override(fixture("pihole", "baseline.yml"))
            .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn pihole_vulnerable_fixture_triggers_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("pihole", "vulnerable.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "service.pihole.admin_public",
                "service.pihole.weak_password",
                "service.pihole.dns_public",
            ]
        );
    }

    #[test]
    fn grafana_baseline_avoids_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("grafana", "baseline.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn grafana_vulnerable_fixture_triggers_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("grafana", "vulnerable.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "service.grafana.admin_public",
                "service.grafana.auth_disabled",
                "service.grafana.anonymous_access",
            ]
        );
    }

    #[test]
    fn npm_baseline_avoids_service_specific_findings() {
        let project = ComposeParser::parse_path_without_override(fixture("npm", "baseline.yml"))
            .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn npm_vulnerable_fixture_triggers_service_specific_findings() {
        let project = ComposeParser::parse_path_without_override(fixture("npm", "vulnerable.yml"))
            .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec!["service.npm.admin_public"]
        );
    }

    #[test]
    fn authentik_baseline_avoids_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("authentik", "baseline.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn authentik_vulnerable_fixture_triggers_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("authentik", "vulnerable.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "service.authentik.admin_public",
                "service.authentik.debug_enabled",
            ]
        );
    }

    #[test]
    fn paperless_baseline_avoids_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("paperless", "baseline.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn paperless_vulnerable_fixture_triggers_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("paperless", "vulnerable.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "service.paperless.ui_public",
                "service.paperless.no_force_login",
            ]
        );
    }
}
