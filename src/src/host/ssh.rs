use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use glob::glob;

use super::{HostContext, HostFindingText, host_finding, resolve_existing_path};
use crate::domain::{Finding, Severity};

pub(crate) const SSH_CONFIG_PATH: &str = "etc/ssh/sshd_config";
const WEAK_KEX_ALGORITHMS: [&str; 2] =
    ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"];
const WEAK_MAC_ALGORITHMS: [&str; 4] =
    ["hmac-md5", "hmac-md5-96", "hmac-sha1-96", "hmac-ripemd160"];
const WEAK_CIPHER_ALGORITHMS: [&str; 6] = [
    "arcfour",
    "arcfour128",
    "arcfour256",
    "blowfish-cbc",
    "3des-cbc",
    "cast128-cbc",
];

pub fn scan_ssh_hardening(context: &HostContext) -> Vec<Finding> {
    let Some(config_path) = resolve_existing_path(&context.root, SSH_CONFIG_PATH) else {
        return Vec::new();
    };

    let Ok(config_result) = parse_sshd_config(&context.root, &config_path) else {
        return Vec::new();
    };

    let settings = &config_result.settings;
    let mut findings = Vec::new();

    if let Some(setting) = settings.get("permitrootlogin")
        && setting.value != "no"
    {
        let subject_path = &setting.source;
        let value = setting.value.as_str();
        findings.push(host_finding(
            "host.ssh_root_login_enabled",
            Severity::High,
            subject_path,
            HostFindingText {
                title: t!("finding.host.ssh_root_login.title").into_owned(),
                description: t!(
                    "finding.host.ssh_root_login.description",
                    path = subject_path.display().to_string(),
                    value = value
                )
                .into_owned(),
                why_risky: t!("finding.host.ssh_root_login.why").into_owned(),
                how_to_fix: t!("finding.host.ssh_root_login.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), subject_path.display().to_string()),
                (String::from("value"), value.to_owned()),
            ]),
        ));
    }

    if let Some(setting) = settings.get("passwordauthentication")
        && setting.value == "yes"
    {
        let subject_path = &setting.source;
        findings.push(host_finding(
            "host.ssh_password_auth_enabled",
            Severity::High,
            subject_path,
            HostFindingText {
                title: t!("finding.host.ssh_password_auth.title").into_owned(),
                description: t!(
                    "finding.host.ssh_password_auth.description",
                    path = subject_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.ssh_password_auth.why").into_owned(),
                how_to_fix: t!("finding.host.ssh_password_auth.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), subject_path.display().to_string())]),
        ));
    }

    if let Some(setting) = settings.get("permitemptypasswords")
        && setting.value == "yes"
    {
        let subject_path = &setting.source;
        findings.push(host_finding(
            "host.ssh_empty_passwords_enabled",
            Severity::Critical,
            subject_path,
            HostFindingText {
                title: t!("finding.host.ssh_empty_passwords.title").into_owned(),
                description: t!(
                    "finding.host.ssh_empty_passwords.description",
                    path = subject_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.ssh_empty_passwords.why").into_owned(),
                how_to_fix: t!("finding.host.ssh_empty_passwords.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), subject_path.display().to_string())]),
        ));
    }

    if let Some(setting) = settings.get("pubkeyauthentication")
        && setting.value == "no"
    {
        let subject_path = &setting.source;
        findings.push(host_finding(
            "host.ssh_pubkey_auth_disabled",
            Severity::Medium,
            subject_path,
            HostFindingText {
                title: t!("finding.host.ssh_pubkey_auth.title").into_owned(),
                description: t!(
                    "finding.host.ssh_pubkey_auth.description",
                    path = subject_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.ssh_pubkey_auth.why").into_owned(),
                how_to_fix: t!("finding.host.ssh_pubkey_auth.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), subject_path.display().to_string())]),
        ));
    }

    if let Some(setting) = settings.get("permituserenvironment")
        && setting.value == "yes"
    {
        let subject_path = &setting.source;
        findings.push(host_finding(
            "host.ssh_user_environment_enabled",
            Severity::Medium,
            subject_path,
            HostFindingText {
                title: t!("finding.host.ssh_user_environment.title").into_owned(),
                description: t!(
                    "finding.host.ssh_user_environment.description",
                    path = subject_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.ssh_user_environment.why").into_owned(),
                how_to_fix: t!("finding.host.ssh_user_environment.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), subject_path.display().to_string())]),
        ));
    }

    if let Some(setting) = settings.get("x11forwarding")
        && setting.value == "yes"
    {
        let subject_path = &setting.source;
        findings.push(host_finding(
            "host.ssh_x11_forwarding_enabled",
            Severity::Medium,
            subject_path,
            HostFindingText {
                title: t!("finding.host.ssh_x11_forwarding.title").into_owned(),
                description: t!(
                    "finding.host.ssh_x11_forwarding.description",
                    path = subject_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.ssh_x11_forwarding.why").into_owned(),
                how_to_fix: t!("finding.host.ssh_x11_forwarding.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), subject_path.display().to_string())]),
        ));
    }

    if !config_result.listen_addresses.is_empty() {
        if config_result
            .listen_addresses
            .iter()
            .any(|s| is_wildcard_listen_address(&s.value))
        {
            let subject_path = &config_result.listen_addresses[0].source;
            let values = config_result
                .listen_addresses
                .iter()
                .map(|s| s.value.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            findings.push(host_finding(
                "host.ssh_listens_on_all_interfaces",
                Severity::Medium,
                subject_path,
                HostFindingText {
                    title: t!("finding.host.ssh_listen_all.title").into_owned(),
                    description: t!(
                        "finding.host.ssh_listen_all.description",
                        path = subject_path.display().to_string(),
                        values = values
                    )
                    .into_owned(),
                    why_risky: t!("finding.host.ssh_listen_all.why").into_owned(),
                    how_to_fix: t!("finding.host.ssh_listen_all.fix").into_owned(),
                },
                BTreeMap::from([
                    (String::from("path"), subject_path.display().to_string()),
                    (String::from("values"), values),
                ]),
            ));
        }
    } else {
        let subject_path = &config_path;
        findings.push(host_finding(
            "host.ssh_listens_on_all_interfaces",
            Severity::Medium,
            subject_path,
            HostFindingText {
                title: t!("finding.host.ssh_listen_all.title").into_owned(),
                description: t!(
                    "finding.host.ssh_listen_all.description_default",
                    path = subject_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.ssh_listen_all.why").into_owned(),
                how_to_fix: t!("finding.host.ssh_listen_all.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), subject_path.display().to_string())]),
        ));
    }

    if let Some(setting) = settings.get("kexalgorithms") {
        let weak = find_weak_algorithms(&setting.value, &WEAK_KEX_ALGORITHMS);
        if !weak.is_empty() {
            let subject_path = &setting.source;
            findings.push(host_finding(
                "host.ssh_weak_kex",
                Severity::High,
                subject_path,
                HostFindingText {
                    title: t!("finding.host.ssh_weak_kex.title").into_owned(),
                    description: t!(
                        "finding.host.ssh_weak_kex.description",
                        path = subject_path.display().to_string(),
                        algorithms = weak.join(", ")
                    )
                    .into_owned(),
                    why_risky: t!("finding.host.ssh_weak_kex.why").into_owned(),
                    how_to_fix: t!("finding.host.ssh_weak_kex.fix").into_owned(),
                },
                BTreeMap::from([
                    (String::from("path"), subject_path.display().to_string()),
                    (String::from("algorithms"), weak.join(", ")),
                ]),
            ));
        }
    }

    if let Some(setting) = settings.get("macs") {
        let weak = find_weak_algorithms(&setting.value, &WEAK_MAC_ALGORITHMS);
        if !weak.is_empty() {
            let subject_path = &setting.source;
            findings.push(host_finding(
                "host.ssh_weak_macs",
                Severity::High,
                subject_path,
                HostFindingText {
                    title: t!("finding.host.ssh_weak_macs.title").into_owned(),
                    description: t!(
                        "finding.host.ssh_weak_macs.description",
                        path = subject_path.display().to_string(),
                        algorithms = weak.join(", ")
                    )
                    .into_owned(),
                    why_risky: t!("finding.host.ssh_weak_macs.why").into_owned(),
                    how_to_fix: t!("finding.host.ssh_weak_macs.fix").into_owned(),
                },
                BTreeMap::from([
                    (String::from("path"), subject_path.display().to_string()),
                    (String::from("algorithms"), weak.join(", ")),
                ]),
            ));
        }
    }

    if let Some(setting) = settings.get("ciphers") {
        let weak = find_weak_algorithms(&setting.value, &WEAK_CIPHER_ALGORITHMS);
        if !weak.is_empty() {
            let subject_path = &setting.source;
            findings.push(host_finding(
                "host.ssh_weak_ciphers",
                Severity::High,
                subject_path,
                HostFindingText {
                    title: t!("finding.host.ssh_weak_ciphers.title").into_owned(),
                    description: t!(
                        "finding.host.ssh_weak_ciphers.description",
                        path = subject_path.display().to_string(),
                        algorithms = weak.join(", ")
                    )
                    .into_owned(),
                    why_risky: t!("finding.host.ssh_weak_ciphers.why").into_owned(),
                    how_to_fix: t!("finding.host.ssh_weak_ciphers.fix").into_owned(),
                },
                BTreeMap::from([
                    (String::from("path"), subject_path.display().to_string()),
                    (String::from("algorithms"), weak.join(", ")),
                ]),
            ));
        }
    }

    findings
}

fn find_weak_algorithms(value: &str, weak_list: &[&str]) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|alg| {
            let lower = alg.to_ascii_lowercase();
            weak_list.contains(&lower.as_str())
        })
        .map(String::from)
        .collect()
}

fn is_wildcard_listen_address(value: &str) -> bool {
    value == "0.0.0.0" || value == "::" || value == "*"
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SshdSetting {
    pub(crate) value: String,
    pub(crate) source: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SshdConfigResult {
    pub(crate) settings: BTreeMap<String, SshdSetting>,
    pub(crate) listen_addresses: Vec<SshdSetting>,
}

pub(crate) fn parse_sshd_config(root: &Path, path: &Path) -> std::io::Result<SshdConfigResult> {
    let mut result = SshdConfigResult {
        settings: BTreeMap::new(),
        listen_addresses: Vec::new(),
    };
    let mut visited = HashSet::new();
    parse_sshd_config_file(root, path, &mut result, &mut visited)?;
    Ok(result)
}

fn parse_sshd_config_file(
    root: &Path,
    path: &Path,
    result: &mut SshdConfigResult,
    visited: &mut HashSet<PathBuf>,
) -> std::io::Result<()> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if !visited.insert(canonical) {
        return Ok(());
    }

    let content = std::fs::read_to_string(path)?;
    let include_base_dir = root.join("etc/ssh");

    for raw_line in content.lines() {
        let stripped = raw_line.split('#').next().unwrap_or_default().trim();
        if stripped.is_empty() {
            continue;
        }

        let mut parts = stripped.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };

        if key.eq_ignore_ascii_case("match") {
            break;
        }

        if key.eq_ignore_ascii_case("include") {
            for pattern in parts {
                let pattern = pattern.trim_matches('"').trim_matches('\'').trim();
                if pattern.is_empty() {
                    continue;
                }

                let resolved = if pattern.starts_with('/') {
                    root.join(pattern.trim_start_matches('/'))
                } else {
                    include_base_dir.join(pattern)
                };

                let mut matches = Vec::new();
                if let Some(pattern_text) = resolved.to_str()
                    && let Ok(paths) = glob(pattern_text)
                {
                    for entry in paths.flatten() {
                        matches.push(entry);
                    }
                }
                matches.sort();

                for include_path in matches {
                    let _ = parse_sshd_config_file(root, &include_path, result, visited);
                }
            }

            continue;
        }

        let Some(value) = parts.next() else {
            continue;
        };

        let setting = SshdSetting {
            value: value.to_ascii_lowercase(),
            source: path.to_path_buf(),
        };

        let key_lower = key.to_ascii_lowercase();
        if key_lower == "listenaddress" {
            result.listen_addresses.push(setting);
        } else {
            result.settings.entry(key_lower).or_insert(setting);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::HostScanner;
    use crate::host::tests::{temp_host_root, write_file};

    #[test]
    fn parse_sshd_config_stops_at_match_block() {
        let root = temp_host_root("match-block");
        let path = root.join(SSH_CONFIG_PATH);
        write_file(
            &path,
            concat!(
                "PermitRootLogin no\n",
                "Match User backup\n",
                "  PermitRootLogin yes\n"
            ),
        );

        let parsed = parse_sshd_config(&root, &path).expect("config should parse");

        assert_eq!(
            parsed
                .settings
                .get("permitrootlogin")
                .map(|setting| setting.value.as_str()),
            Some("no")
        );

        assert_eq!(
            parsed
                .settings
                .get("permitrootlogin")
                .map(|setting| setting.source.as_path()),
            Some(path.as_path())
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn parse_sshd_config_honors_include_globs_and_tracks_effective_source() {
        let root = temp_host_root("sshd-include-abs");
        let config_path = root.join(SSH_CONFIG_PATH);
        let include_path = root.join("etc/ssh/sshd_config.d/10-extra.conf");

        write_file(
            &config_path,
            concat!(
                "Include /etc/ssh/sshd_config.d/*.conf\n",
                "PermitRootLogin yes\n"
            ),
        );
        write_file(&include_path, "PermitRootLogin no\n");

        let parsed = parse_sshd_config(&root, &config_path).expect("config should parse");

        let permit_root = parsed
            .settings
            .get("permitrootlogin")
            .expect("permitrootlogin should be set");
        assert_eq!(permit_root.value, "no");
        assert_eq!(permit_root.source, include_path);

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn parse_sshd_config_include_does_not_override_existing_setting() {
        let root = temp_host_root("sshd-include-rel");
        let config_path = root.join(SSH_CONFIG_PATH);
        let include_path = root.join("etc/ssh/sshd_config.d/99-override.conf");

        write_file(
            &config_path,
            concat!("PermitRootLogin no\n", "Include sshd_config.d/*.conf\n"),
        );
        write_file(&include_path, "PermitRootLogin yes\n");

        let parsed = parse_sshd_config(&root, &config_path).expect("config should parse");

        let permit_root = parsed
            .settings
            .get("permitrootlogin")
            .expect("permitrootlogin should be set");
        assert_eq!(permit_root.value, "no");
        assert_eq!(permit_root.source, config_path);

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn parse_sshd_config_avoids_include_cycles() {
        let root = temp_host_root("sshd-include-cycle");
        let config_path = root.join(SSH_CONFIG_PATH);
        let include_path = root.join("etc/ssh/sshd_config.d/cycle.conf");

        write_file(
            &config_path,
            concat!(
                "PermitRootLogin no\n",
                "Include /etc/ssh/sshd_config.d/cycle.conf\n"
            ),
        );
        write_file(
            &include_path,
            concat!("Include /etc/ssh/sshd_config\n", "PermitRootLogin yes\n"),
        );

        let parsed = parse_sshd_config(&root, &config_path).expect("config should parse");

        let permit_root = parsed
            .settings
            .get("permitrootlogin")
            .expect("permitrootlogin should be set");
        assert_eq!(permit_root.value, "no");
        assert_eq!(permit_root.source, config_path);

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn parse_sshd_config_relative_includes_resolve_from_etc_ssh() {
        let root = temp_host_root("sshd-include-relative-base");
        let config_path = root.join(SSH_CONFIG_PATH);
        let first_include = root.join("etc/ssh/sshd_config.d/10-chain.conf");
        let chained_include = root.join("etc/ssh/extra.conf");

        write_file(&config_path, "Include /etc/ssh/sshd_config.d/*.conf\n");
        write_file(
            &first_include,
            concat!("Include extra.conf\n", "PermitRootLogin yes\n"),
        );
        write_file(&chained_include, "PermitRootLogin no\n");

        let parsed = parse_sshd_config(&root, &config_path).expect("config should parse");

        let permit_root = parsed
            .settings
            .get("permitrootlogin")
            .expect("permitrootlogin should be set");
        assert_eq!(permit_root.value, "no");
        assert_eq!(permit_root.source, chained_include);

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_weak_ssh_algorithms() {
        let root = temp_host_root("ssh-weak-algos");
        write_file(
            &root.join(SSH_CONFIG_PATH),
            concat!(
                "KexAlgorithms diffie-hellman-group1-sha1,curve25519-sha256\n",
                "MACs hmac-md5,hmac-sha2-512-etm@openssh.com\n",
                "Ciphers arcfour,aes256-gcm@openssh.com\n",
            ),
        );

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.ssh_weak_kex")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.ssh_weak_macs")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.ssh_weak_ciphers")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn reports_ssh_x11_forwarding_when_enabled() {
        let root = temp_host_root("ssh-x11-forwarding");
        write_file(&root.join(SSH_CONFIG_PATH), "X11Forwarding yes\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.ssh_x11_forwarding_enabled")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }
}
