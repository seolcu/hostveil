use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use super::{
    HostContext, HostFindingText, host_finding, parse_ini_bool, parse_ini_key_value,
    resolve_existing_path, strip_ini_comments,
};
use crate::domain::{Finding, RemediationKind, Severity};

const UFW_CONFIG_PATH: &str = "etc/ufw/ufw.conf";
const UFW_DEFAULT_POLICY_PATH: &str = "etc/default/ufw";
const UFW_INSTALL_MARKERS: [&str; 3] = ["etc/ufw/ufw.conf", "usr/sbin/ufw", "usr/bin/ufw"];
const FIREWALLD_CONFIG_PATH: &str = "etc/firewalld/firewalld.conf";
const FIREWALLD_CMD_PATHS: [&str; 2] = ["usr/bin/firewall-cmd", "usr/sbin/firewall-cmd"];
const FIREWALLD_SERVICE_PATHS: [&str; 3] = [
    "usr/lib/systemd/system/firewalld.service",
    "lib/systemd/system/firewalld.service",
    "etc/systemd/system/firewalld.service",
];
const FIREWALLD_ENABLED_MARKERS: [&str; 2] = [
    "etc/systemd/system/multi-user.target.wants/firewalld.service",
    "etc/systemd/system/default.target.wants/firewalld.service",
];
const NFTABLES_CONF_PATH: &str = "etc/nftables.conf";
const NFT_PATHS: [&str; 2] = ["usr/sbin/nft", "sbin/nft"];

pub fn scan_firewall_hardening(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    if detect_ufw_installed(&context.root) {
        findings.extend(scan_ufw_hardening(context));
        return findings;
    }

    if detect_firewalld_installed(&context.root) {
        findings.extend(scan_firewalld_hardening(context));
        return findings;
    }

    if detect_nftables_installed(&context.root) {
        findings.extend(scan_nftables_hardening(context));
        return findings;
    }

    findings.push(host_finding(
        "host.no_firewall_detected",
        Severity::Medium,
        &context.root,
        HostFindingText {
            title: t!("finding.host.no_firewall_detected.title").into_owned(),
            description: t!("finding.host.no_firewall_detected.description").into_owned(),
            why_risky: t!("finding.host.no_firewall_detected.why").into_owned(),
            how_to_fix: t!("finding.host.no_firewall_detected.fix").into_owned(),
        },
        BTreeMap::new(),
        RemediationKind::Manual,
    ));

    findings
}

fn scan_ufw_hardening(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(config_path) = resolve_existing_path(&context.root, UFW_CONFIG_PATH)
        && let Ok(config_text) = fs::read_to_string(&config_path)
        && let Some(enabled) = parse_ufw_enabled(&config_text)
        && !enabled
    {
        findings.push(host_finding(
            "host.ufw_installed_but_disabled",
            Severity::Medium,
            &config_path,
            HostFindingText {
                title: t!("finding.host.ufw_disabled.title").into_owned(),
                description: t!(
                    "finding.host.ufw_disabled.description",
                    path = config_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.ufw_disabled.why").into_owned(),
                how_to_fix: t!("finding.host.ufw_disabled.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), config_path.display().to_string()),
                (String::from("enabled"), String::from("no")),
            ]),
            RemediationKind::Review,
        ));
    }

    if let Some(defaults_path) = resolve_existing_path(&context.root, UFW_DEFAULT_POLICY_PATH)
        && let Ok(defaults_text) = fs::read_to_string(&defaults_path)
        && let Some(policy) = parse_ufw_default_input_policy(&defaults_text)
        && policy.eq_ignore_ascii_case("accept")
    {
        findings.push(host_finding(
            "host.ufw_default_input_policy_accept",
            Severity::Medium,
            &defaults_path,
            HostFindingText {
                title: t!("finding.host.ufw_default_input_policy_accept.title").into_owned(),
                description: t!(
                    "finding.host.ufw_default_input_policy_accept.description",
                    path = defaults_path.display().to_string(),
                    policy = policy.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.host.ufw_default_input_policy_accept.why").into_owned(),
                how_to_fix: t!("finding.host.ufw_default_input_policy_accept.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), defaults_path.display().to_string()),
                (String::from("policy"), policy),
            ]),
            RemediationKind::Review,
        ));
    }

    findings
}

fn detect_firewalld_installed(root: &Path) -> bool {
    resolve_existing_path(root, FIREWALLD_CONFIG_PATH).is_some()
        || FIREWALLD_CMD_PATHS
            .iter()
            .any(|path| resolve_existing_path(root, path).is_some())
        || FIREWALLD_SERVICE_PATHS
            .iter()
            .any(|path| resolve_existing_path(root, path).is_some())
}

fn detect_firewalld_enabled(root: &Path) -> bool {
    FIREWALLD_ENABLED_MARKERS
        .iter()
        .any(|marker| resolve_existing_path(root, marker).is_some())
}

fn scan_firewalld_hardening(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !detect_firewalld_enabled(&context.root) {
        let config_path = resolve_existing_path(&context.root, FIREWALLD_CONFIG_PATH)
            .or_else(|| resolve_existing_path(&context.root, FIREWALLD_SERVICE_PATHS[0]))
            .unwrap_or_else(|| context.root.join(FIREWALLD_CONFIG_PATH));

        findings.push(host_finding(
            "host.firewalld_installed_but_disabled",
            Severity::Medium,
            &config_path,
            HostFindingText {
                title: t!("finding.host.firewalld_installed_but_disabled.title").into_owned(),
                description: t!(
                    "finding.host.firewalld_installed_but_disabled.description",
                    path = config_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.firewalld_installed_but_disabled.why").into_owned(),
                how_to_fix: t!("finding.host.firewalld_installed_but_disabled.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), config_path.display().to_string()),
                (String::from("enabled"), String::from("no")),
            ]),
            RemediationKind::Review,
        ));
        return findings;
    }

    if let Some(config_path) = resolve_existing_path(&context.root, FIREWALLD_CONFIG_PATH)
        && let Ok(text) = fs::read_to_string(&config_path)
        && let Some(zone) = parse_firewalld_default_zone(&text)
        && zone.eq_ignore_ascii_case("trusted")
    {
        findings.push(host_finding(
            "host.firewalld_default_zone_trusted",
            Severity::High,
            &config_path,
            HostFindingText {
                title: t!("finding.host.firewalld_default_zone_trusted.title").into_owned(),
                description: t!(
                    "finding.host.firewalld_default_zone_trusted.description",
                    path = config_path.display().to_string(),
                    zone = zone.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.host.firewalld_default_zone_trusted.why").into_owned(),
                how_to_fix: t!("finding.host.firewalld_default_zone_trusted.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), config_path.display().to_string()),
                (String::from("zone"), zone),
            ]),
            RemediationKind::Review,
        ));
    }

    findings
}

fn parse_firewalld_default_zone(text: &str) -> Option<String> {
    for raw_line in text.lines() {
        let line = strip_ini_comments(raw_line);
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = parse_ini_key_value(line) else {
            continue;
        };
        if !key.eq_ignore_ascii_case("DefaultZone") {
            continue;
        }
        let zone = value.trim_matches('"').trim_matches('\'').trim();
        if zone.is_empty() {
            continue;
        }
        return Some(zone.to_owned());
    }
    None
}

fn detect_nftables_installed(root: &Path) -> bool {
    resolve_existing_path(root, NFTABLES_CONF_PATH).is_some()
        || NFT_PATHS
            .iter()
            .any(|path| resolve_existing_path(root, path).is_some())
}

fn scan_nftables_hardening(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(conf_path) = resolve_existing_path(&context.root, NFTABLES_CONF_PATH)
        && let Ok(text) = fs::read_to_string(&conf_path)
        && text.trim().is_empty()
    {
        findings.push(host_finding(
            "host.nftables_installed_no_rules",
            Severity::Medium,
            &conf_path,
            HostFindingText {
                title: t!("finding.host.nftables_installed_no_rules.title").into_owned(),
                description: t!(
                    "finding.host.nftables_installed_no_rules.description",
                    path = conf_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.nftables_installed_no_rules.why").into_owned(),
                how_to_fix: t!("finding.host.nftables_installed_no_rules.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), conf_path.display().to_string())]),
            RemediationKind::Review,
        ));
    }

    findings
}

fn detect_ufw_installed(root: &Path) -> bool {
    UFW_INSTALL_MARKERS
        .iter()
        .any(|marker| resolve_existing_path(root, marker).is_some())
}

fn parse_ufw_enabled(text: &str) -> Option<bool> {
    for raw_line in text.lines() {
        let line = strip_ini_comments(raw_line);
        if line.is_empty() {
            continue;
        }

        let Some((key, value)) = parse_ini_key_value(line) else {
            continue;
        };
        if !key.eq_ignore_ascii_case("ENABLED") {
            continue;
        }

        let value = value.trim_matches('"').trim_matches('\'').trim();
        if let Some(enabled) = parse_ini_bool(value) {
            return Some(enabled);
        }
    }

    None
}

fn parse_ufw_default_input_policy(text: &str) -> Option<String> {
    for raw_line in text.lines() {
        let line = strip_ini_comments(raw_line);
        if line.is_empty() {
            continue;
        }

        let Some((key, value)) = parse_ini_key_value(line) else {
            continue;
        };
        if !key.eq_ignore_ascii_case("DEFAULT_INPUT_POLICY") {
            continue;
        }

        let policy = value.trim_matches('"').trim_matches('\'').trim();
        if policy.is_empty() {
            continue;
        }

        return Some(policy.to_ascii_uppercase());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::HostScanner;
    use crate::host::tests::{temp_host_root, write_file};

    #[test]
    fn reports_ufw_when_installed_but_disabled() {
        let root = temp_host_root("ufw-disabled");
        write_file(&root.join("usr/sbin/ufw"), "");
        write_file(&root.join(UFW_CONFIG_PATH), "ENABLED=no\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.ufw_installed_but_disabled")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn reports_ufw_default_input_policy_accept() {
        let root = temp_host_root("ufw-default-accept");
        write_file(&root.join("usr/sbin/ufw"), "");
        write_file(&root.join(UFW_CONFIG_PATH), "ENABLED=yes\n");
        write_file(
            &root.join(UFW_DEFAULT_POLICY_PATH),
            "DEFAULT_INPUT_POLICY=\"ACCEPT\"\n",
        );

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.ufw_default_input_policy_accept")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn does_not_report_ufw_default_policy_when_drop() {
        let root = temp_host_root("ufw-default-drop");
        write_file(&root.join("usr/sbin/ufw"), "");
        write_file(&root.join(UFW_CONFIG_PATH), "ENABLED=yes\n");
        write_file(
            &root.join(UFW_DEFAULT_POLICY_PATH),
            "DEFAULT_INPUT_POLICY=\"DROP\"\n",
        );

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "host.ufw_default_input_policy_accept")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn does_not_report_ufw_when_enabled() {
        let root = temp_host_root("ufw-enabled");
        write_file(&root.join(UFW_CONFIG_PATH), "ENABLED=yes\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "host.ufw_installed_but_disabled")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_firewalld_disabled() {
        let root = temp_host_root("firewalld-disabled");
        write_file(&root.join("usr/bin/firewall-cmd"), "");
        write_file(
            &root.join("etc/firewalld/firewalld.conf"),
            "DefaultZone=public\n",
        );
        write_file(&root.join("etc/hostname"), "firewalld-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.firewalld_installed_but_disabled")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_firewalld_trusted_zone() {
        let root = temp_host_root("firewalld-trusted");
        write_file(&root.join("usr/bin/firewall-cmd"), "");
        write_file(
            &root.join("etc/systemd/system/multi-user.target.wants/firewalld.service"),
            "",
        );
        write_file(
            &root.join("etc/firewalld/firewalld.conf"),
            "DefaultZone=trusted\n",
        );
        write_file(&root.join("etc/hostname"), "firewalld-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.firewalld_default_zone_trusted")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_nftables_empty() {
        let root = temp_host_root("nftables-empty");
        write_file(&root.join("etc/nftables.conf"), "");
        write_file(&root.join("etc/hostname"), "nftables-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.nftables_installed_no_rules")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn ufw_default_input_policy_parser_handles_common_formats() {
        assert_eq!(
            parse_ufw_default_input_policy("DEFAULT_INPUT_POLICY=\"ACCEPT\""),
            Some(String::from("ACCEPT"))
        );
        assert_eq!(
            parse_ufw_default_input_policy("DEFAULT_INPUT_POLICY='DROP'"),
            Some(String::from("DROP"))
        );
        assert_eq!(
            parse_ufw_default_input_policy("DEFAULT_INPUT_POLICY="),
            None
        );
    }
}
