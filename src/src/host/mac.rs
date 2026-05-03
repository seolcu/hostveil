use std::collections::BTreeMap;
use std::path::Path;

use super::{HostContext, HostFindingText, host_finding, read_sysctl, resolve_existing_path};
use crate::domain::{Finding, Severity};

pub fn scan_mac_frameworks(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    let selinux_installed = resolve_existing_path(&context.root, "etc/selinux/config").is_some()
        || resolve_existing_path(&context.root, "sys/fs/selinux").is_some();

    if selinux_installed {
        let mode = read_selinux_mode(&context.root);
        match mode.as_deref() {
            Some("enforcing") => {}
            Some("permissive") => {
                findings.push(host_finding(
                    "host.selinux_permissive",
                    Severity::Medium,
                    &context.root.join("etc/selinux/config"),
                    HostFindingText {
                        title: t!("finding.host.selinux_permissive.title").into_owned(),
                        description: t!(
                            "finding.host.selinux_permissive.description",
                            path = context
                                .root
                                .join("etc/selinux/config")
                                .display()
                                .to_string()
                        )
                        .into_owned(),
                        why_risky: t!("finding.host.selinux_permissive.why").into_owned(),
                        how_to_fix: t!("finding.host.selinux_permissive.fix").into_owned(),
                    },
                    BTreeMap::from([(String::from("mode"), String::from("permissive"))]),
                ));
            }
            Some("disabled") | None => {
                findings.push(host_finding(
                    "host.selinux_disabled",
                    Severity::Medium,
                    &context.root.join("etc/selinux/config"),
                    HostFindingText {
                        title: t!("finding.host.selinux_disabled.title").into_owned(),
                        description: t!(
                            "finding.host.selinux_disabled.description",
                            path = context
                                .root
                                .join("etc/selinux/config")
                                .display()
                                .to_string()
                        )
                        .into_owned(),
                        why_risky: t!("finding.host.selinux_disabled.why").into_owned(),
                        how_to_fix: t!("finding.host.selinux_disabled.fix").into_owned(),
                    },
                    BTreeMap::from([(String::from("mode"), String::from("disabled"))]),
                ));
            }
            _ => {}
        }
    }

    let apparmor_present =
        resolve_existing_path(&context.root, "sys/kernel/security/apparmor").is_some();
    let apparmor_profiles = apparmor_present
        .then(|| read_sysctl(context, "sys/kernel/security/apparmor/profiles"))
        .flatten();

    if let Some(ref profiles) = apparmor_profiles
        && profiles.contains(" (complain)")
    {
        findings.push(host_finding(
            "host.apparmor_complain_mode",
            Severity::Medium,
            &context.root.join("sys/kernel/security/apparmor/profiles"),
            HostFindingText {
                title: t!("finding.host.apparmor_complain_mode.title").into_owned(),
                description: t!(
                    "finding.host.apparmor_complain_mode.description",
                    path = context
                        .root
                        .join("sys/kernel/security/apparmor/profiles")
                        .display()
                        .to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.apparmor_complain_mode.why").into_owned(),
                how_to_fix: t!("finding.host.apparmor_complain_mode.fix").into_owned(),
            },
            BTreeMap::new(),
        ));
    }

    if let Some(ref profiles) = apparmor_profiles {
        let expected_services = [("docker", "docker"), ("nginx", "nginx"), ("sshd", "sshd")];
        for (service, pattern) in expected_services {
            let has_profile = profiles
                .lines()
                .any(|line| line.to_lowercase().contains(pattern));
            if !has_profile {
                findings.push(host_finding(
                    &format!("host.apparmor_{service}_profile_missing"),
                    Severity::Low,
                    &context.root.join("sys/kernel/security/apparmor/profiles"),
                    HostFindingText {
                        title: t!(
                            "finding.host.apparmor_profile_missing.title",
                            service = service
                        )
                        .into_owned(),
                        description: t!(
                            "finding.host.apparmor_profile_missing.description",
                            service = service,
                            path = context
                                .root
                                .join("sys/kernel/security/apparmor/profiles")
                                .display()
                                .to_string()
                        )
                        .into_owned(),
                        why_risky: t!("finding.host.apparmor_profile_missing.why").into_owned(),
                        how_to_fix: t!("finding.host.apparmor_profile_missing.fix").into_owned(),
                    },
                    BTreeMap::from([(String::from("service"), String::from(service))]),
                ));
            }
        }
    }

    if !selinux_installed && !apparmor_present {
        findings.push(host_finding(
            "host.mac_framework_missing",
            Severity::Low,
            &context.root,
            HostFindingText {
                title: t!("finding.host.mac_framework_missing.title").into_owned(),
                description: t!(
                    "finding.host.mac_framework_missing.description",
                    path = context.root.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.mac_framework_missing.why").into_owned(),
                how_to_fix: t!("finding.host.mac_framework_missing.fix").into_owned(),
            },
            BTreeMap::new(),
        ));
    }

    findings
}

fn read_selinux_mode(root: &Path) -> Option<String> {
    let path = root.join("etc/selinux/config");
    let text = std::fs::read_to_string(&path).ok()?;
    for line in text.lines() {
        let stripped = line.split('#').next().unwrap_or("").trim();
        if stripped.is_empty() {
            continue;
        }
        let Some((key, value)) = stripped.split_once('=') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("SELINUX") {
            return Some(value.trim().to_ascii_lowercase());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::HostScanner;
    use crate::host::tests::{temp_host_root, write_file};

    #[test]
    fn host_scanner_detects_selinux_permissive() {
        let root = temp_host_root("selinux-permissive");
        write_file(
            &root.join("etc/selinux/config"),
            "SELINUX=permissive\nSELINUXTYPE=targeted\n",
        );
        write_file(&root.join("etc/hostname"), "selinux-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.selinux_permissive")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_apparmor_complain_mode() {
        let root = temp_host_root("apparmor-complain");
        write_file(
            &root.join("sys/kernel/security/apparmor/profiles"),
            concat!(
                "/usr/sbin/dnsmasq (enforce)\n",
                "/usr/bin/dockerd (complain)\n",
                "/usr/sbin/nginx (enforce)\n",
                "/usr/sbin/sshd (enforce)\n",
            ),
        );
        write_file(&root.join("etc/hostname"), "apparmor-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.apparmor_complain_mode")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_reports_mac_missing_when_neither_present() {
        let root = temp_host_root("mac-missing");
        write_file(&root.join("etc/hostname"), "mac-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.mac_framework_missing")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }
}
