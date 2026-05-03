use std::collections::BTreeMap;

use super::{HostContext, HostFindingText, host_finding, read_sysctl, resolve_existing_path};
use crate::domain::{Finding, Severity};

pub fn scan_kernel_hardening(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(value) = read_sysctl(context, "proc/sys/kernel/randomize_va_space")
        && value.trim() == "0"
    {
        findings.push(host_finding(
            "host.kernel.aslr_disabled",
            Severity::High,
            &context.root.join("proc/sys/kernel/randomize_va_space"),
            HostFindingText {
                title: t!("finding.host.kernel_aslr_disabled.title").into_owned(),
                description: t!(
                    "finding.host.kernel_aslr_disabled.description",
                    path = context
                        .root
                        .join("proc/sys/kernel/randomize_va_space")
                        .display()
                        .to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.kernel_aslr_disabled.why").into_owned(),
                how_to_fix: t!("finding.host.kernel_aslr_disabled.fix").into_owned(),
            },
            BTreeMap::from([(String::from("value"), String::from("0"))]),
        ));
    }

    if let Some(value) = read_sysctl(context, "proc/sys/net/ipv4/tcp_syncookies")
        && value.trim() == "0"
    {
        findings.push(host_finding(
            "host.kernel.syn_cookies_disabled",
            Severity::Medium,
            &context.root.join("proc/sys/net/ipv4/tcp_syncookies"),
            HostFindingText {
                title: t!("finding.host.kernel_syn_cookies_disabled.title").into_owned(),
                description: t!(
                    "finding.host.kernel_syn_cookies_disabled.description",
                    path = context
                        .root
                        .join("proc/sys/net/ipv4/tcp_syncookies")
                        .display()
                        .to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.kernel_syn_cookies_disabled.why").into_owned(),
                how_to_fix: t!("finding.host.kernel_syn_cookies_disabled.fix").into_owned(),
            },
            BTreeMap::from([(String::from("value"), String::from("0"))]),
        ));
    }

    if let Some(value) = read_sysctl(context, "proc/sys/net/ipv4/icmp_echo_ignore_broadcasts")
        && value.trim() == "0"
    {
        findings.push(host_finding(
            "host.kernel.broadcast_ping_allowed",
            Severity::Low,
            &context
                .root
                .join("proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"),
            HostFindingText {
                title: t!("finding.host.kernel_broadcast_ping_allowed.title").into_owned(),
                description: t!(
                    "finding.host.kernel_broadcast_ping_allowed.description",
                    path = context
                        .root
                        .join("proc/sys/net/ipv4/icmp_echo_ignore_broadcasts")
                        .display()
                        .to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.kernel_broadcast_ping_allowed.why").into_owned(),
                how_to_fix: t!("finding.host.kernel_broadcast_ping_allowed.fix").into_owned(),
            },
            BTreeMap::from([(String::from("value"), String::from("0"))]),
        ));
    }

    let docker_present = resolve_existing_path(&context.root, "var/run/docker.sock").is_some();
    if !docker_present
        && let Some(value) = read_sysctl(context, "proc/sys/net/ipv4/ip_forward")
        && value.trim() == "1"
    {
        findings.push(host_finding(
            "host.kernel.ip_forward_enabled",
            Severity::Medium,
            &context.root.join("proc/sys/net/ipv4/ip_forward"),
            HostFindingText {
                title: t!("finding.host.kernel_ip_forward_enabled.title").into_owned(),
                description: t!(
                    "finding.host.kernel_ip_forward_enabled.description",
                    path = context
                        .root
                        .join("proc/sys/net/ipv4/ip_forward")
                        .display()
                        .to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.kernel_ip_forward_enabled.why").into_owned(),
                how_to_fix: t!("finding.host.kernel_ip_forward_enabled.fix").into_owned(),
            },
            BTreeMap::from([(String::from("value"), String::from("1"))]),
        ));
    }

    if let Some(value) = read_sysctl(context, "proc/sys/kernel/modules_disabled")
        && value.trim() == "0"
    {
        findings.push(host_finding(
            "host.kernel.modules_disabled_not_set",
            Severity::Medium,
            &context.root.join("proc/sys/kernel/modules_disabled"),
            HostFindingText {
                title: t!("finding.host.kernel_modules_disabled_not_set.title").into_owned(),
                description: t!(
                    "finding.host.kernel_modules_disabled_not_set.description",
                    path = context
                        .root
                        .join("proc/sys/kernel/modules_disabled")
                        .display()
                        .to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.kernel_modules_disabled_not_set.why").into_owned(),
                how_to_fix: t!("finding.host.kernel_modules_disabled_not_set.fix").into_owned(),
            },
            BTreeMap::from([(String::from("value"), String::from("0"))]),
        ));
    }

    let sig_enforce_path = "sys/module/module/parameters/sig_enforce";
    let sig_enforce_value = read_sysctl(context, sig_enforce_path);
    let sig_enforce_missing = sig_enforce_value.is_none();
    let sig_enforce_disabled = sig_enforce_value
        .as_deref()
        .is_some_and(|v| v.trim() == "N");

    if sig_enforce_missing || sig_enforce_disabled {
        findings.push(host_finding(
            "host.kernel.module_signing_not_enforced",
            Severity::Low,
            &context.root.join(sig_enforce_path),
            HostFindingText {
                title: t!("finding.host.kernel_module_signing_not_enforced.title").into_owned(),
                description: t!(
                    "finding.host.kernel_module_signing_not_enforced.description",
                    path = context.root.join(sig_enforce_path).display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.kernel_module_signing_not_enforced.why").into_owned(),
                how_to_fix: t!("finding.host.kernel_module_signing_not_enforced.fix").into_owned(),
            },
            BTreeMap::from([(
                String::from("state"),
                if sig_enforce_missing {
                    String::from("missing")
                } else {
                    String::from("disabled")
                },
            )]),
        ));
    }

    findings
}

pub fn scan_secure_boot(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    let efi_vars_path = context.root.join("sys/firmware/efi/efivars");
    if !efi_vars_path.exists() {
        return findings;
    }

    let secure_boot_path = resolve_existing_path(
        &context.root,
        "sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
    );

    if secure_boot_path.is_none() {
        return findings;
    }

    let secure_boot_path = secure_boot_path.unwrap();
    let Ok(data) = std::fs::read(&secure_boot_path) else {
        return findings;
    };

    if data.len() < 5 {
        return findings;
    }

    let secure_boot_enabled = data[4] == 1;

    if !secure_boot_enabled {
        findings.push(host_finding(
            "host.secure_boot_disabled",
            Severity::Low,
            &secure_boot_path,
            HostFindingText {
                title: t!("finding.host.secure_boot_disabled.title").into_owned(),
                description: t!(
                    "finding.host.secure_boot_disabled.description",
                    path = secure_boot_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.secure_boot_disabled.why").into_owned(),
                how_to_fix: t!("finding.host.secure_boot_disabled.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), secure_boot_path.display().to_string())]),
        ));
    }

    findings
}

pub fn scan_user_namespace_settings(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    let docker_present = resolve_existing_path(&context.root, "var/run/docker.sock").is_some();

    if docker_present {
        return findings;
    }

    if let Some(value) = read_sysctl(context, "proc/sys/kernel/unprivileged_userns_clone")
        && value.trim() == "1"
    {
        findings.push(host_finding(
            "host.kernel.unprivileged_userns_clone_enabled",
            Severity::Medium,
            &context
                .root
                .join("proc/sys/kernel/unprivileged_userns_clone"),
            HostFindingText {
                title: t!("finding.host.kernel_unprivileged_userns_clone_enabled.title")
                    .into_owned(),
                description: t!(
                    "finding.host.kernel_unprivileged_userns_clone_enabled.description",
                    path = context
                        .root
                        .join("proc/sys/kernel/unprivileged_userns_clone")
                        .display()
                        .to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.kernel_unprivileged_userns_clone_enabled.why")
                    .into_owned(),
                how_to_fix: t!("finding.host.kernel_unprivileged_userns_clone_enabled.fix")
                    .into_owned(),
            },
            BTreeMap::from([(String::from("value"), String::from("1"))]),
        ));
    }

    if let Some(value) = read_sysctl(context, "proc/sys/user/max_user_namespaces")
        && value.trim().parse::<u64>().unwrap_or(1) > 0
    {
        findings.push(host_finding(
            "host.kernel.max_user_namespaces_enabled",
            Severity::Low,
            &context.root.join("proc/sys/user/max_user_namespaces"),
            HostFindingText {
                title: t!("finding.host.kernel_max_user_namespaces_enabled.title").into_owned(),
                description: t!(
                    "finding.host.kernel_max_user_namespaces_enabled.description",
                    path = context
                        .root
                        .join("proc/sys/user/max_user_namespaces")
                        .display()
                        .to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.kernel_max_user_namespaces_enabled.why").into_owned(),
                how_to_fix: t!("finding.host.kernel_max_user_namespaces_enabled.fix").into_owned(),
            },
            BTreeMap::from([(String::from("value"), value.trim().to_owned())]),
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::HostScanner;
    use crate::host::tests::{temp_host_root, write_file};

    #[test]
    fn host_scanner_detects_modules_disabled_not_set() {
        let root = temp_host_root("modules-disabled");
        write_file(&root.join("proc/sys/kernel/modules_disabled"), "0\n");
        write_file(&root.join("etc/hostname"), "modules-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.kernel.modules_disabled_not_set")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }
}
