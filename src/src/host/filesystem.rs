use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use super::{HostContext, HostFindingText, host_finding, parse_proc_mounts, resolve_existing_path};
use crate::domain::{Finding, RemediationKind, Severity};

const SYSTEMD_SERVICE_DIRS: [&str; 2] = ["etc/systemd/system", "lib/systemd/system"];
const SYSTEMD_HARDENING_MARKERS: [&str; 4] = [
    "NoNewPrivileges",
    "ProtectSystem",
    "ProtectHome",
    "PrivateTmp",
];
const SYSTEMD_HARDENING_SAMPLE_SERVICES: [&str; 4] = [
    "sshd.service",
    "docker.service",
    "nginx.service",
    "fail2ban.service",
];

pub fn scan_mount_flags(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mounts_path = context.root.join("proc/mounts");

    let text = match fs::read_to_string(&mounts_path) {
        Ok(text) => text,
        Err(_) => return findings,
    };

    let mounts = parse_proc_mounts(&text);

    let sensitive_mounts: [(&str, &[&str]); 4] = [
        ("/tmp", &["noexec", "nosuid", "nodev"]),
        ("/home", &["noexec", "nosuid", "nodev"]),
        ("/var", &["noexec", "nosuid", "nodev"]),
        ("/boot", &["noexec", "nosuid", "nodev"]),
    ];

    for (mount_point, expected_flags) in &sensitive_mounts {
        let Some(options) = mounts.get(*mount_point) else {
            continue;
        };

        let missing: Vec<&str> = expected_flags
            .iter()
            .filter(|flag| !options.iter().any(|opt| opt == **flag))
            .copied()
            .collect();

        if missing.is_empty() {
            continue;
        }

        findings.push(host_finding(
            "host.mount_flags_missing",
            Severity::Medium,
            &mounts_path,
            HostFindingText {
                title: t!("finding.host.mount_flags_missing.title").into_owned(),
                description: t!(
                    "finding.host.mount_flags_missing.description",
                    mount_point = mount_point,
                    flags = missing.join(", ")
                )
                .into_owned(),
                why_risky: t!("finding.host.mount_flags_missing.why").into_owned(),
                how_to_fix: t!("finding.host.mount_flags_missing.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("mount_point"), mount_point.to_string()),
                (String::from("missing_flags"), missing.join(", ")),
            ]),
            RemediationKind::Review,
        ));
    }

    findings
}

pub fn scan_proc_hidepid(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mounts_path = context.root.join("proc/mounts");

    let text = match fs::read_to_string(&mounts_path) {
        Ok(text) => text,
        Err(_) => return findings,
    };

    let mounts = parse_proc_mounts(&text);
    let options = match mounts.get("/proc") {
        Some(options) => options,
        None => {
            findings.push(host_finding(
                "host.proc_hidepid_missing",
                Severity::Medium,
                &mounts_path,
                HostFindingText {
                    title: t!("finding.host.proc_hidepid_missing.title").into_owned(),
                    description: t!("finding.host.proc_hidepid_missing.description").into_owned(),
                    why_risky: t!("finding.host.proc_hidepid_missing.why").into_owned(),
                    how_to_fix: t!("finding.host.proc_hidepid_missing.fix").into_owned(),
                },
                BTreeMap::new(),
                RemediationKind::Review,
            ));
            return findings;
        }
    };

    let has_hidepid = options.iter().any(|opt| opt.starts_with("hidepid="));
    let hidepid_hardened = options
        .iter()
        .any(|opt| opt == "hidepid=2" || opt == "hidepid=1");

    if !has_hidepid {
        findings.push(host_finding(
            "host.proc_hidepid_missing",
            Severity::Medium,
            &mounts_path,
            HostFindingText {
                title: t!("finding.host.proc_hidepid_missing.title").into_owned(),
                description: t!("finding.host.proc_hidepid_missing.description").into_owned(),
                why_risky: t!("finding.host.proc_hidepid_missing.why").into_owned(),
                how_to_fix: t!("finding.host.proc_hidepid_missing.fix").into_owned(),
            },
            BTreeMap::new(),
            RemediationKind::Review,
        ));
    } else if !hidepid_hardened {
        findings.push(host_finding(
            "host.proc_hidepid_weak",
            Severity::Low,
            &mounts_path,
            HostFindingText {
                title: t!("finding.host.proc_hidepid_weak.title").into_owned(),
                description: t!("finding.host.proc_hidepid_weak.description").into_owned(),
                why_risky: t!("finding.host.proc_hidepid_weak.why").into_owned(),
                how_to_fix: t!("finding.host.proc_hidepid_weak.fix").into_owned(),
            },
            BTreeMap::new(),
            RemediationKind::Review,
        ));
    }

    findings
}

pub fn scan_systemd_hardening(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    for service_name in SYSTEMD_HARDENING_SAMPLE_SERVICES {
        let Some(path) = find_systemd_service_path(context, service_name) else {
            continue;
        };

        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(_) => continue,
        };

        let missing: Vec<&str> = SYSTEMD_HARDENING_MARKERS
            .iter()
            .filter(|marker| !text.contains(**marker))
            .copied()
            .collect();

        if missing.is_empty() {
            continue;
        }

        findings.push(host_finding(
            "host.systemd_hardening_missing",
            Severity::Low,
            &path,
            HostFindingText {
                title: t!("finding.host.systemd_hardening_missing.title").into_owned(),
                description: t!(
                    "finding.host.systemd_hardening_missing.description",
                    service = service_name,
                    flags = missing.join(", ")
                )
                .into_owned(),
                why_risky: t!("finding.host.systemd_hardening_missing.why").into_owned(),
                how_to_fix: t!("finding.host.systemd_hardening_missing.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("service"), service_name.to_owned()),
                (String::from("missing_flags"), missing.join(", ")),
            ]),
            RemediationKind::Review,
        ));
    }

    findings
}

fn find_systemd_service_path(context: &HostContext, name: &str) -> Option<PathBuf> {
    for dir in SYSTEMD_SERVICE_DIRS {
        let candidate = context.root.join(dir).join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

pub fn scan_grub_hardening(context: &HostContext) -> Vec<Finding> {
    let grub_paths = ["boot/grub/grub.cfg", "boot/grub2/grub.cfg"];

    for relative in &grub_paths {
        let Some(path) = resolve_existing_path(&context.root, relative) else {
            continue;
        };

        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };

        let lower = text.to_ascii_lowercase();
        if lower.contains("password_pbkdf2")
            || lower.contains("password")
            || lower.contains("--unrestricted")
        {
            return Vec::new();
        }

        return vec![host_finding(
            "host.grub_password_missing",
            Severity::Medium,
            &path,
            HostFindingText {
                title: t!("finding.host.grub_password_missing.title").into_owned(),
                description: t!(
                    "finding.host.grub_password_missing.description",
                    path = path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.grub_password_missing.why").into_owned(),
                how_to_fix: t!("finding.host.grub_password_missing.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), path.display().to_string())]),
            RemediationKind::Review,
        )];
    }

    Vec::new()
}

pub fn scan_shadow_hardening(context: &HostContext) -> Vec<Finding> {
    let Some(path) = resolve_existing_path(&context.root, "etc/shadow") else {
        return Vec::new();
    };

    let mut findings = Vec::new();

    if let Ok(metadata) = fs::metadata(&path) {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 > 0o040 {
            findings.push(host_finding(
                "host.shadow_permissions_weak",
                Severity::Medium,
                &path,
                HostFindingText {
                    title: t!("finding.host.shadow_permissions_weak.title").into_owned(),
                    description: t!(
                        "finding.host.shadow_permissions_weak.description",
                        path = path.display().to_string(),
                        mode = super::format_permissions(mode)
                    )
                    .into_owned(),
                    why_risky: t!("finding.host.shadow_permissions_weak.why").into_owned(),
                    how_to_fix: t!("finding.host.shadow_permissions_weak.fix").into_owned(),
                },
                BTreeMap::from([
                    (String::from("path"), path.display().to_string()),
                    (String::from("mode"), super::format_permissions(mode)),
                ]),
                RemediationKind::Review,
            ));
        }
    }

    let Ok(text) = fs::read_to_string(&path) else {
        return findings;
    };

    let mut weak_hash_algorithm = None;
    let mut empty_password_found = false;

    for line in text.lines() {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = stripped.split(':').collect();
        if parts.len() < 2 {
            continue;
        }

        let hash = parts[1];
        if hash.is_empty() {
            empty_password_found = true;
            continue;
        }

        if hash.starts_with("*") || hash.starts_with("!") {
            continue;
        }

        if hash.starts_with("$1$") && weak_hash_algorithm.is_none() {
            weak_hash_algorithm = Some("MD5");
        } else if hash.starts_with("$5$") && weak_hash_algorithm.is_none() {
            weak_hash_algorithm = Some("SHA-256");
        } else if hash.starts_with("$6$") || hash.starts_with("$y$") || hash.starts_with("$2") {
            continue;
        } else if weak_hash_algorithm.is_none() {
            weak_hash_algorithm = Some("unknown/legacy");
        }
    }

    if empty_password_found {
        findings.push(host_finding(
            "host.shadow_empty_password",
            Severity::Critical,
            &path,
            HostFindingText {
                title: t!("finding.host.shadow_empty_password.title").into_owned(),
                description: t!(
                    "finding.host.shadow_empty_password.description",
                    path = path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.shadow_empty_password.why").into_owned(),
                how_to_fix: t!("finding.host.shadow_empty_password.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), path.display().to_string())]),
            RemediationKind::Review,
        ));
    }

    if let Some(algorithm) = weak_hash_algorithm {
        findings.push(host_finding(
            "host.shadow_weak_hash",
            Severity::High,
            &path,
            HostFindingText {
                title: t!("finding.host.shadow_weak_hash.title").into_owned(),
                description: t!(
                    "finding.host.shadow_weak_hash.description",
                    path = path.display().to_string(),
                    algorithm = algorithm
                )
                .into_owned(),
                why_risky: t!("finding.host.shadow_weak_hash.why").into_owned(),
                how_to_fix: t!("finding.host.shadow_weak_hash.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), path.display().to_string()),
                (String::from("algorithm"), algorithm.to_owned()),
            ]),
            RemediationKind::Review,
        ));
    }

    findings
}

pub fn scan_tmp_hardening(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    let mounts_path = context.root.join("proc/mounts");
    let Ok(text) = fs::read_to_string(&mounts_path) else {
        return findings;
    };

    let mut tmp_found = false;
    let mut tmp_flags = Vec::new();

    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        if parts[1] == "/tmp" {
            tmp_found = true;
            tmp_flags = parts[3].split(',').map(str::to_owned).collect();
            break;
        }
    }

    if !tmp_found {
        findings.push(host_finding(
            "host.tmp_not_tmpfs",
            Severity::Low,
            &context.root.join("proc/mounts"),
            HostFindingText {
                title: t!("finding.host.tmp_not_tmpfs.title").into_owned(),
                description: t!("finding.host.tmp_not_tmpfs.description").into_owned(),
                why_risky: t!("finding.host.tmp_not_tmpfs.why").into_owned(),
                how_to_fix: t!("finding.host.tmp_not_tmpfs.fix").into_owned(),
            },
            BTreeMap::new(),
            RemediationKind::Review,
        ));
        return findings;
    }

    let required_flags = ["noexec", "nosuid", "nodev"];
    let missing: Vec<String> = required_flags
        .iter()
        .filter(|flag| !tmp_flags.iter().any(|f| f == **flag))
        .map(|s| (*s).to_owned())
        .collect();

    if !missing.is_empty() {
        findings.push(host_finding(
            "host.tmp_tmpfs_flags_missing",
            Severity::Low,
            &context.root.join("proc/mounts"),
            HostFindingText {
                title: t!("finding.host.tmp_tmpfs_flags_missing.title").into_owned(),
                description: t!(
                    "finding.host.tmp_tmpfs_flags_missing.description",
                    flags = missing.join(", ")
                )
                .into_owned(),
                why_risky: t!("finding.host.tmp_tmpfs_flags_missing.why").into_owned(),
                how_to_fix: t!("finding.host.tmp_tmpfs_flags_missing.fix").into_owned(),
            },
            BTreeMap::from([(String::from("flags"), missing.join(", "))]),
            RemediationKind::Review,
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
    fn host_scanner_detects_missing_systemd_hardening() {
        let root = temp_host_root("systemd-hardening");
        write_file(
            &root.join("lib/systemd/system/sshd.service"),
            "[Service]\nExecStart=/usr/sbin/sshd\n",
        );
        write_file(&root.join("etc/hostname"), "systemd-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.systemd_hardening_missing"
                    && finding.evidence.get("service") == Some(&String::from("sshd.service")))
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_missing_proc_hidepid() {
        let root = temp_host_root("proc-hidepid");
        write_file(&root.join("proc/mounts"), "ext4 / ext4 rw,relatime 0 0\n");
        write_file(&root.join("etc/hostname"), "hidepid-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.proc_hidepid_missing")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_missing_mount_flags() {
        let root = temp_host_root("mount-flags");
        write_file(
            &root.join("proc/mounts"),
            concat!(
                "tmpfs /tmp tmpfs rw,relatime 0 0\n",
                "ext4 /home ext4 rw,noexec,nosuid,nodev,relatime 0 0\n",
                "ext4 /var ext4 rw,noexec,nosuid,nodev,relatime 0 0\n",
            ),
        );
        write_file(&root.join("etc/hostname"), "mount-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        let mount_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "host.mount_flags_missing")
            .collect();
        assert_eq!(mount_findings.len(), 1);
        assert_eq!(
            mount_findings[0].evidence.get("mount_point"),
            Some(&String::from("/tmp"))
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_missing_grub_password() {
        let root = temp_host_root("grub-missing");
        write_file(
            &root.join("boot/grub/grub.cfg"),
            "set timeout=5\nmenuentry 'Linux' {\nlinux /vmlinuz\n}\n",
        );
        write_file(&root.join("etc/hostname"), "grub-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.grub_password_missing")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_skips_grub_when_password_present() {
        let root = temp_host_root("grub-password");
        write_file(
            &root.join("boot/grub2/grub.cfg"),
            "set superusers=\"admin\"\npassword_pbkdf2 admin grub.pbkdf2...\n",
        );
        write_file(&root.join("etc/hostname"), "grub-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "host.grub_password_missing")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_weak_shadow_permissions() {
        let root = temp_host_root("shadow-perms");
        write_file(
            &root.join("etc/shadow"),
            "root:$6$rounds=5000$salt$hash:0:0:root:/root:/bin/bash\n",
        );
        fs::set_permissions(root.join("etc/shadow"), fs::Permissions::from_mode(0o644))
            .expect("permissions should be set");
        write_file(&root.join("etc/hostname"), "shadow-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.shadow_permissions_weak")
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "host.shadow_weak_hash")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_weak_shadow_hashes() {
        let root = temp_host_root("shadow-hash");
        write_file(
            &root.join("etc/shadow"),
            "root:$1$salt$hash:0:0:root:/root:/bin/bash\n",
        );
        fs::set_permissions(root.join("etc/shadow"), fs::Permissions::from_mode(0o640))
            .expect("permissions should be set");
        write_file(&root.join("etc/hostname"), "shadow-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.shadow_weak_hash")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_empty_shadow_passwords() {
        let root = temp_host_root("shadow-empty");
        write_file(&root.join("etc/shadow"), "root::0:0:root:/root:/bin/bash\n");
        fs::set_permissions(root.join("etc/shadow"), fs::Permissions::from_mode(0o640))
            .expect("permissions should be set");
        write_file(&root.join("etc/hostname"), "shadow-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.shadow_empty_password")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_tmp_not_tmpfs() {
        let root = temp_host_root("tmp-not-tmpfs");
        write_file(&root.join("proc/mounts"), "ext4 / ext4 rw,relatime 0 0\n");
        write_file(&root.join("etc/hostname"), "tmp-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.tmp_not_tmpfs")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_tmp_missing_flags() {
        let root = temp_host_root("tmp-flags");
        write_file(
            &root.join("proc/mounts"),
            concat!(
                "tmpfs /tmp tmpfs rw,nosuid,nodev,relatime 0 0\n",
                "ext4 / ext4 rw,relatime 0 0\n",
            ),
        );
        write_file(&root.join("etc/hostname"), "tmp-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.tmp_tmpfs_flags_missing")
        );
        assert_eq!(
            findings
                .iter()
                .find(|f| f.id == "host.tmp_tmpfs_flags_missing")
                .and_then(|f| f.evidence.get("flags")),
            Some(&String::from("noexec"))
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }
}
