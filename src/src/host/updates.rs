use std::collections::BTreeMap;
use std::fs;

use super::{
    HostContext, HostFindingText, host_finding, parse_apt_periodic_bool, parse_ini_bool_in_section,
    resolve_existing_path,
};
use crate::domain::{Finding, RemediationKind, Severity};

const APT_AUTO_UPGRADES_CONFIG_PATH: &str = "etc/apt/apt.conf.d/20auto-upgrades";
const DNF_AUTOMATIC_CONF_PATH: &str = "etc/dnf/automatic.conf";
const DNF_AUTOMATIC_TIMER_ENABLED: [&str; 2] = [
    "etc/systemd/system/multi-user.target.wants/dnf-automatic.timer",
    "etc/systemd/system/timers.target.wants/dnf-automatic.timer",
];
const YUM_CRON_CONF_PATH: &str = "etc/yum/yum-cron.conf";
const YUM_CRON_SERVICE_ENABLED: [&str; 2] = [
    "etc/systemd/system/multi-user.target.wants/yum-cron.service",
    "etc/systemd/system/default.target.wants/yum-cron.service",
];

pub fn scan_package_update_hardening(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(scan_apt_auto_upgrades(context));
    findings.extend(scan_dnf_auto_updates(context));
    findings.extend(scan_yum_cron(context));
    findings
}

fn scan_apt_auto_upgrades(context: &HostContext) -> Vec<Finding> {
    let Some(config_path) = resolve_existing_path(&context.root, APT_AUTO_UPGRADES_CONFIG_PATH)
    else {
        return Vec::new();
    };

    let Ok(config_text) = fs::read_to_string(&config_path) else {
        return Vec::new();
    };

    let mut findings = Vec::new();

    if let Some(enabled) = parse_unattended_upgrades_enabled(&config_text)
        && !enabled
    {
        findings.push(host_finding(
            "host.apt_unattended_upgrades_disabled",
            Severity::Medium,
            &config_path,
            HostFindingText {
                title: t!("finding.host.unattended_upgrades_disabled.title").into_owned(),
                description: t!(
                    "finding.host.unattended_upgrades_disabled.description",
                    path = config_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.unattended_upgrades_disabled.why").into_owned(),
                how_to_fix: t!("finding.host.unattended_upgrades_disabled.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), config_path.display().to_string()),
                (String::from("unattended_upgrade"), String::from("disabled")),
            ]),
            RemediationKind::Review,
        ));
    }

    if let Some(enabled) = parse_package_lists_auto_update_enabled(&config_text)
        && !enabled
    {
        findings.push(host_finding(
            "host.apt_package_lists_auto_update_disabled",
            Severity::Low,
            &config_path,
            HostFindingText {
                title: t!("finding.host.package_lists_auto_update_disabled.title").into_owned(),
                description: t!(
                    "finding.host.package_lists_auto_update_disabled.description",
                    path = config_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.package_lists_auto_update_disabled.why").into_owned(),
                how_to_fix: t!("finding.host.package_lists_auto_update_disabled.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), config_path.display().to_string()),
                (
                    String::from("update_package_lists"),
                    String::from("disabled"),
                ),
            ]),
            RemediationKind::Review,
        ));
    }

    findings
}

fn scan_dnf_auto_updates(context: &HostContext) -> Vec<Finding> {
    let Some(config_path) = resolve_existing_path(&context.root, DNF_AUTOMATIC_CONF_PATH) else {
        return Vec::new();
    };

    let Ok(config_text) = fs::read_to_string(&config_path) else {
        return Vec::new();
    };

    let mut findings = Vec::new();

    if let Some(enabled) = parse_ini_bool_in_section(&config_text, "commands", "apply_updates")
        && !enabled
    {
        findings.push(host_finding(
            "host.dnf_automatic_disabled",
            Severity::Medium,
            &config_path,
            HostFindingText {
                title: t!("finding.host.dnf_automatic_disabled.title").into_owned(),
                description: t!(
                    "finding.host.dnf_automatic_disabled.description",
                    path = config_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.dnf_automatic_disabled.why").into_owned(),
                how_to_fix: t!("finding.host.dnf_automatic_disabled.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), config_path.display().to_string()),
                (String::from("apply_updates"), String::from("disabled")),
            ]),
            RemediationKind::Review,
        ));
    }

    if !DNF_AUTOMATIC_TIMER_ENABLED
        .iter()
        .any(|marker| resolve_existing_path(&context.root, marker).is_some())
    {
        findings.push(host_finding(
            "host.dnf_automatic_timer_disabled",
            Severity::Medium,
            &config_path,
            HostFindingText {
                title: t!("finding.host.dnf_automatic_timer_disabled.title").into_owned(),
                description: t!(
                    "finding.host.dnf_automatic_timer_disabled.description",
                    path = config_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.dnf_automatic_timer_disabled.why").into_owned(),
                how_to_fix: t!("finding.host.dnf_automatic_timer_disabled.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), config_path.display().to_string()),
                (String::from("timer"), String::from("disabled")),
            ]),
            RemediationKind::Review,
        ));
    }

    findings
}

fn scan_yum_cron(context: &HostContext) -> Vec<Finding> {
    let Some(config_path) = resolve_existing_path(&context.root, YUM_CRON_CONF_PATH) else {
        return Vec::new();
    };

    let Ok(config_text) = fs::read_to_string(&config_path) else {
        return Vec::new();
    };

    let mut findings = Vec::new();

    if let Some(enabled) = parse_ini_bool_in_section(&config_text, "commands", "apply_updates")
        && !enabled
    {
        findings.push(host_finding(
            "host.yum_cron_disabled",
            Severity::Medium,
            &config_path,
            HostFindingText {
                title: t!("finding.host.yum_cron_disabled.title").into_owned(),
                description: t!(
                    "finding.host.yum_cron_disabled.description",
                    path = config_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.yum_cron_disabled.why").into_owned(),
                how_to_fix: t!("finding.host.yum_cron_disabled.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), config_path.display().to_string()),
                (String::from("apply_updates"), String::from("disabled")),
            ]),
            RemediationKind::Review,
        ));
    }

    if !YUM_CRON_SERVICE_ENABLED
        .iter()
        .any(|marker| resolve_existing_path(&context.root, marker).is_some())
    {
        findings.push(host_finding(
            "host.yum_cron_service_disabled",
            Severity::Medium,
            &config_path,
            HostFindingText {
                title: t!("finding.host.yum_cron_service_disabled.title").into_owned(),
                description: t!(
                    "finding.host.yum_cron_service_disabled.description",
                    path = config_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.yum_cron_service_disabled.why").into_owned(),
                how_to_fix: t!("finding.host.yum_cron_service_disabled.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), config_path.display().to_string()),
                (String::from("service"), String::from("disabled")),
            ]),
            RemediationKind::Review,
        ));
    }

    findings
}

fn parse_unattended_upgrades_enabled(text: &str) -> Option<bool> {
    parse_apt_periodic_bool(text, "APT::Periodic::Unattended-Upgrade")
}

fn parse_package_lists_auto_update_enabled(text: &str) -> Option<bool> {
    parse_apt_periodic_bool(text, "APT::Periodic::Update-Package-Lists")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::HostScanner;
    use crate::host::tests::{temp_host_root, write_file};

    #[test]
    fn reports_unattended_upgrades_when_explicitly_disabled() {
        let root = temp_host_root("apt-auto-upgrades-disabled");
        write_file(
            &root.join(APT_AUTO_UPGRADES_CONFIG_PATH),
            concat!(
                "APT::Periodic::Update-Package-Lists \"1\";\n",
                "APT::Periodic::Unattended-Upgrade \"0\";\n"
            ),
        );

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.apt_unattended_upgrades_disabled")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn reports_package_list_auto_updates_when_disabled() {
        let root = temp_host_root("apt-package-lists-disabled");
        write_file(
            &root.join(APT_AUTO_UPGRADES_CONFIG_PATH),
            concat!(
                "APT::Periodic::Update-Package-Lists \"0\";\n",
                "APT::Periodic::Unattended-Upgrade \"1\";\n"
            ),
        );

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.apt_package_lists_auto_update_disabled")
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "host.apt_unattended_upgrades_disabled")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn unattended_upgrades_parser_handles_common_formats() {
        assert_eq!(
            parse_unattended_upgrades_enabled("APT::Periodic::Unattended-Upgrade \"1\";"),
            Some(true)
        );
        assert_eq!(
            parse_unattended_upgrades_enabled("APT::Periodic::Unattended-Upgrade \"0\";"),
            Some(false)
        );
        assert_eq!(
            parse_unattended_upgrades_enabled("APT::Periodic::Unattended-Upgrade 1;"),
            Some(true)
        );
        assert_eq!(
            parse_unattended_upgrades_enabled("APT::Periodic::Update-Package-Lists \"1\";"),
            None
        );
        assert_eq!(
            parse_package_lists_auto_update_enabled("APT::Periodic::Update-Package-Lists \"1\";"),
            Some(true)
        );
        assert_eq!(
            parse_package_lists_auto_update_enabled("APT::Periodic::Update-Package-Lists 0;"),
            Some(false)
        );
    }

    #[test]
    fn host_scanner_detects_dnf_automatic_disabled() {
        let root = temp_host_root("dnf-automatic-disabled");
        write_file(
            &root.join("etc/dnf/automatic.conf"),
            "[commands]\napply_updates = no\n",
        );
        write_file(&root.join("etc/hostname"), "dnf-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.dnf_automatic_disabled")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.dnf_automatic_timer_disabled")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_yum_cron_disabled() {
        let root = temp_host_root("yum-cron-disabled");
        write_file(
            &root.join("etc/yum/yum-cron.conf"),
            "[commands]\napply_updates = no\n",
        );
        write_file(&root.join("etc/hostname"), "yum-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.yum_cron_disabled")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.yum_cron_service_disabled")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn parse_ini_bool_in_section_handles_sections() {
        let text = concat!(
            "[commands]\n",
            "apply_updates = yes\n",
            "\n",
            "[email]\n",
            "apply_updates = no\n",
        );
        assert_eq!(
            parse_ini_bool_in_section(text, "commands", "apply_updates"),
            Some(true)
        );
        assert_eq!(
            parse_ini_bool_in_section(text, "email", "apply_updates"),
            Some(false)
        );
        assert_eq!(parse_ini_bool_in_section(text, "commands", "missing"), None);
    }
}
