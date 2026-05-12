use std::collections::BTreeMap;
use std::path::Path;

use crate::domain::{Finding, Severity};
use crate::host::{HostContext, HostFindingText, host_finding, resolve_existing_path};

const AIDE_BINARIES: [&str; 2] = ["usr/bin/aide", "usr/sbin/aide"];
const AIDE_CONF: &str = "etc/aide/aide.conf";
const AIDE_DB_PATHS: [&str; 2] = ["var/lib/aide/aide.db", "var/lib/aide/aide.db.new"];

const TRIPWIRE_BINARIES: [&str; 1] = ["usr/sbin/tripwire"];
const TRIPWIRE_CFG: &str = "etc/tripwire/tw.cfg";
const TRIPWIRE_DB_DIR: &str = "var/lib/tripwire";

const SAMHAIN_BINARIES: [&str; 1] = ["usr/sbin/samhain"];
const SAMHAIN_CFG: &str = "etc/samhain/samhainrc";

const OSSEC_DIR: &str = "var/ossec";

pub fn scan_fim(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    let aide_installed = is_aide_installed(context);
    let tripwire_installed = is_tripwire_installed(context);
    let samhain_installed = is_samhain_installed(context);
    let ossec_installed = is_ossec_installed(context);

    let any_fim = aide_installed || tripwire_installed || samhain_installed || ossec_installed;

    if !any_fim {
        findings.push(host_finding(
            "host.fim_missing",
            Severity::Medium,
            Path::new("/"),
            HostFindingText {
                title: t!("finding.host.fim_missing.title").into_owned(),
                description: t!("finding.host.fim_missing.description").into_owned(),
                why_risky: t!("finding.host.fim_missing.why").into_owned(),
                how_to_fix: t!("finding.host.fim_missing.fix").into_owned(),
            },
            BTreeMap::new(),
        ));
        return findings;
    }

    if aide_installed && !aide_db_exists(context) {
        let subject = resolve_existing_path(&context.root, AIDE_CONF)
            .unwrap_or_else(|| context.root.join(AIDE_CONF));
        findings.push(host_finding(
            "host.aide_not_initialized",
            Severity::Medium,
            &subject,
            HostFindingText {
                title: t!("finding.host.aide_not_initialized.title").into_owned(),
                description: t!("finding.host.aide_not_initialized.description").into_owned(),
                why_risky: t!("finding.host.aide_not_initialized.why").into_owned(),
                how_to_fix: t!("finding.host.aide_not_initialized.fix").into_owned(),
            },
            BTreeMap::new(),
        ));
    }

    if tripwire_installed && !tripwire_db_exists(context) {
        let subject = resolve_existing_path(&context.root, TRIPWIRE_CFG)
            .unwrap_or_else(|| context.root.join(TRIPWIRE_CFG));
        findings.push(host_finding(
            "host.tripwire_not_initialized",
            Severity::Medium,
            &subject,
            HostFindingText {
                title: t!("finding.host.tripwire_not_initialized.title").into_owned(),
                description: t!("finding.host.tripwire_not_initialized.description").into_owned(),
                why_risky: t!("finding.host.tripwire_not_initialized.why").into_owned(),
                how_to_fix: t!("finding.host.tripwire_not_initialized.fix").into_owned(),
            },
            BTreeMap::new(),
        ));
    }

    findings
}

fn is_aide_installed(context: &HostContext) -> bool {
    AIDE_BINARIES
        .iter()
        .any(|p| resolve_existing_path(&context.root, p).is_some())
        || resolve_existing_path(&context.root, AIDE_CONF).is_some()
}

fn aide_db_exists(context: &HostContext) -> bool {
    AIDE_DB_PATHS
        .iter()
        .any(|p| resolve_existing_path(&context.root, p).is_some())
}

fn is_tripwire_installed(context: &HostContext) -> bool {
    TRIPWIRE_BINARIES
        .iter()
        .any(|p| resolve_existing_path(&context.root, p).is_some())
        || resolve_existing_path(&context.root, TRIPWIRE_CFG).is_some()
}

fn tripwire_db_exists(context: &HostContext) -> bool {
    let db_dir = context.root.join(TRIPWIRE_DB_DIR);
    if !db_dir.is_dir() {
        return false;
    }
    match std::fs::read_dir(&db_dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .any(|e| e.path().extension().is_some_and(|ext| ext == "twd")),
        Err(_) => false,
    }
}

fn is_samhain_installed(context: &HostContext) -> bool {
    SAMHAIN_BINARIES
        .iter()
        .any(|p| resolve_existing_path(&context.root, p).is_some())
        || resolve_existing_path(&context.root, SAMHAIN_CFG).is_some()
}

fn is_ossec_installed(context: &HostContext) -> bool {
    resolve_existing_path(&context.root, OSSEC_DIR).is_some_and(|p| p.is_dir())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::HostScanner;
    use crate::host::tests::{temp_host_root, write_file};

    #[test]
    fn host_scanner_warns_when_no_fim() {
        let root = temp_host_root("no-fim");
        write_file(&root.join("etc/hostname"), "no-fim\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.fim_missing")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_aide_not_initialized() {
        let root = temp_host_root("aide-no-db");
        write_file(&root.join("usr/bin/aide"), "");
        write_file(&root.join("etc/aide/aide.conf"), "");
        write_file(&root.join("etc/hostname"), "aide-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.aide_not_initialized")
        );
        assert!(
            !findings
                .iter()
                .any(|finding| finding.id == "host.fim_missing")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_skips_aide_when_initialized() {
        let root = temp_host_root("aide-ok");
        write_file(&root.join("usr/bin/aide"), "");
        write_file(&root.join("var/lib/aide/aide.db"), "");
        write_file(&root.join("etc/hostname"), "aide-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            !findings
                .iter()
                .any(|finding| finding.id == "host.aide_not_initialized")
        );
        assert!(
            !findings
                .iter()
                .any(|finding| finding.id == "host.fim_missing")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_tripwire_not_initialized() {
        let root = temp_host_root("tripwire-no-db");
        write_file(&root.join("usr/sbin/tripwire"), "");
        write_file(&root.join("etc/tripwire/tw.cfg"), "");
        write_file(&root.join("etc/hostname"), "tripwire-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.tripwire_not_initialized")
        );
        assert!(
            !findings
                .iter()
                .any(|finding| finding.id == "host.fim_missing")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_skips_tripwire_when_initialized() {
        let root = temp_host_root("tripwire-ok");
        write_file(&root.join("usr/sbin/tripwire"), "");
        write_file(&root.join("etc/tripwire/tw.cfg"), "");
        std::fs::create_dir_all(root.join("var/lib/tripwire"))
            .expect("tripwire db dir should be created");
        write_file(&root.join("var/lib/tripwire/host.twd"), "");
        write_file(&root.join("etc/hostname"), "tripwire-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            !findings
                .iter()
                .any(|finding| finding.id == "host.tripwire_not_initialized")
        );
        assert!(
            !findings
                .iter()
                .any(|finding| finding.id == "host.fim_missing")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_skips_fim_when_samhain_present() {
        let root = temp_host_root("samhain-ok");
        write_file(&root.join("usr/sbin/samhain"), "");
        write_file(&root.join("etc/hostname"), "samhain-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            !findings
                .iter()
                .any(|finding| finding.id == "host.fim_missing")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_skips_fim_when_ossec_present() {
        let root = temp_host_root("ossec-ok");
        std::fs::create_dir_all(root.join("var/ossec")).expect("ossec dir should be created");
        write_file(&root.join("etc/hostname"), "ossec-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            !findings
                .iter()
                .any(|finding| finding.id == "host.fim_missing")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_aide_via_config_only() {
        let root = temp_host_root("aide-conf-only");
        write_file(&root.join("etc/aide/aide.conf"), "");
        write_file(&root.join("etc/hostname"), "aide-conf-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            !findings
                .iter()
                .any(|finding| finding.id == "host.fim_missing")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.aide_not_initialized")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_tripwire_via_config_only() {
        let root = temp_host_root("tripwire-conf-only");
        write_file(&root.join("etc/tripwire/tw.cfg"), "");
        write_file(&root.join("etc/hostname"), "tripwire-conf-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            !findings
                .iter()
                .any(|finding| finding.id == "host.fim_missing")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.tripwire_not_initialized")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_samhain_via_config_only() {
        let root = temp_host_root("samhain-conf-only");
        write_file(&root.join("etc/samhain/samhainrc"), "");
        write_file(&root.join("etc/hostname"), "samhain-conf-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            !findings
                .iter()
                .any(|finding| finding.id == "host.fim_missing")
        );

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn aide_db_exists_checks_both_paths() {
        let root = temp_host_root("aide-db-paths");
        let ctx = HostContext { root: root.clone() };

        assert!(!aide_db_exists(&ctx));

        write_file(&root.join("var/lib/aide/aide.db"), "");
        assert!(aide_db_exists(&ctx));

        std::fs::remove_file(root.join("var/lib/aide/aide.db")).expect("db file should be removed");
        write_file(&root.join("var/lib/aide/aide.db.new"), "");
        assert!(aide_db_exists(&ctx));

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }
}
