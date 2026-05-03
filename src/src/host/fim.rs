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
