mod exposure;
mod permissions;
mod sensitive;
mod updates;

pub use exposure::{is_public_port, scan_exposure_risk};
pub use permissions::{classify_sensitive_mount, scan_permission_risk};
pub use sensitive::scan_sensitive_data;
pub use updates::{scan_update_risk, split_image_reference};

use crate::compose::ComposeProject;
use crate::domain::{Finding, RemediationKind};

#[derive(Debug, Default)]
pub struct RuleEngine;

impl RuleEngine {
    pub fn scan(&self, project: &ComposeProject) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(scan_exposure_risk(project));
        findings.extend(scan_permission_risk(project));
        findings.extend(scan_sensitive_data(project));
        findings.extend(scan_update_risk(project));
        findings
    }
}

struct ServiceFindingText {
    title: String,
    description: String,
    why_risky: String,
    how_to_fix: String,
}

fn service_finding(
    id: &str,
    axis: crate::domain::Axis,
    severity: crate::domain::Severity,
    service_name: &str,
    text: ServiceFindingText,
    evidence: std::collections::BTreeMap<String, String>,
) -> Finding {
    service_finding_with_remediation(
        id,
        axis,
        severity,
        service_name,
        text,
        evidence,
        RemediationKind::None,
    )
}

fn service_finding_with_remediation(
    id: &str,
    axis: crate::domain::Axis,
    severity: crate::domain::Severity,
    service_name: &str,
    text: ServiceFindingText,
    evidence: std::collections::BTreeMap<String, String>,
    remediation: RemediationKind,
) -> Finding {
    Finding {
        id: id.to_owned(),
        axis,
        severity,
        scope: crate::domain::Scope::Service,
        source: crate::domain::Source::NativeCompose,
        subject: service_name.to_owned(),
        related_service: Some(service_name.to_owned()),
        title: text.title,
        description: text.description,
        why_risky: text.why_risky,
        how_to_fix: text.how_to_fix,
        evidence,
        remediation,
    }
}
