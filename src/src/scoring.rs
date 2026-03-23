use std::collections::BTreeMap;

use crate::domain::{Axis, Finding, ScoreReport, Severity};

fn severity_penalty(severity: Severity) -> u16 {
    match severity {
        Severity::Critical => 75,
        Severity::High => 35,
        Severity::Medium => 15,
        Severity::Low => 5,
    }
}

fn axis_weight(axis: Axis) -> f32 {
    match axis {
        Axis::SensitiveData => 0.35,
        Axis::ExcessivePermissions => 0.30,
        Axis::UnnecessaryExposure => 0.20,
        Axis::UpdateSupplyChainRisk => 0.15,
        Axis::HostHardening => 0.0,
    }
}

pub fn build_score_report(findings: &[Finding]) -> ScoreReport {
    let mut axis_penalties = BTreeMap::new();
    let mut severity_counts = BTreeMap::new();

    for axis in Axis::ALL {
        axis_penalties.insert(axis, 0_u16);
    }
    for severity in Severity::ALL {
        severity_counts.insert(severity, 0_usize);
    }

    for finding in findings {
        *axis_penalties.entry(finding.axis).or_insert(0) += severity_penalty(finding.severity);
        *severity_counts.entry(finding.severity).or_insert(0) += 1;
    }

    let axis_scores = Axis::ALL
        .into_iter()
        .map(|axis| {
            let penalty = axis_penalties.get(&axis).copied().unwrap_or_default();
            let score = 100_i16 - penalty as i16;
            (axis, score.max(0) as u8)
        })
        .collect::<BTreeMap<_, _>>();

    let overall = Axis::ALL
        .into_iter()
        .map(|axis| axis_scores.get(&axis).copied().unwrap_or(100) as f32 * axis_weight(axis))
        .sum::<f32>()
        .round() as u8;

    ScoreReport {
        overall,
        axis_scores,
        severity_counts,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::domain::{Finding, RemediationKind, Scope, Source};

    use super::*;

    fn finding(axis: Axis, severity: Severity, id: &str) -> Finding {
        Finding {
            id: id.to_owned(),
            axis,
            severity,
            scope: Scope::Service,
            source: Source::NativeCompose,
            subject: String::from("svc"),
            related_service: Some(String::from("svc")),
            title: String::from("title"),
            description: String::from("description"),
            why_risky: String::from("why"),
            how_to_fix: String::from("fix"),
            evidence: BTreeMap::new(),
            remediation: RemediationKind::None,
        }
    }

    #[test]
    fn counts_findings_by_axis_and_severity() {
        let findings = vec![
            finding(Axis::SensitiveData, Severity::Critical, "a"),
            finding(Axis::UnnecessaryExposure, Severity::High, "b"),
            finding(Axis::UnnecessaryExposure, Severity::Low, "c"),
        ];

        let report = build_score_report(&findings);

        assert_eq!(report.axis_scores[&Axis::SensitiveData], 25);
        assert_eq!(report.axis_scores[&Axis::ExcessivePermissions], 100);
        assert_eq!(report.axis_scores[&Axis::UnnecessaryExposure], 60);
        assert_eq!(report.axis_scores[&Axis::UpdateSupplyChainRisk], 100);
        assert_eq!(report.axis_scores[&Axis::HostHardening], 100);
        assert_eq!(report.severity_counts[&Severity::Critical], 1);
        assert_eq!(report.severity_counts[&Severity::High], 1);
        assert_eq!(report.severity_counts[&Severity::Low], 1);
    }

    #[test]
    fn single_critical_sensitive_finding_tanks_overall_score() {
        let report = build_score_report(&[finding(Axis::SensitiveData, Severity::Critical, "a")]);

        assert_eq!(report.overall, 74);
        assert!(report.overall < 80);
    }

    #[test]
    fn multiple_findings_cap_axis_scores_at_zero() {
        let report = build_score_report(&[
            finding(Axis::ExcessivePermissions, Severity::Critical, "a"),
            finding(Axis::ExcessivePermissions, Severity::Critical, "b"),
        ]);

        assert_eq!(report.axis_scores[&Axis::ExcessivePermissions], 0);
    }
}
