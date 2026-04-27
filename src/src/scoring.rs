use std::collections::BTreeMap;

use crate::domain::{Axis, Finding, ScoreReport, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Coverage {
    pub compose: bool,
    pub host_hardening: bool,
}

fn severity_penalty(severity: Severity) -> u16 {
    match severity {
        Severity::Critical => 75,
        Severity::High => 35,
        Severity::Medium => 15,
        Severity::Low => 5,
    }
}

fn axis_weight(axis: Axis, coverage: Coverage) -> f32 {
    match (coverage.compose, coverage.host_hardening, axis) {
        (true, false, Axis::SensitiveData) => 0.35,
        (true, false, Axis::ExcessivePermissions) => 0.30,
        (true, false, Axis::UnnecessaryExposure) => 0.20,
        (true, false, Axis::UpdateSupplyChainRisk) => 0.15,
        (true, false, Axis::HostHardening) => 0.0,
        (true, true, Axis::SensitiveData) => 0.30,
        (true, true, Axis::ExcessivePermissions) => 0.25,
        (true, true, Axis::UnnecessaryExposure) => 0.15,
        (true, true, Axis::UpdateSupplyChainRisk) => 0.15,
        (true, true, Axis::HostHardening) => 0.15,
        (false, true, Axis::HostHardening) => 1.0,
        (false, true, _) => 0.0,
        (false, false, _) => 0.0,
    }
}

pub fn build_score_report(findings: &[Finding]) -> ScoreReport {
    build_score_report_with_coverage(
        findings,
        Coverage {
            compose: true,
            host_hardening: false,
        },
    )
}

pub fn build_score_report_with_coverage(findings: &[Finding], coverage: Coverage) -> ScoreReport {
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

    let weighted = Axis::ALL
        .into_iter()
        .map(|axis| {
            axis_scores.get(&axis).copied().unwrap_or(100) as f32 * axis_weight(axis, coverage)
        })
        .sum::<f32>();
    let overall = if coverage.compose || coverage.host_hardening {
        weighted.round() as u8
    } else {
        100
    };

    ScoreReport {
        overall,
        axis_scores,
        severity_counts,
        axis_weights: Axis::ALL
            .into_iter()
            .map(|axis| (axis, axis_weight(axis, coverage)))
            .collect(),
        severity_deductions: Severity::ALL
            .into_iter()
            .map(|severity| (severity, severity_penalty(severity)))
            .collect(),
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

    #[test]
    fn host_hardening_affects_overall_only_when_covered() {
        let findings = [finding(Axis::HostHardening, Severity::Critical, "host")];

        let without_host = build_score_report(&findings);
        let with_host = build_score_report_with_coverage(
            &findings,
            Coverage {
                compose: false,
                host_hardening: true,
            },
        );

        assert_eq!(without_host.overall, 100);
        assert_eq!(without_host.axis_scores[&Axis::HostHardening], 25);
        assert_eq!(with_host.overall, 25);
    }

    fn expected_python_overall(axis_scores: &BTreeMap<Axis, u8>) -> u8 {
        // Mirrors proto/hostveil/scoring.py for Compose-only scans.
        let weighted = axis_scores[&Axis::SensitiveData] as f32 * 0.35
            + axis_scores[&Axis::ExcessivePermissions] as f32 * 0.30
            + axis_scores[&Axis::UnnecessaryExposure] as f32 * 0.20
            + axis_scores[&Axis::UpdateSupplyChainRisk] as f32 * 0.15;
        weighted.round() as u8
    }

    #[test]
    fn matches_python_prototype_for_compose_only_scans() {
        let findings = vec![
            finding(Axis::SensitiveData, Severity::High, "a"),
            finding(Axis::SensitiveData, Severity::Low, "b"),
            finding(Axis::ExcessivePermissions, Severity::Medium, "c"),
            finding(Axis::UnnecessaryExposure, Severity::Critical, "d"),
            finding(Axis::UpdateSupplyChainRisk, Severity::Low, "e"),
        ];

        let report = build_score_report(&findings);

        assert_eq!(report.overall, expected_python_overall(&report.axis_scores));
    }

    #[test]
    fn severe_permissions_drops_score_more_than_low_risk_supply_chain() {
        let low_risk = build_score_report(&[finding(
            Axis::UpdateSupplyChainRisk,
            Severity::Low,
            "supply",
        )]);
        let high_risk = build_score_report(&[finding(
            Axis::ExcessivePermissions,
            Severity::Critical,
            "priv",
        )]);

        assert!(high_risk.overall < low_risk.overall);
    }

    #[test]
    fn weights_sum_to_one_for_known_coverage_modes() {
        let compose_only = Axis::ALL
            .into_iter()
            .map(|axis| {
                axis_weight(
                    axis,
                    Coverage {
                        compose: true,
                        host_hardening: false,
                    },
                )
            })
            .sum::<f32>();
        let compose_and_host = Axis::ALL
            .into_iter()
            .map(|axis| {
                axis_weight(
                    axis,
                    Coverage {
                        compose: true,
                        host_hardening: true,
                    },
                )
            })
            .sum::<f32>();
        let host_only = Axis::ALL
            .into_iter()
            .map(|axis| {
                axis_weight(
                    axis,
                    Coverage {
                        compose: false,
                        host_hardening: true,
                    },
                )
            })
            .sum::<f32>();

        assert!((compose_only - 1.0).abs() < 0.0001);
        assert!((compose_and_host - 1.0).abs() < 0.0001);
        assert!((host_only - 1.0).abs() < 0.0001);
    }
}
