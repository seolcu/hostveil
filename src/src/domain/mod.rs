use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Axis {
    SensitiveData,
    ExcessivePermissions,
    UnnecessaryExposure,
    UpdateSupplyChainRisk,
    HostHardening,
}

impl Axis {
    pub const ALL: [Self; 5] = [
        Self::SensitiveData,
        Self::ExcessivePermissions,
        Self::UnnecessaryExposure,
        Self::UpdateSupplyChainRisk,
        Self::HostHardening,
    ];

    pub const fn as_key(self) -> &'static str {
        match self {
            Self::SensitiveData => "sensitive_data",
            Self::ExcessivePermissions => "permissions",
            Self::UnnecessaryExposure => "exposure",
            Self::UpdateSupplyChainRisk => "supply_chain",
            Self::HostHardening => "host_hardening",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub const ALL: [Self; 4] = [Self::Critical, Self::High, Self::Medium, Self::Low];

    pub const fn as_key(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Service,
    Image,
    Host,
    Project,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    NativeCompose,
    NativeHost,
    Trivy,
    Lynis,
    Dockle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationKind {
    None,
    Safe,
    Guided,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub id: String,
    pub axis: Axis,
    pub severity: Severity,
    pub scope: Scope,
    pub source: Source,
    pub subject: String,
    pub related_service: Option<String>,
    pub title: String,
    pub description: String,
    pub why_risky: String,
    pub how_to_fix: String,
    pub evidence: BTreeMap<String, String>,
    pub remediation: RemediationKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScoreReport {
    pub overall: u8,
    pub axis_scores: BTreeMap<Axis, u8>,
    pub severity_counts: BTreeMap<Severity, usize>,
}

impl Default for ScoreReport {
    fn default() -> Self {
        let axis_scores = Axis::ALL.into_iter().map(|axis| (axis, 100)).collect();
        let severity_counts = Severity::ALL
            .into_iter()
            .map(|severity| (severity, 0))
            .collect();

        Self {
            overall: 100,
            axis_scores,
            severity_counts,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum AdapterStatus {
    Available,
    Missing,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct ScanMetadata {
    pub compose_root: Option<PathBuf>,
    pub compose_file: Option<PathBuf>,
    pub host_root: Option<PathBuf>,
    pub loaded_files: Vec<PathBuf>,
    pub service_count: usize,
    pub adapters: BTreeMap<String, AdapterStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub score_report: ScoreReport,
    pub metadata: ScanMetadata,
}
