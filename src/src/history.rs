use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::domain::{Axis, ScanResult, Severity};
use crate::settings::resolve_config_dir;

const HISTORY_FILE_NAME: &str = "history.json";
const MAX_HISTORY_ENTRIES: usize = 50;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanHistoryEntry {
    pub timestamp: String,
    pub overall: u8,
    pub finding_count: usize,
    #[serde(
        serialize_with = "serialize_axis_scores",
        deserialize_with = "deserialize_axis_scores"
    )]
    pub axis_scores: BTreeMap<Axis, u8>,
    #[serde(
        serialize_with = "serialize_severity_counts",
        deserialize_with = "deserialize_severity_counts"
    )]
    pub severity_counts: BTreeMap<Severity, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ScanHistory {
    pub entries: Vec<ScanHistoryEntry>,
}

impl ScanHistory {
    pub fn record(&mut self, scan_result: &ScanResult) {
        let entry = ScanHistoryEntry {
            timestamp: chrono::Local::now().to_rfc3339(),
            overall: scan_result.score_report.overall,
            finding_count: scan_result.findings.len(),
            axis_scores: scan_result.score_report.axis_scores.clone(),
            severity_counts: scan_result.score_report.severity_counts.clone(),
        };
        self.entries.push(entry);
        if self.entries.len() > MAX_HISTORY_ENTRIES {
            let excess = self.entries.len() - MAX_HISTORY_ENTRIES;
            self.entries.drain(..excess);
        }
    }

    pub fn previous_overall(&self) -> Option<u8> {
        self.entries
            .len()
            .checked_sub(2)
            .map(|idx| self.entries[idx].overall)
    }

    pub fn previous_finding_count(&self) -> Option<usize> {
        self.entries
            .len()
            .checked_sub(2)
            .map(|idx| self.entries[idx].finding_count)
    }

    pub fn trend(&self, count: usize) -> Vec<&ScanHistoryEntry> {
        self.entries
            .iter()
            .rev()
            .take(count)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }
}

pub fn load() -> ScanHistory {
    history_file_path()
        .ok()
        .and_then(|path| load_from_path(&path).ok())
        .unwrap_or_default()
}

pub fn save(history: &ScanHistory) -> io::Result<()> {
    let path = history_file_path()?;
    save_to_path(&path, history)
}

fn load_from_path(path: &Path) -> io::Result<ScanHistory> {
    let text = fs::read_to_string(path)?;
    serde_json::from_str(&text).map_err(|error| io::Error::other(error.to_string()))
}

fn save_to_path(path: &Path, history: &ScanHistory) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let text = serde_json::to_string_pretty(history)
        .map_err(|error| io::Error::other(error.to_string()))?;
    fs::write(path, text + "\n")
}

fn history_file_path() -> io::Result<PathBuf> {
    resolve_config_dir(
        std::env::var("HOSTVEIL_CONFIG_DIR").ok().as_deref(),
        std::env::var("XDG_CONFIG_HOME").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
    )
    .map(|dir| dir.join(HISTORY_FILE_NAME))
    .ok_or_else(|| io::Error::other("failed to resolve a hostveil config directory"))
}

fn serialize_axis_scores<S>(scores: &BTreeMap<Axis, u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let map: BTreeMap<String, u8> = scores
        .iter()
        .map(|(axis, score)| (axis.as_key().to_owned(), *score))
        .collect();
    map.serialize(serializer)
}

fn deserialize_axis_scores<'de, D>(deserializer: D) -> Result<BTreeMap<Axis, u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let map: BTreeMap<String, u8> = BTreeMap::deserialize(deserializer)?;
    let mut result = BTreeMap::new();
    for (key, value) in map {
        if let Some(axis) = Axis::from_key(&key) {
            result.insert(axis, value);
        }
    }
    Ok(result)
}

fn serialize_severity_counts<S>(
    counts: &BTreeMap<Severity, usize>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let map: BTreeMap<String, usize> = counts
        .iter()
        .map(|(severity, count)| (severity.as_key().to_owned(), *count))
        .collect();
    map.serialize(serializer)
}

fn deserialize_severity_counts<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<Severity, usize>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let map: BTreeMap<String, usize> = BTreeMap::deserialize(deserializer)?;
    let mut result = BTreeMap::new();
    for (key, value) in map {
        if let Some(severity) = Severity::from_key(&key) {
            result.insert(severity, value);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Axis, Finding, RemediationKind, ScanResult, Scope, Severity, Source};
    use std::collections::BTreeMap;

    fn dummy_scan_result(overall: u8, finding_count: usize) -> ScanResult {
        let mut result = ScanResult::default();
        result.score_report.overall = overall;
        result.score_report.axis_scores =
            BTreeMap::from([(Axis::SensitiveData, 80), (Axis::ExcessivePermissions, 90)]);
        result.score_report.severity_counts =
            BTreeMap::from([(Severity::Critical, 0), (Severity::High, 1)]);
        for i in 0..finding_count {
            result.findings.push(Finding {
                id: format!("finding-{i}"),
                axis: Axis::SensitiveData,
                severity: Severity::High,
                scope: Scope::Service,
                source: Source::NativeCompose,
                subject: String::from("svc"),
                related_service: None,
                title: String::from("title"),
                description: String::from("desc"),
                why_risky: String::from("why"),
                how_to_fix: String::from("fix"),
                evidence: BTreeMap::new(),
                remediation: RemediationKind::Manual,
            });
        }
        result
    }

    #[test]
    fn history_records_scan_and_trims_old_entries() {
        let mut history = ScanHistory::default();
        for i in 0..MAX_HISTORY_ENTRIES + 5 {
            history.record(&dummy_scan_result(i as u8 % 100, i));
        }
        assert_eq!(history.entries.len(), MAX_HISTORY_ENTRIES);
        assert_eq!(
            history.entries.last().unwrap().overall,
            (MAX_HISTORY_ENTRIES + 4) as u8 % 100
        );
    }

    #[test]
    fn previous_overall_returns_second_last() {
        let mut history = ScanHistory::default();
        history.record(&dummy_scan_result(80, 1));
        history.record(&dummy_scan_result(75, 2));
        history.record(&dummy_scan_result(85, 1));

        assert_eq!(history.previous_overall(), Some(75));
        assert_eq!(history.previous_finding_count(), Some(2));
    }

    #[test]
    fn previous_overall_returns_none_for_single_entry() {
        let mut history = ScanHistory::default();
        history.record(&dummy_scan_result(80, 1));
        assert_eq!(history.previous_overall(), None);
    }

    #[test]
    fn trend_returns_last_n_entries() {
        let mut history = ScanHistory::default();
        for i in 0..10 {
            history.record(&dummy_scan_result(i as u8, i));
        }
        let trend = history.trend(3);
        assert_eq!(trend.len(), 3);
        assert_eq!(trend[0].overall, 7);
        assert_eq!(trend[1].overall, 8);
        assert_eq!(trend[2].overall, 9);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let mut history = ScanHistory::default();
        history.record(&dummy_scan_result(78, 5));
        history.record(&dummy_scan_result(82, 3));

        let dir = std::env::temp_dir().join("hostveil-history-test");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("history.json");

        save_to_path(&path, &history).expect("save should succeed");
        let loaded = load_from_path(&path).expect("load should succeed");
        assert_eq!(loaded, history);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_returns_default_for_corrupted_json() {
        let dir = std::env::temp_dir().join("hostveil-history-corrupted");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("history.json");
        fs::write(&path, "this is not valid json").expect("write corrupted file");

        let result = load_from_path(&path);
        assert!(result.is_err(), "corrupted JSON should produce an error");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_handles_partial_history_json() {
        let dir = std::env::temp_dir().join("hostveil-history-partial");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("history.json");
        fs::write(&path, "{\"entries\": [{\"timestamp\": \"2024-01-01\"}]}")
            .expect("write partial history");

        let result = load_from_path(&path);
        assert!(
            result.is_err(),
            "partial history JSON should produce an error"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_trims_to_max_entries() {
        let mut history = ScanHistory::default();
        let total = MAX_HISTORY_ENTRIES + 5;
        for _ in 0..total {
            history.record(&dummy_scan_result(50, 1));
        }
        assert_eq!(history.entries.len(), MAX_HISTORY_ENTRIES);
        assert_eq!(history.previous_overall(), Some(50));
    }

    #[test]
    fn empty_history_trend_returns_zero() {
        let history = ScanHistory::default();
        assert_eq!(
            history.trend(0).len(),
            0,
            "trend(0) from empty history should be empty"
        );
        assert_eq!(
            history.trend(5).len(),
            0,
            "trend(5) on empty history should be empty"
        );
    }

    #[test]
    fn load_swallows_corrupted_json_and_returns_default() {
        let dir = std::env::temp_dir().join("hostveil-load-corrupt");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("history.json");
        std::fs::write(&path, "corrupted").expect("write corrupted");
        let loaded = load_from_path(&path);
        assert!(
            loaded.is_err(),
            "load_from_path should error on corrupted JSON"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
