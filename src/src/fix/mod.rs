use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixMode {
    QuickFix,
    Fix,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FixPlan {
    pub compose_file: Option<PathBuf>,
    pub diff_preview: String,
    pub backup_path: Option<PathBuf>,
}
