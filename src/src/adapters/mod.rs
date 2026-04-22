use crate::domain::Finding;

pub mod command;
pub mod dockle;
pub mod lynis;
pub mod trivy;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterAvailability {
    Available,
    Missing,
}

pub trait ExternalScannerAdapter {
    fn name(&self) -> &'static str;
    fn availability(&self) -> AdapterAvailability;
    fn scan(&self) -> Vec<Finding>;
}
