use crate::domain::Finding;

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
