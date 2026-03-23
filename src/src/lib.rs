#[macro_use]
extern crate rust_i18n;

i18n!("locales", fallback = "en");

pub mod adapters;
pub mod app;
pub mod compose;
pub mod domain;
pub mod export;
pub mod fix;
pub mod host;
pub mod i18n;
pub mod rules;
pub mod scoring;
pub mod tui;
