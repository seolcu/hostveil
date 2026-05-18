#![cfg(feature = "web")]

mod server;
mod state;

pub(crate) mod api;
pub(crate) mod pages;

pub use server::run_server;
pub use state::AppState;

use crate::domain::ScanResult;
use crate::app::WebConfig;

pub fn serve(scan_result: ScanResult, config: &WebConfig) -> Result<(), crate::app::AppError> {
    let state = AppState::new(scan_result);

    let host = config.host.clone();
    let port = config.port;

    let rt = tokio::runtime::Runtime::new().map_err(|e| {
        crate::app::AppError::Io(std::io::Error::other(e.to_string()))
    })?;

    rt.block_on(async {
        run_server(state, &host, port).await.map_err(|e| {
            crate::app::AppError::Io(std::io::Error::other(e))
        })
    })
}
