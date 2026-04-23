use std::path::Path;
use std::process::Command;

use crate::domain::{AdapterStatus, Finding};

pub fn scan(_host_root: Option<&Path>) -> (AdapterStatus, Vec<Finding>, Vec<String>) {
    let mut command = Command::new("docker-bench-security");
    command.arg("-c").arg("container_images"); // Just an example

    match command.output() {
        Ok(_) => (AdapterStatus::Available, vec![], vec![]),
        Err(_) => (AdapterStatus::Missing, vec![], vec![]),
    }
}
