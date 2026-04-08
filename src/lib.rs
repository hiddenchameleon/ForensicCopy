pub mod errors;
pub mod hasher;
pub mod copier;
pub mod report;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HashMode {
    Full,
    NoVerify,
    NoHash,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConflictMode {
    Skip,
    Overwrite,
    Abort,
}

impl Default for ConflictMode {
    fn default() -> Self {
        ConflictMode::Skip
    }
}

