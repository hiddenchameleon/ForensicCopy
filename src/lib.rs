pub mod errors;
pub mod hasher;
pub mod copier;
pub mod report;
pub mod icloud;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreadSpeed {
    Full,
    Half,
    Slow,
}

impl Default for ThreadSpeed {
    fn default() -> Self {
        ThreadSpeed::Full
    }
}

