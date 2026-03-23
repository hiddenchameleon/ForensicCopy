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

