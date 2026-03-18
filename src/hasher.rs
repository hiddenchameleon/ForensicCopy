use std::fs;
use std::path::Path;
use std::io::Read;
use sha2::{Sha256, Digest};

use crate::errors::ForensicError;

#[derive(Debug, Clone)]
pub enum HashingAlgorithm {
    Sha256,
    Blake3,
}

pub fn hash_file(path: &Path, algorithm: &HashingAlgorithm) -> Result<String, ForensicError> {
    let mut file = fs::File::open(path)
        .map_err(|e| ForensicError::FileReadError(e.to_string()))?;

    let mut buffer = [0u8; 8192];
    match algorithm {
        HashingAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            loop {
                let bytes_read = file.read(&mut buffer)
                    .map_err(|e| ForensicError::FileReadError(e.to_string()))?;
                if bytes_read == 0 { break; }
                hasher.update(&buffer[..bytes_read]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
        HashingAlgorithm::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            loop {
                let bytes_read = file.read(&mut buffer)
                    .map_err(|e| ForensicError::FileReadError(e.to_string()))?;
                if bytes_read == 0 { break; }
                hasher.update(&buffer[..bytes_read]);
            }
            Ok(hasher.finalize().to_hex().to_string())       
        }
    }
}