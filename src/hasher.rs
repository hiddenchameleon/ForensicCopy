use std::fs::File;
use std::io::{Read, Write, BufReader, BufWriter};
use std::path::Path;
use sha2::{Sha256, Digest};
use md5::Md5;

use crate::errors::ForensicError;
use indicatif::ProgressBar;

/// 64 KB buffer — balances syscall reduction with CPU cache friendliness.
const BUF_SIZE: usize = 64 * 1024;

/// Threshold above which Blake3 uses multi-threaded hashing via rayon.
const BLAKE3_MT_THRESHOLD: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone)]
pub enum HashingAlgorithm {
    Sha256,
    Blake3,
    Md5,
}

#[allow(dead_code)]
pub fn hash_file(path: &Path, algorithm: &HashingAlgorithm) -> Result<String, ForensicError> {
    hash_file_with_progress(path, algorithm, None)
}

pub fn hash_file_with_progress(
    path: &Path,
    algorithm: &HashingAlgorithm,
    progress: Option<&ProgressBar>,
) -> Result<String, ForensicError> {
    let file = File::open(path)
        .map_err(|e| ForensicError::FileReadError(e.to_string()))?;
    let file_size = file.metadata()
        .map_err(|e| ForensicError::FileReadError(e.to_string()))?
        .len();
    let mut reader = BufReader::with_capacity(BUF_SIZE, file);

    let mut buffer = [0u8; BUF_SIZE];
    match algorithm {
        HashingAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            loop {
                let bytes_read = reader.read(&mut buffer)
                    .map_err(|e| ForensicError::FileReadError(e.to_string()))?;
                if bytes_read == 0 { break; }
                hasher.update(&buffer[..bytes_read]);
                if let Some(pb) = progress {
                    pb.inc(bytes_read as u64);
                }
            }
            Ok(hex::encode(hasher.finalize()))
        }
        HashingAlgorithm::Md5 => {
            let mut hasher = Md5::new();
            loop {
                let bytes_read = reader.read(&mut buffer)
                    .map_err(|e| ForensicError::FileReadError(e.to_string()))?;
                if bytes_read == 0 { break; }
                hasher.update(&buffer[..bytes_read]);
                if let Some(pb) = progress {
                    pb.inc(bytes_read as u64);
                }
            }
            Ok(hex::encode(hasher.finalize()))
        }
        HashingAlgorithm::Blake3 => {
            if file_size >= BLAKE3_MT_THRESHOLD {
                // For large files, read entire content and use rayon-parallel hashing
                let mut data = Vec::with_capacity(file_size as usize);
                reader.read_to_end(&mut data)
                    .map_err(|e| ForensicError::FileReadError(e.to_string()))?;
                if let Some(pb) = progress {
                    pb.inc(file_size);
                }
                let mut hasher = blake3::Hasher::new();
                hasher.update_rayon(&data);
                Ok(hasher.finalize().to_hex().to_string())
            } else {
                let mut hasher = blake3::Hasher::new();
                loop {
                    let bytes_read = reader.read(&mut buffer)
                        .map_err(|e| ForensicError::FileReadError(e.to_string()))?;
                    if bytes_read == 0 { break; }
                    hasher.update(&buffer[..bytes_read]);
                    if let Some(pb) = progress {
                        pb.inc(bytes_read as u64);
                    }
                }
                Ok(hasher.finalize().to_hex().to_string())
            }
        }
    }
}

/// Copy a file while simultaneously computing the hash of the source data.
/// Returns the hex-encoded source hash. This avoids a separate read pass
/// over the source file.
pub fn copy_and_hash(
    src: &Path,
    dest: &Path,
    algorithm: &HashingAlgorithm,
    progress: Option<&ProgressBar>,
) -> Result<String, ForensicError> {
    let src_file = File::open(src)
        .map_err(|e| ForensicError::FileReadError(e.to_string()))?;
    let dest_file = File::create(dest)
        .map_err(|e| ForensicError::CopyError(e.to_string()))?;

    let mut reader = BufReader::with_capacity(BUF_SIZE, src_file);
    let mut writer = BufWriter::with_capacity(BUF_SIZE, dest_file);

    let mut buffer = [0u8; BUF_SIZE];

    match algorithm {
        HashingAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            loop {
                let bytes_read = reader.read(&mut buffer)
                    .map_err(|e| ForensicError::FileReadError(e.to_string()))?;
                if bytes_read == 0 { break; }
                hasher.update(&buffer[..bytes_read]);
                writer.write_all(&buffer[..bytes_read])
                    .map_err(|e| ForensicError::CopyError(e.to_string()))?;
                if let Some(pb) = progress {
                    pb.inc(bytes_read as u64);
                }
            }
            writer.flush().map_err(|e| ForensicError::CopyError(e.to_string()))?;
            Ok(hex::encode(hasher.finalize()))
        }
        HashingAlgorithm::Md5 => {
            let mut hasher = Md5::new();
            loop {
                let bytes_read = reader.read(&mut buffer)
                    .map_err(|e| ForensicError::FileReadError(e.to_string()))?;
                if bytes_read == 0 { break; }
                hasher.update(&buffer[..bytes_read]);
                writer.write_all(&buffer[..bytes_read])
                    .map_err(|e| ForensicError::CopyError(e.to_string()))?;
                if let Some(pb) = progress {
                    pb.inc(bytes_read as u64);
                }
            }
            writer.flush().map_err(|e| ForensicError::CopyError(e.to_string()))?;
            Ok(hex::encode(hasher.finalize()))
        }
        HashingAlgorithm::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            loop {
                let bytes_read = reader.read(&mut buffer)
                    .map_err(|e| ForensicError::FileReadError(e.to_string()))?;
                if bytes_read == 0 { break; }
                hasher.update(&buffer[..bytes_read]);
                writer.write_all(&buffer[..bytes_read])
                    .map_err(|e| ForensicError::CopyError(e.to_string()))?;
                if let Some(pb) = progress {
                    pb.inc(bytes_read as u64);
                }
            }
            writer.flush().map_err(|e| ForensicError::CopyError(e.to_string()))?;
            Ok(hasher.finalize().to_hex().to_string())
        }
    }
}
