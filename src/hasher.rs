use std::fs::File;
use std::io::{Read, Write, BufReader, BufWriter};
use std::path::Path;
use sha2::{Sha256, Digest};
use md5::Md5;

use crate::errors::ForensicError;
use indicatif::ProgressBar;

/// 64 KB buffer — balances syscall reduction with CPU cache friendliness.
const BUF_SIZE: usize = 64 * 1024;


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
    let _file_size = file.metadata()
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
            // Streaming hash using chunks - avoids loading large files into memory
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

/// Copy a file while simultaneously computing the hash of the source data.
/// Returns the hex-encoded source hash. This avoids a separate read pass
/// over the source file.
pub fn copy_and_hash(
    src: &Path,
    dest: &Path,
    algorithm: &HashingAlgorithm,
    progress: Option<&ProgressBar>,
    file_size: u64,
    byte_progress: Option<&dyn Fn(u64, u64)>,
    check_control: &dyn Fn() -> bool,
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
            let mut bytes_done: u64 = 0;
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
                bytes_done += bytes_read as u64;
                if let Some(cb) = byte_progress {
                    cb(bytes_done, file_size);
                }
                if check_control() { return Err(ForensicError::Aborted); }
            }
            writer.flush().map_err(|e| ForensicError::CopyError(e.to_string()))?;
            Ok(hex::encode(hasher.finalize()))
        }
        HashingAlgorithm::Md5 => {
            let mut hasher = Md5::new();
            let mut bytes_done: u64 = 0;
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
                bytes_done += bytes_read as u64;
                if let Some(cb) = byte_progress {
                    cb(bytes_done, file_size);
                }
                if check_control() { return Err(ForensicError::Aborted); }
            }
            writer.flush().map_err(|e| ForensicError::CopyError(e.to_string()))?;
            Ok(hex::encode(hasher.finalize()))
        }
        HashingAlgorithm::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            let mut bytes_done: u64 = 0;
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
                bytes_done += bytes_read as u64;
                if let Some(cb) = byte_progress {
                    cb(bytes_done, file_size);
                }
                if check_control() { return Err(ForensicError::Aborted); }
            }
            writer.flush().map_err(|e| ForensicError::CopyError(e.to_string()))?;
            Ok(hasher.finalize().to_hex().to_string())
        }
    }
}
