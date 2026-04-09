use thiserror::Error;

#[derive(Debug, Error)]
pub enum ForensicError {
    #[error("Directory not found: {0}")]
    DirectoryNotFound(String),
    #[error("Directory not readable: {0}")]
    DirectoryNotReadable(String),
    #[error("Failed to create directory: {0}")]
    CreateDirectoryFailed(String),
    #[error("Failed to copy file: {0}")]
    CopyError(String),
    // #[error("Hashing error: {0}")]
    // HashingError(String),
    // #[error("Hash mismatch for file: {0}")]
    // HashMismatch(String),
    #[error("Failed to read file: {0}")]
    FileReadError(String),
    // #[error("Failed to write file: {0}")]
    // FileWriteError(String),
    // #[error("Invalid source path: {0}")]
    // InvalidSource(String),
    #[error("Failed to write report: {0}")]
    ReportWriteFailed(String),
    #[error("Operation aborted")]
    Aborted,
    // #[error("Invalid report path: {0}")]
    // ReportPathInvalid(String),
    // #[error("Unsupported hash algorithm: {0}")]
    // UnsupportedHashAlgorithm(String),
    // #[error("Thread error: {0}")]
    // ThreadError(String),
    // #[error("Failed to perserve metadata: {0}")]
    // MetadataError(String),
}