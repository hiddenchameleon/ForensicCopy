use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use rayon::prelude::*;
use crate::errors::ForensicError;
use crate::hasher::HashingAlgorithm;
use crate::hasher::hash_file;

#[derive(Debug)]
pub struct FileCopyResult {
    pub source_path: PathBuf,
    pub dest_path: PathBuf,
    pub file_size: u64,
    pub src_hash: String,
    pub dest_hash: String,
    pub verified: bool,
    pub error: Option<String>,
    pub copy_time_ms: u64,
}

pub fn collect_files(dir: &Path) -> Result<Vec<PathBuf>, ForensicError> {
    let mut files = Vec::new();

    let entries = fs::read_dir(dir)
        .map_err(|e| ForensicError::DirectoryNotReadable(e.to_string()))?;

    for entry in entries {
        let entry = entry.map_err(|e| ForensicError::DirectoryNotReadable(e.to_string()))?;
        let path = entry.path();

        if path.is_dir() {
            let mut sub_files = collect_files(&path)?;
            files.append(&mut sub_files);
        } else {
            files.push(path);
        }
    }
    Ok(files)
}

pub fn forensic_copy(source: &str, destination: &str, algorithm: &HashingAlgorithm) -> Result<Vec<FileCopyResult>, ForensicError> {
    
    let source_path = Path::new(source);
    if !source_path.exists() {
        return Err(ForensicError::DirectoryNotFound(source_path.display().to_string()));
    }
    if !source_path.is_dir() {
        return Err(ForensicError::DirectoryNotFound(source_path.display().to_string()));
    }

    let destination_path = Path::new(destination);
    if !destination_path.exists() {
        fs::create_dir_all(destination_path)
            .map_err(|e| ForensicError::CreateDirectoryFailed(e.to_string()))?;
    }
    
    let all_files = collect_files(&source_path)?;
    let results: Vec<Result<FileCopyResult, ForensicError>> = all_files
        .par_iter()
        .map(|file| {
            let start = Instant::now();

            let relative = file.strip_prefix(source_path).map_err(|e| ForensicError::CopyError(e.to_string()))?;
            let dest_path = destination_path.join(relative);

            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent).map_err(|e| ForensicError::CreateDirectoryFailed(e.to_string()))?;
            }
       
            let file_size = fs::metadata(file).map_err(|e| ForensicError::FileReadError(e.to_string()))?.len();
            let src_hash = hash_file(file, algorithm)?;
            fs::copy(file, &dest_path)
                .map_err(|e| ForensicError::CopyError(e.to_string()))?;
            
            let dest_hash = hash_file(&dest_path, algorithm)?;
            let verified = src_hash == dest_hash;
            let copy_time_ms = start.elapsed().as_millis() as u64;
            Ok(FileCopyResult {
                source_path: file.clone(),
                dest_path,
                file_size,
                src_hash, 
                dest_hash,
                verified,
                error: if verified { None } else {
                    Some(String::from("Hash mismatch!"))
                },
                copy_time_ms,
            })
        })
        .collect();
         
    results.into_iter().collect()
}


        
    