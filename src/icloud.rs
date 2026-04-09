use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;

/// Parsed iCloud Production CSV data — carries the CSV path and the
/// File_Name → GPG_SHA256 mapping for three-way hash comparison.
#[derive(Clone)]
pub struct ICloudMode {
    pub csv_path: PathBuf,
    pub hash_map: HashMap<String, String>,
}

/// Result of a three-way hash comparison for a single file.
#[derive(Debug, Clone)]
pub struct AppleHashComparison {
    pub apple_hash: String,
    pub src_matches_apple: bool,
    pub dest_matches_apple: bool,
    pub full_chain_verified: bool,
}

/// Searches recursively for a file ending in `-account-download-details.csv`
/// starting from the given directory. Returns the first match found.
pub fn find_production_csv(search_root: &Path) -> Option<PathBuf> {
    find_csv_recursive(search_root)
}

fn find_csv_recursive(dir: &Path) -> Option<PathBuf> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return None,
    };

    let mut subdirs = Vec::new();

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.is_dir() {
            subdirs.push(path);
        } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.to_lowercase().ends_with("-account-download-details.csv") {
                return Some(path);
            }
        }
    }

    for subdir in subdirs {
        if let Some(found) = find_csv_recursive(&subdir) {
            return Some(found);
        }
    }

    None
}

/// Parses the Apple production CSV and returns a HashMap of File_Name → GPG_SHA256.
/// Matches columns by header name, not position.
pub fn parse_production_csv(csv_path: &Path) -> Result<HashMap<String, String>, String> {
    let mut reader = csv::Reader::from_path(csv_path)
        .map_err(|e| format!("Failed to open CSV '{}': {}", csv_path.display(), e))?;

    let headers = reader.headers()
        .map_err(|e| format!("Failed to read CSV headers: {}", e))?
        .clone();

    let file_name_idx = headers.iter().position(|h| h.trim() == "File_Name")
        .ok_or_else(|| "CSV missing required column 'File_Name'".to_string())?;

    let gpg_sha256_idx = headers.iter().position(|h| h.trim() == "GPG_SHA256")
        .ok_or_else(|| "CSV missing required column 'GPG_SHA256'".to_string())?;

    let mut map = HashMap::new();

    for result in reader.records() {
        let record = result.map_err(|e| format!("Failed to read CSV row: {}", e))?;

        let file_name = record.get(file_name_idx)
            .unwrap_or("")
            .trim()
            .to_string();

        let gpg_sha256 = record.get(gpg_sha256_idx)
            .unwrap_or("")
            .trim()
            .to_string();

        if !file_name.is_empty() && !gpg_sha256.is_empty() {
            map.insert(file_name, gpg_sha256);
        }
    }

    if map.is_empty() {
        return Err("CSV contained no valid File_Name/GPG_SHA256 entries".to_string());
    }

    Ok(map)
}
