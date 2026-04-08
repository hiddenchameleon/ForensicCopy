use std::fs;
use std::path::PathBuf;
use std::io::Write;
use chrono::Local;
use crate::errors::ForensicError;
use crate::copier::FileCopyResult;
use crate::hasher::HashingAlgorithm;
use crate::HashMode;

pub struct ReportConfig {
    pub enabled: bool,
    pub output_path: Option<PathBuf>,
}

pub fn generate_report(
    results: &[FileCopyResult],
    dir_errors: &[String],
    sources: &[String],
    destination: &str,
    algorithm: &HashingAlgorithm,
    hash_mode: &HashMode,
    total_time_ms: u64,
    config: &ReportConfig,
) -> Result<(), ForensicError> {
    if !config.enabled {
        return Ok(());
    }

    let mut report = String::new();
    report.push_str("==========================================================\n");
    report.push_str("                Forensic Copy Report                      \n");
    report.push_str("==========================================================\n");

    let now = Local::now();
    report.push_str(&format!("Date/Time:          {}\n", now.format("%Y-%m-%d %H:%M:%S")));

    let algo_name = match algorithm {
        HashingAlgorithm::Sha256 => "SHA256",
        HashingAlgorithm::Blake3 => "BLAKE3",
        HashingAlgorithm::Md5    => "MD5",
    };
    let hash_mode_str = match hash_mode {
        HashMode::Full     => format!("{} (full verify)", algo_name),
        HashMode::NoVerify => format!("{} (source only, no verify)", algo_name),
        HashMode::NoHash   => String::from("Disabled"),
    };
    report.push_str(&format!("Hash Mode:          {}\n", hash_mode_str));

    let total_files = results.len();
    let total_size: u64 = results.iter().map(|r| r.file_size).sum();
    let verified_count = results.iter().filter(|r| r.verified).count();
    let failed_count = total_files - verified_count;
    let meta_warn_count = results.iter().filter(|r| r.metadata_error.is_some()).count();
    let avg_time_ms = if total_files > 0 { total_time_ms / total_files as u64 } else { 0 };

    report.push_str("----------------------------------------------------------\n");
    if sources.len() == 1 {
        report.push_str(&format!("Source:             {}\n", sources[0]));
    } else {
        report.push_str(&format!("Sources ({}):\n", sources.len()));
        for src in sources {
            report.push_str(&format!("  - {}\n", src));
        }
    }
    report.push_str(&format!("Destination:        {}\n", destination));
    report.push_str(&format!("Total Files:        {}\n", total_files));
    report.push_str(&format!("Total Size:         {}\n", format_size(total_size)));
    report.push_str(&format!("Total Time:         {}\n", format_duration(total_time_ms)));
    report.push_str(&format!("Avg Time/File:      {}\n", format_duration(avg_time_ms)));
    report.push_str(&format!("Verified:           {}\n", verified_count));
    report.push_str(&format!("Failed:             {}\n", failed_count));
    report.push_str(&format!("Metadata Warnings:  {}\n", meta_warn_count));
    report.push_str(&format!("Dir Meta Warnings:  {}\n", dir_errors.len()));
    report.push_str("----------------------------------------------------------\n");
    report.push_str("FILE DETAILS:\n");
    report.push_str("----------------------------------------------------------\n");

    for result in results {
        let status = if result.error.is_some() { "[FAIL]" } else { "[PASS]" };
        report.push_str(&format!("{}  {}\n", status, result.source_path.display()));
        report.push_str(&format!("   Size:             {}\n", format_size(result.file_size)));
        report.push_str(&format!("   Source Hash:      {}\n", result.src_hash));
        report.push_str(&format!("   Destination Hash: {}\n", result.dest_hash));
        report.push_str(&format!("   Destination Path: {}\n", result.dest_path.display()));
        report.push_str(&format!("   Time:             {}\n", format_duration(result.copy_time_ms)));
        if let Some(err) = &result.error {
            report.push_str(&format!("   Error:            {}\n", err));
        }
        if let Some(meta_err) = &result.metadata_error {
            report.push_str(&format!("   Metadata Warning: {}\n", meta_err));
        }
        report.push_str("\n");
        if !dir_errors.is_empty() {
            report.push_str("----------------------------------------------------------\n");
            report.push_str("DIRECTORY METADATA WARNINGS:\n");
            report.push_str("----------------------------------------------------------\n");
            for err in dir_errors {
                report.push_str(&format!("  ⚠  {}\n", err));
            }
            report.push_str("\n");
        }
    }
    report.push_str("==========================================================\n");

    match &config.output_path {
        None => println!("{}", report),
        Some(path) => {
            let mut file = fs::File::create(path)
                .map_err(|e| ForensicError::ReportWriteFailed(e.to_string()))?;
            file.write_all(report.as_bytes())
                .map_err(|e| ForensicError::ReportWriteFailed(e.to_string()))?;
            println!("Report written to: {}", path.display());
        }
    }
    Ok(())
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.2} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1_024 {
        format!("{:.2} KB", bytes as f64 / 1_024.0)
    } else {
        format!("{} bytes", bytes)
    }
}

pub fn format_duration(ms: u64) -> String {
    if ms >= 60_000 {
        format!("{:.2}m", ms as f64 / 60_000.0)
    } else if ms >= 1_000 {
        format!("{:.2}s", ms as f64 / 1_000.0)
    } else {
        format!("{}ms", ms)
    }
}