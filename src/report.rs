use std::fs;
use std::path::PathBuf;
use std::io::Write;
use chrono::Local;
use crate::errors::ForensicError;
use crate::copier::FileCopyResult;
use crate::hasher::HashingAlgorithm;
use crate::HashMode;
use crate::icloud::ICloudMode;

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
    icloud_mode: Option<&ICloudMode>,
    missing_from_disk: &[(String, String)],
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
    let skipped_count = results.iter().filter(|r| r.skipped).count();
    let verified_count = results.iter().filter(|r| r.verified).count();
    let failed_count = total_files - verified_count - skipped_count;
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
    report.push_str(&format!("Skipped:            {}\n", skipped_count));
    report.push_str(&format!("Metadata Warnings:  {}\n", meta_warn_count));
    report.push_str(&format!("Dir Meta Warnings:  {}\n", dir_errors.len()));

    // iCloud Production summary
    if let Some(icloud) = icloud_mode {
        let chain_verified = results.iter()
            .filter(|r| r.full_chain_verified == Some(true))
            .count();
        let with_apple_hash = results.iter()
            .filter(|r| r.apple_hash.is_some())
            .count();
        let transit_failures = results.iter()
            .filter(|r| r.src_matches_apple == Some(false))
            .count();
        let copy_failures = results.iter()
            .filter(|r| r.dest_matches_apple.is_some() && r.src_matches_apple.is_some()
                && r.src_matches_apple == Some(true) && r.dest_matches_apple == Some(false))
            .count();
        let missing_from_csv = results.iter()
            .filter(|r| r.apple_hash_missing)
            .count();

        report.push_str("----------------------------------------------------------\n");
        report.push_str("iCloud Production:  Yes\n");
        report.push_str(&format!("CSV File:           {}\n", icloud.csv_path.display()));
        report.push_str(&format!("Chain Verified:     {} / {} files (full Apple hash match)\n", chain_verified, with_apple_hash));
        report.push_str(&format!("Transit Failures:   {} (Source Hash != Apple CSV Hash)\n", transit_failures));
        report.push_str(&format!("Copy Failures:      {} (Destination Hash != Source Hash)\n", copy_failures));
        report.push_str(&format!("Missing from CSV:   {} (files copied but not in Apple CSV)\n", missing_from_csv));
        report.push_str(&format!("Missing from Disk:  {} (files in Apple CSV but not found)\n", missing_from_disk.len()));
    }

    report.push_str("----------------------------------------------------------\n");
    report.push_str("FILE DETAILS:\n");
    report.push_str("----------------------------------------------------------\n");

    for result in results {
        let status = if result.skipped {
            "[SKIP]"
        } else if result.error.is_some() {
            "[FAIL]"
        } else {
            "[PASS]"
        };
        report.push_str(&format!("{}  {}\n", status, result.source_path.display()));
        report.push_str(&format!("   Size:             {}\n", format_size(result.file_size)));
        report.push_str(&format!("   Source Hash:      {}\n", result.src_hash));
        report.push_str(&format!("   Destination Hash: {}\n", result.dest_hash));
        report.push_str(&format!("   Destination Path: {}\n", result.dest_path.display()));
        report.push_str(&format!("   Time:             {}\n", format_duration(result.copy_time_ms)));
        if let Some(reason) = &result.skip_reason {
            report.push_str(&format!("   Skip Reason:      {}\n", reason));
        }
        if let Some(err) = &result.error {
            report.push_str(&format!("   Error:            {}\n", err));
        }
        if let Some(meta_err) = &result.metadata_error {
            report.push_str(&format!("   Metadata Warning: {}\n", meta_err));
        }

        // iCloud per-file details
        if let Some(apple) = &result.apple_hash {
            report.push_str(&format!("   Apple Hash:       {}\n", apple));
            if result.src_matches_apple == Some(true) {
                report.push_str("   Apple Match:      ✓ Transit OK\n");
            } else {
                report.push_str("   Apple Match:      ✗ TRANSIT FAILURE (file may have been altered)\n");
            }
            if result.verified {
                report.push_str("   Copy Verified:    ✓ Copy OK\n");
            } else {
                report.push_str("   Copy Verified:    ✗ COPY FAILURE\n");
            }
            if result.full_chain_verified == Some(true) {
                report.push_str("   Chain of Custody: ✓ FULLY VERIFIED\n");
            } else {
                report.push_str("   Chain of Custody: ✗ BROKEN\n");
            }
        } else if result.apple_hash_missing {
            report.push_str("   Apple Hash:       N/A (not in Apple CSV)\n");
        }

        report.push_str("\n");
    }

    // iCloud chain of custody failures section
    if icloud_mode.is_some() {
        let chain_failures: Vec<&FileCopyResult> = results.iter()
            .filter(|r| r.full_chain_verified == Some(false))
            .collect();

        if !chain_failures.is_empty() {
            report.push_str("----------------------------------------------------------\n");
            report.push_str("iCLOUD CHAIN OF CUSTODY FAILURES:\n");
            report.push_str("----------------------------------------------------------\n");
            for r in &chain_failures {
                report.push_str(&format!("  ✗  {}\n", r.source_path.display()));
                if r.src_matches_apple == Some(false) {
                    report.push_str("      → Transit failure: source hash does not match Apple hash\n");
                }
                if !r.verified {
                    report.push_str("      → Copy failure: destination hash does not match source hash\n");
                }
            }
            report.push_str("\n");
        }
    }

    // Missing evidence section (files in CSV but not on disk)
    if !missing_from_disk.is_empty() {
        report.push_str("----------------------------------------------------------\n");
        report.push_str("MISSING EVIDENCE (in Apple CSV but not found on disk):\n");
        report.push_str("----------------------------------------------------------\n");
        for (filename, apple_hash) in missing_from_disk {
            report.push_str(&format!("  ✗  {}\n", filename));
            report.push_str(&format!("      Apple Hash: {}\n", apple_hash));
        }
        report.push_str("\n");
    }

    if !dir_errors.is_empty() {
        report.push_str("----------------------------------------------------------\n");
        report.push_str("DIRECTORY METADATA WARNINGS:\n");
        report.push_str("----------------------------------------------------------\n");
        for err in dir_errors {
            report.push_str(&format!("  ⚠  {}\n", err));
        }
        report.push_str("\n");
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
