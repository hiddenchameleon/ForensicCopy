use std::time::Instant;
use std::path::PathBuf;
use report::ReportConfig;
use forensic_copy::{HashMode, ConflictMode, hasher::HashingAlgorithm, copier, report};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        println!("Usage: forensic_copy --source <path> [--source <path> ...] --destination <path>");
        println!("       forensic_copy <source> <destination>");
        println!("  Options: [--hash sha256|blake3|md5] [--no-hash] [--no-verify] [--report]");
        println!("           [--report-path <path>] [--on-conflict skip|overwrite|abort]");
        return;
    }

    let no_hash = args.contains(&String::from("--no-hash"));
    let no_verify = args.contains(&String::from("--no-verify"));
    if no_hash && no_verify {
        println!("Error: --no-hash and --no-verify are mutually exclusive.");
        return;
    }

    let hash_mode = if no_hash {
        HashMode::NoHash
    } else if no_verify {
        HashMode::NoVerify
    } else {
        HashMode::Full
    };

    let mut hashing_algorithm = HashingAlgorithm::Sha256;
    let hash_pos = args.iter().position(|a| a == "--hash");
    if let Some(pos) = hash_pos {
        let hashing = &args[pos + 1];
        hashing_algorithm = match hashing.as_str() {
            "sha256"        => HashingAlgorithm::Sha256,
            "blake3"        => HashingAlgorithm::Blake3,
            "md5"           => HashingAlgorithm::Md5,
            _               => {
                println!("Usage: forensic_copy --source <path> [--source <path> ...] --destination <path>");
                println!("  Options: [--hash sha256|blake3|md5] [--no-hash] [--no-verify] [--report]");
                println!("           [--report-path <path>] [--on-conflict skip|overwrite|abort]");
                return;
                },
        };
    };

    let mut report_config = ReportConfig {enabled: false, output_path: None};
    let report_enabled = args.contains(&String::from("--report"));
    if report_enabled {
        report_config.enabled = true;
    }

    let report_path_pos = args.iter().position(|a| a == "--report-path");
    if let Some(pos) = report_path_pos {
        let report_path = &args[pos + 1];
        report_config.enabled = true;
        report_config.output_path = Some(PathBuf::from(report_path))
    };

    let mut conflict_mode = ConflictMode::default();
    let conflict_pos = args.iter().position(|a| a == "--on-conflict");
    if let Some(pos) = conflict_pos {
        if pos + 1 >= args.len() {
            println!("Error: --on-conflict requires a mode argument (skip, overwrite, abort).");
            return;
        }
        conflict_mode = match args[pos + 1].as_str() {
            "skip"      => ConflictMode::Skip,
            "overwrite" => ConflictMode::Overwrite,
            "abort"     => ConflictMode::Abort,
            other => {
                println!("Error: unknown conflict mode '{}'. Use skip, overwrite, or abort.", other);
                return;
            }
        };
    }

    // Collect sources: either via --source flags or positional args (legacy)
    let mut sources: Vec<PathBuf> = Vec::new();
    let mut destination: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--source" {
            if i + 1 < args.len() {
                sources.push(PathBuf::from(&args[i + 1]));
                i += 2;
                continue;
            } else {
                println!("Error: --source requires a path argument.");
                return;
            }
        }
        if args[i] == "--destination" {
            if i + 1 < args.len() {
                destination = Some(args[i + 1].clone());
                i += 2;
                continue;
            } else {
                println!("Error: --destination requires a path argument.");
                return;
            }
        }
        i += 1;
    }

    // Fallback: legacy positional arguments (source destination)
    if sources.is_empty() && destination.is_none() {
        sources.push(PathBuf::from(&args[1]));
        destination = Some(args[2].clone());
    }

    let destination = match destination {
        Some(d) => d,
        None => {
            println!("Error: --destination is required.");
            return;
        }
    };

    if sources.is_empty() {
        println!("Error: at least one --source is required.");
        return;
    }

    let source_strings: Vec<String> = sources.iter().map(|s| s.display().to_string()).collect();

    let start = Instant::now();

    match copier::forensic_copy(&sources, &destination, &hashing_algorithm, &hash_mode, &conflict_mode, |_done, _total, _filename| {
        // Progress is printed by forensic_copy via indicatif.
    }) {
        Ok((results, dir_errors)) => {
            let total_time_ms = start.elapsed().as_millis() as u64;
            let skipped = results.iter().filter(|r| r.skipped).count();
            let verified = results.iter().filter(|r| r.verified).count();
            let failed = results.len() - verified - skipped;
            let meta_warnings = results.iter().filter(|r| r.metadata_error.is_some()).count();
            println!("Copied {} files in {}", results.len(), report::format_duration(total_time_ms));
            println!("Verified: {} Failed: {} Skipped: {} Metadata warnings: {} Dir metadata warnings: {}", verified, failed, skipped, meta_warnings, dir_errors.len());
            let dir_error_strings: Vec<String> = dir_errors
                .iter()
                .map(|(path, err)| format!("{}: {}", path.display(), err))
                .collect();
            match report::generate_report(&results, &dir_error_strings, &source_strings, &destination, &hashing_algorithm, &hash_mode, total_time_ms, &report_config) {
                Err(e) => println!("Error: {}", e),
                Ok(()) => println!("Report generated successfully!"),
            };
        },
        Err(e) => println!("Error: {}", e),
    }
}
