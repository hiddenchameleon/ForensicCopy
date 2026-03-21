mod errors;
mod hasher;
mod copier;
mod report;

use std::time::Instant;
use std::path::PathBuf;
use hasher::HashingAlgorithm;
use report::ReportConfig;

pub enum HashMode {
    Full,
    NoVerify,
    NoHash,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 3 {
        println!("Usage: Forensic_copy <source> <destination> [--hash sha256|blake3] [--no-hash] [--no-verify] [--report] [--report_path <path>]");
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
            _               => {
                println!("Usage: Forensic_copy <source> <destination> [--hash sha256|blake3] [--no-hash] [--no-verify] [--report] [--report_path <path>]");
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
        let report_path = &args[pos + 1 ];
        report_config.enabled = true;
        report_config.output_path = Some(PathBuf::from(report_path))        
    };

    let source = &args[1];
    let destination = &args[2];
  
    
    
    
    let start = Instant::now();

    match copier::forensic_copy(source, destination, &hashing_algorithm, &hash_mode ){
        Ok(results) => {
            let total_time_ms = start.elapsed().as_millis() as u64;
            let verified = results.iter().filter(|r| r.verified).count();
            let failed = results.len() - verified;
            let meta_warnings = results.iter().filter(|r| r.metadata_error.is_some()).count();
            println!("Copied {} files in {}", results.len(), report::format_duration(total_time_ms));
            println!("Verified: {} Failed: {} Metadata warnings: {}", verified, failed, meta_warnings);
            match report::generate_report(&results, source, destination, &hashing_algorithm, &hash_mode,total_time_ms, &report_config) {
                Err(e) => println!("Error: {}", e),
                Ok(()) => println!("Report generated successfully!"),
            };
        },
        Err(e) => println!("Error: {}", e),
    }

    
    
}
