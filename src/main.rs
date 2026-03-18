mod errors;
mod hasher;
mod copier;
mod report;

use std::time::Instant;
use std::path::PathBuf;
use hasher::HashingAlgorithm;
use report::ReportConfig;



fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 3 {
        println!("Usage: Forensic_copy <source> <destination> [--hash sha256|blake3] [--report] [--report_path <path>]");
        return;
    }

    let source = &args[1];
    let destination = &args[2];
  
    let mut hashing_algorithm = HashingAlgorithm::Sha256;
    let hash_pos = args.iter().position(|a| a == "--hash");
    if let Some(pos) = hash_pos {
        let hashing = &args[pos + 1];
        hashing_algorithm = match hashing.as_str() {
            "sha256"        => HashingAlgorithm::Sha256,
            "blake3"        => HashingAlgorithm::Blake3,
            _               => {
                println!("Usage: Forensic_copy <source> <destination> [--hash sha256|blake3] [--report] [--report_path <path>]");
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
    let start = Instant::now();

    match copier::forensic_copy(source, destination, &hashing_algorithm){
        Ok(results) => {
            let total_time_ms = start.elapsed().as_millis() as u64;
            let verified = results.iter().filter(|r| r.verified).count();
            let failed = results.len() - verified;
            println!("Copied {} files in {}", results.len(), report::format_duration(total_time_ms));
            println!("Verified: {} Failed: {}", verified, failed);
            match report::generate_report(&results, source, destination, &hashing_algorithm, total_time_ms, &report_config) {
                Err(e) => println!("Error: {}", e),
                Ok(()) => println!("Report generated successfully!"),
            };
        },
        Err(e) => println!("Error: {}", e),
    }

    
    
}
