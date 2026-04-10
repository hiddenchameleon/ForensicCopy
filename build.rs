use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let man_src = PathBuf::from("docs/Forensic_Copy.1");
    let man_dst = out_dir.join("Forensic_Copy.1");

    if man_src.exists() {
        fs::copy(&man_src, &man_dst)
            .unwrap_or_else(|e| panic!("failed to copy man page to OUT_DIR: {}", e));
        println!("cargo:rerun-if-changed=docs/Forensic_Copy.1");
    }
}
