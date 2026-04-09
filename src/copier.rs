use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use filetime::FileTime;
use rayon;
use crate::errors::ForensicError;
use crate::hasher::HashingAlgorithm;
use crate::hasher::{hash_file_with_progress, copy_and_hash};
use crate::{HashMode, ConflictMode};
use crate::icloud::ICloudMode;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::collections::HashSet;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

const LARGE_FILE_THRESHOLD: u64 = 100 * 1024 * 1024;

#[derive(Debug)]
pub struct FileCopyResult {
    pub source_path: PathBuf,
    pub dest_path: PathBuf,
    pub file_size: u64,
    pub src_hash: String,
    pub dest_hash: String,
    pub verified: bool,
    pub skipped: bool,
    pub skip_reason: Option<String>,
    pub error: Option<String>,
    pub copy_time_ms: u64,
    pub metadata_error: Option<String>,
    // iCloud Production fields
    pub apple_hash: Option<String>,
    pub src_matches_apple: Option<bool>,
    pub dest_matches_apple: Option<bool>,
    pub full_chain_verified: Option<bool>,
    pub apple_hash_missing: bool,
}

pub fn collect_files(dir: &Path) -> Result<Vec<PathBuf>, ForensicError> {
    let mut files = Vec::new();
    let mut seen = HashSet::new();
    collect_files_inner(dir, &mut files, &mut seen)?;
    Ok(files)
}

pub fn collect_dirs(dir: &Path) -> Result<Vec<PathBuf>, ForensicError> {
    let mut dirs = Vec::new();
    collect_dirs_inner(dir, &mut dirs)?;
    Ok(dirs)
}

fn collect_dirs_inner(dir: &Path, dirs: &mut Vec<PathBuf>) -> Result<(), ForensicError> {
    let entries = fs::read_dir(dir)
        .map_err(|e| ForensicError::DirectoryNotReadable(e.to_string()))?;
    for entry in entries {
        let entry = entry.map_err(|e| ForensicError::DirectoryNotReadable(e.to_string()))?;
        let path = entry.path();
        if path.is_dir() {
            dirs.push(path.clone());
            collect_dirs_inner(&path, dirs)?;
        }
    }
    Ok(())
}

fn collect_files_inner(
    dir: &Path,
    files: &mut Vec<PathBuf>,
    seen: &mut HashSet<PathBuf>,
) -> Result<(), ForensicError> {
    let entries = fs::read_dir(dir)
        .map_err(|e| ForensicError::DirectoryNotReadable(e.to_string()))?;
    for entry in entries {
        let entry = entry.map_err(|e| ForensicError::DirectoryNotReadable(e.to_string()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_files_inner(&path, files, seen)?;
        } else {
            let file_name = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            if !file_name.starts_with("._") {
                // Only canonicalize when we detect a collision (hardlink/symlink)
                if seen.insert(path.clone()) {
                    files.push(path);
                }
            }
        }
    }
    Ok(())
}

fn preserve_metadata(src: &Path, dest: &Path) -> Result<(), String> {
    let src_meta = fs::metadata(src).map_err(|e| e.to_string())?;

    // Cache metadata once for all platform-specific operations
    #[cfg(windows)]
    let birthtime = src_meta.creation_time();
    #[cfg(target_os = "macos")]
    let birthtime = src_meta.created().ok();

    // Always set access and modification times
    let atime = FileTime::from_last_access_time(&src_meta);
    let mtime = FileTime::from_last_modification_time(&src_meta);
    filetime::set_file_times(dest, atime, mtime).map_err(|e| e.to_string())?;

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::{FILETIME, HANDLE};
        use windows::Win32::Storage::FileSystem::{
            SetFileTime, FILE_WRITE_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS,
        };

        let creation_ft = FILETIME {
            dwLowDateTime: (birthtime & 0xFFFFFFFF) as u32,
            dwHighDateTime: (birthtime >> 32) as u32,
        };

        // Directories require FILE_FLAG_BACKUP_SEMANTICS to open a handle
        let flags = if dest.is_dir() {
            FILE_WRITE_ATTRIBUTES.0 | FILE_FLAG_BACKUP_SEMANTICS.0
        } else {
            FILE_WRITE_ATTRIBUTES.0
        };

        let file = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(flags)
            .open(dest)
            .map_err(|e| format!("birthtime open: {}", e))?;

        let handle = HANDLE(file.as_raw_handle() as *mut std::ffi::c_void);

        unsafe {
            SetFileTime(handle, Some(&creation_ft), None, None)
                .map_err(|e| format!("birthtime set: {}", e))?;
        }
    }

    #[cfg(target_os = "macos")]
    {
        use libc::{attrlist, setattrlist, ATTR_BIT_MAP_COUNT, ATTR_CMN_CRTIME};
        use std::ffi::CString;

        let secs = birthtime
            .ok_or_else(|| "birthtime read failed".to_string())?
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("birthtime duration: {}", e))?
            .as_secs() as libc::time_t;

        let dest_cstr = CString::new(dest.to_string_lossy().as_bytes())
            .map_err(|e| format!("birthtime path: {}", e))?;

        #[repr(C)]
        struct AttrBuf {
            ts: libc::timespec,
        }

        let buf = AttrBuf {
            ts: libc::timespec { tv_sec: secs, tv_nsec: 0 },
        };

        let mut attrs: attrlist = unsafe { std::mem::zeroed() };
        attrs.bitmapcount = ATTR_BIT_MAP_COUNT;
        attrs.commonattr = ATTR_CMN_CRTIME;

        let result = unsafe {
            setattrlist(
                dest_cstr.as_ptr(),
                &mut attrs as *mut attrlist as *mut libc::c_void,
                &buf as *const AttrBuf as *mut libc::c_void,
                std::mem::size_of::<AttrBuf>(),
                0,
            )
        };

        if result != 0 {
            return Err(format!("birthtime setattrlist failed (errno {})", result));
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        return Err(String::from("birthtime preservation not supported on Linux"));
    }

    #[cfg(unix)]
    {
        let permissions = src_meta.permissions();
        fs::set_permissions(dest, permissions).map_err(|e| e.to_string())?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use nix::unistd::{chown, Gid, Uid};
        let uid = Uid::from_raw(src_meta.uid());
        let gid = Gid::from_raw(src_meta.gid());
        if let Err(e) = chown(dest, Some(uid), Some(gid)) {
            return Err(format!("ownership: {}", e));
        }
    }

    #[cfg(unix)]
    {
        for attr in xattr::list(src).map_err(|e| e.to_string())? {
            if let Ok(Some(value)) = xattr::get(src, &attr) {
                xattr::set(dest, &attr, &value).map_err(|e| e.to_string())?;
            }
        }
    }

    Ok(())
}

fn process_file<F, B>(
    file: &Path,
    source_path: &Path,
    destination_path: &Path,
    algorithm: &HashingAlgorithm,
    hash_mode: &HashMode,
    conflict_mode: &ConflictMode,
    icloud_mode: Option<&ICloudMode>,
    multi: &MultiProgress,
    overall_bar: &ProgressBar,
    completed: &AtomicU64,
    total: u64,
    progress_callback: &F,
    byte_progress_callback: &B,
) -> Result<FileCopyResult, ForensicError>
where
    F: Fn(u64, u64, &str) + Send + Sync,
    B: Fn(&str, u64, u64, u64, bool, bool) + Send + Sync,
{
    let start = Instant::now();

    let relative = file
        .strip_prefix(source_path)
        .map_err(|e| ForensicError::CopyError(e.to_string()))?;
    let dest_path = destination_path.join(relative);

    let file_size = fs::metadata(file)
        .map_err(|e| ForensicError::FileReadError(e.to_string()))?
        .len();

    // Conflict check — Skip mode returns early without copying
    if dest_path.exists() && *conflict_mode == ConflictMode::Skip {
        overall_bar.inc(1);
        let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
        let filename = file.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        multi.println(format!("Progress: {}/{} - {} (skipped)", done, total, &filename)).ok();
        progress_callback(done, total, &filename);

        return Ok(FileCopyResult {
            source_path: file.to_path_buf(),
            dest_path,
            file_size,
            src_hash: String::from("N/A"),
            dest_hash: String::from("N/A"),
            verified: false,
            skipped: true,
            skip_reason: Some(String::from("destination already exists")),
            error: None,
            copy_time_ms: 0,
            metadata_error: None,
            apple_hash: None,
            src_matches_apple: None,
            dest_matches_apple: None,
            full_chain_verified: None,
            apple_hash_missing: false,
        });
    }
    // Overwrite mode falls through to normal copy; Abort is handled before the parallel loop.

    let large_file = file_size >= LARGE_FILE_THRESHOLD;
    let file_id = file.display().to_string();

    let file_bar = if large_file {
        let bar = multi.add(ProgressBar::new(file_size));
        bar.set_style(
            ProgressStyle::with_template(
                "  {spinner:.yellow} {wide_msg} [{bar:30.yellow/white}] {bytes}/{total_bytes} ({bytes_per_sec})"
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        bar.set_message(
            file.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        );
        Some(bar)
    } else {
        None
    };

    let last_emit: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);
    let throttled_byte_cb = |bytes_done: u64, bytes_total: u64| {
        let mut last = last_emit.lock().unwrap();
        let should_emit = match *last {
            None => true,
            Some(t) => t.elapsed().as_millis() >= 1000,
        };
        if should_emit {
            byte_progress_callback(&file_id, bytes_done, bytes_total, file_size, false, false);
            *last = Some(Instant::now());
        }
    };

    // Single-pass copy+hash avoids reading the source file twice.
    let src_hash = match hash_mode {
        HashMode::NoHash => {
            fs::copy(file, &dest_path)
                .map_err(|e| ForensicError::CopyError(e.to_string()))?;
            String::from("N/A")
        }
        _ => {
            let byte_cb: Option<&dyn Fn(u64, u64)> = if large_file { Some(&throttled_byte_cb) } else { None };
            copy_and_hash(file, &dest_path, algorithm, file_bar.as_ref(), file_size, byte_cb)?
        }
    };

    let metadata_error = preserve_metadata(file, &dest_path).err();

    if large_file && matches!(hash_mode, HashMode::Full) {
        byte_progress_callback(&file_id, file_size, file_size, file_size, false, true);
    }

    let (dest_hash, verified) = match hash_mode {
        HashMode::Full => {
            let h = hash_file_with_progress(&dest_path, algorithm, file_bar.as_ref())?;
            let v = src_hash == h;
            (h, v)
        }
        HashMode::NoVerify => (String::from("N/A"), true),
        HashMode::NoHash => (String::from("N/A"), true),
    };

    if large_file {
        byte_progress_callback(&file_id, file_size, file_size, file_size, true, false);
    }

    if let Some(bar) = file_bar {
        bar.finish_and_clear();
    }

    overall_bar.inc(1);
    let copy_time_ms = start.elapsed().as_millis() as u64;

    let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
    let filename = file.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    multi.println(format!("Progress: {}/{} - {}", done, total, &filename)).ok();
    progress_callback(done, total, &filename);

    // iCloud three-way hash comparison
    let (apple_hash, src_matches_apple, dest_matches_apple, full_chain_verified, apple_hash_missing) =
        if let Some(icloud) = icloud_mode {
            let filename = file.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            if let Some(apple) = icloud.hash_map.get(&filename) {
                let src_ok = src_hash == *apple;
                let dest_ok = dest_hash == *apple;
                let chain = src_ok && dest_ok && src_hash == dest_hash;
                (Some(apple.clone()), Some(src_ok), Some(dest_ok), Some(chain), false)
            } else {
                (None, None, None, None, true)
            }
        } else {
            (None, None, None, None, false)
        };

    Ok(FileCopyResult {
        source_path: file.to_path_buf(),
        dest_path,
        file_size,
        src_hash,
        dest_hash,
        verified,
        skipped: false,
        skip_reason: None,
        error: if verified { None } else { Some(String::from("Hash mismatch!")) },
        copy_time_ms,
        metadata_error,
        apple_hash,
        src_matches_apple,
        dest_matches_apple,
        full_chain_verified,
        apple_hash_missing,
    })
}

/// Entry describing a single file to copy, carrying the base paths needed to
/// reconstruct the relative destination path.
struct CopyEntry {
    /// Absolute path to the file on disk.
    file: PathBuf,
    /// The "root" path this file's relative path should be computed from.
    strip_base: PathBuf,
    /// Prefix prepended to the relative path inside the destination.
    /// For directory sources this is the directory's name; for individual
    /// files this is empty (file lands directly in the destination root).
    dest_prefix: PathBuf,
    /// iCloud mode for this file's source, if applicable.
    icloud_mode: Option<Arc<ICloudMode>>,
}

pub fn forensic_copy<F, B>(
    sources: &[PathBuf],
    destination: &str,
    algorithm: &HashingAlgorithm,
    hash_mode: &HashMode,
    conflict_mode: &ConflictMode,
    source_icloud_modes: Vec<Option<ICloudMode>>,
    progress_callback: F,
    byte_progress_callback: B,
) -> Result<(Vec<FileCopyResult>, Vec<(PathBuf, String)>, Vec<(String, String)>), ForensicError>
where
    F: Fn(u64, u64, &str) + Send + Sync,
    B: Fn(&str, u64, u64, u64, bool, bool) + Send + Sync,
{
    if sources.is_empty() {
        return Err(ForensicError::DirectoryNotFound("no sources provided".to_string()));
    }

    // Build per-source Arcs
    let source_arcs: Vec<Option<Arc<ICloudMode>>> = source_icloud_modes
        .into_iter()
        .map(|opt| opt.map(Arc::new))
        .collect();

    // iCloud mode enforcement — if any source has iCloud, require SHA256 + Full
    if source_arcs.iter().any(|m| m.is_some()) {
        if !matches!(algorithm, HashingAlgorithm::Sha256) {
            return Err(ForensicError::CopyError(
                "iCloud Production mode requires SHA256 hashing algorithm".to_string(),
            ));
        }
        if !matches!(hash_mode, HashMode::Full) {
            return Err(ForensicError::CopyError(
                "iCloud Production mode requires Full hash mode (no --no-hash or --no-verify)".to_string(),
            ));
        }
    }

    let destination_path = Path::new(destination);
    if !destination_path.exists() {
        fs::create_dir_all(destination_path)
            .map_err(|e| ForensicError::CreateDirectoryFailed(e.to_string()))?;
    }

    // Build a flat list of files to copy, each annotated with how to place it
    // inside the destination.
    let mut entries: Vec<CopyEntry> = Vec::new();
    // Track (source_path, dest_prefix) pairs for directory metadata preservation.
    let mut dir_sources: Vec<(PathBuf, PathBuf)> = Vec::new();

    for (src_idx, src) in sources.iter().enumerate() {
        if !src.exists() {
            return Err(ForensicError::DirectoryNotFound(src.display().to_string()));
        }

        let src_icloud = source_arcs.get(src_idx).and_then(|m| m.clone());

        if src.is_dir() {
            let dir_name = src.file_name()
                .ok_or_else(|| ForensicError::DirectoryNotFound(src.display().to_string()))?;
            let dest_prefix = PathBuf::from(dir_name);

            let files = collect_files(src)?;
            for f in files {
                entries.push(CopyEntry {
                    file: f,
                    strip_base: src.clone(),
                    dest_prefix: dest_prefix.clone(),
                    icloud_mode: src_icloud.clone(),
                });
            }
            dir_sources.push((src.clone(), dest_prefix));
        } else {
            // Individual file — lands directly in the destination root.
            let parent = src.parent()
                .ok_or_else(|| ForensicError::FileReadError(format!("cannot determine parent of {}", src.display())))?;
            entries.push(CopyEntry {
                file: src.clone(),
                strip_base: parent.to_path_buf(),
                dest_prefix: PathBuf::new(),
                icloud_mode: src_icloud,
            });
        }
    }

    let total = entries.len() as u64;

    // Pre-create all destination directories so parallel copies don't race.
    for entry in &entries {
        if let Ok(relative) = entry.file.strip_prefix(&entry.strip_base) {
            let dest_path = destination_path.join(&entry.dest_prefix).join(relative);
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| ForensicError::CreateDirectoryFailed(e.to_string()))?;
            }
        }
    }

    // Abort mode: fail immediately if any destination file already exists.
    if *conflict_mode == ConflictMode::Abort {
        for entry in &entries {
            if let Ok(relative) = entry.file.strip_prefix(&entry.strip_base) {
                let dest_path = destination_path
                    .join(&entry.dest_prefix)
                    .join(relative);
                if dest_path.exists() {
                    return Err(ForensicError::CopyError(format!(
                        "Abort: destination file already exists: {}",
                        dest_path.display()
                    )));
                }
            }
        }
    }

    let multi = MultiProgress::new();
    let overall_bar = multi.add(ProgressBar::new(total));
    overall_bar.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({eta})"
        )
        .unwrap()
        .progress_chars("=>-"),
    );

    // Shared work queue: each thread atomically grabs the next file index.
    let next_index = AtomicU64::new(0);
    let completed = AtomicU64::new(0);

    // Pre-allocate results with None slots; threads fill them by index.
    let results_slots: Vec<std::sync::Mutex<Option<FileCopyResult>>> =
        (0..entries.len()).map(|_| std::sync::Mutex::new(None)).collect();
    let first_error: std::sync::Mutex<Option<ForensicError>> = std::sync::Mutex::new(None);

    let num_threads = rayon::current_num_threads();
    rayon::scope(|s| {
        for _ in 0..num_threads {
            s.spawn(|_| {
                loop {
                    if first_error.lock().unwrap().is_some() {
                        return;
                    }

                    let idx = next_index.fetch_add(1, Ordering::Relaxed) as usize;
                    if idx >= entries.len() {
                        return;
                    }

                    let entry = &entries[idx];
                    let effective_dest = destination_path.join(&entry.dest_prefix);
                    let result = process_file(
                        &entry.file, &entry.strip_base, &effective_dest,
                        algorithm, hash_mode, conflict_mode, entry.icloud_mode.as_deref(), &multi,
                        &overall_bar, &completed, total, &progress_callback,
                        &byte_progress_callback,
                    );

                    match result {
                        Ok(r) => {
                            *results_slots[idx].lock().unwrap() = Some(r);
                        }
                        Err(e) => {
                            *first_error.lock().unwrap() = Some(e);
                            return;
                        }
                    }
                }
            });
        }
    });

    overall_bar.finish_with_message("Done!");

    if let Some(e) = first_error.into_inner().unwrap() {
        return Err(e);
    }

    let file_results: Vec<FileCopyResult> = results_slots
        .into_iter()
        .map(|slot| slot.into_inner().unwrap().unwrap())
        .collect();

    // Preserve directory metadata deepest-first for each directory source.
    let mut dir_metadata_errors: Vec<(PathBuf, String)> = Vec::new();

    for (source_path, dest_prefix) in &dir_sources {
        let effective_dest = destination_path.join(dest_prefix);

        let mut all_dirs = collect_dirs(source_path)?;
        all_dirs.sort_by(|a, b| b.components().count().cmp(&a.components().count()));

        for src_dir in &all_dirs {
            let relative = match src_dir.strip_prefix(source_path) {
                Ok(r) => r,
                Err(e) => {
                    dir_metadata_errors.push((src_dir.clone(), e.to_string()));
                    continue;
                }
            };
            let dest_dir = effective_dest.join(relative);
            if dest_dir.exists() {
                if let Err(e) = preserve_metadata(src_dir, &dest_dir) {
                    dir_metadata_errors.push((src_dir.clone(), e));
                }
            }
        }

        if effective_dest.exists() {
            if let Err(e) = preserve_metadata(source_path, &effective_dest) {
                dir_metadata_errors.push((source_path.clone(), e));
            }
        }
    }

    // Collect files listed in each source's Apple CSV but not found on disk
    let mut missing_from_disk: Vec<(String, String)> = Vec::new();
    for (src_idx, src) in sources.iter().enumerate() {
        if let Some(icloud) = source_arcs.get(src_idx).and_then(|m| m.as_ref()) {
            let copied_filenames: HashSet<String> = file_results.iter()
                .filter(|r| r.source_path.starts_with(src))
                .filter_map(|r| {
                    r.source_path.file_name()
                        .and_then(|n| n.to_str())
                        .map(|s| s.to_string())
                })
                .collect();
            for (name, hash) in &icloud.hash_map {
                if !copied_filenames.contains(name.as_str()) {
                    missing_from_disk.push((name.clone(), hash.clone()));
                }
            }
        }
    }

    Ok((file_results, dir_metadata_errors, missing_from_disk))
}