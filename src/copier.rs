use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use filetime::FileTime;
use crate::errors::ForensicError;
use crate::hasher::HashingAlgorithm;
use crate::hasher::hash_file_with_progress;
use crate::HashMode;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::collections::HashSet;

const LARGE_FILE_THRESHOLD: u64 = 100 * 1024 * 1024;

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
    pub metadata_error: Option<String>,
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
                let canonical = fs::canonicalize(&path)
                    .unwrap_or_else(|_| path.clone());
                if seen.insert(canonical) {
                    files.push(path);
                }
            }
        }
    }
    Ok(())
}

fn preserve_metadata(src: &Path, dest: &Path) -> Result<(), String> {
    let src_meta = fs::metadata(src).map_err(|e| e.to_string())?;

    let atime = FileTime::from_last_access_time(&src_meta);
    let mtime = FileTime::from_last_modification_time(&src_meta);
    filetime::set_file_times(dest, atime, mtime).map_err(|e| e.to_string())?;

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::{FILETIME, HANDLE};
        use windows::Win32::Storage::FileSystem::{SetFileTime, FILE_WRITE_ATTRIBUTES};

        let birthtime = src_meta.creation_time();
        let creation_ft = FILETIME {
            dwLowDateTime: (birthtime & 0xFFFFFFFF) as u32,
            dwHighDateTime: (birthtime >> 32) as u32,
        };

        let file = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(FILE_WRITE_ATTRIBUTES.0)
            .open(dest)
            .map_err(|e| format!("birthtime open: {}", e))?;

        let handle = HANDLE(file.as_raw_handle() as isize);

        unsafe {
            SetFileTime(handle, Some(&creation_ft), None, None)
                .map_err(|e| format!("birthtime set: {}", e))?;
        }
    }

    #[cfg(target_os = "macos")]
    {
        use libc::{attrlist, setattrlist, ATTR_BIT_MAP_COUNT, ATTR_CMN_CRTIME};
        use std::ffi::CString;

        let birthtime = src_meta.created()
            .map_err(|e| format!("birthtime read: {}", e))?;
        let secs = birthtime
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

pub fn forensic_copy<F>(
    source: &str,
    destination: &str,
    algorithm: &HashingAlgorithm,
    hash_mode: &HashMode,
    progress_callback: F,
) -> Result<(Vec<FileCopyResult>, Vec<(PathBuf, String)>), ForensicError>
where
    F: Fn(u64, u64, &str) + Send + Sync,
{
    let source_path = Path::new(source);
    if !source_path.exists() || !source_path.is_dir() {
        return Err(ForensicError::DirectoryNotFound(source_path.display().to_string()));
    }

    let destination_path = Path::new(destination);
    if !destination_path.exists() {
        fs::create_dir_all(destination_path)
            .map_err(|e| ForensicError::CreateDirectoryFailed(e.to_string()))?;
    }

    let all_files = collect_files(source_path)?;
    let total = all_files.len() as u64;

    // let multi = MultiProgress::new();
    // let overall_bar = multi.add(ProgressBar::new(total));
    // overall_bar.set_style(
    //     ProgressStyle::with_template(
    //         "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({eta})"
    //     )
    //     .unwrap()
    //     .progress_chars("=>-"),
    // );
    let multi = MultiProgress::new();
    let overall_bar = multi.add(ProgressBar::hidden());

    let mut file_results: Vec<FileCopyResult> = Vec::new();

    for (i, file) in all_files.iter().enumerate() {
        let start = Instant::now();

        let relative = file
            .strip_prefix(source_path)
            .map_err(|e| ForensicError::CopyError(e.to_string()))?;
        let dest_path = destination_path.join(relative);

        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| ForensicError::CreateDirectoryFailed(e.to_string()))?;
        }

        let file_size = fs::metadata(file)
            .map_err(|e| ForensicError::FileReadError(e.to_string()))?
            .len();

        let file_bar = if file_size >= LARGE_FILE_THRESHOLD {
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

        let src_hash = match hash_mode {
            HashMode::NoHash => String::from("N/A"),
            _ => hash_file_with_progress(file, algorithm, file_bar.as_ref())?,
        };

        fs::copy(file, &dest_path)
            .map_err(|e| ForensicError::CopyError(e.to_string()))?;

        let metadata_error = preserve_metadata(file, &dest_path).err();

        let (dest_hash, verified) = match hash_mode {
            HashMode::Full => {
                let h = hash_file_with_progress(&dest_path, algorithm, file_bar.as_ref())?;
                let v = src_hash == h;
                (h, v)
            }
            HashMode::NoVerify => (String::from("N/A"), true),
            HashMode::NoHash => (String::from("N/A"), true),
        };

        if let Some(bar) = file_bar {
            bar.finish_and_clear();
        }

        overall_bar.inc(1);
        let copy_time_ms = start.elapsed().as_millis() as u64;

        // Fire progress callback
        let filename = file.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        progress_callback(i as u64 + 1, total, &filename);

        file_results.push(FileCopyResult {
            source_path: file.clone(),
            dest_path,
            file_size,
            src_hash,
            dest_hash,
            verified,
            error: if verified { None } else { Some(String::from("Hash mismatch!")) },
            copy_time_ms,
            metadata_error,
        });
    }

    // overall_bar.finish_with_message("Done!");
    overall_bar.finish_and_clear();
    // Preserve directory metadata deepest-first
    let mut all_dirs = collect_dirs(source_path)?;
    all_dirs.sort_by(|a, b| b.components().count().cmp(&a.components().count()));

    let mut dir_metadata_errors: Vec<(PathBuf, String)> = Vec::new();

    for src_dir in &all_dirs {
        let relative = match src_dir.strip_prefix(source_path) {
            Ok(r) => r,
            Err(e) => {
                dir_metadata_errors.push((src_dir.clone(), e.to_string()));
                continue;
            }
        };
        let dest_dir = destination_path.join(relative);
        if dest_dir.exists() {
            if let Err(e) = preserve_metadata(src_dir, &dest_dir) {
                dir_metadata_errors.push((src_dir.clone(), e));
            }
        }
    }

    if let Err(e) = preserve_metadata(source_path, destination_path) {
        dir_metadata_errors.push((source_path.to_path_buf(), e));
    }

    Ok((file_results, dir_metadata_errors))
}