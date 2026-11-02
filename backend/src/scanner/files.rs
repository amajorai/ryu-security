//! Bounded source collection: full-tree walks and the isolated Git metadata
//! projection that lists uncommitted files without loading repository config.

use super::git::{git_environment_path, git_value, read_only_git};
use super::*;

pub(super) fn collect_files(root: &Path) -> Result<FileCollection> {
    let mut collection = FileCollection::default();
    visit_directory(root, root, &mut collection)?;
    Ok(collection)
}

pub(super) fn collect_changed_files(repository: &Path) -> Result<FileCollection> {
    // git diff can run clean/process filters even with --no-ext-diff. Use an
    // isolated metadata directory so repository configuration is never loaded
    // by the index-refreshing operation. Attributes alone cannot define commands.
    let head = git_value(repository, &["rev-parse", "HEAD"]).context("read repository HEAD")?;
    if !matches!(head.len(), 40 | 64) || !head.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("invalid repository HEAD");
    }
    let git_path = |name: &str| -> Result<PathBuf> {
        let path = git_value(repository, &["rev-parse", "--git-path", name])
            .context("resolve repository metadata")?;
        let path = PathBuf::from(path);
        Ok(if path.is_absolute() {
            path
        } else {
            repository.join(path)
        })
    };
    let objects = git_path("objects")?.canonicalize()?;
    let index = git_path("index")?;
    let projection = tempfile::Builder::new()
        .prefix("ryu-security-git-")
        .tempdir()?;
    fs::create_dir(projection.path().join("objects"))?;
    fs::create_dir(projection.path().join("refs"))?;
    fs::write(projection.path().join("HEAD"), format!("{head}\n"))?;
    fs::write(
        projection.path().join("config"),
        if head.len() == 64 {
            "[core]\nrepositoryformatversion = 1\n[extensions]\nobjectFormat = sha256\n"
        } else {
            "[core]\nrepositoryformatversion = 0\n"
        },
    )?;
    if index.exists() {
        // Copy through a bounded reader, not metadata()+copy() with a race.
        let (bytes, index_times) = read_keeping_times(&index, 64 * 1024 * 1024 + 1)?;
        if bytes.len() > 64 * 1024 * 1024 {
            anyhow::bail!("repository index exceeds review limit");
        }
        let hash_bytes = head.len() / 2;
        let mut copied = std::collections::HashSet::new();
        let mut total = bytes.len();
        // Split-index link extensions name a shared index by its hash. Copy
        // only referenced files, preserving the same aggregate metadata cap.
        for (position, marker) in bytes.windows(4).enumerate() {
            if marker != b"link" {
                continue;
            }
            let Some(size_bytes) = bytes.get(position + 4..position + 8) else {
                continue;
            };
            let size = u32::from_be_bytes(size_bytes.try_into().unwrap()) as usize;
            if size < hash_bytes
                || position.saturating_add(8).saturating_add(size)
                    > bytes.len().saturating_sub(hash_bytes)
            {
                continue;
            }
            let hash = &bytes[position + 8..position + 8 + hash_bytes];
            let name = format!(
                "sharedindex.{}",
                hash.iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            let shared = index.parent().context("index has no parent")?.join(&name);
            if !shared.is_file() || !copied.insert(name.clone()) {
                continue;
            }
            let (shared_bytes, shared_times) =
                read_keeping_times(&shared, (64 * 1024 * 1024 - total + 1) as u64)?;
            total += shared_bytes.len();
            if total > 64 * 1024 * 1024 {
                anyhow::bail!("repository index exceeds review limit");
            }
            write_keeping_times(&projection.path().join(name), &shared_bytes, shared_times)?;
        }
        write_keeping_times(&projection.path().join("index"), &bytes, index_times)?;
    }
    let output = read_only_git(repository)
        .env("GIT_DIR", projection.path())
        .env("GIT_WORK_TREE", git_environment_path(repository))
        .env("GIT_OBJECT_DIRECTORY", git_environment_path(&objects))
        .args([
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--name-only",
            "-z",
            "HEAD",
            "--",
        ])
        .output()
        .context("read the repository's uncommitted file list")?;
    if !output.status.success() {
        anyhow::bail!("Git metadata projection could not enumerate changes");
    }
    let mut collection = FileCollection::default();
    for line in String::from_utf8_lossy(&output.stdout).split('\0') {
        if collection.files.len() >= MAX_FILES || collection.total_bytes >= MAX_TOTAL_BYTES {
            collection.capped = true;
            break;
        }
        let relative = Path::new(line);
        if relative.as_os_str().is_empty() || relative.is_absolute() {
            continue;
        }
        let candidate = repository.join(relative);
        let Ok(canonical) = candidate.canonicalize() else {
            continue;
        };
        if !canonical.starts_with(repository) || !canonical.is_file() {
            continue;
        }
        if !is_source_file(&canonical) {
            continue;
        }
        read_source_file(&canonical, repository, &mut collection)?;
    }
    Ok(collection)
}

/// Reads at most `limit` bytes of `path` together with its access and
/// modification times. The times are captured before the contents, so a
/// concurrent rewrite only makes a copy stamped with them more conservative.
pub(super) fn read_keeping_times(path: &Path, limit: u64) -> std::io::Result<(Vec<u8>, fs::FileTimes)> {
    use std::io::Read;
    let file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    let mut times = fs::FileTimes::new().set_modified(metadata.modified()?);
    if let Ok(accessed) = metadata.accessed() {
        times = times.set_accessed(accessed);
    }
    let mut bytes = Vec::new();
    file.take(limit).read_to_end(&mut bytes)?;
    Ok((bytes, times))
}

/// Writes a copy of Git index metadata and stamps it with the source's times.
/// Git trusts a cached stat entry unless the entry is not older than the index
/// file itself (the "racily clean" check), so a fresh mtime on the copy would
/// hide a same-size edit made within the filesystem's timestamp granularity.
/// The copy is written through a handle created here rather than `fs::copy`,
/// which would carry over a read-only index's permissions. Shared split-index
/// files go through the same path; Git resolves them in the projected `GIT_DIR`,
/// beside the projected index.
pub(super) fn write_keeping_times(path: &Path, bytes: &[u8], times: fs::FileTimes) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = fs::File::create(path)?;
    file.write_all(bytes)?;
    file.set_times(times)
}

pub(super) fn visit_directory(root: &Path, current: &Path, collection: &mut FileCollection) -> Result<()> {
    if collection.files.len() >= MAX_FILES || collection.total_bytes >= MAX_TOTAL_BYTES {
        collection.capped = true;
        return Ok(());
    }
    let entries = match fs::read_dir(current) {
        Ok(entries) => entries,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        if collection.files.len() >= MAX_FILES || collection.total_bytes >= MAX_TOTAL_BYTES {
            collection.capped = true;
            break;
        }
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            let name = entry.file_name();
            if SKIP_DIRECTORIES
                .iter()
                .any(|ignored| name.to_string_lossy().eq_ignore_ascii_case(ignored))
            {
                continue;
            }
            visit_directory(root, &path, collection)?;
        } else if file_type.is_file() && is_source_file(&path) {
            read_source_file(&path, root, collection)?;
        }
    }
    Ok(())
}

pub(super) fn read_source_file(path: &Path, root: &Path, collection: &mut FileCollection) -> Result<()> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return Ok(()),
    };
    let size = usize::try_from(metadata.len()).unwrap_or(MAX_FILE_BYTES + 1);
    if size > MAX_FILE_BYTES || collection.total_bytes.saturating_add(size) > MAX_TOTAL_BYTES {
        collection.capped = true;
        return Ok(());
    }
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(()),
    };
    let contents = String::from_utf8_lossy(&bytes).into_owned();
    let relative_path = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    collection.total_bytes = collection.total_bytes.saturating_add(bytes.len());
    collection.files.push(SourceFile {
        relative_path,
        contents,
    });
    Ok(())
}

pub(super) fn is_source_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if name == ".env" || name.starts_with(".env.") {
        return true;
    }
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| {
            SOURCE_EXTENSIONS
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(extension))
        })
        .unwrap_or(false)
}
