//! Racily clean and split-index projections for the changes scan. A child
//! module of `scanner`.

use super::files::{read_keeping_times, write_keeping_times};
use super::git_config_security_tests::git_fixture_failure;
use super::*;
use std::time::{Duration, SystemTime};

const OLD: Duration = Duration::from_secs(1_000_000_000);

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args([
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            "-c",
            "index.version=2",
        ])
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("spawn git {args:?}: {error}"));
    assert!(
        output.status.success(),
        "{}",
        git_fixture_failure(args, &output)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn set_mtime(path: &Path, time: SystemTime) {
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(time)
        .unwrap();
}

/// Builds a repository whose index entry for `edited.rs` is racily clean:
/// the worktree holds a same-size edit whose stat data matches the entry
/// exactly, while the entry still names the committed blob. Only Git's
/// racy-timestamp check (entry mtime not older than the index file) makes
/// it compare contents. This is the state a same-tick edit after
/// `git add` leaves behind, made deterministic.
fn racily_clean_repository(split_index: bool) -> tempfile::TempDir {
    let root = tempfile::Builder::new()
        .prefix("ryu-security-racy-")
        .tempdir()
        .unwrap();
    let path = root.path();
    git(path, &["init", "-q"]);
    let file = path.join("edited.rs");
    fs::write(&file, "fn before() {}\n").unwrap();
    git(path, &["add", "edited.rs"]);
    git(path, &["commit", "-q", "-m", "fixture"]);
    let committed = git(path, &["rev-parse", "HEAD:edited.rs"]);

    // Same size, old mtime; `git add` records the edited file's stat.
    fs::write(&file, "fn after_() {}\n").unwrap();
    let file_mtime = SystemTime::UNIX_EPOCH + OLD;
    set_mtime(&file, file_mtime);
    git(path, &["add", "edited.rs"]);

    // Point the entry back at the committed blob. The trailing checksum is
    // zeroed, which Git accepts on read (index.skipHash form).
    let index = path.join(".git/index");
    let mut bytes = fs::read(&index).unwrap();
    assert_eq!(&bytes[..4], b"DIRC");
    assert_eq!(u32::from_be_bytes(bytes[4..8].try_into().unwrap()), 2);
    assert_eq!(u32::from_be_bytes(bytes[8..12].try_into().unwrap()), 1);
    let blob: Vec<u8> = (0..committed.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&committed[at..at + 2], 16).unwrap())
        .collect();
    assert_eq!(blob.len(), 20);
    bytes[52..72].copy_from_slice(&blob);
    let checksum = bytes.len() - 20;
    bytes[checksum..].fill(0);
    fs::write(&index, bytes).unwrap();

    if split_index {
        git(path, &["update-index", "--split-index"]);
        let mut shared = 0;
        for entry in fs::read_dir(path.join(".git")).unwrap().flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with("sharedindex.")
            {
                set_mtime(&entry.path(), file_mtime);
                shared += 1;
            }
        }
        assert_eq!(shared, 1);
    }
    // The index is no newer than the entry, so it is racily clean.
    set_mtime(&index, file_mtime);
    // Positive control: Git itself, reading the real index, sees the edit.
    assert_eq!(
        git(path, &["diff", "--name-only", "HEAD", "--"]),
        "edited.rs"
    );
    root
}

fn changed(root: &Path) -> Vec<String> {
    collect_changed_files(&root.canonicalize().unwrap())
        .unwrap()
        .files
        .into_iter()
        .map(|file| file.relative_path)
        .collect()
}

#[test]
fn racily_clean_same_size_edit_is_reported() {
    let repository = racily_clean_repository(false);
    assert_eq!(changed(repository.path()), vec!["edited.rs"]);
}

#[test]
fn racily_clean_edit_is_reported_from_a_split_index() {
    let repository = racily_clean_repository(true);
    assert_eq!(changed(repository.path()), vec!["edited.rs"]);
}

#[test]
fn racily_clean_edit_is_reported_from_a_read_only_index() {
    let repository = racily_clean_repository(false);
    let index = repository.path().join(".git/index");
    let mut permissions = fs::metadata(&index).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&index, permissions).unwrap();
    assert_eq!(changed(repository.path()), vec!["edited.rs"]);
}

#[test]
fn index_copy_keeps_times_and_is_writable_from_a_read_only_source() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("index");
    fs::write(&source, b"DIRC index bytes").unwrap();
    let old = SystemTime::UNIX_EPOCH + OLD;
    set_mtime(&source, old);
    let mut permissions = fs::metadata(&source).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&source, permissions).unwrap();

    let (bytes, times) = read_keeping_times(&source, 1024).unwrap();
    let copy = temp.path().join("copy");
    write_keeping_times(&copy, &bytes, times).unwrap();

    let copied = fs::metadata(&copy).unwrap();
    assert_eq!(copied.modified().unwrap(), old);
    assert!(!copied.permissions().readonly());
    assert_eq!(fs::read(&copy).unwrap(), b"DIRC index bytes");
}
