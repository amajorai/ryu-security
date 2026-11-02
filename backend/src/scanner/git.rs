//! Read-only Git invocation and repository metadata lookups.

use super::*;

pub(super) fn git_metadata(repository: &Path) -> (String, String) {
    let (fallback_branch, fallback_head) = git_metadata_from_files(repository);
    let branch = git_value(repository, &["rev-parse", "--abbrev-ref", "HEAD"])
        .or(fallback_branch)
        .unwrap_or_else(|| "Not available".to_owned());
    let head = git_value(repository, &["rev-parse", "--short", "HEAD"])
        .or(fallback_head)
        .unwrap_or_else(|| "Not available".to_owned());
    (branch, head)
}

pub(super) fn git_metadata_from_files(repository: &Path) -> (Option<String>, Option<String>) {
    let git_dir = repository.join(".git");
    let git_dir = if git_dir.is_dir() {
        git_dir
    } else {
        let pointer = match fs::read_to_string(&git_dir) {
            Ok(pointer) => pointer,
            Err(_) => return (None, None),
        };
        let Some(raw) = pointer.trim().strip_prefix("gitdir:").map(str::trim) else {
            return (None, None);
        };
        let path = Path::new(raw);
        if path.is_absolute() {
            path.to_owned()
        } else {
            repository.join(path)
        }
    };
    let Ok(head) = fs::read_to_string(git_dir.join("HEAD")) else {
        return (None, None);
    };
    let Some(reference) = head.trim().strip_prefix("ref: ").map(str::to_owned) else {
        return (None, None);
    };
    let branch = reference.strip_prefix("refs/heads/").map(str::to_owned);
    let commit_path = git_dir.join(&reference);
    let commit = fs::read_to_string(commit_path)
        .ok()
        .map(|value| value.trim().chars().take(9).collect::<String>());
    (branch, commit)
}

pub(super) fn git_environment_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    if cfg!(windows) {
        let path = if let Some(unc) = raw.strip_prefix("\\\\?\\UNC\\") {
            format!("//{unc}")
        } else {
            raw.strip_prefix("\\\\?\\").unwrap_or(&raw).to_owned()
        };
        path.replace('\\', "/")
    } else {
        raw.into_owned()
    }
}

pub(super) fn read_only_git(repository: &Path) -> Command {
    let mut command = Command::new("git");
    command.env_clear();
    // Preserve only OS execution wiring, never inherited Git overrides/tokens.
    for key in ["PATH", "SystemRoot", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.longpaths=true",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .arg("-C")
        .arg(repository);
    command
}

pub(super) fn git_value(repository: &Path, args: &[&str]) -> Option<String> {
    let output = read_only_git(repository).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!value.is_empty()).then_some(value)
}
