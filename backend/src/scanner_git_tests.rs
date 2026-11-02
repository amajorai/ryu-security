//! Proves the changes scan never executes repository-configured Git commands
//! (fsmonitor, clean and process filters). A child module of `scanner`.

use super::git::git_value;
use super::*;

/// Everything needed to diagnose a fixture Git call that failed on one host
/// only: the arguments, the exit status, and both output streams.
pub(super) fn git_fixture_failure(args: &[&str], output: &std::process::Output) -> String {
    format!(
        "git {args:?} failed with {status}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        status = output.status,
        stdout = String::from_utf8_lossy(&output.stdout),
        stderr = String::from_utf8_lossy(&output.stderr),
    )
}

#[test]
fn changes_scan_never_executes_repository_fsmonitor() {
    let root = std::env::temp_dir().join(format!("ryu-security-git-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(args)
            .output()
            .unwrap_or_else(|error| panic!("spawn git {args:?}: {error}"));
        assert!(
            output.status.success(),
            "{}",
            git_fixture_failure(args, &output)
        );
    };
    git(&["init"]);
    fs::write(root.join("fixture.rs"), "fn before() {}\n").unwrap();
    fs::write(root.join("naïve.rs"), "fn before() {}\n").unwrap();
    git(&["add", "fixture.rs", "naïve.rs"]);
    git(&[
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-m",
        "fixture",
    ]);
    fs::write(root.join("fixture.rs"), "fn after() {}\n").unwrap();
    fs::write(root.join("naïve.rs"), "fn after() {}\n").unwrap();
    let marker = root.join("executed");
    let script = root.join(".git/monitor.sh");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf marker > '{}'\n",
            marker.to_string_lossy().replace('\\', "/")
        ),
    )
    .unwrap();
    let hook = format!("sh '{}'", script.to_string_lossy().replace('\\', "/"));
    git(&["config", "core.fsmonitor", &hook]);
    // Positive control proves the configured hook is executable on this host.
    git(&["diff", "--name-only", "HEAD", "--"]);
    assert!(marker.exists());
    fs::remove_file(&marker).unwrap();
    // A clean filter is a separate executable sink during index refresh.
    git(&["config", "core.fsmonitor", "false"]);
    git(&["config", "filter.fixture.clean", &hook]);
    fs::write(root.join(".gitattributes"), "*.rs filter=fixture\n").unwrap();
    git(&[
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--name-only",
        "HEAD",
        "--",
    ]);
    assert!(marker.exists());
    fs::remove_file(&marker).unwrap();
    // The private metadata projection must preserve ordinary split indexes.
    git(&[
        "-c",
        "core.fsmonitor=false",
        "-c",
        "filter.fixture.clean=",
        "update-index",
        "--split-index",
    ]);
    git(&["config", "filter.fixture.process", &hook]);
    // A process filter need not complete its protocol to execute a command.
    let _ = Command::new("git")
        .arg("-C")
        .arg(&root)
        .args(["diff", "--name-only", "HEAD", "--"])
        .output()
        .unwrap();
    assert!(marker.exists());
    fs::remove_file(&marker).unwrap();
    git(&["config", "core.fsmonitor", &hook]);
    let collection = collect_changed_files(&root.canonicalize().unwrap()).unwrap();
    assert_eq!(collection.files.len(), 2);
    assert!(collection
        .files
        .iter()
        .any(|file| file.relative_path == "naïve.rs"));
    assert!(collection.files[0].contents.contains("after"));
    assert!(git_value(&root, &["rev-parse", "HEAD"]).is_some());
    assert!(!marker.exists());
    fs::remove_dir_all(&root).unwrap();
}
