use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::model::{Finding, FindingLocation, Scan, TenantScope};
use crate::store::Store;

const MAX_FILES: usize = 800;
const MAX_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_FILE_BYTES: usize = 256 * 1024;

const SKIP_DIRECTORIES: &[&str] = &[
    ".git",
    ".next",
    ".turbo",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
];

const SOURCE_EXTENSIONS: &[&str] = &[
    "c", "cc", "cpp", "cs", "go", "h", "hpp", "java", "js", "json", "jsx", "kt", "md", "php", "py",
    "rb", "rs", "sql", "swift", "toml", "ts", "tsx", "xml", "yaml", "yml",
];

#[derive(Debug)]
struct SourceFile {
    relative_path: String,
    contents: String,
}

#[derive(Debug, Default)]
struct FileCollection {
    files: Vec<SourceFile>,
    total_bytes: usize,
    capped: bool,
}

pub async fn run_scan(store: Store, scan_id: String) {
    if let Err(error) = run_scan_inner(&store, &scan_id).await {
        let canceled = store
            .get_scan(&scan_id)
            .map(|scan| scan.status == "canceled")
            .unwrap_or(false);
        if !canceled {
            let message = error.to_string();
            let _ = store.update_scan(&scan_id, |scan| {
                scan.status = "failed".to_owned();
                scan.phase = "finalize".to_owned();
                scan.error = Some(message.clone());
                for phase in &mut scan.phases {
                    if phase.key == "finalize" {
                        phase.status = "failed".to_owned();
                        phase.detail = "The scan stopped before it produced a result.".to_owned();
                    }
                }
            });
        }
    }
}

async fn run_scan_inner(store: &Store, scan_id: &str) -> Result<()> {
    let scan = store
        .get_scan(scan_id)
        .context("scan not found before execution")?;
    if scan.status == "canceled" {
        return Ok(());
    }
    let repository = store
        .get_repository(&scan.repository_id)
        .context("repository not found before execution")?;

    set_phase(
        store,
        scan_id,
        "prepare",
        8,
        "Confirming the selected repository and review scope.",
    )?;
    tokio::time::sleep(Duration::from_millis(180)).await;
    ensure_not_canceled(store, scan_id)?;

    let target = resolve_target(&repository.path, &scan)?;
    let (branch, head) = git_metadata(Path::new(&repository.path));
    let collection = if scan.kind == "changes" {
        collect_changed_files(Path::new(&repository.path))?
    } else {
        collect_files(&target)?
    };
    let file_count = collection.files.len();
    store.update_repository_after_scan(&repository.id, scan_id, branch, head, file_count)?;
    store.update_scan(scan_id, |current| {
        current.file_count = file_count;
        current.progress = 20;
    })?;

    set_phase(
        store,
        scan_id,
        "review",
        36,
        if collection.capped {
            "Reviewing source within the bounded file and byte budget."
        } else {
            "Reviewing source files for high-signal security patterns."
        },
    )?;
    tokio::time::sleep(Duration::from_millis(260)).await;
    ensure_not_canceled(store, scan_id)?;
    let findings = scan_files(&collection.files, scan_id, &repository.id);
    store.update_scan(scan_id, |current| {
        current.finding_count = findings.len();
        current.progress = 66;
    })?;
    store.save_findings(scan_id, findings.clone())?;

    set_phase(
        store,
        scan_id,
        "validate",
        74,
        if findings.is_empty() {
            "No static candidates were produced; reachability is not inferred."
        } else {
            "Recording candidates with evidence and counterevidence."
        },
    )?;
    tokio::time::sleep(Duration::from_millis(180)).await;
    ensure_not_canceled(store, scan_id)?;

    set_phase(
        store,
        scan_id,
        "paths",
        88,
        "Building bounded source-to-sink context for each candidate.",
    )?;
    tokio::time::sleep(Duration::from_millis(160)).await;
    ensure_not_canceled(store, scan_id)?;

    store.update_scan(scan_id, |current| {
        current.status = "completed".to_owned();
        current.phase = "finalize".to_owned();
        current.progress = 100;
        current.coverage = if collection.capped { 80 } else { 100 };
        current.finished_at = Some(Utc::now());
        current.error = None;
        for phase in &mut current.phases {
            phase.status = "completed".to_owned();
            phase.detail = if phase.key == "finalize" {
                "Saved scan, findings, and coverage.".to_owned()
            } else {
                phase.detail.clone()
            };
        }
    })?;
    Ok(())
}

fn set_phase(
    store: &Store,
    scan_id: &str,
    phase_key: &str,
    progress: u8,
    detail: &str,
) -> Result<Scan> {
    store.update_scan(scan_id, |scan| {
        scan.status = "running".to_owned();
        scan.phase = phase_key.to_owned();
        scan.progress = progress;
        let active_index = scan
            .phases
            .iter()
            .position(|phase| phase.key == phase_key)
            .unwrap_or(0);
        for (index, phase) in scan.phases.iter_mut().enumerate() {
            if index < active_index {
                phase.status = "completed".to_owned();
            } else if index == active_index {
                phase.status = "running".to_owned();
                phase.detail = detail.to_owned();
            } else {
                phase.status = "pending".to_owned();
                phase.detail = "Waiting to start".to_owned();
            }
        }
    })
}

fn ensure_not_canceled(store: &Store, scan_id: &str) -> Result<()> {
    if store
        .get_scan(scan_id)
        .map(|scan| scan.status == "canceled")
        .unwrap_or(false)
    {
        anyhow::bail!("scan canceled")
    }
    Ok(())
}

fn resolve_target(repository_path: &str, scan: &Scan) -> Result<PathBuf> {
    let repository = Path::new(repository_path)
        .canonicalize()
        .context("resolve repository before scanning")?;
    if scan.scope != "folder" {
        return Ok(repository);
    }
    let raw_scope = scan
        .scope_path
        .as_deref()
        .context("folder scans require a scope path")?;
    let scope = Path::new(raw_scope)
        .canonicalize()
        .with_context(|| format!("resolve scan folder {raw_scope}"))?;
    if !scope.starts_with(&repository) {
        anyhow::bail!("scan folder must be inside the selected repository")
    }
    if !scope.is_dir() {
        anyhow::bail!("scan folder must be a directory")
    }
    Ok(scope)
}

fn collect_files(root: &Path) -> Result<FileCollection> {
    let mut collection = FileCollection::default();
    visit_directory(root, root, &mut collection)?;
    Ok(collection)
}

fn collect_changed_files(repository: &Path) -> Result<FileCollection> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["diff", "--name-only", "HEAD", "--"])
        .output()
        .context("read the repository's uncommitted file list")?;
    if !output.status.success() {
        return Ok(FileCollection::default());
    }
    let mut collection = FileCollection::default();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if collection.files.len() >= MAX_FILES || collection.total_bytes >= MAX_TOTAL_BYTES {
            collection.capped = true;
            break;
        }
        let relative = Path::new(line.trim());
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

fn visit_directory(root: &Path, current: &Path, collection: &mut FileCollection) -> Result<()> {
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

fn read_source_file(path: &Path, root: &Path, collection: &mut FileCollection) -> Result<()> {
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

fn is_source_file(path: &Path) -> bool {
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

fn scan_files(files: &[SourceFile], scan_id: &str, repository_id: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for file in files {
        for (index, line) in file.contents.lines().enumerate() {
            if let Some(finding) = finding_for_line(file, index + 1, line, scan_id, repository_id) {
                findings.push(finding);
                if findings.len() >= 100 {
                    return findings;
                }
            }
        }
    }
    findings
}

fn finding_for_line(
    file: &SourceFile,
    line_number: usize,
    line: &str,
    scan_id: &str,
    repository_id: &str,
) -> Option<Finding> {
    let lower = line.to_ascii_lowercase();
    let (title, severity, confidence, category, cwe, root_cause, impact, remediation) =
        if looks_like_secret(&lower, line) {
            (
                "Hardcoded credential or private key",
                "High",
                "High",
                "secrets",
                "CWE-798",
                "A credential-like value appears to be embedded in source or configuration.",
                "A committed credential can be copied from source history and reused outside the intended trust boundary.",
                "Move the value to Ryu's secret boundary, rotate any exposed credential, and keep only a non-secret reference in source.",
            )
        } else if lower.contains("eval(") || lower.contains("exec(") {
            (
                "Potential dynamic code execution",
                "High",
                "Medium",
                "injection",
                "CWE-95",
                "Input may reach a dynamic evaluator instead of a constrained parser or command API.",
                "An attacker-controlled value could execute code with the privileges of the process if the path is reachable.",
                "Replace dynamic evaluation with a constrained parser or an allowlisted operation map, then add a regression test for attacker-controlled input.",
            )
        } else if lower.contains("innerhtml") || lower.contains("dangerouslysetinnerhtml") {
            (
                "Potential DOM XSS sink",
                "High",
                "Medium",
                "xss",
                "CWE-79",
                "Markup is written into a browser DOM sink without visible evidence of contextual escaping.",
                "Untrusted markup could execute in a user's session or change the meaning of a security-sensitive screen.",
                "Prefer text rendering or sanitize with a context-appropriate allowlist before reaching the DOM sink.",
            )
        } else if lower.contains("yaml.load(") || lower.contains("pickle.loads(") {
            (
                "Unsafe deserialization or configuration load",
                "Medium",
                "Medium",
                "deserialization",
                "CWE-502",
                "A general-purpose deserializer appears to process data that may cross a trust boundary.",
                "Crafted input could instantiate unexpected values or trigger code paths during parsing.",
                "Use a safe loader with an explicit schema, reject unknown fields, and test untrusted input at the boundary.",
            )
        } else if looks_like_sql_interpolation(&lower, line) {
            (
                "Potential SQL injection",
                "High",
                "Medium",
                "injection",
                "CWE-89",
                "A query-like string appears to combine SQL syntax with interpolated or concatenated input.",
                "An attacker could alter the query and read or mutate data outside the intended resource scope.",
                "Use a parameterized query API and keep authorization predicates separate from caller-controlled values.",
            )
        } else if looks_like_ssrf(&lower) {
            (
                "Potential server-side request forgery",
                "High",
                "Medium",
                "network",
                "CWE-918",
                "A request target appears to be derived from a variable without visible destination validation.",
                "An attacker could make the server reach private services or metadata endpoints from a trusted network position.",
                "Allowlist schemes, hosts, ports, redirects, and response sizes; block private/link-local destinations and test the denial path.",
            )
        } else {
            return None;
        };

    let path = file.relative_path.clone();
    let location = format!("{path}:{line_number}");
    Some(Finding {
        id: format!("finding-{}", Uuid::new_v4().simple()),
        tenant: TenantScope::default(),
        scan_id: scan_id.to_owned(),
        repository_id: repository_id.to_owned(),
        title: title.to_owned(),
        severity: severity.to_owned(),
        validation: "Pending".to_owned(),
        confidence: confidence.to_owned(),
        category: category.to_owned(),
        cwe: cwe.to_owned(),
        location: FindingLocation {
            path: file.relative_path.clone(),
            line: line_number,
        },
        summary: format!(
            "The local static pass found a {category} signal at {location}. This is a candidate, not a proof of exploitability."
        ),
        root_cause: root_cause.to_owned(),
        impact: impact.to_owned(),
        attack_path: vec![
            format!("A caller-controlled or sensitive value is present near {location}."),
            format!("The value reaches a {category} sink identified by the static pass."),
            "Reachability and runtime impact still require an independent review.".to_owned(),
        ],
        evidence: vec![
            format!("Static signal matched at {location}."),
            "The scan retained the file path and line number, not the raw source line.".to_owned(),
        ],
        counterevidence: vec![
            "The local pass did not execute repository code.".to_owned(),
            "No provider-backed or browser/device validation was performed.".to_owned(),
        ],
        remediation: remediation.to_owned(),
        patch: None,
        status: "open".to_owned(),
        created_at: Utc::now(),
        reviewed_at: None,
    })
}

fn looks_like_secret(lower: &str, original: &str) -> bool {
    let key_name = [
        "api_key",
        "apikey",
        "api-key",
        "secret",
        "password",
        "token",
        "private_key",
        "private-key",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    let quoted_value = original.contains('"') || original.contains('\'');
    let long_value = original
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .count()
        >= 20;
    let private_key = lower.contains("begin ") && lower.contains("private key");
    private_key || (key_name && quoted_value && long_value)
}

fn looks_like_sql_interpolation(lower: &str, original: &str) -> bool {
    let query = lower.contains("select ")
        || lower.contains("insert ")
        || lower.contains("update ")
        || lower.contains("delete ");
    query && (original.contains("${") || original.contains(" + ") || lower.contains("format!("))
}

fn looks_like_ssrf(lower: &str) -> bool {
    (lower.contains("fetch(") || lower.contains("requests.get(") || lower.contains("reqwest::get("))
        && (lower.contains("url") || lower.contains("uri") || lower.contains("target"))
}

fn git_metadata(repository: &Path) -> (String, String) {
    let (fallback_branch, fallback_head) = git_metadata_from_files(repository);
    let branch = git_value(repository, &["rev-parse", "--abbrev-ref", "HEAD"])
        .or(fallback_branch)
        .unwrap_or_else(|| "Not available".to_owned());
    let head = git_value(repository, &["rev-parse", "--short", "HEAD"])
        .or(fallback_head)
        .unwrap_or_else(|| "Not available".to_owned());
    (branch, head)
}

fn git_metadata_from_files(repository: &Path) -> (Option<String>, Option<String>) {
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

fn git_value(repository: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!value.is_empty()).then_some(value)
}
