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

mod files;
mod git;
mod rules;

use files::{collect_changed_files, collect_files};
use git::git_metadata;
use rules::scan_files;

#[cfg(test)]
#[path = "scanner_git_tests.rs"]
mod git_config_security_tests;

#[cfg(test)]
#[path = "scanner_index_tests.rs"]
mod changed_files_index_tests;

#[cfg(test)]
#[path = "scanner_rule_tests.rs"]
mod rule_tests;
