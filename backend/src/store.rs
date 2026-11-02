use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::model::{
    initial_phases, Finding, NewScan, Repository, Scan, StoreState, TenantContext, TenantScope,
    SCHEMA_VERSION,
};
use crate::paths;

#[derive(Clone)]
pub struct Store {
    path: PathBuf,
    node_id: String,
    state: Arc<RwLock<StoreState>>,
}

impl Store {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create Security data directory {}", parent.display()))?;
        }

        let state = if path.exists() {
            let bytes = fs::read(&path)
                .with_context(|| format!("read Security state {}", path.display()))?;
            let mut state: StoreState = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse Security state {}", path.display()))?;
            if state.schema_version > SCHEMA_VERSION {
                anyhow::bail!(
                    "Security state schema {} is newer than this sidecar supports ({SCHEMA_VERSION})",
                    state.schema_version
                );
            }
            state.schema_version = SCHEMA_VERSION;
            state
        } else {
            StoreState::default()
        };

        let node_id = paths::node_id_for_state_path(&path);
        let store = Self {
            path,
            node_id,
            state: Arc::new(RwLock::new(state)),
        };
        if !store.path.exists() {
            store.persist()?;
        }
        Ok(store)
    }

    pub fn snapshot(&self) -> StoreState {
        self.state
            .read()
            .expect("Security store read lock poisoned")
            .clone()
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn snapshot_for(&self, context: &TenantContext) -> StoreState {
        let state = self.snapshot();
        if context.node_id != self.node_id {
            return StoreState {
                schema_version: state.schema_version,
                ..StoreState::default()
            };
        }

        StoreState {
            schema_version: state.schema_version,
            repositories: state
                .repositories
                .into_iter()
                .filter(|repository| repository.tenant.matches(context))
                .collect(),
            scans: state
                .scans
                .into_iter()
                .filter(|scan| scan.tenant.matches(context))
                .collect(),
            findings: state
                .findings
                .into_iter()
                .filter(|finding| finding.tenant.matches(context))
                .collect(),
        }
    }

    pub fn replace_state(&self, mut state: StoreState) -> Result<()> {
        state.schema_version = SCHEMA_VERSION;
        let mut current = self
            .state
            .write()
            .expect("Security store write lock poisoned");
        *current = state;
        self.persist_state(&current)
    }

    pub fn get_repository(&self, id: &str) -> Option<Repository> {
        self.snapshot()
            .repositories
            .into_iter()
            .find(|repository| repository.id == id)
    }

    pub fn get_repository_for(&self, context: &TenantContext, id: &str) -> Option<Repository> {
        (context.node_id == self.node_id).then(|| {
            self.snapshot()
                .repositories
                .into_iter()
                .find(|repository| repository.id == id && repository.tenant.matches(context))
        })?
    }

    pub fn get_scan(&self, id: &str) -> Option<Scan> {
        self.snapshot().scans.into_iter().find(|scan| scan.id == id)
    }

    pub fn get_scan_for(&self, context: &TenantContext, id: &str) -> Option<Scan> {
        (context.node_id == self.node_id).then(|| {
            self.snapshot()
                .scans
                .into_iter()
                .find(|scan| scan.id == id && scan.tenant.matches(context))
        })?
    }

    pub fn get_finding(&self, id: &str) -> Option<Finding> {
        self.snapshot()
            .findings
            .into_iter()
            .find(|finding| finding.id == id)
    }

    pub fn get_finding_for(&self, context: &TenantContext, id: &str) -> Option<Finding> {
        (context.node_id == self.node_id).then(|| {
            self.snapshot()
                .findings
                .into_iter()
                .find(|finding| finding.id == id && finding.tenant.matches(context))
        })?
    }

    pub fn findings_for_scan(&self, scan_id: &str) -> Vec<Finding> {
        self.snapshot()
            .findings
            .into_iter()
            .filter(|finding| finding.scan_id == scan_id)
            .collect()
    }

    pub fn findings_for_scan_for(&self, context: &TenantContext, scan_id: &str) -> Vec<Finding> {
        if context.node_id != self.node_id {
            return Vec::new();
        }
        self.snapshot()
            .findings
            .into_iter()
            .filter(|finding| finding.scan_id == scan_id && finding.tenant.matches(context))
            .collect()
    }

    pub fn ensure_repository(&self, context: &TenantContext, raw_path: &str) -> Result<Repository> {
        let tenant = self.tenant_scope(context)?;
        let path = canonical_repository_path(raw_path)?;
        let path_string = path.to_string_lossy().into_owned();
        let mut state = self
            .state
            .write()
            .expect("Security store write lock poisoned");

        if let Some(repository) = state
            .repositories
            .iter()
            .find(|repository| repository.path == path_string && repository.tenant == tenant)
            .cloned()
        {
            return Ok(repository);
        }

        let now = Utc::now();
        let repository = Repository {
            id: format!("repo-{}", Uuid::new_v4().simple()),
            tenant,
            name: path
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| !name.trim().is_empty())
                .unwrap_or("Repository")
                .to_owned(),
            path: path_string,
            branch: "Not scanned".to_owned(),
            head: "Not scanned".to_owned(),
            file_count: 0,
            finding_count: 0,
            scan_count: 0,
            last_scan_id: None,
            last_scanned_at: None,
            status: "ready".to_owned(),
            created_at: now,
        };
        state.repositories.insert(0, repository.clone());
        self.persist_state(&state)?;
        Ok(repository)
    }

    pub fn create_scan(&self, context: &TenantContext, input: NewScan) -> Result<Scan> {
        let tenant = self.tenant_scope(context)?;
        let NewScan {
            additional_context,
            deep,
            kind,
            model,
            name,
            reasoning_effort,
            repository_id,
            scope,
            scope_path,
        } = input;
        let mut state = self
            .state
            .write()
            .expect("Security store write lock poisoned");
        let repository = state
            .repositories
            .iter()
            .find(|repository| repository.id == repository_id && repository.tenant == tenant)
            .context("repository not found")?;

        let normalized_kind = if kind.trim().eq_ignore_ascii_case("changes") {
            "changes"
        } else {
            "codebase"
        };
        let normalized_scope = if scope.trim().eq_ignore_ascii_case("folder") {
            "folder"
        } else {
            "entire"
        };
        if normalized_kind == "changes" && deep {
            anyhow::bail!("deep scans are not supported for changes reviews");
        }

        let scan_name = if name.trim().is_empty() {
            format!(
                "{} · {}",
                repository.name,
                if normalized_kind == "changes" {
                    "Changes review"
                } else if deep {
                    "Deep scan"
                } else {
                    "Standard scan"
                }
            )
        } else {
            name.trim().to_owned()
        };
        let scan = Scan {
            id: format!("scan-{}", Uuid::new_v4().simple()),
            tenant,
            repository_id: repository_id.clone(),
            name: scan_name,
            kind: normalized_kind.to_owned(),
            scope: normalized_scope.to_owned(),
            scope_path: scope_path
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty()),
            deep,
            model: if model.trim().is_empty() {
                "Ryu local static pass".to_owned()
            } else {
                model.trim().to_owned()
            },
            reasoning_effort: if reasoning_effort.trim().is_empty() {
                "balanced".to_owned()
            } else {
                reasoning_effort.trim().to_owned()
            },
            additional_context,
            status: "pending".to_owned(),
            phase: "prepare".to_owned(),
            progress: 0,
            file_count: 0,
            finding_count: 0,
            coverage: 0,
            evidence_level: "static-local".to_owned(),
            phases: initial_phases(),
            started_at: Utc::now(),
            finished_at: None,
            error: None,
        };
        state.scans.insert(0, scan.clone());
        self.persist_state(&state)?;
        Ok(scan)
    }

    pub fn update_scan_for<F>(
        &self,
        context: &TenantContext,
        scan_id: &str,
        update: F,
    ) -> Result<Scan>
    where
        F: FnOnce(&mut Scan),
    {
        self.tenant_scope(context)?;
        let mut state = self
            .state
            .write()
            .expect("Security store write lock poisoned");
        let scan = state
            .scans
            .iter_mut()
            .find(|scan| scan.id == scan_id && scan.tenant.matches(context))
            .context("scan not found")?;
        update(scan);
        let updated = scan.clone();
        self.persist_state(&state)?;
        Ok(updated)
    }

    pub fn update_scan<F>(&self, scan_id: &str, update: F) -> Result<Scan>
    where
        F: FnOnce(&mut Scan),
    {
        let mut state = self
            .state
            .write()
            .expect("Security store write lock poisoned");
        let scan = state
            .scans
            .iter_mut()
            .find(|scan| scan.id == scan_id)
            .context("scan not found")?;
        update(scan);
        let updated = scan.clone();
        self.persist_state(&state)?;
        Ok(updated)
    }

    pub fn save_findings(&self, scan_id: &str, findings: Vec<Finding>) -> Result<()> {
        let mut state = self
            .state
            .write()
            .expect("Security store write lock poisoned");
        let scan = state
            .scans
            .iter_mut()
            .find(|scan| scan.id == scan_id)
            .context("scan not found")?;
        let repository_id = scan.repository_id.clone();
        let tenant = scan.tenant.clone();
        state.findings.retain(|finding| finding.scan_id != scan_id);
        let mut findings = findings;
        for finding in &mut findings {
            finding.scan_id = scan_id.to_owned();
            finding.repository_id = repository_id.clone();
            finding.tenant = tenant.clone();
        }
        state.findings.splice(0..0, findings);
        let finding_count = state
            .findings
            .iter()
            .filter(|finding| finding.repository_id == repository_id && finding.tenant == tenant)
            .count();
        if let Some(repository) = state
            .repositories
            .iter_mut()
            .find(|repository| repository.id == repository_id)
        {
            repository.finding_count = finding_count;
        }
        self.persist_state(&state)
    }

    pub fn update_repository_after_scan(
        &self,
        repository_id: &str,
        scan_id: &str,
        branch: String,
        head: String,
        file_count: usize,
    ) -> Result<()> {
        let mut state = self
            .state
            .write()
            .expect("Security store write lock poisoned");
        let repository = state
            .repositories
            .iter_mut()
            .find(|repository| repository.id == repository_id)
            .context("repository not found")?;
        repository.branch = branch;
        repository.head = head;
        repository.file_count = file_count;
        repository.scan_count = repository.scan_count.saturating_add(1);
        repository.last_scan_id = Some(scan_id.to_owned());
        repository.last_scanned_at = Some(Utc::now());
        repository.status = "scanned".to_owned();
        self.persist_state(&state)
    }

    pub fn update_finding_status_for(
        &self,
        context: &TenantContext,
        finding_id: &str,
        status: &str,
    ) -> Result<Finding> {
        self.tenant_scope(context)?;
        let normalized = match status.trim().to_ascii_lowercase().as_str() {
            "accepted" => "accepted",
            "false_positive" | "false-positive" => "false_positive",
            "closed" => "closed",
            _ => "open",
        };
        let mut state = self
            .state
            .write()
            .expect("Security store write lock poisoned");
        let finding = state
            .findings
            .iter_mut()
            .find(|finding| finding.id == finding_id && finding.tenant.matches(context))
            .context("finding not found")?;
        finding.status = normalized.to_owned();
        finding.reviewed_at = Some(Utc::now());
        let updated = finding.clone();
        self.persist_state(&state)?;
        Ok(updated)
    }

    pub fn set_finding_patch_for(
        &self,
        context: &TenantContext,
        finding_id: &str,
        patch: String,
    ) -> Result<Finding> {
        self.tenant_scope(context)?;
        let mut state = self
            .state
            .write()
            .expect("Security store write lock poisoned");
        let finding = state
            .findings
            .iter_mut()
            .find(|finding| finding.id == finding_id && finding.tenant.matches(context))
            .context("finding not found")?;
        finding.patch = Some(patch);
        let updated = finding.clone();
        self.persist_state(&state)?;
        Ok(updated)
    }

    fn tenant_scope(&self, context: &TenantContext) -> Result<TenantScope> {
        if context.node_id != self.node_id {
            anyhow::bail!("tenant node does not match the Security store node");
        }
        Ok(TenantScope::from_context(context))
    }

    fn persist(&self) -> Result<()> {
        let state = self
            .state
            .read()
            .expect("Security store read lock poisoned");
        self.persist_state(&state)
    }

    fn persist_state(&self, state: &StoreState) -> Result<()> {
        let temporary = self.path.with_extension("json.tmp");
        let payload = serde_json::to_vec_pretty(state).context("serialize Security state")?;
        fs::write(&temporary, payload)
            .with_context(|| format!("write Security state {}", temporary.display()))?;
        fs::rename(&temporary, &self.path)
            .with_context(|| format!("replace Security state {}", self.path.display()))?;
        Ok(())
    }
}

fn canonical_repository_path(raw_path: &str) -> Result<PathBuf> {
    let path = Path::new(raw_path.trim());
    if !path.is_absolute() {
        anyhow::bail!("repository path must be absolute");
    }
    let canonical = path
        .canonicalize()
        .with_context(|| format!("resolve repository path {}", path.display()))?;
    if !canonical.is_dir() {
        anyhow::bail!("repository path must be a directory");
    }
    Ok(canonical)
}
