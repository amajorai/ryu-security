use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 2;

/// The verified caller context attached by Core plus the server-owned node
/// identity for the sidecar store. None of the fields come from a request body
/// or a caller-controlled tenant selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantContext {
    pub owner_user_id: Option<String>,
    pub org_id: Option<String>,
    pub node_id: String,
}

impl TenantContext {
    pub fn local(node_id: impl Into<String>) -> Self {
        Self {
            owner_user_id: None,
            org_id: None,
            node_id: node_id.into(),
        }
    }
}

/// Persisted tenancy metadata. Missing metadata represents legacy ownerless
/// state and deliberately does not match any request tenant.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantScope {
    #[serde(default)]
    pub owner_user_id: Option<String>,
    #[serde(default)]
    pub org_id: Option<String>,
    #[serde(default)]
    pub node_id: Option<String>,
}

impl TenantScope {
    pub fn from_context(context: &TenantContext) -> Self {
        Self {
            owner_user_id: context.owner_user_id.clone(),
            org_id: context.org_id.clone(),
            node_id: Some(context.node_id.clone()),
        }
    }

    pub fn matches(&self, context: &TenantContext) -> bool {
        self.node_id.as_deref() == Some(context.node_id.as_str())
            && self.owner_user_id == context.owner_user_id
            && self.org_id == context.org_id
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Repository {
    pub id: String,
    #[serde(default)]
    pub tenant: TenantScope,
    pub name: String,
    pub path: String,
    pub branch: String,
    pub head: String,
    pub file_count: usize,
    pub finding_count: usize,
    #[serde(default)]
    pub scan_count: usize,
    #[serde(default)]
    pub last_scan_id: Option<String>,
    #[serde(default)]
    pub last_scanned_at: Option<DateTime<Utc>>,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanPhase {
    pub key: String,
    pub label: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Scan {
    pub id: String,
    #[serde(default)]
    pub tenant: TenantScope,
    pub repository_id: String,
    pub name: String,
    pub kind: String,
    pub scope: String,
    #[serde(default)]
    pub scope_path: Option<String>,
    pub deep: bool,
    pub model: String,
    pub reasoning_effort: String,
    #[serde(default)]
    pub additional_context: AdditionalContext,
    pub status: String,
    pub phase: String,
    pub progress: u8,
    pub file_count: usize,
    pub finding_count: usize,
    pub coverage: u8,
    pub evidence_level: String,
    pub phases: Vec<ScanPhase>,
    pub started_at: DateTime<Utc>,
    #[serde(default)]
    pub finished_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdditionalContext {
    #[serde(default)]
    pub attack_vectors: String,
    #[serde(default)]
    pub focus_areas: String,
    #[serde(default)]
    pub security_context: String,
}

#[derive(Debug, Clone)]
pub struct NewScan {
    pub additional_context: AdditionalContext,
    pub deep: bool,
    pub kind: String,
    pub model: String,
    pub name: String,
    pub reasoning_effort: String,
    pub repository_id: String,
    pub scope: String,
    pub scope_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    #[serde(default)]
    pub tenant: TenantScope,
    pub scan_id: String,
    pub repository_id: String,
    pub title: String,
    pub severity: String,
    pub validation: String,
    pub confidence: String,
    pub category: String,
    pub cwe: String,
    pub location: FindingLocation,
    pub summary: String,
    pub root_cause: String,
    pub impact: String,
    pub attack_path: Vec<String>,
    pub evidence: Vec<String>,
    pub counterevidence: Vec<String>,
    pub remediation: String,
    #[serde(default)]
    pub patch: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub reviewed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingLocation {
    pub path: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    pub evidence_level: String,
    pub network_access: bool,
    pub agent_verification: bool,
    pub patch_application: bool,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            evidence_level: "static-local".to_owned(),
            network_access: false,
            agent_verification: false,
            patch_application: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreState {
    pub schema_version: u32,
    #[serde(default)]
    pub repositories: Vec<Repository>,
    #[serde(default)]
    pub scans: Vec<Scan>,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

impl Default for StoreState {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            repositories: Vec::new(),
            scans: Vec::new(),
            findings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapResponse {
    pub repositories: Vec<Repository>,
    pub scans: Vec<Scan>,
    pub findings: Vec<Finding>,
    pub capabilities: Capabilities,
}

impl From<StoreState> for BootstrapResponse {
    fn from(state: StoreState) -> Self {
        Self {
            repositories: state.repositories,
            scans: state.scans,
            findings: state.findings,
            capabilities: Capabilities::default(),
        }
    }
}

pub fn initial_phases() -> Vec<ScanPhase> {
    [
        ("prepare", "Preparing scan"),
        ("review", "Reviewing code"),
        ("validate", "Validating findings"),
        ("paths", "Tracing attack paths"),
        ("finalize", "Finalizing scan"),
    ]
    .into_iter()
    .map(|(key, label)| ScanPhase {
        key: key.to_owned(),
        label: label.to_owned(),
        status: "pending".to_owned(),
        detail: "Waiting to start".to_owned(),
    })
    .collect()
}
