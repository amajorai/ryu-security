use std::path::{Path, PathBuf};

pub const STATE_FILE_NAME: &str = "security.json";
const NODE_ID_ENV: &str = "RYU_NODE_ID";
const MANAGED_NODE_ENV: &str = "RYU_MANAGED_NODE";

pub fn ryu_dir() -> PathBuf {
    ryu_sidecar_runtime::ryu_dir()
}

pub fn state_path() -> PathBuf {
    ryu_dir().join(STATE_FILE_NAME)
}

/// Resolve the node identity from server-owned process wiring. Local nodes use
/// their data directory so two local stores cannot accidentally share records;
/// managed deployments may provide the stable control-plane node id.
pub fn node_id_for_state_path(state_path: &Path) -> String {
    if let Some(value) = std::env::var(NODE_ID_ENV)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
    {
        return value;
    }

    let data_dir = state_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()
        .unwrap_or_else(|_| {
            state_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf()
        });
    format!("local:{}", data_dir.display())
}

/// Match Core's managed-node truthy values so an unresolved managed process
/// cannot fall back to the anonymous local tenant.
pub fn is_managed_node() -> bool {
    std::env::var(MANAGED_NODE_ENV).ok().is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes"
        )
    })
}
