use std::sync::Arc;

use axum::extract::{Extension, Path, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{from_fn, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::model::{
    AdditionalContext, BootstrapResponse, Finding, NewScan, Repository, Scan, TenantContext,
};
use crate::paths;
use crate::scanner;
use crate::store::Store;

pub struct Ctx {
    pub store: Store,
}

pub const CALLER_USER_ID_HEADER: &str = "x-ryu-caller-user-id";
pub const CALLER_ORG_ID_HEADER: &str = "x-ryu-caller-org-id";

/// Core strips caller-controlled copies and stamps these values after verifying
/// the user identity. The node id is supplied by this sidecar's own Store and
/// can never be selected by the request.
pub fn tenant_from_headers(
    headers: &HeaderMap,
    node_id: &str,
    managed_node: bool,
) -> Result<TenantContext, StatusCode> {
    let owner_user_id = server_header(headers, CALLER_USER_ID_HEADER)?;
    let org_id = server_header(headers, CALLER_ORG_ID_HEADER)?;
    if org_id.is_some() && owner_user_id.is_none() {
        return Err(StatusCode::FORBIDDEN);
    }
    if owner_user_id.is_none() && managed_node {
        return Err(StatusCode::FORBIDDEN);
    }
    if node_id.trim().is_empty() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    Ok(TenantContext {
        owner_user_id,
        org_id,
        node_id: node_id.to_owned(),
    })
}

fn server_header(headers: &HeaderMap, name: &str) -> Result<Option<String>, StatusCode> {
    let Some(value) = headers.get(name) else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| StatusCode::FORBIDDEN)?.trim();
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(Some(value.to_owned()))
}

async fn attach_tenant(
    mut request: Request,
    next: Next,
    node_id: &str,
    managed_node: bool,
) -> Response {
    let tenant = match tenant_from_headers(request.headers(), node_id, managed_node) {
        Ok(tenant) => tenant,
        Err(status) => return status.into_response(),
    };
    request.extensions_mut().insert(tenant);
    next.run(request).await
}

pub fn routes(ctx: Arc<Ctx>) -> Router {
    let node_id = ctx.store.node_id().to_owned();
    let managed_node = paths::is_managed_node();
    Router::new()
        .route("/bootstrap", get(bootstrap))
        .route("/repositories", get(repositories).post(create_repository))
        .route("/repositories/:id", get(repository))
        .route("/scans", get(scans).post(create_scan))
        .route("/scans/:id", get(scan))
        .route("/scans/:id/cancel", post(cancel_scan))
        .route("/findings", get(findings))
        .route("/findings/:id", get(finding))
        .route("/findings/:id/status", post(update_finding_status))
        .route("/findings/:id/patch", post(generate_patch))
        .with_state(ctx)
        .layer(from_fn(move |request: Request, next: Next| {
            let node_id = node_id.clone();
            async move { attach_tenant(request, next, &node_id, managed_node).await }
        }))
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn bad(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: message.into(),
        }
    }

    fn internal(error: impl std::fmt::Display) -> Self {
        tracing::warn!("Security API error: {error}");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "server_error",
            message: "Security could not complete that request.".to_owned(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "error": { "code": self.code, "message": self.message }
            })),
        )
            .into_response()
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

async fn bootstrap(
    State(ctx): State<Arc<Ctx>>,
    Extension(tenant): Extension<TenantContext>,
) -> ApiResult<BootstrapResponse> {
    Ok(Json(BootstrapResponse::from(
        ctx.store.snapshot_for(&tenant),
    )))
}

async fn repositories(
    State(ctx): State<Arc<Ctx>>,
    Extension(tenant): Extension<TenantContext>,
) -> ApiResult<Value> {
    Ok(Json(json!({
        "repositories": ctx.store.snapshot_for(&tenant).repositories
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateRepositoryRequest {
    path: String,
}

async fn create_repository(
    State(ctx): State<Arc<Ctx>>,
    Extension(tenant): Extension<TenantContext>,
    Json(input): Json<CreateRepositoryRequest>,
) -> ApiResult<Repository> {
    if input.path.trim().is_empty() {
        return Err(ApiError::bad("an absolute repository path is required"));
    }
    ctx.store
        .ensure_repository(&tenant, &input.path)
        .map(Json)
        .map_err(|error| ApiError::bad(error.to_string()))
}

async fn repository(
    State(ctx): State<Arc<Ctx>>,
    Extension(tenant): Extension<TenantContext>,
    Path(id): Path<String>,
) -> ApiResult<Value> {
    let repository = ctx
        .store
        .get_repository_for(&tenant, &id)
        .ok_or_else(|| ApiError::not_found("repository not found"))?;
    let state = ctx.store.snapshot_for(&tenant);
    let scans = state
        .scans
        .into_iter()
        .filter(|scan| scan.repository_id == id)
        .collect::<Vec<_>>();
    let findings = state
        .findings
        .into_iter()
        .filter(|finding| finding.repository_id == id)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "repository": repository,
        "scans": scans,
        "findings": findings
    })))
}

async fn scans(
    State(ctx): State<Arc<Ctx>>,
    Extension(tenant): Extension<TenantContext>,
) -> ApiResult<Value> {
    Ok(Json(
        json!({ "scans": ctx.store.snapshot_for(&tenant).scans }),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateScanRequest {
    #[serde(default)]
    name: String,
    #[serde(default)]
    repository_id: Option<String>,
    #[serde(default)]
    repository_path: Option<String>,
    #[serde(default = "default_kind")]
    kind: String,
    #[serde(default = "default_scope")]
    scope: String,
    #[serde(default)]
    scope_path: Option<String>,
    #[serde(default)]
    deep: bool,
    #[serde(default)]
    model: String,
    #[serde(default)]
    reasoning_effort: String,
    #[serde(default)]
    additional_context: AdditionalContext,
}

fn default_kind() -> String {
    "codebase".to_owned()
}

fn default_scope() -> String {
    "entire".to_owned()
}

async fn create_scan(
    State(ctx): State<Arc<Ctx>>,
    Extension(tenant): Extension<TenantContext>,
    Json(input): Json<CreateScanRequest>,
) -> ApiResult<Scan> {
    let repository_id = match (input.repository_id, input.repository_path) {
        (Some(id), _) if !id.trim().is_empty() => id,
        (_, Some(path)) => ctx
            .store
            .ensure_repository(&tenant, &path)
            .map(|repository| repository.id)
            .map_err(|error| ApiError::bad(error.to_string()))?,
        _ => return Err(ApiError::bad("a repository or absolute path is required")),
    };
    if ctx
        .store
        .get_repository_for(&tenant, &repository_id)
        .is_none()
    {
        return Err(ApiError::not_found("repository not found"));
    }
    let scan = ctx
        .store
        .create_scan(
            &tenant,
            NewScan {
                additional_context: input.additional_context,
                deep: input.deep,
                kind: input.kind,
                model: input.model,
                name: input.name,
                reasoning_effort: input.reasoning_effort,
                repository_id,
                scope: input.scope,
                scope_path: input.scope_path,
            },
        )
        .map_err(|error| {
            if error.to_string().contains("deep scans") {
                ApiError::bad(error.to_string())
            } else {
                ApiError::internal(error)
            }
        })?;
    let store = ctx.store.clone();
    let scan_id = scan.id.clone();
    tokio::spawn(async move {
        scanner::run_scan(store, scan_id).await;
    });
    Ok(Json(scan))
}

async fn scan(
    State(ctx): State<Arc<Ctx>>,
    Extension(tenant): Extension<TenantContext>,
    Path(id): Path<String>,
) -> ApiResult<Value> {
    let scan = ctx
        .store
        .get_scan_for(&tenant, &id)
        .ok_or_else(|| ApiError::not_found("scan not found"))?;
    let repository = ctx.store.get_repository_for(&tenant, &scan.repository_id);
    let findings = ctx.store.findings_for_scan_for(&tenant, &id);
    Ok(Json(json!({
        "scan": scan,
        "repository": repository,
        "findings": findings
    })))
}

async fn cancel_scan(
    State(ctx): State<Arc<Ctx>>,
    Extension(tenant): Extension<TenantContext>,
    Path(id): Path<String>,
) -> ApiResult<Scan> {
    let updated = ctx
        .store
        .update_scan_for(&tenant, &id, |scan| {
            if scan.status == "pending" || scan.status == "running" {
                scan.status = "canceled".to_owned();
                scan.phase = "finalize".to_owned();
                scan.error = Some("Stopped by the reviewer.".to_owned());
                for phase in &mut scan.phases {
                    if phase.status == "running" {
                        phase.status = "canceled".to_owned();
                        phase.detail = "Stopped by the reviewer.".to_owned();
                    }
                }
            }
        })
        .map_err(|error| {
            if error.to_string().contains("not found") {
                ApiError::not_found(error.to_string())
            } else {
                ApiError::internal(error)
            }
        })?;
    Ok(Json(updated))
}

async fn findings(
    State(ctx): State<Arc<Ctx>>,
    Extension(tenant): Extension<TenantContext>,
) -> ApiResult<Value> {
    Ok(Json(
        json!({ "findings": ctx.store.snapshot_for(&tenant).findings }),
    ))
}

async fn finding(
    State(ctx): State<Arc<Ctx>>,
    Extension(tenant): Extension<TenantContext>,
    Path(id): Path<String>,
) -> ApiResult<Finding> {
    ctx.store
        .get_finding_for(&tenant, &id)
        .map(Json)
        .ok_or_else(|| ApiError::not_found("finding not found"))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FindingStatusRequest {
    status: String,
}

async fn update_finding_status(
    State(ctx): State<Arc<Ctx>>,
    Extension(tenant): Extension<TenantContext>,
    Path(id): Path<String>,
    Json(input): Json<FindingStatusRequest>,
) -> ApiResult<Finding> {
    ctx.store
        .update_finding_status_for(&tenant, &id, &input.status)
        .map(Json)
        .map_err(|error| {
            if error.to_string().contains("not found") {
                ApiError::not_found(error.to_string())
            } else {
                ApiError::internal(error)
            }
        })
}

async fn generate_patch(
    State(ctx): State<Arc<Ctx>>,
    Extension(tenant): Extension<TenantContext>,
    Path(id): Path<String>,
) -> ApiResult<Finding> {
    let finding = ctx
        .store
        .get_finding_for(&tenant, &id)
        .ok_or_else(|| ApiError::not_found("finding not found"))?;
    let patch = format!(
        "# Proposal only; Ryu Security did not modify the checkout.\n# Location: {}:{}\n# Remediation: {}\n\n# Next step: validate the issue, add a focused regression test, and apply changes only after review.\n",
        finding.location.path, finding.location.line, finding.remediation
    );
    ctx.store
        .set_finding_patch_for(&tenant, &id, patch)
        .map(Json)
        .map_err(ApiError::internal)
}
