use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::extract::Request;
use axum::http::{header::AUTHORIZATION, StatusCode};
use axum::middleware::{from_fn, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use ryu_security::{paths, routes, Ctx, Store, TenantContext};
use serde_json::json;

const DEFAULT_PORT: u16 = 8044;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let store = Store::open(paths::state_path())?;
    if std::env::args().nth(1).as_deref() == Some("list") {
        if paths::is_managed_node() {
            anyhow::bail!("Security list requires an authenticated caller on a managed node");
        }
        let tenant = TenantContext::local(store.node_id());
        let repositories = store
            .snapshot_for(&tenant)
            .repositories
            .into_iter()
            .map(|repository| {
                json!({
                    "id": repository.id,
                    "name": repository.name,
                    "path": repository.path,
                    "status": repository.status,
                    "lastScanId": repository.last_scan_id,
                })
            })
            .collect::<Vec<_>>();
        println!("{}", serde_json::to_string_pretty(&repositories)?);
        return Ok(());
    }

    let port = std::env::var("RYU_SECURITY_PORT")
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let token = std::env::var("RYU_EXT_TOKEN")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let context = Arc::new(Ctx { store });
    let expected = token.clone();
    let protected = Router::new()
        .nest("/api/security", routes(context))
        .layer(from_fn(move |request: Request, next: Next| {
            let expected = expected.clone();
            async move { require_token(request, next, expected.as_deref()).await }
        }));
    let app = Router::new().route("/health", get(health)).merge(protected);
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "ryu-security sidecar listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({
        "ok": true,
        "name": "ryu-security",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn require_token(request: Request, next: Next, expected: Option<&str>) -> Response {
    let provided = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if ryu_sidecar_runtime::token_ok(provided, expected) {
        next.run(request).await
    } else {
        (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
    }
}
