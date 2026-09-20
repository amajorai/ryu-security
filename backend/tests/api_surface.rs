use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use chrono::Utc;
use ryu_security::model::{Finding, FindingLocation, NewScan, TenantScope};
use ryu_security::{routes, scanner, tenant_from_headers, Ctx, Store, TenantContext};
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

fn fixture_root() -> PathBuf {
    std::env::temp_dir().join(format!("ryu-security-test-{}", Uuid::new_v4().simple()))
}

fn write_fixture(root: &Path) {
    fs::create_dir_all(root.join("src")).expect("create fixture source directory");
    fs::write(
        root.join("src/lib.rs"),
        "fn render(input: &str) { let _ = eval(input); }\n",
    )
    .expect("write fixture source");
}

fn remove_fixture(root: &Path) {
    let _ = fs::remove_dir_all(root);
}

fn tenant(user: &str, org: &str, store: &Store) -> TenantContext {
    TenantContext {
        owner_user_id: Some(user.to_owned()),
        org_id: Some(org.to_owned()),
        node_id: store.node_id().to_owned(),
    }
}

fn new_scan(repository_id: &str) -> NewScan {
    NewScan {
        additional_context: Default::default(),
        deep: false,
        kind: "codebase".to_owned(),
        model: String::new(),
        name: String::new(),
        reasoning_effort: String::new(),
        repository_id: repository_id.to_owned(),
        scope: "entire".to_owned(),
        scope_path: None,
    }
}

fn finding(id: &str, scan_id: &str, repository_id: &str) -> Finding {
    Finding {
        id: id.to_owned(),
        tenant: TenantScope::default(),
        scan_id: scan_id.to_owned(),
        repository_id: repository_id.to_owned(),
        title: "Potential injection".to_owned(),
        severity: "High".to_owned(),
        validation: "Pending".to_owned(),
        confidence: "Medium".to_owned(),
        category: "injection".to_owned(),
        cwe: "CWE-95".to_owned(),
        location: FindingLocation {
            path: "src/lib.rs".to_owned(),
            line: 1,
        },
        summary: "A test finding.".to_owned(),
        root_cause: "A dynamic sink is present.".to_owned(),
        impact: "The sink may execute input.".to_owned(),
        attack_path: vec!["caller input reaches sink".to_owned()],
        evidence: vec!["static test evidence".to_owned()],
        counterevidence: vec!["not executed".to_owned()],
        remediation: "Replace the sink.".to_owned(),
        patch: None,
        status: "open".to_owned(),
        created_at: Utc::now(),
        reviewed_at: None,
    }
}

async fn request(
    app: &axum::Router,
    method: &str,
    path: &str,
    user: Option<&str>,
    org: Option<&str>,
    payload: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(user) = user {
        builder = builder.header("x-ryu-caller-user-id", user);
    }
    if let Some(org) = org {
        builder = builder.header("x-ryu-caller-org-id", org);
    }
    let body = payload
        .map(|value| Body::from(value.to_string()))
        .unwrap_or_else(Body::empty);
    let response = app
        .clone()
        .oneshot(
            builder
                .header("content-type", "application/json")
                .body(body)
                .expect("build request"),
        )
        .await
        .expect("receive response");
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("read response body");
    (
        status,
        serde_json::from_slice(&body).expect("response should be JSON"),
    )
}

#[tokio::test]
async fn scan_persists_static_findings_and_explicit_evidence_boundary() {
    let root = fixture_root();
    write_fixture(&root);
    let store = Store::open(root.join("state/security.json")).expect("open store");
    let tenant = TenantContext::local(store.node_id());
    let repository = store
        .ensure_repository(&tenant, root.to_str().expect("fixture path"))
        .expect("register repository");
    let scan = store
        .create_scan(
            &tenant,
            NewScan {
                additional_context: Default::default(),
                deep: false,
                kind: "codebase".to_owned(),
                model: String::new(),
                name: String::new(),
                reasoning_effort: String::new(),
                repository_id: repository.id.clone(),
                scope: "entire".to_owned(),
                scope_path: None,
            },
        )
        .expect("create scan");

    scanner::run_scan(store.clone(), scan.id.clone()).await;

    let completed = store
        .get_scan_for(&tenant, &scan.id)
        .expect("completed scan");
    assert_eq!(completed.status, "completed");
    assert_eq!(completed.evidence_level, "static-local");
    assert_eq!(completed.coverage, 100);
    assert_eq!(completed.finding_count, 1);
    assert_eq!(
        store.findings_for_scan_for(&tenant, &scan.id)[0].category,
        "injection"
    );

    let reopened = Store::open(root.join("state/security.json")).expect("reopen store");
    assert_eq!(reopened.snapshot().scans.len(), 1);
    assert_eq!(reopened.snapshot().findings.len(), 1);
    remove_fixture(&root);
}

#[tokio::test]
async fn api_rejects_relative_repositories_and_exposes_bootstrap() {
    let root = fixture_root();
    fs::create_dir_all(&root).expect("create test directory");
    let store = Store::open(root.join("security.json")).expect("open store");
    let app = routes(Arc::new(Ctx { store }));

    let response = app
        .clone()
        .oneshot(
            Request::post("/repositories")
                .header("content-type", "application/json")
                .header("x-ryu-caller-user-id", "test-user")
                .header("x-ryu-caller-org-id", "test-org")
                .body(Body::from(
                    json!({ "path": "relative/repository" }).to_string(),
                ))
                .expect("build request"),
        )
        .await
        .expect("receive response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = app
        .oneshot(
            Request::get("/bootstrap")
                .header("x-ryu-caller-user-id", "test-user")
                .header("x-ryu-caller-org-id", "test-org")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("receive response");
    assert_eq!(response.status(), StatusCode::OK);
    remove_fixture(&root);
}

#[test]
fn tenant_boundary_uses_server_node_and_fails_closed_for_unresolved_managed_callers() {
    let headers = HeaderMap::new();
    assert_eq!(
        tenant_from_headers(&headers, "server-node", true),
        Err(StatusCode::FORBIDDEN)
    );

    let mut headers = HeaderMap::new();
    headers.insert("x-ryu-caller-user-id", HeaderValue::from_static("alice"));
    headers.insert("x-ryu-caller-org-id", HeaderValue::from_static("org-1"));
    headers.insert("x-ryu-node-id", HeaderValue::from_static("attacker-node"));
    let tenant = tenant_from_headers(&headers, "server-node", true).expect("caller is resolved");
    assert_eq!(tenant.owner_user_id.as_deref(), Some("alice"));
    assert_eq!(tenant.org_id.as_deref(), Some("org-1"));
    assert_eq!(tenant.node_id, "server-node");
}

#[tokio::test]
async fn security_routes_enforce_exact_tenant_on_reads_and_mutations() {
    let root = fixture_root();
    let alice_root = root.join("alice-repository");
    let bob_root = root.join("bob-repository");
    write_fixture(&alice_root);
    write_fixture(&bob_root);
    let store = Store::open(root.join("state/security.json")).expect("open store");
    let alice = tenant("alice", "org-shared", &store);
    let bob = tenant("bob", "org-shared", &store);

    let alice_repository = store
        .ensure_repository(&alice, alice_root.to_str().expect("alice path"))
        .expect("create Alice repository");
    let bob_repository = store
        .ensure_repository(&bob, bob_root.to_str().expect("Bob path"))
        .expect("create Bob repository");
    let alice_scan = store
        .create_scan(&alice, new_scan(&alice_repository.id))
        .expect("create Alice scan");
    let bob_scan = store
        .create_scan(&bob, new_scan(&bob_repository.id))
        .expect("create Bob scan");
    store
        .save_findings(
            &alice_scan.id,
            vec![finding(
                "finding-alice",
                &alice_scan.id,
                &alice_repository.id,
            )],
        )
        .expect("save Alice finding");
    store
        .save_findings(
            &bob_scan.id,
            vec![finding("finding-bob", &bob_scan.id, &bob_repository.id)],
        )
        .expect("save Bob finding");

    let app = routes(Arc::new(Ctx {
        store: store.clone(),
    }));

    let (status, body) = request(
        &app,
        "GET",
        "/bootstrap",
        Some("alice"),
        Some("org-shared"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["repositories"].as_array().expect("repositories").len(),
        1
    );
    assert_eq!(body["scans"].as_array().expect("scans").len(), 1);
    assert_eq!(body["findings"].as_array().expect("findings").len(), 1);
    assert_eq!(body["repositories"][0]["id"], alice_repository.id);

    let (status, body) = request(
        &app,
        "GET",
        "/repositories",
        Some("bob"),
        Some("org-shared"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["repositories"].as_array().expect("repositories").len(),
        1
    );
    assert_eq!(body["repositories"][0]["id"], bob_repository.id);

    let (status, body) = request(
        &app,
        "GET",
        &format!("/repositories/{}", alice_repository.id),
        Some("alice"),
        Some("org-shared"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["repository"]["id"], alice_repository.id);
    let (status, _) = request(
        &app,
        "GET",
        &format!("/repositories/{}", alice_repository.id),
        Some("bob"),
        Some("org-shared"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = request(
        &app,
        "GET",
        &format!("/repositories/{}", alice_repository.id),
        Some("alice"),
        Some("org-other"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, body) = request(
        &app,
        "GET",
        "/scans",
        Some("alice"),
        Some("org-shared"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["scans"].as_array().expect("scans").len(), 1);
    assert_eq!(body["scans"][0]["id"], alice_scan.id);
    let (status, _) = request(
        &app,
        "GET",
        &format!("/scans/{}", alice_scan.id),
        Some("bob"),
        Some("org-shared"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = request(
        &app,
        "GET",
        &format!("/scans/{}", alice_scan.id),
        Some("alice"),
        Some("org-shared"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["scan"]["id"], alice_scan.id);

    let (status, _) = request(
        &app,
        "POST",
        &format!("/scans/{}/cancel", alice_scan.id),
        Some("bob"),
        Some("org-shared"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = request(
        &app,
        "POST",
        &format!("/scans/{}/cancel", alice_scan.id),
        Some("alice"),
        Some("org-shared"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "canceled");

    let (status, body) = request(
        &app,
        "GET",
        "/findings",
        Some("alice"),
        Some("org-shared"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["findings"].as_array().expect("findings").len(), 1);
    assert_eq!(body["findings"][0]["id"], "finding-alice");
    let (status, _) = request(
        &app,
        "GET",
        "/findings/finding-alice",
        Some("bob"),
        Some("org-shared"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = request(
        &app,
        "GET",
        "/findings/finding-alice",
        Some("alice"),
        Some("org-shared"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], "finding-alice");

    let (status, _) = request(
        &app,
        "POST",
        "/findings/finding-alice/status",
        Some("bob"),
        Some("org-shared"),
        Some(json!({"status":"closed"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = request(
        &app,
        "POST",
        "/findings/finding-alice/status",
        Some("alice"),
        Some("org-shared"),
        Some(json!({"status":"accepted"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "accepted");

    let (status, _) = request(
        &app,
        "POST",
        "/findings/finding-alice/patch",
        Some("bob"),
        Some("org-shared"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = request(
        &app,
        "POST",
        "/findings/finding-alice/patch",
        Some("alice"),
        Some("org-shared"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["patch"]
        .as_str()
        .is_some_and(|patch| patch.contains("Proposal only")));

    let wrong_node = TenantContext {
        owner_user_id: Some("alice".to_owned()),
        org_id: Some("org-shared".to_owned()),
        node_id: "different-server-node".to_owned(),
    };
    assert!(store
        .get_repository_for(&wrong_node, &alice_repository.id)
        .is_none());
    assert!(store
        .update_finding_status_for(&wrong_node, "finding-alice", "closed")
        .is_err());

    remove_fixture(&root);
}

#[tokio::test]
async fn legacy_ownerless_records_are_not_assigned_to_a_request_tenant() {
    let root = fixture_root();
    write_fixture(&root);
    let store = Store::open(root.join("state/security.json")).expect("open store");
    let local = TenantContext::local(store.node_id());
    let repository = store
        .ensure_repository(&local, root.to_str().expect("fixture path"))
        .expect("create repository");
    let mut state = store.snapshot();
    state.repositories[0].tenant = TenantScope::default();
    store.replace_state(state).expect("persist legacy state");
    let app = routes(Arc::new(Ctx {
        store: store.clone(),
    }));

    let (status, body) = request(
        &app,
        "GET",
        "/repositories",
        Some("alice"),
        Some("org-1"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["repositories"]
        .as_array()
        .expect("repositories")
        .is_empty());
    assert!(store.get_repository(&repository.id).is_some());

    remove_fixture(&root);
}
