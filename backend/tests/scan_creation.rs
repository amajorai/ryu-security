//! Scan creation and finding-status normalization through the real router.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use chrono::Utc;
use ryu_security::model::{Finding, FindingLocation, NewScan, TenantScope};
use ryu_security::{routes, Ctx, Store, TenantContext};
use serde_json::{json, Value};
use tower::ServiceExt;

const USER: &str = "alice";
const ORG: &str = "org-a";

struct Fixture {
    _temp: tempfile::TempDir,
    repo: PathBuf,
    store: Store,
    app: axum::Router,
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().expect("temp dir");
    let repo = temp
        .path()
        .canonicalize()
        .expect("canonical temp")
        .join("payments");
    fs::create_dir_all(&repo).expect("create repository");
    fs::write(repo.join("main.rs"), "fn main() {}\n").expect("write source");
    let store = Store::open(temp.path().join("state/security.json")).expect("open store");
    let app = routes(Arc::new(Ctx {
        store: store.clone(),
    }));
    Fixture {
        _temp: temp,
        repo,
        store,
        app,
    }
}

fn tenant(store: &Store) -> TenantContext {
    TenantContext {
        owner_user_id: Some(USER.to_owned()),
        org_id: Some(ORG.to_owned()),
        node_id: store.node_id().to_owned(),
    }
}

async fn post(app: &axum::Router, path: &str, payload: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post(path)
                .header("content-type", "application/json")
                .header("x-ryu-caller-user-id", USER)
                .header("x-ryu-caller-org-id", ORG)
                .body(Body::from(payload.to_string()))
                .expect("build request"),
        )
        .await
        .expect("receive response");
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("read body");
    (
        status,
        serde_json::from_slice(&body).expect("response should be JSON"),
    )
}

impl Fixture {
    fn repo_path(&self) -> String {
        self.repo.to_string_lossy().into_owned()
    }

    async fn create(&self, extra: Value) -> (StatusCode, Value) {
        let mut payload = json!({ "repositoryPath": self.repo_path() });
        for (key, value) in extra.as_object().expect("object payload") {
            payload[key] = value.clone();
        }
        post(&self.app, "/scans", payload).await
    }
}

#[tokio::test]
async fn deep_changes_review_is_refused_and_nothing_is_stored() {
    let fixture = fixture();
    let (status, body) = fixture
        .create(json!({ "kind": "changes", "deep": true }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_request");
    assert!(body["error"]["message"]
        .as_str()
        .expect("message")
        .contains("deep scans are not supported"));
    assert!(fixture.store.snapshot().scans.is_empty());

    // Case and whitespace do not bypass the refusal.
    let (status, _) = fixture
        .create(json!({ "kind": "  CHANGES ", "deep": true }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(fixture.store.snapshot().scans.is_empty());
}

#[tokio::test]
async fn scan_without_a_repository_is_rejected() {
    let fixture = fixture();
    let (status, body) = post(&fixture.app, "/scans", json!({ "kind": "codebase" })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["error"]["message"],
        "a repository or absolute path is required"
    );
    let (status, _) = post(&fixture.app, "/scans", json!({ "repositoryId": "  " })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(fixture.store.snapshot().scans.is_empty());
}

#[tokio::test]
async fn unknown_kind_and_scope_normalize_and_blank_fields_get_defaults() {
    let fixture = fixture();
    let (status, body) = fixture
        .create(json!({
            "kind": "everything",
            "scope": "galaxy",
            "name": "   ",
            "model": " ",
            "reasoningEffort": "",
        }))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["kind"], "codebase");
    assert_eq!(body["scope"], "entire");
    assert_eq!(body["name"], "payments · Standard scan");
    assert_eq!(body["model"], "Ryu local static pass");
    assert_eq!(body["reasoningEffort"], "balanced");

    // Persisted, not only echoed.
    let stored = fixture
        .store
        .get_scan(body["id"].as_str().expect("scan id"))
        .expect("stored scan");
    assert_eq!(stored.kind, "codebase");
    assert_eq!(stored.scope, "entire");
    assert_eq!(stored.model, "Ryu local static pass");
}

#[tokio::test]
async fn default_names_follow_kind_and_depth_and_explicit_values_are_trimmed() {
    let fixture = fixture();
    let (_, deep) = fixture.create(json!({ "deep": true })).await;
    assert_eq!(deep["name"], "payments · Deep scan");
    assert_eq!(deep["deep"], true);

    let (_, changes) = fixture.create(json!({ "kind": "Changes" })).await;
    assert_eq!(changes["kind"], "changes");
    assert_eq!(changes["name"], "payments · Changes review");

    let (_, folder) = fixture
        .create(json!({ "scope": "FOLDER", "scopePath": "  " }))
        .await;
    assert_eq!(folder["scope"], "folder");
    assert!(folder["scopePath"].is_null());

    let (_, named) = fixture
        .create(json!({
            "name": "  Nightly ",
            "model": " custom-model ",
            "reasoningEffort": " high ",
        }))
        .await;
    assert_eq!(named["name"], "Nightly");
    assert_eq!(named["model"], "custom-model");
    assert_eq!(named["reasoningEffort"], "high");
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
            path: "main.rs".to_owned(),
            line: 1,
        },
        summary: "A test finding.".to_owned(),
        root_cause: "A dynamic sink is present.".to_owned(),
        impact: "The sink may execute input.".to_owned(),
        attack_path: vec![],
        evidence: vec![],
        counterevidence: vec![],
        remediation: "Replace the sink.".to_owned(),
        patch: None,
        status: "open".to_owned(),
        created_at: Utc::now(),
        reviewed_at: None,
    }
}

#[tokio::test]
async fn finding_status_aliases_normalize_persist_and_stamp_review_time() {
    let fixture = fixture();
    let context = tenant(&fixture.store);
    let repository = fixture
        .store
        .ensure_repository(&context, &fixture.repo_path())
        .expect("repository");
    let scan = fixture
        .store
        .create_scan(
            &context,
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
        .expect("scan");
    fixture
        .store
        .save_findings(
            &scan.id,
            vec![finding("finding-1", &scan.id, &repository.id)],
        )
        .expect("save finding");
    let path = "/findings/finding-1/status";

    for (requested, expected) in [
        ("false-positive", "false_positive"),
        ("accepted", "accepted"),
        (" FALSE_POSITIVE ", "false_positive"),
        ("Closed", "closed"),
        ("bogus", "open"),
    ] {
        let (status, body) = post(&fixture.app, path, json!({ "status": requested })).await;
        assert_eq!(status, StatusCode::OK, "{requested}");
        assert_eq!(body["status"], expected, "{requested}");
        assert!(body["reviewedAt"].is_string(), "{requested}");
        let stored = fixture
            .store
            .get_finding_for(&context, "finding-1")
            .expect("stored finding");
        assert_eq!(stored.status, expected, "{requested}");
        assert!(stored.reviewed_at.is_some());
    }
}
