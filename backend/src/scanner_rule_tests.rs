//! Static rule classification, privacy, size-limit, and folder-scope tests for
//! the local scanner. Kept out of `scanner.rs` so that file stays reviewable;
//! this is a child module, so the scanner's private helpers stay reachable.

use std::fs;
use std::path::Path;

use super::*;
use crate::model::{NewScan, TenantContext};

fn source(path: &str, contents: &str) -> SourceFile {
    SourceFile {
        relative_path: path.to_owned(),
        contents: contents.to_owned(),
    }
}

fn classify(line: &str) -> Option<Finding> {
    finding_for_line(&source("src/app.ts", line), 7, line, "scan-1", "repo-1")
}

fn category_and_cwe(line: &str) -> Option<(String, String)> {
    classify(line).map(|finding| (finding.category, finding.cwe))
}

fn expect(line: &str, category: &str, cwe: &str) {
    assert_eq!(
        category_and_cwe(line),
        Some((category.to_owned(), cwe.to_owned())),
        "line {line:?}"
    );
}

#[test]
fn quoted_long_credential_is_a_hardcoded_secret() {
    expect(
        r#"const api_key = "AKIAABCDEFGHIJKLMNOPQRST";"#,
        "secrets",
        "CWE-798",
    );
}

#[test]
fn private_key_header_is_a_secret_without_a_key_name() {
    expect("-----BEGIN RSA PRIVATE KEY-----", "secrets", "CWE-798");
    expect("-----BEGIN PRIVATE KEY-----", "secrets", "CWE-798");
}

#[test]
fn each_sink_maps_to_its_category_and_cwe() {
    expect("let value = eval(input);", "injection", "CWE-95");
    expect("element.innerHTML = markup;", "xss", "CWE-79");
    expect(
        "<div dangerouslySetInnerHTML={{ __html: html }} />",
        "xss",
        "CWE-79",
    );
    expect("config = yaml.load(stream)", "deserialization", "CWE-502");
    expect("obj = pickle.loads(blob)", "deserialization", "CWE-502");
    expect(
        "db.query(`SELECT * FROM users WHERE id = ${id}`)",
        "injection",
        "CWE-89",
    );
    expect(
        r#"let sql = format!("DELETE FROM t WHERE id = {}", id);"#,
        "injection",
        "CWE-89",
    );
    expect("const response = await fetch(url);", "network", "CWE-918");
    expect("requests.get(target_host)", "network", "CWE-918");
}

#[test]
fn near_misses_produce_no_finding() {
    // Key name and quotes, but the value is too short to look like a credential.
    assert!(classify(r#"password = "hunter2""#).is_none());
    // Long value, no quotes.
    assert!(classify("token = abcdefghijklmnopqrstuvwxyz0123").is_none());
    // A static query with no interpolation or concatenation.
    assert!(classify(r#"db.query("SELECT id FROM users WHERE active = 1")"#).is_none());
    // A request with a literal destination and no variable-looking target.
    assert!(classify(r#"fetch("/api/health")"#).is_none());
    assert!(classify("let total = a + b;").is_none());
}

#[test]
fn secret_rule_wins_when_several_rules_match() {
    // Matches secret, eval, innerHTML, SQL interpolation, and SSRF at once.
    let line = r#"const secret_token = "abcdefghijklmnopqrstuvwxyz"; eval(x); el.innerHTML = q; fetch(url); `SELECT ${a}`"#;
    expect(line, "secrets", "CWE-798");
    // Without the secret, eval outranks the later sinks.
    expect(
        "eval(x); el.innerHTML = q; fetch(url);",
        "injection",
        "CWE-95",
    );
    // XSS outranks deserialization, SQL, and SSRF.
    expect("el.innerHTML = yaml.load(fetch(url))", "xss", "CWE-79");
}

#[test]
fn finding_text_never_contains_the_raw_source_line() {
    let secret_value = "ZXCVBNMASDFGHJKLQWERTYUIOP1234";
    let line = format!(r#"const api_key = "{secret_value}";"#);
    let finding = classify(&line).expect("secret finding");
    assert_eq!(finding.location.path, "src/app.ts");
    assert_eq!(finding.location.line, 7);
    let text = [
        vec![
            finding.summary.clone(),
            finding.root_cause.clone(),
            finding.impact.clone(),
            finding.remediation.clone(),
            finding.title.clone(),
        ],
        finding.evidence.clone(),
        finding.attack_path.clone(),
        finding.counterevidence.clone(),
    ]
    .concat();
    for entry in &text {
        assert!(!entry.contains(secret_value), "leaked value in {entry:?}");
        assert!(!entry.contains(&line), "leaked line in {entry:?}");
    }
    assert!(finding.summary.contains("src/app.ts:7"));
    assert!(finding.patch.is_none());
}

#[test]
fn scan_files_stops_at_one_hundred_findings() {
    let many = "eval(input);\n".repeat(150);
    let files = vec![
        source("a.js", &many),
        source("b.js", "element.innerHTML = markup;\n"),
    ];
    let findings = scan_files(&files, "scan-1", "repo-1");
    assert_eq!(findings.len(), 100);
    assert!(findings
        .iter()
        .all(|finding| finding.location.path == "a.js"));
    assert_eq!(findings[99].location.line, 100);

    let few = vec![
        source("a.js", "eval(x);\nsafe();\n"),
        source("b.js", "eval(y);\n"),
    ];
    let findings = scan_files(&few, "scan-1", "repo-1");
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].scan_id, "scan-1");
    assert_eq!(findings[1].repository_id, "repo-1");
    assert_eq!(findings[1].location.path, "b.js");
}

#[test]
fn env_files_are_source_and_unknown_extensions_are_not() {
    for name in [".env", ".env.local", ".env.production", "app.TS", "main.rs"] {
        assert!(is_source_file(Path::new(name)), "{name} should be scanned");
    }
    for name in [
        "photo.png",
        "archive.zip",
        "Makefile",
        "env",
        "notes.env.bak",
    ] {
        assert!(!is_source_file(Path::new(name)), "{name} should be skipped");
    }
}

struct ScopeFixture {
    _temp: tempfile::TempDir,
    base: PathBuf,
    store: Store,
    tenant: TenantContext,
    repository_id: String,
}

fn scope_fixture() -> ScopeFixture {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let repo = base.join("repo");
    fs::create_dir_all(repo.join("src")).unwrap();
    fs::write(repo.join("src/inside.js"), "eval(inside);\n").unwrap();
    let sibling = base.join("repo-sibling");
    fs::create_dir_all(&sibling).unwrap();
    fs::write(sibling.join("outside.js"), "eval(outside);\n").unwrap();
    let store = Store::open(base.join("state/security.json")).unwrap();
    let tenant = TenantContext::local(store.node_id());
    let repository_id = store
        .ensure_repository(&tenant, repo.to_str().unwrap())
        .unwrap()
        .id;
    ScopeFixture {
        _temp: temp,
        base,
        store,
        tenant,
        repository_id,
    }
}

impl ScopeFixture {
    fn repo(&self) -> PathBuf {
        self.base.join("repo")
    }

    fn scan(&self, scope: &str, scope_path: Option<PathBuf>) -> Scan {
        self.store
            .create_scan(
                &self.tenant,
                NewScan {
                    additional_context: Default::default(),
                    deep: false,
                    kind: "codebase".to_owned(),
                    model: String::new(),
                    name: String::new(),
                    reasoning_effort: String::new(),
                    repository_id: self.repository_id.clone(),
                    scope: scope.to_owned(),
                    scope_path: scope_path.map(|path| path.to_string_lossy().into_owned()),
                },
            )
            .unwrap()
    }

    fn resolve(&self, scope: &str, scope_path: Option<PathBuf>) -> Result<PathBuf> {
        resolve_target(self.repo().to_str().unwrap(), &self.scan(scope, scope_path))
    }
}

fn error_text(result: Result<PathBuf>) -> String {
    format!("{:#}", result.expect_err("scope should be rejected"))
}

#[test]
fn folder_scope_inside_the_repository_resolves() {
    let fixture = scope_fixture();
    assert_eq!(
        fixture
            .resolve("folder", Some(fixture.repo().join("src")))
            .unwrap(),
        fixture.repo().join("src")
    );
    // Entire scans ignore any scope path and use the repository root.
    assert_eq!(
        fixture
            .resolve("entire", Some(fixture.base.join("repo-sibling")))
            .unwrap(),
        fixture.repo()
    );
}

#[test]
fn folder_scope_outside_the_repository_is_rejected() {
    let fixture = scope_fixture();
    let outside = "scan folder must be inside the selected repository";
    // A sibling whose name shares the repository's prefix.
    let sibling = fixture.resolve("folder", Some(fixture.base.join("repo-sibling")));
    assert!(error_text(sibling).contains(outside));
    // Escaping with `..` from inside the repository.
    let escaped = fixture.resolve(
        "folder",
        Some(fixture.repo().join("src/../../repo-sibling")),
    );
    assert!(error_text(escaped).contains(outside));
    // The repository's parent.
    let parent = fixture.resolve("folder", Some(fixture.base.clone()));
    assert!(error_text(parent).contains(outside));
}

#[cfg(unix)]
#[test]
fn folder_scope_symlink_pointing_outside_is_rejected() {
    let fixture = scope_fixture();
    let link = fixture.repo().join("linked");
    std::os::unix::fs::symlink(fixture.base.join("repo-sibling"), &link).unwrap();
    let result = fixture.resolve("folder", Some(link));
    assert!(error_text(result).contains("scan folder must be inside the selected repository"));
}

#[test]
fn folder_scope_must_be_an_existing_directory() {
    let fixture = scope_fixture();
    let file = fixture.resolve("folder", Some(fixture.repo().join("src/inside.js")));
    assert!(error_text(file).contains("scan folder must be a directory"));
    let missing = fixture.resolve("folder", Some(fixture.repo().join("missing")));
    assert!(error_text(missing).contains("resolve scan folder"));
    let absent = fixture.resolve("folder", None);
    assert!(error_text(absent).contains("folder scans require a scope path"));
}

#[tokio::test]
async fn run_scan_fails_closed_for_a_folder_outside_the_repository() {
    let fixture = scope_fixture();
    let scan = fixture.scan("folder", Some(fixture.base.join("repo-sibling")));
    run_scan(fixture.store.clone(), scan.id.clone()).await;
    let finished = fixture.store.get_scan(&scan.id).unwrap();
    assert_eq!(finished.status, "failed");
    assert_eq!(
        finished.error.as_deref(),
        Some("scan folder must be inside the selected repository")
    );
    assert_eq!(finished.finding_count, 0);
    assert!(fixture.store.snapshot().findings.is_empty());

    // Positive control: the same store scans an inside folder to completion.
    let inside = fixture.scan("folder", Some(fixture.repo().join("src")));
    run_scan(fixture.store.clone(), inside.id.clone()).await;
    let completed = fixture.store.get_scan(&inside.id).unwrap();
    assert_eq!(completed.status, "completed");
    let findings = fixture.store.snapshot().findings;
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].location.path, "inside.js");
}
