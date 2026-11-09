//! Line-level static rules that turn source lines into candidate findings.

use super::*;

pub(super) fn scan_files(files: &[SourceFile], scan_id: &str, repository_id: &str) -> Vec<Finding> {
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

pub(super) fn finding_for_line(
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
                "An attacker could make the server reach private services or cloud metadata services from a trusted network position.",
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

pub(super) fn looks_like_secret(lower: &str, original: &str) -> bool {
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

pub(super) fn looks_like_sql_interpolation(lower: &str, original: &str) -> bool {
    let query = lower.contains("select ")
        || lower.contains("insert ")
        || lower.contains("update ")
        || lower.contains("delete ");
    query && (original.contains("${") || original.contains(" + ") || lower.contains("format!("))
}

pub(super) fn looks_like_ssrf(lower: &str) -> bool {
    (lower.contains("fetch(") || lower.contains("requests.get(") || lower.contains("reqwest::get("))
        && (lower.contains("url") || lower.contains("uri") || lower.contains("target"))
}
