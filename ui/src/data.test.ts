import { describe, expect, test } from "bun:test";
import {
	type Finding,
	findingStatusLabel,
	findingsForScan,
	type Scan,
	scanStatusLabel,
	scansForRepository,
	severityClass,
} from "./data.ts";

const scans: Scan[] = [
	{
		additionalContext: {
			attackVectors: "",
			focusAreas: "",
			securityContext: "",
		},
		coverage: 100,
		deep: false,
		evidenceLevel: "static-local",
		fileCount: 4,
		findingCount: 1,
		id: "scan-one",
		kind: "codebase",
		model: "Ryu local static pass",
		name: "Storefront · Standard scan",
		phase: "finalize",
		phases: [],
		progress: 100,
		reasoningEffort: "balanced",
		repositoryId: "repo-one",
		scope: "entire",
		startedAt: "2026-09-14T00:00:00Z",
		status: "completed",
	},
	{
		additionalContext: {
			attackVectors: "",
			focusAreas: "",
			securityContext: "",
		},
		coverage: 0,
		deep: true,
		evidenceLevel: "static-local",
		fileCount: 0,
		findingCount: 0,
		id: "scan-two",
		kind: "codebase",
		model: "Ryu local static pass",
		name: "Other · Deep scan",
		phase: "prepare",
		phases: [],
		progress: 0,
		reasoningEffort: "deep",
		repositoryId: "repo-two",
		scope: "entire",
		startedAt: "2026-09-14T00:00:00Z",
		status: "pending",
	},
];

const findings: Finding[] = [
	{
		attackPath: [],
		category: "injection",
		counterevidence: [],
		confidence: "Medium",
		createdAt: "2026-09-14T00:00:00Z",
		cwe: "CWE-95",
		evidence: [],
		id: "finding-one",
		impact: "",
		location: { line: 1, path: "src/lib.rs" },
		remediation: "",
		repositoryId: "repo-one",
		rootCause: "",
		scanId: "scan-one",
		severity: "High",
		status: "open",
		summary: "",
		title: "Potential dynamic code execution",
		validation: "Pending",
	},
];

describe("Security workbench data helpers", () => {
	test("keeps repository and scan scopes explicit", () => {
		expect(
			scansForRepository(scans, "repo-one").map((scan) => scan.id)
		).toEqual(["scan-one"]);
		expect(
			findingsForScan(findings, "scan-one").map((finding) => finding.id)
		).toEqual(["finding-one"]);
	});

	test("uses stable labels for async and triage states", () => {
		expect(scanStatusLabel("running")).toBe("Reviewing code");
		expect(scanStatusLabel("canceled")).toBe("Canceled");
		expect(findingStatusLabel("false_positive")).toBe("False positive");
	});

	test("maps severity to a themeable visual hook", () => {
		expect(severityClass("High")).toBe("security-severity-high");
		expect(severityClass("Medium")).toBe("security-severity-medium");
	});
});
