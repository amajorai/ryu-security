import { mkdir } from "node:fs/promises";
import path from "node:path";
import { expect, type Page, test } from "@playwright/test";
import type {
	BootstrapResponse,
	Finding,
	Repository,
	Scan,
} from "../src/data.ts";
import type { SecurityRequestBody } from "../src/schemas.ts";

interface SecurityFixtureCall {
	body?: SecurityRequestBody;
	method: string;
	path: string;
}

interface SecurityFixture {
	calls: SecurityFixtureCall[];
	failCancellationOnce: boolean;
	state: BootstrapResponse;
}

declare global {
	interface Window {
		__securityInteractionFixture?: SecurityFixture;
	}
}

const EVIDENCE_DIRECTORY = path.resolve(import.meta.dirname, "evidence");
const STARTED_AT = "2026-09-30T10:00:00.000Z";

const repositories: Repository[] = [
	{
		branch: "main",
		createdAt: STARTED_AT,
		fileCount: 18,
		findingCount: 1,
		head: "a91ce20",
		id: "repo-payments",
		lastScanId: "scan-payments",
		lastScannedAt: STARTED_AT,
		name: "Payments API",
		path: "/fixture/payments-api",
		scanCount: 1,
		status: "ready",
	},
	{
		branch: "main",
		createdAt: STARTED_AT,
		fileCount: 9,
		findingCount: 0,
		head: "2c80f1a",
		id: "repo-identity",
		lastScanId: "scan-identity",
		lastScannedAt: STARTED_AT,
		name: "Identity service",
		path: "/fixture/identity-service",
		scanCount: 1,
		status: "ready",
	},
];

function makeScan({
	deep = false,
	id,
	kind = "codebase",
	findingCount = 0,
	name,
	progress,
	repositoryId,
	status,
}: {
	deep?: boolean;
	id: string;
	kind?: "codebase" | "changes";
	findingCount?: number;
	name: string;
	progress: number;
	repositoryId: string;
	status: Scan["status"];
}): Scan {
	const active = status === "pending" || status === "running";
	return {
		additionalContext: {
			attackVectors: "",
			focusAreas: "",
			securityContext: "",
		},
		coverage: active ? 42 : 100,
		deep,
		evidenceLevel: "static-local",
		fileCount: 18,
		findingCount,
		finishedAt: active ? null : STARTED_AT,
		id,
		kind,
		model: "Ryu local static pass",
		name,
		phase: active ? "review" : "finalize",
		phases: [
			{
				detail: active ? "Reviewing source files" : "Saved local findings",
				key: active ? "review" : "finalize",
				label: active ? "Review files" : "Save evidence",
				status: active ? "running" : "completed",
			},
		],
		progress,
		reasoningEffort: deep ? "deep" : "balanced",
		repositoryId,
		scope: "entire",
		startedAt: STARTED_AT,
		status,
	};
}

const searchState: BootstrapResponse = {
	capabilities: {
		agentVerification: false,
		evidenceLevel: "static-local",
		networkAccess: false,
		patchApplication: false,
	},
	findings: [],
	repositories,
	scans: [
		makeScan({
			id: "scan-payments",
			kind: "changes",
			name: "Payments source review",
			progress: 100,
			repositoryId: "repo-payments",
			status: "completed",
		}),
		makeScan({
			id: "scan-identity",
			name: "Identity access review",
			progress: 100,
			repositoryId: "repo-identity",
			status: "completed",
		}),
	],
};

const runningScan = makeScan({
	findingCount: 1,
	id: "scan-active",
	name: "Payments live review",
	progress: 48,
	repositoryId: "repo-payments",
	status: "running",
});

const retainedFinding: Finding = {
	attackPath: ["request body", "dynamic evaluator"],
	category: "injection",
	confidence: "High",
	counterevidence: [],
	createdAt: STARTED_AT,
	cwe: "CWE-95",
	evidence: ["User-controlled input reaches a dynamic evaluator."],
	id: "finding-retained",
	impact: "An attacker may execute unintended code.",
	location: { line: 42, path: "src/security.ts" },
	remediation: "Replace dynamic evaluation with an allowlisted parser.",
	repositoryId: "repo-payments",
	rootCause: "Untrusted input reaches code evaluation.",
	scanId: runningScan.id,
	severity: "High",
	status: "open",
	summary: "A user-controlled value is evaluated as code.",
	title: "Potential dynamic code execution",
	validation: "Source flow confirmed by local static analysis.",
};

const runningState: BootstrapResponse = {
	...searchState,
	findings: [retainedFinding],
	scans: [runningScan],
};

async function installFixture(
	page: Page,
	initialState: BootstrapResponse,
	failCancellationOnce = false
) {
	await page.addInitScript(
		({ initial, failOnce }) => {
			const fixture: SecurityFixture = {
				calls: [],
				failCancellationOnce: failOnce,
				state: structuredClone(initial),
			};
			window.__securityInteractionFixture = fixture;
			window.ryu = {
				shell: { subscribeTheme: () => ({ dispose() {} }) },
				context: null,
				app: {
					request: async ({ method, path, body }) => {
						const call: SecurityFixtureCall = { method: method ?? "GET", path };
						if (body !== undefined) {
							call.body = structuredClone(body);
						}
						fixture.calls.push(call);
						if (method === "GET" && path === "/bootstrap") {
							return structuredClone(fixture.state);
						}
						if (method === "GET" && path.startsWith("/scans/")) {
							const id = decodeURIComponent(path.slice("/scans/".length));
							const scan = fixture.state.scans.find((item) => item.id === id);
							if (!scan) {
								throw new Error(`Unknown fixture scan: ${id}`);
							}
							return {
								findings: structuredClone(
									fixture.state.findings.filter((item) => item.scanId === id)
								),
								repository:
									fixture.state.repositories.find(
										(item) => item.id === scan.repositoryId
									) ?? null,
								scan: structuredClone(scan),
							};
						}
						const cancelId = path.match(/^\/scans\/([^/]+)\/cancel$/)?.[1];
						if (method === "POST" && cancelId) {
							if (fixture.failCancellationOnce) {
								fixture.failCancellationOnce = false;
								throw new Error(
									"Cancellation is temporarily unavailable; try again."
								);
							}
							const id = decodeURIComponent(cancelId);
							const activeScan = fixture.state.scans.find(
								(item) => item.id === id
							);
							if (!activeScan) {
								throw new Error(`Unknown fixture scan: ${id}`);
							}
							const canceled = {
								...activeScan,
								finishedAt: new Date().toISOString(),
								phases: activeScan.phases.map((phase) => ({
									...phase,
									detail: "Scan stopped after saving partial findings.",
									status: "canceled",
								})),
								status: "canceled" as const,
							};
							fixture.state.scans = fixture.state.scans.map((item) =>
								item.id === canceled.id ? canceled : item
							);
							return structuredClone(canceled);
						}
						throw new Error(
							`Unexpected Security fixture request: ${method} ${path}`
						);
					},
				},
			};
		},
		{ initial: initialState, failOnce: failCancellationOnce }
	);
}

async function fixtureCalls(page: Page): Promise<SecurityFixtureCall[]> {
	return page.evaluate(() => window.__securityInteractionFixture?.calls ?? []);
}

test("scan search filters by scan name, repository, and kind without a dead filter button", async ({
	page,
}) => {
	await installFixture(page, searchState);
	await page.goto("/");
	await expect(
		page.getByRole("button", { name: /Payments source review/ })
	).toBeVisible();
	await expect(
		page.getByRole("button", { name: /Identity access review/ })
	).toBeVisible();
	await expect(page.getByRole("button", { name: "Filter scans" })).toHaveCount(
		0
	);

	const search = page.getByRole("textbox", { name: "Search scans" });
	await search.fill(" CHANGES ");
	await expect(page.locator(".security-list-count")).toHaveText("1");
	await expect(
		page.getByRole("button", { name: /Payments source review/ })
	).toBeVisible();
	await expect(
		page.getByRole("button", { name: /Identity access review/ })
	).toHaveCount(0);

	await search.fill("identity service");
	await expect(page.locator(".security-list-count")).toHaveText("1");
	await expect(
		page.getByRole("button", { name: /Identity access review/ })
	).toBeVisible();
	await expect(
		page.getByRole("button", { name: /Payments source review/ })
	).toHaveCount(0);
	await expect(page.locator(".security-detail-header h2")).toHaveText(
		"Identity access review"
	);

	const calls = await fixtureCalls(page);
	expect(
		calls.every(({ method, path }) => method === "GET" && path === "/bootstrap")
	).toBe(true);

	await mkdir(EVIDENCE_DIRECTORY, { recursive: true });
	await page.screenshot({
		animations: "disabled",
		fullPage: true,
		path: path.join(EVIDENCE_DIRECTORY, "security-scan-search-filtered.png"),
	});

	await search.fill("no matching scan");
	await expect(page.locator(".security-list-count")).toHaveText("0");
	await expect(
		page.getByRole("heading", { name: "Choose a scan" })
	).toBeVisible();
	await search.clear();
	await expect(page.locator(".security-detail-header h2")).toHaveText(
		"Payments source review"
	);
});

test("Stop scan reports a failure, can be retried, and reads back retained findings", async ({
	page,
}) => {
	await installFixture(page, runningState, true);
	await page.goto("/");
	const stop = page.getByRole("button", { name: "Stop scan" });
	await expect(stop).toBeVisible();
	await expect(
		page.locator(".security-detail-actions .security-status-badge")
	).toHaveText("Reviewing code");

	await stop.click();
	await expect(page.locator(".security-toast")).toContainText(
		"Cancellation is temporarily unavailable; try again."
	);
	await expect(stop).toBeVisible();
	await expect(stop).toBeEnabled();

	await mkdir(EVIDENCE_DIRECTORY, { recursive: true });
	await page.screenshot({
		animations: "disabled",
		fullPage: true,
		path: path.join(EVIDENCE_DIRECTORY, "security-stop-scan-retry-error.png"),
	});

	await stop.click();
	await expect(
		page.locator(".security-detail-actions .security-status-badge")
	).toHaveText("Canceled");
	await expect(page.getByRole("button", { name: "Stop scan" })).toHaveCount(0);
	await expect(page.locator(".security-toast")).toContainText(
		"Scan canceled. No files were changed."
	);
	await expect(
		page.getByText("1 candidate retained before cancellation.", { exact: true })
	).toBeVisible();
	await expect(
		page.getByText("Potential dynamic code execution", { exact: true })
	).toBeVisible();

	const fixture = await page.evaluate(
		() => window.__securityInteractionFixture ?? null
	);
	expect(fixture).not.toBeNull();
	expect(
		fixture?.calls
			.filter(({ method }) => method === "POST")
			.map(({ path }) => path)
	).toEqual([
		`/scans/${runningScan.id}/cancel`,
		`/scans/${runningScan.id}/cancel`,
	]);
	expect(
		fixture?.calls
			.filter(({ method }) => method === "POST")
			.every(({ body }) => body === undefined)
	).toBe(true);
	expect(fixture?.state.scans[0]?.status).toBe("canceled");
	expect(fixture?.state.findings.map(({ id }) => id)).toEqual([
		retainedFinding.id,
	]);
	expect(
		fixture?.calls.some(
			({ method, path }) =>
				method === "GET" && path === `/scans/${runningScan.id}`
		)
	).toBe(true);

	await page.screenshot({
		animations: "disabled",
		fullPage: true,
		path: path.join(
			EVIDENCE_DIRECTORY,
			"security-stop-scan-retained-results.png"
		),
	});
});
