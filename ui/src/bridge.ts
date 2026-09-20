import type {
	AdditionalContext,
	BootstrapResponse,
	Finding,
	Repository,
	Scan,
} from "./data.ts";

export { subscribeCompanionTheme as subscribeLiveTheme } from "@ryu/app-host/companion-theme";

export class SecurityApiError extends Error {
	readonly code: string;
	readonly status: number;

	constructor(status: number, code: string, message: string) {
		super(message);
		this.name = "SecurityApiError";
		this.code = code;
		this.status = status;
	}
}

function bridge() {
	return typeof window === "undefined" ? undefined : window.ryu;
}

async function directRequest<T>(
	path: string,
	method: "GET" | "POST" = "GET",
	body?: unknown
): Promise<T> {
	const response = await fetch(`/api/security${path}`, {
		body: body === undefined ? undefined : JSON.stringify(body),
		headers:
			body === undefined ? undefined : { "content-type": "application/json" },
		method,
	});
	const payload: unknown = await response.json().catch(() => null);
	if (!response.ok) {
		const error =
			typeof payload === "object" && payload !== null
				? (payload as { error?: { code?: string; message?: string } }).error
				: undefined;
		throw new SecurityApiError(
			response.status,
			error?.code ?? "request_failed",
			error?.message ?? "The Security sidecar rejected the request."
		);
	}
	return payload as T;
}

async function request<T>(
	path: string,
	method: "GET" | "POST" = "GET",
	body?: unknown
): Promise<T> {
	const appRequest = bridge()?.app?.request;
	if (appRequest) {
		return (await appRequest({ method, path, body })) as T;
	}
	return directRequest<T>(path, method, body);
}

export function getBootstrap(): Promise<BootstrapResponse> {
	return request<BootstrapResponse>("/bootstrap");
}

export function createRepository(path: string): Promise<Repository> {
	return request<Repository>("/repositories", "POST", { path });
}

export function createScan(input: {
	additionalContext: AdditionalContext;
	deep: boolean;
	kind: "codebase" | "changes";
	model: string;
	name: string;
	reasoningEffort: string;
	repositoryId?: string;
	repositoryPath?: string;
	scope: "entire" | "folder";
	scopePath?: string;
}): Promise<Scan> {
	return request<Scan>("/scans", "POST", input);
}

export function getScan(id: string): Promise<{
	findings: Finding[];
	repository?: Repository | null;
	scan: Scan;
}> {
	return request(`/scans/${encodeURIComponent(id)}`);
}

export function cancelScan(id: string): Promise<Scan> {
	return request<Scan>(`/scans/${encodeURIComponent(id)}/cancel`, "POST");
}

export function updateFindingStatus(
	id: string,
	status: Finding["status"]
): Promise<Finding> {
	return request<Finding>(
		`/findings/${encodeURIComponent(id)}/status`,
		"POST",
		{ status }
	);
}

export function generatePatch(id: string): Promise<Finding> {
	return request<Finding>(`/findings/${encodeURIComponent(id)}/patch`, "POST");
}
