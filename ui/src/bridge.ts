import type { z } from "zod";
import type {
	AdditionalContext,
	BootstrapResponse,
	Finding,
	Repository,
	Scan,
} from "./data.ts";
import {
	bootstrapResponseSchema,
	createScanInputSchema,
	findingSchema,
	repositorySchema,
	type SecurityRequestBody,
	scanDetailSchema,
	scanSchema,
	securityApiErrorSchema,
} from "./schemas.ts";

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
	return globalThis.window?.ryu;
}

async function directRequest<S extends z.ZodType>(
	responseSchema: S,
	path: string,
	method: "GET" | "POST" = "GET",
	body?: SecurityRequestBody
): Promise<z.output<S>> {
	const options: RequestInit = { method };
	if (method === "POST" && body !== undefined) {
		options.body = JSON.stringify(body);
		options.headers = { "content-type": "application/json" };
	}
	const response = await fetch(`/api/security${path}`, options);
	const payload = await response.json().catch(() => null);
	if (!response.ok) {
		const parsed = securityApiErrorSchema.safeParse(payload);
		const error = parsed.success ? parsed.data.error : undefined;
		throw new SecurityApiError(
			response.status,
			error?.code ?? "request_failed",
			error?.message ?? "The Security sidecar rejected the request."
		);
	}
	return responseSchema.parse(payload);
}

async function request<S extends z.ZodType>(
	responseSchema: S,
	path: string,
	method: "GET" | "POST" = "GET",
	body?: SecurityRequestBody
): Promise<z.output<S>> {
	const appRequest = bridge()?.app?.request;
	if (appRequest) {
		return responseSchema.parse(await appRequest({ method, path, body }));
	}
	return directRequest(responseSchema, path, method, body);
}

export function getBootstrap(): Promise<BootstrapResponse> {
	return request(bootstrapResponseSchema, "/bootstrap");
}

export function createRepository(path: string): Promise<Repository> {
	return request(repositorySchema, "/repositories", "POST", { path });
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
	return request(
		scanSchema,
		"/scans",
		"POST",
		createScanInputSchema.parse(input)
	);
}

export function getScan(id: string): Promise<{
	findings: Finding[];
	repository?: Repository | null;
	scan: Scan;
}> {
	return request(scanDetailSchema, `/scans/${encodeURIComponent(id)}`);
}

export function cancelScan(id: string): Promise<Scan> {
	return request(scanSchema, `/scans/${encodeURIComponent(id)}/cancel`, "POST");
}

export function updateFindingStatus(
	id: string,
	status: Finding["status"]
): Promise<Finding> {
	return request(
		findingSchema,
		`/findings/${encodeURIComponent(id)}/status`,
		"POST",
		{ status }
	);
}

export function generatePatch(id: string): Promise<Finding> {
	return request(
		findingSchema,
		`/findings/${encodeURIComponent(id)}/patch`,
		"POST"
	);
}
