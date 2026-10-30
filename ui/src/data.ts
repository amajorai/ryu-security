import { formatDateTime } from "@ryu/ui/lib/timezone.ts";

export type Screen = "scans" | "findings" | "repositories";
export type ScanKind = "codebase" | "changes";
export type ScanStatus =
	| "pending"
	| "running"
	| "completed"
	| "failed"
	| "canceled";
export type FindingStatus = "open" | "accepted" | "false_positive" | "closed";

export interface Repository {
	branch: string;
	createdAt: string;
	fileCount: number;
	findingCount: number;
	head: string;
	id: string;
	lastScanId?: string | null;
	lastScannedAt?: string | null;
	name: string;
	path: string;
	scanCount: number;
	status: string;
}

export interface ScanPhase {
	detail: string;
	key: string;
	label: string;
	status: string;
}

export interface AdditionalContext {
	attackVectors: string;
	focusAreas: string;
	securityContext: string;
}

export interface Scan {
	additionalContext: AdditionalContext;
	coverage: number;
	deep: boolean;
	error?: string | null;
	evidenceLevel: string;
	fileCount: number;
	findingCount: number;
	finishedAt?: string | null;
	id: string;
	kind: ScanKind;
	model: string;
	name: string;
	phase: string;
	phases: ScanPhase[];
	progress: number;
	reasoningEffort: string;
	repositoryId: string;
	scope: "entire" | "folder";
	scopePath?: string | null;
	startedAt: string;
	status: ScanStatus;
}

export interface FindingLocation {
	line: number;
	path: string;
}

export interface Finding {
	attackPath: string[];
	category: string;
	confidence: string;
	counterevidence: string[];
	createdAt: string;
	cwe: string;
	evidence: string[];
	id: string;
	impact: string;
	location: FindingLocation;
	patch?: string | null;
	remediation: string;
	repositoryId: string;
	reviewedAt?: string | null;
	rootCause: string;
	scanId: string;
	severity: "Critical" | "High" | "Medium" | "Low" | string;
	status: FindingStatus;
	summary: string;
	title: string;
	validation: string;
}

export interface Capabilities {
	agentVerification: boolean;
	evidenceLevel: string;
	networkAccess: boolean;
	patchApplication: boolean;
}

export interface BootstrapResponse {
	capabilities: Capabilities;
	findings: Finding[];
	repositories: Repository[];
	scans: Scan[];
}

export function scansForRepository(
	scans: Scan[],
	repositoryId: string
): Scan[] {
	return scans.filter((scan) => scan.repositoryId === repositoryId);
}

export function findingsForScan(
	findings: Finding[],
	scanId: string
): Finding[] {
	return findings.filter((finding) => finding.scanId === scanId);
}

export function severityClass(severity: string): string {
	return `security-severity-${severity.toLowerCase()}`;
}

export function scanStatusLabel(status: ScanStatus): string {
	return {
		pending: "Queued",
		running: "Reviewing code",
		completed: "Completed",
		failed: "Failed",
		canceled: "Canceled",
	}[status];
}

export function findingStatusLabel(status: FindingStatus): string {
	return {
		open: "Open",
		accepted: "Accepted",
		false_positive: "False positive",
		closed: "Closed",
	}[status];
}

export function formatSecurityTime(value?: string | null): string {
	if (!value) {
		return "—";
	}
	return formatDateTime(value, {
		month: "short",
		day: "numeric",
		hour: "numeric",
		minute: "2-digit",
	});
}
