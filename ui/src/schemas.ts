import { z } from "zod";
import type {
	AdditionalContext,
	BootstrapResponse,
	Capabilities,
	Finding,
	FindingLocation,
	FindingStatus,
	Repository,
	Scan,
	ScanPhase,
} from "./data.ts";

export const securityPayloadSchema = z.json();
export type SecurityPayload = z.infer<typeof securityPayloadSchema>;
const nullableText = z.string().nullable().optional();
export const scanScopeSchema = z.enum(["entire", "folder"]);
export const findingStatusSchema = z.enum([
	"open",
	"accepted",
	"false_positive",
	"closed",
]) satisfies z.ZodType<FindingStatus>;
export const repositorySchema = z
	.object({
		branch: z.string(),
		createdAt: z.string(),
		fileCount: z.number(),
		findingCount: z.number(),
		head: z.string(),
		id: z.string(),
		lastScanId: nullableText,
		lastScannedAt: nullableText,
		name: z.string(),
		path: z.string(),
		scanCount: z.number(),
		status: z.string(),
	})
	.catchall(securityPayloadSchema.optional()) satisfies z.ZodType<Repository>;
export const scanPhaseSchema = z
	.object({
		detail: z.string(),
		key: z.string(),
		label: z.string(),
		status: z.string(),
	})
	.catchall(securityPayloadSchema.optional()) satisfies z.ZodType<ScanPhase>;
export const additionalContextSchema = z
	.object({
		attackVectors: z.string(),
		focusAreas: z.string(),
		securityContext: z.string(),
	})
	.catchall(
		securityPayloadSchema.optional()
	) satisfies z.ZodType<AdditionalContext>;
export const scanSchema = z
	.object({
		additionalContext: additionalContextSchema,
		coverage: z.number(),
		deep: z.boolean(),
		error: nullableText,
		evidenceLevel: z.string(),
		fileCount: z.number(),
		findingCount: z.number(),
		finishedAt: nullableText,
		id: z.string(),
		kind: z.enum(["codebase", "changes"]),
		model: z.string(),
		name: z.string(),
		phase: z.string(),
		phases: z.array(scanPhaseSchema),
		progress: z.number(),
		reasoningEffort: z.string(),
		repositoryId: z.string(),
		scope: scanScopeSchema,
		scopePath: nullableText,
		startedAt: z.string(),
		status: z.enum(["pending", "running", "completed", "failed", "canceled"]),
	})
	.catchall(securityPayloadSchema.optional()) satisfies z.ZodType<Scan>;
export const findingLocationSchema = z
	.object({ line: z.number(), path: z.string() })
	.catchall(
		securityPayloadSchema.optional()
	) satisfies z.ZodType<FindingLocation>;
export const findingSchema = z
	.object({
		attackPath: z.array(z.string()),
		category: z.string(),
		confidence: z.string(),
		counterevidence: z.array(z.string()),
		createdAt: z.string(),
		cwe: z.string(),
		evidence: z.array(z.string()),
		id: z.string(),
		impact: z.string(),
		location: findingLocationSchema,
		patch: nullableText,
		remediation: z.string(),
		repositoryId: z.string(),
		reviewedAt: nullableText,
		rootCause: z.string(),
		scanId: z.string(),
		severity: z.string(),
		status: findingStatusSchema,
		summary: z.string(),
		title: z.string(),
		validation: z.string(),
	})
	.catchall(securityPayloadSchema.optional()) satisfies z.ZodType<Finding>;
export const capabilitiesSchema = z
	.object({
		agentVerification: z.boolean(),
		evidenceLevel: z.string(),
		networkAccess: z.boolean(),
		patchApplication: z.boolean(),
	})
	.catchall(securityPayloadSchema.optional()) satisfies z.ZodType<Capabilities>;
export const bootstrapResponseSchema = z
	.object({
		capabilities: capabilitiesSchema,
		findings: z.array(findingSchema),
		repositories: z.array(repositorySchema),
		scans: z.array(scanSchema),
	})
	.catchall(
		securityPayloadSchema.optional()
	) satisfies z.ZodType<BootstrapResponse>;
export const scanDetailSchema = z
	.object({
		findings: z.array(findingSchema),
		repository: repositorySchema.nullable().optional(),
		scan: scanSchema,
	})
	.catchall(securityPayloadSchema.optional());
export const createScanInputSchema = z.object({
	additionalContext: additionalContextSchema,
	deep: z.boolean(),
	kind: z.enum(["codebase", "changes"]),
	model: z.string(),
	name: z.string(),
	reasoningEffort: z.string(),
	repositoryId: z.string().optional(),
	repositoryPath: z.string().optional(),
	scope: scanScopeSchema,
	scopePath: z.string().optional(),
});
export const createRepositoryInputSchema = z.object({ path: z.string() });
export const updateFindingStatusInputSchema = z.object({
	status: findingStatusSchema,
});
export const securityRequestBodySchema = z.union([
	createScanInputSchema,
	createRepositoryInputSchema,
	updateFindingStatusInputSchema,
]);
export type SecurityRequestBody = z.infer<typeof securityRequestBodySchema>;
export const securityApiErrorSchema = z.object({
	error: z
		.object({ code: z.string().optional(), message: z.string().optional() })
		.optional(),
});

export interface SecurityScanDetail {
	findings: Finding[];
	repository?: Repository | null;
	scan: Scan;
}
export type SecurityBridgeReply =
	| BootstrapResponse
	| Repository
	| Scan
	| Finding
	| SecurityScanDetail;
