import {
	Button,
	Dialog,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
	Input,
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
	Spinner,
	Switch,
	Textarea,
} from "@ryu/blocks/companion/controls";
import {
	NativeSelect,
	NativeSelectOption,
} from "@ryu/ui/components/native-select.tsx";
import { Tabs, TabsList, TabsTrigger } from "@ryu/ui/components/tabs.tsx";
import { useEffect, useState } from "react";
import { createRepository, createScan } from "./bridge.ts";
import type { Repository, Scan, ScanKind } from "./data.ts";
import { Glyph } from "./icons.tsx";
import { scanScopeSchema } from "./schemas.ts";

export function NewScanDialog({
	initialRepositoryId,
	onCreated,
	onOpenChange,
	open,
	repositories,
}: {
	initialRepositoryId?: string;
	onCreated: (scan: Scan, repository: Repository) => void;
	onOpenChange: (open: boolean) => void;
	open: boolean;
	repositories: Repository[];
}) {
	const [kind, setKind] = useState<ScanKind>("codebase");
	const [repositoryId, setRepositoryId] = useState(
		initialRepositoryId ?? "new"
	);
	const [path, setPath] = useState("");
	const [scope, setScope] = useState<"entire" | "folder">("entire");
	const [scopePath, setScopePath] = useState("");
	const [deep, setDeep] = useState(false);
	const [model, setModel] = useState("Ryu local static pass");
	const [reasoningEffort, setReasoningEffort] = useState("balanced");
	const [contextOpen, setContextOpen] = useState(false);
	const [attackVectors, setAttackVectors] = useState("");
	const [focusAreas, setFocusAreas] = useState("");
	const [securityContext, setSecurityContext] = useState("");
	const [submitting, setSubmitting] = useState(false);
	const [formError, setFormError] = useState<string | null>(null);

	useEffect(() => {
		if (!open) {
			return;
		}
		setKind("codebase");
		setRepositoryId(initialRepositoryId ?? repositories[0]?.id ?? "new");
		setPath("");
		setScope("entire");
		setScopePath("");
		setDeep(false);
		setModel("Ryu local static pass");
		setReasoningEffort("balanced");
		setContextOpen(false);
		setAttackVectors("");
		setFocusAreas("");
		setSecurityContext("");
		setFormError(null);
	}, [initialRepositoryId, open, repositories]);

	const submit = async () => {
		setFormError(null);
		const selectedRepository = repositories.find(
			(repository) => repository.id === repositoryId
		);
		if (!(selectedRepository || path.trim())) {
			setFormError("Enter an absolute path to an authorized repository.");
			return;
		}
		if (kind === "codebase" && scope === "folder" && !scopePath.trim()) {
			setFormError("Enter an absolute folder path inside the repository.");
			return;
		}
		setSubmitting(true);
		try {
			const repository =
				selectedRepository ?? (await createRepository(path.trim()));
			const scan = await createScan({
				additionalContext: {
					attackVectors: contextOpen ? attackVectors.trim() : "",
					focusAreas: contextOpen ? focusAreas.trim() : "",
					securityContext: contextOpen ? securityContext.trim() : "",
				},
				deep: kind === "codebase" && deep,
				kind,
				model,
				name: "",
				reasoningEffort,
				repositoryId: repository.id,
				scope: kind === "changes" ? "entire" : scope,
				scopePath:
					kind === "codebase" && scope === "folder"
						? scopePath.trim()
						: undefined,
			});
			onCreated(scan, repository);
			onOpenChange(false);
		} catch (error) {
			setFormError(
				error instanceof Error ? error.message : "Could not start scan."
			);
		} finally {
			setSubmitting(false);
		}
	};

	return (
		<Dialog onOpenChange={onOpenChange} open={open}>
			<DialogContent className="security-scan-dialog">
				<DialogHeader>
					<DialogTitle>New scan</DialogTitle>
					<DialogDescription>
						Review an authorized repository without executing its code or
						sending source off-node.
					</DialogDescription>
				</DialogHeader>

				<div className="security-dialog-body">
					<Tabs
						onValueChange={(value) => {
							if (value === "codebase" || value === "changes") {
								setKind(value);
								if (value === "changes") {
									setDeep(false);
								}
							}
						}}
						value={kind}
					>
						<div className="security-scan-type-tabs">
							<TabsList aria-label="Scan type" variant="segmented">
								<TabsTrigger value="codebase">
									<Glyph name="folder" />
									<span>
										<strong>Codebase</strong>
										<small>Review the selected repository</small>
									</span>
								</TabsTrigger>
								<TabsTrigger value="changes">
									<Glyph name="code" />
									<span>
										<strong>Changes</strong>
										<small>Review uncommitted changes</small>
									</span>
								</TabsTrigger>
							</TabsList>
						</div>
					</Tabs>

					<div className="security-form-card">
						<div className="security-form-row">
							<div className="security-form-field security-form-field-wide">
								<label htmlFor="security-repository">Repository</label>
								<NativeSelect
									aria-label="Repository"
									id="security-repository"
									name="repository"
									onChange={(event) => setRepositoryId(event.target.value)}
									value={repositoryId}
								>
									<NativeSelectOption value="new">
										Choose another folder…
									</NativeSelectOption>
									{repositories.map((repository) => (
										<NativeSelectOption
											key={repository.id}
											value={repository.id}
										>
											{repository.name} · {repository.path}
										</NativeSelectOption>
									))}
								</NativeSelect>
								{repositoryId === "new" ? (
									<Input
										aria-label="Absolute repository path"
										autoComplete="off"
										name="repository-path"
										onChange={(event) => setPath(event.target.value)}
										placeholder="e.g. /absolute/path/to/repository…"
										value={path}
									/>
								) : null}
							</div>
							<div className="security-form-field">
								<label htmlFor="security-scope">Scan area</label>
								<NativeSelect
									aria-label="Scan area"
									disabled={kind === "changes"}
									id="security-scope"
									name="scan-area"
									onChange={(event) =>
										setScope(scanScopeSchema.parse(event.target.value))
									}
									value={kind === "changes" ? "entire" : scope}
								>
									<NativeSelectOption value="entire">
										Entire repository
									</NativeSelectOption>
									<NativeSelectOption value="folder">
										Single folder
									</NativeSelectOption>
								</NativeSelect>
								{kind === "codebase" && scope === "folder" ? (
									<Input
										aria-label="Absolute folder path"
										autoComplete="off"
										name="scope-path"
										onChange={(event) => setScopePath(event.target.value)}
										placeholder="e.g. /absolute/path/to/folder…"
										value={scopePath}
									/>
								) : null}
							</div>
						</div>

						<div className="security-form-row">
							<div className="security-form-field">
								<label htmlFor="security-model">Model and reasoning</label>
								<Select onValueChange={setModel} value={model}>
									<SelectTrigger id="security-model">
										<SelectValue />
									</SelectTrigger>
									<SelectContent>
										<SelectItem value="Ryu local static pass">
											Ryu local static pass
										</SelectItem>
									</SelectContent>
								</Select>
							</div>
							<div className="security-form-field">
								<label htmlFor="security-effort">Reasoning effort</label>
								<NativeSelect
									aria-label="Reasoning effort"
									id="security-effort"
									name="reasoning-effort"
									onChange={(event) => setReasoningEffort(event.target.value)}
									value={reasoningEffort}
								>
									<NativeSelectOption value="balanced">
										Balanced
									</NativeSelectOption>
									<NativeSelectOption value="thorough">
										Thorough
									</NativeSelectOption>
									<NativeSelectOption value="deep">Deep</NativeSelectOption>
								</NativeSelect>
							</div>
						</div>

						<div className="security-toggle-row">
							<div>
								<strong>Deep scan</strong>
								<span>
									Search more extensively within the selected codebase.
								</span>
							</div>
							<Switch
								aria-label="Deep scan"
								checked={deep}
								disabled={kind === "changes"}
								onCheckedChange={setDeep}
							/>
						</div>
						<div className="security-toggle-row">
							<div>
								<strong>Additional context</strong>
								<span>
									Describe attack vectors, focus areas, and security guidance.
								</span>
							</div>
							<Switch
								aria-label="Additional context"
								checked={contextOpen}
								onCheckedChange={setContextOpen}
							/>
						</div>

						{contextOpen ? (
							<div className="security-context-fields">
								<div className="security-form-field">
									<label htmlFor="security-attack-vectors">
										Attack vectors
									</label>
									<Textarea
										id="security-attack-vectors"
										name="attack-vectors"
										onChange={(event) => setAttackVectors(event.target.value)}
										placeholder="Authentication bypass, account takeover, or prompt injection"
										value={attackVectors}
									/>
								</div>
								<div className="security-form-field">
									<label htmlFor="security-focus-areas">Focus areas</label>
									<Textarea
										id="security-focus-areas"
										name="focus-areas"
										onChange={(event) => setFocusAreas(event.target.value)}
										placeholder="Authorization, admin endpoints, file uploads, or secrets"
										value={focusAreas}
									/>
								</div>
								<div className="security-form-field">
									<label htmlFor="security-context">
										Additional security context
									</label>
									<Textarea
										id="security-context"
										name="security-context"
										onChange={(event) => setSecurityContext(event.target.value)}
										placeholder="Describe trust boundaries or known sensitive flows"
										value={securityContext}
									/>
								</div>
							</div>
						) : null}
					</div>
					{formError ? (
						<p className="security-form-error" role="alert">
							{formError}
						</p>
					) : null}
				</div>
				<DialogFooter>
					<Button onClick={() => onOpenChange(false)} variant="ghost">
						Cancel
					</Button>
					<Button disabled={submitting} onClick={() => void submit()}>
						{submitting ? (
							<Spinner className="size-4" />
						) : (
							<Glyph name="shield" />
						)}
						{submitting ? "Starting…" : "Start scan"}
					</Button>
				</DialogFooter>
			</DialogContent>
		</Dialog>
	);
}
