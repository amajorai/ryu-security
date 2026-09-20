import {
	RyuAppActions,
	RyuAppEmpty,
	RyuAppMain,
	RyuAppToolbar,
} from "@ryu/blocks/companion/app-ui";
import {
	Badge,
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
import {
	Progress,
	ProgressLabel,
	ProgressValue,
} from "@ryu/ui/components/progress.tsx";
import { Tabs, TabsList, TabsTrigger } from "@ryu/ui/components/tabs.tsx";
import type { ReactNode } from "react";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
	cancelScan,
	createRepository,
	createScan,
	generatePatch,
	getBootstrap,
	getScan,
	updateFindingStatus,
} from "./bridge.ts";
import {
	type BootstrapResponse,
	type Finding,
	findingStatusLabel,
	findingsForScan,
	formatSecurityTime,
	type Repository,
	type Scan,
	type ScanKind,
	type ScanStatus,
	type Screen,
	scanStatusLabel,
	scansForRepository,
	severityClass,
} from "./data.ts";
import { Glyph } from "./icons.tsx";

const EMPTY_DATA: BootstrapResponse = {
	capabilities: {
		agentVerification: false,
		evidenceLevel: "static-local",
		networkAccess: false,
		patchApplication: false,
	},
	findings: [],
	repositories: [],
	scans: [],
};

function initialScreen(): Screen {
	if (typeof window === "undefined") {
		return "scans";
	}
	const requested =
		window.ryu?.context?.screen ??
		new URLSearchParams(window.location.search).get("screen");
	return requested === "findings" || requested === "repositories"
		? requested
		: "scans";
}

export function App() {
	const [screen, setScreen] = useState<Screen>(initialScreen);
	const [data, setData] = useState<BootstrapResponse>(EMPTY_DATA);
	const [loading, setLoading] = useState(true);
	const [loadError, setLoadError] = useState<string | null>(null);
	const [notice, setNotice] = useState<string | null>(null);
	const [newScanOpen, setNewScanOpen] = useState(false);
	const [newScanRepositoryId, setNewScanRepositoryId] = useState<
		string | undefined
	>();
	const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
	const [selectedFindingId, setSelectedFindingId] = useState<string | null>(
		null
	);
	const [selectedRepositoryId, setSelectedRepositoryId] = useState<
		string | null
	>(null);
	const [patchingFindingId, setPatchingFindingId] = useState<string | null>(
		null
	);

	const refresh = useCallback(async () => {
		setLoading(true);
		try {
			const next = await getBootstrap();
			setData(next);
			setLoadError(null);
			setSelectedScanId((current) => current ?? next.scans[0]?.id ?? null);
			setSelectedFindingId(
				(current) => current ?? next.findings[0]?.id ?? null
			);
			setSelectedRepositoryId(
				(current) => current ?? next.repositories[0]?.id ?? null
			);
		} catch (error) {
			setLoadError(
				error instanceof Error
					? error.message
					: "The Security sidecar is unavailable."
			);
		} finally {
			setLoading(false);
		}
	}, []);

	useEffect(() => {
		void refresh();
	}, [refresh]);

	const selectedScan =
		data.scans.find((scan) => scan.id === selectedScanId) ?? null;
	const selectedFinding =
		data.findings.find((finding) => finding.id === selectedFindingId) ?? null;
	const selectedRepository =
		data.repositories.find(
			(repository) => repository.id === selectedRepositoryId
		) ?? null;

	useEffect(() => {
		if (
			!(selectedScan && ["pending", "running"].includes(selectedScan.status))
		) {
			return;
		}
		let disposed = false;
		const poll = async () => {
			try {
				const response = await getScan(selectedScan.id);
				if (disposed) {
					return;
				}
				setData((current) => ({
					...current,
					scans: current.scans.map((scan) =>
						scan.id === response.scan.id ? response.scan : scan
					),
					findings: [
						...response.findings,
						...current.findings.filter(
							(finding) => finding.scanId !== response.scan.id
						),
					],
				}));
			} catch {
				// The next poll or the visible sidecar error is the recovery path.
			}
		};
		void poll();
		const interval = window.setInterval(poll, 700);
		return () => {
			disposed = true;
			window.clearInterval(interval);
		};
	}, [selectedScan?.id, selectedScan?.status]);

	useEffect(() => {
		if (!notice) {
			return;
		}
		const timeout = window.setTimeout(() => setNotice(null), 3600);
		return () => window.clearTimeout(timeout);
	}, [notice]);

	const openNewScan = useCallback((repositoryId?: string) => {
		setNewScanRepositoryId(repositoryId);
		setNewScanOpen(true);
	}, []);

	const handleScanCreated = useCallback(
		(scan: Scan, repository: Repository) => {
			setData((current) => ({
				...current,
				repositories: current.repositories.some(
					(item) => item.id === repository.id
				)
					? current.repositories
					: [repository, ...current.repositories],
				scans: [scan, ...current.scans.filter((item) => item.id !== scan.id)],
			}));
			setSelectedScanId(scan.id);
			setSelectedRepositoryId(repository.id);
			setScreen("scans");
			setNotice("Scan queued. The sidecar is preparing the selected scope.");
		},
		[]
	);

	const handleCancelScan = useCallback(async (scan: Scan) => {
		try {
			const updated = await cancelScan(scan.id);
			setData((current) => ({
				...current,
				scans: current.scans.map((item) =>
					item.id === updated.id ? updated : item
				),
			}));
			setNotice("Scan canceled. No files were changed.");
		} catch (error) {
			setNotice(
				error instanceof Error ? error.message : "Could not cancel scan."
			);
		}
	}, []);

	const handleFindingStatus = useCallback(
		async (finding: Finding, status: Finding["status"]) => {
			try {
				const updated = await updateFindingStatus(finding.id, status);
				setData((current) => ({
					...current,
					findings: current.findings.map((item) =>
						item.id === updated.id ? updated : item
					),
				}));
				setNotice(
					`Finding marked ${findingStatusLabel(updated.status).toLowerCase()}.`
				);
			} catch (error) {
				setNotice(
					error instanceof Error ? error.message : "Could not update finding."
				);
			}
		},
		[]
	);

	const handleGeneratePatch = useCallback(async (finding: Finding) => {
		setPatchingFindingId(finding.id);
		try {
			const updated = await generatePatch(finding.id);
			setData((current) => ({
				...current,
				findings: current.findings.map((item) =>
					item.id === updated.id ? updated : item
				),
			}));
			setNotice("Read-only patch proposal generated for review.");
		} catch (error) {
			setNotice(
				error instanceof Error ? error.message : "Could not generate proposal."
			);
		} finally {
			setPatchingFindingId(null);
		}
	}, []);

	return (
		<>
			<RyuAppToolbar
				actions={
					<RyuAppActions>
						<div aria-label="Scanner posture" className="security-posture">
							<span className="security-posture-dot" />
							<span>Local static pass</span>
							<span className="security-posture-divider" />
							<span>No network access</span>
						</div>
						<Button onClick={() => openNewScan()} size="sm">
							<Glyph name="plus" />
							New scan
						</Button>
					</RyuAppActions>
				}
				title="Security"
			/>
			<a className="security-skip-link" href="#security-content">
				Skip to Security content
			</a>
			<RyuAppMain className="security-main" id="security-content">
				<Tabs
					className="security-navigation"
					onValueChange={(value) => {
						if (
							value === "scans" ||
							value === "findings" ||
							value === "repositories"
						) {
							setScreen(value);
						}
					}}
					value={screen}
				>
					<TabsList
						aria-label="Security sections"
						manageLayout={false}
						variant="line"
					>
						<TabsTrigger value="scans">
							<Glyph name="shield" />
							Scans
						</TabsTrigger>
						<TabsTrigger value="findings">
							<Glyph name="alert" />
							Findings
							{data.findings.length > 0 ? (
								<span className="security-tab-count">
									{data.findings.length}
								</span>
							) : null}
						</TabsTrigger>
						<TabsTrigger value="repositories">
							<Glyph name="folder" />
							Repositories
						</TabsTrigger>
					</TabsList>
				</Tabs>

				{loading ? (
					<div className="security-loading" role="status">
						<Spinner className="size-5" />
						<span>Loading the node workspace…</span>
					</div>
				) : loadError ? (
					<UnavailableState
						message={loadError}
						onRetry={() => void refresh()}
					/>
				) : screen === "scans" ? (
					<ScansWorkspace
						findings={data.findings}
						onCancel={handleCancelScan}
						onNewScan={openNewScan}
						onSelect={setSelectedScanId}
						repositories={data.repositories}
						scan={selectedScan}
						scans={data.scans}
						selectedId={selectedScanId}
					/>
				) : screen === "findings" ? (
					<FindingsWorkspace
						findings={data.findings}
						onGeneratePatch={handleGeneratePatch}
						onSelect={setSelectedFindingId}
						onStatusChange={handleFindingStatus}
						patchingFindingId={patchingFindingId}
						repositories={data.repositories}
						selectedFinding={selectedFinding}
						selectedId={selectedFindingId}
					/>
				) : (
					<RepositoriesWorkspace
						onNewScan={openNewScan}
						onSelect={setSelectedRepositoryId}
						repositories={data.repositories}
						scans={data.scans}
						selectedId={selectedRepositoryId}
						selectedRepository={selectedRepository}
					/>
				)}

				{notice ? (
					<div aria-live="polite" className="security-toast" role="status">
						<Glyph name="check" />
						{notice}
					</div>
				) : null}
			</RyuAppMain>
			<NewScanDialog
				initialRepositoryId={newScanRepositoryId}
				onCreated={handleScanCreated}
				onOpenChange={setNewScanOpen}
				open={newScanOpen}
				repositories={data.repositories}
			/>
		</>
	);
}

function UnavailableState({
	message,
	onRetry,
}: {
	message: string;
	onRetry: () => void;
}) {
	return (
		<div className="security-unavailable" role="alert">
			<div className="security-unavailable-icon">
				<Glyph name="alert" />
			</div>
			<div>
				<h3>Security is unavailable</h3>
				<p>{message}</p>
			</div>
			<Button onClick={onRetry} size="sm" variant="outline">
				Retry
			</Button>
		</div>
	);
}

function ScansWorkspace({
	findings,
	onCancel,
	onNewScan,
	onSelect,
	repositories,
	scan,
	scans,
	selectedId,
}: {
	findings: Finding[];
	onCancel: (scan: Scan) => void;
	onNewScan: (repositoryId?: string) => void;
	onSelect: (id: string) => void;
	repositories: Repository[];
	scan: Scan | null;
	scans: Scan[];
	selectedId: string | null;
}) {
	const [query, setQuery] = useState("");
	const repositoryNames = useMemo(
		() =>
			new Map(
				repositories.map((repository) => [repository.id, repository.name])
			),
		[repositories]
	);
	const filteredScans = useMemo(() => {
		const normalized = query.trim().toLowerCase();
		if (!normalized) {
			return scans;
		}
		return scans.filter((item) => {
			const repository = repositoryNames.get(item.repositoryId) ?? "";
			return `${item.name} ${repository} ${item.kind}`
				.toLowerCase()
				.includes(normalized);
		});
	}, [query, repositoryNames, scans]);

	return (
		<div className="security-workbench">
			<section aria-label="Saved scans" className="security-list-pane">
				<div className="security-list-toolbar">
					<div className="security-search">
						<Glyph name="search" />
						<Input
							aria-label="Search scans"
							autoComplete="off"
							name="scan-search"
							onChange={(event) => setQuery(event.target.value)}
							placeholder="Search scans"
							value={query}
						/>
					</div>
					<Button aria-label="Filter scans" size="icon" variant="ghost">
						<Glyph name="filter" />
					</Button>
				</div>
				<div className="security-list-heading">
					<span>Recent scans</span>
					<span className="security-list-count">{filteredScans.length}</span>
				</div>
				{filteredScans.length > 0 ? (
					<div className="security-record-list">
						{filteredScans.map((item) => (
							<ScanRow
								key={item.id}
								onSelect={onSelect}
								repositoryName={
									repositoryNames.get(item.repositoryId) ?? "Unknown repository"
								}
								scan={item}
								selected={item.id === selectedId}
							/>
						))}
					</div>
				) : (
					<RyuAppEmpty
						actions={
							<Button onClick={() => onNewScan()} size="sm">
								<Glyph name="plus" />
								Start a scan
							</Button>
						}
						description={
							query
								? "Try another search term."
								: "Scan an authorized repository to keep its evidence here."
						}
						title={query ? "No scans found" : "No scans yet"}
					/>
				)}
			</section>
			<section aria-label="Scan details" className="security-detail-pane">
				{scan ? (
					<ScanDetail
						findings={findingsForScan(findings, scan.id)}
						onCancel={onCancel}
						repository={
							repositories.find((item) => item.id === scan.repositoryId) ?? null
						}
						scan={scan}
					/>
				) : (
					<RyuAppEmpty
						description="Select a saved scan to review its phases, findings, and coverage."
						title="Choose a scan"
					/>
				)}
			</section>
		</div>
	);
}

function ScanRow({
	onSelect,
	repositoryName,
	scan,
	selected,
}: {
	onSelect: (id: string) => void;
	repositoryName: string;
	scan: Scan;
	selected: boolean;
}) {
	return (
		<button
			aria-current={selected ? "true" : undefined}
			className="security-record-row"
			data-selected={selected}
			onClick={() => onSelect(scan.id)}
			type="button"
		>
			<span className="security-record-icon">
				<Glyph name={scan.kind === "changes" ? "code" : "shield"} />
			</span>
			<span className="security-record-copy">
				<strong>{scan.name}</strong>
				<span>
					{repositoryName} ·{" "}
					{scan.deep
						? "Deep scan"
						: scan.kind === "changes"
							? "Changes"
							: "Standard scan"}
				</span>
			</span>
			<span className="security-record-meta">
				<ScanStatusBadge status={scan.status} />
				<small>{formatSecurityTime(scan.finishedAt ?? scan.startedAt)}</small>
			</span>
		</button>
	);
}

function ScanDetail({
	findings,
	onCancel,
	repository,
	scan,
}: {
	findings: Finding[];
	onCancel: (scan: Scan) => void;
	repository: Repository | null;
	scan: Scan;
}) {
	const active = scan.status === "pending" || scan.status === "running";
	return (
		<div className="security-detail-scroll">
			<div className="security-detail-header">
				<div>
					<div className="security-detail-meta">
						{scan.kind === "changes"
							? "Changes review"
							: scan.deep
								? "Deep scan"
								: "Standard scan"}
					</div>
					<h2>{scan.name}</h2>
				</div>
				<div className="security-detail-actions">
					<Button
						onClick={() =>
							document.getElementById("scan-activity")?.scrollIntoView({
								block: "start",
							})
						}
						size="sm"
						variant="ghost"
					>
						View activity
					</Button>
					{active ? (
						<Button onClick={() => onCancel(scan)} size="sm" variant="outline">
							<Glyph name="stop" />
							Stop scan
						</Button>
					) : null}
					<ScanStatusBadge status={scan.status} />
				</div>
			</div>

			<div className="security-meta-grid">
				<MetaItem icon="clock" label="Status">
					{scanStatusLabel(scan.status)}
				</MetaItem>
				<MetaItem icon="code" label="Model">
					{scan.model} · {scan.reasoningEffort}
				</MetaItem>
				<MetaItem icon="git-branch" label="Revision">
					<span className="security-mono">
						{repository?.head ?? "Not available"}
					</span>
					<span className="security-submeta">
						{repository?.branch ?? "Not available"}
					</span>
				</MetaItem>
				<MetaItem icon="folder" label="Repository">
					{repository?.name ?? "Unknown repository"}
					<span className="security-submeta security-path">
						{repository?.path ?? "Unavailable"}
					</span>
				</MetaItem>
				<MetaItem icon="alert" label="Findings">
					<span className="security-mono">{scan.findingCount}</span>
				</MetaItem>
				<MetaItem icon="file" label="Files in scope">
					<span className="security-mono">{scan.fileCount}</span>
				</MetaItem>
				<MetaItem icon="shield" label="Scope">
					{scan.scope === "folder"
						? (scan.scopePath ?? "Selected folder")
						: "Entire repository"}
				</MetaItem>
				<MetaItem icon="check" label="Evidence">
					<span className="security-evidence-label">{scan.evidenceLevel}</span>
				</MetaItem>
			</div>

			{active ? (
				<div className="security-progress-card">
					<div className="security-progress-head">
						<div>
							<strong>{phaseLabel(scan)}</strong>
							<span>{scan.progress}% complete · local static analysis</span>
						</div>
						<span className="security-live-indicator">Live</span>
					</div>
					<Progress value={scan.progress}>
						<ProgressLabel className="sr-only">Scan progress</ProgressLabel>
						<ProgressValue className="sr-only" />
					</Progress>
				</div>
			) : null}

			<section className="security-section" id="scan-activity">
				<div className="security-section-heading">
					<div>
						<h3>Scan activity</h3>
						<p>Each phase is retained with the scan record.</p>
					</div>
					<span className="security-evidence-label">{scan.evidenceLevel}</span>
				</div>
				<div className="security-phase-list">
					{scan.phases.map((phase) => (
						<div
							className="security-phase"
							data-status={phase.status}
							key={phase.key}
						>
							<span className="security-phase-icon">
								<Glyph
									name={
										phase.status === "completed"
											? "check"
											: phase.status === "running"
												? "clock"
												: "shield"
									}
								/>
							</span>
							<span className="security-phase-copy">
								<strong>{phase.label}</strong>
								<span>{phase.detail}</span>
							</span>
						</div>
					))}
				</div>
				{scan.error ? (
					<p className="security-error-copy">{scan.error}</p>
				) : null}
			</section>

			<section className="security-section">
				<div className="security-section-heading">
					<div>
						<h3>Findings</h3>
						<p>
							{scan.status === "completed"
								? `${scan.findingCount} candidate${scan.findingCount === 1 ? "" : "s"} retained from this scan.`
								: "Findings appear here after the scan records them."}
						</p>
					</div>
					{scan.status === "completed" ? (
						<span className="security-coverage">
							<span className="security-mono">{scan.coverage}%</span> coverage
						</span>
					) : null}
				</div>
				{findings.length > 0 ? (
					<div className="security-inline-findings">
						{findings.slice(0, 8).map((finding) => (
							<div className="security-inline-finding" key={finding.id}>
								<span
									className={`security-severity-mark ${severityClass(finding.severity)}`}
								/>
								<span>
									<strong>{finding.title}</strong>
									<span>
										{finding.location.path}:{finding.location.line} ·{" "}
										{finding.validation}
									</span>
								</span>
								<Badge variant="outline">{finding.severity}</Badge>
							</div>
						))}
					</div>
				) : (
					<div className="security-inline-empty">
						<Glyph name={scan.status === "completed" ? "check" : "clock"} />
						<span>
							<strong>
								{scan.status === "completed"
									? "No candidates recorded"
									: "Waiting for results"}
							</strong>
							<small>
								{scan.status === "completed"
									? "Static analysis found no matching signals in the bounded scope."
									: "The scanner keeps this result live while the sidecar works."}
							</small>
						</span>
					</div>
				)}
			</section>
		</div>
	);
}

function phaseLabel(scan: Scan): string {
	return (
		scan.phases.find((phase) => phase.key === scan.phase)?.label ??
		"Reviewing code"
	);
}

function MetaItem({
	children,
	icon,
	label,
}: {
	children: ReactNode;
	icon:
		| "alert"
		| "check"
		| "clock"
		| "code"
		| "file"
		| "folder"
		| "git-branch"
		| "shield";
	label: string;
}) {
	return (
		<div className="security-meta-item">
			<Glyph name={icon} />
			<span className="security-meta-label">{label}</span>
			<span className="security-meta-value">{children}</span>
		</div>
	);
}

function ScanStatusBadge({ status }: { status: ScanStatus }) {
	return (
		<Badge
			className={`security-status-badge security-status-${status}`}
			variant="outline"
		>
			<span className="security-status-dot" />
			{scanStatusLabel(status)}
		</Badge>
	);
}

function FindingsWorkspace({
	findings,
	onGeneratePatch,
	onSelect,
	onStatusChange,
	patchingFindingId,
	repositories,
	selectedFinding,
	selectedId,
}: {
	findings: Finding[];
	onGeneratePatch: (finding: Finding) => void;
	onSelect: (id: string) => void;
	onStatusChange: (finding: Finding, status: Finding["status"]) => void;
	patchingFindingId: string | null;
	repositories: Repository[];
	selectedFinding: Finding | null;
	selectedId: string | null;
}) {
	const [query, setQuery] = useState("");
	const [severity, setSeverity] = useState("all");
	const repositoryNames = useMemo(
		() =>
			new Map(
				repositories.map((repository) => [repository.id, repository.name])
			),
		[repositories]
	);
	const filteredFindings = useMemo(() => {
		const normalized = query.trim().toLowerCase();
		return findings.filter((finding) => {
			const searchMatch =
				!normalized ||
				`${finding.title} ${finding.location.path} ${finding.category} ${repositoryNames.get(finding.repositoryId) ?? ""}`
					.toLowerCase()
					.includes(normalized);
			const severityMatch =
				severity === "all" || finding.severity.toLowerCase() === severity;
			return searchMatch && severityMatch;
		});
	}, [findings, query, repositoryNames, severity]);

	return (
		<div className="security-workbench">
			<section aria-label="Saved findings" className="security-list-pane">
				<div className="security-list-toolbar">
					<div className="security-search">
						<Glyph name="search" />
						<Input
							aria-label="Search findings"
							autoComplete="off"
							name="finding-search"
							onChange={(event) => setQuery(event.target.value)}
							placeholder="Search title, repository, or path"
							value={query}
						/>
					</div>
					<NativeSelect
						aria-label="Filter findings by severity"
						className="security-severity-filter"
						onChange={(event) => setSeverity(event.target.value)}
						value={severity}
					>
						<NativeSelectOption value="all">All severities</NativeSelectOption>
						<NativeSelectOption value="high">High</NativeSelectOption>
						<NativeSelectOption value="medium">Medium</NativeSelectOption>
						<NativeSelectOption value="low">Low</NativeSelectOption>
					</NativeSelect>
				</div>
				<div className="security-list-heading">
					<span>Saved findings</span>
					<span className="security-list-count">{filteredFindings.length}</span>
				</div>
				{filteredFindings.length > 0 ? (
					<div className="security-record-list">
						{filteredFindings.map((finding) => (
							<FindingRow
								finding={finding}
								key={finding.id}
								onSelect={onSelect}
								repositoryName={
									repositoryNames.get(finding.repositoryId) ??
									"Unknown repository"
								}
								selected={finding.id === selectedId}
							/>
						))}
					</div>
				) : (
					<RyuAppEmpty
						description={
							findings.length > 0
								? "Try another search or severity filter."
								: "Completed scans will keep reportable candidates here."
						}
						title={
							findings.length > 0 ? "No findings found" : "No findings yet"
						}
					/>
				)}
			</section>
			<section aria-label="Finding details" className="security-detail-pane">
				{selectedFinding ? (
					<FindingDetail
						finding={selectedFinding}
						onGeneratePatch={onGeneratePatch}
						onStatusChange={onStatusChange}
						patching={patchingFindingId === selectedFinding.id}
						repositoryName={
							repositoryNames.get(selectedFinding.repositoryId) ??
							"Unknown repository"
						}
					/>
				) : (
					<RyuAppEmpty
						description="Select a finding to review its evidence, attack path, and remediation."
						title="Choose a finding"
					/>
				)}
			</section>
		</div>
	);
}

function FindingRow({
	finding,
	onSelect,
	repositoryName,
	selected,
}: {
	finding: Finding;
	onSelect: (id: string) => void;
	repositoryName: string;
	selected: boolean;
}) {
	return (
		<button
			aria-current={selected ? "true" : undefined}
			className="security-record-row security-finding-row"
			data-selected={selected}
			onClick={() => onSelect(finding.id)}
			type="button"
		>
			<span
				className={`security-severity-mark ${severityClass(finding.severity)}`}
			/>
			<span className="security-record-copy">
				<strong>{finding.title}</strong>
				<span>
					{repositoryName} · {finding.location.path}:{finding.location.line}
				</span>
			</span>
			<span className="security-record-meta">
				<Badge
					className={`security-finding-badge ${severityClass(finding.severity)}`}
					variant="outline"
				>
					{finding.severity}
				</Badge>
				<small>{findingStatusLabel(finding.status)}</small>
			</span>
		</button>
	);
}

function FindingDetail({
	finding,
	onGeneratePatch,
	onStatusChange,
	patching,
	repositoryName,
}: {
	finding: Finding;
	onGeneratePatch: (finding: Finding) => void;
	onStatusChange: (finding: Finding, status: Finding["status"]) => void;
	patching: boolean;
	repositoryName: string;
}) {
	const [view, setView] = useState<"summary" | "patch">("summary");
	const canReopen = finding.status !== "open";
	return (
		<div className="security-detail-scroll">
			<div className="security-detail-header">
				<div>
					<div className="security-detail-meta">
						{repositoryName} · {finding.category}
					</div>
					<h2>{finding.title}</h2>
				</div>
				<div className="security-detail-actions">
					<Button
						onClick={() =>
							onStatusChange(finding, canReopen ? "open" : "closed")
						}
						size="sm"
						variant="outline"
					>
						{canReopen ? "Reopen finding" : "Close finding"}
					</Button>
					<Badge
						className={`security-finding-badge ${severityClass(finding.severity)}`}
						variant="outline"
					>
						{finding.severity}
					</Badge>
				</div>
			</div>

			<div className="security-finding-meta">
				<MetaItem icon="alert" label="Severity">
					{finding.severity}
				</MetaItem>
				<MetaItem icon="check" label="Validation">
					{finding.validation}
				</MetaItem>
				<MetaItem icon="shield" label="Confidence">
					{finding.confidence}
				</MetaItem>
				<MetaItem icon="clock" label="Status">
					{findingStatusLabel(finding.status)}
				</MetaItem>
				<MetaItem icon="code" label="Category">
					{finding.category}
				</MetaItem>
				<MetaItem icon="code" label="CWE">
					{finding.cwe}
				</MetaItem>
				<MetaItem icon="file" label="Location">
					<span className="security-mono">
						{finding.location.path}:{finding.location.line}
					</span>
				</MetaItem>
			</div>

			<Tabs
				className="security-detail-tabs"
				onValueChange={(value) => {
					if (value === "summary" || value === "patch") {
						setView(value);
					}
				}}
				value={view}
			>
				<TabsList
					aria-label="Finding views"
					manageLayout={false}
					variant="line"
				>
					<TabsTrigger value="summary">Summary</TabsTrigger>
					<TabsTrigger value="patch">Patch</TabsTrigger>
				</TabsList>
			</Tabs>

			{view === "summary" ? (
				<div className="security-finding-body">
					<DetailBlock title="Summary">
						<p>{finding.summary ?? "This finding has no summary."}</p>
					</DetailBlock>
					<DetailBlock title="Root cause">
						<p>{finding.rootCause}</p>
					</DetailBlock>
					<DetailBlock title="Impact">
						<p>{finding.impact}</p>
					</DetailBlock>
					<DetailBlock title="Attack path">
						<div className="security-attack-path">
							{finding.attackPath.map((step, index) => (
								<div
									className="security-attack-step"
									key={`${finding.id}-step-${index}`}
								>
									<span>{index + 1}</span>
									<p>{step}</p>
								</div>
							))}
						</div>
					</DetailBlock>
					<div className="security-evidence-columns">
						<DetailBlock title="Evidence">
							<EvidenceList items={finding.evidence} />
						</DetailBlock>
						<DetailBlock title="Counterevidence">
							<EvidenceList items={finding.counterevidence} muted />
						</DetailBlock>
					</div>
					<DetailBlock title="Remediation">
						<p>{finding.remediation}</p>
					</DetailBlock>
				</div>
			) : (
				<div className="security-patch-view">
					<div className="security-patch-callout">
						<Glyph name="shield" />
						<div>
							<strong>Read-only proposal</strong>
							<p>
								Security prepares a reviewable next step and never changes the
								checkout.
							</p>
						</div>
					</div>
					{finding.patch ? (
						<pre className="security-code-block">{finding.patch}</pre>
					) : (
						<div className="security-patch-empty">
							<p>Generate a minimal remediation proposal for this finding.</p>
							<Button
								disabled={patching}
								onClick={() => onGeneratePatch(finding)}
								size="sm"
							>
								{patching ? (
									<Spinner className="size-4" />
								) : (
									<Glyph name="code" />
								)}
								{patching ? "Generating…" : "Generate patch proposal"}
							</Button>
						</div>
					)}
				</div>
			)}
		</div>
	);
}

function DetailBlock({
	children,
	title,
}: {
	children: ReactNode;
	title: string;
}) {
	return (
		<section className="security-detail-block">
			<h3>{title}</h3>
			{children}
		</section>
	);
}

function EvidenceList({
	items,
	muted = false,
}: {
	items: string[];
	muted?: boolean;
}) {
	return (
		<ul
			className={
				muted ? "security-evidence-list is-muted" : "security-evidence-list"
			}
		>
			{items.map((item) => (
				<li key={item}>
					<span aria-hidden="true">•</span>
					{item}
				</li>
			))}
		</ul>
	);
}

function RepositoriesWorkspace({
	onNewScan,
	onSelect,
	repositories,
	scans,
	selectedId,
	selectedRepository,
}: {
	onNewScan: (repositoryId?: string) => void;
	onSelect: (id: string) => void;
	repositories: Repository[];
	scans: Scan[];
	selectedId: string | null;
	selectedRepository: Repository | null;
}) {
	const [query, setQuery] = useState("");
	const filteredRepositories = useMemo(() => {
		const normalized = query.trim().toLowerCase();
		return normalized
			? repositories.filter((repository) =>
					`${repository.name} ${repository.path}`
						.toLowerCase()
						.includes(normalized)
				)
			: repositories;
	}, [query, repositories]);

	return (
		<div className="security-workbench">
			<section aria-label="Repositories" className="security-list-pane">
				<div className="security-list-toolbar">
					<div className="security-search">
						<Glyph name="search" />
						<Input
							aria-label="Search repositories"
							autoComplete="off"
							name="repository-search"
							onChange={(event) => setQuery(event.target.value)}
							placeholder="Search name or path"
							value={query}
						/>
					</div>
					<Button aria-label="Filter repositories" size="icon" variant="ghost">
						<Glyph name="filter" />
					</Button>
				</div>
				<div className="security-list-heading">
					<span>Repositories</span>
					<span className="security-list-count">
						{filteredRepositories.length}
					</span>
				</div>
				{filteredRepositories.length > 0 ? (
					<div className="security-record-list">
						{filteredRepositories.map((repository) => (
							<button
								aria-current={repository.id === selectedId ? "true" : undefined}
								className="security-record-row"
								data-selected={repository.id === selectedId}
								key={repository.id}
								onClick={() => onSelect(repository.id)}
								type="button"
							>
								<span className="security-record-icon">
									<Glyph name="folder" />
								</span>
								<span className="security-record-copy">
									<strong>{repository.name}</strong>
									<span>{repository.path}</span>
								</span>
								<span className="security-record-meta">
									<Badge variant="outline">
										{repository.findingCount} findings
									</Badge>
									<small>{repository.status}</small>
								</span>
							</button>
						))}
					</div>
				) : (
					<RyuAppEmpty
						actions={
							<Button onClick={() => onNewScan()} size="sm">
								<Glyph name="plus" /> Add repository
							</Button>
						}
						description={
							query
								? "Try another search term."
								: "Add a repository when you are ready to review it."
						}
						title={query ? "No repositories found" : "No repositories yet"}
					/>
				)}
			</section>
			<section aria-label="Repository details" className="security-detail-pane">
				{selectedRepository ? (
					<RepositoryDetail
						onNewScan={onNewScan}
						repository={selectedRepository}
						scans={scansForRepository(scans, selectedRepository.id)}
					/>
				) : (
					<RyuAppEmpty
						description="Select a repository to inspect its revision, scan history, and findings."
						title="Choose a repository"
					/>
				)}
			</section>
		</div>
	);
}

function RepositoryDetail({
	onNewScan,
	repository,
	scans,
}: {
	onNewScan: (repositoryId?: string) => void;
	repository: Repository;
	scans: Scan[];
}) {
	return (
		<div className="security-detail-scroll">
			<div className="security-detail-header">
				<div>
					<div className="security-detail-meta">Repository</div>
					<h2>{repository.name}</h2>
					<p className="security-repository-path">{repository.path}</p>
				</div>
				<Button onClick={() => onNewScan(repository.id)} size="sm">
					<Glyph name="plus" />
					New scan
				</Button>
			</div>
			<div className="security-meta-grid">
				<MetaItem icon="git-branch" label="Branch">
					{repository.branch}
				</MetaItem>
				<MetaItem icon="code" label="Last scanned commit">
					<span className="security-mono">{repository.head}</span>
				</MetaItem>
				<MetaItem icon="file" label="Files">
					<span className="security-mono">{repository.fileCount}</span>
				</MetaItem>
				<MetaItem icon="alert" label="Findings">
					<span className="security-mono">{repository.findingCount}</span>
				</MetaItem>
				<MetaItem icon="shield" label="Scans">
					<span className="security-mono">{repository.scanCount}</span>
				</MetaItem>
				<MetaItem icon="clock" label="Last scan">
					{formatSecurityTime(repository.lastScannedAt)}
				</MetaItem>
			</div>
			<section className="security-section">
				<div className="security-section-heading">
					<div>
						<h3>Recent scans</h3>
						<p>Saved scan history for this repository.</p>
					</div>
				</div>
				{scans.length > 0 ? (
					<div className="security-repository-scans">
						{scans.map((scan) => (
							<div className="security-repository-scan" key={scan.id}>
								<span className="security-record-icon">
									<Glyph name="shield" />
								</span>
								<span className="security-record-copy">
									<strong>{scan.name}</strong>
									<span>
										{scan.kind === "changes"
											? "Changes review"
											: scan.deep
												? "Deep scan"
												: "Standard scan"}{" "}
										· {formatSecurityTime(scan.finishedAt ?? scan.startedAt)}
									</span>
								</span>
								<span className="security-record-meta">
									<ScanStatusBadge status={scan.status} />
									<small>{scan.findingCount} findings</small>
								</span>
							</div>
						))}
					</div>
				) : (
					<div className="security-inline-empty">
						<Glyph name="clock" />
						<span>
							<strong>No scans yet</strong>
							<small>Start the first review from this repository.</small>
						</span>
					</div>
				)}
			</section>
		</div>
	);
}

function NewScanDialog({
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
						<TabsList
							aria-label="Scan type"
							className="security-scan-type-tabs"
							variant="segmented"
						>
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
										setScope(event.target.value as "entire" | "folder")
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
