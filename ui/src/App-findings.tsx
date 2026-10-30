import { RyuAppEmpty } from "@ryu/blocks/companion/app-ui";
import { Badge, Button, Input, Spinner } from "@ryu/blocks/companion/controls";
import {
	NativeSelect,
	NativeSelectOption,
} from "@ryu/ui/components/native-select.tsx";
import { Tabs, TabsList, TabsTrigger } from "@ryu/ui/components/tabs.tsx";
import type { ReactNode } from "react";
import { useMemo, useState } from "react";
import { MetaItem } from "./App-shared.tsx";
import {
	type Finding,
	findingStatusLabel,
	type Repository,
	severityClass,
} from "./data.ts";
import { Glyph } from "./icons.tsx";

export function FindingsWorkspace({
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
					<div className="security-severity-filter">
						<NativeSelect
							aria-label="Filter findings by severity"
							className="w-full"
							onChange={(event) => setSeverity(event.target.value)}
							value={severity}
						>
							<NativeSelectOption value="all">
								All severities
							</NativeSelectOption>
							<NativeSelectOption value="high">High</NativeSelectOption>
							<NativeSelectOption value="medium">Medium</NativeSelectOption>
							<NativeSelectOption value="low">Low</NativeSelectOption>
						</NativeSelect>
					</div>
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

			<div className="security-detail-tabs">
				<Tabs
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
			</div>

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
