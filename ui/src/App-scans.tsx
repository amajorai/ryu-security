import { RyuAppEmpty } from "@ryu/blocks/companion/app-ui";
import { Badge, Button, Input } from "@ryu/blocks/companion/controls";
import { useLiteralMessages } from "@ryu/i18n/react";
import {
	Progress,
	ProgressLabel,
	ProgressValue,
} from "@ryu/ui/components/progress.tsx";
import { useEffect, useMemo, useState } from "react";
import { MetaItem, ScanStatusBadge } from "./App-shared.tsx";
import {
	type Finding,
	findingsForScan,
	formatSecurityTime,
	type Repository,
	type Scan,
	scanStatusLabel,
	severityClass,
} from "./data.ts";
import { Glyph } from "./icons.tsx";

export function ScansWorkspace({
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
	onSelect: (id: string | null) => void;
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
	useEffect(() => {
		if (selectedId && filteredScans.some((item) => item.id === selectedId)) {
			return;
		}
		onSelect(filteredScans[0]?.id ?? null);
	}, [filteredScans, onSelect, selectedId]);

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
	const tl = useLiteralMessages();
	const findingCountText = String(scan.findingCount);
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
							<span>
								{tl("{progress}% complete · local static analysis", {
									progress: scan.progress,
								})}
							</span>
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
								? tl(
										"{count, plural, =1 {{countText} candidate retained from this scan.} other {{countText} candidates retained from this scan.}}",
										{ count: scan.findingCount, countText: findingCountText }
									)
								: scan.status === "canceled"
									? tl(
											"{count, plural, =1 {{countText} candidate retained before cancellation.} other {{countText} candidates retained before cancellation.}}",
											{ count: scan.findingCount, countText: findingCountText }
										)
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
									: scan.status === "canceled"
										? scan.findingCount > 0
											? "Partial results are syncing"
											: "No findings before cancellation"
										: "Waiting for results"}
							</strong>
							<small>
								{scan.status === "completed"
									? "Static analysis found no matching signals in the bounded scope."
									: scan.status === "canceled"
										? scan.findingCount > 0
											? tl(
													"{count, plural, =1 {{countText} candidate was saved before the scan stopped. No files were changed.} other {{countText} candidates were saved before the scan stopped. No files were changed.}}",
													{
														count: scan.findingCount,
														countText: findingCountText,
													}
												)
											: "The scan stopped before it recorded any candidates. No files were changed."
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
