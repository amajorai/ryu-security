import { RyuAppEmpty } from "@ryu/blocks/companion/app-ui";
import { Badge, Button, Input } from "@ryu/blocks/companion/controls";
import { useLiteralMessages } from "@ryu/i18n/react";
import { useMemo, useState } from "react";
import { MetaItem, ScanStatusBadge } from "./App-shared.tsx";
import {
	formatSecurityTime,
	type Repository,
	type Scan,
	scansForRepository,
} from "./data.ts";
import { Glyph } from "./icons.tsx";

export function RepositoriesWorkspace({
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
	const tl = useLiteralMessages();
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
										{tl("{count} findings", {
											count: String(repository.findingCount),
										})}
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
	const tl = useLiteralMessages();
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
									<small>
										{tl("{count} findings", {
											count: String(scan.findingCount),
										})}
									</small>
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
