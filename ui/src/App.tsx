import {
	RyuAppActions,
	RyuAppMain,
	RyuAppToolbar,
} from "@ryu/blocks/companion/app-ui";
import { Button, Spinner } from "@ryu/blocks/companion/controls";
import { useLiteralMessages } from "@ryu/i18n/react";
import { Tabs, TabsList, TabsTrigger } from "@ryu/ui/components/tabs.tsx";
import {
	isViewVisible,
	subscribeViewVisibility,
} from "@ryu/ui/lib/view-visibility.ts";
import { useCallback, useEffect, useState } from "react";
import { FindingsWorkspace } from "./App-findings.tsx";
import { NewScanDialog } from "./App-new-scan-dialog.tsx";
import { RepositoriesWorkspace } from "./App-repositories.tsx";
import { ScansWorkspace } from "./App-scans.tsx";
import {
	cancelScan,
	generatePatch,
	getBootstrap,
	getScan,
	updateFindingStatus,
} from "./bridge.ts";
import {
	type BootstrapResponse,
	type Finding,
	findingStatusLabel,
	type Repository,
	type Scan,
	type Screen,
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
	if (!globalThis.window) {
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
	const tl = useLiteralMessages();
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
		let pending = false;
		const poll = async () => {
			if (disposed || pending || !isViewVisible()) {
				return;
			}
			pending = true;
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
			} finally {
				pending = false;
			}
		};
		const unsubscribe = subscribeViewVisibility(() => void poll());
		void poll();
		const interval = window.setInterval(poll, 700);
		return () => {
			disposed = true;
			unsubscribe();
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
			let latest: Awaited<ReturnType<typeof getScan>> | null = null;
			try {
				latest = await getScan(scan.id);
			} catch {
				// Keep the cancellation response and any findings already in memory.
			}
			setData((current) => ({
				...current,
				scans: current.scans.map((item) =>
					item.id === updated.id ? (latest?.scan ?? updated) : item
				),
				findings: latest
					? [
							...latest.findings,
							...current.findings.filter(
								(finding) => finding.scanId !== updated.id
							),
						]
					: current.findings,
			}));
			setNotice(
				(latest?.scan ?? updated).status === "canceled"
					? "Scan canceled. No files were changed."
					: "The scan ended before it could be stopped."
			);
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
					tl("Finding marked {status}.", {
						status: findingStatusLabel(updated.status).toLowerCase(),
					})
				);
			} catch (error) {
				setNotice(
					error instanceof Error ? error.message : "Could not update finding."
				);
			}
		},
		[tl]
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
			<button
				aria-controls="security-content"
				className="security-skip-link"
				onClick={() => {
					const main = document.getElementById("security-content");
					if (!main) {
						return;
					}
					main.scrollIntoView({ block: "start" });
					main.focus({ preventScroll: true });
				}}
				type="button"
			>
				Skip to Security content
			</button>
			<RyuAppMain className="security-main" id="security-content" tabIndex={-1}>
				<div className="security-navigation">
					<Tabs
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
				</div>

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
