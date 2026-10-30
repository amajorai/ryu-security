import { Badge } from "@ryu/blocks/companion/controls";
import type { ReactNode } from "react";
import { type ScanStatus, scanStatusLabel } from "./data.ts";
import { Glyph } from "./icons.tsx";

export function MetaItem({
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

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
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
