import {
	Alert02Icon,
	ArrowRight01Icon,
	CheckmarkCircle02Icon,
	Clock01Icon,
	CodeIcon,
	File01Icon,
	FilterIcon,
	Folder01Icon,
	GitBranchIcon,
	PlayIcon,
	PlusSignIcon,
	Search01Icon,
	Shield01Icon,
	StopIcon,
} from "@hugeicons/core-free-icons";
import { HugeiconsIcon } from "@hugeicons/react";

export type IconName =
	| "alert"
	| "arrow-right"
	| "check"
	| "clock"
	| "code"
	| "file"
	| "filter"
	| "folder"
	| "git-branch"
	| "play"
	| "plus"
	| "search"
	| "shield"
	| "stop";

const icons = {
	alert: Alert02Icon,
	"arrow-right": ArrowRight01Icon,
	check: CheckmarkCircle02Icon,
	clock: Clock01Icon,
	code: CodeIcon,
	file: File01Icon,
	filter: FilterIcon,
	folder: Folder01Icon,
	"git-branch": GitBranchIcon,
	play: PlayIcon,
	plus: PlusSignIcon,
	search: Search01Icon,
	shield: Shield01Icon,
	stop: StopIcon,
} as const;

export function Glyph({
	name,
	className = "",
}: {
	name: IconName;
	className?: string;
}) {
	return (
		<HugeiconsIcon
			aria-hidden="true"
			className={`security-glyph ${className}`}
			icon={icons[name]}
		/>
	);
}
