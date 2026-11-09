// A finding's `category` is a code the scanner writes ("xss",
// "deserialization"); show a translated label wherever the UI renders it on
// its own. A category the table does not know (a provider-backed scan may
// report its own) is shown as written.
import { translate as tl } from "@ryu/i18n/core";

const CATEGORY_LABELS: Record<string, () => string> = {
	deserialization: () => tl("Unsafe deserialization"),
	injection: () => tl("Injection"),
	network: () => tl("Network request"),
	secrets: () => tl("Secrets"),
	xss: () => tl("Cross-site scripting"),
};

/** The label for a finding category code, in the active locale. */
export function findingCategoryLabel(category: string): string {
	const label = Object.hasOwn(CATEGORY_LABELS, category)
		? CATEGORY_LABELS[category]
		: undefined;
	return label ? label() : category;
}
