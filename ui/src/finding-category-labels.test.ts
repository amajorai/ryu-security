import { afterEach, describe, expect, test } from "bun:test";
import { formatMessage, type MessageValuesInput } from "@ryu/i18n/core";
// The provider registers its runtime here; a test registers a stand-in.
import {
	registerActiveI18nRuntime,
	unregisterActiveI18nRuntime,
} from "../../../../packages/i18n/src/active-locale.ts";
import { findingCategoryLabel } from "./finding-category-labels.ts";

const GERMAN: Record<string, string> = {
	"Cross-site scripting": "Cross-Site-Scripting",
	"Unsafe deserialization": "Unsichere Deserialisierung",
};

const german = {
	direction: "ltr" as const,
	locale: "de",
	translate(id: string, values?: MessageValuesInput, fallback?: string) {
		const source = fallback ?? id;
		return formatMessage(GERMAN[source] ?? source, values, "de");
	},
};

afterEach(() => unregisterActiveI18nRuntime(german));

describe("findingCategoryLabel", () => {
	test("scanner codes read as English labels, not raw codes", () => {
		expect(findingCategoryLabel("xss")).toBe("Cross-site scripting");
		expect(findingCategoryLabel("deserialization")).toBe(
			"Unsafe deserialization"
		);
		expect(findingCategoryLabel("secrets")).toBe("Secrets");
	});

	test("labels follow the active locale", () => {
		registerActiveI18nRuntime(german);
		expect(findingCategoryLabel("xss")).toBe("Cross-Site-Scripting");
		expect(findingCategoryLabel("deserialization")).toBe(
			"Unsichere Deserialisierung"
		);
	});

	test("an unknown category, or an inherited key, is shown as written", () => {
		expect(findingCategoryLabel("supply-chain")).toBe("supply-chain");
		expect(findingCategoryLabel("toString")).toBe("toString");
	});
});
