import { afterEach, describe, expect, test } from "bun:test";
import { registerLiteralCatalogLoader } from "@ryu/i18n/core";
import { I18nProvider } from "@ryu/i18n/react";
import { renderToStaticMarkup } from "react-dom/server";
import { ScanCoverage } from "./App-scan-coverage.tsx";

function render(locale: string, coverage: number): string {
	return renderToStaticMarkup(
		<I18nProvider
			autoLocalizeDom={false}
			initialLocale={locale}
			initialPackId={null}
		>
			<ScanCoverage coverage={coverage} />
		</I18nProvider>
	);
}

afterEach(() => registerLiteralCatalogLoader(null));

describe("ScanCoverage", () => {
	test("keeps the English look", () => {
		expect(render("en", 91)).toBe(
			'<span class="security-coverage"><span class="security-mono">91%</span> coverage</span>'
		);
	});

	test("formats the figure for the reader and lets the sentence move it", () => {
		registerLiteralCatalogLoader(() => ({
			"<b>{coverage}</b> coverage": "Abdeckung: <b>{coverage}</b>",
		}));
		expect(render("de", 87.5)).toMatch(
			/Abdeckung: <span class="security-mono">87,5\s%<\/span>/u
		);
	});
});
