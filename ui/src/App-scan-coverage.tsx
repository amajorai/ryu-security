import { activeLocale, numberFormatter } from "@ryu/i18n/core";
import { useOptionalI18n, useRichLiteralMessages } from "@ryu/i18n/react";
import type { ReactNode } from "react";

const mono = {
	b: (chunks: ReactNode) => <span className="security-mono">{chunks}</span>,
};

/** A 0-100 coverage figure as "91%", "87,5 %" or "٩١٪" in `locale`. */
export function formatCoverage(
	percent: number,
	locale: string = activeLocale()
): string {
	return numberFormatter(locale, {
		maximumFractionDigits: 1,
		style: "percent",
	}).format(percent / 100);
}

/**
 * A completed scan's coverage as one whole message ("<b>91%</b> coverage"),
 * so a language can put the figure where its grammar wants and the percent
 * sign follows the locale ("91 %", "٩١٪").
 */
export function ScanCoverage({ coverage }: { coverage: number }) {
	const tlRich = useRichLiteralMessages();
	const locale = useOptionalI18n()?.formatLocale ?? activeLocale();
	return (
		<span className="security-coverage">
			{tlRich(
				"<b>{coverage}</b> coverage",
				{ coverage: formatCoverage(coverage, locale) },
				mono
			)}
		</span>
	);
}
