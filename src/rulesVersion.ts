/**
 * Tracks the current version of the bundled rule set.
 *
 * BUMP THIS when rules are added, changed, or removed so the update checker
 * can compare against the remote manifest and notify users of newer rule packs.
 *
 * Format: YYYY.MM.PATCH  (calendar versioning)
 */
export const RULES_VERSION = "2026.04.1";

/** Human-readable coverage summary shown in the report panel and notifications. */
export const RULES_METADATA: {
	readonly version: string;
	readonly owaspCoverage: string;
	readonly lastUpdated: string;
	totalRules: number;
	readonly changelogUrl: string;
} = {
	version: RULES_VERSION,
	owaspCoverage: "OWASP Top 10 (2021) — A01 through A10",
	lastUpdated: "2026-04-03",
	totalRules: 0,
	changelogUrl: "https://github.com/tdromgoole/owasp-security-helper/releases",
};
