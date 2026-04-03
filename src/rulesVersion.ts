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
export const RULES_METADATA = {
	version: RULES_VERSION,
	owaspCoverage: "OWASP Top 10 (2021) — A01 through A10",
	lastUpdated: "2026-04-03",
	totalRules: 0, // computed at runtime by updateChecker
	changelogUrl: "https://github.com/your-org/owasp-security-helper/releases",
} as const;
