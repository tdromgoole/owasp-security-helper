import { SecurityRule } from "../types";

/**
 * HTTP Security Response Header rules.
 *
 * Two tiers:
 *  1. Document-level (documentMustMatch) — fires when a required header
 *     directive is entirely absent from an Apache/nginx .conf or .htaccess
 *     file.  Language restricted to "apacheconf" to avoid false positives on
 *     arbitrary XML files.
 *  2. Line-level (patterns) — fires when a header directive is present but
 *     configured with an insecure value.  Applies to "apacheconf" and "xml"
 *     (IIS web.config).
 *
 * Reference: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
 */

/** Restricts document-level missing-header rules to web.config files only. */
const WEB_CONFIG = /web\.config$/i;
export const httpHeaderRules: SecurityRule[] = [
	// ── Missing header rules (document-level, apacheconf + web.config) ──────────

	{
		id: "HDR-MISSING-HSTS",
		category: "HTTP Security Headers",
		title: "Missing Strict-Transport-Security (HSTS) header",
		description:
			"No Strict-Transport-Security header is configured. Without HSTS, browsers may connect via plain HTTP, exposing users to downgrade and man-in-the-middle attacks.",
		severity: "warning",
		languages: ["apacheconf", "nginx", "xml"],
		fileNamePattern: WEB_CONFIG,
		patterns: [],
		documentMustMatch: /Strict-Transport-Security/i,
		fixDescription:
			'Add: Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"',
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#strict-transport-security-hsts",
	},

	{
		id: "HDR-MISSING-CSP",
		category: "HTTP Security Headers",
		title: "Missing Content-Security-Policy header",
		description:
			"No Content-Security-Policy header is configured. Without it the browser places no restriction on which resources can be loaded, making XSS and data-injection attacks significantly more impactful.",
		severity: "warning",
		languages: ["apacheconf", "nginx", "xml"],
		fileNamePattern: WEB_CONFIG,
		patterns: [],
		documentMustMatch: /Content-Security-Policy/i,
		fixDescription:
			"Add a Content-Security-Policy header. A safe starting point: Header always set Content-Security-Policy \"default-src 'self'\"",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#content-security-policy-csp",
	},

	{
		id: "HDR-MISSING-XFO",
		category: "HTTP Security Headers",
		title: "Missing X-Frame-Options header",
		description:
			"X-Frame-Options is not set. Without it the page can be embedded in a frame or iframe on any origin, enabling clickjacking attacks.",
		severity: "warning",
		languages: ["apacheconf", "nginx", "xml"],
		fileNamePattern: WEB_CONFIG,
		patterns: [],
		documentMustMatch: /X-Frame-Options/i,
		fixDescription:
			'Add: Header always set X-Frame-Options "DENY" (use SAMEORIGIN if same-site framing is required).',
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-frame-options",
	},

	{
		id: "HDR-MISSING-XCTO",
		category: "HTTP Security Headers",
		title: "Missing X-Content-Type-Options header",
		description:
			"X-Content-Type-Options is not set. Without 'nosniff', browsers may MIME-sniff responses and execute non-script files as scripts.",
		severity: "warning",
		languages: ["apacheconf", "nginx", "xml"],
		fileNamePattern: WEB_CONFIG,
		patterns: [],
		documentMustMatch: /X-Content-Type-Options/i,
		fixDescription:
			'Add: Header always set X-Content-Type-Options "nosniff"',
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-content-type-options",
	},

	{
		id: "HDR-MISSING-REFERRER-POLICY",
		category: "HTTP Security Headers",
		title: "Missing Referrer-Policy header",
		description:
			"Referrer-Policy is not set. Without it the browser may include the full URL in the Referer header sent to third-party sites, leaking sensitive path and query-string data.",
		severity: "info",
		languages: ["apacheconf", "nginx", "xml"],
		fileNamePattern: WEB_CONFIG,
		patterns: [],
		documentMustMatch: /Referrer-Policy/i,
		fixDescription:
			'Add: Header always set Referrer-Policy "strict-origin-when-cross-origin"',
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#referrer-policy",
	},

	{
		id: "HDR-MISSING-PERMISSIONS-POLICY",
		category: "HTTP Security Headers",
		title: "Missing Permissions-Policy header",
		description:
			"Permissions-Policy is not set. Without it the browser may grant access to sensitive APIs (camera, microphone, geolocation) to pages or injected scripts without restriction.",
		severity: "info",
		languages: ["apacheconf", "nginx", "xml"],
		fileNamePattern: WEB_CONFIG,
		patterns: [],
		documentMustMatch: /Permissions-Policy/i,
		fixDescription:
			'Add: Header always set Permissions-Policy "geolocation=(), camera=(), microphone=()"',
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#permissions-policy-formerly-feature-policy",
	},

	// ── Insecure header value rules (line-level, apacheconf + xml) ────────────

	{
		id: "HDR-MISSING-COOP",
		category: "HTTP Security Headers",
		title: "Missing Cross-Origin-Opener-Policy (COOP) header",
		description:
			"Cross-Origin-Opener-Policy is not set. Without it, attackers may gain a reference to your window object via cross-origin pop-ups, enabling cross-origin information leakage (e.g. XS-Leaks) and Spectre-style attacks.",
		severity: "info",
		languages: ["apacheconf", "nginx", "xml"],
		fileNamePattern: WEB_CONFIG,
		patterns: [],
		documentMustMatch: /Cross-Origin-Opener-Policy/i,
		fixDescription:
			'Add: Header always set Cross-Origin-Opener-Policy "same-origin"  (use same-origin-allow-popups if pop-up functionality is required)',
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#cross-origin-opener-policy-coop",
	},

	{
		id: "HDR-MISSING-XSS-PROTECTION",
		category: "HTTP Security Headers",
		title: "Missing X-XSS-Protection header",
		description:
			"X-XSS-Protection is not explicitly configured. Modern browsers ignore this header in favour of CSP, but explicitly setting it to 0 prevents older browsers from enabling a built-in XSS filter that can introduce new vulnerabilities.",
		severity: "info",
		languages: ["apacheconf", "nginx", "xml"],
		fileNamePattern: WEB_CONFIG,
		patterns: [],
		documentMustMatch: /X-XSS-Protection/i,
		fixDescription:
			'Add: Header always set X-XSS-Protection "0"  (OWASP recommends disabling the legacy filter; rely on Content-Security-Policy instead)',
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-xss-protection",
	},

	// ── Insecure header value rules (line-level, apacheconf + xml) ────────────

	{
		id: "HDR-HSTS-DISABLED",
		category: "HTTP Security Headers",
		title: "HSTS explicitly disabled (max-age=0)",
		description:
			"A max-age of 0 instructs browsers to delete the stored HSTS policy, allowing future plain-HTTP connections and enabling downgrade attacks.",
		severity: "critical",
		languages: ["apacheconf", "nginx", "xml"],
		patterns: [/Strict-Transport-Security[^;\n\r]*max-age\s*=\s*0\b/i],
		fixDescription:
			'Set max-age to at least 31536000 (1 year). Recommended: "max-age=63072000; includeSubDomains; preload"',
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#strict-transport-security-hsts",
	},

	{
		id: "HDR-HSTS-NO-SUBDOMAINS",
		category: "HTTP Security Headers",
		title: "HSTS missing includeSubDomains directive",
		description:
			"The Strict-Transport-Security header does not include 'includeSubDomains'. Subdomains remain reachable over plain HTTP and are not protected against downgrade attacks.",
		severity: "warning",
		languages: ["apacheconf", "nginx", "xml"],
		// Negative lookahead: fires when the line has "Strict-Transport-Security"
		// but "includeSubDomains" does NOT appear later on the same line.
		patterns: [/Strict-Transport-Security(?![^\n\r]*includeSubDomains)/i],
		fixDescription:
			'Add "includeSubDomains" to the Strict-Transport-Security header value.',
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#strict-transport-security-hsts",
	},

	{
		id: "HDR-XFO-ALLOWALL",
		category: "HTTP Security Headers",
		title: "X-Frame-Options set to ALLOWALL",
		description:
			"ALLOWALL is not a recognised X-Frame-Options value; browsers treat it as no restriction, leaving the site fully vulnerable to clickjacking.",
		severity: "critical",
		languages: ["apacheconf", "nginx", "xml"],
		patterns: [/X-Frame-Options[:\s='"]+ALLOWALL/i],
		fixDescription: 'Change X-Frame-Options to "DENY" or "SAMEORIGIN".',
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-frame-options",
	},

	{
		id: "HDR-REFERRER-UNSAFE",
		category: "HTTP Security Headers",
		title: "Referrer-Policy set to unsafe-url",
		description:
			'"unsafe-url" sends the full URL (scheme, host, path, and query string) to all origins on every navigation, leaking potentially sensitive URL parameters to third parties.',
		severity: "warning",
		languages: ["apacheconf", "nginx", "xml"],
		patterns: [/Referrer-Policy[^\n\r]*unsafe-url/i],
		fixDescription:
			'Replace "unsafe-url" with "strict-origin-when-cross-origin" or "no-referrer".',
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#referrer-policy",
	},
];
