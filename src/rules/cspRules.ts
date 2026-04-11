import { SecurityRule } from "../types";

/**
 * Content Security Policy (CSP) analysis rules.
 *
 * These detect common CSP misconfigurations found inline in code
 * (e.g. when setting the Content-Security-Policy header programmatically
 * or using <meta http-equiv="Content-Security-Policy"> values in strings).
 *
 * Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
 *            https://csp-evaluator.withgoogle.com/
 */
export const cspRules: SecurityRule[] = [
	{
		id: "CSP-UNSAFE-INLINE",
		category: "Content Security Policy",
		title: "CSP contains 'unsafe-inline'",
		description:
			"'unsafe-inline' in script-src or style-src allows inline scripts/styles, making XSS mitigations ineffective.",
		severity: "critical",
		languages: [],
		patterns: [/'unsafe-inline'/i],
		fixDescription:
			"Remove 'unsafe-inline'. Use nonces (nonce-{random}) or hashes to allow specific inline scripts.",
		reference:
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#unsafe-inline",
	},

	{
		id: "CSP-UNSAFE-EVAL",
		category: "Content Security Policy",
		title: "CSP contains 'unsafe-eval'",
		description:
			"'unsafe-eval' allows eval(), new Function(), and similar dynamic code execution, undermining XSS protection.",
		severity: "critical",
		languages: [],
		patterns: [/'unsafe-eval'/i],
		fixDescription:
			"Remove 'unsafe-eval'. Refactor code to avoid dynamic code execution.",
		reference:
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#unsafe-eval",
	},

	{
		id: "CSP-WILDCARD-SRC",
		category: "Content Security Policy",
		title: "CSP uses wildcard (*) in source directive",
		description:
			"A wildcard (*) in script-src, object-src, or default-src allows loading resources from any origin, defeating CSP.",
		severity: "critical",
		languages: [],
		patterns: [
			/(?:script-src|object-src|default-src|style-src|img-src|connect-src|font-src|media-src|frame-src)\s+[^;'"]*\*/i,
		],
		fixDescription:
			"Replace * with an explicit allowlist of trusted origins.",
		reference:
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
	},

	{
		id: "CSP-MISSING-DEFAULT-SRC",
		category: "Content Security Policy",
		title: "CSP missing default-src directive",
		description:
			"Without default-src, unspecified resource types fall back to allowing all origins.",
		severity: "warning",
		languages: [],
		patterns: [/Content-Security-Policy(?![^;\n'"]*\bdefault-src\b)/i],
		fixDescription:
			"Add 'default-src' as a catch-all fallback, e.g. default-src 'none'.",
		reference:
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/default-src",
	},

	{
		id: "CSP-MISSING-OBJECT-SRC",
		category: "Content Security Policy",
		title: "CSP missing object-src 'none'",
		description:
			"Without object-src 'none', Flash and other plugin content can be loaded and can bypass CSP entirely.",
		severity: "warning",
		languages: [],
		patterns: [/Content-Security-Policy(?![^;\n'"]*\bobject-src\b)/i],
		fixDescription:
			"Explicitly set object-src 'none' to block plugin-based content.",
		reference:
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/object-src",
	},

	{
		id: "CSP-HTTP-SOURCE",
		category: "Content Security Policy",
		title: "CSP allows HTTP sources",
		description:
			"Including http:// in source directives allows loading mixed content over unencrypted connections.",
		severity: "warning",
		languages: [],
		patterns: [
			/(?:script-src|style-src|img-src|connect-src|font-src|media-src|frame-src|default-src)\s+[^;'"]*\bhttp:\/\//i,
		],
		fixDescription:
			"Replace http:// sources with https:// to enforce encrypted connections.",
		reference:
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
	},

	{
		id: "CSP-MISSING-FRAME-ANCESTORS",
		category: "Content Security Policy",
		title: "CSP missing frame-ancestors directive",
		description:
			"Without frame-ancestors, the page can be framed by any origin, enabling clickjacking attacks.",
		severity: "warning",
		languages: [],
		patterns: [/Content-Security-Policy(?![^;\n'"]*\bframe-ancestors\b)/i],
		fixDescription:
			"Add frame-ancestors 'none' or frame-ancestors 'self' to prevent clickjacking.",
		reference:
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors",
	},

	{
		id: "CSP-REPORT-MISSING",
		category: "Content Security Policy",
		title: "CSP has no report-uri or report-to directive",
		description:
			"Without a reporting directive, CSP violations are silently ignored and attacks go undetected.",
		severity: "info",
		languages: [],
		patterns: [
			/Content-Security-Policy(?!-Report-Only)(?![^;\n'"]*\breport-(?:uri|to)\b)/i,
		],
		fixDescription:
			"Add report-to or report-uri to receive violation reports.",
		reference:
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to",
	},
];
