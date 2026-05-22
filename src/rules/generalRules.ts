import { SecurityRule } from "../types";

/**
 * General secure-coding best-practice rules that go beyond the OWASP Top 10.
 * Covers: insecure HTTP, prototype pollution, XXE, ReDoS, sensitive data exposure.
 */
export const generalRules: SecurityRule[] = [
	// ── Insecure Transport ──────────────────────────────────────────────────

	{
		id: "GEN-HTTP-URL",
		category: "Insecure Communication",
		title: "Hardcoded HTTP URL (non-HTTPS)",
		description:
			"HTTP URLs transmit data in plain text. Use HTTPS for all external communication.",
		severity: "warning",
		languages: [],
		patterns: [/['"`]http:\/\/(?!localhost|127\.0\.0\.1)/i],
		fixDescription:
			"Replace 'http://' with 'https://' for all production URLs.",
		reference:
			"https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels",
	},

	{
		id: "GEN-TLS-REJECT-DISABLED",
		category: "Insecure Communication",
		title: "TLS certificate validation disabled",
		description:
			"Setting rejectUnauthorized: false or VERIFY_NONE disables certificate validation, enabling MitM attacks.",
		severity: "critical",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
			"python",
		],
		patterns: [
			/rejectUnauthorized\s*:\s*false/i,
			/verify\s*=\s*False/,
			/ssl_verify\s*=\s*False/i,
			/VERIFY_NONE/,
		],
		fixDescription:
			"Never disable TLS verification. Fix the certificate or trust the correct CA instead.",
		reference: "https://owasp.org/www-project-web-security-testing-guide/",
	},

	// ── Prototype Pollution ─────────────────────────────────────────────────

	{
		id: "GEN-PROTOTYPE-POLLUTION",
		category: "Prototype Pollution",
		title: "Potential prototype pollution",
		description:
			"Merging or assigning user-controlled objects without key filtering can pollute Object.prototype.",
		severity: "warning",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			/Object\.assign\s*\(\s*(?:target|obj|options|config|defaults)\s*,\s*(?:req\.|request\.|body|params|query)/i,
			/\.\.\.\s*(?:req\.|request\.|body|params|query)/i,
		],
		fixDescription:
			"Use Object.create(null) for accumulator objects, or validate/sanitize keys before merge.",
		reference:
			"https://owasp.org/www-community/vulnerabilities/Prototype_Pollution",
	},

	// ── XXE ─────────────────────────────────────────────────────────────────

	{
		id: "GEN-XXE",
		category: "XML External Entity (XXE)",
		title: "Potential XXE via insecure XML parser",
		description:
			"Parsing untrusted XML without disabling external entity processing can leak internal files or trigger SSRF.",
		severity: "critical",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
			"python",
			"php",
		],
		patterns: [
			/new\s+DOMParser\s*\(\s*\)/,
			/libxml\.parse\s*\(/i,
			/simplexml_load_string\s*\(/i,
			/xml\.etree\.ElementTree\.parse\s*\(/i,
		],
		fixDescription:
			"Disable external entity processing (e.g. libxml2 NOENT / NONET flags, defusedxml in Python).",
		reference:
			"https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
	},

	// ── ReDoS ───────────────────────────────────────────────────────────────

	{
		id: "GEN-REDOS",
		category: "Regular Expression Denial of Service",
		title: "Potentially vulnerable regex (ReDoS)",
		description:
			"Certain regex patterns with nested quantifiers can cause catastrophic backtracking on crafted input.",
		severity: "warning",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
			"python",
			"php",
		],
		patterns: [
			/\(\.[*+]\)[*+]/, // (.*)*  or  (.+)+  patterns
			/\([^)]*[*+][^)]*\)[*+]/, // (a+b)*
		],
		fixDescription:
			"Rewrite the regex to avoid nested quantifiers or use a ReDoS-resistant library.",
		reference:
			"https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS",
	},

	// ── Sensitive Data Exposure ─────────────────────────────────────────────

	{
		id: "GEN-SENSITIVE-COMMENT",
		category: "Sensitive Data Exposure",
		title: "Sensitive data in comment",
		description:
			"Comments containing passwords, tokens, or credentials may be committed to source control.",
		severity: "warning",
		languages: [],
		patterns: [
			/(?:\/\/|#|\/\*)\s*(?:password|token|secret|api.?key|credential)\s*[:=]\s*\S+/i,
		],
		fixDescription:
			"Remove credentials from comments. Store them in environment variables or a secrets manager.",
	},

	// ── Insecure File Operations ────────────────────────────────────────────

	{
		id: "GEN-WORLD-WRITABLE",
		category: "Insecure File Permissions",
		title: "World-writable file permission (0777)",
		description:
			"Setting file permissions to 0777 grants read/write/execute access to all users on the system.",
		severity: "warning",
		languages: [
			"python",
			"php",
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			/(?:chmod|os\.chmod)\s*\([^,)]+,\s*0o?777\s*\)/i,
			/fs\.chmod\s*\([^,)]+,\s*0o?777/i,
		],
		fixDescription:
			"Use restrictive permissions such as 0600 (owner read/write) or 0644 (owner write, others read).",
		reference:
			"https://owasp.org/www-community/vulnerabilities/Insecure_File_Upload",
	},

	// ── Hardcoded cloud / service credentials ────────────────────────────────

	{
		id: "GEN-HARDCODED-CLOUD-KEY",
		category: "A02: Cryptographic Failures",
		title: "Hardcoded cloud or service credential",
		description:
			"AWS access key IDs, GCP API keys, and private key PEM blocks found in source " +
			"code can be harvested from version control and used to access cloud resources, " +
			"decrypt data, or sign malicious payloads.",
		severity: "critical",
		languages: [],
		patterns: [
			// AWS access key ID (starts with AKIA, ASIA, AROA, or AIDA followed by 16 uppercase alphanumeric chars)
			/(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}/,
			// Private key PEM block header
			/-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
			// GCP API key (AIza prefix, 35 chars)
			/AIza[0-9A-Za-z_\-]{35}/,
		],
		fixDescription:
			"Remove credentials from source code immediately and rotate any exposed keys. " +
			"Store secrets in environment variables or a secrets manager (AWS Secrets Manager, " +
			"HashiCorp Vault, Azure Key Vault, GCP Secret Manager). Add secret patterns to .gitignore.",
		reference: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
	},
];
