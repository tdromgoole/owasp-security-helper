import { SecurityRule } from "../types";

/**
 * JavaScript / TypeScript specific secure coding rules.
 * These target patterns unique to JS/TS that are not covered by the general OWASP rules.
 */
export const jsRules: SecurityRule[] = [
	// ── React: dangerouslySetInnerHTML ────────────────────────────────────────

	{
		id: "JS-DANGEROUS-INNER-HTML",
		category: "A03: Injection (XSS)",
		title: "React dangerouslySetInnerHTML with non-literal value",
		description:
			"dangerouslySetInnerHTML bypasses React's XSS protection. " +
			"Using it with a variable or user-derived value enables DOM-based XSS.",
		severity: "critical",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [/dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/],
		fixDescription:
			"Sanitize with DOMPurify before assigning. Prefer rendering text via React children instead.",
		reference: "https://owasp.org/Top10/A03_2021-Injection/",
	},

	// ── Open redirect via window.location ────────────────────────────────────

	{
		id: "JS-OPEN-REDIRECT",
		category: "A01: Broken Access Control",
		title: "Potential open redirect via window.location / res.redirect",
		description:
			"Setting window.location.href or calling res.redirect() with user-controlled " +
			"input allows attackers to redirect victims to malicious sites.",
		severity: "critical",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			/(?:window\.location(?:\.href)?\s*=|location\.replace\s*\()\s*(?:req\.|request\.|params\.|query\.|body\.)/i,
			/res\.redirect\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)/i,
			/window\.location(?:\.href)?\s*=\s*[^'"`;][^;]*(?:params|query|body|req\b)/i,
		],
		fixDescription:
			"Validate redirect targets against an allowlist of known safe paths before redirecting.",
		reference:
			"https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
	},

	// ── postMessage without origin validation ─────────────────────────────────

	{
		id: "JS-POSTMESSAGE-NO-ORIGIN",
		category: "A05: Security Misconfiguration",
		title: "postMessage event listener without origin check",
		description:
			"Handling 'message' events without verifying event.origin allows any page to " +
			"send arbitrary messages and may lead to data theft or XSS.",
		severity: "warning",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			/addEventListener\s*\(\s*['"]message['"]\s*,\s*(?:function|\(|[a-zA-Z_$])/,
		],
		fixDescription:
			"Check event.origin against a known trusted origin at the top of the message handler " +
			"and discard messages from unexpected sources.",
		reference:
			"https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns",
	},

	// ── setTimeout / setInterval with string argument ─────────────────────────

	{
		id: "JS-SETTIMEOUT-STRING",
		category: "A03: Injection",
		title: "setTimeout/setInterval called with a string argument",
		description:
			"Passing a string to setTimeout() or setInterval() causes it to be evaluated like eval(), " +
			"enabling code injection if the string contains user input.",
		severity: "critical",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			/(?:setTimeout|setInterval)\s*\(\s*(?:`[^`]*\$\{|["'][^"']*\+|[a-zA-Z_$]\w*\s*\+)/,
		],
		fixDescription:
			"Always pass a function reference or arrow function to setTimeout/setInterval, never a string.",
		reference:
			"https://developer.mozilla.org/en-US/docs/Web/API/setTimeout#code_strings_are_not_recommended",
	},

	// ── Sensitive data in localStorage / sessionStorage ───────────────────────

	{
		id: "JS-SENSITIVE-STORAGE",
		category: "A02: Cryptographic Failures",
		title: "Sensitive data stored in localStorage/sessionStorage",
		description:
			"localStorage and sessionStorage are accessible to any JS on the page. " +
			"Storing tokens, passwords, or PII there exposes them to XSS attacks.",
		severity: "warning",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			/(?:localStorage|sessionStorage)\.setItem\s*\(\s*['"`](?:token|auth|jwt|password|passwd|secret|user_?id|session|credential)/i,
		],
		fixDescription:
			"Store authentication tokens in memory or in HttpOnly cookies instead of Web Storage.",
		reference: "https://owasp.org/www-community/attacks/Web_Storage",
	},

	// ── NoSQL injection (MongoDB $where) ─────────────────────────────────────

	{
		id: "JS-NOSQL-INJECTION",
		category: "A03: Injection",
		title: "Potential NoSQL injection via $where or unsanitized operator",
		description:
			"Passing user input inside a MongoDB query object can allow attackers to inject " +
			"operators like $where, $gt, or $regex to manipulate queries.",
		severity: "critical",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			/\$where\s*:/,
			/find(?:One)?\s*\(\s*\{\s*\$(?:gt|lt|gte|lte|ne|in|nin|regex|where)\s*:/i,
			/find(?:One)?\s*\([^)]*(?:req\.|request\.|params\.|body\.|query\.)[^)]*\)/i,
		],
		fixDescription:
			"Validate and sanitize query parameters. Use allowlisted field names and typed values. " +
			"Consider libraries like mongo-sanitize.",
		reference: "https://owasp.org/www-community/attacks/NoSQL_Injection",
	},

	// ── new RegExp() with user input ──────────────────────────────────────────

	{
		id: "JS-REGEX-USER-INPUT",
		category: "A03: Injection",
		title: "new RegExp() constructed from user input",
		description:
			"Building a RegExp from user-supplied strings allows ReDoS attacks via crafted patterns " +
			"and may enable injection of regex metacharacters.",
		severity: "warning",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			/new\s+RegExp\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)/i,
			/new\s+RegExp\s*\(\s*[a-zA-Z_$]\w*\s*(?:\+|\))/,
		],
		fixDescription:
			"Escape user input with a regex-escape library before passing to RegExp, " +
			"or reject untrusted regex patterns entirely.",
		reference:
			"https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS",
	},

	// ── express res.sendFile with user input ─────────────────────────────────

	{
		id: "JS-SENDFILE-TRAVERSAL",
		category: "A01: Broken Access Control",
		title: "res.sendFile() with user-controlled path",
		description:
			"Calling res.sendFile() or res.download() with a path derived from user input " +
			"can allow directory traversal and arbitrary file disclosure.",
		severity: "critical",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			/res\.(?:sendFile|download)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)/i,
		],
		fixDescription:
			"Use path.basename() on the input and serve files only from a fixed, allow-listed directory. " +
			"Verify the resolved path starts with the intended base directory.",
		reference: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
	},

	// ── JWT verified without secret check ────────────────────────────────────

	{
		id: "JS-JWT-NO-VERIFY",
		category: "A07: Identification & Authentication Failures",
		title: "JWT decoded without signature verification",
		description:
			"Using jwt.decode() instead of jwt.verify() skips signature validation, " +
			"allowing forged tokens to be accepted.",
		severity: "critical",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [/jwt\.decode\s*\(/],
		fixDescription:
			"Always use jwt.verify(token, secret) with an explicit algorithm list. " +
			"Never trust jwt.decode() for authentication.",
		reference:
			"https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
	},

	// ── Missing rate limiting hint on auth routes ────────────────────────────

	{
		id: "JS-NO-RATE-LIMIT",
		category: "A07: Identification & Authentication Failures",
		title: "Authentication route without apparent rate limiting",
		description:
			"Login and password-reset endpoints without rate limiting are vulnerable to " +
			"brute-force and credential stuffing attacks.",
		severity: "warning",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			/(?:app|router)\.post\s*\(\s*['"`][^'"` ]*(?:login|signin|auth|token|password)[^'"` ]*['"`]/i,
		],
		fixDescription:
			"Apply a rate-limiter middleware (e.g. express-rate-limit) to all authentication endpoints.",
		reference:
			"https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
	},

	// ── Child process with user input (command injection) ────────────────────

	{
		id: "JS-CHILD-PROCESS-USER-INPUT",
		category: "A03: Injection",
		title: "child_process called with user-controlled input",
		description:
			"Passing user input to exec(), execSync(), or shell: true in spawn() " +
			"enables OS command injection.",
		severity: "critical",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			/(?:exec|execSync|execFile|execFileSync)\s*\(`[^`]*\$\{/,
			/spawn\s*\([^)]*shell\s*:\s*true/i,
			/exec\s*\(\s*["'][^"']*["']\s*\+/,
		],
		fixDescription:
			"Use execFile() or spawn() without shell:true, passing arguments as an array " +
			"rather than a single shell string.",
		reference: "https://owasp.org/Top10/A03_2021-Injection/",
	},

	// ── Insecure cookie options in Express ────────────────────────────────────

	{
		id: "JS-INSECURE-COOKIE-OPTIONS",
		category: "A07: Identification & Authentication Failures",
		title: "Express cookie set without secure/httpOnly flags",
		description:
			"Cookies without the secure flag can be sent over HTTP. " +
			"Without httpOnly, they are accessible to JavaScript and vulnerable to XSS theft.",
		severity: "warning",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			// res.cookie() where secure:true is absent from the options object
			/res\.cookie\s*\([^)]*\{(?![^}]*\bsecure\s*:\s*true)[^}]*\}/i,
		],
		fixDescription:
			"Set { secure: true, httpOnly: true, sameSite: 'Strict' } on all sensitive cookies.",
		reference:
			"https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
	},
];
