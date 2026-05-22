/**
 * inputValidationRules.ts
 *
 * Security rules derived from the OWASP Input Validation and File Upload Cheat Sheets,
 * targeting JavaScript/TypeScript (Node.js/Express) and Python (Flask/Django).
 * PHP-specific rules are covered in phpInputValidationRules.ts.
 *
 * References:
 *  - https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
 *  - https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
 */

import { SecurityRule } from "../types";

export const inputValidationRules: SecurityRule[] = [
	// ══════════════════════════════════════════════════════════════════════════
	//  JavaScript / TypeScript — File Upload
	// ══════════════════════════════════════════════════════════════════════════

	// ── Trusting multer-supplied MIME type ────────────────────────────────────

	{
		id: "IV-JS-UPLOAD-MIME-TRUST",
		category: "A04: Insecure Design",
		title: "Trusting browser-supplied MIME type for file upload validation",
		description:
			"req.file.mimetype is taken from the Content-Type header sent by the browser " +
			"and is entirely client-controlled. An attacker can label a PHP or EXE file " +
			"as image/jpeg to bypass this check. MIME type must be determined server-side " +
			"from the file's own magic bytes.",
		severity: "critical",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			// mimetype compared with === / !== / == / !=
			/req\.files?\s*(?:\[.*?\])?\s*(?:\[\d+\])?\.mimetype\s*(?:===?|!==?)/i,
			// mimetype inside an if / switch condition
			/(?:if|switch)\s*\([^)]*req\.files?\.mimetype/i,
			// mimetype passed to .includes() or .startsWith() as a security gate
			/(?:includes|startsWith)\s*\(\s*req\.files?\.mimetype/i,
		],
		fixDescription:
			"Use a magic-byte detection library (e.g. file-type) to inspect the actual " +
			"file content server-side. Combine with an extension allowlist and never " +
			"rely on Content-Type or req.file.mimetype for security decisions.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html#content-type-validation",
	},

	// ── Using original filename from upload as a storage path ─────────────────

	{
		id: "IV-JS-UPLOAD-ORIGINAL-NAME",
		category: "A04: Insecure Design",
		title: "Client-supplied original filename used for file storage",
		description:
			"req.file.originalname is provided by the client and can contain path traversal " +
			"sequences (e.g. ../../etc/passwd), null bytes, or dangerous extensions. Using it " +
			"directly to name the stored file can allow overwriting arbitrary files or " +
			"uploading executable content.",
		severity: "critical",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			// path.join/resolve called with originalname
			/path\.(?:join|resolve)\s*\([^)]*req\.file\.originalname/i,
			// fs write/rename/stream with originalname
			/fs\.(?:writeFile|appendFile|rename|copyFile|createWriteStream)\s*\([^)]*req\.file\.originalname/i,
			// destination variable assigned from originalname
			/(?:dest(?:ination)?|storagePath|filePath|savePath|uploadPath)\s*=\s*[^;\n]*req\.file\.originalname/i,
		],
		fixDescription:
			"Generate a random server-side filename using crypto.randomUUID() or the uuid " +
			"package. Persist the original name in a database record only; never write it " +
			"to the filesystem.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html#upload-storage-location",
	},

	// ══════════════════════════════════════════════════════════════════════════
	//  JavaScript / TypeScript — Input Validation
	// ══════════════════════════════════════════════════════════════════════════

	// ── parseInt / Number on request input without NaN check ──────────────────

	{
		id: "IV-JS-PARSE-NO-NAN-CHECK",
		category: "A03: Injection",
		title: "Request parameter coerced to number without NaN validation",
		description:
			"parseInt(), parseFloat(), and Number() silently return NaN when passed a " +
			"non-numeric string. Using the result directly in arithmetic, database queries, " +
			"or comparisons without an isNaN() / Number.isFinite() guard produces unexpected " +
			"behaviour and may cause data corruption or injection.",
		severity: "warning",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			/(?:parseInt|parseFloat|Number)\s*\(\s*req\.(?:body|query|params)\b/i,
			/(?:parseInt|parseFloat|Number)\s*\(\s*request\.(?:body|query|params)\b/i,
		],
		fixDescription:
			"After parsing, guard with isNaN() or Number.isFinite(). Prefer a validation " +
			"library (zod, joi, express-validator) that enforces numeric type constraints " +
			"before the value reaches application logic.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#data-type-validation",
	},

	// ── Denylist HTML sanitization via String.replace ─────────────────────────

	{
		id: "IV-JS-DENYLIST-SANITIZE",
		category: "A03: Injection",
		title: "Denylist-based HTML sanitization using String.replace()",
		description:
			"Stripping specific tags or event handler names with String.replace() is a " +
			"denylist approach that attackers routinely bypass through encoding, case " +
			"variation, nested tags, or uncommon HTML syntax.",
		severity: "warning",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			// Stripping script tags or angle brackets
			/\.replace(?:All)?\s*\(\s*\/[^/]*(?:<\s*\/?\s*script|javascript\s*:|<[^/][^>]+>)[^/]*/i,
			// Stripping event-handler attribute names
			/\.replace(?:All)?\s*\(\s*\/[^/]*(?:onerror|onload|onclick|oninput|onmouseover)[^/]*/i,
		],
		fixDescription:
			"Use an allowlist-based HTML sanitiser such as DOMPurify (browser) or " +
			"sanitize-html / xss (Node.js). Never attempt to remove dangerous content " +
			"via regex denylist patterns.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#allow-list-vs-deny-list",
	},

	// ══════════════════════════════════════════════════════════════════════════
	//  Python — Input Validation
	// ══════════════════════════════════════════════════════════════════════════

	// ── int() / float() on request params without exception handling ──────────

	{
		id: "IV-PY-INT-NO-EXCEPTION",
		category: "A03: Injection",
		title: "Parsing request parameter with int()/float() without exception handling",
		description:
			"int() and float() raise ValueError when passed a non-numeric string. " +
			"Calling them directly on request parameters without a try/except block " +
			"causes unhandled exceptions that may expose stack traces or crash the server.",
		severity: "critical",
		languages: ["python"],
		patterns: [
			/\bint\s*\(\s*request\.(?:args|form|GET|POST|data|json|values)(?:\.get\s*\(|\s*[\[.])/i,
			/\bfloat\s*\(\s*request\.(?:args|form|GET|POST|data|json|values)(?:\.get\s*\(|\s*[\[.])/i,
		],
		fixDescription:
			"Wrap int()/float() in a try/except ValueError block, or use a validation " +
			"library such as pydantic, marshmallow, or wtforms to enforce type constraints " +
			"at the boundary.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#data-type-validation",
	},

	// ── eval() with request input ─────────────────────────────────────────────

	{
		id: "IV-PY-EVAL-INPUT",
		category: "A03: Injection",
		title: "eval() called with user-controlled request input",
		description:
			"Passing request parameters to eval() allows arbitrary Python code execution. " +
			"An attacker can run system commands, read files, or escalate privileges.",
		severity: "critical",
		languages: ["python"],
		patterns: [
			/\beval\s*\(\s*request\.(?:args|form|GET|POST|data|json|values)(?:\.get\s*\(|\s*[\[.])/i,
		],
		fixDescription:
			"Never pass user input to eval(). Use ast.literal_eval() for safe parsing of " +
			"Python literals, or a proper parser for structured input formats.",
		reference: "https://owasp.org/Top10/A03_2021-Injection/",
	},

	// ── Server-Side Template Injection via render_template_string ─────────────

	{
		id: "IV-PY-SSTI-RENDER",
		category: "A03: Injection",
		title: "Server-Side Template Injection via render_template_string()",
		description:
			"Passing user-controlled input directly to Flask's render_template_string() " +
			"allows Jinja2 Server-Side Template Injection (SSTI). An attacker can craft a " +
			"payload like {{ ''.__class__.__mro__[1].__subclasses__() }} to achieve remote " +
			"code execution.",
		severity: "critical",
		languages: ["python"],
		patterns: [
			// request data passed directly as the template string
			/render_template_string\s*\([^)]*request\.(?:args|form|GET|POST|values|json)(?:\.get\s*\(|\s*[\[.])/i,
			// f-string used as the template — any user data could be interpolated
			/render_template_string\s*\(\s*f['"][^'"]*\{/,
		],
		fixDescription:
			"Always use render_template() with static .html template files stored on the " +
			"server. Never interpolate user input into the template string argument of " +
			"render_template_string().",
		reference: "https://owasp.org/Top10/A03_2021-Injection/",
	},

	// ── Unvalidated open redirect via Flask redirect() ────────────────────────

	{
		id: "IV-PY-OPEN-REDIRECT",
		category: "A01: Broken Access Control",
		title: "Unvalidated open redirect using request parameters in Python",
		description:
			"Passing a URL taken from request.args, request.form, or similar directly to " +
			"Flask's redirect() allows attackers to craft phishing URLs that appear to " +
			"originate from your domain (e.g. /login?next=https://evil.com).",
		severity: "critical",
		languages: ["python"],
		patterns: [
			/redirect\s*\(\s*request\.(?:args|form|GET|POST|values)(?:\.get\s*\(|\s*[\[.])/i,
		],
		fixDescription:
			"Validate redirect targets against an allowlist of trusted internal paths. " +
			"Use url_for() for application-internal redirects and reject any external URLs " +
			"that were not explicitly approved.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
	},

	// ══════════════════════════════════════════════════════════════════════════
	//  Python — File Upload
	// ══════════════════════════════════════════════════════════════════════════

	// ── Using original filename from request.files for storage ────────────────

	{
		id: "IV-PY-UPLOAD-ORIGINAL-NAME",
		category: "A04: Insecure Design",
		title: "Client-supplied filename used for file storage in Python",
		description:
			"request.files[key].filename is provided by the browser and can contain path " +
			"traversal sequences (../../), null bytes, or dangerous extensions. Using it " +
			"directly to name a stored file can overwrite arbitrary paths or serve " +
			"malicious content.",
		severity: "critical",
		languages: ["python"],
		patterns: [
			// .filename accessed directly from request.files
			/request\.files\s*\[[^\]]+\]\s*\.filename\b/i,
		],
		fixDescription:
			"Always pass the filename through werkzeug.utils.secure_filename() before " +
			"any filesystem operation. Better still, generate a UUID-based storage name " +
			"and store the sanitized original name only in your database.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html#upload-storage-location",
	},

	// ── Trusting content_type / mimetype of an uploaded file ─────────────────

	{
		id: "IV-PY-UPLOAD-MIME-TRUST",
		category: "A04: Insecure Design",
		title: "Trusting client-supplied content_type for file upload validation in Python",
		description:
			"request.files[key].content_type and .mimetype reflect the Content-Type header " +
			"sent by the client. An attacker can set any MIME type and bypass extension- or " +
			"type-based upload filters.",
		severity: "critical",
		languages: ["python"],
		patterns: [
			// direct access to .content_type or .mimetype from request.files
			/request\.files\s*\[[^\]]+\]\s*\.(?:content_type|mimetype)\b/i,
			// variable named 'file' (common Flask convention) with mimetype comparison
			/\bfile\.(?:content_type|mimetype)\s*(?:==|!=|not\s+in\b|\bin\b)/i,
		],
		fixDescription:
			"Detect the file type server-side by inspecting magic bytes using a library " +
			"such as python-magic or filetype. Never rely on the Content-Type header or " +
			"the .mimetype attribute from the uploaded file object.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html#content-type-validation",
	},

	// ── Saving uploads to a web-accessible directory in Flask ────────────────

	{
		id: "IV-PY-UPLOAD-WEB-ROOT",
		category: "A04: Insecure Design",
		title: "Uploaded file saved to a web-accessible directory in Python",
		description:
			"Saving uploaded files inside static/, public/, uploads/, or media/ paths " +
			"that are served directly by the web server lets an attacker upload a script " +
			"and access it via a direct URL, potentially achieving remote code execution.",
		severity: "critical",
		languages: ["python"],
		patterns: [
			// file.save() with a literal path leading into a web-accessible folder
			/\.save\s*\(\s*(?:os\.path\.join\s*\(\s*)?['"][^'"]*(?:static|public|uploads?|media|files?)(?:\/|\\)/i,
			// os.path.join used to build a path rooted in a web-accessible folder
			/os\.path\.join\s*\(\s*['"](?:static|public|uploads?|media|files?)['"]/i,
		],
		fixDescription:
			"Store uploaded files in a directory that is outside the web root and not " +
			"served by the HTTP server. Serve files through a controlled endpoint that " +
			"validates access rights and streams the file from the private location.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html#upload-storage-location",
	},

	// ── zipfile.extractall() without path-traversal validation ───────────────

	{
		id: "IV-PY-ZIP-NO-VALIDATION",
		category: "A01: Broken Access Control",
		title: "ZIP extraction without path traversal validation in Python",
		description:
			"zipfile.extractall() writes every archive member to the target directory " +
			"without checking whether a member's path resolves outside it. An attacker can " +
			"craft a ZIP with entries like ../../etc/cron.d/evil to overwrite arbitrary " +
			"files on the server (Zip Slip vulnerability).",
		severity: "critical",
		languages: ["python"],
		patterns: [/\.extractall\s*\(/i],
		fixDescription:
			"Before extraction, iterate over zipfile.namelist() and verify that " +
			"os.path.realpath(os.path.join(dest, name)) starts with os.path.realpath(dest). " +
			"Reject any archive that contains unsafe paths.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html#archive-file-management",
	},

	// ──────────────────────────────────────────────────────────────────────────
	//  Python — Django / SQLAlchemy
	// ──────────────────────────────────────────────────────────────────────────

	// ── SQL query built with f-string or .format() ───────────────────────────

	{
		id: "IV-PY-SQL-FSTRING",
		category: "A03: Injection",
		title: "SQL query built with f-string or .format()",
		description:
			"Constructing SQL queries with f-strings or str.format() inserts values " +
			"directly into the query text, enabling SQL injection. This applies to " +
			"raw cursor.execute() calls as well as SQLAlchemy text() expressions.",
		severity: "critical",
		languages: ["python"],
		patterns: [
			// f-string containing a SQL keyword
			/f['"](?:[^'"]*)?\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^'"]*\{/i,
			// .format() called on a SQL string
			/['"](?:[^'"]*)?\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^'"]*['"]\s*\.format\s*\(/i,
		],
		fixDescription:
			"Use parameterized queries: cursor.execute('SELECT … WHERE id = %s', (user_id,)) " +
			"or SQLAlchemy bound parameters (sqlalchemy.text('… WHERE id = :id').bindparams(id=user_id)).",
		reference: "https://owasp.org/Top10/A03_2021-Injection/",
	},

	// ── Django @csrf_exempt ───────────────────────────────────────────────────

	{
		id: "IV-PY-DJANGO-CSRF-EXEMPT",
		category: "A04: Insecure Design",
		title: "Django @csrf_exempt disables CSRF protection",
		description:
			"The @csrf_exempt decorator removes CSRF token validation from the decorated " +
			"view. Any state-changing endpoint without CSRF protection is vulnerable to " +
			"cross-site request forgery attacks.",
		severity: "warning",
		languages: ["python"],
		patterns: [/@csrf_exempt/],
		fixDescription:
			"Remove @csrf_exempt. Ensure CsrfViewMiddleware is listed in MIDDLEWARE and " +
			"use Django's {% csrf_token %} template tag or the csrfmiddlewaretoken form field. " +
			"For API views, use DRF's SessionAuthentication which enforces CSRF by default.",
		reference: "https://owasp.org/Top10/A04_2021-Insecure_Design/",
	},

	// ── Django ALLOWED_HOSTS wildcard ─────────────────────────────────────────

	{
		id: "IV-PY-DJANGO-ALLOWED-HOSTS",
		category: "A05: Security Misconfiguration",
		title: "Django ALLOWED_HOSTS set to wildcard",
		description:
			"Setting ALLOWED_HOSTS = ['*'] disables Django's HTTP Host header validation. " +
			"This enables Host header injection attacks, which can poison password-reset " +
			"links, cache poisoning, and other host-dependent logic.",
		severity: "warning",
		languages: ["python"],
		patterns: [/ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\s*\]/],
		fixDescription:
			"Set ALLOWED_HOSTS to the explicit list of domains your application is served " +
			"from, e.g. ALLOWED_HOSTS = ['example.com', 'www.example.com'].",
		reference:
			"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
	},
];
