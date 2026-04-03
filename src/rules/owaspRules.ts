import { SecurityRule } from "../types";

/**
 * OWASP Top 10 (2021) rules for JavaScript/TypeScript, Python, and PHP.
 *
 * References:
 *  https://owasp.org/Top10/
 */
export const owaspRules: SecurityRule[] = [
	// ─── A01: Broken Access Control ──────────────────────────────────────────

	{
		id: "A01-DIRECTORY-TRAVERSAL",
		category: "A01: Broken Access Control",
		title: "Potential directory traversal",
		description:
			"User-controlled input used directly in file path operations can allow attackers to read files outside the intended directory.",
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
			/(?:readFile|readFileSync|open|fopen|file_get_contents|include|require)\s*\(\s*(?:req\.|request\.|_GET|_POST|\$_GET|\$_POST|\$_REQUEST)/i,
			/path\.join\s*\([^)]*(?:req\.|request\.params|request\.query|request\.body)/i,
		],
		fixDescription:
			"Validate and sanitize file paths; use path.basename() and restrict to an allow-listed directory.",
		reference: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
	},

	// ─── A02: Cryptographic Failures ─────────────────────────────────────────

	{
		id: "A02-WEAK-HASH-MD5",
		category: "A02: Cryptographic Failures",
		title: "MD5 used for hashing",
		description:
			"MD5 is a broken cryptographic hash function. Do not use it for passwords, certificates, or integrity checks.",
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
			/(?:createHash|md5|hashlib\.md5)\s*\(\s*['"]md5['"]\s*\)/i,
			/md5\s*\(/i,
		],
		fixDescription:
			'Replace MD5 with SHA-256 (crypto.createHash("sha256")) or bcrypt/argon2 for passwords.',
		reference: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
	},
	{
		id: "A02-WEAK-HASH-SHA1",
		category: "A02: Cryptographic Failures",
		title: "SHA-1 used for hashing",
		description:
			"SHA-1 is deprecated and broken for cryptographic purposes.",
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
			/createHash\s*\(\s*['"]sha1['"]\s*\)/i,
			/hashlib\.sha1\s*\(/i,
		],
		fixDescription: "Upgrade to SHA-256 or stronger.",
		reference: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
	},
	{
		id: "A02-HARDCODED-SECRET",
		category: "A02: Cryptographic Failures",
		title: "Hardcoded secret or password",
		description:
			"Secrets, API keys, and passwords must not be hardcoded in source code. They can be extracted from the repository.",
		severity: "critical",
		languages: [],
		patterns: [
			/(?:password|passwd|secret|api_?key|apikey|auth_?token|access_?token|private_?key)\s*=\s*['"][^'"]{4,}['"]/i,
		],
		fixDescription:
			"Store secrets in environment variables or a secrets manager (e.g. Azure Key Vault, AWS Secrets Manager).",
		fixReplacer: (lineText: string) =>
			lineText.replace(
				/((?:password|passwd|secret|api_?key|apikey|auth_?token|access_?token|private_?key)\s*=\s*)['"][^'"]*['"]/i,
				"$1process.env.SECRET_VALUE",
			),
		reference: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
	},
	{
		id: "A02-INSECURE-RANDOM",
		category: "A02: Cryptographic Failures",
		title: "Non-cryptographic random number used",
		description:
			"Math.random() / rand() / random() are not cryptographically secure and must not be used for tokens, session IDs, or security decisions.",
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
			/\bMath\.random\s*\(/,
			/\brand\s*\(/,
			/\brandom\.random\s*\(/,
		],
		fixDescription:
			"Use crypto.getRandomValues(), crypto.randomBytes(), secrets.token_hex(), or openssl_random_pseudo_bytes().",
		reference: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
	},

	// ─── A03: Injection ───────────────────────────────────────────────────────

	{
		id: "A03-SQL-INJECTION",
		category: "A03: Injection",
		title: "Potential SQL injection",
		description:
			"Concatenating user input directly into SQL queries allows attackers to manipulate database queries.",
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
			// JS/TS: query function called with string concatenation using user input
			/(?:query|execute|exec|raw)\s*\(\s*[`"'].*\+\s*(?:req\.|request\.|_GET|_POST|\$_GET|\$_POST|\$_REQUEST|params\.|body\.)/i,
			// JS/TS: query function called with template literal containing user input
			/(?:query|execute|exec|raw)\s*\(\s*`[^`]*\$\{[^}]*(?:req|request|params|body|query)/i,
			// PHP: mysql_query/mysqli_query/pg_query passed a concatenated variable
			/(?:mysql_query|mysqli_query|pg_query)\s*\([^)]*\.\s*\$/i,
			// PHP: SQL keyword anywhere on line, followed by dot-concat with a PHP variable
			// Catches: $sql = "SELECT ... WHERE x = '".$var."'";
			/(?:SELECT|INSERT|UPDATE|DELETE|EXEC)\b.*\.\s*\$\w+/i,
			// PHP: variable assigned a string that contains SQL keyword and dot-concat
			// Catches assignment forms: $q = "... FROM ... " . $var
			/\$\w+\s*=\s*["'].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b.*\.\s*\$\w+/i,
			// Python: % string formatting with SQL keywords
			/["'].*(?:SELECT|INSERT|UPDATE|DELETE)\b.*["']\s*%\s*(?:\(|\w)/i,
		],
		fixDescription:
			"Use parameterized queries or prepared statements. Never concatenate user input into SQL.",
		reference: "https://owasp.org/Top10/A03_2021-Injection/",
	},
	{
		id: "A03-COMMAND-INJECTION",
		category: "A03: Injection",
		title: "Potential command injection",
		description:
			"Passing unsanitized user input to shell execution functions can allow arbitrary command execution.",
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
			/(?:exec|execSync|spawn|spawnSync|system|shell_exec|passthru|popen|subprocess\.call|subprocess\.run|os\.system)\s*\([^)]*(?:req\.|request\.|params\.|body\.|_GET|_POST|\$_GET|\$_POST)/i,
			/(?:exec|execSync)\s*\(\s*[`"'][^`"']*\+/i,
		],
		fixDescription:
			"Avoid shell execution with user input. Use parameterized APIs (e.g. child_process.spawn with array args).",
		reference: "https://owasp.org/Top10/A03_2021-Injection/",
	},
	{
		id: "A03-XSS-INNERHTML",
		category: "A03: Injection",
		title: "XSS via innerHTML / document.write",
		description:
			"Setting innerHTML or calling document.write with unsanitized data enables cross-site scripting attacks.",
		severity: "critical",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			/\.innerHTML\s*=\s*(?!['"`]<)/,
			/\.outerHTML\s*=\s*(?!['"`]<)/,
			/document\.write\s*\(/,
			/document\.writeln\s*\(/,
		],
		fixDescription:
			"Use textContent instead of innerHTML, or sanitize with DOMPurify before assigning.",
		reference: "https://owasp.org/Top10/A03_2021-Injection/",
	},
	{
		id: "A03-EVAL-INJECTION",
		category: "A03: Injection",
		title: "Use of eval() or Function() with dynamic input",
		description:
			"eval() and new Function() execute arbitrary code. Passing user data to them is a critical code-injection risk.",
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
			/\beval\s*\(/,
			/new\s+Function\s*\(/,
			/\bexec\s*\(\s*(?:compile|input)/,
		],
		fixDescription:
			"Avoid eval(). Use safer alternatives such as JSON.parse() for data or a well-tested expression parser.",
		reference: "https://owasp.org/Top10/A03_2021-Injection/",
	},
	{
		id: "A03-TEMPLATE-INJECTION",
		category: "A03: Injection",
		title: "Possible server-side template injection",
		description:
			"Rendering user input directly as a template string can lead to server-side template injection.",
		severity: "critical",
		languages: [
			"python",
			"php",
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			/render_template_string\s*\(/,
			/\.render\s*\(\s*(?:req\.|request\.|_GET|_POST)/i,
		],
		fixDescription:
			"Never pass user-supplied data as template names or raw template strings. Use static template files with escaped variables.",
		reference: "https://owasp.org/Top10/A03_2021-Injection/",
	},

	// ─── A05: Security Misconfiguration ──────────────────────────────────────

	{
		id: "A05-DEBUG-ENABLED",
		category: "A05: Security Misconfiguration",
		title: "Debug mode enabled",
		description:
			"Running applications in debug mode in production exposes stack traces and internal details.",
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
			/app\.run\s*\([^)]*debug\s*=\s*True/,
			/DEBUG\s*=\s*True/,
			/debug\s*:\s*true/i,
			/display_errors\s*=\s*On/i,
		],
		fixDescription:
			"Disable debug mode in production. Use environment variables to toggle debug settings.",
		reference:
			"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
	},
	{
		id: "A05-CORS-WILDCARD",
		category: "A05: Security Misconfiguration",
		title: "CORS wildcard origin",
		description:
			"Setting Access-Control-Allow-Origin: * on APIs with authentication bypasses origin-based protection.",
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
			/Access-Control-Allow-Origin['"]\s*[,:]\s*['"\s]*\*/i,
			/origin\s*:\s*['"`]\*['"`]/i,
			/cors\s*\(\s*\{[^}]*origin\s*:\s*['"`]\*['"`]/i,
		],
		fixDescription:
			"Specify an explicit list of allowed origins instead of using a wildcard.",
		reference:
			"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
	},

	// ─── A07: Identification and Authentication Failures ─────────────────────

	{
		id: "A07-INSECURE-COOKIE",
		category: "A07: Identification & Authentication Failures",
		title: "Cookie missing Secure or HttpOnly flag",
		description:
			"Cookies without Secure and HttpOnly flags can be stolen via XSS or transmitted over plain HTTP.",
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
			/res\.cookie\s*\([^)]*\)/,
			/setcookie\s*\([^)]*\)/i,
			/response\.set_cookie\s*\([^)]*\)/i,
		],
		fixDescription:
			'Always set { secure: true, httpOnly: true, sameSite: "Strict" } on sensitive cookies.',
		reference:
			"https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
	},
	{
		id: "A07-JWT-NONE-ALG",
		category: "A07: Identification & Authentication Failures",
		title: '"none" algorithm in JWT',
		description:
			'Using the "none" algorithm disables signature verification, allowing token forgery.',
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
			/algorithm[s]?\s*:\s*['"`]none['"`]/i,
			/jwt\.decode\s*\([^)]*algorithms\s*=\s*\[['"]none['"]\]/i,
		],
		fixDescription:
			"Always specify a strong algorithm (RS256, ES256) and verify the signature server-side.",
		reference:
			"https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
	},

	// ─── A08: Software and Data Integrity Failures ───────────────────────────

	{
		id: "A08-DESERIALIZE-PICKLE",
		category: "A08: Software & Data Integrity Failures",
		title: "Unsafe deserialization (pickle)",
		description:
			"Deserializing untrusted data with pickle/unserialize leads to arbitrary code execution.",
		severity: "critical",
		languages: ["python"],
		patterns: [
			/pickle\.loads?\s*\(/i,
			/cPickle\.loads?\s*\(/i,
			/yaml\.load\s*\([^,)]+\)/, // yaml.load without Loader= is unsafe
		],
		fixDescription:
			"Use pickle only with trusted data. For YAML, use yaml.safe_load(). Consider using JSON instead.",
		reference:
			"https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
	},
	{
		id: "A08-DESERIALIZE-PHP",
		category: "A08: Software & Data Integrity Failures",
		title: "Unsafe deserialization (unserialize)",
		description:
			"PHP unserialize() with untrusted data can lead to object injection and remote code execution.",
		severity: "critical",
		languages: ["php"],
		patterns: [/unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i],
		fixDescription:
			"Avoid unserialize() with user input. Use JSON instead.",
		reference:
			"https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
	},

	// ─── A09: Security Logging & Monitoring Failures ─────────────────────────

	{
		id: "A09-SENSITIVE-LOG",
		category: "A09: Security Logging & Monitoring Failures",
		title: "Sensitive data in log statement",
		description:
			"Logging passwords, tokens, or PII exposes sensitive data in log files.",
		severity: "warning",
		languages: [],
		patterns: [
			/(?:console\.|logger\.|log\.|print)\s*(?:log|debug|info|warn|error)?\s*\([^)]*(?:password|passwd|secret|token|credit_?card|ssn|social_security)/i,
		],
		fixDescription:
			"Mask or redact sensitive fields before logging. Use structured logging with field-level filters.",
		reference:
			"https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
	},

	// ─── A10: SSRF ───────────────────────────────────────────────────────────

	{
		id: "A10-SSRF",
		category: "A10: Server-Side Request Forgery",
		title: "Potential SSRF via user-controlled URL",
		description:
			"Making HTTP requests to a URL derived from user input can allow attackers to probe internal services.",
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
			/(?:fetch|axios\.get|axios\.post|requests\.get|requests\.post|file_get_contents|curl_exec)\s*\([^)]*(?:req\.|request\.|params\.|body\.|_GET|_POST|\$_GET|\$_POST)/i,
		],
		fixDescription:
			"Validate and allowlist URLs or IP ranges before making server-side requests.",
		reference:
			"https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
	},

	// ─── A04: Insecure Design ─────────────────────────────────────────────────

	{
		id: "A04-MISSING-CSRF",
		category: "A04: Insecure Design",
		title: "Potential missing CSRF protection on state-changing route",
		description:
			"POST/PUT/DELETE routes that modify state without CSRF token validation " +
			"are vulnerable to Cross-Site Request Forgery attacks.",
		severity: "warning",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
			"php",
		],
		patterns: [
			// Express routes without csrf middleware visible on same line
			/(?:app|router)\.(?:post|put|patch|delete)\s*\(\s*['"`][^'"` ]+['"`]\s*,\s*(?!.*csrf)/i,
			// PHP form processing without token check
			/\$_(?:POST|REQUEST)\s*\[.*\].*(?!=.*csrf|token)/i,
		],
		fixDescription:
			"Apply CSRF middleware (e.g. csurf for Express, or synchronizer token pattern for PHP) " +
			"to all state-changing endpoints.",
		reference: "https://owasp.org/Top10/A04_2021-Insecure_Design/",
	},
	{
		id: "A04-MASS-ASSIGNMENT",
		category: "A04: Insecure Design",
		title: "Potential mass assignment via unsanitized request body",
		description:
			"Passing the entire request body/params object directly to a model or database " +
			"call allows attackers to set fields they should not control (e.g. isAdmin, role).",
		severity: "critical",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			// ORM create/update with raw req.body
			/\.(?:create|update|updateOne|updateMany|findOneAndUpdate|save|insert)\s*\(\s*req\.body\s*[,)]/i,
			/\.(?:create|update)\s*\(\s*\{\s*\.\.\.req\.body/i,
			// Sequelize/TypeORM patterns
			/(?:repository|manager)\.save\s*\(\s*(?:Object\.assign|plainToClass)\s*\([^,]+,\s*req\.body/i,
		],
		fixDescription:
			"Explicitly pick allowed fields from req.body (e.g. const { name, email } = req.body). " +
			"Never pass the whole body object to a model.",
		reference: "https://owasp.org/Top10/A04_2021-Insecure_Design/",
	},
	{
		id: "A04-INSECURE-DIRECT-OBJECT-REF",
		category: "A04: Insecure Design",
		title: "Potential Insecure Direct Object Reference (IDOR)",
		description:
			"Looking up records by an ID taken directly from user input without verifying " +
			"the requester owns or has access to that resource enables IDOR.",
		severity: "warning",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
			"php",
		],
		patterns: [
			/\.findById\s*\(\s*req\.\w+\.\w+\s*\)/i,
			/\.findOne\s*\(\s*\{\s*(?:id|_id)\s*:\s*req\.\w+\.\w+\s*\}\s*\)/i,
			/WHERE\s+(?:id|user_?id)\s*=\s*['"]?\s*\$_(?:GET|POST|REQUEST)/i,
		],
		fixDescription:
			"After retrieving the record, verify that the authenticated user's ID matches " +
			"the record's owner field before returning or modifying it.",
		reference:
			"https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference",
	},
	{
		id: "A04-UNRESTRICTED-FILE-SIZE",
		category: "A04: Insecure Design",
		title: "File upload without size limit",
		description:
			"Accepting file uploads without enforcing a maximum size limit allows attackers " +
			"to exhaust server disk space or memory (DoS).",
		severity: "warning",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			// multer without limits
			/multer\s*\(\s*\{(?![^}]*limits)[^}]*\}\s*\)/i,
			// busboy/formidable without maxFileSize
			/(?:busboy|formidable)\s*\(\s*\{(?![^}]*(?:maxFileSize|fileSize))[^}]*\}\s*\)/i,
		],
		fixDescription:
			"Set a reasonable file size limit in your upload middleware, " +
			"e.g. multer({ limits: { fileSize: 5 * 1024 * 1024 } }).",
		reference: "https://owasp.org/Top10/A04_2021-Insecure_Design/",
	},
	{
		id: "A04-TIMING-ATTACK",
		category: "A04: Insecure Design",
		title: "String equality used for secret/token comparison (timing attack)",
		description:
			"Using === or == to compare secrets, tokens, or hashes allows timing attacks " +
			"because comparison short-circuits on the first mismatched byte.",
		severity: "warning",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			/(?:token|secret|hash|hmac|signature|digest)\s*===?\s*(?:req\.|request\.|provided|expected|computed)/i,
			/(?:req\.|request\.)\w+(?:\.\w+)*\s*===?\s*(?:token|secret|hash|hmac|signature)/i,
		],
		fixDescription:
			"Use crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)) for constant-time comparison.",
		reference: "https://owasp.org/Top10/A04_2021-Insecure_Design/",
	},

	// ─── A06: Vulnerable and Outdated Components ──────────────────────────────

	{
		id: "A06-VULNERABLE-JQUERY",
		category: "A06: Vulnerable & Outdated Components",
		title: "Potentially outdated or vulnerable jQuery usage pattern",
		description:
			"jQuery versions below 3.5.0 contain XSS vulnerabilities in $.html(), $.load(), " +
			"and selector injection. The pattern $.parseHTML(userInput) is also unsafe.",
		severity: "warning",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			/\$\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.|\$_(?:GET|POST))/i,
			/\$\.parseHTML\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)/i,
			/\$\([^)]*\)\.html\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)/i,
		],
		fixDescription:
			"Upgrade jQuery to 3.5.0+. Never pass user input to jQuery selectors or .html().",
		reference:
			"https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
	},
	{
		id: "A06-KNOWN-VULNERABLE-PACKAGE",
		category: "A06: Vulnerable & Outdated Components",
		title: "Import of a known historically vulnerable package",
		description:
			"These packages have had high-severity CVEs and should be audited or replaced.",
		severity: "warning",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			// node-serialize - RCE
			/require\s*\(\s*['"]node-serialize['"]\s*\)/i,
			// lodash < 4.17.21 - prototype pollution / RCE
			/require\s*\(\s*['"]lodash['"]\s*\)/i,
			// minimist < 1.2.6 - prototype pollution
			/require\s*\(\s*['"]minimist['"]\s*\)/i,
			// jsonwebtoken < 9.0.0 - verification bypass
			/require\s*\(\s*['"]jsonwebtoken['"]\s*\)/i,
			// request (deprecated with open CVEs)
			/require\s*\(\s*['"]request['"]\s*\)/i,
		],
		fixDescription:
			"Run 'npm audit' to check for known vulnerabilities. " +
			"Update to the latest patched versions or replace deprecated packages.",
		reference:
			"https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
	},
	{
		id: "A06-KNOWN-VULNERABLE-PACKAGE-PHP",
		category: "A06: Vulnerable & Outdated Components",
		title: "Use of PHP function removed or deprecated due to security issues",
		description:
			"These PHP functions have been removed or deprecated because of inherent security flaws.",
		severity: "critical",
		languages: ["php"],
		patterns: [
			// mysql_* - removed in PHP 7, no parameterized queries
			/\bmysql_(?:connect|query|escape_string)\s*\(/i,
			// mcrypt - deprecated/removed, use openssl
			/\bmcrypt_(?:encrypt|decrypt|create_iv)\s*\(/i,
			// ereg - removed in PHP 7 (use preg_*)
			/\bereg(?:i|_replace|i_replace)?\s*\(/i,
			// create_function - removed in PHP 8, equivalent to eval
			/\bcreate_function\s*\(/i,
		],
		fixDescription:
			"Replace removed functions: mysql_* → PDO/MySQLi, mcrypt → openssl_*, " +
			"ereg → preg_*, create_function → anonymous functions.",
		reference:
			"https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
	},
	{
		id: "A06-EVAL-PACKAGE",
		category: "A06: Vulnerable & Outdated Components",
		title: "Use of eval-based package (vm2 / vm-browserify)",
		description:
			"vm2 had multiple sandbox-escape CVEs (CVSS 10.0). Any code execution in vm2 " +
			"can lead to full host RCE.",
		severity: "critical",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [/require\s*\(\s*['"]vm2['"]\s*\)/i, /from\s+['"]vm2['"]/i],
		fixDescription:
			"Replace vm2 with a maintained alternative such as isolated-vm, " +
			"or run untrusted code in a separate process/container.",
		reference:
			"https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
	},
];
