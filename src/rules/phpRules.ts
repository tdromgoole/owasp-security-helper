import { SecurityRule } from "../types";

/**
 * PHP-specific secure coding rules.
 * These target patterns unique to PHP that are not covered by the general OWASP rules.
 */
export const phpRules: SecurityRule[] = [
	// ── Direct output of superglobals (Reflected XSS) ────────────────────────

	{
		id: "PHP-ECHO-XSS",
		category: "A03: Injection (XSS)",
		title: "Unsanitized superglobal echoed directly",
		description:
			"Echoing $_GET, $_POST, $_REQUEST, or $_COOKIE without escaping enables reflected XSS. " +
			"An attacker can inject arbitrary HTML/JS into the response.",
		severity: "critical",
		languages: ["php"],
		patterns: [
			/echo\s+\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[/i,
			/print\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[/i,
			/echo\s+.*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i,
		],
		fixDescription:
			"Wrap output in htmlspecialchars($val, ENT_QUOTES, 'UTF-8') before echoing user input.",
		reference: "https://owasp.org/Top10/A03_2021-Injection/",
	},

	// ── htmlspecialchars without ENT_QUOTES ──────────────────────────────────

	{
		id: "PHP-HTMLSPECIALCHARS-FLAGS",
		category: "A03: Injection (XSS)",
		title: "htmlspecialchars() missing ENT_QUOTES flag",
		description:
			"Calling htmlspecialchars() without ENT_QUOTES leaves single-quoted HTML attributes " +
			"vulnerable to XSS (e.g. value='$input').",
		severity: "warning",
		languages: ["php"],
		patterns: [/htmlspecialchars\s*\([^)]*\)(?!\s*,\s*ENT_QUOTES)/i],
		fixDescription:
			"Use htmlspecialchars($val, ENT_QUOTES, 'UTF-8') to escape both single and double quotes.",
		reference:
			"https://www.php.net/manual/en/function.htmlspecialchars.php",
	},

	// ── Open Redirect via header() ────────────────────────────────────────────

	{
		id: "PHP-OPEN-REDIRECT",
		category: "A01: Broken Access Control",
		title: "Potential open redirect via header()",
		description:
			"Passing user-controlled input directly to header('Location:') allows attackers " +
			"to redirect users to malicious sites.",
		severity: "critical",
		languages: ["php"],
		patterns: [
			/header\s*\(\s*['"]Location:\s*['"]\s*\.\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|\w+)/i,
			/header\s*\(\s*"Location:\s*\$_(?:GET|POST|REQUEST)/i,
		],
		fixDescription:
			"Validate redirect targets against an allowlist of known safe URLs before redirecting.",
		reference:
			"https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
	},

	// ── Header injection ──────────────────────────────────────────────────────

	{
		id: "PHP-HEADER-INJECTION",
		category: "A03: Injection",
		title: "Potential HTTP header injection",
		description:
			"Injecting user input into HTTP headers (other than Location) can enable response splitting, " +
			"cookie injection, and cache poisoning.",
		severity: "critical",
		languages: ["php"],
		patterns: [
			/header\s*\(\s*["'][^"']+["']\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)/i,
			/header\s*\(\s*["'][^"']*\$_(?:GET|POST|REQUEST|COOKIE)/i,
		],
		fixDescription:
			"Never interpolate user input into HTTP header values. Validate and sanitize all header data.",
		reference:
			"https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
	},

	// ── extract() with superglobals ───────────────────────────────────────────

	{
		id: "PHP-EXTRACT",
		category: "A03: Injection",
		title: "extract() called with user-controlled array",
		description:
			"extract($_GET) / extract($_POST) / extract($_REQUEST) imports all submitted keys as " +
			"PHP variables, allowing attackers to overwrite any variable in the current scope.",
		severity: "critical",
		languages: ["php"],
		patterns: [/\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SESSION)/i],
		fixDescription:
			"Remove extract() entirely. Access individual keys explicitly: $name = $_POST['name'] ?? ''.",
		reference: "https://www.php.net/manual/en/function.extract.php",
	},

	// ── preg_replace /e modifier ──────────────────────────────────────────────

	{
		id: "PHP-PREG-REPLACE-E",
		category: "A03: Injection",
		title: "preg_replace() with /e modifier (code execution)",
		description:
			"The /e modifier in preg_replace() causes the replacement string to be evaluated as PHP code, " +
			"enabling arbitrary code execution if user input is involved.",
		severity: "critical",
		languages: ["php"],
		patterns: [/preg_replace\s*\(\s*['"][^'"]*\/e['"]/i],
		fixDescription:
			"Replace preg_replace() with /e with preg_replace_callback() using a safe callback function.",
		reference: "https://www.php.net/manual/en/function.preg-replace.php",
	},

	// ── assert() with user input ──────────────────────────────────────────────

	{
		id: "PHP-ASSERT-INJECTION",
		category: "A03: Injection",
		title: "assert() called with user input",
		description:
			"In PHP, assert() can evaluate a string as PHP code. Passing user input enables remote code execution.",
		severity: "critical",
		languages: ["php"],
		patterns: [
			/\bassert\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i,
			/\bassert\s*\(\s*\$\w+/i,
		],
		fixDescription:
			"Never pass user input to assert(). Use assert() only with static expressions for development checks.",
		reference: "https://www.php.net/manual/en/function.assert.php",
	},

	// ── Variable variables with user input ────────────────────────────────────

	{
		id: "PHP-VARIABLE-VARIABLE",
		category: "A03: Injection",
		title: "Variable variable ($$var) used with user input",
		description:
			"Using $$var where $var comes from user input allows attackers to read or overwrite any variable.",
		severity: "critical",
		languages: ["php"],
		patterns: [/\$\$_(?:GET|POST|REQUEST|COOKIE)/i],
		fixDescription:
			"Avoid variable variables. Use an explicit associative array instead.",
		reference:
			"https://www.php.net/manual/en/language.variables.variable.php",
	},

	// ── File upload without type validation ───────────────────────────────────

	{
		id: "PHP-FILE-UPLOAD-NO-VALIDATION",
		category: "A04: Insecure Design",
		title: "move_uploaded_file() without MIME/extension validation",
		description:
			"Moving an uploaded file without validating its type or extension can allow uploading of " +
			"web shells and other malicious files.",
		severity: "critical",
		languages: ["php"],
		patterns: [/move_uploaded_file\s*\(\s*\$_FILES/i],
		fixDescription:
			"Validate file extension against an allowlist and verify MIME type with finfo_file(). " +
			"Store uploads outside the web root.",
		reference:
			"https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
	},

	// ── Deprecated mysql_* functions ──────────────────────────────────────────

	{
		id: "PHP-DEPRECATED-MYSQL",
		category: "A02: Cryptographic Failures",
		title: "Deprecated mysql_* functions used",
		description:
			"The mysql_* extension was removed in PHP 7. It has no supported parameterized query mechanism " +
			"and is inherently vulnerable to SQL injection.",
		severity: "critical",
		languages: ["php"],
		patterns: [
			/\bmysql_(?:query|connect|select_db|real_escape_string|fetch_array|fetch_row|num_rows)\s*\(/i,
		],
		fixDescription:
			"Replace all mysql_* calls with PDO or MySQLi with prepared statements.",
		reference:
			"https://www.php.net/manual/en/migration70.removed-exts-sapis.php",
	},

	// ── LDAP injection ────────────────────────────────────────────────────────

	{
		id: "PHP-LDAP-INJECTION",
		category: "A03: Injection",
		title: "Potential LDAP injection",
		description:
			"Passing unsanitized user input to ldap_search() or ldap_bind() can allow attackers to " +
			"manipulate LDAP queries and bypass authentication.",
		severity: "critical",
		languages: ["php"],
		patterns: [
			/ldap_(?:search|bind|add|modify|delete)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i,
			/ldap_(?:search|bind|add|modify|delete)\s*\([^)]*\.\s*\$\w+/i,
		],
		fixDescription:
			"Sanitize input with ldap_escape() using the appropriate flags (LDAP_ESCAPE_FILTER or LDAP_ESCAPE_DN).",
		reference: "https://owasp.org/www-community/attacks/LDAP_Injection",
	},

	// ── PHP type juggling ─────────────────────────────────────────────────────

	{
		id: "PHP-TYPE-JUGGLING",
		category: "A07: Identification & Authentication Failures",
		title: "Loose comparison (==) in authentication/security context",
		description:
			"PHP's loose == comparison causes type coercion. '0e...' hashes compare equal to 0, " +
			"and 'true' == any non-empty string, enabling authentication bypass.",
		severity: "warning",
		languages: ["php"],
		patterns: [
			/(?:hash|password|token|digest|checksum)\s*==\s*(?!\s*false|\s*null|\s*['"])/i,
			/if\s*\(\s*\$(?:pass|password|hash|token)\s*==\s*\$/i,
		],
		fixDescription:
			"Use strict comparison (===) for all security-sensitive comparisons. " +
			"Use hash_equals() for comparing hashes to prevent timing attacks.",
		reference:
			"https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection",
	},

	// ── Missing password_hash ─────────────────────────────────────────────────

	{
		id: "PHP-PLAIN-PASSWORD-STORE",
		category: "A02: Cryptographic Failures",
		title: "Password stored without proper hashing",
		description:
			"Storing raw or weakly hashed passwords (MD5/SHA1) in the database exposes all user " +
			"credentials if the database is breached.",
		severity: "critical",
		languages: ["php"],
		patterns: [
			/(?:INSERT|UPDATE)\b.*(?:password|passwd)\s*['"`=].*(?:md5|sha1|base64_encode)\s*\(/i,
		],
		fixDescription:
			"Use password_hash($password, PASSWORD_BCRYPT) to store passwords " +
			"and password_verify() to check them.",
		reference: "https://www.php.net/manual/en/function.password-hash.php",
	},
];
