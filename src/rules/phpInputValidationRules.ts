import { SecurityRule } from "../types";

/**
 * PHP Input Validation rules based on the OWASP Input Validation Cheat Sheet.
 *
 * Reference: https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
 *
 * Covers:
 *  - No server-side validation (using superglobals raw)
 *  - Denylist vs allowlist validation
 *  - Type validation (int, float, email, URL, boolean)
 *  - String length enforcement
 *  - Regex without anchors
 *  - File upload validation (extension, MIME, filename, storage)
 *  - Null byte injection
 *  - Enumerable input not allowlisted
 *  - filter_input/filter_var misuse
 *  - ZIP file upload without extraction limits
 */
export const phpInputValidationRules: SecurityRule[] = [
	// ── Raw superglobal use without any validation ────────────────────────────

	{
		id: "PHP-IV-RAW-GET",
		category: "Input Validation",
		title: "Raw $_GET value used without validation",
		description:
			"$_GET values are directly user-controlled. Using them without validation, " +
			"type-casting, or filter_input() allows malformed or malicious data to enter " +
			"the application. All input should be validated server-side as early as possible.",
		severity: "warning",
		languages: ["php"],
		patterns: [
			// Direct use in function calls or assignments without a wrapping validator
			/\$_GET\s*\[[^\]]+\]\s*(?!.*(?:filter_var|filter_input|intval|floatval|htmlspecialchars|preg_match|is_numeric|strip_tags|trim|addslashes))/i,
		],
		fixDescription:
			"Use filter_input(INPUT_GET, 'param', FILTER_SANITIZE_*) or validate with " +
			"filter_var(), intval(), preg_match(), or htmlspecialchars() before use.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
	},

	{
		id: "PHP-IV-RAW-POST",
		category: "Input Validation",
		title: "Raw $_POST value used without validation",
		description:
			"$_POST values must be validated server-side before processing. " +
			"Never assume client-submitted data is safe or of the expected type.",
		severity: "warning",
		languages: ["php"],
		patterns: [
			/\$_POST\s*\[[^\]]+\]\s*(?!.*(?:filter_var|filter_input|intval|floatval|htmlspecialchars|preg_match|is_numeric|strip_tags|trim))/i,
		],
		fixDescription:
			"Validate $_POST values with filter_input(INPUT_POST, 'field', FILTER_VALIDATE_*) " +
			"before any use. Apply type-specific validation (intval, preg_match, etc.).",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
	},

	// ── filter_var / filter_input misuse ─────────────────────────────────────

	{
		id: "PHP-IV-FILTER-DEFAULT",
		category: "Input Validation",
		title: "filter_var/filter_input used with FILTER_DEFAULT (no-op)",
		description:
			"FILTER_DEFAULT (alias FILTER_UNSAFE_RAW) does not validate or sanitize input — " +
			"it only optionally strips or encodes special characters. " +
			"Using it gives a false sense of security.",
		severity: "warning",
		languages: ["php"],
		patterns: [
			/filter_(?:var|input)\s*\([^)]*FILTER_(?:DEFAULT|UNSAFE_RAW)[^)]*\)/i,
		],
		fixDescription:
			"Replace FILTER_DEFAULT with an appropriate validation filter such as " +
			"FILTER_VALIDATE_INT, FILTER_VALIDATE_EMAIL, FILTER_VALIDATE_URL, or " +
			"a type-specific FILTER_SANITIZE_* constant.",
		reference: "https://www.php.net/manual/en/filter.filters.sanitize.php",
	},

	{
		id: "PHP-IV-MISSING-EMAIL-VALIDATION",
		category: "Input Validation",
		title: "Email address used without FILTER_VALIDATE_EMAIL",
		description:
			"Email addresses from user input must be validated with filter_var($email, " +
			"FILTER_VALIDATE_EMAIL) before being stored, displayed, or passed to a mail function. " +
			"Invalid email addresses can trigger injection or unexpected behaviour.",
		severity: "warning",
		languages: ["php"],
		patterns: [
			// email-named variable holding a superglobal value without validation nearby
			/\$(?:email|mail|e_?mail)\s*=\s*\$_(?:GET|POST|REQUEST)\s*\[/i,
		],
		fixDescription:
			"Validate with: if (!filter_var($email, FILTER_VALIDATE_EMAIL)) { /* reject */ } " +
			"Only accept emails that pass syntactic validation, then send a confirmation link " +
			"for semantic validation.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#email-address-validation",
	},

	{
		id: "PHP-IV-MISSING-URL-VALIDATION",
		category: "Input Validation",
		title: "URL used without FILTER_VALIDATE_URL",
		description:
			"User-supplied URLs must be validated with filter_var($url, FILTER_VALIDATE_URL) " +
			"before use in redirects, HTTP requests, or output. " +
			"Unvalidated URLs enable open redirect and SSRF attacks.",
		severity: "warning",
		languages: ["php"],
		patterns: [
			/\$(?:url|uri|link|redirect|href)\s*=\s*\$_(?:GET|POST|REQUEST)\s*\[/i,
		],
		fixDescription:
			"Validate with filter_var($url, FILTER_VALIDATE_URL) and additionally enforce " +
			"an allowlist of permitted schemes (https only) and hostnames.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
	},

	{
		id: "PHP-IV-MISSING-INT-VALIDATION",
		category: "Input Validation",
		title: "Numeric input used without integer validation",
		description:
			"Input fields expected to be integers (IDs, counts, page numbers) should be " +
			"validated with filter_var($val, FILTER_VALIDATE_INT) and checked against " +
			"an expected min/max range. Using intval() alone silently coerces any string to 0.",
		severity: "warning",
		languages: ["php"],
		patterns: [
			// intval used directly on a superglobal without range check
			/intval\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[/i,
			// superglobal cast to int without validation
			/\(\s*int\s*\)\s*\$_(?:GET|POST|REQUEST)\s*\[/i,
		],
		fixDescription:
			"Use filter_var($val, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, " +
			"'max_range' => 10000]]) to validate both type and range.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#implementing-input-validation",
	},

	// ── String length enforcement ─────────────────────────────────────────────

	{
		id: "PHP-IV-NO-LENGTH-CHECK",
		category: "Input Validation",
		title: "String input stored without length validation",
		description:
			"Storing strings of unbounded length from user input can cause database " +
			"truncation errors, buffer issues, or denial-of-service via oversized payloads. " +
			"OWASP recommends enforcing minimum and maximum lengths on all string inputs.",
		severity: "warning",
		languages: ["php"],
		patterns: [
			// INSERT/UPDATE with a superglobal value but no strlen/mb_strlen nearby
			/(?:INSERT|UPDATE)\b.*\$_(?:POST|GET|REQUEST)\s*\[(?![^;]*(?:strlen|mb_strlen|mb_substr|substr))/i,
		],
		fixDescription:
			"Check: if (mb_strlen($input) < 1 || mb_strlen($input) > 255) { /* reject */ } " +
			"before storing. Define and document max lengths for every string field.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#implementing-input-validation",
	},

	// ── Regex validation without anchors ──────────────────────────────────────

	{
		id: "PHP-IV-REGEX-NO-ANCHORS",
		category: "Input Validation",
		title: "preg_match() pattern missing start/end anchors",
		description:
			"A regex used for validation without ^ and $ anchors only checks for a match " +
			"anywhere in the string. An attacker can prepend or append malicious content " +
			"that still satisfies the regex. OWASP recommends anchoring all validation patterns.",
		severity: "warning",
		languages: ["php"],
		patterns: [
			// preg_match with a pattern that doesn't start with ^ or \A
			/preg_match\s*\(\s*['"](?!\/\^|\/\\A)[^'"]*['"]/i,
		],
		fixDescription:
			"Anchor validation patterns: preg_match('/^[a-z0-9]{1,32}$/i', $input). " +
			"The ^ asserts start-of-string and $ asserts end-of-string.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#regular-expressions-regex",
	},

	// ── Denylist / blacklist validation ───────────────────────────────────────

	{
		id: "PHP-IV-DENYLIST-ONLY",
		category: "Input Validation",
		title: "Denylist-based input filtering (str_replace / strip_tags on user input)",
		description:
			"Filtering input by stripping or replacing specific dangerous characters " +
			"(denylist) is easily bypassed. Attackers use encoding, alternate representations, " +
			"or obscure character sequences to evade character-based filters. " +
			"OWASP strongly recommends allowlist validation instead.",
		severity: "warning",
		languages: ["php"],
		patterns: [
			// str_replace or str_ireplace used to 'clean' a superglobal
			/str_(?:i)?replace\s*\(\s*(?:['"][<>&]|array\s*\()[^)]*,\s*['"]{2}\s*,\s*\$_(?:GET|POST|REQUEST)/i,
			// strip_tags as the only defence on user input
			/strip_tags\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[/i,
		],
		fixDescription:
			"Use allowlist validation: define exactly what is permitted (regex, enum, range) " +
			"and reject everything else. Denylist filters may be added as a supplementary " +
			"layer but must never be the primary defence.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#allowlist-vs-denylist",
	},

	// ── Enumerable input not allowlisted ─────────────────────────────────────

	{
		id: "PHP-IV-NO-ENUM-ALLOWLIST",
		category: "Input Validation",
		title: "Enumerable input (sort/order/type/status) used without allowlist check",
		description:
			"Inputs chosen from a fixed set (e.g. sort direction ASC/DESC, status, type) " +
			"must be validated against an explicit allowlist server-side. " +
			"Using them directly in queries or logic allows injection of arbitrary values.",
		severity: "warning",
		languages: ["php"],
		patterns: [
			// sort/order/direction/status param used directly in string context
			/\$_(?:GET|POST|REQUEST)\s*\[\s*['"](?:sort|order|direction|status|type|action|tab|page_?type)['"]\s*\](?!\s*;)(?![^;]*(?:in_array|match|switch|\?\?))/i,
		],
		fixDescription:
			"Use in_array(): $allowed = ['ASC','DESC']; " +
			"if (!in_array($input, $allowed, true)) { die('Invalid input'); } " +
			"Always use strict comparison (third arg = true).",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#allowlist-vs-denylist",
	},

	// ── Null byte injection ───────────────────────────────────────────────────

	{
		id: "PHP-IV-NULL-BYTE",
		category: "Input Validation",
		title: "No null byte check on user input used in file operations",
		description:
			"Null bytes (\\0) in filenames or paths can be used to truncate strings " +
			"in C-based PHP extensions, causing security checks to be bypassed " +
			"(e.g. 'file.php\\0.jpg' can be stored as 'file.php').",
		severity: "critical",
		languages: ["php"],
		patterns: [
			// file operations on a variable sourced from user input without a null-byte check
			/(?:fopen|file_get_contents|include|require|move_uploaded_file|unlink|rename)\s*\(\s*(?:\$_(?:GET|POST|REQUEST|FILES)|[^)]*\$_(?:GET|POST|REQUEST|FILES)[^)]*)\s*\[/i,
		],
		fixDescription:
			"Check for null bytes before any file operation: " +
			"if (strpos($filename, \"\\0\") !== false) { die('Invalid filename'); } " +
			"Also use basename() and restrict to a known-safe directory.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#file-upload-validation",
	},

	// ── File upload: trusting browser-supplied MIME ───────────────────────────

	{
		id: "PHP-IV-FILE-MIME-TRUST",
		category: "Input Validation",
		title: "File MIME type taken from $_FILES['type'] (browser-controlled)",
		description:
			"$_FILES['type'] is supplied by the browser and can be forged by an attacker. " +
			"A malicious PHP script can be uploaded with type 'image/jpeg'. " +
			"Always detect MIME type server-side using finfo_file().",
		severity: "critical",
		languages: ["php"],
		patterns: [/\$_FILES\s*\[[^\]]+\]\s*\[\s*['"]type['"]\s*\]/i],
		fixDescription:
			"Use finfo to detect the actual content type: " +
			"$finfo = new finfo(FILEINFO_MIME_TYPE); " +
			"$mime = $finfo->file($_FILES['file']['tmp_name']); " +
			"Check $mime against an explicit allowlist: ['image/jpeg', 'image/png'].",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#image-upload-verification",
	},

	{
		id: "PHP-IV-FILE-UPLOAD-EXTENSION",
		category: "Input Validation",
		title: "Uploaded file stored without extension allowlist check",
		description:
			"Storing uploaded files without validating the file extension against an allowlist " +
			"allows attackers to upload .php, .phtml, .phar, .asp, and other executable files " +
			"that can be triggered to execute server-side code.",
		severity: "critical",
		languages: ["php"],
		patterns: [
			// move_uploaded_file without any pathinfo/extension check nearby
			/move_uploaded_file\s*\([^)]+\)(?![^;]{0,300}(?:pathinfo|strtolower|in_array|allowlist|whitelist|extension))/i,
		],
		fixDescription:
			"Validate the extension: $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION)); " +
			"$allowed = ['jpg','jpeg','png','gif','pdf']; " +
			"if (!in_array($ext, $allowed, true)) { die('File type not permitted'); } " +
			"Also verify the MIME type with finfo_file().",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#beware-of-specific-file-types",
	},

	{
		id: "PHP-IV-FILE-UPLOAD-USER-FILENAME",
		category: "Input Validation",
		title: "Uploaded file stored using user-supplied filename",
		description:
			"Using the original filename from $_FILES['name'] when storing an uploaded file " +
			"allows path traversal (../../config.php), null byte injection, and overwrite attacks. " +
			"OWASP recommends generating a random server-side filename.",
		severity: "critical",
		languages: ["php"],
		patterns: [
			/move_uploaded_file\s*\([^,]+,\s*[^)]*\$_FILES\s*\[[^\]]+\]\s*\[\s*['"]name['"]\s*\]/i,
		],
		fixDescription:
			"Generate a random filename: $filename = bin2hex(random_bytes(16)) . '.' . $ext; " +
			"Store the original name separately in the database for display purposes only.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#upload-storage",
	},

	{
		id: "PHP-IV-FILE-UPLOAD-WEB-ROOT",
		category: "Input Validation",
		title: "Uploaded file stored inside the web root",
		description:
			"Storing uploaded files in a web-accessible directory (e.g. uploads/ under document root) " +
			"means an attacker who uploads a PHP file can execute it by browsing to its URL. " +
			"Files should be stored outside the document root.",
		severity: "warning",
		languages: ["php"],
		patterns: [
			// move_uploaded_file to a relative path that looks like it's in the web root
			/move_uploaded_file\s*\([^,]+,\s*['"](?:\.\/|uploads?\/|images?\/|files?\/|media\/)/i,
			/move_uploaded_file\s*\([^,]+,\s*__DIR__\s*\.\s*['"]\/(?:uploads?|images?|files?|media)\//i,
		],
		fixDescription:
			"Store uploads in a directory outside the web root and serve them through " +
			"a PHP script that validates access and sets the correct Content-Type header.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#upload-storage",
	},

	// ── ZIP file extraction without limits ────────────────────────────────────

	{
		id: "PHP-IV-ZIP-SLIP",
		category: "Input Validation",
		title: "ZipArchive extraction without path traversal or size validation",
		description:
			"Extracting a ZIP archive without checking entry filenames for path traversal " +
			"(../) or enforcing a size limit can enable Zip Slip attacks " +
			"(writing files anywhere on the filesystem) or ZIP bomb denial-of-service.",
		severity: "critical",
		languages: ["php"],
		patterns: [
			/ZipArchive\s*::|new\s+ZipArchive/i,
			/\$zip\s*->\s*extractTo\s*\(/i,
		],
		fixDescription:
			"Before extracting, iterate entries and verify: (1) no entry path contains ../, " +
			"(2) the resolved path starts with the intended destination directory, " +
			"(3) total uncompressed size is within an acceptable limit. " +
			"Reference: https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#upload-verification",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#upload-verification",
	},

	// ── Client-side-only validation (JS attribute without server-side check) ──

	{
		id: "PHP-IV-CLIENT-SIDE-ONLY",
		category: "Input Validation",
		title: "Input used after relying solely on client-side maxlength/pattern",
		description:
			"HTML attributes like maxlength, pattern, type='email', and required are " +
			"easily bypassed by disabling JavaScript or using a proxy. " +
			"Server-side validation must always be the authoritative check.",
		severity: "info",
		languages: ["php"],
		patterns: [
			// PHP that outputs user input directly after an HTML form field — no server-side validation visible
			/echo\s+\$_(?:POST|GET|REQUEST)\s*\[[^\]]+\].*;\s*\/\/\s*(?:validated\s+by\s+html|client.?side)/i,
		],
		fixDescription:
			"Implement server-side validation in PHP regardless of client-side constraints. " +
			"Client-side validation is UX only; server-side validation is security.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#client-side-vs-server-side-validation",
	},

	// ── settype used as validation ────────────────────────────────────────────

	{
		id: "PHP-IV-SETTYPE-NOT-VALIDATION",
		category: "Input Validation",
		title: "settype() used as input validation",
		description:
			"settype() coerces a value to a type but does not validate it. " +
			"For example, settype($age, 'integer') converts 'abc' to 0 silently. " +
			"This creates a false sense of validation.",
		severity: "warning",
		languages: ["php"],
		patterns: [/settype\s*\(\s*\$_(?:GET|POST|REQUEST)/i],
		fixDescription:
			"Use filter_var() with FILTER_VALIDATE_INT (or appropriate type validator) " +
			"and reject the input explicitly when validation fails.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#implementing-input-validation",
	},
];
