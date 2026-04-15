import { SecurityRule } from "../types";

/**
 * CISA Secure-by-Design rules.
 *
 * These rules are derived from CISA's Secure-by-Design guidance and cover
 * vulnerability classes NOT already addressed by owaspRules.ts, generalRules.ts,
 * jsRules.ts, phpRules.ts, inputValidationRules.ts, phpInputValidationRules.ts,
 * cspRules.ts, or httpHeaderRules.ts.
 *
 * References:
 *  - https://www.cisa.gov/resources-tools/resources/secure-by-design
 *  - https://www.cisa.gov/sites/default/files/2023-10/SecureByDesign_1025_508c.pdf
 *
 * Categories covered here:
 *  - Insecure Deserialization (PHP unserialize, Python pickle, Python yaml)
 *  - Cryptographic Failures (ECB mode, hardcoded IV/nonce)
 *  - Authentication / JWT (alg:none, missing algorithm restriction)
 *  - PHP: type juggling, dynamic class instantiation, remote file inclusion
 *  - Python: subprocess shell injection, TLS verification disabled,
 *            Jinja2 autoescape disabled, unsafe XML parsing
 */
export const cisaRules: SecurityRule[] = [
	// ══════════════════════════════════════════════════════════════════════════
	//  Insecure Deserialization
	// ══════════════════════════════════════════════════════════════════════════

	{
		id: "CISA-PHP-UNSERIALIZE",
		category: "CISA: Insecure Deserialization",
		title: "PHP unserialize() called with user-controlled data",
		description:
			"Passing user-supplied data to PHP's unserialize() allows Object Injection attacks. " +
			"If the codebase contains gadget chains (magic methods such as __wakeup(), " +
			"__destruct(), or __toString()), an attacker can trigger arbitrary code execution, " +
			"file deletion, or other destructive actions. CISA lists insecure deserialization " +
			"as a root cause of preventable vulnerabilities.",
		severity: "critical",
		languages: ["php"],
		patterns: [
			// unserialize() called directly with a superglobal
			/\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)/i,
			// unserialize() called on a variable that clearly holds user-supplied data
			/\bunserialize\s*\(\s*\$(?:data|input|body|payload|params?|content|str|val|serialized|encoded|raw|user\w*)\b/i,
		],
		fixDescription:
			"Never deserialize data from untrusted sources. Use json_decode() for data " +
			"interchange. If PHP objects must be transferred, use a signed token format " +
			"(e.g. JWT) and validate the signature before deserializing. " +
			"Alternatively, use the Symfony Serializer with an explicit type allowlist.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
	},

	{
		id: "CISA-PY-PICKLE-UNSAFE",
		category: "CISA: Insecure Deserialization",
		title: "Python pickle.loads() / pickle.load() — arbitrary code execution risk",
		description:
			"The Python pickle module executes arbitrary code during deserialization. " +
			"Any data passed to pickle.loads() or pickle.load() that originates from an " +
			"untrusted source enables Remote Code Execution. CISA explicitly identifies " +
			"unsafe deserialization as a class of preventable vulnerability.",
		severity: "critical",
		languages: ["python"],
		patterns: [
			// Any pickle.loads() or pickle.load() call — there is no safe use with untrusted data
			/\bpickle\.loads?\s*\(/i,
		],
		fixDescription:
			"Replace pickle with a safe serialization format: json, msgpack (with type " +
			"restrictions), or Protocol Buffers. If pickle is used purely for internal " +
			"caching (never with network or user data), add an owasp-ignore comment with " +
			"justification. Always protect pickled data with an HMAC or signed envelope " +
			"before storing it anywhere an attacker could tamper with it.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html#python",
	},

	{
		id: "CISA-PY-YAML-UNSAFE-LOAD",
		category: "CISA: Insecure Deserialization",
		title: "Python yaml.load() used without SafeLoader (code execution risk)",
		description:
			"yaml.load() with the default Loader (or with yaml.Loader / yaml.UnsafeLoader) " +
			"supports Python-specific YAML tags that allow instantiating arbitrary Python " +
			"objects and executing OS commands " +
			"(e.g. !!python/object/apply:os.system ['id']). " +
			"CISA highlights unsafe deserialization of configuration and data formats as a " +
			"consistently exploited vulnerability class.",
		severity: "critical",
		languages: ["python"],
		patterns: [
			// yaml.load(anything) — yaml.safe_load() is the safe alternative and would NOT match
			/\byaml\.load\s*\(/i,
		],
		fixDescription:
			"Replace yaml.load(data) with yaml.safe_load(data) for all untrusted input. " +
			"safe_load() only resolves standard YAML scalar types (str, int, list, dict, etc.) " +
			"and never instantiates Python objects. If a full Loader is genuinely required " +
			"for internal config files, use yaml.load(data, Loader=yaml.SafeLoader) and " +
			"document the justification.",
		reference: "https://pyyaml.org/wiki/PyYAMLDocumentation#loading-yaml",
	},

	// ══════════════════════════════════════════════════════════════════════════
	//  Cryptographic Failures
	// ══════════════════════════════════════════════════════════════════════════

	{
		id: "CISA-CRYPTO-ECB-MODE",
		category: "CISA: Cryptographic Failures",
		title: "ECB cipher mode used — deterministic encryption leaks plaintext patterns",
		description:
			"Electronic Code Book (ECB) mode encrypts each block independently using the " +
			"same key. Identical plaintext blocks always produce identical ciphertext blocks, " +
			"making the encrypted output structure-preserving and vulnerable to pattern " +
			"analysis. CISA's Secure-by-Design guidance requires choosing authenticated " +
			"encryption modes (e.g. AES-GCM).",
		severity: "critical",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
			"php",
			"python",
		],
		patterns: [
			// Node.js: createCipheriv / createDecipheriv with an ECB algorithm string
			/createCipher(?:iv)?\s*\(\s*['"][^'"]*-ecb['"]/i,
			/createDecipher(?:iv)?\s*\(\s*['"][^'"]*-ecb['"]/i,
			// PHP: openssl_encrypt / openssl_decrypt with an ECB method string
			/openssl_(?:encrypt|decrypt)\s*\([^,)]*,[^,)]*['"][^'"]*-ECB['"]/i,
			// Python: PyCryptodome / PyCrypto MODE_ECB constant
			/\bMODE_ECB\b/,
			// Python: cryptography library ECB mode object
			/\bmodes\.ECB\s*\(/i,
		],
		fixDescription:
			"Replace ECB mode with an Authenticated Encryption with Associated Data (AEAD) " +
			"cipher such as AES-GCM or ChaCha20-Poly1305. These provide both confidentiality " +
			"and integrity and require a unique nonce per encryption operation. " +
			"Node.js: 'aes-256-gcm', PHP: 'aes-256-gcm', Python: AESGCM from cryptography.hazmat.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#cipher-modes",
	},

	{
		id: "CISA-CRYPTO-HARDCODED-IV",
		category: "CISA: Cryptographic Failures",
		title: "Hardcoded IV or nonce in symmetric encryption",
		description:
			"Reusing a fixed Initialization Vector (IV) or nonce with the same key destroys " +
			"semantic security. In CTR and GCM modes a repeated nonce allows an attacker " +
			"to XOR ciphertexts together to recover plaintext. In CBC mode it enables " +
			"chosen-plaintext attacks. CISA requires nonces and IVs to be randomly " +
			"generated per encryption operation.",
		severity: "critical",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
			"php",
			"python",
		],
		patterns: [
			// JS: Buffer.from('<hardcoded hex>') used directly as IV argument in createCipheriv
			/createCipheriv\s*\([^)]*,\s*[^,)]*,\s*Buffer\.from\s*\(\s*['"][0-9a-fA-F\\x]{8,}['"]/i,
			// JS/TS: variable named iv or nonce assigned a hardcoded string or zero-bytes
			/\b(?:iv|nonce)\s*=\s*(?:Buffer\.from\s*\(\s*['"][^'"]{4,}['"]|['"][0-9a-fA-F]{8,}['"])/i,
			// PHP: hardcoded hex/byte string literal as IV argument to openssl_encrypt/decrypt
			/openssl_(?:encrypt|decrypt)\s*\([^;)]*,\s*['"][0-9a-fA-F]{16,}['"]\s*[,)]/i,
			// Python: iv or nonce variable assigned a hardcoded byte string b'...'
			/\b(?:iv|nonce)\s*=\s*b['"][^'"]{4,}['"]/i,
		],
		fixDescription:
			"Generate the IV/nonce from a cryptographically secure random source for every " +
			"encryption operation: crypto.randomBytes(16) in Node.js, random_bytes(16) in PHP, " +
			"or os.urandom(16) in Python. Prepend the IV to the ciphertext so it can be " +
			"read back at decryption time without needing to be secret.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#iv-nonce",
	},

	// ══════════════════════════════════════════════════════════════════════════
	//  Authentication — JWT
	// ══════════════════════════════════════════════════════════════════════════

	{
		id: "CISA-JWT-ALG-NONE",
		category: "CISA: Authentication Failures",
		title: "JWT configured to accept 'none' algorithm (signature bypass)",
		description:
			"The JWT specification allows an 'alg: none' header indicating no signature is " +
			"required. Libraries that honour this value accept forged tokens without any " +
			"secret key. CISA's Secure-by-Design principles require that authentication " +
			"mechanisms have no opt-out affordances for their core security guarantees.",
		severity: "critical",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
			"python",
		],
		patterns: [
			// algorithms list explicitly includes the string 'none'
			/algorithms\s*:\s*\[[^\]]*['"]none['"]/i,
			// algorithm option set to the literal string 'none'
			/algorithm\s*[=:]\s*['"]none['"]/i,
			// python-jose / python-jwt disabling signature verification via options dict
			/['"]verify_signature['"]\s*:\s*False/i,
		],
		fixDescription:
			"Explicitly specify an allowed algorithms list that excludes 'none'. " +
			"Node.js jsonwebtoken: jwt.verify(token, secret, { algorithms: ['HS256'] }). " +
			"python-jose: jwt.decode(token, key, algorithms=['RS256']). " +
			"Never include 'none' in the allowed algorithms list.",
		reference:
			"https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
	},

	{
		id: "CISA-JWT-NO-ALG-RESTRICT",
		category: "CISA: Authentication Failures",
		title: "jwt.verify() options object missing explicit algorithms list",
		description:
			"Calling jwt.verify() with an options object that omits the 'algorithms' " +
			"property allows algorithm confusion attacks. An attacker who possesses an " +
			"RS256 public key can re-sign a token using HS256 (HMAC), using that public " +
			"key as the HMAC secret, bypassing signature verification. CISA requires " +
			"authentication components to enforce exact algorithm expectations.",
		severity: "warning",
		languages: [
			"javascript",
			"javascriptreact",
			"typescript",
			"typescriptreact",
		],
		patterns: [
			// jwt.verify options object that does NOT include 'algorithms' on the same line
			/jwt\.verify\s*\([^)]*\{(?![^}]*\balgorithms\b)[^}]*\}/i,
		],
		fixDescription:
			"Always specify an algorithms array in the options: " +
			"jwt.verify(token, secret, { algorithms: ['HS256'] }, callback). " +
			"This prevents algorithm confusion attacks and 'alg:none' bypass.",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#signature-algorithm-confusion",
	},

	// ══════════════════════════════════════════════════════════════════════════
	//  PHP-specific CISA concerns
	// ══════════════════════════════════════════════════════════════════════════

	{
		id: "CISA-PHP-TYPE-JUGGLING",
		category: "CISA: Authentication Failures",
		title: "PHP loose equality (==) used with password, hash, or token value",
		description:
			"PHP's loose equality operator (==) performs type coercion before comparing. " +
			"This enables 'magic hash' exploits where hash strings beginning with '0e' are " +
			"coerced to 0.0 in scientific notation and compare equal to any other '0e...' " +
			"hash string. Comparing a numeric-looking user string with == 0 evaluates to " +
			"true in PHP < 8. CISA identifies weak authentication logic as a preventable " +
			"root cause of authentication failures.",
		severity: "critical",
		languages: ["php"],
		patterns: [
			// $passwordVar == something (loose, not ===)
			/\$\w*(?:pass(?:word)?|pwd|hash|token|secret|pin|code|digest)\w*\s*==(?!=)\s*/i,
			// something == $passwordVar
			/\s*==(?!=)\s*\$\w*(?:pass(?:word)?|pwd|hash|token|secret|pin|code|digest)\w*/i,
		],
		fixDescription:
			"Use strict equality (===) for all security-sensitive comparisons in PHP. " +
			"For password verification use password_verify(), which performs a constant-time " +
			"comparison. For HMAC or token comparison use hash_equals($known, $provided).",
		reference:
			"https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html",
	},

	{
		id: "CISA-PHP-DYNAMIC-CLASS",
		category: "CISA: Injection",
		title: "PHP dynamic class instantiation from user-controlled variable",
		description:
			"Instantiating a PHP class from a user-supplied string (new $$userInput(), " +
			"new $classFromRequest()) allows an attacker to instantiate any autoloaded class. " +
			"If constructors or magic methods perform file operations, network calls, or " +
			"code evaluation, this leads to remote code execution. CISA identifies this as " +
			"insufficient input validation enabling injection.",
		severity: "critical",
		languages: ["php"],
		patterns: [
			// new $$var() — double-dollar variable-variable instantiation
			/\bnew\s+\$\$\w+\s*[({]/i,
			// new $superglobal['key']()
			/\bnew\s+\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i,
			// new $className() where variable name implies user-provided class
			/\bnew\s+\$(?:class(?:_?name)?|type|handler|model|controller)\s*[({]/i,
		],
		fixDescription:
			"Never instantiate classes from user-supplied strings. Use an explicit allowlist: " +
			"$allowed = ['Foo', 'Bar']; " +
			"if (in_array($className, $allowed, true)) { $obj = new $className(); } " +
			"A factory function with a match/switch on known class names is the safest pattern.",
		reference:
			"https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection",
	},

	{
		id: "CISA-PHP-REMOTE-INCLUDE",
		category: "CISA: Injection",
		title: "PHP remote or user-controlled file inclusion",
		description:
			"When allow_url_include = On in php.ini, passing a URL to include() / require() " +
			"fetches and executes arbitrary remote PHP code. Even with allow_url_include = Off, " +
			"passing user input to include/require enables Local File Inclusion (LFI) and " +
			"path traversal to sensitive files such as /etc/passwd or application config files. " +
			"CISA identifies remote code execution via file inclusion as a critical preventable " +
			"vulnerability.",
		severity: "critical",
		languages: ["php"],
		patterns: [
			// include/require with a URL literal
			/\b(?:include|require|include_once|require_once)\s*\(?['"]https?:\/\//i,
			// include/require directly from a superglobal
			/\b(?:include|require|include_once|require_once)\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i,
			// include/require with a user-data-named variable
			/\b(?:include|require|include_once|require_once)\s*\(?\s*\$(?:page|file|path|module|template|view|inc)\b/i,
		],
		fixDescription:
			"Never pass user input to include/require. Use an allowlist of permitted files: " +
			"$allowed = ['home', 'about', 'contact']; " +
			"if (in_array($page, $allowed, true)) { " +
			"include __DIR__ . '/pages/' . $page . '.php'; } " +
			"Also set allow_url_include = Off in php.ini.",
		reference:
			"https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
	},

	// ══════════════════════════════════════════════════════════════════════════
	//  Python-specific CISA concerns
	// ══════════════════════════════════════════════════════════════════════════

	{
		id: "CISA-PY-SUBPROCESS-SHELL",
		category: "CISA: Injection",
		title: "Python subprocess called with shell=True (OS command injection risk)",
		description:
			"subprocess.call(), .run(), .Popen(), and .check_output() with shell=True " +
			"pass the command to /bin/sh -c, enabling shell metacharacter injection. " +
			"Combined with any user-controlled string in the command, this leads to OS " +
			"command injection. CISA explicitly requires eliminating entire classes of " +
			"injection at the language/API level rather than relying on input sanitization.",
		severity: "critical",
		languages: ["python"],
		patterns: [
			// subprocess.*(shell=True)
			/\bsubprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*\bshell\s*=\s*True/i,
			// os.system() with string concatenation or f-string (user data present)
			/\bos\.system\s*\(\s*(?:[^)]*\+[^)]*|f['"])/i,
			// os.popen() with string concatenation or f-string
			/\bos\.popen\s*\(\s*(?:[^)]*\+[^)]*|f['"])/i,
		],
		fixDescription:
			"Pass the command as a list of arguments and keep shell=False (the default): " +
			"subprocess.run(['git', 'clone', repo_url], shell=False). " +
			"This prevents shell metacharacter interpretation. " +
			"If shell=True cannot be avoided, sanitize every user-supplied argument " +
			"with shlex.quote().",
		reference:
			"https://docs.python.org/3/library/subprocess.html#security-considerations",
	},

	{
		id: "CISA-PY-SSL-NO-VERIFY",
		category: "CISA: Cryptographic Failures",
		title: "Python TLS certificate verification disabled",
		description:
			"Setting verify=False in requests/httpx, or using ssl.CERT_NONE / " +
			"check_hostname=False, disables TLS certificate chain validation. " +
			"This allows man-in-the-middle attacks where any certificate — including " +
			"self-signed or expired — is accepted. CISA's Secure-by-Design principles " +
			"require encryption in transit with full certificate validation.",
		severity: "critical",
		languages: ["python"],
		patterns: [
			// requests / httpx with verify=False
			/\brequests?\.\w+\s*\([^)]*\bverify\s*=\s*False/i,
			/\bhttpx?\.\w+\s*\([^)]*\bverify\s*=\s*False/i,
			// ssl module constants or properties disabling verification
			/\bssl\.CERT_NONE\b/,
			/\bcheck_hostname\s*=\s*False\b/i,
			// Suppressing urllib3 InsecureRequestWarning — almost always masks verify=False
			/\bInsecureRequestWarning\b/,
		],
		fixDescription:
			"Remove verify=False. Ensure the server presents a certificate signed by a " +
			"trusted CA. If using a private or self-signed CA, pass the bundle path: " +
			"requests.get(url, verify='/path/to/ca-bundle.crt'). " +
			"For ssl contexts, use ssl.create_default_context() without modification.",
		reference:
			"https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification",
	},

	{
		id: "CISA-PY-JINJA2-AUTOESCAPE-OFF",
		category: "CISA: Injection",
		title: "Jinja2 environment created with HTML autoescaping disabled",
		description:
			"Jinja2 disables HTML autoescaping by default outside Flask. Creating a " +
			"jinja2.Environment without autoescape=True (or with autoescape=False) causes " +
			"template variables to be rendered verbatim, enabling stored or reflected XSS " +
			"whenever any user-controlled value is rendered. CISA requires that security " +
			"features be enabled by default and that disabling them be an explicit, " +
			"justified override.",
		severity: "critical",
		languages: ["python"],
		patterns: [
			// jinja2.Environment() without autoescape=True on the same line
			/jinja2\.Environment\s*\((?![^)]*\bautoescape\s*=\s*True)[^)]*\)/i,
			// explicit autoescape=False anywhere
			/\bautoescape\s*=\s*False\b/i,
		],
		fixDescription:
			"Set autoescape=True when constructing the Jinja2 Environment: " +
			"env = jinja2.Environment(autoescape=True, loader=...). " +
			"For mixed HTML/non-HTML templates, use " +
			"autoescape=select_autoescape(['html', 'xml']). " +
			"Note: Flask enables autoescaping automatically for .html/.htm/.xml templates.",
		reference:
			"https://jinja.palletsprojects.com/en/3.1.x/api/#autoescaping",
	},

	{
		id: "CISA-PY-XML-UNSAFE",
		category: "CISA: Injection",
		title: "Python stdlib XML parser — vulnerable to XXE and Billion Laughs DoS",
		description:
			"Python's built-in xml.etree.ElementTree, xml.dom.minidom, and xml.sax parsers " +
			"do not defend against XML eXternal Entity (XXE) injection or Billion Laughs " +
			"(exponential entity expansion) denial-of-service attacks when parsing untrusted " +
			"XML. CISA highlights XXE as a consistently exploited vulnerability in " +
			"server-side components.",
		severity: "warning",
		languages: ["python"],
		patterns: [
			// xml.etree.ElementTree parse / fromstring
			/\bElementTree\.(?:parse|fromstring|XML|XMLID)\s*\(/i,
			// Common ET alias for ElementTree
			/\bET\.(?:parse|fromstring|XML)\s*\(/i,
			// xml.dom.minidom
			/\bminidom\.(?:parse|parseString)\s*\(/i,
			// xml.sax
			/\bxml\.sax\.(?:parse|parseString)\s*\(/i,
		],
		fixDescription:
			"Use the defusedxml library, which disables dangerous XML features by default: " +
			"import defusedxml.ElementTree as ET; tree = ET.fromstring(data). " +
			"Install with: pip install defusedxml. " +
			"For applications that only parse fully internal, trusted XML " +
			"(never from the network or user uploads), add an owasp-ignore comment " +
			"with justification.",
		reference:
			"https://docs.python.org/3/library/xml.html#xml-vulnerabilities",
	},
];
