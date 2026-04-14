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
shouldMatch("A04-MISSING-CSRF", "$name = $_POST['name'];");
// A line that contains a CSRF reference should NOT fire
shouldNotMatch("A04-MISSING-CSRF", "$token = $_POST['csrf_token'];");
shouldNotMatch("A04-MISSING-CSRF", "verifyToken($_POST['token']);");

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
