# OWASP Security Helper

A VS Code extension that detects insecure coding practices in real time using **OWASP Top 10 (2021)** rules, **Content Security Policy** analysis, dedicated **PHP** and **JavaScript / TypeScript** rule packs, and **PHP input validation** patterns based on the OWASP Input Validation Cheat Sheet.

**86 rules** across 6 categories — diagnostics appear inline as you type, with Quick Fix actions and a full security report panel.

---

## Features

| Feature                           | Detail                                                                                                          |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **Real-time inline diagnostics**  | Red/yellow/blue squiggles appear as you type or on save                                                         |
| **OWASP Top 10 (2021) — A01–A10** | Full coverage: 27 rules for JS/TS, Python, and PHP                                                              |
| **PHP security rules**            | 13 PHP-specific rules covering XSS, injection, file upload, type juggling, and more                             |
| **PHP input validation rules**    | 18 rules based on the OWASP Input Validation Cheat Sheet                                                        |
| **JavaScript / TypeScript rules** | 12 rules for dangerous DOM APIs, NoSQL injection, JWT, rate limiting, and more                                  |
| **CSP analysis**                  | 8 rules detecting `unsafe-inline`, wildcards, missing directives, and report-uri                                |
| **General secure-coding rules**   | 7 rules covering hardcoded secrets, insecure TLS, prototype pollution, XXE, ReDoS                               |
| **Severity levels**               | Critical 🔴 / Warning 🟡 / Info 🔵 — configurable minimum threshold                                             |
| **Quick Fixes**                   | Auto-fix, suppress with comment, or open OWASP reference docs                                                   |
| **Security Report panel**         | Full webview summary: filter by severity, By Severity / By File views, severity filter chips, mitigated section |
| **Workspace scan**                | Scan every supported file across the workspace; raw-byte reader bypasses the tokenizer for large files          |
| **Saved HTML + JSON reports**     | Each scan writes a timestamped `.html` + `.json` report to `.securityReport/`                                   |
| **Justification / mitigation**    | Add a suppression justification in-source; persists across rescans                                              |
| **Rule update checker**           | Compares bundled rules against a remote manifest and notifies on new versions                                   |

---

## Commands

All commands are available via the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`).

| Command                                | Description                                                               |
| -------------------------------------- | ------------------------------------------------------------------------- |
| `OWASP Helper: Show Security Report`   | Open the report panel displaying all findings for open files              |
| `OWASP Helper: Scan Workspace`         | Scan every supported file in the workspace and surface diagnostics        |
| `OWASP Helper: Check for Rule Updates` | Fetch the remote manifest and report whether newer rules are available    |
| `OWASP Helper: Show Rules Status`      | Display a Quick Pick listing rule version, coverage, and total rule count |

---

## Configuration

| Setting                           | Type    | Default          | Description                                                        |
| --------------------------------- | ------- | ---------------- | ------------------------------------------------------------------ |
| `owaspHelper.enableOnSave`        | boolean | `true`           | Re-scan the file automatically on every save                       |
| `owaspHelper.severity`            | string  | `"all"`          | Minimum severity to report: `all`, `critical`, `warning`, `info`   |
| `owaspHelper.ignoredRules`        | array   | `[]`             | Rule IDs to suppress, e.g. `["A03-XSS-INNERHTML", "GEN-HTTP-URL"]` |
| `owaspHelper.autoCheckForUpdates` | boolean | `true`           | Check for new rule versions once per day on startup                |
| `owaspHelper.rulesManifestUrl`    | string  | (GitHub raw URL) | URL of the remote `rules-manifest.json` used for update comparison |

---

## Supported Languages

| Language                     | Rule packs applied               |
| ---------------------------- | -------------------------------- |
| JavaScript / JSX             | OWASP, CSP, General, JS/TS       |
| TypeScript / TSX             | OWASP, CSP, General, JS/TS       |
| PHP                          | OWASP, PHP, PHP Input Validation |
| Python                       | OWASP, General                   |
| Apache config / `.htaccess`  | CSP, General                     |
| IIS `web.config` / `.config` | CSP, General                     |

---

## Rule Reference

### A: OWASP Top 10 (2021) — 27 rules

| Rule ID                            | OWASP Category                | Description                                                      | Severity |
| ---------------------------------- | ----------------------------- | ---------------------------------------------------------------- | -------- |
| `A01-DIRECTORY-TRAVERSAL`          | A01 Broken Access Control     | Path traversal via unsanitised user input                        | Critical |
| `A02-WEAK-HASH-MD5`                | A02 Cryptographic Failures    | MD5 used as a cryptographic hash                                 | Critical |
| `A02-WEAK-HASH-SHA1`               | A02 Cryptographic Failures    | SHA-1 used as a cryptographic hash                               | Warning  |
| `A02-HARDCODED-SECRET`             | A02 Cryptographic Failures    | Secret / password / API key in source code                       | Critical |
| `A02-INSECURE-RANDOM`              | A02 Cryptographic Failures    | Non-cryptographic random (`Math.random`, `rand()`)               | Warning  |
| `A03-SQL-INJECTION`                | A03 Injection                 | String-concatenated SQL query                                    | Critical |
| `A03-COMMAND-INJECTION`            | A03 Injection                 | Shell command built from user-controlled data                    | Critical |
| `A03-XSS-INNERHTML`                | A03 Injection                 | Unsafe `innerHTML` assignment                                    | Critical |
| `A03-EVAL-INJECTION`               | A03 Injection                 | `eval()` called with dynamic data                                | Critical |
| `A03-TEMPLATE-INJECTION`           | A03 Injection                 | Server-side template rendered with user input                    | Critical |
| `A04-MISSING-CSRF`                 | A04 Insecure Design           | State-changing route with no CSRF token check                    | Warning  |
| `A04-MASS-ASSIGNMENT`              | A04 Insecure Design           | Model created directly from request body                         | Critical |
| `A04-INSECURE-DIRECT-OBJECT-REF`   | A04 Insecure Design           | Object retrieved by user-supplied ID without authorisation check | Warning  |
| `A04-UNRESTRICTED-FILE-SIZE`       | A04 Insecure Design           | File upload with no size limit enforced                          | Warning  |
| `A04-TIMING-ATTACK`                | A04 Insecure Design           | String equality used for secrets (timing-unsafe)                 | Warning  |
| `A05-DEBUG-ENABLED`                | A05 Security Misconfiguration | Debug mode enabled in production config                          | Warning  |
| `A05-CORS-WILDCARD`                | A05 Security Misconfiguration | CORS policy allows all origins (`*`)                             | Warning  |
| `A06-VULNERABLE-JQUERY`            | A06 Vulnerable Components     | Old jQuery version with known vulnerabilities                    | Warning  |
| `A06-KNOWN-VULNERABLE-PACKAGE`     | A06 Vulnerable Components     | Known-vulnerable npm package referenced                          | Warning  |
| `A06-KNOWN-VULNERABLE-PACKAGE-PHP` | A06 Vulnerable Components     | Known-vulnerable Composer package referenced                     | Critical |
| `A06-EVAL-PACKAGE`                 | A06 Vulnerable Components     | Package that evaluates arbitrary code at runtime                 | Critical |
| `A07-INSECURE-COOKIE`              | A07 Auth Failures             | Cookie set without Secure / HttpOnly flags                       | Warning  |
| `A07-JWT-NONE-ALG`                 | A07 Auth Failures             | JWT decoded/verified accepting `none` algorithm                  | Critical |
| `A08-DESERIALIZE-PICKLE`           | A08 Data Integrity Failures   | Python pickle deserialisation of untrusted data                  | Critical |
| `A08-DESERIALIZE-PHP`              | A08 Data Integrity Failures   | PHP `unserialize()` on untrusted data                            | Critical |
| `A09-SENSITIVE-LOG`                | A09 Logging Failures          | Password / token logged in plain text                            | Warning  |
| `A10-SSRF`                         | A10 SSRF                      | HTTP request built from user-supplied URL                        | Critical |

---

### B: Content Security Policy — 8 rules

| Rule ID                       | What it detects                                          | Severity |
| ----------------------------- | -------------------------------------------------------- | -------- |
| `CSP-UNSAFE-INLINE`           | `'unsafe-inline'` in script-src or style-src             | Critical |
| `CSP-UNSAFE-EVAL`             | `'unsafe-eval'` in CSP directives                        | Critical |
| `CSP-WILDCARD-SRC`            | Wildcard (`*`) source in any CSP directive               | Critical |
| `CSP-MISSING-DEFAULT-SRC`     | CSP header with no `default-src` fallback                | Warning  |
| `CSP-MISSING-OBJECT-SRC`      | Missing `object-src` directive (allows plugin injection) | Warning  |
| `CSP-HTTP-SOURCE`             | `http://` origin in a CSP source list                    | Warning  |
| `CSP-MISSING-FRAME-ANCESTORS` | Missing `frame-ancestors` (clickjacking risk)            | Warning  |
| `CSP-REPORT-MISSING`          | No `report-uri` or `report-to` directive                 | Info     |

---

### C: General Secure Coding — 7 rules

| Rule ID                   | What it detects                                       | Severity |
| ------------------------- | ----------------------------------------------------- | -------- |
| `GEN-HTTP-URL`            | Plaintext HTTP URL (not HTTPS)                        | Warning  |
| `GEN-TLS-REJECT-DISABLED` | TLS certificate verification disabled                 | Critical |
| `GEN-PROTOTYPE-POLLUTION` | Assignment to `__proto__` or `Object.prototype`       | Warning  |
| `GEN-XXE`                 | XML parsing without external entity protection        | Critical |
| `GEN-REDOS`               | Regex pattern vulnerable to catastrophic backtracking | Warning  |
| `GEN-SENSITIVE-COMMENT`   | TODO/FIXME comment referencing secrets or auth        | Warning  |
| `GEN-WORLD-WRITABLE`      | File permissions set to world-writable (0777/0666)    | Warning  |

---

### D: PHP Security — 14 rules

| Rule ID                         | What it detects                                          | Severity |
| ------------------------------- | -------------------------------------------------------- | -------- |
| `PHP-ECHO-XSS`                  | Unescaped `echo` of user-controlled data                 | Critical |
| `PHP-HTMLSPECIALCHARS-FLAGS`    | `htmlspecialchars()` without `ENT_QUOTES` flag           | Warning  |
| `PHP-OPEN-REDIRECT`             | `header('Location: ...')` built from user input          | Critical |
| `PHP-HEADER-INJECTION`          | User input injected into arbitrary HTTP response headers | Critical |
| `PHP-EXTRACT`                   | `extract($_GET/POST)` overwrites arbitrary variables     | Critical |
| `PHP-PREG-REPLACE-E`            | `preg_replace()` with `/e` modifier (code execution)     | Critical |
| `PHP-ASSERT-INJECTION`          | `assert()` called with a user-supplied string            | Critical |
| `PHP-VARIABLE-VARIABLE`         | Variable variable (`$$var`) sourced from user input      | Critical |
| `PHP-FILE-UPLOAD-NO-VALIDATION` | File upload storage without extension or MIME checks     | Critical |
| `PHP-DEPRECATED-MYSQL`          | Deprecated `mysql_*` functions (removed in PHP 7)        | Critical |
| `PHP-LDAP-INJECTION`            | User input used in LDAP search without escaping          | Critical |
| `PHP-TYPE-JUGGLING`             | Loose comparison (`==`) used with user-supplied data     | Warning  |
| `PHP-PLAIN-PASSWORD-STORE`      | Password stored without hashing                          | Critical |
| `PHP-SQL-INJECTION`             | SQL query built via PHP string concatenation             | Critical |

---

### E: PHP Input Validation — 18 rules

Based on the [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html).

| Rule ID                            | What it detects                                                             | Severity |
| ---------------------------------- | --------------------------------------------------------------------------- | -------- |
| `PHP-IV-RAW-GET`                   | `$_GET` value used without any validation                                   | Warning  |
| `PHP-IV-RAW-POST`                  | `$_POST` value used without any validation                                  | Warning  |
| `PHP-IV-FILTER-DEFAULT`            | `filter_var()` / `filter_input()` with `FILTER_DEFAULT` (no-op)             | Warning  |
| `PHP-IV-MISSING-EMAIL-VALIDATION`  | Email variable from superglobal without `FILTER_VALIDATE_EMAIL`             | Warning  |
| `PHP-IV-MISSING-URL-VALIDATION`    | URL variable from superglobal without `FILTER_VALIDATE_URL`                 | Warning  |
| `PHP-IV-MISSING-INT-VALIDATION`    | `intval()` or `(int)` cast without range validation                         | Warning  |
| `PHP-IV-NO-LENGTH-CHECK`           | String stored in DB without `strlen` / `mb_strlen` check                    | Warning  |
| `PHP-IV-REGEX-NO-ANCHORS`          | `preg_match()` validation pattern missing `^` / `$` anchors                 | Warning  |
| `PHP-IV-DENYLIST-ONLY`             | `str_replace` / `strip_tags` used as primary sanitiser (denylist approach)  | Warning  |
| `PHP-IV-NO-ENUM-ALLOWLIST`         | Enumerable param (sort, status, type) used without `in_array()` allowlist   | Warning  |
| `PHP-IV-NULL-BYTE`                 | File operation on user input without null-byte check                        | Critical |
| `PHP-IV-FILE-MIME-TRUST`           | Trusting browser-supplied `$_FILES['type']` instead of `finfo_file()`       | Critical |
| `PHP-IV-FILE-UPLOAD-EXTENSION`     | `move_uploaded_file()` without extension allowlist validation               | Critical |
| `PHP-IV-FILE-UPLOAD-USER-FILENAME` | Uploaded file stored using original `$_FILES['name']` (path traversal risk) | Critical |
| `PHP-IV-FILE-UPLOAD-WEB-ROOT`      | Uploaded file written directly inside the web root                          | Warning  |
| `PHP-IV-ZIP-SLIP`                  | `ZipArchive::extractTo()` without path-traversal or size validation         | Critical |
| `PHP-IV-CLIENT-SIDE-ONLY`          | Comment or code suggesting only client-side validation is used              | Info     |
| `PHP-IV-SETTYPE-NOT-VALIDATION`    | `settype()` on user input used as a validation substitute                   | Warning  |

---

### F: JavaScript / TypeScript — 12 rules

| Rule ID                       | What it detects                                              | Severity |
| ----------------------------- | ------------------------------------------------------------ | -------- |
| `JS-DANGEROUS-INNER-HTML`     | Direct `innerHTML` assignment from user data                 | Critical |
| `JS-OPEN-REDIRECT`            | `window.location` set from user-controlled source            | Critical |
| `JS-POSTMESSAGE-NO-ORIGIN`    | `postMessage` listener with no origin check                  | Warning  |
| `JS-SETTIMEOUT-STRING`        | `setTimeout` / `setInterval` called with a string argument   | Critical |
| `JS-SENSITIVE-STORAGE`        | Token / password stored in `localStorage` / `sessionStorage` | Warning  |
| `JS-NOSQL-INJECTION`          | Mongoose / MongoDB query built from user-controlled data     | Critical |
| `JS-REGEX-USER-INPUT`         | `new RegExp()` constructed from user input (ReDoS risk)      | Warning  |
| `JS-SENDFILE-TRAVERSAL`       | Express `res.sendFile()` path built from user input          | Critical |
| `JS-JWT-NO-VERIFY`            | JWT decoded without signature verification                   | Critical |
| `JS-NO-RATE-LIMIT`            | Express route with no rate-limit middleware                  | Warning  |
| `JS-CHILD-PROCESS-USER-INPUT` | `child_process.exec` / `spawn` with user-supplied arguments  | Critical |
| `JS-INSECURE-COOKIE-OPTIONS`  | Cookie set without `httpOnly` or `secure` flags              | Warning  |

---

## Suppressing Rules

To suppress a specific rule for a line, use a Quick Fix action or manually add a suppression comment above the line:

```php
// owasphelper-disable PHP-TYPE-JUGGLING
if ($user_input == "admin") { ... }
```

To suppress rules globally across the workspace, add their IDs to settings:

```json
"owaspHelper.ignoredRules": ["GEN-HTTP-URL", "PHP-IV-RAW-GET"]
```

---

## References

- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [Content Security Policy — MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [VS Code Extension API](https://code.visualstudio.com/api)

## License

MIT
