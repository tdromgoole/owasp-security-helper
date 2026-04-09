# Changelog

All notable changes to OWASP Security Helper are documented here.
This project uses [calendar versioning](https://calver.org/) for its rule set (`YYYY.MM.PATCH`).

---

## [0.2.0] — 2026-04-08

### Added

- **New rule: `PHP-SQL-INJECTION`** — dedicated PHP-only rule detecting SQL queries built via string concatenation (dot-concat patterns). Split out from the shared `A03-SQL-INJECTION` rule to eliminate false positives on JS/TS files.
- **Apache / IIS config file scanning** — workspace scan now covers `.conf`, `web.config` / `.config`, and `.htaccess` files. CSP and General rules fire on these file types, enabling detection of missing or misconfigured security headers in server configuration files.
- **Saved report companion JSON** — each workspace scan now writes both a `.html` and a `.json` report to `.securityReport/YYYY-MM-DD_HH-MM-SS.{html,json}`. The JSON is used to reload a saved report into the panel without rescanning.
- **Justification persistence** — suppression comments added via "Add Justification" are saved to disk immediately so they survive subsequent raw-byte rescans.
- **Severity filter chips** — the report panel summary bar now has clickable severity filter chips (Critical / Warnings / Info / Mitigated). The Mitigated chip is mutually exclusive with the severity chips.

### Fixed

- **Scan stalling on large workspaces** — replaced `openTextDocument` with a raw-byte reader (`openForScan`) that skips VS Code's tokenizer and language servers. Files over 512 KB are skipped entirely; lines over 2000 characters are ignored to prevent regex backtracking freezes.
- **Duplicate findings after rescan** — added a `seenKeys` deduplication set keyed on `rule + normalised path + line`. Path normalisation now converts `\` to `/` before lower-casing so that Windows forward-slash and backslash variants of the same path produce the same key.
- **Info findings visible when Mitigated filter active** — the Mitigated filter chip now clears all active severity filters when clicked, and any severity chip clears the Mitigated filter. Both groups can no longer be shown simultaneously.
- **PHP SQL injection false positives on JS/TS** — removed `"php"` from the language list of `A03-SQL-INJECTION`; PHP files are now handled exclusively by the new `PHP-SQL-INJECTION` rule.
- **`.webconfig` glob matched nothing** — IIS config files have the extension `.config`, not `.webconfig`. Corrected the workspace scan glob to `**/*.{js,jsx,ts,tsx,py,php,conf,config}` and added a separate `findFiles("**/.htaccess")` pass.
- **Concurrent scan lock** — added an `isScanning` guard to prevent a second scan from starting while one is already in progress.

---

## [0.1.0] — 2026-04-03

Initial public release. **85 rules** across 6 categories.

### Added

#### Core extension

- Real-time inline diagnostics via `DiagnosticCollection` — squiggles appear as you type (800 ms debounce on keystroke, immediate on save)
- Quick Fix code actions for every finding: one-click auto-fix, suppress-with-comment, and open OWASP reference docs
- Security Report webview panel — findings grouped by severity with nonce-secured Content Security Policy
- Workspace-wide scan command that processes every supported file (JS, TS, JSX, TSX, PHP, Python)
- Configurable minimum severity threshold (`owaspHelper.severity`: `all` / `critical` / `warning` / `info`)
- Per-rule suppression via `owaspHelper.ignoredRules` setting
- `owaspHelper.enableOnSave` option for automatic re-scan on every file save
- Rule update checker: fetches a remote `rules-manifest.json`, compares the bundled version, and notifies when newer rules exist
- Auto-check on startup (once per day, tracked via VS Code `globalState`)
- `OWASP Helper: Check for Rule Updates` command for manual on-demand checks
- `OWASP Helper: Show Rules Status` Quick Pick displaying rule version, coverage summary, and total rule count
- Calendar-versioned rule set — initial version `2026.04.1`

#### OWASP Top 10 (2021) — 27 rules

- **A01 Broken Access Control** — directory traversal via unsanitised user input
- **A02 Cryptographic Failures** — MD5 hash (Critical), SHA-1 hash (Warning), hardcoded secrets (Critical), non-cryptographic random (Warning)
- **A03 Injection** — SQL injection including PHP dot-concatenation patterns, command injection, XSS via `innerHTML`, `eval()` injection, server-side template injection
- **A04 Insecure Design** — missing CSRF token, mass assignment, insecure direct object reference, unrestricted file upload size, timing-unsafe equality for secrets
- **A05 Security Misconfiguration** — debug mode enabled in production, CORS wildcard (`*`)
- **A06 Vulnerable Components** — outdated jQuery, known-vulnerable npm packages, known-vulnerable Composer packages, code-evaluating packages
- **A07 Authentication Failures** — insecure cookie flags (no Secure/HttpOnly), JWT `none` algorithm acceptance
- **A08 Data Integrity Failures** — Python pickle deserialisation of untrusted data, PHP `unserialize()` on untrusted data
- **A09 Logging Failures** — passwords and tokens logged in plain text
- **A10 SSRF** — HTTP request constructed from a user-supplied URL

#### Content Security Policy — 8 rules

- `'unsafe-inline'` and `'unsafe-eval'` in CSP directives (Critical)
- Wildcard source (`*`) in any directive (Critical)
- Missing `default-src` fallback, missing `object-src`, HTTP source in source list, missing `frame-ancestors` (Warning)
- Missing `report-uri` / `report-to` directive (Info)

#### General Secure Coding — 7 rules

- Plaintext HTTP URLs, disabled TLS certificate verification
- Prototype pollution via `__proto__` or `Object.prototype` assignment
- XML External Entity (XXE) loading in XML parsers
- Catastrophic ReDoS regex patterns
- Sensitive information in TODO/FIXME comments
- World-writable file permissions (0777 / 0666)

#### PHP Security — 13 rules

- Unescaped `echo` of user-controlled data (XSS)
- `htmlspecialchars()` without `ENT_QUOTES` flag
- Open redirect via `header('Location: ...')` from user input
- HTTP response header injection
- `extract($_GET/POST)` enabling arbitrary variable overwrite
- `preg_replace()` with `/e` modifier (remote code execution)
- `assert()` called with a user-supplied string
- Variable variables (`$$var`) sourced from user input
- File upload stored without extension allowlist or MIME validation
- Deprecated `mysql_*` functions (removed in PHP 7)
- LDAP injection via unescaped user input in search filters
- Loose type comparison (`==`) with user-supplied data (type juggling)
- Plain-text password storage (no `password_hash()`)

#### PHP Input Validation — 18 rules

Based on the [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html).

- Raw `$_GET` / `$_POST` values used without any validation wrapper
- `filter_var()` / `filter_input()` called with `FILTER_DEFAULT` (no-op filter)
- Email field from superglobal without `FILTER_VALIDATE_EMAIL` check
- URL field from superglobal without `FILTER_VALIDATE_URL` check
- `intval()` / `(int)` cast on user input without range validation
- String values stored in database without `strlen` / `mb_strlen` length check
- `preg_match()` validation pattern missing `^` / `$` anchors
- Denylist sanitisation (`str_replace`, `strip_tags`) used as the primary defence
- Enumerable input (sort, status, action, type) used without `in_array()` allowlist
- File operations on user input without null-byte injection check (Critical)
- Browser-supplied `$_FILES['type']` trusted instead of `finfo_file()` (Critical)
- `move_uploaded_file()` without extension allowlist validation (Critical)
- Uploaded file stored using original `$_FILES['name']` — path traversal risk (Critical)
- Uploaded files written directly inside the web root
- `ZipArchive::extractTo()` without path-traversal or decompression-size checks — Zip Slip (Critical)
- Client-side-only validation (HTML5 attributes) without corresponding server-side checks (Info)
- `settype()` on superglobal used as a validation substitute

#### JavaScript / TypeScript — 12 rules

- Direct `innerHTML` assignment from user-controlled data (XSS)
- `window.location` set from user-controlled source (open redirect)
- `postMessage` event listener with no origin validation
- `setTimeout` / `setInterval` called with a string argument (implicit eval)
- Sensitive tokens or passwords stored in `localStorage` / `sessionStorage`
- Mongoose / MongoDB queries built directly from user-controlled data (NoSQL injection)
- `new RegExp()` constructed from user input (ReDoS risk)
- Express `res.sendFile()` path built from user input (path traversal)
- JWT decoded without signature verification
- Express route handler registered with no rate-limit middleware
- `child_process.exec` / `spawn` called with user-supplied arguments (command injection)
- Cookie set without `httpOnly` or `secure` flags
