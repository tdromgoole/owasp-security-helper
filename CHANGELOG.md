# Changelog

All notable changes to OWASP Security Helper are documented here.
This project uses [calendar versioning](https://calver.org/) for its rule set (`YYYY.MM.PATCH`).

---

## [1.1.0] — 2026-06-07

### Added

- **GitHub Copilot integration — "Ask Copilot to fix" code action** — every OWASP Security Helper diagnostic now includes an **Ask Copilot to fix: \<RULE-ID\>** option in the Quick Fix lightbulb menu. Clicking it opens GitHub Copilot Chat pre-loaded with the rule ID, severity, a plain-English description of the vulnerability, the exact flagged line, and a request for a corrected version — no copy-pasting or context switching required. The command is registered as `owaspHelper.askCopilotToFix` and invokes `workbench.action.chat.open` with a fully-formed query.

- **Workspace Copilot instructions** (`.github/copilot-instructions.md`) — a workspace-level instructions file that teaches GitHub Copilot about every security rule enforced by the extension. When generating new code in this workspace, Copilot will automatically avoid the patterns that would trigger diagnostics and suggest secure alternatives instead.

- **Reusable security prompt files** (`.github/prompts/`) — three ready-made Copilot Chat prompt files for common security workflows:
    - `analyze-finding.prompt.md` — explain a specific finding, walk through the exploit scenario, and provide a corrected version.
    - `security-review-file.prompt.md` — request a full OWASP Top 10 review of the current file with an overall risk rating and prioritised fix list.
    - `fix-vulnerability.prompt.md` — generate a secure replacement for a flagged code block, constrained to the project's language and existing dependencies.

---

## [1.0.0] — 2026-05-21

### Added

- **8 new security rules (133 total)** — the following gaps identified during a rule audit have been filled:
    - **PHP-CURL-SSRF** — flags `curl_setopt($ch, CURLOPT_URL, $_GET[...])` patterns. The existing A10-SSRF rule only catches `curl_exec` when user input appears directly in the call; the real-world PHP SSRF pattern uses a two-step setup that was not previously detected.
    - **PHP-PHPINFO** — flags any call to `phpinfo()`. In production this exposes server configuration, PHP version, loaded extensions, and environment variables to anyone who can trigger the response.
    - **PHP-DEBUG-OUTPUT** — flags `var_dump()`, `print_r()`, and `var_export()` when called with a PHP superglobal, catching debug statements that leak internal data in production.
    - **PHP-SESSION-FIXATION** — flags `session_id($_GET[...])` / `session_id($_POST[...])` / `session_id($_COOKIE[...])`. Accepting a session ID from user input allows an attacker to set a known ID and hijack the session after the victim authenticates.
    - **IV-PY-SQL-FSTRING** — flags Python SQL queries built with f-strings (`f"SELECT … {user_id}"`) or `.format()`. The existing A03-SQL-INJECTION rule only covered `%`-style string formatting; f-strings and `.format()` were completely missed.
    - **IV-PY-DJANGO-CSRF-EXEMPT** — flags the `@csrf_exempt` decorator. This silently disables CSRF validation on the decorated view and is commonly applied to API endpoints and forgotten.
    - **IV-PY-DJANGO-ALLOWED-HOSTS** — flags `ALLOWED_HOSTS = ['*']` in Django settings. This disables Host header validation and enables Host header injection attacks.
    - **GEN-HARDCODED-CLOUD-KEY** — flags hardcoded AWS access key IDs (`AKIA…`/`ASIA…`), private key PEM blocks (`-----BEGIN … PRIVATE KEY-----`), and GCP API keys (`AIza…`) across all supported languages. The existing A02-HARDCODED-SECRET rule catches generic `password =` assignments but not credential-format patterns.

---

## [0.9.0] — 2026-05-21

### Added

- **CVE database status in the Security Report** — the Security Report panel now shows a banner indicating the state of your local CVE database at the time the report was generated:
    - **Not downloaded** — a red banner alerts you that dependency vulnerability scanning is limited and provides a one-click button to open the CVE database manager.
    - **Out of date** — an orange banner appears when the database has not been updated in more than 7 days, showing the exact last-updated date and time alongside an update button.
    - **Current** — a blue info strip shows the date and time the database was last updated, so you always know how fresh your CVE coverage is.

### Improved

- **PHP false positive reduction** — several PHP rules were refined to dramatically cut the number of false positive findings in real-world codebases:
    - SQL injection findings are now split into two levels: a **Critical** finding when user-supplied superglobal values (such as `$_POST` or `$_GET`) appear directly in a SQL string, and a lower-severity **Warning** when a generic variable is used — making it easier to triage real risks first.
    - The CSRF check now fires once per form handler entry point rather than once per `$_POST` read, reducing noise in large PHP form handlers from hundreds of findings to one.
    - Raw `$_POST` and `$_GET` rules now recognise validators that appear on the same line as the superglobal (for example `isset($_POST['field'])`), removing a common source of false positives on standard PHP null-checks.
    - A context-aware suppression mechanism was added: if a `$_POST` or `$_GET` key was validated within the preceding few lines using a real validator (such as `is_numeric`, `filter_var`, or `preg_match`), the raw-use finding on that key is suppressed automatically. `isset` and `empty` are intentionally excluded from this suppression — they check existence, not content.

---

## [0.8.0] — 2026-05-09

### Added

- **End-of-life & deprecated dependency detection** — the dependency scanner now flags packages that have reached end-of-life or been officially marked deprecated, not just packages with known CVEs. This closes a significant security blind spot: once a package stops receiving updates, future vulnerabilities go unpatched even if no CVE exists yet. Affected packages appear in a dedicated **EOL / Deprecated** tab in the dependency panel, with the reason, badge, and a clear explanation of the risk.

- **Local CVE database** — you can now download and maintain an offline copy of the full CVE catalogue (sourced from the [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) feed) directly inside VS Code. The dependency scanner automatically cross-references this local database alongside the existing live vulnerability feeds, giving broader coverage without relying solely on internet lookups. The database supports incremental delta updates so you don't need to re-download the full catalogue each time. Three new commands support this workflow:
    - **Open CVE Database** — opens the CVE database manager panel showing current status and allowing searches by vendor or product name.
    - **Download CVE Baseline** — performs an initial download of the full CVE catalogue into local storage.
    - **Update CVE Database (Delta)** — applies only the changes since the last update, keeping the database current efficiently.

---

## [0.7.0] — 2026-05-07

### Added

- **Markdown export** — the Security Report panel now includes an **Export to Markdown** button alongside the existing PDF export. Clicking it writes a timestamped `.md` file to `.securityReport/` and offers to open it directly in the editor. The report includes a summary table, all active findings grouped by severity, and any mitigated findings with their justifications. Markdown reports are portable, diff-friendly, and can be committed alongside project code.

---

## [0.6.1] — 2026-04-14

### Fixed

- **PDF export — "Printing is not available" error** — when Chrome's `--headless=new` renderer rejects `Page.printToPDF` (a known limitation in some Chrome builds and environments), the exporter now automatically retries with `--headless` (classic headless mode), which reliably supports PDF printing.
- **PDF export — timeout on large reports** — PDF generation capped each severity section at 300 cards in the rendered HTML. Reports with thousands of findings (e.g. 9 000+) previously caused Chrome to time out during rendering; sections beyond 300 entries now show a notice directing users to the interactive HTML report for the full list.

---

## [0.6.0] — 2026-04-14

### Added

- **CISA Secure-by-Design rules** — 14 new rules in `cisaRules.ts` based on [CISA Secure-by-Design guidance](https://www.cisa.gov/resources-tools/resources/secure-by-design). All rules are net-new and do not overlap with any existing OWASP, General, PHP, JS, or Input Validation rules:
    - `CISA-PHP-UNSERIALIZE` — PHP `unserialize()` called on user-supplied data (object injection / RCE)
    - `CISA-PY-PICKLE-UNSAFE` — `pickle.loads()` / `pickle.load()` — arbitrary code execution risk
    - `CISA-PY-YAML-UNSAFE-LOAD` — `yaml.load()` without SafeLoader (RCE via YAML Python object tags)
    - `CISA-CRYPTO-ECB-MODE` — ECB cipher mode used in JS/PHP/Python (deterministic, pattern-leaking ciphertext)
    - `CISA-CRYPTO-HARDCODED-IV` — hardcoded IV or nonce in symmetric encryption across all three languages
    - `CISA-JWT-ALG-NONE` — JWT configured to accept the `none` algorithm (signature bypass)
    - `CISA-JWT-NO-ALG-RESTRICT` — `jwt.verify()` options missing an explicit `algorithms` list (algorithm confusion)
    - `CISA-PHP-TYPE-JUGGLING` — loose equality (`==`) comparing password / hash / token variables (magic hash exploits)
    - `CISA-PHP-DYNAMIC-CLASS` — dynamic class instantiation from a user-controlled string (`new $$var()`)
    - `CISA-PHP-REMOTE-INCLUDE` — `include` / `require` with user input or a remote URL (RFI / LFI)
    - `CISA-PY-SUBPROCESS-SHELL` — `subprocess.*(..., shell=True)` or `os.system(f"...")` (shell injection)
    - `CISA-PY-SSL-NO-VERIFY` — TLS certificate verification disabled (`verify=False`, `ssl.CERT_NONE`, `InsecureRequestWarning`)
    - `CISA-PY-JINJA2-AUTOESCAPE-OFF` — Jinja2 `Environment()` created without `autoescape=True` (XSS)
    - `CISA-PY-XML-UNSAFE` — Python stdlib XML parsers (`ElementTree`, `minidom`, `xml.sax`) vulnerable to XXE and Billion Laughs DoS
- **Clickable rule-ID filter in the report panel** — rule ID badges (e.g. `PHP-SQL-INJECTION`) in the Security Report panel are now interactive buttons. Clicking one populates the search box and filters the panel to show only findings for that rule. Clicking the same rule ID again clears the filter.
- **PDF export — minimal HTML generation** (`buildPdfHtml`) — instead of serving the full 200k+ line interactive webview as a PDF source, `convertReportToPdf` now reads the companion `.json` report and generates a compact, JavaScript-free HTML document. This eliminates Chrome CDP timeout failures caused by rendering very large HTML documents.
- **PDF export — in-memory HTTP server** (`serveContentLocally`) — the PDF pipeline now spins up a temporary `http.createServer` on `127.0.0.1:<random-port>` to serve the generated HTML buffer. This resolves Chrome's `file://` sandbox restrictions under `--headless=new` without writing any temporary files.
- **PDF export — WebSocket fragment reassembly** — the internal `WsClient` now correctly accumulates fragmented WebSocket frames (FIN=0) before dispatching, preventing premature message-dispatch when Chrome splits large CDP responses across multiple frames.

---

## [0.5.0] — 2026-04-13

### Added

- **nginx config file scanning** — all 12 HTTP security header rules now fire on nginx configuration files (`nginx` language). The Supported Languages list and editor title-bar command visibility both include nginx.
- **`poetry.lock` and `Pipfile.lock` dependency scanning** — the workspace dependency scanner now recognises Python Poetry and Pipenv lock files in addition to `package.json`, `requirements.txt`, and `composer.json`.
- **Test suite** — 84 automated tests covering positive and negative matches across all 110 rules; run with `npm test`.

### Fixed

- **`A04-MISSING-CSRF` PHP regex** — the previous regex used a malformed negative lookahead that matched a literal `=` character; corrected to `/^(?!.*(?:csrf|token)).*\$_(?:POST|REQUEST)\s*\[/i` so only POST/REQUEST handlers without a CSRF token are flagged.
- **`A03-XSS-INNERHTML` false negatives** — lookahead backtracking allowed the rule to miss unsafe `innerHTML` assignments to dynamic expressions; the lookahead now correctly includes the optional whitespace between `=` and a quote character.
- **`A02-WEAK-HASH-MD5` Python false negatives** — the combined JS + Python pattern could not match Python's `hashlib.md5()`; split into two dedicated patterns covering `createHash('md5')` and `hashlib.md5()` independently.
- **`PHP-ECHO-XSS` false positives** — the overly broad echo pattern no longer fires on output wrapped in `htmlspecialchars()` or a similar sanitiser; only unsanitised concatenated `echo` expressions are flagged.
- **`JS-NO-RATE-LIMIT` and `JS-POSTMESSAGE-NO-ORIGIN` severity** — downgraded from Warning to Info; both are advisory rules that require additional context to confirm a real vulnerability.
- **Editor title-bar command visibility** — the `when` clause for the editor title contribution point was missing several language IDs (`nginx`, `xml`); the toolbar icon now appears in all supported file types.
- **`fullScanExclude` default** — corrected to include `**/node_modules/**` and `**/.venv/**`, which were unintentionally absent from the previous default.
- **`ALL_RULES` rebuilt multiple times** — `diagnosticProvider`, `codeActionProvider`, and `updateChecker` each independently reconstructed the full rule array; all three now reference the single `ALL_RULES` export from `rules/index.ts`.
- **Duplicated report utilities** — `escapeHtml`, `truncateMatch`, and `getRelativePath` were defined independently in both `reportPanel.ts` and `reportWriter.ts`; extracted to a shared `reportUtils.ts` module.

---

## [0.4.0] — 2026-04-11

### Added

- **Mitigated findings tab** — the report panel now has a dedicated **✅ Mitigated** tab alongside "By Severity" and "By File". The tab only appears when there are mitigated findings and participates fully in the existing tab-switching system; mitigated findings are no longer always visible regardless of the active tab.
- **Cancellation indicator in report** — if a workspace scan is cancelled mid-run, the report panel shows a red ⚠️ banner ("Scan was cancelled — results below are partial") and the toast notification message reflects the partial state.
- **`apacheconf` and `xml` quick-fix support** — lightbulb Quick Fix actions (suppress, open docs) now appear in Apache `.conf` / `.htaccess` and IIS `web.config` files.

### Fixed

- **`showReport` command consistency** — "Show Security Report" now always re-displays the findings from the last workspace scan rather than an ad-hoc mix of per-file scan results. Falls back to per-file cache if no workspace scan has been run yet.
- **Per-document debounce** — editing two files simultaneously no longer cancels the pending re-scan for the other file. Each document now has its own independent 800 ms debounce timer.
- **Update notification spam** — "A newer rule pack is available" notification is now suppressed on startup if the user has already been notified about that exact remote version. The notification fires again only when a new version beyond the last-seen one is published.
- **`fixReplacer` in config files** — auto-fix code suggestions are no longer inserted into Apache `.conf` / `.htaccess` or IIS `web.config` files; only "suppress" and "open docs" quick fixes are offered for those file types.
- **`ignoredRules` performance** — the ignored-rules list is now converted to a `Set` before each scan loop, reducing per-rule lookup from O(n) to O(1).
- **`totalRules` always zero** — `RULES_METADATA.totalRules` is now populated at extension startup with the actual count of loaded rules. Previously the `as const` assertion prevented the runtime assignment from taking effect.
- **Glob exclude patterns for file extensions** — `fastScanExclude` / `fullScanExclude` patterns in the form `**/*.min.js` now correctly match files by suffix. Previously only `**/dir/**` directory patterns were handled, so extension-based excludes were silently ignored.
- **CSP "missing directive" false negatives** — all four CSP rules that detect missing directives (`CSP-MISSING-DEFAULT-SRC`, `CSP-MISSING-OBJECT-SRC`, `CSP-MISSING-FRAME-ANCESTORS`, `CSP-REPORT-MISSING`) were using a broken negative-lookahead pattern that could never match. Patterns were corrected to anchor the lookahead immediately after `Content-Security-Policy`.
- **Insecure cookie false positives** — `A07-INSECURE-COOKIE` (`res.cookie`) no longer fires when the cookie already has `secure: true` in its options object.
- **PHP `assert()` over-matching** — `PHP-ASSERT-INJECTION` no longer flags `assert()` calls with a bare variable; it now only flags calls with a string literal or string concatenation argument (the actual injection vectors).
- **`A02-WEAK-HASH-MD5` catch-all** — removed the overly broad `/md5\s*\(/i` pattern that triggered on any function named `md5`. The rule now requires the canonical `md5()` call form.
- **PHP `htmlspecialchars` false positives** — `PHP-HTMLSPECIALCHARS-FLAGS` now checks for the `ENT_QUOTES` flag only within the argument list of the call, preventing matches on nearby code.
- **Suppress comment format** — quick-fix "Suppress this rule" comments now use the `owasp-ignore: RULE-ID -- suppressed` format that the diagnostic provider actually reads. The previous `owaspHelper-disable-next-line` format was never recognised.
- **Per-file scan false positives** — the on-type / on-save scanner no longer scans `node_modules/`, `out/`, `dist/`, `.venv/`, or minified files opened in the editor, eliminating thousands of spurious diagnostics from bundled output files.
- **Dependency scanner blocking I/O** — all four manifest parse functions (`package.json`, `package-lock.json`, `requirements.txt`, `composer.json`) now use `fs.promises.readFile` instead of the synchronous `readFileSync`.
- **Missing rule modules in quick-fix** — `httpHeaderRules` and `inputValidationRules` were absent from the `ALL_RULES` array in the code action provider; quick fixes for those rule packs now resolve correctly.
- **Missing activation events** — `owaspHelper.checkForUpdates` and `owaspHelper.showRulesStatus` were missing from `activationEvents`; the commands now activate the extension when invoked from the Command Palette.
- **Saved HTML report CSP** — the HTML file written to `.securityReport/` now includes a `Content-Security-Policy` meta tag.
- **Update checker forced HTTPS** — the rules manifest fetch now rejects `http://` manifest URLs at the call site, preventing accidental plaintext fetches.

---

## [0.3.0] — 2026-04-09

### Added

- **Input Validation & File Upload rules (JS/TS + Python)** — 12 new rules in `inputValidationRules.ts` based on the OWASP [Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) and [File Upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) Cheat Sheets:
    - `IV-JS-UPLOAD-MIME-TRUST` — trusting `req.file.mimetype` (client-controlled) for upload security checks
    - `IV-JS-UPLOAD-ORIGINAL-NAME` — `req.file.originalname` used directly as a storage path (path traversal risk)
    - `IV-JS-PARSE-NO-NAN-CHECK` — `parseInt()` / `Number()` on request params without `isNaN` / `isFinite()` guard
    - `IV-JS-DENYLIST-SANITIZE` — denylist HTML sanitisation via `String.replace()` stripping `<script>` or event handlers
    - `IV-PY-INT-NO-EXCEPTION` — `int(request...)` / `float(request...)` without `try/except` (unhandled `ValueError`)
    - `IV-PY-EVAL-INPUT` — `eval(request.args...)` or equivalent (arbitrary Python code execution)
    - `IV-PY-SSTI-RENDER` — Flask `render_template_string()` with user input or f-string (Jinja2 SSTI)
    - `IV-PY-OPEN-REDIRECT` — Flask `redirect(request.args...)` without URL validation
    - `IV-PY-UPLOAD-ORIGINAL-NAME` — `request.files[key].filename` used directly as a storage path
    - `IV-PY-UPLOAD-MIME-TRUST` — trusting `request.files[key].content_type` / `.mimetype` for type validation
    - `IV-PY-UPLOAD-WEB-ROOT` — `file.save()` targeting `static/`, `uploads/`, or `public/` paths inside the web root
    - `IV-PY-ZIP-NO-VALIDATION` — `zipfile.extractall()` without path-traversal validation (Zip Slip)
- **esbuild bundling** — `vscode:prepublish` now runs a `clean` + `esbuild` pipeline, producing a single minified `out/extension.js` (~139 KB) in ~5 ms. Development builds (`npm run compile`, `npm run watch`) are unchanged. `.vscodeignore` updated to a whitelist so only `out/extension.js`, `package.json`, `LICENSE`, and `README.md` are included in the `.vsix`.

### Fixed

- **PHP SQL injection false positives on plain English strings** — tightened the three `PHP-SQL-INJECTION` patterns to require the SQL keyword to appear at or near the opening quote of a string literal. Phrases such as `"To update your password, log in..."` no longer trigger the rule.

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
