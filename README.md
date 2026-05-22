# OWASP Security Helper

![Version](https://badgen.net/vs-marketplace/v/ThomasDromgoole.owasp-security-helper)
![Installs](https://badgen.net/vs-marketplace/i/ThomasDromgoole.owasp-security-helper)
![Downloads](https://badgen.net/vs-marketplace/d/ThomasDromgoole.owasp-security-helper)
![Rating](https://badgen.net/vs-marketplace/rating/ThomasDromgoole.owasp-security-helper)
![License](https://img.shields.io/github/license/tdromgoole/owasp-security-helper)

A VS Code extension that spots insecure code as you type — covering **OWASP Top 10**, **Content Security Policy**, **HTTP security headers**, **PHP**, **JavaScript / TypeScript**, **Python**, and **CISA Secure-by-Design** patterns. Findings appear inline with squiggles, Quick Fix actions, and a full Security Report panel.

**133 rules across 9 categories.**

![Report Example](https://raw.githubusercontent.com/tdromgoole/owasp-security-helper/refs/heads/main/images/reportExample.png)

---

## What it does

- **Inline diagnostics** — red/yellow/blue squiggles appear as you type or on save, directly in the editor.
- **Quick Fixes** — one-click actions to suppress a finding with a justification comment, or jump straight to the relevant OWASP documentation.
- **Security Report panel** — a full summary of all findings, filterable by severity, grouped by file or severity, with click-to-navigate to each issue.
- **Workspace scan** — scan every file in the project at once and get a consolidated report.
- **Export to Markdown** — save the report as a portable `.md` file you can commit alongside your code or share with your team.
- **Export to PDF** — save the report as a PDF via Chrome/Edge (requires a Chromium browser).
- **Dependency vulnerability check** — flags known-vulnerable npm, Composer, pip, and Poetry packages against live vulnerability feeds.
- **End-of-life & deprecated dependency detection** — identifies packages that have reached end-of-life or been officially deprecated. These are a hidden security risk: they stop receiving CVE patches even when new vulnerabilities are discovered, a gap that standard vulnerability scanners miss.
- **Local CVE database** — download and maintain an offline copy of the full CVE catalogue directly inside VS Code. The dependency scanner automatically cross-references it alongside live feeds, so you get broader coverage without relying solely on internet lookups.
- **CVE database status** — the Security Report panel shows whether your local CVE database is downloaded and how recently it was updated. A banner alerts you when the database is missing or more than a week out of date, with a one-click link to the CVE manager.
- **Justification / suppression** — mark a finding as intentionally accepted with a note; it stays visible but clearly marked as mitigated.
- **Rule update checker** — notifies you when a newer ruleset is available.

---

## Supported languages

JavaScript, TypeScript, JSX/TSX, PHP, Python, Apache config / `.htaccess`, IIS `web.config`, and nginx.

---

## Commands

Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`) and search for **OWASP Helper**:

| Command                         | What it does                                                              |
| ------------------------------- | ------------------------------------------------------------------------- |
| **Show Security Report**        | Open the report panel for all currently open files                        |
| **Scan Workspace**              | Scan every supported file in the project                                  |
| **Full Scan Workspace**         | Same as above, including large files and running a dependency check       |
| **Check Dependencies**          | Check installed packages against known vulnerability lists and EOL status |
| **Open CVE Database**           | Open the CVE database manager panel                                       |
| **Download CVE Baseline**       | Download the full CVE catalogue for offline use                           |
| **Update CVE Database (Delta)** | Apply the latest incremental updates to the local CVE database            |
| **Check for Rule Updates**      | See whether a newer ruleset is available                                  |
| **Show Rules Status**           | Quick summary of the current rule version and coverage                    |

---

## Configuration

| Setting                           | Default                                   | Description                                                    |
| --------------------------------- | ----------------------------------------- | -------------------------------------------------------------- |
| `owaspHelper.enableOnSave`        | `true`                                    | Re-scan the file on every save                                 |
| `owaspHelper.severity`            | `"all"`                                   | Minimum severity to show: `all`, `critical`, `warning`, `info` |
| `owaspHelper.ignoredRules`        | `[]`                                      | Rule IDs to silence workspace-wide                             |
| `owaspHelper.fastScanExclude`     | node_modules, out, dist, .venv, \*.min.js | Paths skipped during the fast workspace scan                   |
| `owaspHelper.fullScanExclude`     | node_modules, out, dist, .venv            | Paths skipped during the full workspace scan                   |
| `owaspHelper.autoCheckForUpdates` | `true`                                    | Check for new rules once per day on startup                    |
| `owaspHelper.cveStalenessDays`    | `7`                                       | Days before the CVE database is considered out of date         |

---

## Rule coverage

| Category                       | Rules | Languages                 |
| ------------------------------ | ----- | ------------------------- |
| OWASP Top 10 (2021) A01–A10    | 27    | JS/TS, PHP, Python        |
| Content Security Policy        | 8     | JS/TS, Apache, IIS, nginx |
| General secure coding          | 8     | All languages             |
| PHP security                   | 19    | PHP                       |
| PHP input validation           | 18    | PHP                       |
| JavaScript / TypeScript        | 12    | JS/TS                     |
| HTTP security headers          | 12    | Apache, IIS, nginx        |
| Input validation & file upload | 15    | JS/TS, Python             |
| CISA Secure-by-Design          | 14    | JS/TS, PHP, Python        |

Covers injection, broken access control, cryptographic failures, insecure deserialization, misconfigured security headers, dangerous language APIs, and more.

---

## Suppressing a finding

Add a suppression comment on the line above the flagged code (or use the Quick Fix action):

```js
// owasp-ignore: A03-XSS-INNERHTML -- output is sanitised by upstream middleware
element.innerHTML = safeContent;
```

To silence a rule across the whole workspace, add it to `owaspHelper.ignoredRules` in your VS Code settings.

---

## References

- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [CISA Secure-by-Design](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Content Security Policy — MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

## License

MIT

---

[View full changelog](CHANGELOG.md)
