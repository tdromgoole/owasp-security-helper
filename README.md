# OWASP Security Helper

A VS Code extension that detects insecure coding practices in real time using **OWASP Top 10 (2021)**, **Content Security Policy** analysis, and additional **secure-coding best practices**.

## Features

| Feature                          | Detail                                                                     |
| -------------------------------- | -------------------------------------------------------------------------- |
| **Real-time inline diagnostics** | Red/yellow/blue squiggles appear as you type                               |
| **OWASP Top 10 rules**           | A01–A10 coverage for JS/TS, Python, PHP                                    |
| **CSP analysis**                 | Detects `unsafe-inline`, wildcards, missing directives                     |
| **General rules**                | Hardcoded secrets, insecure TLS, prototype pollution, XXE, ReDoS, and more |
| **Severity levels**              | Critical 🔴 / Warning 🟡 / Info 🔵                                         |
| **Quick Fixes**                  | Auto-fix or suppress rules with one click                                  |
| **Security Report panel**        | Full summary webview with grouped findings                                 |
| **Workspace scan**               | Scan all JS/TS/Python/PHP files at once                                    |

## Getting Started

### Install dependencies and build

```bash
npm install
npm run compile
```

### Run in Extension Development Host

Press **F5** in VS Code.

### Package for distribution

```bash
npm run package
```

## Commands

| Command                              | Description                                      |
| ------------------------------------ | ------------------------------------------------ |
| `OWASP Helper: Show Security Report` | Open the report panel for all open-file findings |
| `OWASP Helper: Scan Workspace`       | Scan every supported file in the workspace       |

## Configuration

| Setting                    | Default | Description                                            |
| -------------------------- | ------- | ------------------------------------------------------ |
| `owaspHelper.enableOnSave` | `true`  | Re-scan on every file save                             |
| `owaspHelper.severity`     | `"all"` | Minimum severity: `all`, `critical`, `warning`, `info` |
| `owaspHelper.ignoredRules` | `[]`    | Rule IDs to suppress, e.g. `["A03-XSS-INNERHTML"]`     |

## Rule Reference

### OWASP Top 10

| ID                        | Category                  | Severity |
| ------------------------- | ------------------------- | -------- |
| `A01-DIRECTORY-TRAVERSAL` | Broken Access Control     | Critical |
| `A02-WEAK-HASH-MD5`       | Cryptographic Failures    | Critical |
| `A02-WEAK-HASH-SHA1`      | Cryptographic Failures    | Warning  |
| `A02-HARDCODED-SECRET`    | Cryptographic Failures    | Critical |
| `A02-INSECURE-RANDOM`     | Cryptographic Failures    | Warning  |
| `A03-SQL-INJECTION`       | Injection                 | Critical |
| `A03-COMMAND-INJECTION`   | Injection                 | Critical |
| `A03-XSS-INNERHTML`       | Injection (XSS)           | Critical |
| `A03-EVAL-INJECTION`      | Injection                 | Critical |
| `A03-TEMPLATE-INJECTION`  | Injection                 | Critical |
| `A05-DEBUG-ENABLED`       | Security Misconfiguration | Warning  |
| `A05-CORS-WILDCARD`       | Security Misconfiguration | Warning  |
| `A07-INSECURE-COOKIE`     | Auth Failures             | Warning  |
| `A07-JWT-NONE-ALG`        | Auth Failures             | Critical |
| `A08-DESERIALIZE-PICKLE`  | Data Integrity Failures   | Critical |
| `A08-DESERIALIZE-PHP`     | Data Integrity Failures   | Critical |
| `A09-SENSITIVE-LOG`       | Logging Failures          | Warning  |
| `A10-SSRF`                | SSRF                      | Critical |

### Content Security Policy

| ID                            | Severity |
| ----------------------------- | -------- |
| `CSP-UNSAFE-INLINE`           | Critical |
| `CSP-UNSAFE-EVAL`             | Critical |
| `CSP-WILDCARD-SRC`            | Critical |
| `CSP-MISSING-DEFAULT-SRC`     | Warning  |
| `CSP-MISSING-OBJECT-SRC`      | Warning  |
| `CSP-HTTP-SOURCE`             | Warning  |
| `CSP-MISSING-FRAME-ANCESTORS` | Warning  |
| `CSP-REPORT-MISSING`          | Info     |

### General Secure Coding

| ID                        | Severity |
| ------------------------- | -------- |
| `GEN-HTTP-URL`            | Warning  |
| `GEN-TLS-REJECT-DISABLED` | Critical |
| `GEN-PROTOTYPE-POLLUTION` | Warning  |
| `GEN-XXE`                 | Critical |
| `GEN-REDOS`               | Warning  |
| `GEN-SENSITIVE-COMMENT`   | Warning  |
| `GEN-WORLD-WRITABLE`      | Warning  |

## Suppressing Rules

Add a comment on the line above the flagged code:

```js
// owaspHelper-disable-next-line A03-XSS-INNERHTML
element.innerHTML = safeHtml;
```

Or use the Quick Fix lightbulb → **Suppress** action.

## License

MIT
