# GitHub Copilot Instructions – OWASP Security Helper

This workspace contains the **OWASP Security Helper** VS Code extension. When
generating or suggesting code, always follow the rules enforced by this
extension. Violations will be flagged as diagnostics in the editor.

---

## Language support

JavaScript, TypeScript, Python, PHP, Apache config, nginx, XML/web.config.

---

## Rules to follow when writing code

### OWASP Top 10

| Rule ID                       | What to avoid                                                                          | Preferred alternative                                         |
| ----------------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| A01-DIRECTORY-TRAVERSAL       | Using raw user input (`req.params`, `$_GET`, etc.) in `readFile`, `fopen`, `path.join` | Validate with `path.basename()`, restrict to allow-listed dir |
| A01-IDOR                      | Accessing resources by user-supplied ID without ownership check                        | Always verify the requesting user owns the resource           |
| A02-WEAK-HASH-MD5             | `createHash('md5')`, `hashlib.md5`                                                     | `createHash('sha256')`, bcrypt, argon2 for passwords          |
| A02-WEAK-HASH-SHA1            | `createHash('sha1')`, `hashlib.sha1`                                                   | SHA-256 or stronger                                           |
| A02-HARDCODED-SECRET          | Secrets, API keys, passwords in source code                                            | Load from environment variables or a secrets manager          |
| A02-WEAK-CIPHER               | DES, 3DES, RC4, Blowfish                                                               | AES-256-GCM                                                   |
| A02-ECB-MODE                  | AES in ECB mode                                                                        | AES-GCM or AES-CBC with a random IV                           |
| A02-RANDOM-INSECURE           | `Math.random()`, `random.random()` for security purposes                               | `crypto.randomBytes()`, `secrets` module                      |
| A03-SQL-INJECTION             | String-concatenated SQL queries                                                        | Parameterised queries / prepared statements                   |
| A03-NOSQL-INJECTION           | Passing raw user input to MongoDB `$where` / `eval`                                    | Sanitise and use typed query builders                         |
| A03-COMMAND-INJECTION         | `exec()`, `shell_exec()`, `os.system()` with user input                                | `execFile()` with explicit args array; avoid shell=True       |
| A03-EVAL-INJECTION            | `eval()`, `Function()`, `exec()` on user-controlled strings                            | Never evaluate dynamic strings                                |
| A03-LDAP-INJECTION            | User input concatenated into LDAP filters                                              | Escape special characters per RFC 4515                        |
| A03-XPATH-INJECTION           | User input in XPath expressions                                                        | Parameterised XPath                                           |
| A03-TEMPLATE-INJECTION        | User input in template render calls                                                    | Sandbox or escape before rendering                            |
| A05-SECURITY-MISCONFIGURATION | `app.use(cors())` without origin, debug mode on in production                          | Explicit CORS origins; disable debug flags                    |
| A05-HELMET-MISSING            | Express app without `helmet()`                                                         | `app.use(require('helmet')())`                                |
| A06-OUTDATED-CRYPTO           | Deprecated TLS/SSL versions                                                            | TLS 1.2+                                                      |
| A07-HARDCODED-CREDENTIALS     | Hardcoded username/password strings                                                    | Env vars or secrets manager                                   |
| A07-JWT-NONE-ALG              | Accepting `alg: none` JWT                                                              | Reject tokens with no algorithm                               |
| A07-JWT-WEAK-SECRET           | Short JWT secrets                                                                      | 256-bit+ random secret                                        |
| A07-BROKEN-AUTH-SESSION       | Long session expiry (> 24 h)                                                           | Short-lived tokens with refresh                               |
| A08-DESERIALISATION           | `pickle.loads`, `unserialize` on untrusted data                                        | Validate data before deserialisation                          |
| A09-INSUFFICIENT-LOGGING      | Catching errors silently (`catch {}`, bare `except`)                                   | Log errors with context                                       |
| A10-SSRF                      | Fetching user-supplied URLs without validation                                         | Validate against allow-list of hostnames                      |

### Content Security Policy (CSP)

- Never use `unsafe-inline` or `unsafe-eval` in CSP headers
- Always set `default-src 'none'` or a strict fallback
- Use nonces/hashes instead of `unsafe-inline`

### HTTP Security Headers

- Set `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Permissions-Policy`
- Never set `X-Powered-By` in production responses

### General secure coding

- Never use `http://` (non-HTTPS) URLs for external services
- Never set `rejectUnauthorized: false` or `verify=False` for TLS
- Validate and sanitise all user input at system boundaries
- Use parameterised queries — never build queries via string concatenation

---

## Suppression comments

If a finding is a known false positive, suppress it with a comment on the line
**before** the flagged code and provide a justification:

```js
// owasp-ignore: A02-HARDCODED-SECRET -- test fixture, not a real secret
const testKey = "example-only";
```

```python
# owasp-ignore: A03-COMMAND-INJECTION -- path is hard-coded, no user input
subprocess.run(["git", "status"])
```

---

## Project structure

- `src/rules/` — all security rule definitions (`SecurityRule[]`)
- `src/diagnosticProvider.ts` — document scanner
- `src/codeActionProvider.ts` — quick fixes and AI code actions
- `src/reportPanel.ts` — webview report UI
- `src/types.ts` — shared `SecurityFinding` / `SecurityRule` types

When adding a new rule, add it to the relevant file in `src/rules/` following
the existing `SecurityRule` shape and export it from `src/rules/index.ts`.
