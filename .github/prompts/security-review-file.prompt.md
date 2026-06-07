---
mode: ask
description: Review a file for OWASP security issues and summarize all risks
---

Please perform a security review of the currently open file with a focus on the OWASP Top 10 (2021) categories, CSP, HTTP headers, and general secure-coding best practices enforced by the OWASP Security Helper extension.

For each issue found:

- **Rule ID** (e.g. `A03-SQL-INJECTION`)
- **Line(s)** where the issue occurs
- **Risk summary** — what an attacker could do
- **Recommended fix** — corrected code

At the end, provide an overall risk rating (Critical / High / Medium / Low) for the file and a prioritized list of fixes.

Only flag genuine risks — do not surface false positives for comments, test fixtures with an `owasp-ignore` suppression comment, or code that is clearly not reachable from user input.
