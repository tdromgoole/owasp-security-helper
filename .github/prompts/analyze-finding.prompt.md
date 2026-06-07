---
mode: ask
description: Analyze a specific OWASP Security Helper finding and explain the risk and fix
---

I have an OWASP Security Helper diagnostic in my code. Please analyze this finding and help me fix it.

**Rule:** ${input:ruleId} — ${input:ruleTitle}
**File:** ${input:filePath}
**Line ${input:lineNumber}:** `${input:matchedCode}`

Please:

1. Explain in plain language why this specific code pattern is a security vulnerability
2. Show what an attacker could do to exploit it in context
3. Provide a corrected version of the flagged line (or block) that eliminates the vulnerability
4. Note any edge cases or related patterns to watch for in the same file
