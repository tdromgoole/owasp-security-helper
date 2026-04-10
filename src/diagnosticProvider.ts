import * as vscode from "vscode";
import {
	owaspRules,
	cspRules,
	generalRules,
	phpRules,
	jsRules,
	phpInputValidationRules,
	httpHeaderRules,
	inputValidationRules,
} from "./rules";
import { SecurityFinding, SecurityRule, Severity } from "./types";

const ALL_RULES: SecurityRule[] = [
	...owaspRules,
	...cspRules,
	...generalRules,
	...phpRules,
	...jsRules,
	...phpInputValidationRules,
	...httpHeaderRules,
	...inputValidationRules,
];

const SUPPORTED_LANGUAGES = new Set([
	"javascript",
	"javascriptreact",
	"typescript",
	"typescriptreact",
	"python",
	"php",
	"apacheconf",
	"xml",
]);

/** Map our severity to VS Code DiagnosticSeverity */
function toDiagSeverity(s: Severity): vscode.DiagnosticSeverity {
	switch (s) {
		case "critical":
			return vscode.DiagnosticSeverity.Error;
		case "warning":
			return vscode.DiagnosticSeverity.Warning;
		case "info":
			return vscode.DiagnosticSeverity.Information;
	}
}

/** Severity order for threshold filtering */
const SEVERITY_ORDER: Record<Severity, number> = {
	critical: 0,
	warning: 1,
	info: 2,
};

function meetsThreshold(ruleSeverity: Severity, threshold: string): boolean {
	if (threshold === "all") {
		return true;
	}
	return (
		SEVERITY_ORDER[ruleSeverity] <= SEVERITY_ORDER[threshold as Severity]
	);
}

/**
 * Returns the justification text if the line preceding `lineIdx` contains
 * an `owasp-ignore: RULE-ID -- reason` comment suppressing `ruleId`.
 * Supports both `//` (JS/TS/PHP) and `#` (Python) comment styles.
 */
function getIgnoreJustification(
	document: vscode.TextDocument,
	lineIdx: number,
	ruleId: string,
): string | undefined {
	// For line-0 findings (document-level missing-header rules), check whether
	// line 0 itself is an owasp-ignore comment so the finding can be suppressed
	// by placing the comment at the very top of the file.
	const checkIdx = lineIdx === 0 ? 0 : lineIdx - 1;
	const prevLine = document.lineAt(checkIdx).text.trim();
	const m = prevLine.match(
		/^(?:\/\/|#)\s*owasp-ignore:\s*([A-Z0-9_-]+)\s*(?:--\s*(.*))?$/i,
	);
	if (m && m[1].toUpperCase() === ruleId.toUpperCase()) {
		return m[2]?.trim() || "(no justification provided)";
	}
	return undefined;
}

/**
 * Scans a single TextDocument and returns all SecurityFindings.
 */
export function scanDocument(document: vscode.TextDocument): SecurityFinding[] {
	const langId = document.languageId;
	if (!SUPPORTED_LANGUAGES.has(langId)) {
		return [];
	}

	const config = vscode.workspace.getConfiguration("owaspHelper");
	const severityThreshold: string = config.get("severity", "all");
	const ignoredRules: string[] = config.get("ignoredRules", []);

	const findings: SecurityFinding[] = [];
	const lineCount = document.lineCount;
	const filePath = document.uri.fsPath;

	for (const rule of ALL_RULES) {
		if (ignoredRules.includes(rule.id)) {
			continue;
		}
		if (!meetsThreshold(rule.severity, severityThreshold)) {
			continue;
		}
		if (rule.languages.length > 0 && !rule.languages.includes(langId)) {
			continue;
		}

		for (let lineIdx = 0; lineIdx < lineCount; lineIdx++) {
			const rawLine = document.lineAt(lineIdx).text;

			// Truncate lines that are too long to come from hand-written code.
			// Regex patterns with .* have O(n²) backtracking on long lines and
			// will freeze the extension host (e.g. inlined data URIs, minified blobs).
			// Truncating (rather than skipping) preserves partial coverage of
			// minified files included by the Full Scan.
			const lineText =
				rawLine.length > 2000 ? rawLine.slice(0, 2000) : rawLine;

			for (const pattern of rule.patterns) {
				// Reset lastIndex for global regexes
				pattern.lastIndex = 0;
				const match = pattern.exec(lineText);
				if (match) {
					const startChar = match.index ?? lineText.indexOf(match[0]);
					const endChar = startChar + match[0].length;
					const justification = getIgnoreJustification(
						document,
						lineIdx,
						rule.id,
					);
					findings.push({
						rule,
						line: lineIdx,
						startChar,
						endChar,
						matchedText: match[0],
						filePath,
						justification,
					});
					break; // one finding per rule per line is enough
				}
			}
		}
	}

	// ── Document-level checks (e.g. missing required security headers) ─────────
	// These fire when a required pattern is absent from the full document text.
	// Findings are placed at line 0 and can be suppressed with an owasp-ignore
	// comment on the first line of the file.
	const fullText = document.getText();
	const fileBaseName = filePath.split(/[/\\]/).pop() ?? "";
	for (const rule of ALL_RULES) {
		if (!rule.documentMustMatch) {
			continue;
		}
		if (ignoredRules.includes(rule.id)) {
			continue;
		}
		if (!meetsThreshold(rule.severity, severityThreshold)) {
			continue;
		}
		if (rule.languages.length > 0 && !rule.languages.includes(langId)) {
			continue;
		}
		if (rule.fileNamePattern && !rule.fileNamePattern.test(fileBaseName)) {
			continue;
		}
		rule.documentMustMatch.lastIndex = 0;
		if (!rule.documentMustMatch.test(fullText)) {
			const justification = getIgnoreJustification(document, 0, rule.id);
			findings.push({
				rule,
				line: 0,
				startChar: 0,
				endChar: 0,
				matchedText: "(header not found in this file)",
				filePath,
				justification,
			});
		}
	}

	return findings;
}

/**
 * Converts SecurityFindings into VS Code Diagnostics and publishes them.
 */
export function publishDiagnostics(
	document: vscode.TextDocument,
	findings: SecurityFinding[],
	collection: vscode.DiagnosticCollection,
): void {
	// Do not raise diagnostics for findings suppressed with owasp-ignore comments
	const activeFindings = findings.filter((f) => !f.justification);
	const diagnostics: vscode.Diagnostic[] = activeFindings.map((f) => {
		const range = new vscode.Range(f.line, f.startChar, f.line, f.endChar);
		const message = `[${f.rule.id}] ${f.rule.title}: ${f.rule.description}`;
		const diag = new vscode.Diagnostic(
			range,
			message,
			toDiagSeverity(f.rule.severity),
		);
		diag.source = "OWASP Security Helper";
		diag.code = {
			value: f.rule.id,
			target: f.rule.reference
				? vscode.Uri.parse(f.rule.reference)
				: vscode.Uri.parse("https://owasp.org/Top10/"),
		};
		return diag;
	});

	collection.set(document.uri, diagnostics);
}
