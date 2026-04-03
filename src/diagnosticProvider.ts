import * as vscode from "vscode";
import {
	owaspRules,
	cspRules,
	generalRules,
	phpRules,
	jsRules,
	phpInputValidationRules,
} from "./rules";
import { SecurityFinding, SecurityRule, Severity } from "./types";

const ALL_RULES: SecurityRule[] = [
	...owaspRules,
	...cspRules,
	...generalRules,
	...phpRules,
	...jsRules,
	...phpInputValidationRules,
];

const SUPPORTED_LANGUAGES = new Set([
	"javascript",
	"javascriptreact",
	"typescript",
	"typescriptreact",
	"python",
	"php",
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
			const lineText = document.lineAt(lineIdx).text;

			for (const pattern of rule.patterns) {
				// Reset lastIndex for global regexes
				pattern.lastIndex = 0;
				const match = pattern.exec(lineText);
				if (match) {
					const startChar = match.index ?? lineText.indexOf(match[0]);
					const endChar = startChar + match[0].length;
					findings.push({
						rule,
						line: lineIdx,
						startChar,
						endChar,
						matchedText: match[0],
						filePath,
					});
					break; // one finding per rule per line is enough
				}
			}
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
	const diagnostics: vscode.Diagnostic[] = findings.map((f) => {
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
