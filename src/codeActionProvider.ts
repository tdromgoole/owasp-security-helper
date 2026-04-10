import * as vscode from "vscode";
import {
	owaspRules,
	cspRules,
	generalRules,
	phpRules,
	jsRules,
	phpInputValidationRules,
} from "./rules";
import { SecurityRule } from "./types";

const ALL_RULES: SecurityRule[] = [
	...owaspRules,
	...cspRules,
	...generalRules,
	...phpRules,
	...jsRules,
	...phpInputValidationRules,
];
const RULE_MAP = new Map<string, SecurityRule>(ALL_RULES.map((r) => [r.id, r]));

export class SecurityCodeActionProvider implements vscode.CodeActionProvider {
	public static readonly providedCodeActionKinds = [
		vscode.CodeActionKind.QuickFix,
	];

	provideCodeActions(
		document: vscode.TextDocument,
		range: vscode.Range,
		context: vscode.CodeActionContext,
	): vscode.CodeAction[] {
		const actions: vscode.CodeAction[] = [];

		for (const diag of context.diagnostics) {
			if (diag.source !== "OWASP Security Helper") {
				continue;
			}

			const ruleId =
				typeof diag.code === "object" && diag.code !== null
					? String(diag.code.value)
					: String(diag.code);

			const rule = RULE_MAP.get(ruleId);
			if (!rule) {
				continue;
			}

			// ── Quick Fix: apply fixReplacer if available ────────────────────────
			if (rule.fixReplacer) {
				const line = document.lineAt(diag.range.start.line);
				const lineText = line.text;
				const pattern = rule.patterns[0];
				pattern.lastIndex = 0;
				const match = pattern.exec(lineText);
				if (match) {
					const fixed = rule.fixReplacer(lineText, match);
					if (fixed !== lineText) {
						const fix = new vscode.CodeAction(
							`Fix: ${rule.fixDescription ?? rule.title}`,
							vscode.CodeActionKind.QuickFix,
						);
						fix.edit = new vscode.WorkspaceEdit();
						fix.edit.replace(document.uri, line.range, fixed);
						fix.diagnostics = [diag];
						fix.isPreferred = true;
						actions.push(fix);
					}
				}
			}

			// ── Quick Fix: show fix guidance if fixDescription is available ─────────
			if (rule.fixDescription) {
				const guidanceLabel =
					rule.fixDescription.length > 60
						? `💡 How to fix: ${rule.fixDescription.slice(0, 57)}…`
						: `💡 How to fix: ${rule.fixDescription}`;
				const guidance = new vscode.CodeAction(
					guidanceLabel,
					vscode.CodeActionKind.QuickFix,
				);
				guidance.command = {
					command: "owaspHelper.showFixGuidance",
					title: "Show Fix Guidance",
					arguments: [rule.fixDescription, rule.reference],
				};
				guidance.diagnostics = [diag];
				actions.push(guidance);
			}

			// ── Quick Fix: suppress this rule for the line (comment) ─────────────
			const suppress = new vscode.CodeAction(
				`Suppress: Add owaspHelper-disable-next-line ${ruleId}`,
				vscode.CodeActionKind.QuickFix,
			);
			suppress.edit = new vscode.WorkspaceEdit();
			const lineStart = new vscode.Position(diag.range.start.line, 0);
			const suppressComment = buildSuppressComment(
				document.languageId,
				ruleId,
			);
			suppress.edit.insert(
				document.uri,
				lineStart,
				suppressComment + "\n",
			);
			suppress.diagnostics = [diag];
			actions.push(suppress);

			// ── Quick Fix: open reference docs ───────────────────────────────────
			if (rule.reference) {
				const openDocs = new vscode.CodeAction(
					`Open OWASP reference: ${ruleId}`,
					vscode.CodeActionKind.QuickFix,
				);
				openDocs.command = {
					command: "vscode.open",
					title: "Open Reference",
					arguments: [vscode.Uri.parse(rule.reference)],
				};
				openDocs.diagnostics = [diag];
				actions.push(openDocs);
			}
		}

		return actions;
	}
}

function buildSuppressComment(languageId: string, ruleId: string): string {
	switch (languageId) {
		case "python":
			return `# owaspHelper-disable-next-line ${ruleId}`;
		case "php":
			return `// owaspHelper-disable-next-line ${ruleId}`;
		default:
			return `// owaspHelper-disable-next-line ${ruleId}`;
	}
}
