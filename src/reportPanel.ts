import * as vscode from "vscode";
import { randomFillSync } from "crypto";
import { SecurityFinding, Severity } from "./types";

const SEVERITY_ICON: Record<Severity, string> = {
	critical: "🔴",
	warning: "🟡",
	info: "🔵",
};

/** Produces the full HTML content for the Security Report webview. */
function buildHtml(
	webview: vscode.Webview,
	findings: SecurityFinding[],
	nonce: string,
): string {
	const critical = findings.filter((f) => f.rule.severity === "critical");
	const warning = findings.filter((f) => f.rule.severity === "warning");
	const info = findings.filter((f) => f.rule.severity === "info");

	function buildSection(title: string, items: SecurityFinding[]): string {
		if (items.length === 0) {
			return "";
		}
		const rows = items
			.map((f) => {
				const shortPath = f.filePath
					.replace(/\\/g, "/")
					.split("/")
					.slice(-2)
					.join("/");
				const ref = f.rule.reference
					? `<a href="${f.rule.reference}" target="_blank">Learn more</a>`
					: "";
				const fix = f.rule.fixDescription
					? `<div class="fix"><strong>Fix:</strong> ${escapeHtml(f.rule.fixDescription)}</div>`
					: "";
				return `
        <div class="finding ${f.rule.severity}">
          <div class="finding-header">
            <span class="badge ${f.rule.severity}">${SEVERITY_ICON[f.rule.severity]} ${f.rule.severity.toUpperCase()}</span>
            <span class="rule-id">${escapeHtml(f.rule.id)}</span>
            <span class="location">${escapeHtml(shortPath)} — line ${f.line + 1}</span>
            ${ref}
          </div>
          <div class="title">${escapeHtml(f.rule.title)}</div>
          <div class="desc">${escapeHtml(f.rule.description)}</div>
          <code class="matched">${escapeHtml(f.matchedText)}</code>
          ${fix}
          <div class="category">${escapeHtml(f.rule.category)}</div>
        </div>`;
			})
			.join("");
		return `<h2>${title} <span class="count">(${items.length})</span></h2>${rows}`;
	}

	const noFindings =
		findings.length === 0
			? `<div class="no-findings">✅ No security issues detected.</div>`
			: "";

	return /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OWASP Security Report</title>
  <style nonce="${nonce}">
    body { font-family: var(--vscode-font-family); font-size: var(--vscode-font-size);
           color: var(--vscode-foreground); background: var(--vscode-editor-background);
           padding: 12px; margin: 0; }
    h1 { font-size: 1.3em; border-bottom: 1px solid var(--vscode-panel-border); padding-bottom: 6px; }
    h2 { font-size: 1em; margin-top: 20px; }
    .count { color: var(--vscode-descriptionForeground); font-weight: normal; }
    .summary-bar { display: flex; gap: 16px; margin-bottom: 12px; }
    .summary-chip { padding: 4px 10px; border-radius: 12px; font-size: 0.85em; font-weight: 600; }
    .chip-critical { background: #c0392b33; color: #e74c3c; }
    .chip-warning  { background: #e67e2233; color: #e67e22; }
    .chip-info     { background: #2980b933; color: #3498db; }
    .finding { border: 1px solid var(--vscode-panel-border); border-radius: 6px;
               padding: 10px 12px; margin-bottom: 10px; }
    .finding.critical { border-left: 4px solid #e74c3c; }
    .finding.warning  { border-left: 4px solid #e67e22; }
    .finding.info     { border-left: 4px solid #3498db; }
    .finding-header { display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
                      margin-bottom: 6px; font-size: 0.85em; }
    .badge { padding: 2px 7px; border-radius: 4px; font-size: 0.8em; }
    .badge.critical { background: #c0392b33; color: #e74c3c; }
    .badge.warning  { background: #e67e2233; color: #e67e22; }
    .badge.info     { background: #2980b933; color: #3498db; }
    .rule-id { font-family: monospace; font-weight: 600; }
    .location { color: var(--vscode-descriptionForeground); }
    .title { font-weight: 600; margin-bottom: 4px; }
    .desc { font-size: 0.9em; color: var(--vscode-descriptionForeground); margin-bottom: 6px; }
    .matched { display: block; background: var(--vscode-textCodeBlock-background);
               padding: 4px 8px; border-radius: 4px; font-size: 0.85em;
               white-space: pre-wrap; word-break: break-all; margin-bottom: 6px; }
    .fix { font-size: 0.88em; background: #27ae6022; border-left: 3px solid #27ae60;
           padding: 4px 8px; border-radius: 3px; margin-bottom: 4px; }
    .category { font-size: 0.78em; color: var(--vscode-descriptionForeground); }
    a { color: var(--vscode-textLink-foreground); }
    .no-findings { padding: 20px; text-align: center; color: #27ae60; font-size: 1.1em; }
  </style>
</head>
<body>
  <h1>OWASP Security Report</h1>
  <div class="summary-bar">
    <span class="summary-chip chip-critical">🔴 Critical: ${critical.length}</span>
    <span class="summary-chip chip-warning">🟡 Warning: ${warning.length}</span>
    <span class="summary-chip chip-info">🔵 Info: ${info.length}</span>
  </div>
  ${noFindings}
  ${buildSection("🔴 Critical Issues", critical)}
  ${buildSection("🟡 Warnings", warning)}
  ${buildSection("🔵 Informational", info)}
</body>
</html>`;
}

function escapeHtml(text: string): string {
	return text
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#039;");
}

function generateNonce(): string {
	const chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	const array = new Uint8Array(32);
	randomFillSync(array);
	return Array.from(array)
		.map((b) => chars[b % chars.length])
		.join("");
}

export class SecurityReportPanel {
	private static current: SecurityReportPanel | undefined;
	private readonly panel: vscode.WebviewPanel;
	private findings: SecurityFinding[] = [];
	private disposables: vscode.Disposable[] = [];

	private constructor(extensionUri: vscode.Uri) {
		this.panel = vscode.window.createWebviewPanel(
			"owaspSecurityReport",
			"OWASP Security Report",
			vscode.ViewColumn.Two,
			{
				enableScripts: true,
				localResourceRoots: [extensionUri],
				retainContextWhenHidden: true,
			},
		);

		this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
		this.render();
	}

	public static show(
		extensionUri: vscode.Uri,
		findings: SecurityFinding[],
	): void {
		const col =
			vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One;
		if (SecurityReportPanel.current) {
			SecurityReportPanel.current.update(findings);
			SecurityReportPanel.current.panel.reveal(col + 1);
		} else {
			SecurityReportPanel.current = new SecurityReportPanel(extensionUri);
			SecurityReportPanel.current.update(findings);
		}
	}

	public update(findings: SecurityFinding[]): void {
		this.findings = findings;
		this.render();
	}

	private render(): void {
		const nonce = generateNonce();
		this.panel.webview.html = buildHtml(
			this.panel.webview,
			this.findings,
			nonce,
		);
	}

	private dispose(): void {
		SecurityReportPanel.current = undefined;
		this.panel.dispose();
		for (const d of this.disposables) {
			d.dispose();
		}
		this.disposables = [];
	}
}
