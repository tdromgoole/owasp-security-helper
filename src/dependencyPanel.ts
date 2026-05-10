import * as vscode from "vscode";
import * as path from "path";
import { randomFillSync } from "crypto";
import {
	DependencyResult,
	DependencyVuln,
	versionBumpType,
} from "./dependencyScanner";

// ── Helpers ───────────────────────────────────────────────────────────────────

function generateNonce(): string {
	const chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	const array = new Uint8Array(32);
	randomFillSync(array);
	return Array.from(array)
		.map((b) => chars[b % chars.length])
		.join("");
}

function escapeHtml(text: string): string {
	return text
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#039;");
}

const SEV_ORDER: Record<DependencyVuln["severity"], number> = {
	critical: 0,
	high: 1,
	medium: 2,
	low: 3,
	unknown: 4,
};

const BUMP_ORDER: Record<string, number> = {
	major: 0,
	minor: 1,
	patch: 2,
	none: 3,
};

function worstSeverity(vulns: DependencyVuln[]): DependencyVuln["severity"] {
	return vulns.reduce(
		(best, v) =>
			SEV_ORDER[v.severity] < SEV_ORDER[best] ? v.severity : best,
		"unknown" as DependencyVuln["severity"],
	);
}

// ── HTML builders ─────────────────────────────────────────────────────────────

function buildVulnerableCard(r: DependencyResult, idx: number): string {
	const worst = worstSeverity(r.vulnerabilities);
	const updateHint =
		r.latestVersion && r.isOutdated
			? `<div class="update-hint">⏫ Update available: <strong>${escapeHtml(r.resolvedVersion)}</strong> → <strong>${escapeHtml(r.latestVersion)}</strong></div>`
			: "";
	const vulnRows = r.vulnerabilities
		.slice() // sort copy
		.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity])
		.map(
			(v) => `
        <div class="vuln-row">
          <span class="sev-badge sev-${v.severity}">${v.severity.toUpperCase()}</span>
          <a class="vuln-id" href="${escapeHtml(v.url)}" target="_blank">${escapeHtml(v.id)}</a>
          <span class="vuln-summary">${escapeHtml(v.summary)}</span>
        </div>`,
		)
		.join("");

	return `
    <div class="dep-card vuln-card border-${worst}" data-idx="${idx}">
      <div class="dep-header">
        <span class="dep-name">${escapeHtml(r.name)}</span>
        <span class="dep-ver">${escapeHtml(r.resolvedVersion)}</span>
        <span class="eco-badge eco-${escapeHtml(r.ecosystem)}">${escapeHtml(r.ecosystem)}</span>
        <span class="vuln-count sev-${worst}">${r.vulnerabilities.length} vuln${r.vulnerabilities.length !== 1 ? "s" : ""}</span>
        <button class="open-btn" data-file="${escapeHtml(r.sourceFile)}">Open ${escapeHtml(path.basename(r.sourceFile))} ↗</button>
      </div>
      <div class="vuln-list">${vulnRows}</div>
      ${updateHint}
    </div>`;
}

function buildOutdatedCard(r: DependencyResult, idx: number): string {
	const latest = r.latestVersion ?? "?";
	const bump = r.latestVersion
		? versionBumpType(r.resolvedVersion, r.latestVersion)
		: "none";
	return `
    <div class="dep-card outdated-card" data-idx="${idx}">
      <div class="dep-header">
        <span class="dep-name">${escapeHtml(r.name)}</span>
        <span class="bump-badge bump-${bump}">${bump.toUpperCase()}</span>
        <span class="eco-badge eco-${escapeHtml(r.ecosystem)}">${escapeHtml(r.ecosystem)}</span>
        <button class="open-btn" data-file="${escapeHtml(r.sourceFile)}">Open ${escapeHtml(path.basename(r.sourceFile))} ↗</button>
      </div>
      <div class="version-row">
        <span class="ver-current">${escapeHtml(r.resolvedVersion)}</span>
        <span class="ver-arrow">→</span>
        <span class="ver-latest">${escapeHtml(latest)}</span>
      </div>
    </div>`;
}

function buildEolCard(r: DependencyResult, idx: number): string {
	return `
    <div class="dep-card eol-card" data-idx="${idx}">
      <div class="dep-header">
        <span class="dep-name">${escapeHtml(r.name)}</span>
        <span class="dep-ver">${escapeHtml(r.resolvedVersion)}</span>
        <span class="eco-badge eco-${escapeHtml(r.ecosystem)}">${escapeHtml(r.ecosystem)}</span>
        <span class="eol-badge">EOL / DEPRECATED</span>
        <button class="open-btn" data-file="${escapeHtml(r.sourceFile)}">Open ${escapeHtml(path.basename(r.sourceFile))} ↗</button>
      </div>
      <div class="eol-reason">${escapeHtml(r.deprecationReason ?? "No longer maintained")}</div>
      <div class="eol-warning">⚠️ CVE feeds do not investigate unsupported version ranges. This package may be affected by vulnerabilities that will never receive an official CVE advisory or scanner alert — upgrade or replace it to restore coverage.</div>
    </div>`;
}

function buildHtml(
	_webview: vscode.Webview,
	results: DependencyResult[],
	nonce: string,
): string {
	const vulnerable = results
		.filter((r) => r.vulnerabilities.length > 0)
		.sort(
			(a, b) =>
				SEV_ORDER[worstSeverity(a.vulnerabilities)] -
				SEV_ORDER[worstSeverity(b.vulnerabilities)],
		);

	const outdated = results
		.filter((r) => r.isOutdated)
		.sort((a, b) => {
			const bumpA = a.latestVersion
				? BUMP_ORDER[
						versionBumpType(a.resolvedVersion, a.latestVersion)
					]
				: 3;
			const bumpB = b.latestVersion
				? BUMP_ORDER[
						versionBumpType(b.resolvedVersion, b.latestVersion)
					]
				: 3;
			return bumpA - bumpB || a.name.localeCompare(b.name);
		});

	const deprecated = results
		.filter((r) => r.isDeprecated)
		.sort((a, b) => a.name.localeCompare(b.name));

	const upToDate = results.filter(
		(r) =>
			r.vulnerabilities.length === 0 && !r.isOutdated && !r.isDeprecated,
	).length;

	const noIssues =
		vulnerable.length === 0 &&
		outdated.length === 0 &&
		deprecated.length === 0
			? `<div class="no-issues">✅ All ${results.length} scanned package${results.length !== 1 ? "s" : ""} are up to date with no known vulnerabilities or EOL concerns.</div>`
			: "";

	// Build a meta array for file-open messages (indexed by dep-card data-idx)
	const depMeta = JSON.stringify(
		results.map((r) => ({ file: r.sourceFile })),
	);

	const vulnTab =
		vulnerable.length === 0
			? `<div class="empty-tab">✅ No packages with known vulnerabilities found.</div>`
			: vulnerable
					.map((r) => buildVulnerableCard(r, results.indexOf(r)))
					.join("");

	const outdatedTab =
		outdated.length === 0
			? `<div class="empty-tab">✅ All packages are on the latest version.</div>`
			: outdated
					.map((r) => buildOutdatedCard(r, results.indexOf(r)))
					.join("");

	const eolTab =
		deprecated.length === 0
			? `<div class="empty-tab">✅ No deprecated or end-of-life packages detected.</div>`
			: `<div class="eol-explainer">
          <strong>The EOL blind spot:</strong> CVE feeds only investigate actively maintained version ranges.
          Packages below are deprecated or past end-of-life — even if no CVE lists them as affected,
          ~80% of vulnerabilities in supported versions also affect EOL versions that were never
          officially investigated. These packages carry hidden risk your vulnerability scanner cannot see.
        </div>` +
				deprecated
					.map((r) => buildEolCard(r, results.indexOf(r)))
					.join("");

	return /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OWASP Dependency Check</title>
  <style nonce="${nonce}">
    body { font-family: var(--vscode-font-family); font-size: var(--vscode-font-size);
           color: var(--vscode-foreground); background: var(--vscode-editor-background);
           padding: 12px; margin: 0; }
    h1 { font-size: 1.3em; border-bottom: 1px solid var(--vscode-panel-border);
         padding-bottom: 6px; margin-bottom: 10px; }
    /* Summary */
    .summary-bar { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 14px; }
    .chip { padding: 4px 10px; border-radius: 12px; font-size: 0.85em; font-weight: 600; }
    .chip-vuln    { background: #c0392b33; color: #e74c3c; }
    .chip-outdated{ background: #e67e2233; color: #e67e22; }
    .chip-ok      { background: #27ae6033; color: #27ae60; }
    .chip-total   { background: var(--vscode-badge-background); color: var(--vscode-badge-foreground); }
    /* Tabs */
    .tabs { display: flex; gap: 2px; margin-bottom: 12px;
            border-bottom: 1px solid var(--vscode-panel-border); }
    .tab-btn { background: none; border: none; cursor: pointer;
               color: var(--vscode-foreground); padding: 6px 14px; font-size: 0.9em;
               border-bottom: 2px solid transparent; margin-bottom: -1px; }
    .tab-btn.active { color: var(--vscode-textLink-foreground);
                      border-bottom-color: var(--vscode-textLink-foreground); font-weight: 600; }
    .tab-btn:hover { background: var(--vscode-list-hoverBackground); }
    /* Cards */
    .dep-card { border: 1px solid var(--vscode-panel-border); border-radius: 6px;
                padding: 10px 12px; margin-bottom: 10px; }
    .border-critical { border-left: 4px solid #e74c3c; }
    .border-high     { border-left: 4px solid #e67e22; }
    .border-medium   { border-left: 4px solid #f1c40f; }
    .border-low      { border-left: 4px solid #3498db; }
    .border-unknown  { border-left: 4px solid #95a5a6; }
    .outdated-card   { border-left: 4px solid #e67e22; }
    .dep-header { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }
    .dep-name   { font-family: monospace; font-weight: 700; font-size: 1em; }
    .dep-ver    { font-family: monospace; font-size: 0.85em; color: var(--vscode-descriptionForeground); }
    /* Ecosystem badges */
    .eco-badge  { padding: 2px 6px; border-radius: 4px; font-size: 0.75em; font-weight: 600; }
    .eco-npm        { background: #cb3837; color: #fff; }
    .eco-pypi       { background: #3572A5; color: #fff; }
    .eco-packagist  { background: #f28d1a; color: #fff; }
    /* Severity badges */
    .sev-badge  { padding: 2px 7px; border-radius: 4px; font-size: 0.8em; font-weight: 700; }
    .sev-critical, .vuln-count.sev-critical { background: #c0392b33; color: #e74c3c; }
    .sev-high,     .vuln-count.sev-high     { background: #e67e2233; color: #e67e22; }
    .sev-medium,   .vuln-count.sev-medium   { background: #f1c40f33; color: #b7950b; }
    .sev-low,      .vuln-count.sev-low      { background: #2980b933; color: #3498db; }
    .sev-unknown,  .vuln-count.sev-unknown  { background: #95a5a633; color: #95a5a6; }
    .vuln-count { padding: 2px 7px; border-radius: 4px; font-size: 0.8em; font-weight: 700; margin-left: auto; }
    /* Open button */
    .open-btn { background: none; border: 1px solid var(--vscode-panel-border); border-radius: 4px;
                color: var(--vscode-textLink-foreground); cursor: pointer; font-size: 0.8em;
                padding: 1px 7px; font-family: var(--vscode-font-family); }
    .open-btn:hover { background: var(--vscode-list-hoverBackground); }
    /* CVE rows */
    .vuln-list  { display: flex; flex-direction: column; gap: 5px; margin-bottom: 6px; }
    .vuln-row   { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; font-size: 0.88em; }
    .vuln-id    { font-family: monospace; font-weight: 600; color: var(--vscode-textLink-foreground);
                  text-decoration: none; }
    .vuln-id:hover { text-decoration: underline; }
    .vuln-summary { color: var(--vscode-foreground); flex: 1; }
    /* Version diff */
    .version-row { display: flex; align-items: center; gap: 8px; font-family: monospace; font-size: 0.9em; }
    .ver-current { color: #e74c3c; }
    .ver-arrow   { color: var(--vscode-descriptionForeground); }
    .ver-latest  { color: #27ae60; font-weight: 600; }
    /* Bump badges */
    .bump-badge { padding: 2px 7px; border-radius: 4px; font-size: 0.78em; font-weight: 700; }
    .bump-major { background: #c0392b33; color: #e74c3c; }
    .bump-minor { background: #e67e2233; color: #e67e22; }
    .bump-patch { background: #2980b933; color: #3498db; }
    .bump-none  { background: #95a5a633; color: #95a5a6; }
    /* Update hint */
    .update-hint { font-size: 0.85em; color: var(--vscode-descriptionForeground); margin-top: 6px; }
    /* Misc */
    .no-issues  { padding: 24px; text-align: center; color: #27ae60; font-size: 1.05em; }
    .empty-tab  { padding: 16px 0; color: #27ae60; font-size: 0.95em; }
    .scan-info  { font-size: 0.82em; color: var(--vscode-descriptionForeground); margin-bottom: 10px; }
    /* EOL / Deprecated cards */
    .chip-eol   { background: #8e44ad33; color: #8e44ad; }
    .eol-card   { border-left: 4px solid #8e44ad; }
    .eol-badge  { padding: 2px 7px; border-radius: 4px; font-size: 0.78em; font-weight: 700;
                  background: #8e44ad33; color: #8e44ad; margin-left: auto; }
    .eol-reason { font-size: 0.87em; color: var(--vscode-descriptionForeground);
                  margin-bottom: 6px; font-style: italic; }
    .eol-warning { font-size: 0.82em; background: #8e44ad15; border-left: 3px solid #8e44ad;
                   padding: 6px 10px; border-radius: 0 4px 4px 0; }
    .eol-explainer { font-size: 0.87em; background: #8e44ad12; border: 1px solid #8e44ad44;
                     border-radius: 6px; padding: 10px 14px; margin-bottom: 12px;
                     line-height: 1.5; }
  </style>
</head>
<body>
  <h1>🔍 OWASP Dependency Check</h1>
  <div class="scan-info">Scanned <strong>${results.length}</strong> package${results.length !== 1 ? "s" : ""} across all manifest files.</div>
  <div class="summary-bar">
    <span class="chip chip-vuln">🔴 Vulnerable: ${vulnerable.length}</span>
    <span class="chip chip-outdated">⏫ Outdated: ${outdated.length}</span>
    <span class="chip chip-eol">⚰️ EOL / Deprecated: ${deprecated.length}</span>
    <span class="chip chip-ok">✅ Up to date: ${upToDate}</span>
    <span class="chip chip-total">📦 Total: ${results.length}</span>
  </div>
  ${noIssues}
  ${
		results.length > 0
			? `
  <div class="tabs">
    <button class="tab-btn active" data-tab="vulnerable">🔴 Vulnerable (${vulnerable.length})</button>
    <button class="tab-btn" data-tab="outdated">⏫ Outdated (${outdated.length})</button>
    <button class="tab-btn" data-tab="eol">⚰️ EOL / Deprecated (${deprecated.length})</button>
  </div>
  <div id="tab-vulnerable">${vulnTab}</div>
  <div id="tab-outdated" style="display:none">${outdatedTab}</div>
  <div id="tab-eol" style="display:none">${eolTab}</div>`
			: ""
  }
  <script nonce="${nonce}">
    var vscode = acquireVsCodeApi();
    var _d = ${depMeta};

    document.addEventListener('click', function(e) {
      var target = e.target;

      // Open manifest file
      var openBtn = target.closest('[data-file]');
      if (openBtn) {
        vscode.postMessage({ command: 'openFile', file: openBtn.getAttribute('data-file') });
        return;
      }

      // Switch tabs
      var tabBtn = target.closest('[data-tab]');
      if (tabBtn) {
        var tab = tabBtn.getAttribute('data-tab');
        document.querySelectorAll('[id^="tab-"]').forEach(function(el) {
          el.style.display = 'none';
        });
        document.querySelectorAll('.tab-btn').forEach(function(el) {
          el.classList.remove('active');
        });
        var tabEl = document.getElementById('tab-' + tab);
        if (tabEl) { tabEl.style.display = ''; }
        tabBtn.classList.add('active');
      }
    });
  </script>
</body>
</html>`;
}

// ── Panel class ───────────────────────────────────────────────────────────────

export class DependencyPanel {
	private static current: DependencyPanel | undefined;
	private readonly panel: vscode.WebviewPanel;
	private readonly disposables: vscode.Disposable[] = [];

	private constructor(extensionUri: vscode.Uri) {
		this.panel = vscode.window.createWebviewPanel(
			"owaspDependencyCheck",
			"OWASP Dependency Check",
			vscode.ViewColumn.Two,
			{
				enableScripts: true,
				localResourceRoots: [extensionUri],
			},
		);
	}

	static show(extensionUri: vscode.Uri, results: DependencyResult[]): void {
		if (DependencyPanel.current) {
			DependencyPanel.current.update(results);
			DependencyPanel.current.panel.reveal(vscode.ViewColumn.Two);
			return;
		}
		const instance = new DependencyPanel(extensionUri);
		DependencyPanel.current = instance;
		instance.update(results);

		instance.panel.onDidDispose(
			() => {
				DependencyPanel.current = undefined;
				instance.disposables.forEach((d) => d.dispose());
			},
			null,
			instance.disposables,
		);

		instance.panel.webview.onDidReceiveMessage(
			(msg: { command: string; file?: string }) => {
				if (msg.command === "openFile" && msg.file) {
					vscode.workspace.openTextDocument(msg.file).then(
						(doc) => vscode.window.showTextDocument(doc),
						() => {
							/* file may have been deleted or moved */
						},
					);
				}
			},
			null,
			instance.disposables,
		);
	}

	private update(results: DependencyResult[]): void {
		const nonce = generateNonce();
		this.panel.webview.html = buildHtml(this.panel.webview, results, nonce);
	}
}
