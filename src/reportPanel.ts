import * as vscode from "vscode";
import { randomFillSync } from "crypto";
import { SecurityFinding, Severity } from "./types";

const SEVERITY_ICON: Record<Severity, string> = {
	critical: "🔴",
	warning: "🟡",
	info: "🔵",
};

function getRelativePath(filePath: string, workspaceRoot: string): string {
	const norm = filePath.replace(/\\/g, "/");
	const rootNorm = workspaceRoot.replace(/\\/g, "/").replace(/\/?$/, "/");
	if (rootNorm !== "/" && norm.startsWith(rootNorm)) {
		return norm.slice(rootNorm.length);
	}
	return norm.split("/").slice(-3).join("/");
}

/** Produces the full HTML content for the Security Report webview. */
function buildHtml(
	webview: vscode.Webview,
	findings: SecurityFinding[],
	nonce: string,
	workspaceRoot: string,
	scannedCount?: number,
	skippedCount?: number,
): string {
	const critical = findings.filter((f) => f.rule.severity === "critical");
	const warning = findings.filter((f) => f.rule.severity === "warning");
	const info = findings.filter((f) => f.rule.severity === "info");

	const activeFindings = findings.filter((f) => !f.justification);
	const mitigatedFindings = findings.filter((f) => !!f.justification);

	// Safe JSON for the inline script — minimal metadata only
	const findingsMeta = JSON.stringify(
		findings.map((f) => ({
			file: f.filePath,
			line: f.line,
			ruleId: f.rule.id,
		})),
	);

	// Group ACTIVE findings by file, sorted by finding count descending
	const byFile = new Map<
		string,
		Array<{ f: SecurityFinding; idx: number }>
	>();
	activeFindings.forEach((f) => {
		const idx = findings.indexOf(f);
		const arr = byFile.get(f.filePath) ?? [];
		arr.push({ f, idx });
		byFile.set(f.filePath, arr);
	});
	const sortedFiles = [...byFile.entries()].sort(
		(a, b) => b[1].length - a[1].length,
	);

	function buildFindingCard(
		f: SecurityFinding,
		globalIdx: number,
		showFile: boolean,
	): string {
		const relPath = getRelativePath(f.filePath, workspaceRoot);
		const ref = f.rule.reference
			? `<a href="${f.rule.reference}" target="_blank">Learn more ↗</a>`
			: "";
		const fix = f.rule.fixDescription
			? `<div class="fix"><strong>Fix:</strong> ${escapeHtml(f.rule.fixDescription)}</div>`
			: "";
		const loc = showFile
			? `<button class="jump-btn" data-jump="${globalIdx}">${escapeHtml(relPath)} — Line ${f.line + 1}</button>`
			: `<button class="jump-btn" data-jump="${globalIdx}">↗ Line ${f.line + 1}</button>`;

		if (f.justification) {
			// Mitigated card — greyed with justification note
			return `
        <div class="finding mitigated" data-severity="mitigated">
          <div class="finding-header">
            <span class="badge mitigated">✅ MITIGATED</span>
            <span class="badge ${f.rule.severity} muted">${SEVERITY_ICON[f.rule.severity]} ${f.rule.severity.toUpperCase()}</span>
            <span class="rule-id">${escapeHtml(f.rule.id)}</span>
            ${loc}
            ${ref}
          </div>
          <div class="title">${escapeHtml(f.rule.title)}</div>
          <div class="justification">💬 <strong>Justification:</strong> ${escapeHtml(f.justification)}</div>
          <code class="matched muted-code">${escapeHtml(truncateMatch(f.matchedText))}</code>
          <div class="category">Category: ${escapeHtml(f.rule.category)}</div>
        </div>`;
		}

		return `
        <div class="finding ${f.rule.severity}" data-severity="${f.rule.severity}">
          <div class="finding-header">
            <span class="badge ${f.rule.severity}">${SEVERITY_ICON[f.rule.severity]} ${f.rule.severity.toUpperCase()}</span>
            <span class="rule-id">${escapeHtml(f.rule.id)}</span>
            ${loc}
            <button class="justify-btn" data-justify="${globalIdx}" title="Add justification to suppress this finding">Add Justification</button>
            ${ref}
          </div>
          <div class="title">${escapeHtml(f.rule.title)}</div>
          <div class="desc">${escapeHtml(f.rule.description)}</div>
          <code class="matched">${escapeHtml(truncateMatch(f.matchedText))}</code>
          ${fix}
          <div class="category">Category: ${escapeHtml(f.rule.category)}</div>
        </div>`;
	}

	function buildSeveritySection(
		title: string,
		items: SecurityFinding[],
		severityKey: string,
	): string {
		if (items.length === 0) {
			return "";
		}
		const rows = items
			.map((f) => buildFindingCard(f, findings.indexOf(f), true))
			.join("");
		return `<div data-severity-group="${severityKey}"><h2>${title} <span class="count">(${items.length})</span></h2>${rows}</div>`;
	}

	function buildMitigatedSection(items: SecurityFinding[]): string {
		if (items.length === 0) {
			return "";
		}
		const rows = items
			.map((f) => buildFindingCard(f, findings.indexOf(f), true))
			.join("");
		return `
		<div class="mitigated-section" data-severity-group="mitigated">
		  <h2 class="mitigated-title" data-toggle-section="mitigated-body">
		    <span class="chevron">▼</span> ✅ Mitigated <span class="count">(${items.length})</span>
		  </h2>
		  <div id="mitigated-body">${rows}</div>
		</div>`;
	}

	function buildFileSection(
		filePath: string,
		items: Array<{ f: SecurityFinding; idx: number }>,
		sectionIdx: number,
	): string {
		const relPath = getRelativePath(filePath, workspaceRoot);
		const sorted = [...items].sort((a, b) => a.f.line - b.f.line);
		const critCount = sorted.filter(
			(x) => x.f.rule.severity === "critical",
		).length;
		const warnCount = sorted.filter(
			(x) => x.f.rule.severity === "warning",
		).length;
		const infoCount = sorted.filter(
			(x) => x.f.rule.severity === "info",
		).length;
		const chips = [
			critCount > 0
				? `<span class="chip chip-critical">${critCount} critical</span>`
				: "",
			warnCount > 0
				? `<span class="chip chip-warning">${warnCount} warning</span>`
				: "",
			infoCount > 0
				? `<span class="chip chip-info">${infoCount} info</span>`
				: "",
		].join("");
		const rows = sorted
			.map(({ f, idx }) => buildFindingCard(f, idx, false))
			.join("");
		return `
        <div class="file-group">
          <div class="file-header" data-toggle="ff-${sectionIdx}">
            <span class="chevron">▼</span>
            <span class="file-path">${escapeHtml(relPath)}</span>
            <span class="file-chips">${chips}</span>
          </div>
          <div class="file-findings" id="ff-${sectionIdx}">
            ${rows}
          </div>
        </div>`;
	}

	const activeCritical = activeFindings.filter(
		(f) => f.rule.severity === "critical",
	);
	const activeWarning = activeFindings.filter(
		(f) => f.rule.severity === "warning",
	);
	const activeInfo = activeFindings.filter((f) => f.rule.severity === "info");

	const noFindings =
		activeFindings.length === 0 && mitigatedFindings.length === 0
			? `<div class="no-findings">✅ No security issues detected.</div>`
			: "";

	const scanSummary =
		scannedCount !== undefined
			? `<div class="scan-info">Scanned <strong>${scannedCount}</strong> file(s)${skippedCount ? ` &mdash; <span class="skip-warn">${skippedCount} skipped (unreadable)</span>` : ""}.</div>`
			: "";

	const severityContent =
		(activeFindings.length === 0
			? `<div class="no-findings" style="text-align:left;padding:12px 0">✅ No active issues.</div>`
			: buildSeveritySection(
					"🔴 Critical Issues",
					activeCritical,
					"critical",
				) +
				buildSeveritySection("🟡 Warnings", activeWarning, "warning") +
				buildSeveritySection("🔵 Informational", activeInfo, "info")) +
		buildMitigatedSection(mitigatedFindings);

	const fileContent =
		(activeFindings.length === 0
			? `<div class="no-findings" style="text-align:left;padding:12px 0">✅ No active issues.</div>`
			: sortedFiles
					.map(([fp, items], i) => buildFileSection(fp, items, i))
					.join("")) + buildMitigatedSection(mitigatedFindings);

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
    h1 { font-size: 1.3em; border-bottom: 1px solid var(--vscode-panel-border);
         padding-bottom: 6px; margin-bottom: 10px; }
    h2 { font-size: 1em; margin-top: 20px; }
    .count { color: var(--vscode-descriptionForeground); font-weight: normal; }
    .summary-bar { display: flex; gap: 16px; margin-bottom: 12px; flex-wrap: wrap; }
    .summary-chip { padding: 4px 10px; border-radius: 12px; font-size: 0.85em; font-weight: 600; }
    .chip-critical { background: #c0392b33; color: #e74c3c; }
    .chip-warning  { background: #e67e2233; color: #e67e22; }
    .chip-info     { background: #2980b933; color: #3498db; }
    /* Tabs */
    .tabs { display: flex; gap: 2px; margin-bottom: 14px;
            border-bottom: 1px solid var(--vscode-panel-border); }
    .tab-btn { background: none; border: none; cursor: pointer;
               color: var(--vscode-foreground); padding: 6px 14px; font-size: 0.9em;
               border-bottom: 2px solid transparent; margin-bottom: -1px; }
    .tab-btn.active { color: var(--vscode-textLink-foreground);
                      border-bottom-color: var(--vscode-textLink-foreground); font-weight: 600; }
    .tab-btn:hover { background: var(--vscode-list-hoverBackground); }
    /* Findings */
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
    .jump-btn { background: none; border: 1px solid var(--vscode-panel-border); border-radius: 4px;
                color: var(--vscode-textLink-foreground); cursor: pointer; font-size: 0.8em;
                padding: 1px 7px; font-family: var(--vscode-font-family); }
    .jump-btn:hover { background: var(--vscode-list-hoverBackground); }
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
    .scan-info { font-size: 0.82em; color: var(--vscode-descriptionForeground); margin-bottom: 10px; }
    .skip-warn { color: #e67e22; }
    /* File grouping */
    .file-group { border: 1px solid var(--vscode-panel-border); border-radius: 6px;
                  margin-bottom: 10px; overflow: hidden; }
    .file-header { display: flex; align-items: center; gap: 10px; padding: 8px 12px;
                   background: var(--vscode-sideBar-background); cursor: pointer;
                   user-select: none; flex-wrap: wrap; }
    .file-header:hover { background: var(--vscode-list-hoverBackground); }
    .chevron { font-size: 0.75em; width: 10px; flex-shrink: 0; }
    .file-path { font-family: monospace; font-weight: 600; font-size: 0.9em; flex: 1;
                 min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .file-chips { display: flex; gap: 6px; flex-shrink: 0; }
    .chip { padding: 2px 7px; border-radius: 10px; font-size: 0.78em; font-weight: 600; }
    .file-findings { padding: 10px 12px; }
    .file-findings .finding { margin-bottom: 8px; }
    /* Justify button */
    .justify-btn { background: none; border: 1px dashed var(--vscode-panel-border); border-radius: 4px;
                   color: var(--vscode-descriptionForeground); cursor: pointer; font-size: 0.78em;
                   padding: 1px 7px; font-family: var(--vscode-font-family); margin-left: auto; }
    .justify-btn:hover { background: var(--vscode-list-hoverBackground); color: var(--vscode-foreground); }
    /* Mitigated findings */
    .finding.mitigated { opacity: 0.7; border-left: 4px solid #27ae60; background: #27ae6008; }
    .badge.mitigated { background: #27ae6033; color: #27ae60; }
    .badge.muted { opacity: 0.5; }
    .muted-code { opacity: 0.6; }
    .justification { font-size: 0.88em; background: #27ae6015; border-left: 3px solid #27ae60;
                     padding: 4px 8px; border-radius: 3px; margin-bottom: 6px; }
    .chip-mitigated { background: #27ae6033; color: #27ae60; }
    .mitigated-section { margin-top: 20px; }
    .mitigated-title { cursor: pointer; user-select: none; display: flex; align-items: center; gap: 6px; }
    .mitigated-title:hover { opacity: 0.8; }
    /* Filter chips */
    .filter-chip { cursor: pointer; user-select: none; }
    .filter-chip.filter-active { outline: 2px solid currentColor; outline-offset: 2px; }
    .filter-chip.filter-dim { opacity: 0.4; }
  </style>
</head>
<body>
  <h1>OWASP Security Report</h1>
  ${scanSummary}
  <div class="summary-bar">
    <span class="summary-chip chip-critical filter-chip" data-filter="critical">🔴 Critical: ${activeCritical.length}</span>
    <span class="summary-chip chip-warning filter-chip" data-filter="warning">🟡 Warnings: ${activeWarning.length}</span>
    <span class="summary-chip chip-info filter-chip" data-filter="info">🔵 Info: ${activeInfo.length}</span>
    <span class="summary-chip" style="background:var(--vscode-badge-background);color:var(--vscode-badge-foreground)">📁 Files: ${byFile.size}</span>
    ${mitigatedFindings.length > 0 ? `<span class="summary-chip chip-mitigated filter-chip" data-filter="mitigated">✅ Mitigated: ${mitigatedFindings.length}</span>` : ""}
  </div>
  <div class="tabs">
    <button class="tab-btn active" data-tab="severity">By Severity</button>
    <button class="tab-btn" data-tab="file">By File</button>
  </div>
  <div class="tab-content" id="tab-severity">
    ${severityContent}
  </div>
  <div class="tab-content" id="tab-file" style="display:none">
    ${fileContent}
  </div>
  <script nonce="${nonce}">
    var vscode = acquireVsCodeApi();
    var _f = ${findingsMeta};
    var _filters = new Set();

    function applyFilters() {
      var hasFilter = _filters.size > 0;
      document.querySelectorAll('.filter-chip').forEach(function(chip) {
        var f = chip.getAttribute('data-filter');
        chip.classList.toggle('filter-active', hasFilter && _filters.has(f));
        chip.classList.toggle('filter-dim', hasFilter && !_filters.has(f));
      });
      // By Severity tab: show/hide severity groups
      document.querySelectorAll('[data-severity-group]').forEach(function(grp) {
        var sev = grp.getAttribute('data-severity-group');
        grp.style.display = (!hasFilter || _filters.has(sev)) ? '' : 'none';
      });
      // By File tab: show/hide individual cards; hide empty file groups
      document.querySelectorAll('.file-group').forEach(function(group) {
        var visCount = 0;
        group.querySelectorAll('.finding').forEach(function(card) {
          var sev = card.getAttribute('data-severity');
          var show = !hasFilter || _filters.has(sev);
          card.style.display = show ? '' : 'none';
          if (show) { visCount++; }
        });
        group.style.display = visCount > 0 ? '' : 'none';
      });
    }

    document.addEventListener('click', function(e) {
      var target = e.target;

      // Toggle filter chip (mitigated is exclusive with severity filters)
      var filterChip = target.closest('[data-filter]');
      if (filterChip) {
        var f = filterChip.getAttribute('data-filter');
        if (_filters.has(f)) {
          _filters.delete(f);
        } else {
          if (f === 'mitigated') {
            _filters.delete('critical');
            _filters.delete('warning');
            _filters.delete('info');
          } else {
            _filters.delete('mitigated');
          }
          _filters.add(f);
        }
        applyFilters();
        return;
      }

      // Jump to file+line
      var jumpBtn = target.closest('[data-jump]');
      if (jumpBtn) {
        var idx = parseInt(jumpBtn.getAttribute('data-jump'), 10);
        vscode.postMessage({ command: 'openFile', file: _f[idx].file, line: _f[idx].line });
        return;
      }

      // Toggle file section (collapse/expand)
      var header = target.closest('[data-toggle]');
      if (header) {
        var id = header.getAttribute('data-toggle');
        var el = document.getElementById(id);
        if (el) {
          var collapsed = el.style.display === 'none';
          el.style.display = collapsed ? 'block' : 'none';
          var chevron = header.querySelector('.chevron');
          if (chevron) { chevron.textContent = collapsed ? '▼' : '▶'; }
        }
        return;
      }

      // Toggle mitigated section
      var secHeader = target.closest('[data-toggle-section]');
      if (secHeader) {
        var secId = secHeader.getAttribute('data-toggle-section');
        var secEl = document.getElementById(secId);
        if (secEl) {
          var secCollapsed = secEl.style.display === 'none';
          secEl.style.display = secCollapsed ? 'block' : 'none';
          var secChevron = secHeader.querySelector('.chevron');
          if (secChevron) { secChevron.textContent = secCollapsed ? '▼' : '▶'; }
        }
        return;
      }

      // Add justification
      var justifyBtn = target.closest('[data-justify]');
      if (justifyBtn) {
        var idx = parseInt(justifyBtn.getAttribute('data-justify'), 10);
        vscode.postMessage({ command: 'addJustification', globalIdx: idx });
        return;
      }

      // Switch tabs
      var tabBtn = target.closest('[data-tab]');
      if (tabBtn) {
        var tab = tabBtn.getAttribute('data-tab');
        document.querySelectorAll('.tab-content').forEach(function(el) {
          el.style.display = 'none';
        });
        document.querySelectorAll('.tab-btn').forEach(function(el) {
          el.classList.remove('active');
        });
        var tabEl = document.getElementById('tab-' + tab);
        if (tabEl) { tabEl.style.display = 'block'; }
        tabBtn.classList.add('active');
      }
    });
  </script>
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

function truncateMatch(text: string, maxChars = 300): string {
	const lines = text.split("\n");
	if (lines.length > 5) {
		const first5 = lines.slice(0, 5).join("\n");
		return (
			(first5.length > maxChars
				? first5.slice(0, maxChars) + "\u2026"
				: first5) + "\n\u2026"
		);
	}
	if (text.length > maxChars) {
		return text.slice(0, maxChars) + "\u2026";
	}
	return text;
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
	private scannedCount: number | undefined;
	private skippedCount: number | undefined;
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

		// Handle messages from the webview
		this.panel.webview.onDidReceiveMessage(
			async (msg: {
				command: string;
				file: string;
				line: number;
				globalIdx?: number;
			}) => {
				if (msg.command === "openFile") {
					try {
						const uri = vscode.Uri.file(msg.file);
						const doc =
							await vscode.workspace.openTextDocument(uri);
						const editor = await vscode.window.showTextDocument(
							doc,
							vscode.ViewColumn.One,
						);
						const pos = new vscode.Position(
							Math.max(0, msg.line),
							0,
						);
						editor.selection = new vscode.Selection(pos, pos);
						editor.revealRange(
							new vscode.Range(pos, pos),
							vscode.TextEditorRevealType.InCenter,
						);
					} catch {
						// File may no longer exist; silently ignore
					}
				} else if (
					msg.command === "addJustification" &&
					msg.globalIdx !== undefined
				) {
					const finding = this.findings[msg.globalIdx];
					if (!finding || finding.justification) {
						return;
					}
					const justification = await vscode.window.showInputBox({
						title: `Justify: ${finding.rule.id}`,
						prompt: `Reason for suppressing this finding at line ${finding.line + 1} in ${finding.filePath.split(/[\/\\]/).pop()}`,
						placeHolder:
							"e.g. Input is validated upstream; no user data reaches this call",
						validateInput: (v) =>
							v.trim() ? null : "Justification cannot be empty",
					});
					if (justification === undefined) {
						return; // cancelled
					}
					// Insert ignore comment into the source file
					try {
						const uri = vscode.Uri.file(finding.filePath);
						const doc =
							await vscode.workspace.openTextDocument(uri);
						const indent =
							doc.lineAt(finding.line).text.match(/^\s*/)?.[0] ??
							"";
						const commentPrefix = finding.filePath.endsWith(".py")
							? "#"
							: "//";
						const commentLine = `${indent}${commentPrefix} owasp-ignore: ${finding.rule.id} -- ${justification.trim()}\n`;
						const edit = new vscode.WorkspaceEdit();
						edit.insert(
							uri,
							new vscode.Position(finding.line, 0),
							commentLine,
						);
						await vscode.workspace.applyEdit(edit);
						// Save immediately so future workspace scans read the comment from disk.
						try {
							const savedDoc =
								await vscode.workspace.openTextDocument(uri);
							await savedDoc.save();
						} catch {
							// Save failure is non-fatal — the in-memory version still works
							// for the current session.
						}
					} catch {
						vscode.window.showWarningMessage(
							"OWASP Helper: Could not insert justification comment.",
						);
						return;
					}
					// Optimistic update — reflect mitigation in the panel immediately
					finding.justification = justification.trim();
					this.render();
				}
			},
			null,
			this.disposables,
		);

		this.render();
	}

	public static show(
		extensionUri: vscode.Uri,
		findings: SecurityFinding[],
		scannedCount?: number,
		skippedCount?: number,
	): void {
		const col =
			vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One;
		if (SecurityReportPanel.current) {
			SecurityReportPanel.current.update(
				findings,
				scannedCount,
				skippedCount,
			);
			// Reveal in its current column without forcing a column change
			SecurityReportPanel.current.panel.reveal(undefined, false);
		} else {
			SecurityReportPanel.current = new SecurityReportPanel(extensionUri);
			SecurityReportPanel.current.update(
				findings,
				scannedCount,
				skippedCount,
			);
		}
	}

	public update(
		findings: SecurityFinding[],
		scannedCount?: number,
		skippedCount?: number,
	): void {
		this.findings = findings;
		this.scannedCount = scannedCount;
		this.skippedCount = skippedCount;
		this.render();
	}

	private render(): void {
		const nonce = generateNonce();
		const workspaceRoot =
			vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? "";
		this.panel.webview.html = buildHtml(
			this.panel.webview,
			this.findings,
			nonce,
			workspaceRoot,
			this.scannedCount,
			this.skippedCount,
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
