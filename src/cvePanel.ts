/**
 * CVE Database Panel — webview UI for managing and searching the local CVE database.
 */

import * as vscode from "vscode";
import { randomFillSync } from "crypto";
import {
	getStatus,
	downloadBaseline,
	updateDeltas,
	searchByVendorProduct,
	CveDbStatus,
	CveRecord,
	CveProgressEvent,
} from "./cveDatabase";

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

function buildHtml(nonce: string, status: CveDbStatus): string {
	const statusHtml = status.downloaded
		? `<div class="status-card status-ok">
        <span class="status-dot ok"></span>
        <div class="status-details">
          <strong>Database ready</strong>
          <span>${status.cveCount > 0 ? status.cveCount.toLocaleString() + " CVEs" : "CVE count unknown"} · ${status.dbSizeMb} MB on disk</span>
          ${status.baselineDate ? `<span>Baseline: ${escapeHtml(status.baselineDate)}</span>` : ""}
          ${status.lastUpdated ? `<span>Last updated: ${escapeHtml(status.lastUpdated)}</span>` : ""}
          ${status.releaseTag ? `<span>Release: ${escapeHtml(status.releaseTag)}</span>` : ""}
        </div>
      </div>`
		: `<div class="status-card status-missing">
        <span class="status-dot missing"></span>
        <div class="status-details">
          <strong>Database not downloaded</strong>
          <span>Download the CVE List V5 baseline to enable local CVE search independent of OSV/NVD.</span>
        </div>
      </div>`;

	return /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>CVE Database</title>
  <style nonce="${nonce}">
    *, *::before, *::after { box-sizing: border-box; }
    body { font-family: var(--vscode-font-family); font-size: var(--vscode-font-size);
           color: var(--vscode-foreground); background: var(--vscode-editor-background);
           padding: 16px; margin: 0; }
    h1 { font-size: 1.25em; border-bottom: 1px solid var(--vscode-panel-border);
         padding-bottom: 8px; margin-bottom: 14px; }
    h2 { font-size: 1em; margin: 18px 0 8px; }
    /* Status card */
    .status-card { display: flex; align-items: flex-start; gap: 12px; padding: 12px 14px;
                   border: 1px solid var(--vscode-panel-border); border-radius: 6px;
                   margin-bottom: 16px; }
    .status-dot  { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; margin-top: 4px; }
    .status-dot.ok      { background: #27ae60; }
    .status-dot.missing { background: #e74c3c; }
    .status-details { display: flex; flex-direction: column; gap: 2px; font-size: 0.88em; }
    .status-details strong { font-size: 1em; }
    /* Buttons */
    .btn-row { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
    button { padding: 6px 14px; border-radius: 4px; cursor: pointer; font-size: 0.9em;
             font-family: var(--vscode-font-family); border: 1px solid var(--vscode-button-border, transparent); }
    .btn-primary { background: var(--vscode-button-background); color: var(--vscode-button-foreground); }
    .btn-primary:hover { background: var(--vscode-button-hoverBackground); }
    .btn-secondary { background: var(--vscode-button-secondaryBackground);
                     color: var(--vscode-button-secondaryForeground); }
    .btn-secondary:hover { background: var(--vscode-button-secondaryHoverBackground); }
    button:disabled { opacity: 0.5; cursor: default; }
    /* Progress log */
    #progress-section { display: none; }
    #progress-bar-wrap { background: var(--vscode-progressBar-background, #333);
                         border-radius: 4px; height: 6px; margin-bottom: 8px; overflow: hidden; }
    #progress-bar { height: 100%; width: 0%; background: var(--vscode-progressBar-foreground, #0e70c0);
                    border-radius: 4px; transition: width 0.3s; }
    #progress-log  { font-family: monospace; font-size: 0.82em; max-height: 160px; overflow-y: auto;
                     background: var(--vscode-terminal-background, #1e1e1e);
                     color: var(--vscode-terminal-foreground, #ccc);
                     border: 1px solid var(--vscode-panel-border); border-radius: 4px;
                     padding: 8px; white-space: pre-wrap; }
    /* Search */
    .search-row { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
    input[type="text"] { flex: 1; min-width: 160px; padding: 5px 8px; border-radius: 4px;
                         background: var(--vscode-input-background);
                         color: var(--vscode-input-foreground);
                         border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
                         font-family: var(--vscode-font-family); font-size: 0.9em; }
    /* Results */
    #search-results { display: flex; flex-direction: column; gap: 8px; }
    .cve-card { border: 1px solid var(--vscode-panel-border); border-radius: 6px;
                padding: 10px 12px; border-left: 4px solid #e74c3c; }
    .cve-header { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; flex-wrap: wrap; }
    .cve-id { font-family: monospace; font-weight: 700; color: var(--vscode-textLink-foreground);
               cursor: pointer; text-decoration: underline; font-size: 0.95em; }
    .cve-date { font-size: 0.8em; color: var(--vscode-descriptionForeground); }
    .cve-product { font-size: 0.8em; background: var(--vscode-badge-background);
                   color: var(--vscode-badge-foreground); padding: 1px 6px; border-radius: 10px; }
    .cve-desc { font-size: 0.87em; line-height: 1.4; }
    .no-results { font-size: 0.9em; color: var(--vscode-descriptionForeground); padding: 8px 0; }
    .search-note { font-size: 0.82em; color: var(--vscode-descriptionForeground); margin-bottom: 10px; }
  </style>
</head>
<body>
  <h1>🗄️ CVE Database (CVEProject/cvelistV5)</h1>

  ${statusHtml}

  <div class="btn-row">
    <button class="btn-primary" id="btn-download">⬇ Download / Refresh Baseline</button>
    <button class="btn-secondary" id="btn-update" ${!status.downloaded ? "disabled" : ""}>🔄 Apply Delta Updates</button>
  </div>

  <div id="progress-section">
    <div id="progress-bar-wrap"><div id="progress-bar"></div></div>
    <div id="progress-log"></div>
  </div>

  <h2>🔍 Search CVEs</h2>
  <p class="search-note">Search the local database by vendor/project name and optional product name.
     Results are limited to 100 published CVEs, ordered by most recent.</p>
  <div class="search-row">
    <input type="text" id="vendor-input" placeholder="Vendor / project name (e.g. apache)" />
    <input type="text" id="product-input" placeholder="Product name (optional, e.g. log4j)" />
    <button class="btn-primary" id="btn-search" ${!status.downloaded ? "disabled" : ""}>Search</button>
  </div>
  <div id="search-results"></div>

  <script nonce="${nonce}">
    var vscode = acquireVsCodeApi();

    document.getElementById('btn-download').addEventListener('click', function() {
      vscode.postMessage({ command: 'downloadBaseline' });
    });
    document.getElementById('btn-update').addEventListener('click', function() {
      vscode.postMessage({ command: 'updateDeltas' });
    });
    document.getElementById('btn-search').addEventListener('click', doSearch);
    document.getElementById('vendor-input').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') { doSearch(); }
    });
    document.getElementById('product-input').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') { doSearch(); }
    });

    function doSearch() {
      var vendor = document.getElementById('vendor-input').value.trim();
      if (!vendor) { return; }
      var product = document.getElementById('product-input').value.trim();
      document.getElementById('search-results').innerHTML = '<div class="no-results">Searching…</div>';
      vscode.postMessage({ command: 'search', vendor: vendor, product: product });
    }

    window.addEventListener('message', function(e) {
      var msg = e.data;
      if (msg.type === 'progress') { handleProgress(msg.event); }
      if (msg.type === 'searchResults') { renderResults(msg.results); }
      if (msg.type === 'refresh') { window.location.reload(); }
    });

    function handleProgress(evt) {
      var sec = document.getElementById('progress-section');
      var log = document.getElementById('progress-log');
      var bar = document.getElementById('progress-bar');
      sec.style.display = 'block';

      if (evt.event === 'status') {
        log.textContent += evt.message + '\\n';
        log.scrollTop = log.scrollHeight;
      } else if (evt.event === 'download_start') {
        log.textContent += 'Downloading ' + evt.filename + ' (' + evt.totalMb + ' MB)…\\n';
        log.scrollTop = log.scrollHeight;
      } else if (evt.event === 'download_progress') {
        bar.style.width = evt.percent + '%';
        // Update last line
        var lines = log.textContent.split('\\n');
        var last = lines[lines.length - 2] || '';
        var newLine = '  ↓ ' + evt.percent + '% at ' + evt.speedMbps + ' MB/s, ETA ' + evt.etaSeconds + 's';
        if (last.startsWith('  ↓')) { lines[lines.length - 2] = newLine; } else { lines.push(newLine); lines.push(''); }
        log.textContent = lines.join('\\n');
        log.scrollTop = log.scrollHeight;
      } else if (evt.event === 'download_complete') {
        bar.style.width = '100%';
        log.textContent += 'Download complete. Indexing…\\n';
        log.scrollTop = log.scrollHeight;
      } else if (evt.event === 'index_start') {
        log.textContent += (evt.message || 'Indexing…') + '\\n';
        log.scrollTop = log.scrollHeight;
      } else if (evt.event === 'index_progress') {
        bar.style.width = evt.percent + '%';
        var lines2 = log.textContent.split('\\n');
        var last2 = lines2[lines2.length - 2] || '';
        var newLine2 = '  Indexed ' + evt.filesProcessed.toLocaleString() + ' / ' + evt.totalFiles.toLocaleString() + ' (' + evt.percent + '%)';
        if (last2.startsWith('  Indexed')) { lines2[lines2.length - 2] = newLine2; } else { lines2.push(newLine2); lines2.push(''); }
        log.textContent = lines2.join('\\n');
        log.scrollTop = log.scrollHeight;
      } else if (evt.event === 'delta_start') {
        log.textContent += 'Applying ' + evt.totalDeltas + ' delta update(s)…\\n';
        log.scrollTop = log.scrollHeight;
      } else if (evt.event === 'delta_progress') {
        bar.style.width = Math.round(evt.current / evt.total * 100) + '%';
        log.textContent += '  Delta ' + evt.current + '/' + evt.total + ': +' + evt.newCves + ' new, ' + evt.updatedCves + ' updated\\n';
        log.scrollTop = log.scrollHeight;
      } else if (evt.event === 'complete') {
        bar.style.width = '100%';
        var msg = evt.message || ('Done! ' + (evt.totalCves ? evt.totalCves.toLocaleString() + ' CVEs in database.' : ''));
        log.textContent += '✅ ' + msg + '\\n';
        log.scrollTop = log.scrollHeight;
        document.getElementById('btn-search').disabled = false;
        document.getElementById('btn-update').disabled = false;
        // Reload panel to show updated status
        setTimeout(function() { vscode.postMessage({ command: 'refresh' }); }, 1500);
      } else if (evt.event === 'error') {
        log.textContent += '❌ Error: ' + evt.message + '\\n';
        log.scrollTop = log.scrollHeight;
      }
    }

    function renderResults(results) {
      var container = document.getElementById('search-results');
      if (!results || results.length === 0) {
        container.innerHTML = '<div class="no-results">No matching CVEs found in the local database.</div>';
        return;
      }
      container.innerHTML = results.map(function(r) {
        var date = r.datePublished ? r.datePublished.slice(0, 10) : '';
        return '<div class="cve-card">' +
          '<div class="cve-header">' +
          '<span class="cve-id" data-id="' + r.cveId + '">' + r.cveId + '</span>' +
          '<span class="cve-date">' + date + '</span>' +
          (r.product ? '<span class="cve-product">' + escHtml(r.vendor) + ' / ' + escHtml(r.product) + '</span>' : '') +
          '</div>' +
          '<div class="cve-desc">' + escHtml(r.description.slice(0, 300)) + (r.description.length > 300 ? '…' : '') + '</div>' +
          '</div>';
      }).join('');

      container.querySelectorAll('.cve-id').forEach(function(el) {
        el.addEventListener('click', function() {
          vscode.postMessage({ command: 'openCve', cveId: el.getAttribute('data-id') });
        });
      });
    }

    function escHtml(t) {
      return String(t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }
  </script>
</body>
</html>`;
}

// ── Panel class ───────────────────────────────────────────────────────────────

export class CvePanel {
	private static current: CvePanel | undefined;
	private readonly panel: vscode.WebviewPanel;
	private readonly context: vscode.ExtensionContext;
	private readonly disposables: vscode.Disposable[] = [];
	private operationToken: vscode.CancellationTokenSource | null = null;

	private constructor(context: vscode.ExtensionContext) {
		this.context = context;
		this.panel = vscode.window.createWebviewPanel(
			"owaspCveDatabase",
			"CVE Database",
			vscode.ViewColumn.Two,
			{ enableScripts: true, localResourceRoots: [context.extensionUri] },
		);
	}

	static show(context: vscode.ExtensionContext): void {
		if (CvePanel.current) {
			CvePanel.current.refresh();
			CvePanel.current.panel.reveal(vscode.ViewColumn.Two);
			return;
		}
		const instance = new CvePanel(context);
		CvePanel.current = instance;
		instance.refresh();

		instance.panel.onDidDispose(
			() => {
				instance.operationToken?.cancel();
				CvePanel.current = undefined;
				instance.disposables.forEach((d) => d.dispose());
			},
			null,
			instance.disposables,
		);

		instance.panel.webview.onDidReceiveMessage(
			async (msg: {
				command: string;
				vendor?: string;
				product?: string;
				cveId?: string;
			}) => {
				switch (msg.command) {
					case "downloadBaseline":
						await instance.runOperation(() =>
							downloadBaseline(
								context,
								(evt) => instance.sendProgress(evt),
								instance.operationToken?.token,
							),
						);
						break;
					case "updateDeltas":
						await instance.runOperation(() =>
							updateDeltas(
								context,
								(evt) => instance.sendProgress(evt),
								instance.operationToken?.token,
							),
						);
						break;
					case "search":
						{
							const results = await searchByVendorProduct(
								context,
								msg.vendor ?? "",
								msg.product ?? "",
							);
							instance.panel.webview.postMessage({
								type: "searchResults",
								results,
							});
						}
						break;
					case "openCve":
						if (msg.cveId) {
							vscode.env.openExternal(
								vscode.Uri.parse(
									`https://www.cve.org/CVERecord?id=${encodeURIComponent(msg.cveId)}`,
								),
							);
						}
						break;
					case "refresh":
						instance.refresh();
						break;
				}
			},
			null,
			instance.disposables,
		);
	}

	private refresh(): void {
		const nonce = generateNonce();
		const status = getStatus(this.context);
		this.panel.webview.html = buildHtml(nonce, status);
	}

	private sendProgress(evt: CveProgressEvent): void {
		void this.panel.webview.postMessage({ type: "progress", event: evt });
	}

	private async runOperation(fn: () => Promise<void>): Promise<void> {
		this.operationToken?.cancel();
		this.operationToken = new vscode.CancellationTokenSource();
		try {
			await fn();
		} catch (err) {
			this.sendProgress({
				event: "error",
				message: err instanceof Error ? err.message : String(err),
			});
		} finally {
			this.operationToken = null;
		}
	}
}
