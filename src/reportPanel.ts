import * as path from "path";
import * as vscode from "vscode";
import { randomFillSync } from "crypto";
import { SecurityFinding, Severity } from "./types";
import { DependencyResult, versionBumpType } from "./dependencyScanner";
import { CveDbStatus } from "./cveDatabase";
import { convertReportToPdf } from "./pdfExporter";
import { writeMarkdownReport } from "./reportWriter";
import { escapeHtml, truncateMatch, getRelativePath } from "./reportUtils";

const _mi = (d: string): string =>
	`<svg class="mi" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="${d}"/></svg>`;
const MI_CRITICAL = _mi(
	"M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z",
);
const MI_WARNING = _mi("M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z");
const MI_INFO = _mi(
	"M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z",
);
const MI_CHECK = _mi(
	"M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 14l-4-4 1.41-1.41L10 13.17l6.59-6.59L18 8l-8 8z",
);
const MI_FOLDER = _mi(
	"M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z",
);
const MI_REPORT = _mi(
	"M15.73 3H8.27L3 8.27v7.46L8.27 21h7.46L21 15.73V8.27L15.73 3zM12 17.3c-.72 0-1.3-.58-1.3-1.3s.58-1.3 1.3-1.3 1.3.58 1.3 1.3-.58 1.3-1.3 1.3zm1-4.3h-2V7h2v6z",
);
const MI_PACKAGE = _mi(
	"M20.54 5.23l-1.39-1.68C18.88 3.21 18.47 3 18 3H6c-.47 0-.88.21-1.16.55L3.46 5.23C3.17 5.57 3 6.02 3 6.5V19c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V6.5c0-.48-.17-.93-.46-1.27zM12 17.5L6.5 12H10v-2h4v2h3.5L12 17.5zM5.12 5l.81-1h12l.94 1H5.12z",
);
const MI_COMMENT = _mi(
	"M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2z",
);
const MI_OPEN_NEW = _mi(
	"M19 19H5V5h7V3H5c-1.11 0-2 .9-2 2v14c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2v-7h-2v7zM14 3v2h3.59l-9.83 9.83 1.41 1.41L19 6.41V10h2V3h-7z",
);
const MI_ALERT = _mi("M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z");
const MI_CLOSE = _mi(
	"M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z",
);

const SEVERITY_ICON: Record<Severity, string> = {
	critical: MI_CRITICAL,
	warning: MI_WARNING,
	info: MI_INFO,
};

/** Produces the full HTML content for the Security Report webview. */
function buildHtml(
	webview: vscode.Webview,
	findings: SecurityFinding[],
	nonce: string,
	workspaceRoot: string,
	scannedCount?: number,
	skippedCount?: number,
	depResults?: DependencyResult[],
	cancelled?: boolean,
	cveStatus?: CveDbStatus,
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
			? `<a href="${f.rule.reference}" target="_blank">Learn more ${MI_OPEN_NEW}</a>`
			: "";
		const fix = f.rule.fixDescription
			? `<div class="fix"><strong>Fix:</strong> ${escapeHtml(f.rule.fixDescription)}</div>`
			: "";
		const loc = showFile
			? `<button class="jump-btn" data-jump="${globalIdx}">${escapeHtml(relPath)} — Line ${f.line + 1}</button>`
			: `<button class="jump-btn" data-jump="${globalIdx}">${MI_OPEN_NEW} Line ${f.line + 1}</button>`;

		if (f.justification) {
			// Mitigated card — greyed with justification note
			return `
				<div class="finding mitigated" data-severity="mitigated">
					<div class="finding-header">
						<span class="badge mitigated">${MI_CHECK} MITIGATED</span>
						<span class="badge ${f.rule.severity} muted">${SEVERITY_ICON[f.rule.severity]} ${f.rule.severity.toUpperCase()}</span>
					<button class="rule-id" data-rule-id="${escapeHtml(f.rule.id)}" title="Filter by ${escapeHtml(f.rule.id)}">${escapeHtml(f.rule.id)}</button>
						${loc}
						${ref}
					</div>
					<div class="title">${escapeHtml(f.rule.title)}</div>
					<div class="justification">${MI_COMMENT} <strong>Justification:</strong> ${escapeHtml(f.justification)}</div>
					<code class="matched muted-code">${escapeHtml(truncateMatch(f.matchedText))}</code>
					<div class="category">Category: ${escapeHtml(f.rule.category)}</div>
				</div>`;
		}

		return `
				<div class="finding ${f.rule.severity}" data-severity="${f.rule.severity}">
					<div class="finding-header">
						<span class="badge ${f.rule.severity}">${SEVERITY_ICON[f.rule.severity]} ${f.rule.severity.toUpperCase()}</span>
					<button class="rule-id" data-rule-id="${escapeHtml(f.rule.id)}" title="Filter by ${escapeHtml(f.rule.id)}">${escapeHtml(f.rule.id)}</button>
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
		const rows = items
			.map((f) => buildFindingCard(f, findings.indexOf(f), true))
			.join("");
		return `<div class="mitigated-section" data-severity-group="mitigated">${rows}</div>`;
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

	function buildDepContent(results: DependencyResult[]): string {
		const SEV_ORDER: Record<string, number> = {
			critical: 0,
			high: 1,
			medium: 2,
			low: 3,
			unknown: 4,
		};
		const sevScore = (v: { severity: string }): number =>
			SEV_ORDER[v.severity] ?? 4;
		const sevColor = (s: string): string => {
			if (s === "critical") {
				return "#e74c3c";
			}
			if (s === "high") {
				return "#c0392b";
			}
			if (s === "medium") {
				return "#e67e22";
			}
			if (s === "low") {
				return "#f39c12";
			}
			return "#888";
		};
		const vulnerable = [
			...results.filter((r) => r.vulnerabilities.length > 0),
		].sort(
			(a, b) =>
				Math.min(...a.vulnerabilities.map(sevScore)) -
				Math.min(...b.vulnerabilities.map(sevScore)),
		);
		const bumpOrder = ["major", "minor", "patch"];
		const outdated = [
			...results.filter((r) => r.isOutdated && r.latestVersion !== null),
		]
			.filter(
				(r) =>
					versionBumpType(r.resolvedVersion, r.latestVersion!) !==
					"none",
			)
			.sort(
				(a, b) =>
					bumpOrder.indexOf(
						versionBumpType(a.resolvedVersion, a.latestVersion!),
					) -
					bumpOrder.indexOf(
						versionBumpType(b.resolvedVersion, b.latestVersion!),
					),
			);
		let html = "";
		if (vulnerable.length > 0) {
			html += `<h2>${MI_REPORT} Vulnerable Packages <span class="count">(${vulnerable.length})</span></h2>`;
			for (const r of vulnerable) {
				const src = r.sourceFile
					.replace(/\\/g, "/")
					.split("/")
					.slice(-2)
					.join("/");
				html += `<div class="dep-card dep-vuln">`;
				html += `<div class="dep-header"><span class="dep-name">${escapeHtml(r.name)}</span>`;
				html += `<span class="dep-ver dep-ver-current">${escapeHtml(r.resolvedVersion)}</span>`;
				html += `<span class="dep-eco">${escapeHtml(r.ecosystem.toUpperCase())}</span>`;
				html += `<span class="dep-src">${escapeHtml(src)}</span></div>`;
				for (const v of [...r.vulnerabilities].sort(
					(a, b) => sevScore(a) - sevScore(b),
				)) {
					html += `<div class="cve-row">`;
					html += `<span class="cve-sev" style="background:${sevColor(v.severity)}22;color:${sevColor(v.severity)}">${escapeHtml(v.severity.toUpperCase())}</span>`;
					html += `<a href="${escapeHtml(v.url)}" target="_blank">${escapeHtml(v.id)} ${MI_OPEN_NEW}</a>`;
					html += `<span class="cve-sum">${escapeHtml(v.summary)}</span></div>`;
				}
				html += `</div>`;
			}
		} else {
			html += `<h2>${MI_REPORT} Vulnerable Packages <span class="count">(0)</span></h2><div class="dep-ok">${MI_CHECK} No known vulnerabilities found in scanned dependencies.</div>`;
		}
		if (outdated.length > 0) {
			html += `<h2>${MI_PACKAGE} Outdated Packages <span class="count">(${outdated.length})</span></h2>`;
			for (const r of outdated) {
				const bump = versionBumpType(
					r.resolvedVersion,
					r.latestVersion!,
				);
				const src = r.sourceFile
					.replace(/\\/g, "/")
					.split("/")
					.slice(-2)
					.join("/");
				html += `<div class="dep-card dep-outdated">`;
				html += `<div class="dep-header"><span class="dep-name">${escapeHtml(r.name)}</span>`;
				html += `<span class="bump-badge bump-${bump}">${bump.toUpperCase()}</span>`;
				html += `<span class="dep-ver">${escapeHtml(r.resolvedVersion)} → <strong>${escapeHtml(r.latestVersion!)}</strong></span>`;
				html += `<span class="dep-eco">${escapeHtml(r.ecosystem.toUpperCase())}</span>`;
				html += `<span class="dep-src">${escapeHtml(src)}</span></div>`;
				html += `</div>`;
			}
		}
		return html;
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
			? `<div class="no-findings">${MI_CHECK} No security issues detected.</div>`
			: "";

	const scanSummary =
		scannedCount !== undefined
			? `<div class="scan-info">${cancelled ? `<span class="cancel-banner">${MI_ALERT} Scan was cancelled — results below are partial.</span> ` : ""}Scanned <strong>${scannedCount}</strong> file(s)${skippedCount ? ` &mdash; <span class="skip-warn">${skippedCount} skipped (unreadable)</span>` : ""}.</div>`
			: cancelled
				? `<div class="scan-info"><span class="cancel-banner">${MI_ALERT} Scan was cancelled — results below are partial.</span></div>`
				: "";

	// ── CVE database status banner ────────────────────────────────────────────
	let cveBanner = "";
	if (cveStatus && !cveStatus.downloaded) {
		cveBanner = `<div class="cve-banner cve-banner-error">${MI_ALERT} CVE database not downloaded — dependency vulnerability scanning is unavailable. <button class="cve-banner-btn" id="cve-open-btn">Download CVE Database</button></div>`;
	} else if (cveStatus?.lastUpdated) {
		const lastUpdatedDate = new Date(cveStatus.lastUpdated);
		const stalenessDays = vscode.workspace
			.getConfiguration("owaspHelper")
			.get<number>("cveStalenessDays", 7);
		const daysSinceUpdate = Math.floor(
			(Date.now() - lastUpdatedDate.getTime()) / (1000 * 60 * 60 * 24),
		);
		const formattedDate = lastUpdatedDate.toLocaleString(undefined, {
			year: "numeric",
			month: "short",
			day: "numeric",
			hour: "2-digit",
			minute: "2-digit",
		});
		if (daysSinceUpdate > stalenessDays) {
			cveBanner = `<div class="cve-banner cve-banner-warn">${MI_WARNING} CVE database is <strong>${daysSinceUpdate} days</strong> out of date. Last updated: <strong>${escapeHtml(formattedDate)}</strong>. <button class="cve-banner-btn" id="cve-open-btn">Update CVE Database</button></div>`;
		} else {
			cveBanner = `<div class="cve-banner cve-banner-info">${MI_INFO} CVE database last updated: <strong>${escapeHtml(formattedDate)}</strong>.</div>`;
		}
	}

	const severityContent =
		activeFindings.length === 0
			? `<div class="no-findings" style="text-align:left;padding:12px 0">${MI_CHECK} No active issues.</div>`
			: buildSeveritySection(
					`${MI_CRITICAL} Critical Issues`,
					activeCritical,
					"critical",
				) +
				buildSeveritySection(
					`${MI_WARNING} Warnings`,
					activeWarning,
					"warning",
				) +
				buildSeveritySection(
					`${MI_INFO} Informational`,
					activeInfo,
					"info",
				);

	const fileContent =
		activeFindings.length === 0
			? `<div class="no-findings" style="text-align:left;padding:12px 0">${MI_CHECK} No active issues.</div>`
			: sortedFiles
					.map(([fp, items], i) => buildFileSection(fp, items, i))
					.join("");
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
		.rule-id { font-family: monospace; font-weight: 600; background: none;
						 border: none; cursor: pointer; padding: 0; color: var(--vscode-textLink-foreground);
						 font-size: inherit; text-decoration: underline dotted; }
		.rule-id:hover { text-decoration: underline; }
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
		.cancel-banner { color: #e74c3c; font-weight: 600; }
		.cve-banner { display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
		              font-size: 0.85em; padding: 7px 12px; border-radius: 5px;
		              margin-bottom: 10px; border-left: 4px solid; }
		.cve-banner-error { background: #c0392b18; border-color: #e74c3c; color: var(--vscode-foreground); }
		.cve-banner-warn  { background: #e67e2218; border-color: #e67e22; color: var(--vscode-foreground); }
		.cve-banner-info  { background: #2980b918; border-color: #3498db; color: var(--vscode-foreground); }
		.cve-banner-btn { padding: 2px 10px; border-radius: 4px; font-size: 0.9em; cursor: pointer;
		                  border: 1px solid var(--vscode-panel-border);
		                  background: var(--vscode-button-secondaryBackground);
		                  color: var(--vscode-button-secondaryForeground);
		                  font-family: var(--vscode-font-family); flex-shrink: 0; }
		.cve-banner-btn:hover { background: var(--vscode-button-secondaryHoverBackground); }
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
		/* Search */
		.search-bar { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; }
		.search-input { flex: 1; max-width: 400px; padding: 5px 10px; border-radius: 4px;
										border: 1px solid var(--vscode-input-border); background: var(--vscode-input-background);
										color: var(--vscode-input-foreground); font-family: var(--vscode-font-family);
										font-size: 0.9em; outline: none; }
		.search-input:focus { border-color: var(--vscode-focusBorder); }
		.search-clear { background: none; border: none; cursor: pointer; padding: 4px 8px;
										color: var(--vscode-descriptionForeground); font-size: 0.9em; border-radius: 4px; }
		.search-clear:hover { background: var(--vscode-list-hoverBackground); color: var(--vscode-foreground); }
		.search-count { font-size: 0.82em; color: var(--vscode-descriptionForeground); }
		/* Dependency cards */
		.dep-card { border: 1px solid var(--vscode-panel-border); border-radius: 6px;
								padding: 10px 12px; margin-bottom: 10px; }
		.dep-vuln  { border-left: 4px solid #e74c3c; }
		.dep-outdated { border-left: 4px solid #e67e22; }
		.dep-header { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 4px; }
		.dep-name { font-family: monospace; font-weight: 700; font-size: 0.95em; }
		.dep-ver { font-family: monospace; font-size: 0.85em; color: var(--vscode-descriptionForeground); }
		.dep-ver-current { color: #e74c3c; }
		.dep-eco { font-size: 0.75em; padding: 1px 6px; border-radius: 4px;
							 background: var(--vscode-badge-background); color: var(--vscode-badge-foreground); }
		.dep-src { font-size: 0.8em; color: var(--vscode-descriptionForeground); font-family: monospace; margin-left: auto; }
		.cve-row { display: flex; align-items: baseline; gap: 8px; margin-bottom: 4px; flex-wrap: wrap; font-size: 0.88em; }
		.cve-sev { padding: 1px 7px; border-radius: 4px; font-size: 0.8em; font-weight: 700; flex-shrink: 0; }
		.cve-sum { color: var(--vscode-descriptionForeground); flex: 1; }
		.bump-badge { padding: 2px 8px; border-radius: 4px; font-size: 0.78em; font-weight: 700; }
		.bump-major { background: #c0392b33; color: #e74c3c; }
		.bump-minor { background: #e67e2233; color: #e67e22; }
		.bump-patch { background: #2980b933; color: #3498db; }
		.dep-ok { padding: 10px 0; color: #27ae60; }
		.chip-dep-vuln { background: #c0392b33; color: #e74c3c; }
		/* PDF export button */
		.report-title-row { display: flex; align-items: baseline; justify-content: space-between;
												border-bottom: 1px solid var(--vscode-panel-border); margin-bottom: 10px;
												padding-bottom: 6px; }
		.report-title-row h1 { border-bottom: none; padding-bottom: 0; margin-bottom: 0; }
		.pdf-btn { padding: 4px 12px; border-radius: 4px; font-size: 0.82em;
							 border: 1px solid var(--vscode-panel-border);
							 background: var(--vscode-button-secondaryBackground);
							 color: var(--vscode-button-secondaryForeground);
							 cursor: pointer; font-family: var(--vscode-font-family); flex-shrink: 0; }
		.pdf-btn:hover:not(:disabled) { background: var(--vscode-button-secondaryHoverBackground); }
		.pdf-btn:disabled { opacity: 0.5; cursor: not-allowed; }
		.pdf-btn-icon { vertical-align: -3px; margin-right: 5px; }
		.mi { width: 1em; height: 1em; vertical-align: -0.15em; display: inline-block; }		.export-btns { display: flex; gap: 6px; flex-shrink: 0; }		@media print { .pdf-btn { display: none !important; } }
	</style>
</head>
<body>
	<div class="report-title-row">
		<h1>OWASP Security Report</h1>
		<div class="export-btns">
			<button class="pdf-btn" id="md-btn"><svg class="pdf-btn-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="14" height="14" fill="currentColor" aria-hidden="true"><path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm-1 7V3.5L18.5 9H13zm-2 8l-2.5-2.5 1.41-1.41L10 14.17l3.59-3.58L15 12l-4 4zm1-4.5V10h2v4h1.5l-2.5 2.5L9 14h1.5z"/></svg>Export to Markdown</button>
			<button class="pdf-btn" id="pdf-btn"><svg class="pdf-btn-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="14" height="14" fill="currentColor" aria-hidden="true"><path d="M20 2H8c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-8.5 7.5c0 .83-.67 1.5-1.5 1.5H9v2H7.5V7H10c.83 0 1.5.67 1.5 1.5v1zm5 2c0 .83-.67 1.5-1.5 1.5h-2.5V7H15c.83 0 1.5.67 1.5 1.5v3zm4-3H19v1h1.5V11H19v2h-1.5V7h3v1.5zM9 9.5h1v-1H9v1zM4 6H2v14c0 1.1.9 2 2 2h14v-2H4V6zm10 5.5h1v-3h-1v3z"/></svg>Export to PDF</button>
		</div>
	</div>
	${scanSummary}
	${cveBanner}
	<div class="summary-bar">
		<span class="summary-chip chip-critical filter-chip" data-filter="critical">${MI_CRITICAL} Critical: ${activeCritical.length}</span>
		<span class="summary-chip chip-warning filter-chip" data-filter="warning">${MI_WARNING} Warnings: ${activeWarning.length}</span>
		<span class="summary-chip chip-info filter-chip" data-filter="info">${MI_INFO} Info: ${activeInfo.length}</span>
		<span class="summary-chip" style="background:var(--vscode-badge-background);color:var(--vscode-badge-foreground)">${MI_FOLDER} Files: ${byFile.size}</span>
		${mitigatedFindings.length > 0 ? `<span class="summary-chip chip-mitigated filter-chip" data-filter="mitigated">${MI_CHECK} Mitigated: ${mitigatedFindings.length}</span>` : ""}
		${depResults && depResults.filter((r) => r.vulnerabilities.length > 0).length > 0 ? `<span class="summary-chip chip-dep-vuln">${MI_REPORT} Dep Vulns: ${depResults.filter((r) => r.vulnerabilities.length > 0).length}</span>` : ""}
	</div>
	<div class="tabs">
		<button class="tab-btn active" data-tab="severity">By Severity</button>
		<button class="tab-btn" data-tab="file">By File</button>
		${mitigatedFindings.length > 0 ? `<button class="tab-btn" data-tab="mitigated">${MI_CHECK} Mitigated</button>` : ""}
		${depResults && depResults.length > 0 ? `<button class="tab-btn" data-tab="deps">${MI_PACKAGE} Dependencies</button>` : ""}
	</div>
	<div class="search-bar">
		<input class="search-input" id="search-input" type="text" placeholder="Search by file name or rule ID…" autocomplete="off" spellcheck="false">
		<button class="search-clear" id="search-clear" title="Clear search">${MI_CLOSE}</button>
		<span class="search-count" id="search-count"></span>
	</div>
	<div class="tab-content" id="tab-severity">
		${severityContent}
	</div>
	<div class="tab-content" id="tab-file" style="display:none">
		${fileContent}
	</div>
	${mitigatedFindings.length > 0 ? `<div class="tab-content" id="tab-mitigated" style="display:none">${buildMitigatedSection(mitigatedFindings)}</div>` : ""}
	${depResults && depResults.length > 0 ? `<div class="tab-content" id="tab-deps" style="display:none">${buildDepContent(depResults)}</div>` : ""}
	<script nonce="${nonce}">
		var vscode = acquireVsCodeApi();
		var _f = ${findingsMeta};
		var _filters = new Set();
		var _searchTerm = '';

		// CVE database banner button
		var cveBannerBtn = document.getElementById('cve-open-btn');
		if (cveBannerBtn) {
			cveBannerBtn.addEventListener('click', function() {
				vscode.postMessage({ command: 'openCveDatabase' });
			});
		}

		function matchesSearch(card) {
			if (!_searchTerm) { return true; }
			var idx = card.querySelector('[data-jump]');
			if (!idx) { return true; }
			var i = parseInt(idx.getAttribute('data-jump'), 10);
			var file = (_f[i] && _f[i].file ? _f[i].file : '').toLowerCase();
			var rule = (_f[i] && _f[i].ruleId ? _f[i].ruleId : '').toLowerCase();
			return file.indexOf(_searchTerm) !== -1 || rule.indexOf(_searchTerm) !== -1;
		}

		function applyFilters() {
			var hasFilter = _filters.size > 0;
			document.querySelectorAll('.filter-chip').forEach(function(chip) {
				var f = chip.getAttribute('data-filter');
				chip.classList.toggle('filter-active', hasFilter && _filters.has(f));
				chip.classList.toggle('filter-dim', hasFilter && !_filters.has(f));
			});
			var totalVisible = 0;
			// By Severity tab: show/hide individual cards; hide empty severity groups
			document.querySelectorAll('[data-severity-group]').forEach(function(grp) {
				var sev = grp.getAttribute('data-severity-group');
				var sevVisible = 0;
				grp.querySelectorAll('.finding').forEach(function(card) {
					var cardSev = card.getAttribute('data-severity');
					var show = (!hasFilter || _filters.has(cardSev)) && matchesSearch(card);
					card.style.display = show ? '' : 'none';
					if (show) { sevVisible++; totalVisible++; }
				});
				grp.style.display = (!hasFilter || _filters.has(sev)) && sevVisible > 0 ? '' : 'none';
			});
			// By File tab: show/hide individual cards; hide empty file groups
			document.querySelectorAll('.file-group').forEach(function(group) {
				var visCount = 0;
				group.querySelectorAll('.finding').forEach(function(card) {
					var sev = card.getAttribute('data-severity');
					var show = (!hasFilter || _filters.has(sev)) && matchesSearch(card);
					card.style.display = show ? '' : 'none';
					if (show) { visCount++; }
				});
				group.style.display = visCount > 0 ? '' : 'none';
			});
			var countEl = document.getElementById('search-count');
			if (countEl) {
				countEl.textContent = _searchTerm ? totalVisible + ' match' + (totalVisible !== 1 ? 'es' : '') : '';
			}
		}

		var searchInput = document.getElementById('search-input');
		var searchClear = document.getElementById('search-clear');
		searchInput.addEventListener('input', function() {
			_searchTerm = searchInput.value.trim().toLowerCase();
			applyFilters();
		});
		searchClear.addEventListener('click', function() {
			searchInput.value = '';
			_searchTerm = '';
			applyFilters();
			searchInput.focus();
		});

		document.addEventListener('click', function(e) {
			var target = e.target;

			// Filter by rule ID
			var ruleIdBtn = target.closest('[data-rule-id]');
			if (ruleIdBtn) {
				var ruleId = ruleIdBtn.getAttribute('data-rule-id').toLowerCase();
				if (_searchTerm === ruleId) {
					// Second click clears the filter
					searchInput.value = '';
					_searchTerm = '';
				} else {
					searchInput.value = ruleId;
					_searchTerm = ruleId;
				}
				applyFilters();
				return;
			}

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
		// PDF export
		var PDF_BTN_LABEL = '<svg class="pdf-btn-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="14" height="14" fill="currentColor" aria-hidden="true"><path d="M20 2H8c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-8.5 7.5c0 .83-.67 1.5-1.5 1.5H9v2H7.5V7H10c.83 0 1.5.67 1.5 1.5v1zm5 2c0 .83-.67 1.5-1.5 1.5h-2.5V7H15c.83 0 1.5.67 1.5 1.5v3zm4-3H19v1h1.5V11H19v2h-1.5V7h3v1.5zM9 9.5h1v-1H9v1zM4 6H2v14c0 1.1.9 2 2 2h14v-2H4V6zm10 5.5h1v-3h-1v3z"/></svg>Export to PDF';
		var pdfBtn = document.getElementById('pdf-btn');
		if (pdfBtn) {
			pdfBtn.addEventListener('click', function() {
				pdfBtn.disabled = true;
				pdfBtn.textContent = 'Converting\u2026';
				vscode.postMessage({ command: 'convertToPdf' });
			});
		}
		// Markdown export
		var MD_BTN_LABEL = '<svg class="pdf-btn-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="14" height="14" fill="currentColor" aria-hidden="true"><path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm-1 7V3.5L18.5 9H13zm-2 8l-2.5-2.5 1.41-1.41L10 14.17l3.59-3.58L15 12l-4 4zm1-4.5V10h2v4h1.5l-2.5 2.5L9 14h1.5z"/></svg>Export to Markdown';
		var mdBtn = document.getElementById('md-btn');
		if (mdBtn) {
			mdBtn.addEventListener('click', function() {
				mdBtn.disabled = true;
				mdBtn.textContent = 'Exporting\u2026';
				vscode.postMessage({ command: 'exportMarkdown' });
			});
		}
		window.addEventListener('message', function(event) {
			var msg = event.data;
			if (msg.command === 'pdfConverted') {
				var btn = document.getElementById('pdf-btn');
				if (btn) { btn.disabled = false; btn.innerHTML = PDF_BTN_LABEL; }
			} else if (msg.command === 'pdfError') {
				var btn = document.getElementById('pdf-btn');
				if (btn) { btn.disabled = false; btn.innerHTML = PDF_BTN_LABEL; }
			} else if (msg.command === 'mdExported') {
				var btn = document.getElementById('md-btn');
				if (btn) { btn.disabled = false; btn.innerHTML = MD_BTN_LABEL; }
			} else if (msg.command === 'mdError') {
				var btn = document.getElementById('md-btn');
				if (btn) { btn.disabled = false; btn.innerHTML = MD_BTN_LABEL; }
			}
		});
	</script>
</body>
</html>`;
}

// escapeHtml, truncateMatch, and getRelativePath are imported from ./reportUtils

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
	private depResults: DependencyResult[] | undefined;
	private cancelled: boolean = false;
	private cveStatus: CveDbStatus | undefined;
	private disposables: vscode.Disposable[] = [];
	private lastReportPath?: string;

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
						const targetLine = Math.min(
							finding.line,
							doc.lineCount - 1,
						);
						const indent =
							doc.lineAt(targetLine).text.match(/^\s*/)?.[0] ??
							"";
						const commentPrefix = finding.filePath.endsWith(".py")
							? "#"
							: "//";
						const commentLine = `${indent}${commentPrefix} owasp-ignore: ${finding.rule.id} -- ${justification.trim()}\n`;
						const edit = new vscode.WorkspaceEdit();
						edit.insert(
							uri,
							new vscode.Position(targetLine, 0),
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
				} else if (msg.command === "openCveDatabase") {
					vscode.commands.executeCommand(
						"owaspHelper.openCveDatabase",
					);
				} else if (msg.command === "convertToPdf") {
					if (!this.lastReportPath) {
						vscode.window.showErrorMessage(
							"OWASP Helper: No saved report found. Run a workspace scan first.",
						);
						this.panel.webview.postMessage({ command: "pdfError" });
						return;
					}
					try {
						const pdfPath = await convertReportToPdf(
							this.lastReportPath,
						);
						this.panel.webview.postMessage({
							command: "pdfConverted",
						});
						const open = "Open PDF";
						const choice =
							await vscode.window.showInformationMessage(
								`OWASP Helper: PDF saved \u2014 ${path.basename(pdfPath)}`,
								open,
							);
						if (choice === open) {
							vscode.env.openExternal(vscode.Uri.file(pdfPath));
						}
					} catch (err) {
						this.panel.webview.postMessage({ command: "pdfError" });
						if (
							err instanceof Error &&
							err.message === "NO_BROWSER"
						) {
							vscode.window.showErrorMessage(
								"OWASP Helper: No Chromium-based browser found. " +
									"Install Google Chrome or Microsoft Edge to enable PDF export.",
							);
						} else {
							vscode.window.showErrorMessage(
								`OWASP Helper: PDF conversion failed \u2014 ${
									err instanceof Error
										? err.message
										: String(err)
								}`,
							);
						}
					}
				} else if (msg.command === "exportMarkdown") {
					const workspaceRoot =
						vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
					if (!workspaceRoot) {
						vscode.window.showErrorMessage(
							"OWASP Helper: No workspace folder open.",
						);
						this.panel.webview.postMessage({ command: "mdError" });
						return;
					}
					try {
						const mdPath = writeMarkdownReport(
							this.findings,
							workspaceRoot,
							this.scannedCount ?? 0,
							this.skippedCount ?? 0,
						);
						this.panel.webview.postMessage({
							command: "mdExported",
						});
						const open = "Open Markdown";
						const choice =
							await vscode.window.showInformationMessage(
								`OWASP Helper: Markdown report saved \u2014 ${path.basename(mdPath)}`,
								open,
							);
						if (choice === open) {
							const doc = await vscode.workspace.openTextDocument(
								vscode.Uri.file(mdPath),
							);
							await vscode.window.showTextDocument(doc);
						}
					} catch (err) {
						this.panel.webview.postMessage({ command: "mdError" });
						vscode.window.showErrorMessage(
							`OWASP Helper: Markdown export failed \u2014 ${
								err instanceof Error ? err.message : String(err)
							}`,
						);
					}
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
		cancelled?: boolean,
		depResults?: DependencyResult[],
		cveStatus?: CveDbStatus,
	): void {
		if (SecurityReportPanel.current) {
			SecurityReportPanel.current.update(
				findings,
				scannedCount,
				skippedCount,
				depResults,
				cancelled,
				cveStatus,
			);
			// Reveal in its current column without forcing a column change
			SecurityReportPanel.current.panel.reveal(undefined, false);
		} else {
			SecurityReportPanel.current = new SecurityReportPanel(extensionUri);
			SecurityReportPanel.current.update(
				findings,
				scannedCount,
				skippedCount,
				depResults,
				cancelled,
				cveStatus,
			);
		}
	}

	public static setReportPath(reportPath: string): void {
		if (SecurityReportPanel.current) {
			SecurityReportPanel.current.lastReportPath = reportPath;
		}
	}

	public static updateDependencies(depResults: DependencyResult[]): void {
		if (SecurityReportPanel.current) {
			SecurityReportPanel.current.depResults = depResults;
			SecurityReportPanel.current.render();
		}
	}

	public update(
		findings: SecurityFinding[],
		scannedCount?: number,
		skippedCount?: number,
		depResults?: DependencyResult[],
		cancelled?: boolean,
		cveStatus?: CveDbStatus,
	): void {
		this.findings = findings;
		this.scannedCount = scannedCount;
		this.skippedCount = skippedCount;
		this.depResults = depResults;
		this.cancelled = cancelled ?? false;
		if (cveStatus !== undefined) {
			this.cveStatus = cveStatus;
		}
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
			this.depResults,
			this.cancelled,
			this.cveStatus,
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
