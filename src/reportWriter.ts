import * as fs from "fs";
import * as path from "path";
import { SecurityFinding, Severity } from "./types";
import { escapeHtml, truncateMatch, getRelativePath } from "./reportUtils";

const SEVERITY_ICON: Record<Severity, string> = {
	critical: "🔴",
	warning: "🟡",
	info: "🔵",
};

function buildFindingRow(f: SecurityFinding, workspaceRoot: string): string {
	const relPath = getRelativePath(f.filePath, workspaceRoot);
	const ref = f.rule.reference
		? `<a href="${escapeHtml(f.rule.reference)}" target="_blank">Learn more ↗</a>`
		: "";

	if (f.justification) {
		return `
			<div class="finding mitigated">
				<div class="finding-header">
					<span class="badge mitigated">✅ MITIGATED</span>
					<span class="badge ${f.rule.severity} muted">${SEVERITY_ICON[f.rule.severity]} ${f.rule.severity.toUpperCase()}</span>
					<span class="rule-id">${escapeHtml(f.rule.id)}</span>
					<span class="location">${escapeHtml(relPath)} — Line ${f.line + 1}</span>
					${ref}
				</div>
				<div class="title">${escapeHtml(f.rule.title)}</div>
				<div class="justification">💬 <strong>Justification:</strong> ${escapeHtml(f.justification)}</div>
				<code class="matched muted-code">${escapeHtml(truncateMatch(f.matchedText))}</code>
				<div class="category">Category: ${escapeHtml(f.rule.category)}</div>
			</div>`;
	}

	const fix = f.rule.fixDescription
		? `<div class="fix"><strong>Fix:</strong> ${escapeHtml(f.rule.fixDescription)}</div>`
		: "";
	return `
			<div class="finding ${f.rule.severity}">
				<div class="finding-header">
					<span class="badge ${f.rule.severity}">${SEVERITY_ICON[f.rule.severity]} ${f.rule.severity.toUpperCase()}</span>
					<span class="rule-id">${escapeHtml(f.rule.id)}</span>
					<span class="location">${escapeHtml(relPath)} — Line ${f.line + 1}</span>
					${ref}
				</div>
				<div class="title">${escapeHtml(f.rule.title)}</div>
				<div class="desc">${escapeHtml(f.rule.description)}</div>
				<code class="matched">${escapeHtml(truncateMatch(f.matchedText))}</code>
				${fix}
				<div class="category">Category: ${escapeHtml(f.rule.category)}</div>
			</div>`;
}

function buildSection(
	title: string,
	items: SecurityFinding[],
	workspaceRoot: string,
): string {
	if (items.length === 0) {
		return "";
	}
	return `<h2>${title} <span class="count">(${items.length})</span></h2>
${items.map((f) => buildFindingRow(f, workspaceRoot)).join("\n")}`;
}

function buildFileSection(
	filePath: string,
	items: SecurityFinding[],
	workspaceRoot: string,
): string {
	const relPath = getRelativePath(filePath, workspaceRoot);
	const sorted = [...items].sort((a, b) => a.line - b.line);
	const critCount = sorted.filter(
		(f) => f.rule.severity === "critical",
	).length;
	const warnCount = sorted.filter(
		(f) => f.rule.severity === "warning",
	).length;
	const infoCount = sorted.filter((f) => f.rule.severity === "info").length;
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
	return `
		<div class="file-group">
			<div class="file-header">
				<span class="file-path">${escapeHtml(relPath)}</span>
				<span class="file-chips">${chips}</span>
			</div>
			<div class="file-findings">
				${sorted.map((f) => buildFindingRow(f, workspaceRoot)).join("\n")}
			</div>
		</div>`;
}

function buildReportHtml(
	findings: SecurityFinding[],
	workspaceRoot: string,
	scannedCount: number,
	skippedCount: number,
	generatedAt: Date,
): string {
	const activeFindings = findings.filter((f) => !f.justification);
	const mitigatedFindings = findings.filter((f) => !!f.justification);
	const critical = activeFindings.filter(
		(f) => f.rule.severity === "critical",
	);
	const warning = activeFindings.filter((f) => f.rule.severity === "warning");
	const info = activeFindings.filter((f) => f.rule.severity === "info");

	const byFile = new Map<string, SecurityFinding[]>();
	for (const f of activeFindings) {
		const arr = byFile.get(f.filePath) ?? [];
		arr.push(f);
		byFile.set(f.filePath, arr);
	}
	const sortedFiles = [...byFile.entries()].sort(
		([, a], [, b]) => b.length - a.length,
	);

	const noActiveFindings =
		activeFindings.length === 0
			? `<div class="no-findings">✅ No active security issues detected.</div>`
			: "";

	const mitigatedSection =
		mitigatedFindings.length === 0
			? ""
			: `
		<div class="mitigated-section">
		  <h2>✅ Mitigated <span class="count">(${mitigatedFindings.length})</span></h2>
		  ${mitigatedFindings.map((f) => buildFindingRow(f, workspaceRoot)).join("\n")}
		</div>`;

	const severityContent =
		noActiveFindings ||
		buildSection("🔴 Critical Issues", critical, workspaceRoot) +
			buildSection("🟡 Warnings", warning, workspaceRoot) +
			buildSection("🔵 Informational", info, workspaceRoot);

	const fileContent =
		noActiveFindings ||
		sortedFiles
			.map(([fp, items]) => buildFileSection(fp, items, workspaceRoot))
			.join("\n");

	const dateStr = generatedAt.toLocaleString();

	return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>OWASP Security Report — ${escapeHtml(dateStr)}</title>
	<style>
		*, *::before, *::after { box-sizing: border-box; }
		body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
					 font-size: 14px; color: #1e1e1e; background: #fff; padding: 20px; margin: 0; }
		h1 { font-size: 1.4em; border-bottom: 2px solid #ddd; padding-bottom: 8px; margin-bottom: 6px; }
		h2 { font-size: 1.05em; margin-top: 24px; margin-bottom: 8px; }
		.meta { font-size: 0.82em; color: #666; margin-bottom: 14px; }
		.count { color: #888; font-weight: normal; }
		.summary-bar { display: flex; gap: 14px; margin-bottom: 18px; flex-wrap: wrap; }
		.summary-chip { padding: 4px 12px; border-radius: 12px; font-size: 0.85em; font-weight: 600; }
		.chip-critical { background: #fde8e8; color: #c0392b; }
		.chip-warning  { background: #fef3e2; color: #d35400; }
		.chip-info     { background: #e8f4fd; color: #2471a3; }
		.chip-files    { background: #eee; color: #333; }
		/* Tabs */
		.tabs { display: flex; border-bottom: 2px solid #ddd; margin-bottom: 16px; gap: 0; }
		.tab-btn { background: none; border: none; cursor: pointer; padding: 8px 18px;
							 font-size: 0.9em; border-bottom: 2px solid transparent; margin-bottom: -2px;
							 color: #555; font-family: inherit; }
		.tab-btn.active { color: #2471a3; border-bottom-color: #2471a3; font-weight: 600; }
		.tab-btn:hover { background: #f5f5f5; }
		/* Findings */
		.finding { border: 1px solid #e0e0e0; border-radius: 6px;
							 padding: 10px 14px; margin-bottom: 10px; background: #fafafa; }
		.finding.critical { border-left: 4px solid #e74c3c; }
		.finding.warning  { border-left: 4px solid #e67e22; }
		.finding.info     { border-left: 4px solid #3498db; }
		.finding-header { display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
											margin-bottom: 6px; font-size: 0.85em; }
		.badge { padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: 600; }
		.badge.critical { background: #fde8e8; color: #c0392b; }
		.badge.warning  { background: #fef3e2; color: #d35400; }
		.badge.info     { background: #e8f4fd; color: #2471a3; }
		.rule-id { font-family: monospace; font-weight: 600; }
		.location { color: #555; font-family: monospace; font-size: 0.9em; }
		.title { font-weight: 600; margin-bottom: 4px; }
		.desc { font-size: 0.9em; color: #555; margin-bottom: 6px; }
		.matched { display: block; background: #f0f0f0; padding: 5px 10px; border-radius: 4px;
							 font-size: 0.85em; white-space: pre-wrap; word-break: break-all;
							 margin-bottom: 6px; font-family: monospace; }
		.fix { font-size: 0.88em; background: #eafaf1; border-left: 3px solid #27ae60;
					 padding: 5px 10px; border-radius: 3px; margin-bottom: 4px; }
		.category { font-size: 0.78em; color: #888; }
		a { color: #2471a3; }
		.no-findings { padding: 24px; text-align: center; color: #27ae60; font-size: 1.1em; }
		/* Mitigated */
		.finding.mitigated { opacity: 0.75; border-left: 4px solid #27ae60; background: #eafaf1; }
		.badge.mitigated { background: #d5f5e3; color: #1e8449; }
		.badge.muted { opacity: 0.5; }
		.muted-code { opacity: 0.6; }
		.justification { font-size: 0.88em; background: #eafaf1; border-left: 3px solid #27ae60;
		                 padding: 5px 10px; border-radius: 3px; margin-bottom: 6px; }
		.chip-mitigated { background: #d5f5e3; color: #1e8449; }
		.mitigated-section { margin-top: 24px; border-top: 2px dashed #27ae60; padding-top: 12px; }
		/* File grouping */
		.file-group { border: 1px solid #e0e0e0; border-radius: 6px; margin-bottom: 12px; overflow: hidden; }
		.file-header { display: flex; align-items: center; gap: 10px; padding: 8px 14px;
									 background: #f5f5f5; flex-wrap: wrap; }
		.file-path { font-family: monospace; font-weight: 600; font-size: 0.9em; flex: 1; }
		.file-chips { display: flex; gap: 6px; flex-shrink: 0; }
		.chip { padding: 2px 8px; border-radius: 10px; font-size: 0.78em; font-weight: 600; }
		.file-findings { padding: 10px 14px; }
		.file-findings .finding { margin-bottom: 8px; }
		.tab-content { display: none; }
		.tab-content.active { display: block; }
	</style>
</head>
<body>
	<h1>OWASP Security Report</h1>
	<div class="meta">Generated: ${escapeHtml(dateStr)} &nbsp;|&nbsp; Scanned: <strong>${scannedCount}</strong> file(s)${skippedCount > 0 ? ` &nbsp;|&nbsp; <span style="color:#d35400">${skippedCount} skipped</span>` : ""}</div>
	<div class="summary-bar">
		<span class="summary-chip chip-critical">🔴 Critical: ${critical.length}</span>
		<span class="summary-chip chip-warning">🟡 Warnings: ${warning.length}</span>
		<span class="summary-chip chip-info">🔵 Info: ${info.length}</span>
		<span class="summary-chip chip-files">📁 Files affected: ${byFile.size}</span>
		${mitigatedFindings.length > 0 ? `<span class="summary-chip chip-mitigated">✅ Mitigated: ${mitigatedFindings.length}</span>` : ""}
	</div>
	<div class="tabs">
		<button class="tab-btn active" onclick="showTab('severity',this)">By Severity</button>
		<button class="tab-btn" onclick="showTab('file',this)">By File</button>
	</div>
	<div class="tab-content active" id="tab-severity">
		${severityContent}
	</div>
	<div class="tab-content" id="tab-file">
		${fileContent}
	</div>
	${mitigatedSection}
	<script>
		function showTab(id, btn) {
			document.querySelectorAll('.tab-content').forEach(function(el) {
				el.classList.remove('active');
			});
			document.querySelectorAll('.tab-btn').forEach(function(el) {
				el.classList.remove('active');
			});
			document.getElementById('tab-' + id).classList.add('active');
			btn.classList.add('active');
		}
	</script>
</body>
</html>`;
}

/**
 * Writes an HTML security report into <workspaceRoot>/.securityReport/
 * with the filename format YYYY-MM-DD_HH-MM-SS.html.
 * Returns the path of the written file.
 */
/** Serialisable subset of SecurityFinding (no RegExp / function fields). */
interface SavedFinding {
	rule: {
		id: string;
		category: string;
		title: string;
		description: string;
		severity: string;
		languages: string[];
		fixDescription?: string;
		reference?: string;
	};
	line: number;
	startChar: number;
	endChar: number;
	matchedText: string;
	filePath: string;
	justification?: string;
}

interface SavedReport {
	scannedCount: number;
	skippedCount: number;
	findings: SavedFinding[];
}

export function writeSecurityReport(
	findings: SecurityFinding[],
	workspaceRoot: string,
	scannedCount: number,
	skippedCount: number,
): string {
	const reportDir = path.join(workspaceRoot, ".securityReport");
	fs.mkdirSync(reportDir, { recursive: true });

	const now = new Date();
	const pad = (n: number): string => String(n).padStart(2, "0");
	const datePart = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
	const timePart = `${pad(now.getHours())}-${pad(now.getMinutes())}-${pad(now.getSeconds())}`;
	const baseName = `${datePart}_${timePart}`;
	const htmlPath = path.join(reportDir, `${baseName}.html`);
	const jsonPath = path.join(reportDir, `${baseName}.json`);

	const html = buildReportHtml(
		findings,
		workspaceRoot,
		scannedCount,
		skippedCount,
		now,
	);
	fs.writeFileSync(htmlPath, html, "utf8");

	// Companion JSON — used by the "Open in Report Panel" context-menu command.
	const saved: SavedReport = {
		scannedCount,
		skippedCount,
		findings: findings.map((f) => ({
			rule: {
				id: f.rule.id,
				category: f.rule.category,
				title: f.rule.title,
				description: f.rule.description,
				severity: f.rule.severity,
				languages: f.rule.languages,
				fixDescription: f.rule.fixDescription,
				reference: f.rule.reference,
			},
			line: f.line,
			startChar: f.startChar,
			endChar: f.endChar,
			matchedText: f.matchedText,
			filePath: f.filePath,
			justification: f.justification,
		})),
	};
	fs.writeFileSync(jsonPath, JSON.stringify(saved, null, 2), "utf8");

	return htmlPath;
}

/**
 * Escapes special Markdown characters in plain text (not inside code spans).
 */
function escapeMd(text: string): string {
	return text.replace(/([\\`*_{}[\]()#+\-.!|>])/g, "\\$1");
}

function buildMarkdownReport(
	findings: SecurityFinding[],
	workspaceRoot: string,
	scannedCount: number,
	skippedCount: number,
	generatedAt: Date,
): string {
	const activeFindings = findings.filter((f) => !f.justification);
	const mitigatedFindings = findings.filter((f) => !!f.justification);
	const critical = activeFindings.filter(
		(f) => f.rule.severity === "critical",
	);
	const warning = activeFindings.filter((f) => f.rule.severity === "warning");
	const info = activeFindings.filter((f) => f.rule.severity === "info");

	const byFile = new Map<string, SecurityFinding[]>();
	for (const f of activeFindings) {
		const arr = byFile.get(f.filePath) ?? [];
		arr.push(f);
		byFile.set(f.filePath, arr);
	}

	const pad = (n: number): string => String(n).padStart(2, "0");
	const dateStr = `${generatedAt.getFullYear()}-${pad(generatedAt.getMonth() + 1)}-${pad(generatedAt.getDate())} ${pad(generatedAt.getHours())}:${pad(generatedAt.getMinutes())}:${pad(generatedAt.getSeconds())}`;

	const lines: string[] = [];

	lines.push("# OWASP Security Report", "");
	lines.push(
		`**Generated:** ${dateStr}  |  **Scanned:** ${scannedCount} file(s)` +
			(skippedCount > 0 ? `  |  **Skipped:** ${skippedCount}` : ""),
		"",
	);

	// Summary table
	lines.push("## Summary", "");
	lines.push("| Severity | Count |");
	lines.push("|----------|------:|");
	lines.push(`| 🔴 Critical | ${critical.length} |`);
	lines.push(`| 🟡 Warning | ${warning.length} |`);
	lines.push(`| 🔵 Info | ${info.length} |`);
	if (mitigatedFindings.length > 0) {
		lines.push(`| ✅ Mitigated | ${mitigatedFindings.length} |`);
	}
	lines.push("");

	function findingBlock(f: SecurityFinding): string {
		const relPath = getRelativePath(f.filePath, workspaceRoot);
		const block: string[] = [];
		if (f.justification) {
			block.push(
				`### ~~\`${f.rule.id}\`~~ · ${relPath} — Line ${f.line + 1}`,
				"",
				`~~**${escapeMd(f.rule.title)}**~~`,
				"",
				`> ✅ **Justification:** ${escapeMd(f.justification)}`,
			);
		} else {
			const ref = f.rule.reference
				? `  |  [Learn more ↗](${f.rule.reference})`
				: "";
			block.push(
				`### \`${f.rule.id}\` · ${relPath} — Line ${f.line + 1}`,
				"",
				`**${escapeMd(f.rule.title)}**`,
				"",
				escapeMd(f.rule.description),
			);
			if (f.rule.fixDescription) {
				block.push("", `> **Fix:** ${escapeMd(f.rule.fixDescription)}`);
			}
			block.push(
				"",
				"```",
				truncateMatch(f.matchedText),
				"```",
				"",
				`**Category:** ${escapeMd(f.rule.category)}${ref}`,
			);
		}
		return block.join("\n");
	}

	function severitySection(title: string, items: SecurityFinding[]): void {
		if (items.length === 0) return;
		lines.push(`## ${title} (${items.length})`, "");
		for (const f of items) {
			lines.push(findingBlock(f), "", "---", "");
		}
	}

	if (activeFindings.length === 0) {
		lines.push("✅ **No active security issues detected.**", "");
	} else {
		severitySection("🔴 Critical Issues", critical);
		severitySection("🟡 Warnings", warning);
		severitySection("🔵 Informational", info);
	}

	if (mitigatedFindings.length > 0) {
		lines.push(`## ✅ Mitigated (${mitigatedFindings.length})`, "");
		for (const f of mitigatedFindings) {
			lines.push(findingBlock(f), "", "---", "");
		}
	}

	return lines.join("\n");
}

/**
 * Writes a Markdown security report into <workspaceRoot>/.securityReport/
 * with the filename format YYYY-MM-DD_HH-MM-SS.md.
 * Returns the path of the written file.
 */
export function writeMarkdownReport(
	findings: SecurityFinding[],
	workspaceRoot: string,
	scannedCount: number,
	skippedCount: number,
): string {
	const reportDir = path.join(workspaceRoot, ".securityReport");
	fs.mkdirSync(reportDir, { recursive: true });

	const now = new Date();
	const pad = (n: number): string => String(n).padStart(2, "0");
	const datePart = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
	const timePart = `${pad(now.getHours())}-${pad(now.getMinutes())}-${pad(now.getSeconds())}`;
	const mdPath = path.join(reportDir, `${datePart}_${timePart}.md`);

	const md = buildMarkdownReport(
		findings,
		workspaceRoot,
		scannedCount,
		skippedCount,
		now,
	);
	fs.writeFileSync(mdPath, md, "utf8");
	return mdPath;
}

/**
 * Reads the companion `.json` file for a saved `.html` report and
 * reconstructs the `SecurityFinding[]` array (patterns omitted — display only).
 */
export function loadSavedReport(htmlPath: string): {
	findings: SecurityFinding[];
	scannedCount: number;
	skippedCount: number;
} {
	const jsonPath = htmlPath.replace(/\.html$/i, ".json");
	if (!fs.existsSync(jsonPath)) {
		throw new Error("NO_JSON");
	}
	const raw: SavedReport = JSON.parse(fs.readFileSync(jsonPath, "utf8"));
	const findings: SecurityFinding[] = raw.findings.map((f) => ({
		rule: {
			...f.rule,
			severity: f.rule.severity as SecurityFinding["rule"]["severity"],
			patterns: [],
		},
		line: f.line,
		startChar: f.startChar,
		endChar: f.endChar,
		matchedText: f.matchedText,
		filePath: f.filePath,
		justification: f.justification,
	}));
	return {
		findings,
		scannedCount: raw.scannedCount,
		skippedCount: raw.skippedCount,
	};
}
