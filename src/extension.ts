import * as path from "path";
import * as vscode from "vscode";
import { scanDocument, publishDiagnostics } from "./diagnosticProvider";
import { SecurityReportPanel } from "./reportPanel";
import { SecurityCodeActionProvider } from "./codeActionProvider";
import { checkForRuleUpdates, showRulesStatus } from "./updateChecker";
import { writeSecurityReport, loadSavedReport } from "./reportWriter";
import { SecurityFinding } from "./types";
import { scanDependencies } from "./dependencyScanner";
import { DependencyPanel } from "./dependencyPanel";
import { convertReportToPdf } from "./pdfExporter";
import { CvePanel } from "./cvePanel";
import { getStatus as getCveStatus } from "./cveDatabase";

const SUPPORTED_SELECTOR: vscode.DocumentSelector = [
	{ language: "javascript" },
	{ language: "javascriptreact" },
	{ language: "typescript" },
	{ language: "typescriptreact" },
	{ language: "python" },
	{ language: "php" },
	{ language: "apacheconf" },
	{ language: "nginx" },
	{ language: "xml" },
];

export function activate(context: vscode.ExtensionContext): void {
	const diagnosticCollection =
		vscode.languages.createDiagnosticCollection("owaspHelper");
	context.subscriptions.push(diagnosticCollection);

	/** In-memory cache of all findings by file path, used to build the report */
	const findingsCache = new Map<string, SecurityFinding[]>();

	/**
	 * Stores the findings/stats from the most recent workspace scan so that
	 * the "Show Report" command always re-displays that consistent snapshot
	 * rather than an ad-hoc mix of per-file scan results.
	 */
	let lastScanSnapshot:
		| {
				findings: SecurityFinding[];
				scannedCount: number;
				skippedCount: number;
				cancelled: boolean;
		  }
		| undefined;

	/**
	 * Returns true if the file path should be excluded from per-file scanning.
	 * Mirrors the fastScanExclude logic used by the workspace scan so that the
	 * Problems panel and the report panel stay in sync.
	 */
	function isExcludedFromPerFileScan(filePath: string): boolean {
		const normalized = filePath.replace(/\\/g, "/");

		// Always skip compiled output — the bundled extension.js contains all
		// rule regex strings literally and matches hundreds of rules on its own.
		const hardExcludes = [
			"/node_modules/",
			"/out/",
			"/dist/",
			"/.venv/",
			".min.js",
			".min.jsx",
		];
		if (hardExcludes.some((p) => normalized.includes(p))) {
			return true;
		}

		// Also apply user-configured fastScanExclude patterns.
		const config = vscode.workspace.getConfiguration("owaspHelper");
		const excludePatterns = config.get<string[]>("fastScanExclude", []);
		for (const pattern of excludePatterns) {
			// Handle the two common glob forms:
			//   **/some/dir/**  → substring check for "some/dir/"
			//   **/*.ext        → suffix check for ".ext"
			if (pattern.startsWith("**/") && pattern.includes("*.", 3)) {
				// Extension pattern: **/*.min.js → suffix ".min.js"
				const suffix = pattern.slice(pattern.lastIndexOf("*.") + 1);
				if (suffix && normalized.endsWith(suffix)) {
					return true;
				}
			} else {
				// Directory pattern: strip leading **/ and trailing /**
				const inner = pattern
					.replace(/^\*\*\//, "")
					.replace(/\/\*\*$/, "");
				if (inner && normalized.includes("/" + inner + "/")) {
					return true;
				}
			}
		}
		return false;
	}

	function scanAndPublish(document: vscode.TextDocument): void {
		if (isExcludedFromPerFileScan(document.uri.fsPath)) {
			return;
		}
		const findings = scanDocument(document);
		findingsCache.set(document.uri.fsPath, findings);
		publishDiagnostics(document, findings, diagnosticCollection);
	}

	// ── Scan on open ─────────────────────────────────────────────────────────
	if (vscode.window.activeTextEditor) {
		scanAndPublish(vscode.window.activeTextEditor.document);
	}

	context.subscriptions.push(
		vscode.window.onDidChangeActiveTextEditor((editor) => {
			if (editor) {
				scanAndPublish(editor.document);
			}
		}),
	);

	// ── Scan on change (debounced 800 ms per document) ───────────────────────────
	// Use a per-document timer so edits in file B don't cancel the pending
	// scan for file A when both are being edited simultaneously.
	const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();
	context.subscriptions.push(
		vscode.workspace.onDidChangeTextDocument((event) => {
			const key = event.document.uri.fsPath;
			clearTimeout(debounceTimers.get(key));
			debounceTimers.set(
				key,
				setTimeout(() => {
					debounceTimers.delete(key);
					scanAndPublish(event.document);
				}, 800),
			);
		}),
	);

	// ── Scan on save ─────────────────────────────────────────────────────────
	context.subscriptions.push(
		vscode.workspace.onDidSaveTextDocument((document) => {
			const config = vscode.workspace.getConfiguration("owaspHelper");
			if (config.get<boolean>("enableOnSave", true)) {
				scanAndPublish(document);
			}
		}),
	);

	// ── Clean up diagnostics when a file is closed ───────────────────────────
	context.subscriptions.push(
		vscode.workspace.onDidCloseTextDocument((document) => {
			diagnosticCollection.delete(document.uri);
			findingsCache.delete(document.uri.fsPath);
		}),
	);

	// ── Command: Show Report ─────────────────────────────────────────────────
	context.subscriptions.push(
		vscode.commands.registerCommand("owaspHelper.showReport", () => {
			if (lastScanSnapshot) {
				SecurityReportPanel.show(
					context.extensionUri,
					lastScanSnapshot.findings,
					lastScanSnapshot.scannedCount,
					lastScanSnapshot.skippedCount,
					undefined,
					undefined,
					getCveStatus(context),
				);
			} else {
				// No workspace scan has been run yet — show per-file findings
				SecurityReportPanel.show(
					context.extensionUri,
					Array.from(findingsCache.values()).flat(),
					undefined,
					undefined,
					undefined,
					undefined,
					getCveStatus(context),
				);
			}
		}),
	);

	// ── Commands: Fast Scan / Full Scan ──────────────────────────────────────

	/**
	 * Reads a file for scanning without going through VS Code's tokenizer.
	 * For already-open documents the live version is returned immediately.
	 * For everything else the raw bytes are read directly from disk and a
	 * lightweight duck-typed object is returned — no language server, no
	 * syntax-highlighting pipeline, no stalls.
	 */
	const EXT_TO_LANG: Record<string, string> = {
		js: "javascript",
		jsx: "javascriptreact",
		ts: "typescript",
		tsx: "typescriptreact",
		py: "python",
		php: "php",
		conf: "apacheconf",
		config: "xml",
		webconfig: "xml",
		htaccess: "apacheconf",
		nginxconf: "nginx",
	};

	async function openForScan(uri: vscode.Uri): Promise<vscode.TextDocument> {
		// Re-use an already-open live document if available.
		// Use case-insensitive comparison so WorkspaceEdit-modified unsaved
		// documents are found even if drive-letter casing differs on Windows.
		const targetPath = uri.fsPath.toLowerCase();
		const live = vscode.workspace.textDocuments.find(
			(d) => d.uri.fsPath.toLowerCase() === targetPath,
		);
		if (live) {
			return live;
		}
		// Read raw bytes — completely bypasses VS Code's tokenizer and any
		// language-server activation that openTextDocument triggers.
		const ext = uri.fsPath.split(".").pop()?.toLowerCase() ?? "";
		const langId = EXT_TO_LANG[ext] ?? "plaintext";
		const bytes = await vscode.workspace.fs.readFile(uri);
		const text = Buffer.from(bytes).toString("utf8");
		const lines = text.split(/\r?\n/);
		return {
			languageId: langId,
			lineCount: lines.length,
			uri,
			lineAt: (n: number) => ({ text: lines[n] ?? "" }),
			getText: () => text,
		} as unknown as vscode.TextDocument;
	}

	let isScanning = false;

	/**
	 * Core workspace scanner. When `skipLargeFiles` is true files > 512 KB
	 * are skipped; when false they are included.
	 */
	async function runWorkspaceScan(skipLargeFiles: boolean): Promise<void> {
		if (isScanning) {
			vscode.window.showInformationMessage(
				"OWASP Helper: A scan is already in progress.",
			);
			return;
		}
		isScanning = true;

		const include = "**/*.{js,jsx,ts,tsx,py,php,conf,config,webconfig}";
		const htaccessGlob = "**/.htaccess";
		const scanConfig = vscode.workspace.getConfiguration("owaspHelper");
		const excludePatterns = skipLargeFiles
			? scanConfig.get<string[]>("fastScanExclude", [
					"**/node_modules/**",
					"**/out/**",
					"**/dist/**",
					"**/.venv/**",
					"**/*.min.js",
					"**/*.min.jsx",
				])
			: scanConfig.get<string[]>("fullScanExclude", [
					"**/node_modules/**",
					"**/out/**",
					"**/dist/**",
					"**/.venv/**",
				]);
		const exclude = `{${excludePatterns.join(",")}}`;

		const scanFindings: SecurityFinding[] = [];
		const seenKeys = new Set<string>();
		let scannedCount = 0;
		let skippedCount = 0;

		try {
			const progressTitle = skipLargeFiles
				? "OWASP Security Helper: Fast scanning workspace…"
				: "OWASP Security Helper: Full scanning workspace (including large files)…";
			let scanWasCancelled = false;
			await vscode.window.withProgress(
				{
					location: vscode.ProgressLocation.Notification,
					title: progressTitle,
					cancellable: true,
				},
				async (progress, token) => {
					const files = [
						...(await vscode.workspace.findFiles(include, exclude)),
						...(await vscode.workspace.findFiles(
							htaccessGlob,
							exclude,
						)),
					];

					if (files.length === 0) {
						vscode.window.showInformationMessage(
							"OWASP Helper: No supported files found in the workspace. " +
								"Make sure a folder is open that contains .js/.ts/.php/.py files.",
						);
						return;
					}

					progress.report({ message: `0 / ${files.length} files` });

					let done = 0;
					for (const fileUri of files) {
						if (token.isCancellationRequested) {
							scanWasCancelled = true;
							break;
						}
						if (done % 10 === 0) {
							await new Promise<void>((resolve) =>
								setTimeout(resolve, 0),
							);
						}
						try {
							if (skipLargeFiles) {
								const stat =
									await vscode.workspace.fs.stat(fileUri);
								if (stat.size > 512 * 1024) {
									skippedCount++;
									done++;
									progress.report({
										increment: 100 / files.length,
										message: `${done} / ${files.length} files`,
									});
									continue;
								}
							}
							const doc = await openForScan(fileUri);
							const findings = scanDocument(doc);
							findingsCache.set(doc.uri.fsPath, findings);
							publishDiagnostics(
								doc,
								findings,
								diagnosticCollection,
							);
							for (const f of findings) {
								const normPath = f.filePath
									.replace(/\\/g, "/")
									.toLowerCase();
								const key = `${f.rule.id}\x00${normPath}\x00${f.line}`;
								if (!seenKeys.has(key)) {
									seenKeys.add(key);
									scanFindings.push(f);
								}
							}
							scannedCount++;
						} catch {
							skippedCount++;
						}
						done++;
						progress.report({
							increment: 100 / files.length,
							message: `${done} / ${files.length} files`,
						});
					}
				},
			);

			// GAP-10: persist snapshot so showReport always reflects the last scan
			// GAP-11c: store cancellation flag
			lastScanSnapshot = {
				findings: scanFindings,
				scannedCount,
				skippedCount,
				cancelled: scanWasCancelled,
			};

			SecurityReportPanel.show(
				context.extensionUri,
				scanFindings,
				scannedCount,
				skippedCount,
				scanWasCancelled,
				undefined,
				getCveStatus(context),
			);

			const activeCount = scanFindings.filter(
				(f) => !f.justification,
			).length;
			const summaryMsg = scanWasCancelled
				? `OWASP Helper: Scan cancelled — ${activeCount} issue(s) found so far in ${scannedCount} file(s) scanned.`
				: activeCount === 0
					? `OWASP Helper: Scan complete — no issues found in ${scannedCount} file(s). ✅`
					: `OWASP Helper: Scan complete — ${activeCount} issue(s) found in ${scannedCount} file(s).`;

			const workspaceRoot =
				vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
			if (workspaceRoot && scannedCount > 0) {
				try {
					const reportPath = writeSecurityReport(
						scanFindings,
						workspaceRoot,
						scannedCount,
						skippedCount,
					);
					SecurityReportPanel.setReportPath(reportPath);
					const open = "Open in Browser";
					vscode.window
						.showInformationMessage(summaryMsg, open)
						.then((choice) => {
							if (choice === open) {
								vscode.env.openExternal(
									vscode.Uri.file(reportPath),
								);
							}
						});
				} catch {
					vscode.window.showInformationMessage(summaryMsg);
				}
			} else {
				vscode.window.showInformationMessage(summaryMsg);
			}
		} finally {
			isScanning = false;
		}
	}

	context.subscriptions.push(
		vscode.commands.registerCommand("owaspHelper.scanWorkspace", () =>
			runWorkspaceScan(true),
		),
	);

	context.subscriptions.push(
		vscode.commands.registerCommand(
			"owaspHelper.scanWorkspaceFull",
			async () => {
				await runWorkspaceScan(false);
				// Run dependency check as part of the full scan
				await vscode.window.withProgress(
					{
						location: vscode.ProgressLocation.Notification,
						title: "OWASP Helper: Checking dependencies…",
						cancellable: true,
					},
					async (progress, token) => {
						try {
							const results = await scanDependencies({
								progress,
								token,
								extensionContext: context,
							});
							if (
								!token.isCancellationRequested &&
								results.length > 0
							) {
								SecurityReportPanel.updateDependencies(results);
							}
						} catch {
							// Dependency check failure should not block the main scan result
						}
					},
				);
			},
		),
	);

	// ── Code Actions (Quick Fixes) ────────────────────────────────────────────
	context.subscriptions.push(
		vscode.languages.registerCodeActionsProvider(
			SUPPORTED_SELECTOR,
			new SecurityCodeActionProvider(),
			{
				providedCodeActionKinds:
					SecurityCodeActionProvider.providedCodeActionKinds,
			},
		),
	);

	// ── Command: Check for Rule Updates ───────────────────────────────────────
	context.subscriptions.push(
		vscode.commands.registerCommand("owaspHelper.checkForUpdates", () => {
			checkForRuleUpdates(context, false).catch((err) => {
				vscode.window.showErrorMessage(
					`OWASP Helper: Update check failed — ${
						err instanceof Error ? err.message : String(err)
					}`,
				);
			});
		}),
	);

	// ── Command: Check Dependencies ──────────────────────────────────────────
	context.subscriptions.push(
		vscode.commands.registerCommand(
			"owaspHelper.checkDependencies",
			async () => {
				await vscode.window.withProgress(
					{
						location: vscode.ProgressLocation.Notification,
						title: "OWASP Helper: Checking dependencies…",
						cancellable: true,
					},
					async (progress, token) => {
						try {
							const results = await scanDependencies({
								progress,
								token,
								extensionContext: context,
							});
							if (token.isCancellationRequested) {
								return;
							}
							if (results.length === 0) {
								vscode.window.showInformationMessage(
									"OWASP Helper: No package.json, requirements.txt, poetry.lock, Pipfile.lock, or composer.json files found in this workspace.",
								);
								return;
							}
							DependencyPanel.show(context.extensionUri, results);
						} catch (err) {
							vscode.window.showErrorMessage(
								`OWASP Helper: Dependency check failed — ${
									err instanceof Error
										? err.message
										: String(err)
								}`,
							);
						}
					},
				);
			},
		),
	);

	// ── Command: Show Fix Guidance ────────────────────────────────────────────
	context.subscriptions.push(
		vscode.commands.registerCommand(
			"owaspHelper.showFixGuidance",
			(fixDescription: string, reference?: string) => {
				const actions: string[] = [];
				if (reference) {
					actions.push("Open Reference");
				}
				vscode.window
					.showInformationMessage(`💡 ${fixDescription}`, ...actions)
					.then((choice) => {
						if (choice === "Open Reference" && reference) {
							vscode.env.openExternal(
								vscode.Uri.parse(reference),
							);
						}
					});
			},
		),
	);

	// ── Commands: CVE Database ────────────────────────────────────────────────
	context.subscriptions.push(
		vscode.commands.registerCommand("owaspHelper.openCveDatabase", () => {
			CvePanel.show(context);
		}),
	);

	context.subscriptions.push(
		vscode.commands.registerCommand(
			"owaspHelper.downloadCveBaseline",
			async () => {
				CvePanel.show(context);
				// Give the panel time to render, then trigger download automatically
				await new Promise<void>((resolve) => setTimeout(resolve, 500));
				// The user can click the download button in the panel.
				// Alternatively expose this as a separate progress-notification flow:
				await vscode.window.withProgress(
					{
						location: vscode.ProgressLocation.Notification,
						title: "OWASP Helper: Downloading CVE database…",
						cancellable: true,
					},
					async (progress, token) => {
						const { downloadBaseline } =
							await import("./cveDatabase");
						await downloadBaseline(
							context,
							(evt) => {
								if (evt.event === "status") {
									progress.report({ message: evt.message });
								} else if (evt.event === "download_progress") {
									progress.report({
										message: `Downloading… ${evt.percent}%`,
									});
								} else if (evt.event === "index_progress") {
									progress.report({
										message: `Indexing… ${evt.percent}%`,
									});
								} else if (evt.event === "complete") {
									progress.report({
										message: `Done — ${evt.totalCves?.toLocaleString()} CVEs indexed.`,
									});
								} else if (evt.event === "error") {
									vscode.window.showErrorMessage(
										`CVE DB: ${evt.message}`,
									);
								}
							},
							token,
						);
					},
				);
			},
		),
	);

	context.subscriptions.push(
		vscode.commands.registerCommand(
			"owaspHelper.updateCveDeltas",
			async () => {
				await vscode.window.withProgress(
					{
						location: vscode.ProgressLocation.Notification,
						title: "OWASP Helper: Updating CVE database…",
						cancellable: true,
					},
					async (progress, token) => {
						const { updateDeltas } = await import("./cveDatabase");
						await updateDeltas(
							context,
							(evt) => {
								if (evt.event === "status") {
									progress.report({ message: evt.message });
								} else if (evt.event === "delta_progress") {
									progress.report({
										message: `Applying delta ${evt.current}/${evt.total}…`,
									});
								} else if (evt.event === "complete") {
									const msg =
										evt.message ??
										`Done — ${evt.newCves} new, ${evt.updatedCves} updated.`;
									vscode.window.showInformationMessage(
										`OWASP Helper: ${msg}`,
									);
								} else if (evt.event === "error") {
									vscode.window.showErrorMessage(
										`CVE DB: ${evt.message}`,
									);
								}
							},
							token,
						);
					},
				);
			},
		),
	);

	// ── Command: Show Rules Status ────────────────────────────────────────────
	context.subscriptions.push(
		vscode.commands.registerCommand("owaspHelper.showRulesStatus", () => {
			showRulesStatus();
		}),
	);

	// ── Command: Open Saved Report in Report Panel ───────────────────────────
	context.subscriptions.push(
		vscode.commands.registerCommand(
			"owaspHelper.openSavedReport",
			(uri?: vscode.Uri) => {
				if (!uri) {
					return;
				}
				try {
					const { findings, scannedCount, skippedCount } =
						loadSavedReport(uri.fsPath);
					SecurityReportPanel.show(
						context.extensionUri,
						findings,
						scannedCount,
						skippedCount,
						undefined,
						undefined,
						getCveStatus(context),
					);
					SecurityReportPanel.setReportPath(uri.fsPath);
				} catch (err) {
					const msg =
						err instanceof Error && err.message === "NO_JSON"
							? 'OWASP Helper: This report was saved before the panel feature was added. Run "OWASP Helper: Fast Scan" again to generate a new report that can be opened in the panel.'
							: "OWASP Helper: Could not load the saved report.";
					vscode.window.showErrorMessage(msg);
				}
			},
		),
	);

	// ── Command: Convert Report to PDF ──────────────────────────────────────
	context.subscriptions.push(
		vscode.commands.registerCommand(
			"owaspHelper.convertReportToPdf",
			async (uri?: vscode.Uri) => {
				if (!uri) {
					return;
				}
				await vscode.window.withProgress(
					{
						location: vscode.ProgressLocation.Notification,
						title: "OWASP Helper: Converting report to PDF…",
						cancellable: false,
					},
					async () => {
						try {
							const pdfPath = await convertReportToPdf(
								uri.fsPath,
							);
							const open = "Open PDF";
							const choice =
								await vscode.window.showInformationMessage(
									`OWASP Helper: PDF saved — ${path.basename(pdfPath)}`,
									open,
								);
							if (choice === open) {
								vscode.env.openExternal(
									vscode.Uri.file(pdfPath),
								);
							}
						} catch (err) {
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
									`OWASP Helper: PDF conversion failed — ${
										err instanceof Error
											? err.message
											: String(err)
									}`,
								);
							}
						}
					},
				);
			},
		),
	);

	// ── Auto-check for updates on startup ────────────────────────────────────
	const config = vscode.workspace.getConfiguration("owaspHelper");
	if (config.get<boolean>("autoCheckForUpdates", true)) {
		checkForRuleUpdates(context, true).catch(() => {
			/* background check failure is silent */
		});
	}
}

export function deactivate(): void {}
