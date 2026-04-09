import * as vscode from "vscode";
import { scanDocument, publishDiagnostics } from "./diagnosticProvider";
import { SecurityReportPanel } from "./reportPanel";
import { SecurityCodeActionProvider } from "./codeActionProvider";
import { checkForRuleUpdates, showRulesStatus } from "./updateChecker";
import { writeSecurityReport, loadSavedReport } from "./reportWriter";
import { SecurityFinding } from "./types";

const SUPPORTED_SELECTOR: vscode.DocumentSelector = [
	{ language: "javascript" },
	{ language: "javascriptreact" },
	{ language: "typescript" },
	{ language: "typescriptreact" },
	{ language: "python" },
	{ language: "php" },
];

export function activate(context: vscode.ExtensionContext): void {
	const diagnosticCollection =
		vscode.languages.createDiagnosticCollection("owaspHelper");
	context.subscriptions.push(diagnosticCollection);

	/** In-memory cache of all findings by file path, used to build the report */
	const findingsCache = new Map<string, SecurityFinding[]>();

	function scanAndPublish(document: vscode.TextDocument): void {
		const findings = scanDocument(document);
		findingsCache.set(document.uri.fsPath, findings);
		publishDiagnostics(document, findings, diagnosticCollection);
	}

	function allFindings(): SecurityFinding[] {
		return Array.from(findingsCache.values()).flat();
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

	// ── Scan on change (debounced 800 ms) ────────────────────────────────────
	let debounceTimer: ReturnType<typeof setTimeout> | undefined;
	context.subscriptions.push(
		vscode.workspace.onDidChangeTextDocument((event) => {
			clearTimeout(debounceTimer);
			debounceTimer = setTimeout(
				() => scanAndPublish(event.document),
				800,
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
			SecurityReportPanel.show(context.extensionUri, allFindings());
		}),
	);

	// ── Command: Scan Workspace ───────────────────────────────────────────────

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
		htaccess: "apacheconf",
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
	context.subscriptions.push(
		vscode.commands.registerCommand(
			"owaspHelper.scanWorkspace",
			async () => {
				if (isScanning) {
					vscode.window.showInformationMessage(
						"OWASP Helper: A scan is already in progress.",
					);
					return;
				}
				isScanning = true;

				const include = "**/*.{js,jsx,ts,tsx,py,php,conf,config}";
				const htaccessGlob = "**/.htaccess";
				const exclude =
					"{**/node_modules/**,**/out/**,**/dist/**,**/.venv/**,**/*.min.js,**/*.min.jsx}";

				// Collect findings locally so onDidCloseTextDocument can't
				// race-clear findingsCache before the report is shown.
				const scanFindings: SecurityFinding[] = [];
				// Deduplicate findings: same rule + file + line = same finding.
				// Guards against the same file being visited twice (e.g. symlinks
				// or case-insensitive Windows paths returning two URIs).
				const seenKeys = new Set<string>();
				let scannedCount = 0;
				let skippedCount = 0;

				try {
					await vscode.window.withProgress(
						{
							location: vscode.ProgressLocation.Notification,
							title: "OWASP Security Helper: Scanning workspace…",
							cancellable: true,
						},
						async (progress, token) => {
							const files = [
								...(await vscode.workspace.findFiles(
									include,
									exclude,
								)),
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

							progress.report({
								message: `0 / ${files.length} files`,
							});

							let done = 0;
							for (const fileUri of files) {
								if (token.isCancellationRequested) {
									break;
								}
								// Yield to the event loop every 10 files so the
								// UI stays responsive and progress updates render.
								if (done % 10 === 0) {
									await new Promise<void>((resolve) =>
										setTimeout(resolve, 0),
									);
								}
								try {
									// Skip files larger than 512 KB — they are almost
									// certainly generated/minified and can cause regex
									// backtracking hangs in scanDocument.
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
									const doc = await openForScan(fileUri);
									const findings = scanDocument(doc);
									// Merge into shared cache for inline diagnostics
									findingsCache.set(doc.uri.fsPath, findings);
									publishDiagnostics(
										doc,
										findings,
										diagnosticCollection,
									);
									// Accumulate locally, deduplicating by rule+file+line.
									// Normalize separators so c:/foo and c:\foo produce the same key.
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

					// Show the report panel (always — even for 0 findings)
					SecurityReportPanel.show(
						context.extensionUri,
						scanFindings,
						scannedCount,
						skippedCount,
					);

					// Always show a completion notification so the user knows the scan ran
					const activeCount = scanFindings.filter(
						(f) => !f.justification,
					).length;
					const summaryMsg =
						activeCount === 0
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
			checkForRuleUpdates(context, false);
		}),
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
					);
				} catch (err) {
					const msg =
						err instanceof Error && err.message === "NO_JSON"
							? 'OWASP Helper: This report was saved before the panel feature was added. Run "OWASP Helper: Scan Workspace" again to generate a new report that can be opened in the panel.'
							: "OWASP Helper: Could not load the saved report. The companion .json file may be missing or corrupt.";
					vscode.window.showErrorMessage(msg);
				}
			},
		),
	);

	// ── Auto-check for updates once per day in the background ─────────────────
	const ONE_DAY_MS = 24 * 60 * 60 * 1000;
	const lastCheck = context.globalState.get<number>(
		"lastUpdateCheckTimestamp",
		0,
	);
	if (Date.now() - lastCheck > ONE_DAY_MS) {
		context.globalState.update("lastUpdateCheckTimestamp", Date.now());
		// Delay 10 s so it doesn't block the editor on startup
		setTimeout(() => checkForRuleUpdates(context, true), 10_000);
	}

	console.log("OWASP Security Helper is active.");
}

export function deactivate(): void {
	/* nothing to clean up */
}
