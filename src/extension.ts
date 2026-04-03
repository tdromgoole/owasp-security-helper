import * as vscode from "vscode";
import { scanDocument, publishDiagnostics } from "./diagnosticProvider";
import { SecurityReportPanel } from "./reportPanel";
import { SecurityCodeActionProvider } from "./codeActionProvider";
import { checkForRuleUpdates, showRulesStatus } from "./updateChecker";
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
	context.subscriptions.push(
		vscode.commands.registerCommand(
			"owaspHelper.scanWorkspace",
			async () => {
				const include = "**/*.{js,jsx,ts,tsx,py,php}";
				const exclude =
					"{**/node_modules/**,**/out/**,**/dist/**,**/.venv/**}";

				await vscode.window.withProgress(
					{
						location: vscode.ProgressLocation.Notification,
						title: "OWASP Security Helper: Scanning workspace…",
						cancellable: true,
					},
					async (progress, token) => {
						const files = await vscode.workspace.findFiles(
							include,
							exclude,
						);
						let done = 0;
						for (const fileUri of files) {
							if (token.isCancellationRequested) {
								break;
							}
							try {
								const doc =
									await vscode.workspace.openTextDocument(
										fileUri,
									);
								scanAndPublish(doc);
							} catch {
								// skip unreadable files silently
							}
							done++;
							progress.report({
								increment: (done / files.length) * 100,
							});
						}
					},
				);

				SecurityReportPanel.show(context.extensionUri, allFindings());
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
