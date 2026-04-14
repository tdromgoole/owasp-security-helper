import * as vscode from "vscode";
import * as https from "https";
import { RULES_VERSION, RULES_METADATA } from "./rulesVersion";
import { ALL_RULES } from "./rules";

// Populate the shared metadata object so any code reading RULES_METADATA.totalRules
// gets the correct count rather than the placeholder 0.
RULES_METADATA.totalRules = ALL_RULES.length;

/** Shape of the remote rules-manifest.json */
interface RulesManifest {
	rulesVersion: string;
	lastUpdated: string;
	owaspCoverage: string;
	changelogUrl: string;
	releaseNotes?: string;
}

/** Compare two calendar-version strings (YYYY.MM.PATCH). Returns true if remote > local. */
function isNewer(remote: string, local: string): boolean {
	const parse = (v: string) => v.split(".").map(Number);
	const [rY = 0, rM = 0, rP = 0] = parse(remote);
	const [lY = 0, lM = 0, lP = 0] = parse(local);
	if (rY !== lY) {
		return rY > lY;
	}
	if (rM !== lM) {
		return rM > lM;
	}
	return rP > lP;
}

/** Fetches JSON from a URL using Node's built-in https module (no extra deps). */
function fetchJson<T>(url: string, timeoutMs = 8000): Promise<T> {
	return new Promise((resolve, reject) => {
		if (!url.startsWith("https://")) {
			reject(new Error("Only HTTPS requests are permitted"));
			return;
		}
		const req = https.get(url, { timeout: timeoutMs }, (res) => {
			// Follow redirects (GitHub raw URLs occasionally redirect)
			if (
				res.statusCode !== undefined &&
				res.statusCode >= 300 &&
				res.statusCode < 400 &&
				res.headers.location
			) {
				res.resume(); // drain the response
				const redirectUrl = res.headers.location;
				if (!redirectUrl.startsWith("https://")) {
					reject(new Error("Redirect to non-HTTPS URL blocked"));
					return;
				}
				resolve(fetchJson<T>(redirectUrl, timeoutMs));
				return;
			}
			if (res.statusCode !== 200) {
				reject(new Error(`HTTP ${res.statusCode}`));
				return;
			}
			const chunks: Buffer[] = [];
			res.on("data", (chunk: Buffer) => chunks.push(chunk));
			res.on("end", () => {
				try {
					resolve(
						JSON.parse(Buffer.concat(chunks).toString("utf8")) as T,
					);
				} catch {
					reject(new Error("Invalid JSON in rules manifest"));
				}
			});
		});
		req.on("error", reject);
		req.on("timeout", () => {
			req.destroy();
			reject(new Error("Request timed out"));
		});
	});
}

/**
 * Checks the remote manifest URL for a newer rules version and shows a
 * notification if one is available.
 *
 * @param silent  When true, skips the "up to date" success notification
 *                (used for background auto-checks on startup).
 */
export async function checkForRuleUpdates(
	context: vscode.ExtensionContext,
	silent = true,
): Promise<void> {
	const config = vscode.workspace.getConfiguration("owaspHelper");
	const manifestUrl: string = config.get(
		"rulesManifestUrl",
		"https://raw.githubusercontent.com/your-org/owasp-security-helper/main/rules-manifest.json",
	);

	// Respect user opt-out
	if (!config.get<boolean>("autoCheckForUpdates", true)) {
		if (!silent) {
			vscode.window.showInformationMessage(
				"OWASP Security Helper: Automatic update checks are disabled in settings.",
			);
		}
		return;
	}

	try {
		const manifest = await fetchJson<RulesManifest>(manifestUrl);

		if (isNewer(manifest.rulesVersion, RULES_VERSION)) {
			// GAP-11a: skip the notification if we already told the user about
			// this exact remote version — avoids firing every startup.
			const lastSeen = context.globalState.get<string>(
				"lastSeenRemoteVersion",
			);
			if (silent && lastSeen === manifest.rulesVersion) {
				return;
			}

			const action = await vscode.window.showInformationMessage(
				`OWASP Security Helper: A newer rule pack is available! ` +
					`(current: ${RULES_VERSION} → latest: ${manifest.rulesVersion}). ` +
					(manifest.releaseNotes ? manifest.releaseNotes + " " : "") +
					`Update the extension to get the latest security rules.`,
				"View Changelog",
				"Dismiss",
			);

			if (action === "View Changelog") {
				vscode.env.openExternal(
					vscode.Uri.parse(
						manifest.changelogUrl ?? RULES_METADATA.changelogUrl,
					),
				);
			}

			// Store last-seen remote version so we don't spam the notification
			await context.globalState.update(
				"lastSeenRemoteVersion",
				manifest.rulesVersion,
			);
		} else if (!silent) {
			vscode.window.showInformationMessage(
				`OWASP Security Helper: Rules are up to date (v${RULES_VERSION}). ` +
					`${ALL_RULES.length} rules active covering ${RULES_METADATA.owaspCoverage}.`,
			);
		}
	} catch (err) {
		if (!silent) {
			vscode.window.showWarningMessage(
				`OWASP Security Helper: Could not reach rules manifest (${manifestUrl}). ` +
					`Check your internet connection or the 'owaspHelper.rulesManifestUrl' setting. ` +
					`Error: ${(err as Error).message}`,
			);
		}
		// Silently ignore network errors during background checks
	}
}

/**
 * Shows the current rules status in a quick-pick menu.
 */
export function showRulesStatus(): void {
	const items: vscode.QuickPickItem[] = [
		{
			label: `$(shield) OWASP Security Helper — Rules Status`,
			kind: vscode.QuickPickItemKind.Separator,
		},
		{
			label: `$(versions) Local rules version`,
			description: RULES_VERSION,
		},
		{
			label: `$(calendar) Last updated`,
			description: RULES_METADATA.lastUpdated,
		},
		{
			label: `$(checklist) Total rules loaded`,
			description: String(ALL_RULES.length),
		},
		{
			label: `$(globe) OWASP coverage`,
			description: RULES_METADATA.owaspCoverage,
		},
		{
			label: `$(law) Rule breakdown`,
			kind: vscode.QuickPickItemKind.Separator,
		},
		{
			label: "OWASP Top 10 rules",
			description: `${ALL_RULES.filter((r) => /^A\d/.test(r.id)).length} rules`,
		},
		{
			label: "Content Security Policy rules",
			description: `${ALL_RULES.filter((r) => r.id.startsWith("CSP-")).length} rules`,
		},
		{
			label: "PHP-specific rules",
			description: `${ALL_RULES.filter((r) => r.id.startsWith("PHP-") && !r.id.startsWith("PHP-IV")).length} rules`,
		},
		{
			label: "PHP input validation rules",
			description: `${ALL_RULES.filter((r) => r.id.startsWith("PHP-IV")).length} rules`,
		},
		{
			label: "JavaScript/TypeScript rules",
			description: `${ALL_RULES.filter((r) => r.id.startsWith("JS-")).length} rules`,
		},
		{
			label: "General secure coding rules",
			description: `${ALL_RULES.filter((r) => r.id.startsWith("GEN-")).length} rules`,
		},
		{
			label: "HTTP security header rules",
			description: `${ALL_RULES.filter((r) => r.id.startsWith("HDR-")).length} rules`,
		},
		{
			label: "Input validation rules",
			description: `${ALL_RULES.filter((r) => r.id.startsWith("IV-")).length} rules`,
		},
	];

	vscode.window.showQuickPick(items, {
		title: "OWASP Security Helper — Rules Status",
		placeHolder: "Press Escape to close",
		matchOnDescription: true,
	});
}
