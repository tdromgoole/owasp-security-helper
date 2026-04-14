import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as vscode from "vscode";
import { execFile } from "child_process";

/**
 * Resolves a command on `PATH` using the shell's `which` (Linux/macOS) or
 * `where` (Windows). Returns the first result, or `undefined` on failure.
 */
function which(cmd: string): Promise<string | undefined> {
	return new Promise((resolve) => {
		const tool = process.platform === "win32" ? "where" : "which";
		execFile(tool, [cmd], { timeout: 3_000 }, (err, stdout) => {
			if (err || !stdout.trim()) {
				resolve(undefined);
			} else {
				resolve(stdout.trim().split(/\r?\n/)[0]);
			}
		});
	});
}

/**
 * Searches common install locations for a Chromium-based browser executable
 * that supports the `--headless` / `--print-to-pdf` CLI flags.
 * Returns the first path that exists, or `undefined` if none is found.
 */
async function findChromiumExecutable(): Promise<string | undefined> {
	const platform = process.platform;

	// 1. Honour explicit environment overrides (CI, WSL, custom installs)
	for (const envVar of ["CHROME_PATH", "CHROMIUM_PATH", "BROWSER_PATH"]) {
		const envPath = process.env[envVar];
		if (envPath && fs.existsSync(envPath)) {
			return envPath;
		}
	}

	// 2. Platform-specific hardcoded candidates
	let candidates: string[];

	if (platform === "win32") {
		const local = process.env["LOCALAPPDATA"] ?? "";
		const pf = process.env["PROGRAMFILES"] ?? "C:\\Program Files";
		const pf86 =
			process.env["PROGRAMFILES(X86)"] ?? "C:\\Program Files (x86)";
		candidates = [
			path.join(pf, "Google", "Chrome", "Application", "chrome.exe"),
			path.join(pf86, "Google", "Chrome", "Application", "chrome.exe"),
			path.join(local, "Google", "Chrome", "Application", "chrome.exe"),
			path.join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
			path.join(pf86, "Microsoft", "Edge", "Application", "msedge.exe"),
			path.join(local, "Microsoft", "Edge", "Application", "msedge.exe"),
			path.join(
				local,
				"BraveSoftware",
				"Brave-Browser",
				"Application",
				"brave.exe",
			),
			path.join(
				pf,
				"BraveSoftware",
				"Brave-Browser",
				"Application",
				"brave.exe",
			),
		];
	} else if (platform === "darwin") {
		candidates = [
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
		];
	} else {
		// Linux — covers Debian/Ubuntu, Fedora/RHEL, Arch, Snap, and manual installs
		candidates = [
			"/usr/bin/google-chrome",
			"/usr/bin/google-chrome-stable",
			"/usr/bin/chromium-browser",
			"/usr/bin/chromium",
			"/usr/bin/microsoft-edge",
			"/usr/bin/microsoft-edge-stable",
			"/usr/bin/brave-browser",
			"/usr/local/bin/google-chrome",
			"/usr/local/bin/chromium",
			"/opt/google/chrome/google-chrome",
			"/opt/google/chrome-beta/google-chrome",
			"/opt/chromium.org/chromium/chromium",
			"/snap/bin/chromium",
			"/snap/bin/google-chrome",
		];
	}

	const fromCandidates = candidates.find((p) => {
		try {
			return fs.existsSync(p);
		} catch {
			return false;
		}
	});
	if (fromCandidates) {
		return fromCandidates;
	}

	// 3. PATH fallback — catches nix, Homebrew ARM, and other non-standard prefixes
	const pathNames =
		platform === "win32"
			? ["chrome.exe", "msedge.exe", "brave.exe"]
			: platform === "darwin"
				? ["google-chrome", "chromium", "brave"]
				: [
						"google-chrome",
						"google-chrome-stable",
						"chromium-browser",
						"chromium",
						"brave-browser",
					];

	for (const name of pathNames) {
		const found = await which(name);
		if (found) {
			return found;
		}
	}

	return undefined;
}

/**
 * Converts a saved HTML security report to a PDF file placed alongside it.
 *
 * Uses a locally installed Chromium-based browser (Chrome or Edge) in
 * headless mode — no additional npm dependencies required.
 *
 * @param htmlPath Absolute path to the `.html` report file.
 * @returns Absolute path of the generated `.pdf` file.
 * @throws `Error('NO_BROWSER')` when no supported browser is found.
 * @throws Any other error from the browser sub-process on failure.
 */
export async function convertReportToPdf(htmlPath: string): Promise<string> {
	const browser = await findChromiumExecutable();
	if (!browser) {
		throw new Error("NO_BROWSER");
	}

	const pdfPath = htmlPath.replace(/\.html$/i, ".pdf");
	if (pdfPath === htmlPath) {
		throw new Error("Expected an .html file path");
	}

	// Use a unique per-call temp directory so concurrent exports don't
	// conflict (Chrome refuses a second launch sharing the same profile dir).
	// The directory is removed automatically after export completes or fails.
	const userDataDir = path.join(
		os.tmpdir(),
		`owasp-pdf-${Date.now()}-${Math.random().toString(36).slice(2)}`,
	);

	const fileUrl = vscode.Uri.file(htmlPath).toString();
	const args = [
		"--headless=new",
		"--disable-gpu",
		"--no-sandbox",
		...(process.platform === "linux" ? ["--disable-dev-shm-usage"] : []),
		`--user-data-dir=${userDataDir}`,
		`--print-to-pdf=${pdfPath}`,
		"--no-pdf-header-footer",
		// Ensure all deferred/animated content finishes rendering before print
		"--run-all-compositor-stages-before-draw",
		"--virtual-time-budget=5000",
		fileUrl,
	];

	try {
		return await new Promise<string>((resolve, reject) => {
			execFile(browser, args, { timeout: 30_000 }, (err) => {
				if (err) {
					reject(err);
				} else if (!fs.existsSync(pdfPath)) {
					reject(new Error("PDF file was not created"));
				} else {
					resolve(pdfPath);
				}
			});
		});
	} finally {
		// Clean up the ephemeral chrome profile dir; ignore errors (dir may
		// not exist if Chrome failed before creating it)
		try {
			fs.rmSync(userDataDir, { recursive: true, force: true });
		} catch {
			// non-fatal
		}
	}
}
