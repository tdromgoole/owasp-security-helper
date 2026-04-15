import * as fs from "fs";
import * as http from "http";
import * as net from "net";
import * as stream from "stream";
import * as crypto from "crypto";
import * as os from "os";
import * as path from "path";
import { execFile, spawn } from "child_process";

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

// ---------------------------------------------------------------------------
// Chrome DevTools Protocol (CDP) helpers
// ---------------------------------------------------------------------------

/** Returns a free TCP port on 127.0.0.1. */
function getFreePort(): Promise<number> {
	return new Promise((resolve, reject) => {
		const srv = net.createServer();
		srv.listen(0, "127.0.0.1", () => {
			const port = (srv.address() as net.AddressInfo).port;
			srv.close(() => resolve(port));
		});
		srv.on("error", reject);
	});
}

/** HTTP GET — returns the full response body as a string. */
function httpGet(url: string): Promise<string> {
	return new Promise((resolve, reject) => {
		http.get(url, (res) => {
			let body = "";
			res.on("data", (c: Buffer) => (body += c.toString()));
			res.on("end", () => resolve(body));
		}).on("error", reject);
	});
}

/**
 * Polls `http://127.0.0.1:<port>/json/list` until a page target with a
 * webSocketDebuggerUrl appears, or `timeoutMs` elapses.
 */
async function waitForDebugTarget(
	port: number,
	timeoutMs: number,
): Promise<string> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		try {
			const raw = await httpGet(`http://127.0.0.1:${port}/json/list`);
			const targets = JSON.parse(raw) as Array<{
				type?: string;
				webSocketDebuggerUrl?: string;
			}>;
			const pg = targets.find(
				(t) => t.type === "page" && t.webSocketDebuggerUrl,
			);
			if (pg?.webSocketDebuggerUrl) {
				return pg.webSocketDebuggerUrl;
			}
		} catch {
			// Chrome not ready yet — keep polling
		}
		await new Promise<void>((r) => setTimeout(r, 200));
	}
	throw new Error("Chrome DevTools target did not appear within the timeout");
}

/** Build a masked WebSocket text frame (client → server, RFC 6455 §5). */
function wsMakeFrame(text: string): Buffer {
	const payload = Buffer.from(text, "utf8");
	const len = payload.length;
	const maskKey = crypto.randomBytes(4);
	let headerSize: number;
	if (len < 126) {
		headerSize = 2;
	} else if (len < 65536) {
		headerSize = 4;
	} else {
		headerSize = 10;
	}
	const frame = Buffer.allocUnsafe(headerSize + 4 + len);
	frame[0] = 0x81; // FIN=1, opcode=1 (text)
	let offset = 1;
	if (len < 126) {
		frame[offset++] = 0x80 | len;
	} else if (len < 65536) {
		frame[offset++] = 0x80 | 126;
		frame.writeUInt16BE(len, offset);
		offset += 2;
	} else {
		frame[offset++] = 0x80 | 127;
		frame.writeBigUInt64BE(BigInt(len), offset);
		offset += 8;
	}
	maskKey.copy(frame, offset);
	offset += 4;
	for (let i = 0; i < len; i++) {
		frame[offset + i] = payload[i] ^ maskKey[i % 4];
	}
	return frame;
}

/**
 * Minimal WebSocket text-frame client over a raw Node.js Duplex stream.
 * Handles only text / continuation frames (sufficient for CDP).
 *
 * Correctly reassembles fragmented messages (FIN=0 frames) — required for
 * large CDP responses such as Page.printToPDF on multi-megabyte reports.
 */
class WsClient {
	private buf = Buffer.alloc(0);
	/** Accumulates UTF-8 chunks across fragmented (FIN=0) WebSocket frames. */
	private fragText = "";
	constructor(
		private readonly socket: stream.Duplex,
		private readonly onMessage: (text: string) => void,
	) {
		socket.on("data", (chunk: Buffer) => {
			this.buf = Buffer.concat([this.buf, chunk]);
			this.drain();
		});
	}
	send(text: string): void {
		this.socket.write(wsMakeFrame(text));
	}
	private drain(): void {
		while (this.buf.length >= 2) {
			const firstByte = this.buf[0];
			const fin = (firstByte & 0x80) !== 0;
			const opcode = firstByte & 0x0f;
			const masked = (this.buf[1] & 0x80) !== 0;
			let payloadLen = this.buf[1] & 0x7f;
			let offset = 2;
			if (payloadLen === 126) {
				if (this.buf.length < 4) {
					return;
				}
				payloadLen = this.buf.readUInt16BE(2);
				offset = 4;
			} else if (payloadLen === 127) {
				if (this.buf.length < 10) {
					return;
				}
				payloadLen = Number(this.buf.readBigUInt64BE(2));
				offset = 10;
			}
			if (masked) {
				offset += 4;
			} // server→client frames are unmasked; skip just in case
			if (this.buf.length < offset + payloadLen) {
				return;
			}
			const payload = this.buf.subarray(offset, offset + payloadLen);
			this.buf = this.buf.subarray(offset + payloadLen);
			if (opcode === 0x1) {
				// Start of a text message (may be the only frame if FIN=1)
				this.fragText = payload.toString("utf8");
				if (fin) {
					const msg = this.fragText;
					this.fragText = "";
					this.onMessage(msg);
				}
			} else if (opcode === 0x0) {
				// Continuation frame — append to in-progress message
				this.fragText += payload.toString("utf8");
				if (fin) {
					const msg = this.fragText;
					this.fragText = "";
					this.onMessage(msg);
				}
			}
			// opcode 0x8 (close) / 0x9 (ping) / 0xA (pong) — ignored
		}
	}
}

/**
 * Connects to a Chrome DevTools WebSocket target, navigates to `fileUrl`,
 * waits for the page load event, then issues `Page.printToPDF`.
 * Returns the PDF content as a base-64 string.
 */
function cdpPrintToPdf(
	wsUrl: string,
	fileUrl: string,
	timeoutMs: number,
): Promise<string> {
	return new Promise((resolve, reject) => {
		const target = new URL(wsUrl);
		const wsKey = crypto.randomBytes(16).toString("base64");
		const req = http.request({
			hostname: target.hostname,
			port: parseInt(target.port, 10) || 80,
			path: target.pathname,
			headers: {
				Host: `${target.hostname}:${target.port}`,
				Connection: "Upgrade",
				Upgrade: "websocket",
				"Sec-WebSocket-Key": wsKey,
				"Sec-WebSocket-Version": "13",
			},
		});
		// Capture the upgraded socket so the timeout can close it directly.
		let activeSocket: stream.Duplex | undefined;
		let pollInterval: ReturnType<typeof setInterval> | undefined;

		const cleanup = () => {
			if (pollInterval) {
				clearInterval(pollInterval);
				pollInterval = undefined;
			}
			activeSocket?.destroy();
		};

		const timer = setTimeout(() => {
			cleanup();
			reject(new Error("CDP Page.printToPDF timed out"));
		}, timeoutMs);
		req.on(
			"upgrade",
			(_res: http.IncomingMessage, socket: stream.Duplex) => {
				activeSocket = socket;
				let printing = false;
				const triggerPrint = () => {
					if (printing) {
						return;
					}
					printing = true;
					// Stop polling — page is ready.
					if (pollInterval) {
						clearInterval(pollInterval);
						pollInterval = undefined;
					}
					ws.send(
						JSON.stringify({
							id: 3,
							method: "Page.printToPDF",
							params: {
								printBackground: false,
								transferMode: "ReturnAsBase64",
							},
						}),
					);
				};
				const sendReadyStateCheck = () => {
					ws.send(
						JSON.stringify({
							id: 10,
							method: "Runtime.evaluate",
							params: { expression: "document.readyState" },
						}),
					);
				};
				const ws = new WsClient(socket, (msg) => {
					let data: {
						id?: number;
						method?: string;
						result?: {
							data?: string;
							result?: { value?: string };
						};
						error?: { message: string };
					};
					try {
						data = JSON.parse(msg);
					} catch {
						return;
					}
					// Page.loadEventFired — page is ready to print
					if (data.method === "Page.loadEventFired") {
						triggerPrint();
					}
					// Page.navigate response — do an immediate readyState check
					// and start a polling interval as belt-and-suspenders fallback.
					// file:// URLs in headless=new sometimes load before
					// Page.loadEventFired is dispatched, so polling covers that gap.
					if (data.id === 2) {
						sendReadyStateCheck();
						if (!pollInterval) {
							pollInterval = setInterval(() => {
								if (printing) {
									clearInterval(pollInterval);
									pollInterval = undefined;
									return;
								}
								sendReadyStateCheck();
							}, 500);
						}
					}
					// Runtime.evaluate response — print if readyState is complete
					if (data.id === 10) {
						if (data.result?.result?.value === "complete") {
							triggerPrint();
						}
					}
					// Page.printToPDF response
					if (data.id === 3) {
						clearTimeout(timer);
						cleanup();
						if (data.result?.data) {
							resolve(data.result.data);
						} else if (data.error) {
							reject(
								new Error(
									`CDP Page.printToPDF error: ${data.error.message}`,
								),
							);
						} else {
							reject(
								new Error("Page.printToPDF returned no data"),
							);
						}
					}
				});
				socket.on("error", (err: Error) => {
					clearTimeout(timer);
					cleanup();
					reject(err);
				});
				// Enable the Page domain then navigate to the report
				ws.send(JSON.stringify({ id: 1, method: "Page.enable" }));
				ws.send(
					JSON.stringify({
						id: 2,
						method: "Page.navigate",
						params: { url: fileUrl },
					}),
				);
			},
		);
		req.on("error", (err: Error) => {
			clearTimeout(timer);
			reject(err);
		});
		req.end();
	});
}

// ---------------------------------------------------------------------------
// PDF-specific minimal HTML builder
// ---------------------------------------------------------------------------

interface PdfFinding {
	rule: {
		id: string;
		title: string;
		description: string;
		severity: string;
		category: string;
		fixDescription?: string;
		reference?: string;
	};
	line: number;
	matchedText: string;
	filePath: string;
	justification?: string;
}

interface PdfReport {
	scannedCount: number;
	skippedCount: number;
	findings: PdfFinding[];
}

function pdfEsc(s: string): string {
	return s
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;");
}

function pdfTruncate(text: string): string {
	const lines = text.split("\n");
	const first5 = lines.slice(0, 5).join("\n");
	const withEllipsis = lines.length > 5 ? first5 + "\n\u2026" : first5;
	return withEllipsis.length > 400
		? withEllipsis.slice(0, 400) + "\u2026"
		: withEllipsis;
}

/**
 * Builds a minimal, JavaScript-free, print-optimised HTML document.
 * Each finding appears exactly once (by severity). No tabs, no search,
 * no interactive elements — renders an order of magnitude faster than
 * the full interactive report in headless Chrome.
 */
function buildPdfHtml(
	findings: PdfFinding[],
	scannedCount: number,
	skippedCount: number,
	workspaceRoot: string,
): string {
	const active = findings.filter((f) => !f.justification);
	const mitigated = findings.filter((f) => !!f.justification);
	const critical = active.filter((f) => f.rule.severity === "critical");
	const warning = active.filter((f) => f.rule.severity === "warning");
	const info = active.filter((f) => f.rule.severity === "info");
	const fileCount = new Set(active.map((f) => f.filePath)).size;
	const dateStr = new Date().toLocaleString();

	const relPath = (fp: string): string => {
		const norm = fp.replace(/\\/g, "/");
		const rootNorm = workspaceRoot.replace(/\\/g, "/").replace(/\/?$/, "/");
		if (rootNorm !== "/" && norm.startsWith(rootNorm)) {
			return norm.slice(rootNorm.length);
		}
		return norm.split("/").slice(-3).join("/");
	};

	const SEV: Record<string, { bg: string; color: string; border: string }> = {
		critical: { bg: "#fde8e8", color: "#c0392b", border: "#e74c3c" },
		warning: { bg: "#fef3e2", color: "#d35400", border: "#e67e22" },
		info: { bg: "#e8f4fd", color: "#2471a3", border: "#3498db" },
		mitigated: { bg: "#d5f5e3", color: "#1e8449", border: "#27ae60" },
	};

	const card = (f: PdfFinding): string => {
		const key = f.justification ? "mitigated" : f.rule.severity;
		const st = SEV[key] ?? SEV["info"];
		const label = f.justification
			? "MITIGATED"
			: f.rule.severity.toUpperCase();
		const ref = f.rule.reference
			? ` &mdash; <a href="${pdfEsc(f.rule.reference)}">${pdfEsc(f.rule.reference)}</a>`
			: "";
		const fix = f.rule.fixDescription
			? `<div class="fix"><strong>Fix:</strong> ${pdfEsc(f.rule.fixDescription)}</div>`
			: "";
		const just = f.justification
			? `<div class="fix"><strong>Justification:</strong> ${pdfEsc(f.justification)}</div>`
			: "";
		return (
			`<div class="card" style="border-left:4px solid ${st.border}">` +
			`<div class="chdr">` +
			`<span class="badge" style="background:${st.bg};color:${st.color}">${label}</span> ` +
			`<span class="rid">${pdfEsc(f.rule.id)}</span> ` +
			`<span class="loc">${pdfEsc(relPath(f.filePath))} &mdash; Line ${f.line + 1}${ref}</span>` +
			`</div>` +
			`<div class="title">${pdfEsc(f.rule.title)}</div>` +
			(f.justification
				? ""
				: `<div class="desc">${pdfEsc(f.rule.description)}</div>`) +
			`<code class="matched">${pdfEsc(pdfTruncate(f.matchedText))}</code>` +
			fix +
			just +
			`<div class="cat">Category: ${pdfEsc(f.rule.category)}</div>` +
			`</div>`
		);
	};

	const section = (heading: string, items: PdfFinding[]): string => {
		if (items.length === 0) {
			return "";
		}
		return (
			`<h2>${pdfEsc(heading)} <span class="cnt">(${items.length})</span></h2>\n` +
			items.map(card).join("\n")
		);
	};

	const body =
		active.length === 0
			? `<div class="no-issues">&#10003; No active security issues detected.</div>`
			: section("Critical Issues", critical) +
				section("Warnings", warning) +
				section("Informational", info);

	const mitSection =
		mitigated.length > 0
			? `<div class="mit">${section("Mitigated", mitigated)}</div>`
			: "";

	return (
		`<!DOCTYPE html><html lang="en"><head>\n` +
		`<meta charset="UTF-8"><title>OWASP Security Report</title>\n` +
		`<style>\n` +
		`*,*::before,*::after{box-sizing:border-box}\n` +
		`body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:13px;color:#1e1e1e;background:#fff;padding:20px;margin:0}\n` +
		`h1{font-size:1.3em;border-bottom:2px solid #ddd;padding-bottom:6px;margin-bottom:4px}\n` +
		`h2{font-size:1em;margin-top:20px;margin-bottom:6px;page-break-after:avoid}\n` +
		`.meta{font-size:0.8em;color:#666;margin-bottom:12px}\n` +
		`.summary{display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap}\n` +
		`.chip{padding:3px 10px;border-radius:10px;font-size:0.82em;font-weight:600}\n` +
		`.cc{background:#fde8e8;color:#c0392b}.cw{background:#fef3e2;color:#d35400}\n` +
		`.ci{background:#e8f4fd;color:#2471a3}.cf{background:#eee;color:#333}.cm{background:#d5f5e3;color:#1e8449}\n` +
		`.cnt{color:#888;font-weight:normal}\n` +
		`.card{border:1px solid #e0e0e0;border-radius:5px;padding:8px 12px;margin-bottom:8px;background:#fafafa;page-break-inside:avoid}\n` +
		`.chdr{display:flex;align-items:baseline;gap:8px;flex-wrap:wrap;margin-bottom:4px;font-size:0.82em}\n` +
		`.badge{padding:1px 7px;border-radius:4px;font-size:0.78em;font-weight:700;flex-shrink:0}\n` +
		`.rid{font-family:monospace;font-weight:700}.loc{color:#555;font-family:monospace;font-size:0.85em}\n` +
		`.title{font-weight:600;margin-bottom:3px}\n` +
		`.desc{font-size:0.88em;color:#555;margin-bottom:4px}\n` +
		`.matched{display:block;background:#f0f0f0;padding:4px 8px;border-radius:3px;font-size:0.8em;white-space:pre-wrap;word-break:break-all;margin-bottom:4px;font-family:'Courier New',monospace}\n` +
		`.fix{font-size:0.85em;background:#eafaf1;border-left:3px solid #27ae60;padding:3px 8px;border-radius:2px;margin-bottom:3px}\n` +
		`.cat{font-size:0.75em;color:#888}\n` +
		`.no-issues{padding:16px;text-align:center;color:#27ae60;font-size:1.1em}\n` +
		`.mit{margin-top:20px;padding-top:10px;border-top:2px dashed #27ae60}\n` +
		`a{color:#2471a3}\n` +
		`</style></head>\n<body>\n` +
		`<h1>OWASP Security Report</h1>\n` +
		`<div class="meta">Generated: ${pdfEsc(dateStr)}&nbsp;|&nbsp;Scanned: <strong>${scannedCount}</strong> file(s)` +
		(skippedCount > 0
			? `&nbsp;|&nbsp;<span style="color:#d35400">${skippedCount} skipped</span>`
			: "") +
		`</div>\n` +
		`<div class="summary">` +
		`<span class="chip cc">&#128308; Critical: ${critical.length}</span>` +
		`<span class="chip cw">&#128993; Warnings: ${warning.length}</span>` +
		`<span class="chip ci">&#128309; Info: ${info.length}</span>` +
		`<span class="chip cf">&#128193; Files: ${fileCount}</span>` +
		(mitigated.length > 0
			? `<span class="chip cm">&#10003; Mitigated: ${mitigated.length}</span>`
			: "") +
		`</div>\n` +
		body +
		mitSection +
		`\n</body></html>`
	);
}

// ---------------------------------------------------------------------------
// Local HTTP server
// ---------------------------------------------------------------------------

/**
 * Serves an in-memory HTML buffer over a loopback HTTP server.
 * Returns the URL and a shutdown function.
 */
function serveContentLocally(
	content: Buffer,
): Promise<{ url: string; stop: () => void }> {
	return new Promise((resolve, reject) => {
		const server = http.createServer((_req, res) => {
			res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
			res.end(content);
		});
		server.listen(0, "127.0.0.1", () => {
			const port = (server.address() as net.AddressInfo).port;
			resolve({
				url: `http://127.0.0.1:${port}/report.html`,
				stop: () => server.close(),
			});
		});
		server.on("error", reject);
	});
}

/**
 * Converts a saved HTML security report to a PDF file placed alongside it.
 *
 * Reads the companion `.json` file (written by the workspace scan alongside
 * the `.html`) and generates a minimal, JavaScript-free HTML document for
 * Chrome to print. This is an order of magnitude smaller than the full
 * interactive report HTML, dramatically reducing render time.
 *
 * Falls back to serving the original `.html` if no companion JSON exists.
 *
 * @param htmlPath Absolute path to the `.html` report file.
 * @returns Absolute path of the generated `.pdf` file.
 * @throws `Error('NO_BROWSER')` when no supported browser is found.
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

	// Build a minimal PDF-specific HTML from the companion JSON when available.
	// The companion JSON contains raw finding data without any UI chrome,
	// letting us produce a document that is many times smaller than the
	// interactive report (no duplicate tabs, no JavaScript, no filter widgets).
	let htmlContent: Buffer;
	const jsonPath = htmlPath.replace(/\.html$/i, ".json");
	if (fs.existsSync(jsonPath)) {
		try {
			const saved: PdfReport = JSON.parse(
				fs.readFileSync(jsonPath, "utf8"),
			);
			// Derive workspace root from the report directory structure:
			// htmlPath is {workspaceRoot}/.securityReport/YYYY-MM-DD_HH-MM-SS.html
			const workspaceRoot = path.dirname(path.dirname(htmlPath));
			const minimalHtml = buildPdfHtml(
				saved.findings,
				saved.scannedCount,
				saved.skippedCount,
				workspaceRoot,
			);
			htmlContent = Buffer.from(minimalHtml, "utf8");
		} catch {
			// JSON unreadable — fall back to the original HTML
			htmlContent = fs.readFileSync(htmlPath);
		}
	} else {
		htmlContent = fs.readFileSync(htmlPath);
	}

	const { url: reportUrl, stop: stopServer } =
		await serveContentLocally(htmlContent);

	const userDataDir = path.join(
		os.tmpdir(),
		`owasp-pdf-${crypto.randomBytes(8).toString("hex")}`,
	);
	const debugPort = await getFreePort();
	const child = spawn(
		browser,
		[
			"--headless=new",
			"--disable-gpu",
			"--no-sandbox",
			"--disable-extensions",
			"--disable-background-networking",
			...(process.platform === "linux"
				? ["--disable-dev-shm-usage"]
				: []),
			`--user-data-dir=${userDataDir}`,
			`--remote-debugging-port=${debugPort}`,
			"about:blank",
		],
		{ stdio: "ignore", detached: false },
	);
	try {
		const wsUrl = await waitForDebugTarget(debugPort, 10_000);
		const pdfBase64 = await cdpPrintToPdf(wsUrl, reportUrl, 120_000);
		fs.writeFileSync(pdfPath, Buffer.from(pdfBase64, "base64"));
		return pdfPath;
	} finally {
		stopServer();
		child.kill();
		try {
			fs.rmSync(userDataDir, { recursive: true, force: true });
		} catch {
			// non-fatal
		}
	}
}
