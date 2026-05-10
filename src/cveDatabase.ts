/**
 * CVE Database Manager
 *
 * Downloads and indexes the CVEProject/cvelistV5 baseline release from GitHub
 * into a local SQLite database (via sql.js — pure JS, no native binaries).
 * Supports baseline download, delta updates, and product/vendor searches.
 *
 * Data is stored in VS Code's globalStorageUri so it persists across workspaces
 * and survives extension updates.
 */

import * as fs from "fs";
import * as https from "https";
import * as path from "path";
import * as zlib from "zlib";
import * as vscode from "vscode";

// sql.js is a pure-JS SQLite compiled from WASM — no native binaries required.
import type SqlJsTypes from "sql.js";
// eslint-disable-next-line @typescript-eslint/no-require-imports
const initSqlJs = require("sql.js") as (cfg?: {
	locateFile?: (file: string) => string;
}) => Promise<SqlJsTypes.SqlJsStatic>;

const GITHUB_RELEASES_API =
	"https://api.github.com/repos/CVEProject/cvelistV5/releases";

const DB_FILENAME = "cve.db";

// ── Progress event types ───────────────────────────────────────────────────────

export type CveProgressEvent =
	| { event: "status"; message: string }
	| { event: "download_start"; filename: string; totalMb: number }
	| {
			event: "download_progress";
			percent: number;
			speedMbps: number;
			etaSeconds: number;
	  }
	| { event: "download_complete" }
	| { event: "index_start"; totalFiles?: number; message: string }
	| {
			event: "index_progress";
			filesProcessed: number;
			totalFiles: number;
			percent: number;
			lastCveId: string;
	  }
	| { event: "delta_start"; totalDeltas: number }
	| {
			event: "delta_progress";
			current: number;
			total: number;
			newCves: number;
			updatedCves: number;
	  }
	| {
			event: "complete";
			totalCves?: number;
			newCves?: number;
			updatedCves?: number;
			message?: string;
	  }
	| { event: "error"; message: string };

export interface CveDbStatus {
	downloaded: boolean;
	cveCount: number;
	baselineDate: string | null;
	lastUpdated: string | null;
	releaseTag: string | null;
	dbSizeMb: number;
}

export interface CveRecord {
	cveId: string;
	state: string;
	datePublished: string;
	dateUpdated: string;
	description: string;
	vendor: string;
	product: string;
}

// ── Internal helpers ──────────────────────────────────────────────────────────

let _dbPath: string | null = null;

function getDbPath(context: vscode.ExtensionContext): string {
	if (!_dbPath) {
		const storageDir = context.globalStorageUri.fsPath;
		fs.mkdirSync(storageDir, { recursive: true });
		_dbPath = path.join(storageDir, DB_FILENAME);
	}
	return _dbPath;
}

/** Fetch a URL and return its body as a Buffer. Follows one redirect. */
function fetchBuffer(
	url: string,
	onProgress?: (downloaded: number, total: number) => void,
): Promise<Buffer> {
	return new Promise((resolve, reject) => {
		const parsed = new URL(url);
		if (parsed.protocol !== "https:") {
			reject(new Error("Only HTTPS requests are permitted"));
			return;
		}
		const options: https.RequestOptions = {
			hostname: parsed.hostname,
			path: parsed.pathname + parsed.search,
			headers: {
				"User-Agent": "owasp-security-helper-vscode/1.0",
				Accept: "*/*",
			},
			timeout: 30000,
		};
		const req = https.get(options, (res) => {
			// Follow single redirect (GitHub release assets redirect to S3)
			if (
				res.statusCode &&
				res.statusCode >= 300 &&
				res.statusCode < 400 &&
				res.headers.location
			) {
				res.resume();
				const loc = res.headers.location;
				if (!loc.startsWith("https://")) {
					reject(new Error("Redirect to non-HTTPS URL blocked"));
					return;
				}
				resolve(fetchBuffer(loc, onProgress));
				return;
			}
			if (res.statusCode !== 200) {
				reject(
					new Error(`HTTP ${res.statusCode} from ${parsed.hostname}`),
				);
				return;
			}
			const total = parseInt(res.headers["content-length"] ?? "0", 10);
			const chunks: Buffer[] = [];
			let downloaded = 0;
			res.on("data", (chunk: Buffer) => {
				chunks.push(chunk);
				downloaded += chunk.length;
				if (onProgress) {
					onProgress(downloaded, total);
				}
			});
			res.on("end", () => resolve(Buffer.concat(chunks)));
			res.on("error", reject);
		});
		req.on("error", reject);
		req.on("timeout", () => {
			req.destroy();
			reject(new Error("Request timed out"));
		});
	});
}

/** Fetch a URL as a JSON object. */
async function fetchJson<T>(url: string): Promise<T> {
	const parsed = new URL(url);
	if (parsed.protocol !== "https:") {
		throw new Error("Only HTTPS requests are permitted");
	}
	const buf = await new Promise<Buffer>((resolve, reject) => {
		const options: https.RequestOptions = {
			hostname: parsed.hostname,
			path: parsed.pathname + parsed.search,
			headers: {
				"User-Agent": "owasp-security-helper-vscode/1.0",
				Accept: "application/json",
			},
			timeout: 15000,
		};
		const req = https.get(options, (res) => {
			if (res.statusCode !== 200) {
				reject(new Error(`HTTP ${res.statusCode}`));
				return;
			}
			const chunks: Buffer[] = [];
			res.on("data", (c: Buffer) => chunks.push(c));
			res.on("end", () => resolve(Buffer.concat(chunks)));
			res.on("error", reject);
		});
		req.on("error", reject);
		req.on("timeout", () => {
			req.destroy();
			reject(new Error("Request timed out"));
		});
	});
	return JSON.parse(buf.toString("utf8")) as T;
}

/** Stream-download a URL to a local file, reporting progress. */
function downloadToFile(
	url: string,
	destPath: string,
	onProgress: (downloaded: number, total: number, speedBps: number) => void,
): Promise<void> {
	return new Promise((resolve, reject) => {
		const parsed = new URL(url);
		if (parsed.protocol !== "https:") {
			reject(new Error("Only HTTPS requests are permitted"));
			return;
		}
		const options: https.RequestOptions = {
			hostname: parsed.hostname,
			path: parsed.pathname + parsed.search,
			headers: {
				"User-Agent": "owasp-security-helper-vscode/1.0",
			},
			timeout: 0, // no socket timeout for large downloads
		};
		const req = https.get(options, (res) => {
			// Follow redirect
			if (
				res.statusCode &&
				res.statusCode >= 300 &&
				res.statusCode < 400 &&
				res.headers.location
			) {
				res.resume();
				const loc = res.headers.location;
				if (!loc.startsWith("https://")) {
					reject(new Error("Redirect to non-HTTPS URL blocked"));
					return;
				}
				resolve(downloadToFile(loc, destPath, onProgress));
				return;
			}
			if (res.statusCode !== 200) {
				reject(new Error(`HTTP ${res.statusCode}`));
				return;
			}
			const total = parseInt(res.headers["content-length"] ?? "0", 10);
			const file = fs.createWriteStream(destPath);
			let downloaded = 0;
			let lastReport = Date.now();
			let lastBytes = 0;
			const startTime = Date.now();
			res.on("data", (chunk: Buffer) => {
				file.write(chunk);
				downloaded += chunk.length;
				const now = Date.now();
				if (now - lastReport >= 500) {
					const interval = (now - lastReport) / 1000;
					const speedBps =
						interval > 0 ? (downloaded - lastBytes) / interval : 0;
					onProgress(downloaded, total, speedBps);
					lastReport = now;
					lastBytes = downloaded;
				}
				void startTime; // suppress unused warning
			});
			res.on("end", () => {
				file.end();
				resolve();
			});
			res.on("error", (err) => {
				file.destroy();
				reject(err);
			});
			file.on("error", reject);
		});
		req.on("error", reject);
	});
}

// ── Zip extraction (pure Node.js) ─────────────────────────────────────────────

interface ZipEntry {
	name: string;
	compressedSize: number;
	uncompressedSize: number;
	offset: number;
	compressionMethod: number;
}

/** Minimal ZIP central-directory parser (no external deps). */
function parseZipCentralDirectory(buf: Buffer): ZipEntry[] {
	const entries: ZipEntry[] = [];
	// Find end-of-central-directory record (scan backwards for signature 0x06054b50)
	let eocdOffset = -1;
	for (let i = buf.length - 22; i >= 0; i--) {
		if (
			buf[i] === 0x50 &&
			buf[i + 1] === 0x4b &&
			buf[i + 2] === 0x05 &&
			buf[i + 3] === 0x06
		) {
			eocdOffset = i;
			break;
		}
	}
	if (eocdOffset < 0) {
		throw new Error("Not a valid ZIP file (no EOCD record found)");
	}
	const cdOffset = buf.readUInt32LE(eocdOffset + 16);
	const cdSize = buf.readUInt32LE(eocdOffset + 12);
	let pos = cdOffset;
	while (pos < cdOffset + cdSize) {
		if (buf.readUInt32LE(pos) !== 0x02014b50) {
			break; // not a central directory header
		}
		const compressionMethod = buf.readUInt16LE(pos + 10);
		const compressedSize = buf.readUInt32LE(pos + 20);
		const uncompressedSize = buf.readUInt32LE(pos + 24);
		const fileNameLen = buf.readUInt16LE(pos + 28);
		const extraLen = buf.readUInt16LE(pos + 30);
		const commentLen = buf.readUInt16LE(pos + 32);
		const localOffset = buf.readUInt32LE(pos + 42);
		const name = buf
			.subarray(pos + 46, pos + 46 + fileNameLen)
			.toString("utf8");
		entries.push({
			name,
			compressedSize,
			uncompressedSize,
			offset: localOffset,
			compressionMethod,
		});
		pos += 46 + fileNameLen + extraLen + commentLen;
	}
	return entries;
}

/** Read compressed content of one zip entry from the archive buffer. */
function extractZipEntry(buf: Buffer, entry: ZipEntry): Buffer {
	// Local file header: signature(4) + fixed fields(26) + filename + extra
	const localPos = entry.offset;
	if (buf.readUInt32LE(localPos) !== 0x04034b50) {
		throw new Error(`Bad local header for ${entry.name}`);
	}
	const localFileNameLen = buf.readUInt16LE(localPos + 26);
	const localExtraLen = buf.readUInt16LE(localPos + 28);
	const dataOffset = localPos + 30 + localFileNameLen + localExtraLen;
	const compressed = buf.subarray(
		dataOffset,
		dataOffset + entry.compressedSize,
	);
	if (entry.compressionMethod === 0) {
		return compressed;
	}
	if (entry.compressionMethod === 8) {
		return zlib.inflateRawSync(compressed);
	}
	throw new Error(
		`Unsupported compression method ${entry.compressionMethod} for ${entry.name}`,
	);
}

// ── SQL helpers ───────────────────────────────────────────────────────────────

const INIT_SQL = `
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS metadata (
  key TEXT PRIMARY KEY,
  value TEXT
);
CREATE TABLE IF NOT EXISTS cve_records (
  cve_id TEXT PRIMARY KEY,
  state TEXT,
  date_published TEXT,
  date_updated TEXT,
  description TEXT
);
CREATE TABLE IF NOT EXISTS cve_affected (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT,
  vendor TEXT,
  product TEXT,
  FOREIGN KEY (cve_id) REFERENCES cve_records(cve_id)
);
CREATE INDEX IF NOT EXISTS idx_affected_vendor  ON cve_affected(vendor COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_affected_product ON cve_affected(product COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_affected_cve_id  ON cve_affected(cve_id);
`;

interface CveRawRecord {
	cveId: string;
	state: string;
	datePub: string;
	dateUpd: string;
	desc: string;
	affected: Array<{ vendor: string; product: string }>;
}

function parseCveJson(data: Record<string, unknown>): CveRawRecord {
	const meta = (data["cveMetadata"] ?? {}) as Record<string, unknown>;
	const cveId = String(meta["cveId"] ?? "");
	const state = String(meta["state"] ?? "");
	const datePub = String(meta["datePublished"] ?? "");
	const dateUpd = String(meta["dateUpdated"] ?? "");

	const cna = ((data["containers"] as Record<string, unknown>)?.["cna"] ??
		{}) as Record<string, unknown>;

	let desc = "";
	const descriptions = (cna["descriptions"] ?? []) as Array<
		Record<string, string>
	>;
	for (const d of descriptions) {
		if (d["lang"]?.startsWith("en")) {
			desc = d["value"] ?? "";
			break;
		}
	}
	if (!desc && descriptions.length > 0) {
		desc = descriptions[0]["value"] ?? "";
	}
	desc = desc.slice(0, 2000);

	const affected: Array<{ vendor: string; product: string }> = [];
	for (const a of (cna["affected"] ?? []) as Array<Record<string, string>>) {
		const vendor = a["vendor"] ?? "";
		const product = a["product"] ?? "";
		if (vendor || product) {
			affected.push({ vendor, product });
		}
	}
	return { cveId, state, datePub, dateUpd, desc, affected };
}

// ── Public API ────────────────────────────────────────────────────────────────

/** Return status/metadata about the local CVE database. */
export function getStatus(context: vscode.ExtensionContext): CveDbStatus {
	const dbPath = getDbPath(context);
	if (!fs.existsSync(dbPath)) {
		return {
			downloaded: false,
			cveCount: 0,
			baselineDate: null,
			lastUpdated: null,
			releaseTag: null,
			dbSizeMb: 0,
		};
	}
	// Read metadata without initialising sql.js (synchronous raw read)
	try {
		// We must actually open the DB to read metadata; do it synchronously via a temp SQL.js instance.
		// However, sql.js is async-init. Instead store a companion JSON sidecar file for fast status reads.
		const sidecarPath = dbPath + ".meta.json";
		if (fs.existsSync(sidecarPath)) {
			const meta = JSON.parse(fs.readFileSync(sidecarPath, "utf8")) as {
				cveCount: number;
				baselineDate: string;
				lastUpdated: string;
				releaseTag: string;
			};
			const dbSizeMb =
				Math.round((fs.statSync(dbPath).size / 1024 / 1024) * 10) / 10;
			return {
				downloaded: meta.cveCount > 0,
				cveCount: meta.cveCount,
				baselineDate: meta.baselineDate ?? null,
				lastUpdated: meta.lastUpdated ?? null,
				releaseTag: meta.releaseTag ?? null,
				dbSizeMb,
			};
		}
		const dbSizeMb =
			Math.round((fs.statSync(dbPath).size / 1024 / 1024) * 10) / 10;
		return {
			downloaded: true,
			cveCount: -1,
			baselineDate: null,
			lastUpdated: null,
			releaseTag: null,
			dbSizeMb,
		};
	} catch {
		return {
			downloaded: false,
			cveCount: 0,
			baselineDate: null,
			lastUpdated: null,
			releaseTag: null,
			dbSizeMb: 0,
		};
	}
}

/** Write updated sidecar metadata. */
function writeSidecar(
	dbPath: string,
	meta: {
		cveCount: number;
		baselineDate: string;
		lastUpdated: string;
		releaseTag: string;
	},
): void {
	fs.writeFileSync(dbPath + ".meta.json", JSON.stringify(meta), "utf8");
}

/**
 * Download or re-download the full CVE baseline from GitHub.
 * Calls `onProgress` with structured events during the operation.
 */
export async function downloadBaseline(
	context: vscode.ExtensionContext,
	onProgress: (evt: CveProgressEvent) => void,
	token?: vscode.CancellationToken,
): Promise<void> {
	const dbPath = getDbPath(context);

	onProgress({
		event: "status",
		message: "Fetching latest release info from GitHub…",
	});

	// 1. Get latest release metadata
	let release: Record<string, unknown>;
	try {
		release = await fetchJson<Record<string, unknown>>(
			`${GITHUB_RELEASES_API}/latest`,
		);
	} catch (err) {
		onProgress({
			event: "error",
			message: `GitHub API error: ${String(err)}`,
		});
		return;
	}

	if (token?.isCancellationRequested) {
		return;
	}

	// 2. Find the baseline asset (_all_CVEs_at_midnight)
	const assets = (release["assets"] ?? []) as Array<Record<string, unknown>>;
	const baselineAsset = assets.find((a) =>
		String(a["name"] ?? "").includes("_all_CVEs_at_midnight"),
	);
	if (!baselineAsset) {
		onProgress({
			event: "error",
			message: "Baseline ZIP not found in latest GitHub release.",
		});
		return;
	}

	const totalBytes = Number(baselineAsset["size"] ?? 0);
	const downloadUrl = String(baselineAsset["browser_download_url"] ?? "");
	const filename = String(baselineAsset["name"] ?? "cve_baseline.zip");
	const releaseTag = String(release["tag_name"] ?? "");

	onProgress({
		event: "download_start",
		filename,
		totalMb: Math.round((totalBytes / 1024 / 1024) * 10) / 10,
	});

	// 3. Stream download to a temp file
	const tmpZip = path.join(
		context.globalStorageUri.fsPath,
		"cve_baseline_tmp.zip",
	);
	const startTime = Date.now();
	try {
		await downloadToFile(
			downloadUrl,
			tmpZip,
			(downloaded, total, speedBps) => {
				if (token?.isCancellationRequested) {
					return;
				}
				const elapsed = (Date.now() - startTime) / 1000;
				const etaSeconds =
					speedBps > 0
						? Math.round((total - downloaded) / speedBps)
						: 0;
				void elapsed;
				onProgress({
					event: "download_progress",
					percent:
						total > 0 ? Math.round((downloaded / total) * 100) : 0,
					speedMbps: Math.round((speedBps / 1024 / 1024) * 100) / 100,
					etaSeconds,
				});
			},
		);
	} catch (err) {
		onProgress({
			event: "error",
			message: `Download failed: ${String(err)}`,
		});
		try {
			fs.unlinkSync(tmpZip);
		} catch {
			/* ignore */
		}
		return;
	}

	if (token?.isCancellationRequested) {
		try {
			fs.unlinkSync(tmpZip);
		} catch {
			/* ignore */
		}
		return;
	}

	onProgress({ event: "download_complete" });

	// 4. Parse the zip and index into SQLite
	onProgress({ event: "index_start", message: "Reading ZIP archive…" });

	let zipBuf: Buffer;
	try {
		zipBuf = fs.readFileSync(tmpZip);
	} catch (err) {
		onProgress({
			event: "error",
			message: `Failed to read downloaded file: ${String(err)}`,
		});
		return;
	}

	// Handle double-zip (outer zip contains an inner zip)
	let entries: ZipEntry[];
	try {
		entries = parseZipCentralDirectory(zipBuf);
	} catch (err) {
		onProgress({
			event: "error",
			message: `ZIP parse error: ${String(err)}`,
		});
		try {
			fs.unlinkSync(tmpZip);
		} catch {
			/* ignore */
		}
		return;
	}

	const innerZipEntry = entries.find((e) => e.name.endsWith(".zip"));
	if (innerZipEntry) {
		onProgress({
			event: "index_start",
			message: "Extracting inner archive…",
		});
		try {
			const innerBuf = extractZipEntry(zipBuf, innerZipEntry);
			zipBuf = innerBuf;
			entries = parseZipCentralDirectory(zipBuf);
		} catch (err) {
			onProgress({
				event: "error",
				message: `Inner ZIP extraction failed: ${String(err)}`,
			});
			try {
				fs.unlinkSync(tmpZip);
			} catch {
				/* ignore */
			}
			return;
		}
	}

	const jsonEntries = entries.filter((e) => e.name.endsWith(".json"));
	const totalFiles = jsonEntries.length;
	onProgress({
		event: "index_start",
		totalFiles,
		message: `Indexing ${totalFiles.toLocaleString()} CVE records…`,
	});

	// 5. Initialise sql.js and build the DB
	let SQL: SqlJsTypes.SqlJsStatic;
	try {
		SQL = await initSqlJs({ locateFile: (f) => path.join(__dirname, f) });
	} catch (err) {
		onProgress({
			event: "error",
			message: `Failed to load SQL engine: ${String(err)}`,
		});
		return;
	}

	const db = new SQL.Database();
	db.run(INIT_SQL);
	db.run("DELETE FROM cve_affected; DELETE FROM cve_records;");

	let processed = 0;
	let lastProgressReport = Date.now();
	let lastCveId = "";

	// Batch insert for performance
	db.run("BEGIN TRANSACTION;");
	const stmtRecord = db.prepare(
		"INSERT OR REPLACE INTO cve_records VALUES (?,?,?,?,?)",
	);
	const stmtAffected = db.prepare(
		"INSERT INTO cve_affected (cve_id, vendor, product) VALUES (?,?,?)",
	);

	for (const entry of jsonEntries) {
		if (token?.isCancellationRequested) {
			db.close();
			try {
				fs.unlinkSync(tmpZip);
			} catch {
				/* ignore */
			}
			return;
		}
		try {
			const raw = extractZipEntry(zipBuf, entry);
			const data = JSON.parse(raw.toString("utf8")) as Record<
				string,
				unknown
			>;
			const rec = parseCveJson(data);
			stmtRecord.run([
				rec.cveId,
				rec.state,
				rec.datePub,
				rec.dateUpd,
				rec.desc,
			]);
			for (const a of rec.affected) {
				stmtAffected.run([rec.cveId, a.vendor, a.product]);
			}
			lastCveId = rec.cveId;
		} catch {
			// Skip malformed records
		}

		processed++;
		if (processed % 5000 === 0) {
			db.run("COMMIT; BEGIN TRANSACTION;");
		}
		const now = Date.now();
		if (now - lastProgressReport >= 1000) {
			onProgress({
				event: "index_progress",
				filesProcessed: processed,
				totalFiles,
				percent: Math.round((processed / totalFiles) * 100),
				lastCveId,
			});
			lastProgressReport = now;
		}
	}
	db.run("COMMIT;");
	stmtRecord.free();
	stmtAffected.free();

	// 6. Persist DB to disk
	const baselineDate = filename.split("_")[0] ?? "";
	const lastUpdated = new Date().toISOString();
	db.run("INSERT OR REPLACE INTO metadata VALUES ('baseline_date', ?)", [
		baselineDate,
	]);
	db.run("INSERT OR REPLACE INTO metadata VALUES ('last_updated', ?)", [
		lastUpdated,
	]);
	db.run("INSERT OR REPLACE INTO metadata VALUES ('release_tag', ?)", [
		releaseTag,
	]);

	const cveCountResult = db.exec("SELECT COUNT(*) FROM cve_records");
	const cveCount = (cveCountResult[0]?.values?.[0]?.[0] as number) ?? 0;

	const dbData = db.export();
	db.close();
	fs.writeFileSync(dbPath, Buffer.from(dbData));
	writeSidecar(dbPath, { cveCount, baselineDate, lastUpdated, releaseTag });

	try {
		fs.unlinkSync(tmpZip);
	} catch {
		/* ignore */
	}

	onProgress({ event: "complete", totalCves: cveCount });
}

/**
 * Apply delta updates from GitHub releases newer than our stored baseline tag.
 */
export async function updateDeltas(
	context: vscode.ExtensionContext,
	onProgress: (evt: CveProgressEvent) => void,
	token?: vscode.CancellationToken,
): Promise<void> {
	const dbPath = getDbPath(context);
	if (!fs.existsSync(dbPath)) {
		onProgress({
			event: "error",
			message: "No database found. Download the full database first.",
		});
		return;
	}

	const sidecarPath = dbPath + ".meta.json";
	if (!fs.existsSync(sidecarPath)) {
		onProgress({
			event: "error",
			message:
				"No baseline metadata found. Please re-download the full database.",
		});
		return;
	}
	const meta = JSON.parse(fs.readFileSync(sidecarPath, "utf8")) as {
		releaseTag: string;
	};
	const currentTag = meta.releaseTag;
	if (!currentTag) {
		onProgress({
			event: "error",
			message:
				"No release tag in metadata. Please re-download the full database.",
		});
		return;
	}

	onProgress({ event: "status", message: "Checking for updates…" });

	let releases: Array<Record<string, unknown>>;
	try {
		releases = await fetchJson<Array<Record<string, unknown>>>(
			`${GITHUB_RELEASES_API}?per_page=100`,
		);
	} catch (err) {
		onProgress({
			event: "error",
			message: `GitHub API error: ${String(err)}`,
		});
		return;
	}

	// Find delta assets from releases newer than currentTag
	interface DeltaAsset {
		tag: string;
		asset: Record<string, unknown>;
	}
	const deltaAssets: DeltaAsset[] = [];
	let foundCurrent = false;

	for (const release of [...releases].reverse()) {
		const tag = String(release["tag_name"] ?? "");
		if (tag === currentTag) {
			foundCurrent = true;
			continue;
		}
		if (!foundCurrent) {
			continue;
		}
		const assets = (release["assets"] ?? []) as Array<
			Record<string, unknown>
		>;
		for (const asset of assets) {
			if (
				String(asset["name"] ?? "").includes("_delta_") &&
				Number(asset["size"] ?? 0) > 100
			) {
				deltaAssets.push({ tag, asset });
			}
		}
	}

	if (!foundCurrent) {
		onProgress({
			event: "error",
			message:
				"Current release tag not found. Please re-download the full database.",
		});
		return;
	}
	if (deltaAssets.length === 0) {
		onProgress({
			event: "complete",
			message: "Already up to date!",
			newCves: 0,
			updatedCves: 0,
		});
		return;
	}

	onProgress({ event: "delta_start", totalDeltas: deltaAssets.length });

	// Load existing DB
	let SQL: SqlJsTypes.SqlJsStatic;
	try {
		SQL = await initSqlJs({ locateFile: (f) => path.join(__dirname, f) });
	} catch (err) {
		onProgress({
			event: "error",
			message: `Failed to load SQL engine: ${String(err)}`,
		});
		return;
	}
	const db = new SQL.Database(fs.readFileSync(dbPath));

	let totalNew = 0;
	let totalUpdated = 0;
	let lastTag = currentTag;

	for (let i = 0; i < deltaAssets.length; i++) {
		if (token?.isCancellationRequested) {
			break;
		}
		const { tag, asset } = deltaAssets[i];
		const downloadUrl = String(asset["browser_download_url"] ?? "");
		if (!downloadUrl) {
			continue;
		}

		try {
			const buf = await fetchBuffer(downloadUrl);
			const entries = parseZipCentralDirectory(buf);
			const jsonEntries = entries.filter((e) => e.name.endsWith(".json"));

			db.run("BEGIN TRANSACTION;");
			for (const entry of jsonEntries) {
				try {
					const raw = extractZipEntry(buf, entry);
					const data = JSON.parse(raw.toString("utf8")) as Record<
						string,
						unknown
					>;
					const rec = parseCveJson(data);
					const exists = db.exec(
						"SELECT 1 FROM cve_records WHERE cve_id = ?",
						[rec.cveId],
					);
					if (exists[0]?.values?.length) {
						totalUpdated++;
					} else {
						totalNew++;
					}
					db.run(
						"INSERT OR REPLACE INTO cve_records VALUES (?,?,?,?,?)",
						[
							rec.cveId,
							rec.state,
							rec.datePub,
							rec.dateUpd,
							rec.desc,
						],
					);
					db.run("DELETE FROM cve_affected WHERE cve_id = ?", [
						rec.cveId,
					]);
					for (const a of rec.affected) {
						db.run(
							"INSERT INTO cve_affected (cve_id, vendor, product) VALUES (?,?,?)",
							[rec.cveId, a.vendor, a.product],
						);
					}
				} catch {
					/* skip */
				}
			}
			db.run("COMMIT;");
			lastTag = tag;
		} catch {
			/* skip bad delta */
		}

		onProgress({
			event: "delta_progress",
			current: i + 1,
			total: deltaAssets.length,
			newCves: totalNew,
			updatedCves: totalUpdated,
		});
	}

	// Save
	const nowIso = new Date().toISOString();
	db.run("INSERT OR REPLACE INTO metadata VALUES ('release_tag', ?)", [
		lastTag,
	]);
	db.run("INSERT OR REPLACE INTO metadata VALUES ('last_updated', ?)", [
		nowIso,
	]);
	const cveCountResult = db.exec("SELECT COUNT(*) FROM cve_records");
	const cveCount = (cveCountResult[0]?.values?.[0]?.[0] as number) ?? 0;
	const dbData = db.export();
	db.close();
	fs.writeFileSync(dbPath, Buffer.from(dbData));

	const sidecar = JSON.parse(fs.readFileSync(sidecarPath, "utf8")) as {
		cveCount: number;
		baselineDate: string;
		lastUpdated: string;
		releaseTag: string;
	};
	writeSidecar(dbPath, {
		cveCount,
		baselineDate: sidecar.baselineDate,
		lastUpdated: nowIso,
		releaseTag: lastTag,
	});

	onProgress({
		event: "complete",
		totalCves: cveCount,
		newCves: totalNew,
		updatedCves: totalUpdated,
	});
}

/**
 * Search the local CVE database by vendor and/or product name.
 * Returns up to 100 matching published CVEs.
 */
export async function searchByVendorProduct(
	context: vscode.ExtensionContext,
	vendor: string,
	product = "",
): Promise<CveRecord[]> {
	const dbPath = getDbPath(context);
	if (!fs.existsSync(dbPath)) {
		return [];
	}

	let SQL: SqlJsTypes.SqlJsStatic;
	try {
		SQL = await initSqlJs({ locateFile: (f) => path.join(__dirname, f) });
	} catch {
		return [];
	}

	const db = new SQL.Database(fs.readFileSync(dbPath));
	try {
		let results: SqlJsTypes.QueryExecResult[];
		if (product) {
			results = db.exec(
				`SELECT DISTINCT r.cve_id, r.state, r.date_published, r.date_updated,
				        r.description, a.vendor, a.product
				 FROM cve_records r
				 JOIN cve_affected a ON r.cve_id = a.cve_id
				 WHERE a.vendor LIKE ? AND a.product LIKE ?
				 AND r.state = 'PUBLISHED'
				 ORDER BY r.date_published DESC
				 LIMIT 100`,
				[`%${vendor}%`, `%${product}%`],
			);
		} else {
			results = db.exec(
				`SELECT DISTINCT r.cve_id, r.state, r.date_published, r.date_updated,
				        r.description, a.vendor, a.product
				 FROM cve_records r
				 JOIN cve_affected a ON r.cve_id = a.cve_id
				 WHERE a.vendor LIKE ?
				 AND r.state = 'PUBLISHED'
				 ORDER BY r.date_published DESC
				 LIMIT 100`,
				[`%${vendor}%`],
			);
		}
		if (!results[0]) {
			return [];
		}
		return results[0].values.map((row: SqlJsTypes.SqlValue[]) => ({
			cveId: String(row[0] ?? ""),
			state: String(row[1] ?? ""),
			datePublished: String(row[2] ?? ""),
			dateUpdated: String(row[3] ?? ""),
			description: String(row[4] ?? ""),
			vendor: String(row[5] ?? ""),
			product: String(row[6] ?? ""),
		}));
	} finally {
		db.close();
	}
}

/**
 * Quickly search CVEs by package name — tries the name as both vendor and product.
 * Used by the dependency scanner to augment OSV results with local DB findings.
 */
export async function searchByPackageName(
	context: vscode.ExtensionContext,
	name: string,
): Promise<CveRecord[]> {
	const dbPath = getDbPath(context);
	if (!fs.existsSync(dbPath)) {
		return [];
	}

	let SQL: SqlJsTypes.SqlJsStatic;
	try {
		SQL = await initSqlJs({ locateFile: (f) => path.join(__dirname, f) });
	} catch {
		return [];
	}

	// Normalise: strip npm scope (@org/pkg → pkg)
	const baseName = name.includes("/") ? name.split("/").pop()! : name;

	const db = new SQL.Database(fs.readFileSync(dbPath));
	try {
		const results = db.exec(
			`SELECT DISTINCT r.cve_id, r.state, r.date_published, r.date_updated,
			        r.description, a.vendor, a.product
			 FROM cve_records r
			 JOIN cve_affected a ON r.cve_id = a.cve_id
			 WHERE (a.product LIKE ? OR a.vendor LIKE ?)
			 AND r.state = 'PUBLISHED'
			 ORDER BY r.date_published DESC
			 LIMIT 50`,
			[`%${baseName}%`, `%${baseName}%`],
		);
		if (!results[0]) {
			return [];
		}
		return results[0].values.map((row: SqlJsTypes.SqlValue[]) => ({
			cveId: String(row[0] ?? ""),
			state: String(row[1] ?? ""),
			datePublished: String(row[2] ?? ""),
			dateUpdated: String(row[3] ?? ""),
			description: String(row[4] ?? ""),
			vendor: String(row[5] ?? ""),
			product: String(row[6] ?? ""),
		}));
	} finally {
		db.close();
	}
}
