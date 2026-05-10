import * as https from "https";
import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";

// ── Public types ──────────────────────────────────────────────────────────────

export interface DependencyVuln {
	id: string;
	summary: string;
	severity: "critical" | "high" | "medium" | "low" | "unknown";
	url: string;
}

export interface DependencyResult {
	name: string;
	/** Version string as written in the manifest (may include range prefix) */
	requestedVersion: string;
	/** Exact version actually resolved (from lock file, or range-stripped) */
	resolvedVersion: string;
	latestVersion: string | null;
	isOutdated: boolean;
	vulnerabilities: DependencyVuln[];
	ecosystem: "npm" | "pypi" | "packagist";
	sourceFile: string;
	/** True if the package/version is deprecated, EOL, or abandoned */
	isDeprecated: boolean;
	/** Human-readable deprecation or EOL reason (null when not deprecated) */
	deprecationReason: string | null;
}

export type VersionBump = "major" | "minor" | "patch" | "none";

export function versionBumpType(current: string, latest: string): VersionBump {
	const parse = (v: string) =>
		v
			.replace(/^v/, "")
			.split(/[.\-]/)
			.slice(0, 3)
			.map((n) => parseInt(n, 10) || 0);
	const c = parse(current);
	const l = parse(latest);
	if ((l[0] ?? 0) > (c[0] ?? 0)) {
		return "major";
	}
	if ((l[1] ?? 0) > (c[1] ?? 0)) {
		return "minor";
	}
	if ((l[2] ?? 0) > (c[2] ?? 0)) {
		return "patch";
	}
	return "none";
}

// ── Utilities ─────────────────────────────────────────────────────────────────

/** Strip semver range prefix (^, ~, >=, etc.) and return the base version. */
function stripRange(version: string): string {
	const m = version.match(/(\d+(?:\.\d+)*(?:-[^\s,|<>+]*)?)/);
	return m ? m[1] : "";
}

function isNewer(current: string, latest: string): boolean {
	const parse = (v: string) =>
		v
			.replace(/^v/, "")
			.split(/[.\-]/)
			.slice(0, 3)
			.map((n) => parseInt(n, 10) || 0);
	const c = parse(current);
	const l = parse(latest);
	for (let i = 0; i < 3; i++) {
		if ((l[i] ?? 0) > (c[i] ?? 0)) {
			return true;
		}
		if ((l[i] ?? 0) < (c[i] ?? 0)) {
			return false;
		}
	}
	return false;
}

/** Fetch JSON over HTTPS. Supports GET and POST. */
function fetchJson<T>(url: string, postBody?: string): Promise<T> {
	return new Promise((resolve, reject) => {
		let parsed: URL;
		try {
			parsed = new URL(url);
		} catch {
			reject(new Error(`Invalid URL: ${url}`));
			return;
		}
		if (parsed.protocol !== "https:") {
			reject(new Error("Only HTTPS requests are permitted"));
			return;
		}
		const bodyBytes = postBody ? Buffer.from(postBody, "utf8") : undefined;
		const options: https.RequestOptions = {
			hostname: parsed.hostname,
			path: parsed.pathname + parsed.search,
			method: bodyBytes ? "POST" : "GET",
			headers: {
				"User-Agent": "owasp-security-helper-vscode/1.0",
				Accept: "application/json",
				...(bodyBytes
					? {
							"Content-Type": "application/json",
							"Content-Length": bodyBytes.length,
						}
					: {}),
			},
			timeout: 15000,
		};
		const req = https.request(options, (res) => {
			const chunks: Buffer[] = [];
			res.on("data", (chunk: unknown) =>
				chunks.push(
					Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)),
				),
			);
			res.on("end", () => {
				try {
					resolve(
						JSON.parse(Buffer.concat(chunks).toString("utf8")) as T,
					);
				} catch {
					reject(
						new Error(
							`Invalid JSON response from ${parsed.hostname}`,
						),
					);
				}
			});
			res.on("error", reject);
		});
		req.on("error", reject);
		req.on("timeout", () => {
			req.destroy();
			reject(new Error(`Request timed out: ${parsed.hostname}`));
		});
		if (bodyBytes) {
			req.write(bodyBytes);
		}
		req.end();
	});
}

/** Run an array of async tasks with bounded parallelism. */
async function withConcurrency<T>(
	tasks: Array<() => Promise<T>>,
	limit: number,
): Promise<T[]> {
	const results: T[] = new Array(tasks.length);
	let next = 0;
	const worker = async (): Promise<void> => {
		while (true) {
			const i = next++;
			if (i >= tasks.length) {
				break;
			}
			results[i] = await tasks[i]();
		}
	};
	await Promise.all(
		Array.from({ length: Math.min(limit, tasks.length) }, worker),
	);
	return results;
}

// ── Manifest parsers ──────────────────────────────────────────────────────────

/** Read package.json and return declared dependency names + version ranges. */
async function parsePackageJson(
	filePath: string,
): Promise<Array<{ name: string; version: string }>> {
	try {
		const raw = JSON.parse(await fs.promises.readFile(filePath, "utf8"));
		const deps: Array<{ name: string; version: string }> = [];
		for (const section of [
			"dependencies",
			"devDependencies",
			"peerDependencies",
		]) {
			const obj = raw[section];
			if (obj && typeof obj === "object") {
				for (const [name, ver] of Object.entries(obj)) {
					if (
						typeof ver === "string" &&
						ver !== "*" &&
						ver !== "latest" &&
						!ver.startsWith("file:") &&
						!ver.startsWith("github:") &&
						!ver.startsWith("git:")
					) {
						deps.push({ name, version: ver });
					}
				}
			}
		}
		return deps;
	} catch {
		return [];
	}
}

/** Read package-lock.json (v1/v2/v3) and return a map of resolved versions. */
async function parsePackageLock(
	lockPath: string,
): Promise<Map<string, string>> {
	const resolved = new Map<string, string>();
	try {
		const raw = JSON.parse(await fs.promises.readFile(lockPath, "utf8"));
		if (raw.packages) {
			// v2/v3 format
			for (const [key, val] of Object.entries<{
				version?: string;
			}>(raw.packages)) {
				if (key.startsWith("node_modules/") && val.version) {
					resolved.set(
						key.slice("node_modules/".length),
						val.version,
					);
				}
			}
		} else if (raw.dependencies) {
			// v1 format
			for (const [name, val] of Object.entries<{ version?: string }>(
				raw.dependencies,
			)) {
				if (val.version) {
					resolved.set(name, val.version);
				}
			}
		}
	} catch {
		/* ignore */
	}
	return resolved;
}

async function parseRequirementsTxt(
	filePath: string,
): Promise<Array<{ name: string; version: string }>> {
	const deps: Array<{ name: string; version: string }> = [];
	try {
		const lines = (await fs.promises.readFile(filePath, "utf8")).split(
			/\r?\n/,
		);
		for (const line of lines) {
			const trimmed = line.trim();
			if (
				!trimmed ||
				trimmed.startsWith("#") ||
				trimmed.startsWith("-")
			) {
				continue;
			}
			// e.g. Flask==2.0.1, Django>=3.2, requests~=2.28.0
			const m = trimmed.match(
				/^([A-Za-z0-9][\w.\-]*)\s*(?:\[[^\]]*\])?\s*(?:[=~!<>]=?|===)\s*([\d][^\s;]*)/,
			);
			if (m) {
				deps.push({ name: m[1], version: m[2] });
			}
		}
	} catch {
		/* ignore */
	}
	return deps;
}

async function parseComposerJson(
	filePath: string,
): Promise<Array<{ name: string; version: string }>> {
	try {
		const raw = JSON.parse(await fs.promises.readFile(filePath, "utf8"));
		const deps: Array<{ name: string; version: string }> = [];
		for (const section of ["require", "require-dev"]) {
			const obj = raw[section];
			if (obj && typeof obj === "object") {
				for (const [name, ver] of Object.entries(obj)) {
					if (
						name === "php" ||
						name.startsWith("ext-") ||
						name.startsWith("lib-")
					) {
						continue;
					}
					if (typeof ver === "string" && ver !== "*") {
						deps.push({ name, version: ver });
					}
				}
			}
		}
		return deps;
	} catch {
		return [];
	}
}

// ── Poetry lock file parser ───────────────────────────────────────────────────

/**
 * Parses `poetry.lock` (TOML-subset, no external dep) to extract resolved
 * package names and exact version strings.
 */
async function parsePoetryLock(
	filePath: string,
): Promise<Array<{ name: string; version: string }>> {
	const deps: Array<{ name: string; version: string }> = [];
	try {
		const content = await fs.promises.readFile(filePath, "utf8");
		// Each package block starts with [[package]]
		const blocks = content.split(/\[\[package\]\]/g).slice(1);
		for (const block of blocks) {
			const nameMatch = block.match(/^\s*name\s*=\s*"([^"]+)"/m);
			const verMatch = block.match(/^\s*version\s*=\s*"([^"]+)"/m);
			if (nameMatch && verMatch) {
				deps.push({ name: nameMatch[1], version: verMatch[1] });
			}
		}
	} catch {
		/* ignore missing / unreadable */
	}
	return deps;
}

/**
 * Parses `Pipfile.lock` (JSON) to extract resolved package names and versions.
 */
async function parsePipfileLock(
	filePath: string,
): Promise<Array<{ name: string; version: string }>> {
	const deps: Array<{ name: string; version: string }> = [];
	try {
		const raw = JSON.parse(await fs.promises.readFile(filePath, "utf8"));
		for (const section of ["default", "develop"] as const) {
			const obj = raw[section];
			if (!obj || typeof obj !== "object") {
				continue;
			}
			for (const [name, meta] of Object.entries<{
				version?: string;
			}>(obj)) {
				// Pipfile.lock stores version as "==1.2.3"
				const ver = meta?.version?.replace(/^==/, "");
				if (ver && /^\d/.test(ver)) {
					deps.push({ name, version: ver });
				}
			}
		}
	} catch {
		/* ignore */
	}
	return deps;
}

// ── OSV vulnerability API ─────────────────────────────────────────────────────

interface OsvVuln {
	id: string;
	summary?: string;
	references?: Array<{ type: string; url: string }>;
	database_specific?: Record<string, unknown>;
}

interface OsvBatchResponse {
	results: Array<{ vulns?: OsvVuln[] }>;
}

function osvSeverity(vuln: OsvVuln): DependencyVuln["severity"] {
	// GitHub Advisory Database includes textual severity in database_specific
	const dbSev = vuln.database_specific?.["severity"];
	if (dbSev) {
		const s = String(dbSev).toLowerCase();
		if (s === "critical") {
			return "critical";
		}
		if (s === "high") {
			return "high";
		}
		if (s === "moderate" || s === "medium") {
			return "medium";
		}
		if (s === "low") {
			return "low";
		}
	}
	// Some databases include numeric CVSS score
	const cvssScore = (
		vuln.database_specific?.["cvss"] as Record<string, unknown> | undefined
	)?.["score"];
	if (typeof cvssScore === "number") {
		if (cvssScore >= 9.0) {
			return "critical";
		}
		if (cvssScore >= 7.0) {
			return "high";
		}
		if (cvssScore >= 4.0) {
			return "medium";
		}
		return "low";
	}
	return "unknown";
}

async function queryOsvBatch(
	queries: Array<{
		idx: number;
		name: string;
		version: string;
		ecosystem: string;
	}>,
): Promise<Map<number, DependencyVuln[]>> {
	const resultMap = new Map<number, DependencyVuln[]>();
	if (queries.length === 0) {
		return resultMap;
	}

	const BATCH = 500;
	for (let start = 0; start < queries.length; start += BATCH) {
		const chunk = queries.slice(start, start + BATCH);
		const body = {
			queries: chunk.map((q) => ({
				package: { name: q.name, ecosystem: q.ecosystem },
				version: q.version,
			})),
		};
		try {
			const response = await fetchJson<OsvBatchResponse>(
				"https://api.osv.dev/v1/querybatch",
				JSON.stringify(body),
			);
			(response.results ?? []).forEach((r, i) => {
				const orig = chunk[i];
				if (!orig) {
					return;
				}
				resultMap.set(
					orig.idx,
					(r.vulns ?? []).map(
						(v): DependencyVuln => ({
							id: v.id,
							summary: v.summary ?? v.id,
							severity: osvSeverity(v),
							url:
								v.references?.find((ref) => ref.type === "WEB")
									?.url ??
								`https://osv.dev/vulnerability/${v.id}`,
						}),
					),
				);
			});
		} catch {
			/* OSV unavailable — chunk returns no results */
		}
	}
	return resultMap;
}

// ── Latest version APIs ───────────────────────────────────────────────────────

async function getNpmLatest(name: string): Promise<string | null> {
	try {
		const data = await fetchJson<Record<string, string>>(
			`https://registry.npmjs.org/-/package/${encodeURIComponent(name)}/dist-tags`,
		);
		return data["latest"] ?? null;
	} catch {
		return null;
	}
}

interface PypiPackageInfo {
	latest: string | null;
	deprecated: string | null;
}

async function getPypiInfo(name: string): Promise<PypiPackageInfo> {
	try {
		const data = await fetchJson<{
			info: { version: string; classifiers: string[] };
		}>(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
		const latest = data.info?.version ?? null;
		const classifiers: string[] = data.info?.classifiers ?? [];
		const isInactive = classifiers.some((c) =>
			c.includes("Development Status :: 7 - Inactive"),
		);
		return {
			latest,
			deprecated: isInactive
				? "Package is marked as Inactive on PyPI"
				: null,
		};
	} catch {
		return { latest: null, deprecated: null };
	}
}

async function getPackagistLatest(name: string): Promise<string | null> {
	try {
		const data = await fetchJson<{
			packages: Record<string, Array<{ version: string }>>;
		}>(`https://packagist.org/p2/${name}.json`);
		const versions = data.packages?.[name];
		if (!Array.isArray(versions)) {
			return null;
		}
		const stable = versions
			.map((v) =>
				v.version.startsWith("v") ? v.version.slice(1) : v.version,
			)
			.filter((v) => /^\d/.test(v) && !/dev|alpha|beta|rc/i.test(v));
		return stable[0] ?? null;
	} catch {
		return null;
	}
}

// ── EOL / Deprecation checks ──────────────────────────────────────────────────

/**
 * Maps well-known npm/PyPI package names to their endoflife.date product slug.
 * Only frameworks/libraries with published EOL schedules are listed.
 */
const EOL_DATE_MAP: Record<string, string> = {
	// JavaScript / npm
	"@angular/core": "angular",
	"@angular/common": "angular",
	"@angular/router": "angular",
	"@angular/forms": "angular",
	"@angular/platform-browser": "angular",
	"@angular/platform-browser-dynamic": "angular",
	vue: "vue",
	jquery: "jquery",
	bootstrap: "bootstrap",
	// Python / PyPI
	django: "django",
	ansible: "ansible-core",
	"ansible-core": "ansible-core",
};

interface EolCycle {
	cycle: string;
	eol: string | boolean;
	latest?: string;
}

/**
 * Checks endoflife.date for a known framework/library.
 * Returns a human-readable EOL message or null if not EOL / not tracked.
 */
async function checkEndOfLifeDate(
	name: string,
	version: string,
): Promise<string | null> {
	const product = EOL_DATE_MAP[name];
	if (!product) {
		return null;
	}
	try {
		const cycles = await fetchJson<EolCycle[]>(
			`https://endoflife.date/api/${encodeURIComponent(product)}.json`,
		);
		const parts = version.replace(/^v/, "").split(".");
		// Try major.minor first, then major only
		const cyclesToTry = [parts.slice(0, 2).join("."), parts[0]].filter(
			Boolean,
		);
		for (const cycle of cyclesToTry) {
			const found = cycles.find((c) => String(c.cycle) === cycle);
			if (!found) {
				continue;
			}
			if (found.eol === false) {
				return null; // not yet EOL
			}
			if (typeof found.eol === "string") {
				const eolDate = new Date(found.eol);
				if (!isNaN(eolDate.getTime()) && eolDate <= new Date()) {
					return `End of life since ${found.eol} (source: endoflife.date)`;
				}
			}
			return null;
		}
	} catch {
		/* endoflife.date unavailable or product not found — silently ignore */
	}
	return null;
}

/**
 * Checks whether a specific npm package version carries a deprecation notice
 * from the npm registry. Returns the deprecation message or null.
 */
async function checkNpmDeprecated(
	name: string,
	version: string,
): Promise<string | null> {
	try {
		// Scoped packages: @scope/name → @scope%2Fname in URL path
		const npmPath = name.startsWith("@")
			? "@" + encodeURIComponent(name.slice(1))
			: encodeURIComponent(name);
		const data = await fetchJson<{ deprecated?: string }>(
			`https://registry.npmjs.org/${npmPath}/${encodeURIComponent(version)}`,
		);
		return typeof data.deprecated === "string" ? data.deprecated : null;
	} catch {
		return null;
	}
}

// ── Main scan entry point ─────────────────────────────────────────────────────

export interface ScanDependenciesOptions {
	progress?: vscode.Progress<{ message?: string; increment?: number }>;
	token?: vscode.CancellationToken;
	/** Optional extension context — when provided, local CVE DB is used to augment OSV results. */
	extensionContext?: vscode.ExtensionContext;
}

export async function scanDependencies(
	options: ScanDependenciesOptions = {},
): Promise<DependencyResult[]> {
	const { progress, token, extensionContext } = options;
	const report = (msg: string) => progress?.report({ message: msg });

	// 1. Discover manifest files
	report("Finding dependency files…");
	const fileUris = await vscode.workspace.findFiles(
		"{**/package.json,**/requirements.txt,**/composer.json,**/poetry.lock,**/Pipfile.lock}",
		"{**/node_modules/**,**/.venv/**,**/vendor/**,**/out/**,**/dist/**}",
	);
	if (token?.isCancellationRequested || fileUris.length === 0) {
		return [];
	}

	// 2. Parse each manifest
	type RawDep = {
		name: string;
		version: string;
		resolvedVersion: string;
		ecosystem: "npm" | "pypi" | "packagist";
		sourceFile: string;
	};
	const rawDeps: RawDep[] = [];
	const lockCache = new Map<string, Map<string, string>>();

	for (const uri of fileUris) {
		const filePath = uri.fsPath;
		const dir = path.dirname(filePath);
		const base = path.basename(filePath);

		if (base === "package.json") {
			// Load lock file for exact resolved versions if available
			if (!lockCache.has(dir)) {
				const lockPath = path.join(dir, "package-lock.json");
				if (fs.existsSync(lockPath)) {
					lockCache.set(dir, await parsePackageLock(lockPath));
				}
			}
			for (const dep of await parsePackageJson(filePath)) {
				const locked = lockCache.get(dir)?.get(dep.name);
				const resolved = locked ?? stripRange(dep.version);
				if (resolved) {
					rawDeps.push({
						...dep,
						resolvedVersion: resolved,
						ecosystem: "npm",
						sourceFile: filePath,
					});
				}
			}
		} else if (base === "requirements.txt") {
			for (const dep of await parseRequirementsTxt(filePath)) {
				rawDeps.push({
					...dep,
					resolvedVersion: dep.version,
					ecosystem: "pypi",
					sourceFile: filePath,
				});
			}
		} else if (base === "poetry.lock") {
			for (const dep of await parsePoetryLock(filePath)) {
				rawDeps.push({
					...dep,
					resolvedVersion: dep.version,
					ecosystem: "pypi",
					sourceFile: filePath,
				});
			}
		} else if (base === "Pipfile.lock") {
			for (const dep of await parsePipfileLock(filePath)) {
				rawDeps.push({
					...dep,
					resolvedVersion: dep.version,
					ecosystem: "pypi",
					sourceFile: filePath,
				});
			}
		} else if (base === "composer.json") {
			for (const dep of await parseComposerJson(filePath)) {
				const resolved = stripRange(dep.version);
				if (resolved) {
					rawDeps.push({
						...dep,
						resolvedVersion: resolved,
						ecosystem: "packagist",
						sourceFile: filePath,
					});
				}
			}
		}
	}

	if (rawDeps.length === 0 || token?.isCancellationRequested) {
		return [];
	}

	// 3. Query OSV for known vulnerabilities
	report(`Checking ${rawDeps.length} packages for known vulnerabilities…`);
	const osvEco: Record<string, string> = {
		npm: "npm",
		pypi: "PyPI",
		packagist: "Packagist",
	};
	const osvQueries = rawDeps
		.map((d, i) => ({
			idx: i,
			name: d.name,
			version: d.resolvedVersion,
			ecosystem: osvEco[d.ecosystem] ?? d.ecosystem,
		}))
		.filter((q) => /^\d/.test(q.version)); // only proper semver versions

	const vulnMap = await queryOsvBatch(osvQueries);
	if (token?.isCancellationRequested) {
		return [];
	}

	// 4. Fetch latest versions and EOL/deprecation status with bounded concurrency
	report("Fetching latest versions and EOL status…");

	interface DepCheckResult {
		latest: string | null;
		deprecated: string | null;
	}

	const latestTasks = rawDeps.map(
		(dep) => async (): Promise<DepCheckResult> => {
			if (token?.isCancellationRequested) {
				return { latest: null, deprecated: null };
			}
			if (dep.ecosystem === "npm") {
				const [latest, npmDep, eolDep] = await Promise.all([
					getNpmLatest(dep.name),
					checkNpmDeprecated(dep.name, dep.resolvedVersion),
					checkEndOfLifeDate(dep.name, dep.resolvedVersion),
				]);
				return { latest, deprecated: npmDep ?? eolDep };
			}
			if (dep.ecosystem === "pypi") {
				const [info, eolDep] = await Promise.all([
					getPypiInfo(dep.name),
					checkEndOfLifeDate(dep.name, dep.resolvedVersion),
				]);
				return {
					latest: info.latest,
					deprecated: info.deprecated ?? eolDep,
				};
			}
			if (dep.ecosystem === "packagist") {
				return {
					latest: await getPackagistLatest(dep.name),
					deprecated: null,
				};
			}
			return { latest: null, deprecated: null };
		},
	);
	const depCheckResults = await withConcurrency(latestTasks, 8);

	// 5. Augment with local CVE DB (if available and not cancelled)
	const localCveMap = new Map<number, DependencyVuln[]>();
	if (extensionContext && !token?.isCancellationRequested) {
		report("Cross-referencing local CVE database…");
		try {
			const { searchByPackageName, getStatus } =
				await import("./cveDatabase");
			const dbStatus = getStatus(extensionContext);
			if (dbStatus.downloaded) {
				const localTasks = rawDeps.map((dep, idx) => async () => {
					if (token?.isCancellationRequested) {
						return;
					}
					try {
						const records = await searchByPackageName(
							extensionContext,
							dep.name,
						);
						if (records.length > 0) {
							const existing = new Set(
								(vulnMap.get(idx) ?? []).map((v) => v.id),
							);
							const newVulns: DependencyVuln[] = records
								.filter((r) => !existing.has(r.cveId))
								.map((r) => ({
									id: r.cveId,
									summary:
										r.description.slice(0, 200) || r.cveId,
									severity: "unknown" as const,
									url: `https://www.cve.org/CVERecord?id=${encodeURIComponent(r.cveId)}`,
								}));
							if (newVulns.length > 0) {
								localCveMap.set(idx, newVulns);
							}
						}
					} catch {
						/* local DB unavailable — skip gracefully */
					}
				});
				await withConcurrency(localTasks, 4);
			}
		} catch {
			/* import failed or DB not available — continue without local CVEs */
		}
	}

	// 6. Assemble results
	return rawDeps.map((dep, i) => {
		const { latest, deprecated } = depCheckResults[i] ?? {
			latest: null,
			deprecated: null,
		};
		const osvVulns = vulnMap.get(i) ?? [];
		const localVulns = localCveMap.get(i) ?? [];
		return {
			name: dep.name,
			requestedVersion: dep.version,
			resolvedVersion: dep.resolvedVersion,
			latestVersion: latest,
			isOutdated: latest !== null && isNewer(dep.resolvedVersion, latest),
			vulnerabilities: [...osvVulns, ...localVulns],
			ecosystem: dep.ecosystem,
			sourceFile: dep.sourceFile,
			isDeprecated: deprecated !== null,
			deprecationReason: deprecated,
		};
	});
}
