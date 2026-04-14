/**
 * Shared utility functions used by both the live report webview panel
 * (reportPanel.ts) and the saved HTML/JSON report writer (reportWriter.ts).
 */

export function escapeHtml(text: string): string {
	return text
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#039;");
}

export function truncateMatch(text: string, maxChars = 300): string {
	const lines = text.split("\n");
	if (lines.length > 5) {
		const first5 = lines.slice(0, 5).join("\n");
		return (
			(first5.length > maxChars
				? first5.slice(0, maxChars) + "\u2026"
				: first5) + "\n\u2026"
		);
	}
	if (text.length > maxChars) {
		return text.slice(0, maxChars) + "\u2026";
	}
	return text;
}

export function getRelativePath(
	filePath: string,
	workspaceRoot: string,
): string {
	const norm = filePath.replace(/\\/g, "/");
	const rootNorm = workspaceRoot.replace(/\\/g, "/").replace(/\/?$/, "/");
	if (rootNorm !== "/" && norm.startsWith(rootNorm)) {
		return norm.slice(rootNorm.length);
	}
	return norm.split("/").slice(-3).join("/");
}
