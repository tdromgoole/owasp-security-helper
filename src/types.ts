// Types shared across the extension

export type Severity = "critical" | "warning" | "info";

export interface SecurityRule {
	/** Unique rule identifier, e.g. "A03-SQL-INJECTION" */
	id: string;
	/** OWASP / CSP / general category */
	category: string;
	/** Short human-readable title */
	title: string;
	/** Detailed description of the vulnerability */
	description: string;
	/** Severity level */
	severity: Severity;
	/** Languages this rule applies to. Empty = all supported languages. */
	languages: string[];
	/**
	 * Regex patterns to match against each document line.
	 * A match triggers the diagnostic.
	 */
	patterns: RegExp[];
	/**
	 * When set, the rule fires if this pattern does NOT match anywhere in the
	 * full document text. Use for "missing required header/directive" checks.
	 * The rule still respects the `languages` filter.
	 */
	documentMustMatch?: RegExp;
	/**
	 * When set, the rule only applies to files whose base name matches this
	 * pattern. Useful for restricting broad language IDs (e.g. "xml") to
	 * specific config files such as web.config.
	 */
	fileNamePattern?: RegExp;
	/** Suggested fix description shown in the Quick Fix menu */
	fixDescription?: string;
	/** Optional replacement factory (line text → fixed line text) */
	fixReplacer?: (lineText: string, match: RegExpMatchArray) => string;
	/** Reference URL for more information */
	reference?: string;
}

export interface SecurityFinding {
	rule: SecurityRule;
	/** 0-based line index */
	line: number;
	/** 0-based start char */
	startChar: number;
	/** 0-based end char */
	endChar: number;
	/** The matched source text */
	matchedText: string;
	filePath: string;
	/**
	 * When set, the finding was suppressed by an `owasp-ignore` comment.
	 * Contains the justification text from that comment.
	 */
	justification?: string;
}
