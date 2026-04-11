const fs = require("fs");
let c = fs.readFileSync(
	"c:/Development/owaspHelper/src/rules/cspRules.ts",
	"utf8",
);

// Fix CSP-MISSING-DEFAULT-SRC
c = c.replace(
	"/Content-Security-Policy[^'\";\n]*(?!default-src)/i",
	"/Content-Security-Policy(?![^;\\n'\"]*\\bdefault-src\\b)/i",
);
// Fix CSP-MISSING-OBJECT-SRC
c = c.replace(
	"/Content-Security-Policy[^'\";\n]*(?!object-src)/i",
	"/Content-Security-Policy(?![^;\\n'\"]*\\bobject-src\\b)/i",
);
// Fix CSP-MISSING-FRAME-ANCESTORS
c = c.replace(
	"/Content-Security-Policy[^'\";\n]*(?!frame-ancestors)/i",
	"/Content-Security-Policy(?![^;\\n'\"]*\\bframe-ancestors\\b)/i",
);
// Fix CSP-REPORT-MISSING
c = c.replace(
	"/Content-Security-Policy(?!-Report-Only)[^'\";\n]*(?!report-(?:uri|to))/i",
	"/Content-Security-Policy(?!-Report-Only)(?![^;\\n'\"]*\\breport-(?:uri|to)\\b)/i",
);

fs.writeFileSync("c:/Development/owaspHelper/src/rules/cspRules.ts", c, "utf8");
console.log("Done");
