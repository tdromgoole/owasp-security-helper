export { owaspRules } from "./owaspRules";
export { cspRules } from "./cspRules";
export { generalRules } from "./generalRules";
export { phpRules } from "./phpRules";
export { jsRules } from "./jsRules";
export { phpInputValidationRules } from "./phpInputValidationRules";
export { httpHeaderRules } from "./httpHeaderRules";
export { inputValidationRules } from "./inputValidationRules";
export { cisaRules } from "./cisaRules";

import { owaspRules } from "./owaspRules";
import { cspRules } from "./cspRules";
import { generalRules } from "./generalRules";
import { phpRules } from "./phpRules";
import { jsRules } from "./jsRules";
import { phpInputValidationRules } from "./phpInputValidationRules";
import { httpHeaderRules } from "./httpHeaderRules";
import { inputValidationRules } from "./inputValidationRules";
import { cisaRules } from "./cisaRules";
import { SecurityRule } from "../types";

/** The complete, ordered list of all bundled security rules. */
export const ALL_RULES: SecurityRule[] = [
	...owaspRules,
	...cspRules,
	...generalRules,
	...phpRules,
	...jsRules,
	...phpInputValidationRules,
	...httpHeaderRules,
	...inputValidationRules,
	...cisaRules,
];
