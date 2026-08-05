import type { OpenVPNCoreConfig, OpenVPNInstance, OpenVPNValidationResult } from "./types.js";
export declare function isValidIpAddress(value: string): boolean;
export declare function isValidCidr(value: string): boolean;
export declare function validateOpenVPNCoreConfig(input: unknown): OpenVPNValidationResult;
export declare function assertValidOpenVPNCoreConfig(input: unknown): OpenVPNCoreConfig;
export declare function isOpenVPNInstance(value: unknown): value is OpenVPNInstance;
//# sourceMappingURL=validation.d.ts.map