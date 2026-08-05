import type { OpenVPNCoreConfig, OpenVPNProtocol, OpenVPNValidationIssue } from "./types.js";
/**
 * Form-state shape for a single OpenVPN instance, distinct from the persisted JSON shape -
 * every numeric-ish field is a string (or `number | string` for port, to match the
 * "random port" generator button pattern already used by the sing-box/Xray inbound forms).
 */
export type OpenVPNInstanceDraft = {
    readonly tag: string;
    readonly protocol: OpenVPNProtocol;
    readonly port: number | string;
    readonly network: string;
    readonly cipher: string;
    readonly auth: string;
    readonly keepalive: string;
    readonly maxClients: string;
    readonly dnsServers: readonly string[];
    readonly redirectGateway: boolean;
    readonly duplicateCN: boolean;
    readonly verb: string;
};
/**
 * Core-level PKI draft. Unlike every other draft field here, these are never hand-typed by
 * an admin - they are populated wholesale from the panel's generate-pki endpoint (the panel
 * is the only side that can run `generate_openvpn_pki()`, since it needs the `cryptography`
 * Python library). This kit only stores/validates/serializes them.
 */
export type OpenVPNPKIDraft = {
    readonly caCert: string;
    readonly serverCert: string;
    readonly serverKey: string;
    readonly tlsCryptKey: string;
};
export type OpenVPNCoreDraft = {
    readonly instances: readonly OpenVPNInstanceDraft[];
    readonly pki: OpenVPNPKIDraft;
};
export declare function createDefaultOpenVPNInstanceDraft(existingTags?: readonly string[]): OpenVPNInstanceDraft;
export declare function createDefaultOpenVPNPKIDraft(): OpenVPNPKIDraft;
export declare function createDefaultOpenVPNCoreDraft(): OpenVPNCoreDraft;
/** True once every PKI field has been populated (typically right after a "Generate PKI" call). */
export declare function isOpenVPNPKIDraftComplete(pki: OpenVPNPKIDraft): boolean;
/** Mirrors the validation.ts semantic rules, at the draft/form level (pre-serialization). */
export declare function validateOpenVPNInstanceDraft(draft: OpenVPNInstanceDraft, index: number, allTags: readonly string[], allPortKeys: readonly string[]): OpenVPNValidationIssue[];
/** Mirrors OpenVPNConfig._validate: at least one instance, unique tags/ports, and a complete pki section. */
export declare function validateOpenVPNCoreDraft(draft: OpenVPNCoreDraft): OpenVPNValidationIssue[];
export declare function createOpenVPNCoreConfigFromDraft(draft: OpenVPNCoreDraft): OpenVPNCoreConfig;
export declare function generateOpenVPNCoreConfigJsonFromDraft(draft: OpenVPNCoreDraft, space?: number): string;
/** Exposed for callers that build a single instance's config JSON without a full draft (e.g. previews). */
export declare function createOpenVPNInstanceConfigFromDraft(draft: OpenVPNInstanceDraft): import("./types.js").OpenVPNInstance;
//# sourceMappingURL=form.d.ts.map