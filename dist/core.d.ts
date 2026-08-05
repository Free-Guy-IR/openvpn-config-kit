import type { CreateOpenVPNCoreConfigOptions, CreateOpenVPNCorePayloadOptions, CreateOpenVPNInstanceOptions, OpenVPNCoreConfig, OpenVPNCorePayload, OpenVPNInstance } from "./types.js";
export declare function createOpenVPNInstanceConfig(options: CreateOpenVPNInstanceOptions): OpenVPNInstance;
/** Builds an OpenVPN core config. Unlike sing-box/xray, this does not itself generate PKI -
 * PKI is server-only (see `generate_openvpn_pki()` in the panel's `app/core/openvpn.py`) and
 * must be supplied via `options.pki` (typically fetched from the panel's generate-pki endpoint). */
export declare function createOpenVPNCoreConfig(options: CreateOpenVPNCoreConfigOptions): OpenVPNCoreConfig;
export declare function generateOpenVPNCoreConfigJson(options: CreateOpenVPNCoreConfigOptions, space?: number): string;
export declare function createOpenVPNCorePayload(options: CreateOpenVPNCorePayloadOptions): OpenVPNCorePayload;
//# sourceMappingURL=core.d.ts.map