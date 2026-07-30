export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export type JsonObject = { readonly [key: string]: JsonValue };

export type OpenVPNProtocol = "udp" | "tcp";

/**
 * One independent `openvpn` process (protocol+port). Mirrors the panel's
 * `app/core/openvpn.py::OpenVPNConfig` backend, which runs each configured
 * instance as its own subprocess rather than a single multi-listener process
 * (unlike Xray/sing-box). What the backend calls an "instance" is exposed to
 * the rest of the panel as just another inbound tag.
 */
export type OpenVPNInstance = JsonObject & {
  readonly tag: string;
  readonly protocol: OpenVPNProtocol;
  readonly port: number;
  /** Server-side tunnel network in CIDR form, e.g. "10.8.0.0/24". */
  readonly network: string;
  readonly cipher?: string;
  readonly auth?: string;
  readonly keepalive?: string;
  readonly max_clients?: number;
  readonly dns_servers?: readonly string[];
  readonly redirect_gateway?: boolean;
  readonly duplicate_cn?: boolean;
  readonly verb?: number;
};

/**
 * Server-side PKI (CA + server cert/key + tls-crypt static key) shared by every
 * instance in the core. Generated once via the panel's `generate_openvpn_pki()`
 * (there is no browser-safe equivalent - X.509 generation needs the `cryptography`
 * Python library) and stored inline as PEM/armored text, exactly like the fields
 * this kit's types describe. All four fields are required before the panel will
 * accept the config (`OpenVPNConfig._validate`), but are optional here since a
 * fresh draft has no PKI until the admin generates one.
 */
export type OpenVPNPKI = JsonObject & {
  readonly ca_cert?: string;
  readonly server_cert?: string;
  readonly server_key?: string;
  readonly tls_crypt_key?: string;
};

export type OpenVPNCoreConfig = JsonObject & {
  readonly instances: readonly OpenVPNInstance[];
  readonly pki: OpenVPNPKI;
};

export type OpenVPNCorePayload = {
  readonly name: string;
  readonly type: "openvpn";
  readonly config: OpenVPNCoreConfig;
  readonly exclude_inbound_tags: readonly string[];
  /** OpenVPN cores reject a non-empty fallbacks_inbound_tags server-side; always []. */
  readonly fallbacks_inbound_tags: readonly string[];
};

export type CreateOpenVPNInstanceOptions = {
  readonly tag: string;
  readonly protocol: OpenVPNProtocol;
  readonly port: number;
  readonly network: string;
  readonly cipher?: string;
  readonly auth?: string;
  readonly keepalive?: string;
  readonly maxClients?: number;
  readonly dnsServers?: readonly string[];
  readonly redirectGateway?: boolean;
  readonly duplicateCN?: boolean;
  readonly verb?: number;
};

export type CreateOpenVPNPKIOptions = {
  readonly caCert?: string;
  readonly serverCert?: string;
  readonly serverKey?: string;
  readonly tlsCryptKey?: string;
};

export type CreateOpenVPNCoreConfigOptions = {
  readonly instances: readonly CreateOpenVPNInstanceOptions[];
  readonly pki?: CreateOpenVPNPKIOptions;
};

export type CreateOpenVPNCorePayloadOptions = CreateOpenVPNCoreConfigOptions & {
  readonly name?: string;
};

export type OpenVPNValidationIssue = {
  readonly code: string;
  readonly path: string;
  readonly message: string;
};

export type OpenVPNValidationResult =
  | {
      readonly ok: true;
      readonly config: OpenVPNCoreConfig;
      readonly issues: readonly [];
    }
  | {
      readonly ok: false;
      readonly issues: readonly OpenVPNValidationIssue[];
    };
