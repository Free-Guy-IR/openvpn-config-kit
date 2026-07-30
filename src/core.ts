import { assertValidOpenVPNCoreConfig } from "./validation.js";
import type {
  CreateOpenVPNCoreConfigOptions,
  CreateOpenVPNCorePayloadOptions,
  CreateOpenVPNInstanceOptions,
  CreateOpenVPNPKIOptions,
  JsonValue,
  OpenVPNCoreConfig,
  OpenVPNCorePayload,
  OpenVPNInstance,
  OpenVPNPKI
} from "./types.js";

export function createOpenVPNInstanceConfig(options: CreateOpenVPNInstanceOptions): OpenVPNInstance {
  const instance: Record<string, JsonValue> = {
    tag: options.tag,
    protocol: options.protocol,
    port: options.port,
    network: options.network
  };

  if (options.cipher !== undefined) instance.cipher = options.cipher;
  if (options.auth !== undefined) instance.auth = options.auth;
  if (options.keepalive !== undefined) instance.keepalive = options.keepalive;
  if (options.maxClients !== undefined) instance.max_clients = options.maxClients;
  if (options.dnsServers !== undefined) instance.dns_servers = [...options.dnsServers];
  if (options.redirectGateway !== undefined) instance.redirect_gateway = options.redirectGateway;
  if (options.duplicateCN !== undefined) instance.duplicate_cn = options.duplicateCN;
  if (options.verb !== undefined) instance.verb = options.verb;

  return instance as OpenVPNInstance;
}

function pkiFromOptions(pki: CreateOpenVPNPKIOptions | undefined): OpenVPNPKI {
  const result: Record<string, JsonValue> = {};
  if (pki?.caCert !== undefined) result.ca_cert = pki.caCert;
  if (pki?.serverCert !== undefined) result.server_cert = pki.serverCert;
  if (pki?.serverKey !== undefined) result.server_key = pki.serverKey;
  if (pki?.tlsCryptKey !== undefined) result.tls_crypt_key = pki.tlsCryptKey;
  return result as OpenVPNPKI;
}

function configFromOptions(options: CreateOpenVPNCoreConfigOptions): Record<string, JsonValue> {
  return {
    instances: options.instances.map(createOpenVPNInstanceConfig) as unknown as JsonValue,
    pki: pkiFromOptions(options.pki) as JsonValue
  };
}

/** Builds an OpenVPN core config. Unlike sing-box/xray, this does not itself generate PKI -
 * PKI is server-only (see `generate_openvpn_pki()` in the panel's `app/core/openvpn.py`) and
 * must be supplied via `options.pki` (typically fetched from the panel's generate-pki endpoint). */
export function createOpenVPNCoreConfig(options: CreateOpenVPNCoreConfigOptions): OpenVPNCoreConfig {
  return assertValidOpenVPNCoreConfig(configFromOptions(options));
}

export function generateOpenVPNCoreConfigJson(options: CreateOpenVPNCoreConfigOptions, space = 2): string {
  return JSON.stringify(createOpenVPNCoreConfig(options), null, space);
}

export function createOpenVPNCorePayload(options: CreateOpenVPNCorePayloadOptions): OpenVPNCorePayload {
  const { name = "openvpn_core", ...configOptions } = options;
  return {
    name,
    type: "openvpn",
    config: createOpenVPNCoreConfig(configOptions),
    exclude_inbound_tags: [],
    fallbacks_inbound_tags: []
  };
}
