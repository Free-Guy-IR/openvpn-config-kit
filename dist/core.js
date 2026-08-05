import { assertValidOpenVPNCoreConfig } from "./validation.js";
export function createOpenVPNInstanceConfig(options) {
    const instance = {
        tag: options.tag,
        protocol: options.protocol,
        port: options.port,
        network: options.network
    };
    if (options.cipher !== undefined)
        instance.cipher = options.cipher;
    if (options.auth !== undefined)
        instance.auth = options.auth;
    if (options.keepalive !== undefined)
        instance.keepalive = options.keepalive;
    if (options.maxClients !== undefined)
        instance.max_clients = options.maxClients;
    if (options.dnsServers !== undefined)
        instance.dns_servers = [...options.dnsServers];
    if (options.redirectGateway !== undefined)
        instance.redirect_gateway = options.redirectGateway;
    if (options.duplicateCN !== undefined)
        instance.duplicate_cn = options.duplicateCN;
    if (options.verb !== undefined)
        instance.verb = options.verb;
    return instance;
}
function pkiFromOptions(pki) {
    const result = {};
    if (pki?.caCert !== undefined)
        result.ca_cert = pki.caCert;
    if (pki?.serverCert !== undefined)
        result.server_cert = pki.serverCert;
    if (pki?.serverKey !== undefined)
        result.server_key = pki.serverKey;
    if (pki?.tlsCryptKey !== undefined)
        result.tls_crypt_key = pki.tlsCryptKey;
    return result;
}
function configFromOptions(options) {
    return {
        instances: options.instances.map(createOpenVPNInstanceConfig),
        pki: pkiFromOptions(options.pki)
    };
}
/** Builds an OpenVPN core config. Unlike sing-box/xray, this does not itself generate PKI -
 * PKI is server-only (see `generate_openvpn_pki()` in the panel's `app/core/openvpn.py`) and
 * must be supplied via `options.pki` (typically fetched from the panel's generate-pki endpoint). */
export function createOpenVPNCoreConfig(options) {
    return assertValidOpenVPNCoreConfig(configFromOptions(options));
}
export function generateOpenVPNCoreConfigJson(options, space = 2) {
    return JSON.stringify(createOpenVPNCoreConfig(options), null, space);
}
export function createOpenVPNCorePayload(options) {
    const { name = "openvpn_core", ...configOptions } = options;
    return {
        name,
        type: "openvpn",
        config: createOpenVPNCoreConfig(configOptions),
        exclude_inbound_tags: [],
        fallbacks_inbound_tags: []
    };
}
//# sourceMappingURL=core.js.map