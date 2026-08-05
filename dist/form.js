import { createOpenVPNCoreConfig, createOpenVPNInstanceConfig } from "./core.js";
import { isValidCidr, isValidIpAddress } from "./validation.js";
function issue(path, code, message) {
    return { path, code, message };
}
function parsePort(value) {
    if (typeof value === "number")
        return Number.isInteger(value) ? value : undefined;
    const trimmed = value.trim();
    if (!/^\d+$/.test(trimmed))
        return undefined;
    return Number(trimmed);
}
function randomPort() {
    return Math.floor(Math.random() * (65535 - 10000 + 1)) + 10000;
}
function uniqueDefaultTag(existingTags) {
    const taken = new Set(existingTags.map(t => t.trim()));
    if (!taken.has("OpenVPN"))
        return "OpenVPN";
    let n = 2;
    while (taken.has(`OpenVPN_${n}`))
        n += 1;
    return `OpenVPN_${n}`;
}
export function createDefaultOpenVPNInstanceDraft(existingTags = []) {
    return {
        tag: uniqueDefaultTag(existingTags),
        protocol: "udp",
        port: existingTags.length === 0 ? 1194 : randomPort(),
        network: "10.8.0.0/24",
        cipher: "AES-256-GCM",
        auth: "SHA256",
        keepalive: "10 60",
        maxClients: "",
        dnsServers: [],
        redirectGateway: true,
        duplicateCN: true,
        verb: ""
    };
}
export function createDefaultOpenVPNPKIDraft() {
    return { caCert: "", serverCert: "", serverKey: "", tlsCryptKey: "" };
}
export function createDefaultOpenVPNCoreDraft() {
    return {
        instances: [createDefaultOpenVPNInstanceDraft([])],
        pki: createDefaultOpenVPNPKIDraft()
    };
}
/** True once every PKI field has been populated (typically right after a "Generate PKI" call). */
export function isOpenVPNPKIDraftComplete(pki) {
    return Boolean(pki.caCert.trim() && pki.serverCert.trim() && pki.serverKey.trim() && pki.tlsCryptKey.trim());
}
/** Mirrors the validation.ts semantic rules, at the draft/form level (pre-serialization). */
export function validateOpenVPNInstanceDraft(draft, index, allTags, allPortKeys) {
    const issues = [];
    const base = `/instances/${index}`;
    const tag = draft.tag.trim();
    if (!tag) {
        issues.push(issue(`${base}/tag`, "OV_FORM_TAG_REQUIRED", "Tag is required."));
    }
    else if (allTags.filter(t => t.trim() === tag).length > 1) {
        issues.push(issue(`${base}/tag`, "OV_FORM_TAG_DUPLICATE", `Duplicate instance tag: ${tag}.`));
    }
    const port = parsePort(draft.port);
    if (port === undefined || port < 1 || port > 65535) {
        issues.push(issue(`${base}/port`, "OV_FORM_PORT_INVALID", "Port must be an integer between 1 and 65535."));
    }
    else {
        const key = `${draft.protocol}/${port}`;
        if (allPortKeys.filter(k => k === key).length > 1) {
            issues.push(issue(`${base}/port`, "OV_FORM_PORT_DUPLICATE", `Duplicate ${draft.protocol}/${port} within this core config.`));
        }
    }
    const network = draft.network.trim();
    if (!network) {
        issues.push(issue(`${base}/network`, "OV_FORM_NETWORK_REQUIRED", "Network (CIDR) is required."));
    }
    else if (!isValidCidr(network)) {
        issues.push(issue(`${base}/network`, "OV_FORM_NETWORK_INVALID", "Network must be a valid CIDR, e.g. 10.8.0.0/24."));
    }
    const maxClients = draft.maxClients.trim();
    if (maxClients && (!/^\d+$/.test(maxClients) || Number(maxClients) < 1)) {
        issues.push(issue(`${base}/maxClients`, "OV_FORM_MAX_CLIENTS_INVALID", "Max clients must be a positive integer."));
    }
    draft.dnsServers.forEach((dns, dnsIndex) => {
        const trimmed = dns.trim();
        if (trimmed && !isValidIpAddress(trimmed)) {
            issues.push(issue(`${base}/dnsServers/${dnsIndex}`, "OV_FORM_DNS_INVALID", `"${dns}" is not a valid IP address.`));
        }
    });
    const verb = draft.verb.trim();
    if (verb && (!/^\d+$/.test(verb) || Number(verb) < 0 || Number(verb) > 11)) {
        issues.push(issue(`${base}/verb`, "OV_FORM_VERB_INVALID", "Verb must be an integer between 0 and 11."));
    }
    return issues;
}
function portKeyForDraft(instance) {
    const port = parsePort(instance.port);
    return `${instance.protocol}/${port ?? instance.port}`;
}
const PKI_FIELD_LABELS = {
    caCert: "CA certificate",
    serverCert: "server certificate",
    serverKey: "server key",
    tlsCryptKey: "tls-crypt static key"
};
/** Mirrors OpenVPNConfig._validate: at least one instance, unique tags/ports, and a complete pki section. */
export function validateOpenVPNCoreDraft(draft) {
    const issues = [];
    if (draft.instances.length === 0) {
        issues.push(issue("/instances", "OV_FORM_NO_INSTANCES", "At least one instance is required."));
    }
    const allTags = draft.instances.map(i => i.tag);
    const allPortKeys = draft.instances.map(portKeyForDraft);
    draft.instances.forEach((instance, index) => {
        issues.push(...validateOpenVPNInstanceDraft(instance, index, allTags, allPortKeys));
    });
    Object.keys(PKI_FIELD_LABELS).forEach(field => {
        if (!draft.pki[field].trim()) {
            issues.push(issue(`/pki/${field}`, "OV_FORM_PKI_MISSING", `PKI is incomplete: ${PKI_FIELD_LABELS[field]} is missing. Use "Generate PKI" before saving.`));
        }
    });
    return issues;
}
function instanceOptionsFromDraft(draft) {
    const port = parsePort(draft.port);
    if (port === undefined) {
        throw new Error(`/port: port must be an integer between 1 and 65535 (tag: ${draft.tag || "?"}).`);
    }
    const maxClients = draft.maxClients.trim() ? Number(draft.maxClients.trim()) : undefined;
    const verb = draft.verb.trim() ? Number(draft.verb.trim()) : undefined;
    const dnsServers = draft.dnsServers.map(v => v.trim()).filter(Boolean);
    return {
        tag: draft.tag.trim(),
        protocol: draft.protocol,
        port,
        network: draft.network.trim(),
        cipher: draft.cipher.trim() || undefined,
        auth: draft.auth.trim() || undefined,
        keepalive: draft.keepalive.trim() || undefined,
        maxClients,
        dnsServers: dnsServers.length > 0 ? dnsServers : undefined,
        redirectGateway: draft.redirectGateway,
        duplicateCN: draft.duplicateCN,
        verb
    };
}
export function createOpenVPNCoreConfigFromDraft(draft) {
    const issues = validateOpenVPNCoreDraft(draft);
    if (issues.length > 0) {
        const firstIssue = issues[0];
        throw new Error(`${firstIssue.path}: ${firstIssue.message}`);
    }
    return createOpenVPNCoreConfig({
        instances: draft.instances.map(instanceOptionsFromDraft),
        pki: {
            caCert: draft.pki.caCert.trim(),
            serverCert: draft.pki.serverCert.trim(),
            serverKey: draft.pki.serverKey.trim(),
            tlsCryptKey: draft.pki.tlsCryptKey.trim()
        }
    });
}
export function generateOpenVPNCoreConfigJsonFromDraft(draft, space = 2) {
    return JSON.stringify(createOpenVPNCoreConfigFromDraft(draft), null, space);
}
/** Exposed for callers that build a single instance's config JSON without a full draft (e.g. previews). */
export function createOpenVPNInstanceConfigFromDraft(draft) {
    return createOpenVPNInstanceConfig(instanceOptionsFromDraft(draft));
}
//# sourceMappingURL=form.js.map