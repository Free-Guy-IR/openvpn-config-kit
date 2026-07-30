import { createOpenVPNCoreConfig, createOpenVPNInstanceConfig } from "./core.js";
import { isValidCidr, isValidIpAddress } from "./validation.js";
import type { CreateOpenVPNInstanceOptions, OpenVPNCoreConfig, OpenVPNProtocol, OpenVPNValidationIssue } from "./types.js";

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

function issue(path: string, code: string, message: string): OpenVPNValidationIssue {
  return { path, code, message };
}

function parsePort(value: number | string): number | undefined {
  if (typeof value === "number") return Number.isInteger(value) ? value : undefined;
  const trimmed = value.trim();
  if (!/^\d+$/.test(trimmed)) return undefined;
  return Number(trimmed);
}

function randomPort(): number {
  return Math.floor(Math.random() * (65535 - 10000 + 1)) + 10000;
}

function uniqueDefaultTag(existingTags: readonly string[]): string {
  const taken = new Set(existingTags.map(t => t.trim()));
  if (!taken.has("OpenVPN")) return "OpenVPN";
  let n = 2;
  while (taken.has(`OpenVPN_${n}`)) n += 1;
  return `OpenVPN_${n}`;
}

export function createDefaultOpenVPNInstanceDraft(existingTags: readonly string[] = []): OpenVPNInstanceDraft {
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

export function createDefaultOpenVPNPKIDraft(): OpenVPNPKIDraft {
  return { caCert: "", serverCert: "", serverKey: "", tlsCryptKey: "" };
}

export function createDefaultOpenVPNCoreDraft(): OpenVPNCoreDraft {
  return {
    instances: [createDefaultOpenVPNInstanceDraft([])],
    pki: createDefaultOpenVPNPKIDraft()
  };
}

/** True once every PKI field has been populated (typically right after a "Generate PKI" call). */
export function isOpenVPNPKIDraftComplete(pki: OpenVPNPKIDraft): boolean {
  return Boolean(pki.caCert.trim() && pki.serverCert.trim() && pki.serverKey.trim() && pki.tlsCryptKey.trim());
}

/** Mirrors the validation.ts semantic rules, at the draft/form level (pre-serialization). */
export function validateOpenVPNInstanceDraft(draft: OpenVPNInstanceDraft, index: number, allTags: readonly string[], allPortKeys: readonly string[]): OpenVPNValidationIssue[] {
  const issues: OpenVPNValidationIssue[] = [];
  const base = `/instances/${index}`;

  const tag = draft.tag.trim();
  if (!tag) {
    issues.push(issue(`${base}/tag`, "OV_FORM_TAG_REQUIRED", "Tag is required."));
  } else if (allTags.filter(t => t.trim() === tag).length > 1) {
    issues.push(issue(`${base}/tag`, "OV_FORM_TAG_DUPLICATE", `Duplicate instance tag: ${tag}.`));
  }

  const port = parsePort(draft.port);
  if (port === undefined || port < 1 || port > 65535) {
    issues.push(issue(`${base}/port`, "OV_FORM_PORT_INVALID", "Port must be an integer between 1 and 65535."));
  } else {
    const key = `${draft.protocol}/${port}`;
    if (allPortKeys.filter(k => k === key).length > 1) {
      issues.push(issue(`${base}/port`, "OV_FORM_PORT_DUPLICATE", `Duplicate ${draft.protocol}/${port} within this core config.`));
    }
  }

  const network = draft.network.trim();
  if (!network) {
    issues.push(issue(`${base}/network`, "OV_FORM_NETWORK_REQUIRED", "Network (CIDR) is required."));
  } else if (!isValidCidr(network)) {
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

function portKeyForDraft(instance: OpenVPNInstanceDraft): string {
  const port = parsePort(instance.port);
  return `${instance.protocol}/${port ?? instance.port}`;
}

const PKI_FIELD_LABELS: Record<keyof OpenVPNPKIDraft, string> = {
  caCert: "CA certificate",
  serverCert: "server certificate",
  serverKey: "server key",
  tlsCryptKey: "tls-crypt static key"
};

/** Mirrors OpenVPNConfig._validate: at least one instance, unique tags/ports, and a complete pki section. */
export function validateOpenVPNCoreDraft(draft: OpenVPNCoreDraft): OpenVPNValidationIssue[] {
  const issues: OpenVPNValidationIssue[] = [];

  if (draft.instances.length === 0) {
    issues.push(issue("/instances", "OV_FORM_NO_INSTANCES", "At least one instance is required."));
  }

  const allTags = draft.instances.map(i => i.tag);
  const allPortKeys = draft.instances.map(portKeyForDraft);
  draft.instances.forEach((instance, index) => {
    issues.push(...validateOpenVPNInstanceDraft(instance, index, allTags, allPortKeys));
  });

  (Object.keys(PKI_FIELD_LABELS) as (keyof OpenVPNPKIDraft)[]).forEach(field => {
    if (!draft.pki[field].trim()) {
      issues.push(
        issue(`/pki/${field}`, "OV_FORM_PKI_MISSING", `PKI is incomplete: ${PKI_FIELD_LABELS[field]} is missing. Use "Generate PKI" before saving.`)
      );
    }
  });

  return issues;
}

function instanceOptionsFromDraft(draft: OpenVPNInstanceDraft): CreateOpenVPNInstanceOptions {
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

export function createOpenVPNCoreConfigFromDraft(draft: OpenVPNCoreDraft): OpenVPNCoreConfig {
  const issues = validateOpenVPNCoreDraft(draft);
  if (issues.length > 0) {
    const firstIssue = issues[0]!;
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

export function generateOpenVPNCoreConfigJsonFromDraft(draft: OpenVPNCoreDraft, space = 2): string {
  return JSON.stringify(createOpenVPNCoreConfigFromDraft(draft), null, space);
}

/** Exposed for callers that build a single instance's config JSON without a full draft (e.g. previews). */
export function createOpenVPNInstanceConfigFromDraft(draft: OpenVPNInstanceDraft) {
  return createOpenVPNInstanceConfig(instanceOptionsFromDraft(draft));
}
