import { describe, expect, it } from "bun:test";
import {
  createDefaultOpenVPNCoreDraft,
  createDefaultOpenVPNInstanceDraft,
  createOpenVPNCoreConfig,
  createOpenVPNCoreConfigFromDraft,
  createOpenVPNCorePayload,
  createOpenVPNInstanceConfig,
  generateOpenVPNCoreConfigJson,
  generateOpenVPNCoreConfigJsonFromDraft,
  isOpenVPNPKIDraftComplete,
  isValidCidr,
  isValidIpAddress,
  validateOpenVPNCoreConfig,
  validateOpenVPNCoreDraft
} from "../src/index.js";

const VALID_PKI = {
  caCert: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
  serverCert: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
  serverKey: "-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----",
  tlsCryptKey: "-----BEGIN OpenVPN Static key V1-----\n...\n-----END OpenVPN Static key V1-----"
};

const VALID_PKI_RAW = {
  ca_cert: VALID_PKI.caCert,
  server_cert: VALID_PKI.serverCert,
  server_key: VALID_PKI.serverKey,
  tls_crypt_key: VALID_PKI.tlsCryptKey
};

describe("openvpn-config-kit", () => {
  it("creates a minimal default openvpn core config", () => {
    const config = createOpenVPNCoreConfig({
      instances: [{ tag: "udp-main", protocol: "udp", port: 1194, network: "10.8.0.0/24" }],
      pki: VALID_PKI
    });

    expect(config).toEqual({
      instances: [{ tag: "udp-main", protocol: "udp", port: 1194, network: "10.8.0.0/24" }],
      pki: VALID_PKI_RAW
    });

    const json = generateOpenVPNCoreConfigJson({
      instances: [{ tag: "udp-main", protocol: "udp", port: 1194, network: "10.8.0.0/24" }],
      pki: VALID_PKI
    });
    expect(JSON.parse(json)).toMatchObject({ instances: [{ tag: "udp-main", protocol: "udp" }] });
  });

  it("supports the full instance option set", () => {
    const instance = createOpenVPNInstanceConfig({
      tag: "tcp-fallback",
      protocol: "tcp",
      port: 443,
      network: "10.9.0.0/24",
      cipher: "CHACHA20-POLY1305",
      auth: "SHA512",
      keepalive: "10 60",
      maxClients: 250,
      dnsServers: ["1.1.1.1", "8.8.8.8"],
      redirectGateway: false,
      duplicateCN: false,
      verb: 4
    });

    expect(instance).toMatchObject({
      tag: "tcp-fallback",
      protocol: "tcp",
      port: 443,
      cipher: "CHACHA20-POLY1305",
      auth: "SHA512",
      max_clients: 250,
      dns_servers: ["1.1.1.1", "8.8.8.8"],
      redirect_gateway: false,
      duplicate_cn: false,
      verb: 4
    });
  });

  it("builds a create payload shaped for the panel API", () => {
    const payload = createOpenVPNCorePayload({
      name: "my-openvpn",
      instances: [{ tag: "udp-main", protocol: "udp", port: 1194, network: "10.8.0.0/24" }],
      pki: VALID_PKI
    });
    expect(payload).toMatchObject({
      name: "my-openvpn",
      type: "openvpn",
      exclude_inbound_tags: [],
      fallbacks_inbound_tags: []
    });
    expect(payload.config.instances).toHaveLength(1);
  });

  it("validates CIDR and IP helpers", () => {
    expect(isValidCidr("10.8.0.0/24")).toBe(true);
    expect(isValidCidr("2001:db8::/32")).toBe(true);
    expect(isValidCidr("not-a-cidr")).toBe(false);
    expect(isValidCidr("10.8.0.0")).toBe(false);
    expect(isValidCidr("10.8.0.0/33")).toBe(false);
    expect(isValidCidr("999.1.1.1/24")).toBe(false);

    expect(isValidIpAddress("1.1.1.1")).toBe(true);
    expect(isValidIpAddress("::1")).toBe(true);
    expect(isValidIpAddress("not-an-ip")).toBe(false);
  });

  it("rejects configs with no instances, bad ports, bad CIDR, duplicate tags/ports, and incomplete pki", () => {
    expect(validateOpenVPNCoreConfig({ instances: [], pki: VALID_PKI_RAW }).ok).toBe(false);

    const badPort = validateOpenVPNCoreConfig({
      instances: [{ tag: "a", protocol: "udp", port: 70000, network: "10.8.0.0/24" }],
      pki: VALID_PKI_RAW
    });
    expect(badPort.ok).toBe(false);

    const badCidr = validateOpenVPNCoreConfig({
      instances: [{ tag: "a", protocol: "udp", port: 1194, network: "not-a-cidr" }],
      pki: VALID_PKI_RAW
    });
    expect(badCidr.ok).toBe(false);

    const dupTags = validateOpenVPNCoreConfig({
      instances: [
        { tag: "a", protocol: "udp", port: 1194, network: "10.8.0.0/24" },
        { tag: "a", protocol: "tcp", port: 443, network: "10.9.0.0/24" }
      ],
      pki: VALID_PKI_RAW
    });
    expect(dupTags.ok).toBe(false);

    const dupPorts = validateOpenVPNCoreConfig({
      instances: [
        { tag: "a", protocol: "udp", port: 1194, network: "10.8.0.0/24" },
        { tag: "b", protocol: "udp", port: 1194, network: "10.9.0.0/24" }
      ],
      pki: VALID_PKI_RAW
    });
    expect(dupPorts.ok).toBe(false);

    // Same port number but different protocol is fine - the backend keys uniqueness by (protocol, port).
    const samePortDifferentProtocol = validateOpenVPNCoreConfig({
      instances: [
        { tag: "a", protocol: "udp", port: 1194, network: "10.8.0.0/24" },
        { tag: "b", protocol: "tcp", port: 1194, network: "10.9.0.0/24" }
      ],
      pki: VALID_PKI_RAW
    });
    expect(samePortDifferentProtocol.ok).toBe(true);

    const missingPki = validateOpenVPNCoreConfig({
      instances: [{ tag: "a", protocol: "udp", port: 1194, network: "10.8.0.0/24" }],
      pki: { ca_cert: "x", server_cert: "", server_key: "x", tls_crypt_key: "x" }
    });
    expect(missingPki.ok).toBe(false);

    const ok = validateOpenVPNCoreConfig({
      instances: [{ tag: "a", protocol: "udp", port: 1194, network: "10.8.0.0/24" }],
      pki: VALID_PKI_RAW
    });
    expect(ok.ok).toBe(true);
  });

  it("creates unique default instance drafts and round-trips through draft -> config", () => {
    const draft = createDefaultOpenVPNCoreDraft();
    expect(draft.instances).toHaveLength(1);
    expect(draft.instances[0]!.tag).toBe("OpenVPN");
    expect(isOpenVPNPKIDraftComplete(draft.pki)).toBe(false);

    const second = createDefaultOpenVPNInstanceDraft(draft.instances.map(i => i.tag));
    expect(second.tag).toBe("OpenVPN_2");

    const draftWithTwo = { ...draft, instances: [...draft.instances, { ...second, protocol: "tcp" as const, port: 443 }], pki: VALID_PKI };
    expect(validateOpenVPNCoreDraft(draftWithTwo)).toEqual([]);
    expect(isOpenVPNPKIDraftComplete(draftWithTwo.pki)).toBe(true);

    const config = createOpenVPNCoreConfigFromDraft(draftWithTwo);
    expect(config.instances).toHaveLength(2);

    const json = generateOpenVPNCoreConfigJsonFromDraft(draftWithTwo);
    expect(JSON.parse(json)).toEqual(config);
  });

  it("flags duplicate tags, duplicate ports, and missing pki at the draft level", () => {
    const draft = createDefaultOpenVPNCoreDraft();
    const dupTagDraft = { ...draft, instances: [draft.instances[0]!, { ...draft.instances[0]! }] };
    const dupIssues = validateOpenVPNCoreDraft(dupTagDraft);
    expect(dupIssues.some(i => i.code === "OV_FORM_TAG_DUPLICATE")).toBe(true);
    expect(dupIssues.some(i => i.code === "OV_FORM_PORT_DUPLICATE")).toBe(true);
    expect(dupIssues.some(i => i.code === "OV_FORM_PKI_MISSING")).toBe(true);

    const badNetworkDraft = { ...draft, instances: [{ ...draft.instances[0]!, network: "nope" }] };
    const netIssues = validateOpenVPNCoreDraft(badNetworkDraft);
    expect(netIssues.some(i => i.code === "OV_FORM_NETWORK_INVALID")).toBe(true);

    const badDnsDraft = { ...draft, instances: [{ ...draft.instances[0]!, dnsServers: ["not-an-ip"] }] };
    const dnsIssues = validateOpenVPNCoreDraft(badDnsDraft);
    expect(dnsIssues.some(i => i.code === "OV_FORM_DNS_INVALID")).toBe(true);

    const badMaxClientsDraft = { ...draft, instances: [{ ...draft.instances[0]!, maxClients: "0" }] };
    expect(validateOpenVPNCoreDraft(badMaxClientsDraft).some(i => i.code === "OV_FORM_MAX_CLIENTS_INVALID")).toBe(true);

    const badVerbDraft = { ...draft, instances: [{ ...draft.instances[0]!, verb: "42" }] };
    expect(validateOpenVPNCoreDraft(badVerbDraft).some(i => i.code === "OV_FORM_VERB_INVALID")).toBe(true);
  });

  it("throws a descriptive error building a config from an invalid draft", () => {
    const draft = createDefaultOpenVPNCoreDraft();
    expect(() => createOpenVPNCoreConfigFromDraft(draft)).toThrow(/pki/);
  });
});
