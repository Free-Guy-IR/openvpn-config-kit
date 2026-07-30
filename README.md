# @pasarguard/openvpn-config-kit

Browser-safe TypeScript helpers for generating and validating PasarGuard OpenVPN core
configuration JSON.

Mirrors the panel's `app/core/openvpn.py::OpenVPNConfig` backend. Unlike Xray/sing-box
(one process, many inbounds), OpenVPN has no single-process multi-listener mode - each
configured **instance** (a protocol+port combination, e.g. UDP/1194 and TCP/443) runs as
its own independent `openvpn` subprocess. An OpenVPN core config here is always:

```json
{
  "instances": [
    {
      "tag": "udp-main",
      "protocol": "udp",
      "port": 1194,
      "network": "10.8.0.0/24",
      "cipher": "AES-256-GCM",
      "auth": "SHA256",
      "keepalive": "10 60",
      "max_clients": 500,
      "dns_servers": ["1.1.1.1", "8.8.8.8"],
      "redirect_gateway": true,
      "duplicate_cn": true,
      "verb": 3
    }
  ],
  "pki": {
    "ca_cert": "-----BEGIN CERTIFICATE-----...",
    "server_cert": "-----BEGIN CERTIFICATE-----...",
    "server_key": "-----BEGIN PRIVATE KEY-----...",
    "tls_crypt_key": "-----BEGIN OpenVPN Static key V1-----...-----END OpenVPN Static key V1-----"
  }
}
```

Modeled directly on the file layout and tooling of `@pasarguard/singbox-config-kit`,
adapted for a **list** of independently-configured instances (different ports/protocols)
instead of a single inbound type.

## PKI is not generated here

`pki` (CA + server cert/key + tls-crypt static key) is server-side only - X.509
generation needs the `cryptography` Python library, so there is no browser-safe
equivalent of the panel's `generate_openvpn_pki()`. This kit only stores, validates, and
serializes the four PEM/armored strings; the dashboard fetches them from the panel's
generate-pki endpoint and passes them in via `OpenVPNPKIDraft` / `CreateOpenVPNPKIOptions`.
A draft's `pki` fields are optional/empty until that call has been made - saving a config
with any field missing fails validation (`OV_FORM_PKI_MISSING` / `OV_SEMANTIC_INVALID_CORE_CONFIG`),
matching the panel's `OpenVPNConfig._validate` rejecting an incomplete `pki` section.

## Modules

- `types.ts` — plain config shape (`OpenVPNCoreConfig`, `OpenVPNInstance`, `OpenVPNPKI`, ...).
- `validation.ts` — Zod schema + semantic validators (`validateOpenVPNCoreConfig`), kept
  compatible with the Python-side `OpenVPNConfig._validate` / `_validate_instance` rules:
  non-empty `instances`, unique non-empty tags, `protocol` in `udp`/`tcp`, `port` in
  `1..65535` unique per `(protocol, port)` pair, `network` a valid CIDR, `max_clients` (if
  present) a positive integer, and all four `pki` fields non-empty. Also exports
  `isValidCidr` / `isValidIpAddress`, small self-contained IPv4/IPv6 checkers used for the
  `network` and `dns_servers` fields (this kit has no dependency on Node's `net`/`dns`
  modules, so it stays usable in the browser).
- `form.ts` — a "draft" shape for form state (`OpenVPNCoreDraft`, `OpenVPNInstanceDraft`,
  `OpenVPNPKIDraft`) distinct from the final JSON config, plus draft helpers used by the
  dashboard's visual editor (`createDefaultOpenVPNCoreDraft`, `createDefaultOpenVPNInstanceDraft`,
  `validateOpenVPNCoreDraft`, `createOpenVPNCoreConfigFromDraft`,
  `generateOpenVPNCoreConfigJsonFromDraft`, `isOpenVPNPKIDraftComplete`). Cross-instance
  rules (duplicate tags, duplicate `(protocol, port)` pairs) are surfaced as config-level
  issues (`/instances/<n>/tag`, `/instances/<n>/port`), not per-instance-only checks.
- `core.ts` — pure config-building functions (`createOpenVPNInstanceConfig`,
  `createOpenVPNCoreConfig`, `createOpenVPNCorePayload`).
