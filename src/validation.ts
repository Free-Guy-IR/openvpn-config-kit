import { z } from "zod";
import type {
  JsonValue,
  OpenVPNCoreConfig,
  OpenVPNInstance,
  OpenVPNValidationIssue,
  OpenVPNValidationResult
} from "./types.js";

const jsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number().finite(),
    z.boolean(),
    z.null(),
    z.array(jsonValueSchema),
    z.record(jsonValueSchema)
  ])
);

const instanceSchema = z
  .object({
    tag: z.string(),
    protocol: z.enum(["udp", "tcp"]),
    port: z.number(),
    network: z.string(),
    cipher: z.string().optional(),
    auth: z.string().optional(),
    keepalive: z.string().optional(),
    max_clients: z.number().optional(),
    dns_servers: z.array(z.string()).optional(),
    redirect_gateway: z.boolean().optional(),
    duplicate_cn: z.boolean().optional(),
    verb: z.number().optional()
  })
  .catchall(jsonValueSchema);

const pkiSchema = z
  .object({
    ca_cert: z.string().optional(),
    server_cert: z.string().optional(),
    server_key: z.string().optional(),
    tls_crypt_key: z.string().optional()
  })
  .catchall(jsonValueSchema);

const rawOpenVPNCoreConfigSchema = z
  .object({
    instances: z.array(instanceSchema),
    pki: pkiSchema
  })
  .catchall(jsonValueSchema);

const REQUIRED_PKI_FIELDS = ["ca_cert", "server_cert", "server_key", "tls_crypt_key"] as const;

function issue(path: string, code: string, message: string): OpenVPNValidationIssue {
  return { path, code, message };
}

function pathForZod(path: readonly (string | number)[]): string {
  if (path.length === 0) return "/";
  return `/${path.map(String).join("/")}`;
}

/**
 * Lightweight CIDR validator (IPv4 and IPv6), deliberately not a full RFC parser -
 * mirrors what Python's `ipaddress.ip_network(value, strict=False)` accepts closely
 * enough for form-level UX; the panel is still the source of truth server-side
 * (`OpenVPNConfig._validate_instance`).
 */
function isValidIPv4(address: string): boolean {
  const parts = address.split(".");
  if (parts.length !== 4) return false;
  return parts.every(part => {
    if (!/^\d{1,3}$/.test(part)) return false;
    if (part.length > 1 && part.startsWith("0")) return false;
    const n = Number(part);
    return n >= 0 && n <= 255;
  });
}

function isValidIPv6(address: string): boolean {
  if (address === "::") return true;
  if (!/^[0-9a-fA-F:]+$/.test(address)) return false;
  if ((address.match(/::/g) ?? []).length > 1) return false;
  const groups = address.split(":").filter(g => g.length > 0);
  if (groups.length === 0 || groups.length > 8) return false;
  return groups.every(g => /^[0-9a-fA-F]{1,4}$/.test(g));
}

export function isValidIpAddress(value: string): boolean {
  return isValidIPv4(value) || isValidIPv6(value);
}

export function isValidCidr(value: string): boolean {
  const parts = value.split("/");
  if (parts.length !== 2) return false;
  const [address, prefixRaw] = parts;
  if (!address || !prefixRaw || !/^\d{1,3}$/.test(prefixRaw)) return false;
  const prefix = Number(prefixRaw);
  if (isValidIPv4(address)) return prefix >= 0 && prefix <= 32;
  if (isValidIPv6(address)) return prefix >= 0 && prefix <= 128;
  return false;
}

/** Mirrors `OpenVPNConfig._validate_instance`. Mutates `seenTags`/`seenPorts` as it goes, like the Python loop. */
function validateInstance(instance: z.infer<typeof instanceSchema>, index: number, seenTags: Set<string>, seenPorts: Set<string>): void {
  const path = `/instances/${index}`;

  const tag = instance.tag.trim();
  if (!tag) {
    throw new Error(`${path}/tag: all instances must have a unique tag.`);
  }
  if (seenTags.has(tag)) {
    throw new Error(`${path}/tag: duplicate instance tag: ${tag}.`);
  }
  seenTags.add(tag);

  if (!Number.isInteger(instance.port) || instance.port < 1 || instance.port > 65535) {
    throw new Error(`${path}/port: port must be an integer between 1 and 65535.`);
  }
  const portKey = `${instance.protocol}/${instance.port}`;
  if (seenPorts.has(portKey)) {
    throw new Error(`${path}/port: duplicate ${instance.protocol}/${instance.port} within this core config.`);
  }
  seenPorts.add(portKey);

  if (!instance.network.trim()) {
    throw new Error(`${path}/network: network (CIDR) is required.`);
  }
  if (!isValidCidr(instance.network.trim())) {
    throw new Error(`${path}/network: network must be a valid CIDR, got ${JSON.stringify(instance.network)}.`);
  }

  if (instance.max_clients !== undefined && (!Number.isInteger(instance.max_clients) || instance.max_clients < 1)) {
    throw new Error(`${path}/max_clients: max_clients must be a positive integer.`);
  }

  if (instance.dns_servers) {
    instance.dns_servers.forEach((dns, dnsIndex) => {
      if (!isValidIpAddress(dns.trim())) {
        throw new Error(`${path}/dns_servers/${dnsIndex}: "${dns}" is not a valid IP address.`);
      }
    });
  }

  if (instance.verb !== undefined && (!Number.isInteger(instance.verb) || instance.verb < 0 || instance.verb > 11)) {
    throw new Error(`${path}/verb: verb must be an integer between 0 and 11.`);
  }
}

/** Mirrors `OpenVPNConfig._validate`: non-empty instances, unique tags/ports, and a complete pki section. */
function normalizeConfig(input: z.infer<typeof rawOpenVPNCoreConfigSchema>): OpenVPNCoreConfig {
  if (input.instances.length === 0) {
    throw new Error("/instances: config doesn't have instances.");
  }

  const seenTags = new Set<string>();
  const seenPorts = new Set<string>();
  input.instances.forEach((instance, index) => validateInstance(instance, index, seenTags, seenPorts));

  for (const field of REQUIRED_PKI_FIELDS) {
    const value = input.pki[field];
    if (!value || !value.trim()) {
      throw new Error(`/pki/${field}: pki.${field} is required - generate it via the "Generate PKI" action before saving.`);
    }
  }

  return input as OpenVPNCoreConfig;
}

export function validateOpenVPNCoreConfig(input: unknown): OpenVPNValidationResult {
  const parsed = rawOpenVPNCoreConfigSchema.safeParse(input);
  if (!parsed.success) {
    return {
      ok: false,
      issues: parsed.error.issues.map(zodIssue =>
        issue(
          pathForZod(zodIssue.path.filter((part): part is string | number => typeof part === "string" || typeof part === "number")),
          "OV_SCHEMA_INVALID_CORE_CONFIG",
          zodIssue.message
        )
      )
    };
  }

  const issues: OpenVPNValidationIssue[] = [];
  let config: OpenVPNCoreConfig | undefined;

  try {
    config = normalizeConfig(parsed.data);
  } catch (error) {
    const rawMessage = error instanceof Error ? error.message : "Invalid OpenVPN core config.";
    const match = rawMessage.match(/^(\/[^:]*):\s*(.+)$/);
    issues.push(issue(match?.[1] ?? "/", "OV_SEMANTIC_INVALID_CORE_CONFIG", match?.[2] ?? rawMessage));
  }

  if (!config) return { ok: false, issues };
  return { ok: true, config, issues: [] };
}

export function assertValidOpenVPNCoreConfig(input: unknown): OpenVPNCoreConfig {
  const result = validateOpenVPNCoreConfig(input);
  if (!result.ok) {
    const firstIssue = result.issues[0];
    throw new Error(firstIssue ? `${firstIssue.path}: ${firstIssue.message}` : "Invalid OpenVPN core config.");
  }
  return result.config;
}

export function isOpenVPNInstance(value: unknown): value is OpenVPNInstance {
  return !!value && typeof value === "object" && typeof (value as Record<string, unknown>).tag === "string" && (value as Record<string, unknown>).protocol !== undefined;
}
