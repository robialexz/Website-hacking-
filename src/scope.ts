import { readFileSync } from "node:fs";

export interface ScopeConfig {
  readonly mode: "laboratory";
  readonly approvedOrigins: readonly string[];
  readonly approvedPathPrefixes: readonly string[];
  readonly budgets: {
    readonly maxRequestsPerAudit: number;
    readonly maxConcurrentAudits: number;
    readonly timeoutMs: number;
  };
}

export interface ScopedFetchResponse {
  readonly status: number;
  readonly headers: Headers;
  /** The response body decoded as UTF-8 text. */
  readonly text: string;
}

type ParsedScopeUrl = {
  url: URL;
  originKey: string;
};

const requestCounts = new WeakMap<object, number>();
const redirectStatuses = new Set([301, 302, 303, 307, 308]);

function fail(message: string): never {
  throw new Error(message);
}

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function parseLoopbackHttpUrl(value: string | URL, label: string): ParsedScopeUrl {
  const raw = value instanceof URL ? value.href : value;
  if (typeof raw !== "string" || raw.length === 0) {
    fail(`${label} must be an absolute HTTP URL`);
  }

  // Parsing the authority before URL normalization preserves explicit default ports
  // such as :80, which URL.port intentionally removes.
  const absoluteMatch = /^http:\/\/([^/?#]*)(?:[/?#]|$)/i.exec(raw);
  if (!absoluteMatch) {
    fail(`${label} must use the http protocol`);
  }

  const authority = absoluteMatch[1];
  if (authority.includes("@")) {
    fail(`${label} must not contain credentials`);
  }

  const authorityMatch = /^(127\.0\.0\.1|\[::1\]):([1-9]\d{0,4})$/i.exec(authority);
  if (!authorityMatch) {
    fail(`${label} must use a literal loopback IP and an explicit port`);
  }

  const host = authorityMatch[1].toLowerCase();
  const port = Number(authorityMatch[2]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    fail(`${label} has an invalid port`);
  }

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    fail(`${label} must be a valid absolute HTTP URL`);
  }

  if (url.protocol !== "http:" || url.username !== "" || url.password !== "") {
    fail(`${label} must be an HTTP URL without credentials`);
  }
  const expectedHostname = host === "[::1]" ? "[::1]" : "127.0.0.1";
  if (url.hostname !== expectedHostname) {
    fail(`${label} must use the literal loopback IP 127.0.0.1 or ::1`);
  }

  return {
    url,
    originKey: `http://${host}:${port}`,
  };
}

function validatePathPrefix(value: unknown, index: number): string {
  if (typeof value !== "string" || !value.startsWith("/")) {
    fail(`approvedPathPrefixes[${index}] must be an absolute path prefix`);
  }
  if (value.startsWith("//") || /[\\?#\u0000-\u001f]/.test(value)) {
    fail(`approvedPathPrefixes[${index}] contains unsupported characters`);
  }

  let normalized: string;
  try {
    normalized = new URL(value, "http://127.0.0.1").pathname;
  } catch {
    fail(`approvedPathPrefixes[${index}] must be a valid path prefix`);
  }
  if (normalized !== value) {
    fail(`approvedPathPrefixes[${index}] must already be in normalized form`);
  }
  return value;
}

function validateScopeConfig(value: unknown): asserts value is ScopeConfig {
  const config = asRecord(value, "scope config");
  if (config.mode !== "laboratory") {
    fail('scope config mode must be "laboratory"');
  }

  if (!Array.isArray(config.approvedOrigins) || config.approvedOrigins.length === 0) {
    fail("approvedOrigins must contain at least one origin");
  }
  for (let index = 0; index < config.approvedOrigins.length; index += 1) {
    const origin = config.approvedOrigins[index];
    if (typeof origin !== "string") {
      fail(`approvedOrigins[${index}] must be a string`);
    }
    const parsed = parseLoopbackHttpUrl(origin, `approvedOrigins[${index}]`);
    if (
      parsed.url.pathname !== "/" ||
      parsed.url.search !== "" ||
      parsed.url.hash !== ""
    ) {
      fail(`approvedOrigins[${index}] must contain only an origin`);
    }
  }

  if (!Array.isArray(config.approvedPathPrefixes) || config.approvedPathPrefixes.length === 0) {
    fail("approvedPathPrefixes must contain at least one path prefix");
  }
  for (let index = 0; index < config.approvedPathPrefixes.length; index += 1) {
    validatePathPrefix(config.approvedPathPrefixes[index], index);
  }

  const budgets = asRecord(config.budgets, "budgets");
  const { maxRequestsPerAudit, maxConcurrentAudits, timeoutMs } = budgets;
  if (!Number.isInteger(maxRequestsPerAudit) || (maxRequestsPerAudit as number) < 0) {
    fail("budgets.maxRequestsPerAudit must be a non-negative integer");
  }
  if (!Number.isInteger(maxConcurrentAudits) || (maxConcurrentAudits as number) < 1) {
    fail("budgets.maxConcurrentAudits must be a positive integer");
  }
  if (!Number.isInteger(timeoutMs) || (timeoutMs as number) < 1) {
    fail("budgets.timeoutMs must be a positive integer");
  }
}

function originKeys(config: ScopeConfig): Set<string> {
  return new Set(config.approvedOrigins.map((origin) => parseLoopbackHttpUrl(origin, "approved origin").originKey));
}

/** Read and validate the laboratory-only scope config from a JSON file. */
export function loadScopeConfig(configPath: string): ScopeConfig {
  if (typeof configPath !== "string" || configPath.length === 0) {
    fail("configPath must be a non-empty path string");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(configPath, "utf8"));
  } catch (error) {
    throw new Error(`Could not read scope config at ${configPath}`, { cause: error });
  }
  validateScopeConfig(parsed);

  // Copy and freeze the security-relevant fields so later mutation cannot widen scope.
  const config = Object.freeze({
    mode: "laboratory" as const,
    approvedOrigins: Object.freeze([...parsed.approvedOrigins]),
    approvedPathPrefixes: Object.freeze([...parsed.approvedPathPrefixes]),
    budgets: Object.freeze({
      maxRequestsPerAudit: parsed.budgets.maxRequestsPerAudit,
      maxConcurrentAudits: parsed.budgets.maxConcurrentAudits,
      timeoutMs: parsed.budgets.timeoutMs,
    }),
  });
  requestCounts.set(config, 0);
  return config;
}

/** Throw unless a URL is covered by the laboratory's exact origin and path allowlists. */
export function assertInScope(value: string | URL, config: ScopeConfig): URL {
  validateScopeConfig(config);
  const parsed = parseLoopbackHttpUrl(value, "URL");
  if (!originKeys(config).has(parsed.originKey)) {
    fail("URL origin is outside the approved scope");
  }
  if (!config.approvedPathPrefixes.some((prefix) => parsed.url.pathname.startsWith(prefix))) {
    fail("URL path is outside the approved scope");
  }
  return parsed.url;
}

/** Fetch one in-scope URL with a per-config request budget and timeout. Redirects are disabled. */
export async function scopedFetch(
  value: string | URL,
  config: ScopeConfig,
  init: RequestInit = {},
): Promise<ScopedFetchResponse> {
  const targetUrl = assertInScope(value, config);
  const count = requestCounts.get(config) ?? 0;
  if (count >= config.budgets.maxRequestsPerAudit) {
    fail("Scope request budget exhausted");
  }
  requestCounts.set(config, count + 1);

  if (init.redirect === "follow") {
    fail("Network redirects are disabled by scopedFetch");
  }

  const timeoutSignal = AbortSignal.timeout(config.budgets.timeoutMs);
  const signal = init.signal ? AbortSignal.any([init.signal, timeoutSignal]) : timeoutSignal;

  try {
    const response = await fetch(targetUrl, {
      ...init,
      redirect: "manual",
      signal,
    });

    if (redirectStatuses.has(response.status)) {
      const location = response.headers.get("location");
      if (location) {
        try {
          assertInScope(new URL(location, targetUrl), config);
        } catch {
          fail("Redirect destination is outside the approved scope");
        }
      }
      fail("Network redirects are disabled by scopedFetch");
    }

    const text = await response.text();
    return {
      status: response.status,
      headers: response.headers,
      text,
    };
  } catch (error) {
    if (timeoutSignal.aborted) {
      throw new Error(`Scoped request timed out after ${config.budgets.timeoutMs}ms`, { cause: error });
    }
    throw error;
  }
}
