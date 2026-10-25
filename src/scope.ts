import { readFileSync } from "node:fs";
import { posix, win32 } from "node:path";
import { isIP } from "node:net";

export interface ScopeConfig {
  readonly mode: "laboratory";
  readonly approvedOrigins: readonly string[];
  readonly approvedPathPrefixes: readonly string[];
  readonly approvedServices: readonly string[];
  readonly sourceDirectories: readonly string[];
  readonly testAccounts: readonly { readonly name: string; readonly role: string }[];
  readonly approvedCallbacks: readonly string[];
  readonly publicReadOnlyPages: readonly string[];
  readonly resetProcedure: string;
  readonly budgets: {
    readonly maxRequestsPerAudit: number;
    readonly maxConcurrentAudits: number;
    readonly timeoutMs: number;
    readonly maxSourceFiles: number;
    readonly maxSourceBytes: number;
    readonly maxPublicPages: number;
    readonly maxPublicBytesPerPage: number;
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

function validateSourceDirectory(value: unknown, index: number): string {
  if (typeof value !== "string" || value.length === 0 || value.includes("\u0000")) {
    fail(`sourceDirectories[${index}] must be a normalized local project directory`);
  }
  if (process.platform === "win32" && win32.isAbsolute(value)) {
    if (win32.normalize(value) !== value || value === win32.parse(value).root) {
      fail(`sourceDirectories[${index}] must be a normalized local project directory`);
    }
    return value;
  }
  if (process.platform !== "win32" && posix.isAbsolute(value)) {
    if (posix.normalize(value) !== value || value === posix.parse(value).root) {
      fail(`sourceDirectories[${index}] must be a normalized local project directory`);
    }
    return value;
  }
  if ((process.platform === "win32" && posix.isAbsolute(value)) || (process.platform !== "win32" && win32.isAbsolute(value))) {
    fail(`sourceDirectories[${index}] must be a normalized local project directory`);
  }
  if (value.includes("\\")) fail(`sourceDirectories[${index}] must use normalized project-relative paths`);
  const withoutDotPrefix = value.startsWith("./") ? value.slice(2) : value;
  const normalized = posix.normalize(withoutDotPrefix);
  if (
    withoutDotPrefix.length === 0 ||
    normalized !== withoutDotPrefix ||
    normalized === "." ||
    normalized === ".." ||
    normalized.startsWith(`..${posix.sep}`)
  ) {
    fail(`sourceDirectories[${index}] must be normalized and remain inside the project`);
  }
  return `.${posix.sep}${normalized}`;
}

function validateStringList(value: unknown, label: string, minLength = 1): string[] {
  if (!Array.isArray(value) || value.length < minLength) fail(`${label} must contain at least ${minLength} item(s)`);
  const values: string[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const entry = value[index];
    if (typeof entry !== "string" || entry.trim().length === 0 || entry.length > 240) {
      fail(`${label}[${index}] must be a non-empty string of at most 240 characters`);
    }
    values.push(entry.trim());
  }
  if (new Set(values).size !== values.length) fail(`${label} must not contain duplicates`);
  return values;
}

function validatePublicReadOnlyPage(value: unknown, index: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048) {
    fail(`publicReadOnlyPages[${index}] must be an absolute HTTPS page URL`);
  }
  let url: URL;
  try { url = new URL(value); } catch { fail(`publicReadOnlyPages[${index}] must be a valid HTTPS URL`); }
  const hostname = url.hostname.toLowerCase();
  const bareHostname = hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    (url.port !== "" && url.port !== "443") ||
    url.search !== "" ||
    url.hash !== "" ||
    isIP(bareHostname) !== 0 ||
    !hostname.includes(".") ||
    hostname.endsWith(".") ||
    hostname === "localhost" ||
    /\.(?:localhost|local|internal|test|example|invalid|home\.arpa|lan)$/.test(hostname) ||
    value !== url.href
  ) {
    fail(`publicReadOnlyPages[${index}] must be a canonical public HTTPS URL without credentials, query, fragment, or nondefault port`);
  }
  return url.href;
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

  const approvedServices = validateStringList(config.approvedServices, "approvedServices");
  const supportedServices = new Set(["revenueguard-demo", "source-review", "passive-public-review"]);
  if (!approvedServices.includes("revenueguard-demo") || approvedServices.some((service) => !supportedServices.has(service))) {
    fail('approvedServices must include "revenueguard-demo" and may include only "source-review" or "passive-public-review"');
  }

  if (!Array.isArray(config.sourceDirectories) || config.sourceDirectories.length === 0 || config.sourceDirectories.length > 8) {
    fail("sourceDirectories must contain between 1 and 8 local project directories");
  }
  const sourceDirectories = config.sourceDirectories.map(validateSourceDirectory);
  if (new Set(sourceDirectories).size !== sourceDirectories.length) fail("sourceDirectories must not contain duplicates");

  if (!Array.isArray(config.testAccounts) || config.testAccounts.length > 20) {
    fail("testAccounts must be an array containing at most 20 entries");
  }
  const accountNames = new Set<string>();
  for (let index = 0; index < config.testAccounts.length; index += 1) {
    const account = asRecord(config.testAccounts[index], `testAccounts[${index}]`);
    if (typeof account.name !== "string" || account.name.trim().length === 0 || typeof account.role !== "string" || account.role.trim().length === 0) {
      fail(`testAccounts[${index}] must include a non-empty name and role`);
    }
    if (account.name.length > 80 || account.role.length > 80 || accountNames.has(account.name.trim())) {
      fail(`testAccounts[${index}] has an invalid or duplicate name/role`);
    }
    accountNames.add(account.name.trim());
  }
  const expectedAccounts = [{ name: "alice", role: "user" }, { name: "bob", role: "user" }, { name: "admin", role: "admin" }];
  if (JSON.stringify(config.testAccounts.map((account) => ({ name: account.name.trim(), role: account.role.trim() }))) !== JSON.stringify(expectedAccounts)) {
    fail("testAccounts must match the synthetic Alice, Bob, and admin accounts used by the demo fixture");
  }

  if (!Array.isArray(config.approvedCallbacks) || config.approvedCallbacks.length !== 0) {
    fail("approvedCallbacks must be empty; callback integrations are not supported");
  }
  if (!Array.isArray(config.publicReadOnlyPages) || config.publicReadOnlyPages.length > 8) {
    fail("publicReadOnlyPages must be an array containing at most 8 exact URLs");
  }
  const publicReadOnlyPages = config.publicReadOnlyPages.map(validatePublicReadOnlyPage);
  if (new Set(publicReadOnlyPages).size !== publicReadOnlyPages.length) fail("publicReadOnlyPages must not contain duplicates");
  if (typeof config.resetProcedure !== "string" || config.resetProcedure.trim().length === 0 || config.resetProcedure.length > 500) {
    fail("resetProcedure must be a non-empty description of at most 500 characters");
  }
  if (!config.resetProcedure.startsWith("POST /api/lab/profile")) {
    fail("resetProcedure must describe the supported POST /api/lab/profile demo reset");
  }

  const budgets = asRecord(config.budgets, "budgets");
  const { maxRequestsPerAudit, maxConcurrentAudits, timeoutMs, maxSourceFiles, maxSourceBytes, maxPublicPages, maxPublicBytesPerPage } = budgets;
  if (!Number.isInteger(maxRequestsPerAudit) || (maxRequestsPerAudit as number) < 0) {
    fail("budgets.maxRequestsPerAudit must be a non-negative integer");
  }
  if (maxConcurrentAudits !== 1) {
    fail("budgets.maxConcurrentAudits must be 1; only one audit worker is supported");
  }
  if (!Number.isInteger(timeoutMs) || (timeoutMs as number) < 1) {
    fail("budgets.timeoutMs must be a positive integer");
  }
  if (!Number.isInteger(maxSourceFiles) || (maxSourceFiles as number) < 1 || (maxSourceFiles as number) > 5000) {
    fail("budgets.maxSourceFiles must be an integer from 1 to 5000");
  }
  if (!Number.isInteger(maxSourceBytes) || (maxSourceBytes as number) < 1024 || (maxSourceBytes as number) > 20_000_000) {
    fail("budgets.maxSourceBytes must be an integer from 1024 to 20000000");
  }
  if (!Number.isInteger(maxPublicPages) || (maxPublicPages as number) < 1 || (maxPublicPages as number) > 8) {
    fail("budgets.maxPublicPages must be an integer from 1 to 8");
  }
  if (publicReadOnlyPages.length > (maxPublicPages as number)) fail("publicReadOnlyPages exceeds budgets.maxPublicPages");
  if (!Number.isInteger(maxPublicBytesPerPage) || (maxPublicBytesPerPage as number) < 1024 || (maxPublicBytesPerPage as number) > 2_000_000) {
    fail("budgets.maxPublicBytesPerPage must be an integer from 1024 to 2000000");
  }
}

function originKeys(config: ScopeConfig): Set<string> {
  return new Set(config.approvedOrigins.map((origin) => parseLoopbackHttpUrl(origin, "approved origin").originKey));
}

function migrateScopeConfig(value: unknown): unknown {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return value;
  const original = value as Record<string, unknown>;
  const migrated: Record<string, unknown> = { ...original };
  if (!Array.isArray(original.publicReadOnlyPages)) migrated.publicReadOnlyPages = [];
  if (original.budgets && typeof original.budgets === "object" && !Array.isArray(original.budgets)) {
    const budgets = original.budgets as Record<string, unknown>;
    migrated.budgets = {
      ...budgets,
      maxSourceFiles: budgets.maxSourceFiles ?? 500,
      maxSourceBytes: budgets.maxSourceBytes ?? 2_000_000,
      maxPublicPages: budgets.maxPublicPages ?? 4,
      maxPublicBytesPerPage: budgets.maxPublicBytesPerPage ?? 1_000_000,
    };
  }
  return migrated;
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
  parsed = migrateScopeConfig(parsed);
  validateScopeConfig(parsed);

  // Copy and freeze the security-relevant fields so later mutation cannot widen scope.
  const config = Object.freeze({
    mode: "laboratory" as const,
    approvedOrigins: Object.freeze([...parsed.approvedOrigins]),
    approvedPathPrefixes: Object.freeze([...parsed.approvedPathPrefixes]),
    approvedServices: Object.freeze([...parsed.approvedServices]),
    sourceDirectories: Object.freeze(parsed.sourceDirectories.map(validateSourceDirectory)),
    testAccounts: Object.freeze(parsed.testAccounts.map((account) => Object.freeze({ name: account.name.trim(), role: account.role.trim() }))),
    approvedCallbacks: Object.freeze([] as string[]),
    publicReadOnlyPages: Object.freeze(parsed.publicReadOnlyPages.map(validatePublicReadOnlyPage)),
    resetProcedure: parsed.resetProcedure.trim(),
    budgets: Object.freeze({
      maxRequestsPerAudit: parsed.budgets.maxRequestsPerAudit,
      maxConcurrentAudits: parsed.budgets.maxConcurrentAudits,
      timeoutMs: parsed.budgets.timeoutMs,
      maxSourceFiles: parsed.budgets.maxSourceFiles,
      maxSourceBytes: parsed.budgets.maxSourceBytes,
      maxPublicPages: parsed.budgets.maxPublicPages,
      maxPublicBytesPerPage: parsed.budgets.maxPublicBytesPerPage,
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

/** Require an exact, canonical public page URL from the explicit allowlist. */
export function assertPublicPageInScope(value: string | URL, config: ScopeConfig): URL {
  validateScopeConfig(config);
  const raw = value instanceof URL ? value.href : value;
  const canonical = validatePublicReadOnlyPage(raw, 0);
  if (!config.publicReadOnlyPages.includes(canonical)) {
    fail("Public page URL is outside the exact configured scope");
  }
  return new URL(canonical);
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
