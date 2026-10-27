import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer as createHttpServer, request as httpRequest } from "node:http";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";

const HOST = "127.0.0.1";
let PORT = 0;
let BASE = "";
const TOKEN = "a1B2c3D4_PRIVATE_MARKER";
const JOB_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const TARGET_ONLY_JOB_ID = "cccccccc-cccc-cccc-cccc-cccccccccccc";
const MALFORMED_JOB_ID = "dddddddd-dddd-dddd-dddd-dddddddddddd";
const TARGET = `https://scan.example.net/r/${TOKEN}`;

function pause(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function availablePort(): Promise<number> {
  const probe = createHttpServer();
  await new Promise<void>((resolve, reject) => {
    probe.once("error", reject);
    probe.listen(0, HOST, () => resolve());
  });
  const address = probe.address();
  if (!address || typeof address === "string") throw new Error("Could not reserve a loopback test port.");
  const port = address.port;
  await new Promise<void>((resolve, reject) => probe.close((error) => error ? reject(error) : resolve()));
  return port;
}

async function startServer(projectDir: string): Promise<ReturnType<typeof spawn>> {
  const serverScript = fileURLToPath(new URL("./server.ts", import.meta.url));
  const child = spawn(process.execPath, [serverScript], {
    cwd: projectDir,
    stdio: "ignore",
    env: { ...process.env, REVENUEGUARD_PORT: String(PORT) },
  });
  const deadline = Date.now() + 8_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`RevenueGuard exited during startup (${child.exitCode}).`);
    try {
      const response = await fetch(`${BASE}/api/health`);
      if (response.ok) return child;
    } catch { /* The loopback server has not started listening yet. */ }
    await pause(40);
  }
  child.kill("SIGKILL");
  throw new Error("RevenueGuard did not start within eight seconds.");
}

async function waitForExit(child: ReturnType<typeof spawn>): Promise<void> {
  if (child.exitCode !== null) return;
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("RevenueGuard did not stop within five seconds.")), 5_000);
    child.once("exit", () => { clearTimeout(timer); resolve(); });
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
  });
}

async function waitForListenerClosed(): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const closed = await new Promise<boolean>((resolve, reject) => {
      const socket = createConnection(PORT, HOST);
      socket.once("connect", () => { socket.destroy(); resolve(false); });
      socket.once("error", (error) => {
        socket.destroy();
        if (["ECONNREFUSED", "ECONNRESET"].includes((error as NodeJS.ErrnoException).code || "")) resolve(true);
        else reject(error);
      });
    });
    if (closed) return;
    await pause(10);
  }
  throw new Error("RevenueGuard continued accepting connections after SIGTERM.");
}

async function stopServer(child: ReturnType<typeof spawn>): Promise<void> {
  if (child.exitCode === null) child.kill("SIGTERM");
  await waitForExit(child);
}

test("local API keeps web-scan paths out of saved history and rejects a slow job during shutdown", async () => {
  const projectDir = await mkdtemp(join(tmpdir(), "revenueguard-integration-"));
  let child: ReturnType<typeof spawn> | undefined;
  try {
    PORT = await availablePort();
    BASE = `http://${HOST}:${PORT}`;
    await mkdir(join(projectDir, "public"), { recursive: true });
    await cp(fileURLToPath(new URL("../public", import.meta.url)), join(projectDir, "public"), { recursive: true });
    await cp(fileURLToPath(new URL("../scope.example.json", import.meta.url)), join(projectDir, "scope.example.json"));
    await cp(fileURLToPath(new URL("../package.json", import.meta.url)), join(projectDir, "package.json"));
    const scopeExamplePath = join(projectDir, "scope.example.json");
    const scopeExample = JSON.parse(await readFile(scopeExamplePath, "utf8")) as { approvedOrigins: string[] };
    scopeExample.approvedOrigins = scopeExample.approvedOrigins.map((origin) => origin === "http://127.0.0.1:8765" ? BASE : origin);
    await writeFile(scopeExamplePath, JSON.stringify(scopeExample, null, 2) + "\n");

    child = await startServer(projectDir);
    await stopServer(child);
    child = undefined;

    const databasePath = join(projectDir, "data", "revenueguard.sqlite");
    const db = new DatabaseSync(databasePath);
    db.prepare("DELETE FROM settings WHERE key = 'web_scan_path_privacy_v1'").run();
    db.prepare("INSERT INTO jobs(id, action, profile, status, created_at, finished_at, error, coverage_json, scope_json, target_pages_json, attestation_json) VALUES(?, 'web-scan', 'web-baseline', 'complete', ?, ?, ?, ?, ?, ?, ?)")
      .run(JOB_ID, new Date().toISOString(), new Date().toISOString(), `Old error ${TARGET}`,
        JSON.stringify([{ key: "web.fetch.page-1", label: `Fetch ${TARGET}`, attempted: true, status: "NOT TESTED", error: TARGET }]),
        JSON.stringify({ webScanTarget: "https://scan.example.net" }), JSON.stringify([TARGET]),
        JSON.stringify({ version: 1, target: TARGET, origin: "https://scan.example.net", authorized: true, safeGet: true }));
    db.prepare(`INSERT INTO findings(
      id, job_id, finding_key, title, category, severity, status, confidence, target,
      endpoint, component, preconditions, expected, actual, reproduction_json, impact,
      severity_rationale, remediation, evidence_json, retest_status, created_at
    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", JOB_ID, "web.headers.csp", "Fixture finding", "Fixture", "Low", "SUSPECTED", "Medium",
        "https://scan.example.net", TARGET, "HTTP response", "Fixture", "Expected", `Observed on 1 page(s). Sample paths: ${TARGET}.`, JSON.stringify([TARGET]), "Fixture", "Fixture", "Fixture",
        JSON.stringify({ webScan: { pageCount: 1, samplePaths: [TARGET], checks: {} }, note: TARGET }), "NOT RETESTED", new Date().toISOString());
    db.prepare("INSERT INTO execution_logs(job_id, created_at, level, message) VALUES(?, ?, 'warning', ?)")
      .run(JOB_ID, new Date().toISOString(), `Old log ${TARGET}`);
    db.prepare("INSERT INTO jobs(id, action, profile, status, created_at, finished_at, coverage_json, scope_json, target_pages_json, attestation_json) VALUES(?, 'web-scan', 'web-baseline', 'complete', ?, ?, '[]', '{}', '[]', ?)")
      .run(TARGET_ONLY_JOB_ID, new Date().toISOString(), new Date().toISOString(),
        JSON.stringify({ version: 2, target: TARGET, authorized: true, safeGet: true }));
    db.prepare("INSERT INTO jobs(id, action, profile, status, created_at, finished_at, coverage_json, scope_json, target_pages_json, attestation_json) VALUES(?, 'web-scan', 'web-baseline', 'complete', ?, ?, '[]', ?, ?, ?)")
      .run(MALFORMED_JOB_ID, new Date().toISOString(), new Date().toISOString(),
        JSON.stringify({ webScanTarget: `malformed ${TOKEN}` }), JSON.stringify([`malformed/${TOKEN}`]),
        JSON.stringify({ target: `malformed ${TOKEN}`, authorized: true }));
    db.close();

    child = await startServer(projectDir);
    const healthResponse = await fetch(`${BASE}/api/health`);
    const health = await healthResponse.json() as Record<string, unknown>;
    assert.equal(health.mode, "scanner");
    assert.equal(health.externalNetworkEnabled, true);
    assert.equal("externalNetwork" in health, false);

    const jobResponse = await fetch(`${BASE}/api/jobs/${JOB_ID}`);
    const jobData = await jobResponse.text();
    assert.equal(jobResponse.status, 200);
    assert.doesNotMatch(jobData, new RegExp(TOKEN));
    assert.match(jobData, /https:\/\/scan\.example\.net/);
    const targetOnlyResponse = await fetch(`${BASE}/api/jobs/${TARGET_ONLY_JOB_ID}`);
    const targetOnlyJob = await targetOnlyResponse.text();
    assert.equal(targetOnlyResponse.status, 200);
    assert.doesNotMatch(targetOnlyJob, new RegExp(TOKEN));
    const malformedResponse = await fetch(`${BASE}/api/jobs/${MALFORMED_JOB_ID}`);
    const malformedJob = await malformedResponse.text();
    assert.equal(malformedResponse.status, 200);
    assert.doesNotMatch(malformedJob, new RegExp(TOKEN));

    const reportResponse = await fetch(`${BASE}/reports/${JOB_ID}/technical`);
    const report = await reportResponse.text();
    assert.equal(reportResponse.status, 200);
    assert.doesNotMatch(report, new RegExp(TOKEN));
    assert.match(report, /Sample paths omitted for privacy/);

    const sessionResponse = await fetch(`${BASE}/api/session`);
    const session = await sessionResponse.json() as { csrfToken: string };
    const body = JSON.stringify({
      action: "web-scan",
      target: "https://nodbim.com/private",
      maxPages: 1,
      maxDepth: 0,
      authorizationAttestation: {
        version: 2, authorized: true, safeGet: true, target: "https://nodbim.com/",
        origin: "https://nodbim.com", maxPages: 1, maxDepth: 0,
      },
    });
    let slowRequest: ReturnType<typeof httpRequest> | undefined;
    let resolvePostConnected: (() => void) | undefined;
    let rejectPostConnected: ((error: Error) => void) | undefined;
    const postConnected = new Promise<void>((resolve, reject) => {
      resolvePostConnected = resolve;
      rejectPostConnected = reject;
    });
    const slowResponse = new Promise<{ status: number; body: string }>((resolve, reject) => {
      const request = httpRequest({
        hostname: HOST,
        port: PORT,
        method: "POST",
        path: "/api/jobs",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
          "x-csrf-token": session.csrfToken,
          origin: BASE,
        },
      }, (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () => resolve({ status: response.statusCode || 0, body: Buffer.concat(chunks).toString("utf8") }));
      });
      slowRequest = request;
      request.on("socket", (socket) => {
        socket.once("connect", () => resolvePostConnected?.());
        if (!socket.connecting) resolvePostConnected?.();
      });
      request.on("error", (error) => { rejectPostConnected?.(error); reject(error); });
      request.write(body.slice(0, 24));
    });
    void slowResponse.catch(() => undefined);
    await postConnected;
    const healthWhilePostBodyIsOpen = await fetch(`${BASE}/api/health`);
    assert.equal(healthWhilePostBodyIsOpen.status, 200);
    child.kill("SIGTERM");
    await waitForListenerClosed();
    slowRequest?.end(body.slice(24));
    const result = await slowResponse;
    assert.equal(result.status, 409);
    assert.match(result.body, /shutting down/i);
    await stopServer(child);
    child = undefined;

    const verifyDb = new DatabaseSync(databasePath);
    const job = verifyDb.prepare("SELECT target_pages_json, attestation_json, scope_json, coverage_json, error FROM jobs WHERE id = ?").get(JOB_ID) as Record<string, unknown>;
    const targetOnlyJobRow = verifyDb.prepare("SELECT target_pages_json, attestation_json, scope_json FROM jobs WHERE id = ?").get(TARGET_ONLY_JOB_ID) as Record<string, unknown>;
    const malformedJobRow = verifyDb.prepare("SELECT target_pages_json, attestation_json, scope_json FROM jobs WHERE id = ?").get(MALFORMED_JOB_ID) as Record<string, unknown>;
    const finding = verifyDb.prepare("SELECT endpoint, actual, evidence_json, reproduction_json FROM findings WHERE job_id = ?").get(JOB_ID) as Record<string, unknown>;
    const logs = verifyDb.prepare("SELECT message FROM execution_logs WHERE job_id = ?").all(JOB_ID);
    const jobCount = verifyDb.prepare("SELECT COUNT(*) AS count FROM jobs").get() as { count: number };
    verifyDb.close();
    const persisted = JSON.stringify({ job, targetOnlyJobRow, malformedJobRow, finding, logs, jobCount });
    assert.doesNotMatch(persisted, new RegExp(TOKEN));
    assert.equal(jobCount.count, 3, "shutdown must not acknowledge or insert a stranded queued run");
    assert.deepEqual(JSON.parse(String(job.target_pages_json)), ["https://scan.example.net"]);
    assert.deepEqual(JSON.parse(String(targetOnlyJobRow.target_pages_json)), ["https://scan.example.net"]);
    assert.deepEqual(JSON.parse(String(malformedJobRow.target_pages_json)), []);
  } finally {
    if (child) await stopServer(child).catch(() => child?.kill("SIGKILL"));
    await rm(projectDir, { recursive: true, force: true });
  }
});
