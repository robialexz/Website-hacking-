# RevenueGuard Lab

> An offline-first, loopback-only security training lab for exploring common web flaws with a disposable synthetic app. Compare vulnerable examples with secure controls, review evidence, and generate reports without scanning real websites.

RevenueGuard Lab is a small, dependency-free learning project. Its dashboard runs on your own machine and audits only the demo service included in this repository. It is **not** a general-purpose website scanner, and its findings describe the synthetic fixture only.

## Quick start

### Requirements

- Node.js 26 or newer.
- No `npm install`, API key, database server, or internet connection is needed to run the app.

### Run it

```sh
git clone https://github.com/robialexz/Website-hacking-.git
cd Website-hacking-
node --version   # confirm v26 or newer
npm start
```

Open **http://127.0.0.1:8765** in your browser. On its first start, the app creates `scope.json` from `scope.example.json` and creates `data/revenueguard.sqlite` for local run history. Both are local files and are excluded from source control.

### Run the vulnerable-versus-secure walkthrough

1. In **Demo profile**, select **Vulnerable examples**.
2. Select **Run local audit** and wait for the job to finish.
3. Open findings to review their evidence, expected behavior, impact, and suggested remediation.
4. Select **Secure controls**.
5. Select **Retest findings** to check whether the earlier confirmed demo behaviors still reproduce.
6. Open a report from the run history and use **Print / Save as PDF** if you want a copy.

A retest marks an earlier confirmed finding as fixed only if all required checks validate their expected safe controls. A timeout, server error, missing route, or other unverified response is incomplete evidence; it cannot prove a fix.

## What the checks demonstrate

The audit runs seven deterministic checks against the built-in fixture:

| Check | What the vulnerable example demonstrates | What it does not prove |
| --- | --- | --- |
| Record authorization | A synthetic user can read another synthetic user's record. | No real account or customer data is accessed. |
| Admin authorization | The synthetic admin panel responds without credentials. | No real administrative system is contacted. |
| Search filter canary | A fixed lab marker returns more synthetic rows than an unmatched query. | This is not SQL execution or a verified SQL injection. |
| Reflected HTML canary | A fixed SVG marker is returned unescaped in an HTML response. | The audit does not open a browser to execute it; arbitrary query text is escaped. |
| Fake file boundary | A hard-coded marker for a fake private file is returned. | No host file is read; the file exists only in memory. |
| Single-use discount | The same synthetic discount succeeds twice. | No payment, purchase, or real transaction occurs. |
| Dependency marker | A fictional `RG-DEMO-001` marker is shown for cautious triage. | It is not a real advisory and is reported as suspected only. |

The secure profile provides the expected denial, encoding, or one-time-use behavior for these fixtures. Reports distinguish confirmed fixture behavior from suspected markers and include the scope caveat.

## Reports and local data

The dashboard keeps recent jobs, findings, evidence, and logs in `data/revenueguard.sqlite`. The database stays on your machine. Generated reports are available at:

- `/reports/<job-id>/technical`
- `/reports/<job-id>/executive`
- `/reports/<job-id>/remediation`

Each report includes a scope note. Use its **Print / Save as PDF** button to save or print it from the browser. The reports are examples for learning and must not be presented as evidence about a real site, customer impact, or lost revenue.

## Safety boundary

- The web server binds only to `127.0.0.1:8765`, checks the request host and local socket, and does not listen on your network interface.
- The audit uses a fixed demo origin and requires it to appear in the scope config. Paths and payloads are fixed in code; adding another origin to the JSON file does not redirect the audit.
- The scope guard accepts literal loopback addresses and approved paths only. Redirects are disabled, and requests have a timeout and per-audit budget.
- Users, records, discounts, dependency data, and files are synthetic. The fake file is stored in memory.
- No public-target discovery, external callback, cloud AI, or live advisory download is enabled.

**Do not use this project to scan public websites or systems you do not own and have explicit permission to test.** This release intentionally cannot target arbitrary URLs. Its vulnerable profile is a toy fixture for local learning.

## Development

```sh
npm test
```

The tests use Node's built-in test runner and synthetic fixtures. They do not contact external services or scan other applications. There are no third-party runtime dependencies.

### Project layout

```text
src/server.ts          Local HTTP server, dashboard API, queue, SQLite history, and reports
src/audit.ts           Fixed audit checks and evidence generation
src/lab-target.ts      Synthetic vulnerable and secure demo behaviors
src/scope.ts           Loopback, path, timeout, redirect, and request-budget guard
src/*.test.ts          Unit tests for the audit, scope guard, and demo fixtures
public/                Dashboard and printable report UI
scope.example.json     Safe local scope template copied on first start
```

## Current limitations

This first release audits only its own demo service. It does not import a third-party project, accept an arbitrary target URL, inspect real dependencies, patch arbitrary source code, or test session invalidation, password reset, CSRF, CORS, SSRF, uploads, command execution, or race conditions. A future feature that changes the target boundary needs a separate design and an explicitly authorized isolated environment.

## License

No license has been added yet. Public visibility lets people view the repository, but it does not grant permission to reuse or redistribute its code. Add a license if you want to grant those rights.

