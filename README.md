# RevenueGuard Lab

> An offline-first security lab with loopback-only dynamic checks, read-only local source review, and optional bounded public-page observations.

![RevenueGuard Lab overview illustration](revenueguard-lab-social-preview.jpg)

RevenueGuard Lab is a small, dependency-free learning project. Its active audit targets only the synthetic service included in this repository. A separate read-only source review checks JavaScript and TypeScript files under explicitly scoped local directories. An optional public-page review makes one unauthenticated GET request per exact HTTPS page listed in local `scope.json`. It does not run vulnerability probes, crawl the site, or follow links or redirects; GET requests can still trigger actions on some sites.

## Quick start

### Requirements

- Node.js 26 or newer.
- No `npm install`, API key, or database server is needed. Internet access is not used by the local audit or source review. The optional public-page review requires network access only when a user starts it.

### Run it

```sh
git clone https://github.com/robialexz/revenueguard-lab.git
cd revenueguard-lab
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

### Review local source code

1. The example scope enables only `revenueguard-demo`. Add `source-review` to `approvedServices` to enable local source review, then confirm the directories under `sourceDirectories` are the folders you intend to inspect. The default is `./src`.
2. For another local project, add its exact source directory to `sourceDirectories`. Absolute paths are accepted only when they resolve inside a recognizable local project. Symlinks are rejected or skipped.
3. Restart RevenueGuard Lab after editing `scope.json`, then select **Review approved source**. The checks look for dynamic code evaluation, disabled TLS certificate validation, credential-like literals, and dynamic HTML insertion.
4. Open each result

The default source budget is 500 files and 2 MB in total. Generated folders, hidden folders, binary files, and files outside the JavaScript/TypeScript extensions supported by the scanner are skipped. If a limit is reached, coverage says the review is incomplete.

### Review an approved public page

The checked-in example enables only `revenueguard-demo` and leaves `publicReadOnlyPages` empty. To enable a public-page review, add `passive-public-review` to `approvedServices` and add the exact canonical HTTPS page URL to `publicReadOnlyPages` in your local scope, for example `https://example.com/`. Do not add a query string or fragment. The list is capped at four pages by default.

Restart RevenueGuard Lab after editing the scope, then select **Review approved pages**. Before each run, confirm that you own or have permission to review every listed page and that each URL is safe to request. A single unauthenticated GET can still trigger an action on some sites, such as a confirmation or unsubscribe route, so do not list tokenized or state-changing pages.

RevenueGuard makes one direct GET per listed page without credentials, cookies, referrers, retries, or asset requests. It does not follow redirects or links. It records response status, a timing and byte measurement, selected response headers, metadata lengths/counts, and image alt-attribute counts. The HTML body is parsed in memory and is not saved in SQLite or reports.

Each report lists the exact pages captured in that run's scope. Results are **Suspected** page-level observations about headers, search metadata, or image alt attributes. They are not security vulnerabilities, ranking guarantees, or revenue estimates. A 3xx response is recorded without following its `Location` header. If DNS resolves to a private or reserved address, the request is stopped before connecting.

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

The source review and public-page review are separate from the dynamic fixture audit. They do not change the vulnerable or secure demo profile. Static or passive observations are always marked **Suspected** and are not exploitability claims.

The secure profile provides the expected denial, encoding, or one-time-use behavior for these fixtures. Reports distinguish confirmed fixture behavior from suspected markers and include the scope caveat.

## Reports and local data

The dashboard keeps recent jobs, findings, evidence, and logs in `data/revenueguard.sqlite`. The database stays on your machine. Generated reports are available at:

- `/reports/<job-id>/technical`
- `/reports/<job-id>/executive`
- `/reports/<job-id>/remediation`

Each report includes a scope note. Public-page reports also list the exact URLs captured when that job was queued; queued or interrupted jobs are marked failed after an app restart and are never replayed automatically.

## Safety boundary

- The web server binds only to `127.0.0.1:8765`, checks the request host and local socket, and does not listen on your network interface.
- The dynamic audit uses a fixed loopback demo origin and requires it to appear in the scope config. Paths and payloads are fixed in code; adding another origin does not redirect the audit.
- The dynamic scope guard accepts literal loopback addresses and approved paths only. Redirects are disabled, and requests have a timeout and per-audit budget.
- `sourceDirectories` is an explicit local filesystem allowlist. Source review reads regular JavaScript/TypeScript files only, rejects a symlinked approved root, skips symlinked entries, and enforces file-count and byte budgets.
- `publicReadOnlyPages` is a separate exact-URL allowlist. Each run requires confirmation because an ordinary GET can still trigger a site action.
- `approvedServices` starts with only the synthetic demo. Add source or public-page review only when you intend to enable it; migrations preserve existing approvals. Synthetic `testAccounts`, empty `approvedCallbacks`, and `resetProcedure` are validated against this release's capabilities.
- Users, records, discounts, dependency data, and files are synthetic. The fake file is stored in memory.
- No public-target discovery, crawling, external callback, cloud AI, or live advisory download is enabled. Only the optional exact-page review makes outbound requests, and only after a local user starts it.

**Use public-page review only for pages you own or have permission to assess, and only when the exact GET URLs are safe to request.** Some sites attach side effects to GET routes. The app asks for confirmation before each run. The dynamic audit cannot target remote systems, and the public review cannot target arbitrary URLs. The vulnerable profile is a toy fixture for local learning.

## Development

```sh
npm test
```

The tests use Node's built-in test runner

### Project layout

```text
src/server.ts          Local HTTP server, dashboard API, queue, SQLite history, and reports
src/audit.ts           Fixed audit checks and evidence generation
src/source-review.ts   Read-only, budgeted static checks for scoped local source
src/public-review.ts   Exact-page passive HTTPS checks with DNS pinning and response limits
src/lab-target.ts      Synthetic vulnerable and secure demo behaviors
src/scope.ts           Strict local/public allowlists and request-budget validation
src/*.test.ts          Unit tests for demo checks, source review, and passive transport behavior
public/                Dashboard and printable report UI
scope.example.json     Safe local scope template copied on first start
docs/getting-started.md Setup and scope instructions for all three workflows
```

## Current limitations

This release does not perform active security testing against another application. The source review currently checks four patterns; it is not a complete SAST engine, does not resolve dependencies, does not apply patches, and may miss issues or return false positives. The public-page review is a bounded passive check; it does not inspect authentication, forms, third-party assets, or route behavior. To use active testing on another application, a separately designed, isolated, explicitly authorized target configuration is required.

## License

No license has been added yet. Public visibility lets people view the repository, but it does not grant permission to reuse or redistribute its code. Add a license if you want to grant those rights.

