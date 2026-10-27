# RevenueGuard Lab

> A local-only security learning tool with a synthetic loopback audit, local source review, passive SEO/accessibility observations, and optional HTTPS posture observations. It is not a production multi-user scanning service.

![RevenueGuard Lab overview illustration](revenueguard-lab-social-preview.jpg)

RevenueGuard Lab is a small, dependency-free, local-only learning project. Its synthetic lab audit targets only the demo service included in this repository. A separate source review checks JavaScript and TypeScript files under explicitly scoped local directories. The passive SEO/accessibility review and the HTTPS posture review are separate actions; each uses exact HTTPS pages in local `scope.json` and makes one unauthenticated GET per page when started. The posture review requires an operator attestation that the pages are authorized and safe to request. That attestation is not proof of authorization. A GET can still trigger a site action. Neither public workflow crawls pages, sends authentication, submits forms, or probes payloads.

## Quick start

### Requirements

- Node.js 26 or newer.
- No `npm install`, API key, or database server is needed. Internet access is not used by the synthetic audit or source review. The optional public-page and HTTPS posture reviews need network access only when an operator starts them.

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

### Review passive SEO and accessibility observations

The checked-in example enables only `revenueguard-demo` and leaves `publicReadOnlyPages` empty. To enable a public-page review, add `passive-public-review` to `approvedServices` and add the exact canonical HTTPS page URL to `publicReadOnlyPages` in your local scope, for example `https://example.com/`. Do not add a query string or fragment. The list is capped at four pages by default.

Restart RevenueGuard Lab after editing the scope, then select **Review approved pages**. This action reports basic page metadata and image alt-text observations. It is separate from HTTPS posture observations and from the synthetic lab audit. A single unauthenticated GET can still trigger an action on some sites, so do not list tokenized or state-changing pages.

RevenueGuard makes one direct GET per listed page without credentials, cookies, referrers, retries, or asset requests. It does not follow redirects or links. It records response status, a timing and byte measurement, metadata lengths/counts, and image alt-attribute counts. The HTML body is parsed in memory and is not saved in SQLite or reports.

Each report lists the exact pages captured in that run's scope. Results are **Suspected** page-level SEO and accessibility observations, not an active security assessment, ranking prediction, or revenue estimate. A 3xx response is recorded without following its `Location` header. If DNS resolves to a private or reserved address, the request is stopped before connecting.

### Review HTTPS posture observations

The HTTPS posture review is a separate `posture-review` action for a small set of observable HTTPS response properties: normalized HSTS/CSP/browser-header summaries, TLS certificate and hostname validation for the connection, and cookie flag counts. It uses the same `passive-public-review` approval and exact `publicReadOnlyPages` allowlist shown above; no additional scope key or service is needed. The default budget allows at most four pages and caps each response at 1 MB and each request at 30 seconds.

Before each run, the operator must attest that they own or have permission to review the exact listed pages and that each URL is safe to request. This is an operator attestation, not verification or proof of authorization. The review sends one unauthenticated GET per exact scoped page. It sends no cookies or credentials, does not crawl or follow redirects, submit forms, or send payload probes, and does not automatically retry. A GET may still cause a side effect on some sites; exclude state-changing URLs and stop if a response suggests the request was unsafe.

Treat the results as limited observations of the responses received. They are not an active vulnerability scan, do not establish that a site is secure or authorized, and are not a compliance assessment. RevenueGuard runs as a local-only, single-user application; it is not a hosted or production multi-user service.

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

The source review, passive SEO/accessibility review, and HTTPS posture review are separate from the dynamic fixture audit. They do not change the vulnerable or secure demo profile. Passive SEO/accessibility observations are marked **Suspected**; posture output is marked **Observed** or **Inconclusive**. Neither status is an exploitability claim, and an empty observation list does not establish security.

The secure profile provides the expected denial, encoding, or one-time-use behavior for these fixtures. Reports distinguish confirmed fixture behavior from suspected markers and include the scope caveat.

## Reports and local data

The dashboard keeps recent jobs, findings, evidence, and logs in `data/revenueguard.sqlite`. The database stays on your machine. Generated reports are available at:

- `/reports/<job-id>/technical`
- `/reports/<job-id>/executive`
- `/reports/<job-id>/remediation`

Each report includes a scope note. Public-page reports also list the exact URLs captured when that job was queued; queued or interrupted jobs are marked failed after an app restart and are never replayed automatically.

The app has no per-run deletion screen or automatic retention period. It stores exact posture target URLs, normalized header summaries, coverage, findings, and logs locally; it does not store response bodies, cookie names, or cookie values. To clear local history, stop the app and delete `data/revenueguard.sqlite`; remove target URLs separately from your local `scope.json`.

## Safety boundary

- The web server binds only to `127.0.0.1:8765`, checks the request host and local socket, and does not listen on your network interface.
- The dynamic audit uses a fixed loopback demo origin and requires it to appear in the scope config. Paths and payloads are fixed in code; adding another origin does not redirect the audit.
- The dynamic scope guard accepts literal loopback addresses and approved paths only. Redirects are disabled, requests have a timeout and per-audit budget, and `maxResponseBytes` caps the response body at 2 MB by default (configurable from 1 KB to 20 MB).
- `sourceDirectories` is an explicit local filesystem allowlist. Source review reads regular JavaScript/TypeScript files only, rejects a symlinked approved root, skips symlinked entries, and enforces file-count and byte budgets.
- `publicReadOnlyPages` is a separate exact-URL allowlist shared by the public-page and HTTPS posture reviews. Each run requires operator confirmation because an ordinary GET can still trigger a site action; this confirmation is not proof of authorization.
- `approvedServices` starts with only the synthetic demo. Add source or public review only when you intend to enable it; `passive-public-review` is shared by the SEO/accessibility and HTTPS posture actions. Migrations preserve existing approvals. Synthetic `testAccounts`, empty `approvedCallbacks`, and `resetProcedure` are validated against this release's capabilities.
- Users, records, discounts, dependency data, and files are synthetic. The fake file is stored in memory.
- No public-target discovery, crawling, external callback, cloud AI, or live advisory download is enabled. Only the optional exact-page public workflows make outbound requests, after a local operator starts them.

**Use the public-page and HTTPS posture reviews only for exact pages you own or have permission to review, and only when each GET is safe to request.** The operator attestation is not proof of authorization. Some sites attach side effects to GET routes. The dynamic audit cannot target remote systems, and the public workflows cannot target arbitrary URLs. The vulnerable profile is a toy fixture for local learning.

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
src/posture-review.ts Limited HTTPS posture observations using the same bounded transport
src/lab-target.ts      Synthetic vulnerable and secure demo behaviors
src/scope.ts           Strict local/public allowlists and request-budget validation
src/*.test.ts          Unit tests for demo checks, source review, and passive transport behavior
public/                Dashboard and printable report UI
scope.example.json     Safe local scope template copied on first start
docs/getting-started.md Setup and scope instructions for all four workflows
```

## Current limitations

This release does not perform active security testing against another application. The source review currently checks four patterns; it is not a complete SAST engine, does not resolve dependencies, does not apply patches, and may miss issues or return false positives. The passive SEO/accessibility and HTTPS posture reviews are bounded observations, not active vulnerability scans. They do not inspect authenticated behavior, submit forms, crawl routes, or probe payloads. The operator attestation is not proof of target authorization. RevenueGuard is a local-only, single-user learning application and is not production-ready as a hosted multi-user scanner. Active testing of another application would require a separately designed, isolated, explicitly authorized target configuration.

## License

No license has been added yet. Public visibility lets people view the repository, but it does not grant permission to reuse or redistribute its code. Add a license if you want to grant those rights.

