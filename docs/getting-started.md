# Getting started

RevenueGuard is a local single-operator baseline scanner for websites you own or are explicitly authorized to review. It is not a hosted multi-user service. Authorization is self-attested and not independently verified; an HTTP GET can still cause an action on an unknown route.

## Start the app

Requirements: Node.js 24.15 or newer. No npm packages need to be installed.

```sh
git clone https://github.com/robialexz/revenueguard-lab.git
cd revenueguard-lab
npm start
```

Open <http://127.0.0.1:8765>. RevenueGuard listens on loopback only. On first start, it copies `scope.example.json` to local `scope.json` and creates `data/revenueguard.sqlite`. Startup makes no request to a website.

The default port is 8765. To use another port on a fresh checkout, first copy `scope.example.json` to `scope.json`, add the matching origin (such as `http://127.0.0.1:8877`) to `approvedOrigins`, then start with `REVENUEGUARD_PORT=8877 npm start`. RevenueGuard continues to bind to loopback.

The example scope enables `web-scan` by default. A legacy scope whose mode is `laboratory` is migrated in memory to scanner mode and gains `web-scan`; no target is selected or contacted by this migration. The actual run requires a URL and two confirmations.

## Run a web scan

1. In **Web scan**, replace the displayed `https://<your-domain>/` placeholder with an HTTPS URL for a website you own or are authorized to assess. The URL must use a public DNS name on port 443, without credentials, query string, or fragment. IP literals, private or reserved DNS answers, and obvious action-like starting paths are rejected.
2. Set a per-run page limit and link depth within the configured caps. Read the request count, total duration, per-request timeout, in-memory response-body processing limits, and delay shown under **Scope & safety**.
3. Confirm both statements about authorization and unauthenticated GET requests. The confirmation applies to the final target and budget; changing any of them clears the confirmations.
4. Select **Start web scan**. Only one local run is active at a time. Select **Stop scan** to abort the current request and stop later pages from starting.
5. Open the report to review observations and coverage. Cancelled or budget-limited runs are marked incomplete. Findings are leads for review; no findings does not establish that the site is secure.

The crawler uses unauthenticated same-origin HTTPS GET requests. It follows links found in fetched HTML, up to the selected depth and hard page/request/time/body budgets. It does not follow redirects, query-string links, static files, off-origin links, obvious action-like routes, or ambiguous encoded paths. It does not execute JavaScript, fetch page assets, log in, use cookies, submit forms, or send exploit payloads. The action-path filter is heuristic and cannot guarantee that an unknown GET is side-effect-free.

Checks cover selected browser security headers, TLS certificate-chain and hostname validation, cookie attribute counts, wildcard CORS response headers, numeric server-version banners, mixed-content references, insecure form destinations, and missing SRI markers on external scripts or stylesheets. CORS origin reflection/preflight, authenticated behavior, access control, SQL injection, XSS, SSRF payloads, business logic, and client-rendered routes are not tested.

## Local fixture walkthrough

The separate synthetic fixture demonstrates known behavior without contacting external sites:

1. Leave **Demo profile** on **Vulnerable examples** and select **Run local fixture checks**.
2. Review the findings; every user, record, file, and dependency marker is synthetic.
3. Select **Secure controls** and then **Retest findings**.
4. Open the report to see what was checked and which results remain unverified.

The fixture is training material, not a scan of the target website.

## Review local source

`source-review` is enabled by the example scope. The approved source path defaults to `./src`. Select **Review approved source** to inspect JavaScript and TypeScript files for a small set of static patterns. It does not execute or modify the project. Findings are heuristic and may be missed or false-positive. File-count and byte limits are shown in the scope panel.

To review a different local directory, edit `sourceDirectories` in your private `scope.json`, make sure the folder is the one you intend to inspect, and restart the app. Relative directories must stay inside the RevenueGuard project. Absolute paths are accepted only inside a recognizable local project. Symlinks are rejected or skipped.

## Optional exact-page reviews

`passive-public-review` is not enabled in the example scope and `publicReadOnlyPages` starts empty. To enable the passive SEO/accessibility or HTTPS posture workflow, add the service and exact canonical HTTPS page URLs to local `scope.json`, then restart. Each run asks for authorization and safe-GET confirmation.

These workflows make one GET per selected page; they do not crawl, follow redirects, fetch assets, or submit forms. A GET may still trigger a website action. Their observations are limited to the selected responses and do not establish security.

## Scope and history

- Keep the synthetic fixture's `approvedOrigins` on loopback and `approvedPathPrefixes` under `/lab/`.
- `approvedServices` controls which local workflows are available. Enabling a workflow does not select a target; external requests start only after an operator queues an enabled public workflow and completes its attestations.
- `web-scan` requests HTTPS on port 443 for one origin at a time. The page, depth, request, duration, per-request timeout, response-body, and delay budgets are configured under `budgets` in local `scope.json`.
- Response-body budgets cap content copied into memory for parsing. Bodies are discarded after analysis. A received network chunk may exceed the remaining in-memory allowance before the connection is stopped.
- Web-scan targets are held in memory while queued or running. Local history stores only the origin and aggregate observations; reports omit route paths. Startup removes paths saved by older web-scan builds. Token-like routes and action-like paths are skipped.
- Stop the app and remove `data/revenueguard.sqlite` to clear local run history. There is no automatic retention period or per-run deletion screen. Remove any exact-page URLs from `scope.json` separately.
- Queued work is cancelled during shutdown and never replayed after restart. An active web scan is aborted during shutdown.

## Verify changes

```sh
npm ci
npm run verify
```

`npm ci` installs the TypeScript checker used in verification; it is not needed to run RevenueGuard. Tests use local fixtures and mocked transports. They do not request an external website.
