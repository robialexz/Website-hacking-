# Introducing RevenueGuard Lab v0.1.0: A Local Security Training Lab

I'm sharing RevenueGuard Lab v0.1.0, an early pre-release of a small security training lab that runs on your own machine.

The lab starts its own synthetic demo app and runs a fixed set of checks against it. You can switch between **Vulnerable examples** and **Secure controls**, inspect request and response evidence, and retest the same fixture. It is designed for learning how specific behaviors differ; it is not a general-purpose website scanner.

[View the repository](https://github.com/robialexz/revenueguard-lab) or [download the v0.1.0 pre-release](https://github.com/robialexz/revenueguard-lab/releases/tag/v0.1.0).

## Quick start

You'll need Node.js 26 or newer. The app has no third-party runtime dependencies, and running it does not require `npm install`, an API key, a database server, or an internet connection.

```sh
git clone https://github.com/robialexz/revenueguard-lab.git
cd revenueguard-lab
node --version   # confirm v26 or newer
npm start
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765) in your browser. On first start, the app copies `scope.example.json` to `scope.json` and creates `data/revenueguard.sqlite` for local run history.

## Walk through vulnerable and secure profiles

1. In **Demo profile**, choose **Vulnerable examples**.
2. Select **Run local audit** and wait for the job to finish.
3. In **Latest findings**, choose **View evidence** to inspect what the check sent and received, along with the expected behavior, observed behavior, impact, and suggested remediation.

The fixture contains seven deterministic checks. Six are designed to reproduce a confirmed behavior in the vulnerable profile:

- A synthetic user can read another synthetic user's record, and an unauthenticated request can reach the synthetic admin panel.
- A fixed search canary returns more synthetic rows than an unmatched query. This is a filter-bypass demonstration, not SQL execution or a verified SQL injection.
- A fixed SVG marker is returned as unescaped HTML. The audit records the response; it does not open a browser to execute the marker, and arbitrary query text is escaped.
- A hard-coded marker for a fake private file is returned from an in-memory fixture. The check does not read a file from your computer.
- The same synthetic one-use discount can be redeemed twice.

The seventh check displays the fictional `RG-DEMO-001` dependency marker as **suspected** for cautious triage. It is not a real advisory, and the app does not download advisory data.

4. Change **Demo profile** to **Secure controls**.
5. Select **Retest findings**.

In the secure profile, the synthetic cross-user record request is denied, the admin route requires valid authorization, the search canary is treated literally, the HTML marker is escaped, the fake traversal is blocked, and a second use of the discount is rejected. The six confirmed fixture findings should no longer reproduce; the fictional dependency marker remains suspected.

A retest marks earlier confirmed findings as fixed only when every required check validates its expected safe behavior. A timeout, server error, missing route, or other unverified response is incomplete evidence, not proof of a fix. Even a complete secure-profile retest says something only about this bundled demo app.

## Reports stay local

Open a completed run from **Recent audit runs** to view its logs, or open its report. The lab provides technical, executive, and remediation report views; each includes a scope note and can be printed or saved as a PDF with **Print / Save as PDF**.

Run history, findings, evidence, and logs are stored in the local SQLite database at `data/revenueguard.sqlite`. Reports are examples for learning. They are not evidence about a real website, customer impact, or lost revenue.

## Safety boundary and current limits

The server binds to `127.0.0.1:8765`, checks the request host and local socket, and the audit uses a fixed loopback origin and fixed fixture paths. The scope guard accepts literal loopback addresses and approved paths, disables redirects, and applies a request budget and timeout. Adding another origin to `scope.json` does not redirect the audit.

All accounts, records, discounts, dependency data, and files are synthetic. The lab makes no external callbacks, real purchases, cloud AI calls, or live advisory lookups. It cannot target an arbitrary URL.

This pre-release does not scan a real application, import another project, inspect its dependencies, or patch source code. It also does not test session invalidation, password reset, CSRF, CORS, SSRF, uploads, command execution, or race conditions. Please use it as a local learning environment, not to scan public websites or systems you do not own and have explicit permission to test.

## Feedback and contributions

If you try the lab, I’d value specific feedback: which check was easiest or hardest to understand, whether the evidence and reports explain the result clearly, and what would make the local walkthrough more useful. Bug reports and contribution proposals are welcome; please read [CONTRIBUTING.md](https://github.com/robialexz/revenueguard-lab/blob/main/CONTRIBUTING.md) and [SECURITY.md](https://github.com/robialexz/revenueguard-lab/blob/main/SECURITY.md) first.

One project-status note: the repository currently has **no software license**. It is public so people can review it, but public visibility does not grant permission to reuse or redistribute the code. I’m not presenting it as open-source software while that remains unresolved.

Thanks for taking a look at this early preview.
