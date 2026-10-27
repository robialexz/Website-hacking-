# Security policy

## Safe use

RevenueGuard Lab is a local-only learning application. Its vulnerable routes under `/lab/` are a synthetic fixture; those results do not describe any other system. A separate optional HTTPS posture workflow makes bounded observations of exact HTTPS pages listed in local `scope.json`.

Use HTTPS posture observations only for exact pages that you own or are explicitly authorized to review, and only when a single unauthenticated GET to each page is safe. Before a run, the operator must attest to that authorization and safety. The attestation is not verification or proof of authorization. GET requests can still trigger side effects, so exclude state-changing, tokenized, confirmation, unsubscribe, and similar URLs.

The posture workflow is limited to one unauthenticated GET per exact scoped page. It does not crawl, follow links or redirects, use authentication, submit forms, or send payload probes. It is not an active vulnerability scan and does not establish that a site is secure. Do not change the loopback binding, fixed synthetic audit origin, or scope guard to enable active tests against public systems.

The app is intended for one local operator. It has no production multi-user accounts or tenant isolation; do not expose it to a network or present it as a hosted production scanning service.

The synthetic demo uses fake users and records, in-memory files, fixed input canaries, and a fictional dependency marker. It makes no external callbacks and performs no real purchases or file reads. The passive SEO/accessibility review is separate from both the synthetic demo and the HTTPS posture workflow.

## Reporting a defect in this project

If you find a security defect in RevenueGuard Lab itself, use GitHub's **Report a vulnerability** option if private vulnerability reporting is enabled for the repository. Otherwise, contact the repository owner through their GitHub profile before sharing exploit details publicly.

Please include the affected version or commit, the local steps to reproduce the issue, and the impact. Do not include credentials, real customer information, or details about an unrelated third-party target.

