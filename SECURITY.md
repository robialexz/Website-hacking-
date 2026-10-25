# Security policy

## Safe use

RevenueGuard Lab is intentionally restricted to a synthetic demo service on the local machine. The vulnerable routes under `/lab/` are part of the training fixture; their results do not describe any other system.

Do not use this project to test websites, networks, or accounts unless you own them and have explicit authorization. This release is not designed to accept external targets. Do not change its loopback binding, fixed audit origin, or scope guard to reach public systems.

The demo uses synthetic users and records, fake in-memory files, fixed input canaries, and a fictional dependency marker. It makes no external callbacks and performs no real purchases or file reads.

## Reporting a defect in this project

If you find a security defect in RevenueGuard Lab itself, use GitHub's **Report a vulnerability** option if private vulnerability reporting is enabled for the repository. Otherwise, contact the repository owner through their GitHub profile before sharing exploit details publicly.

Please include the affected version or commit, the local steps to reproduce the issue, and the impact. Do not include credentials, real customer information, or details about an unrelated third-party target.

