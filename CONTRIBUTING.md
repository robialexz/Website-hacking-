# Contributing

Thanks for helping improve RevenueGuard. It is a local single-operator baseline scanner plus separate synthetic training and local source-review workflows. Keep new scanner behavior bounded, explicitly scoped, and honest about what was and was not tested.

Before changing scan behavior, consider:

- Could the change contact a different origin, include credentials, follow a redirect, or trigger a state-changing GET?
- Are page, request, depth, time, response-body, and cancellation limits preserved?
- Are target paths, cookies, headers, and response bodies kept out of logs and reports unless they are explicitly safe to retain?
- Does coverage distinguish a clean observation from an untested or incomplete check?
- Are tests using injected transports or local fixtures instead of external targets?

Run the local verification suite with:

```sh
npm run verify
```

The test suite must not make live requests to public websites. Keep private scope files, databases, credentials, and target URLs out of pull requests.
