# The CI job for the web entry point

`.github/workflows/ci.yml` is not edited by this change. This is the job to
add to it, verbatim, after the existing `node-runtimes` job.

Nothing else in the workflow needs to move. The `node` matrix job already
covers the web build's correctness: `npm test` builds `dist/web/`,
type-checks it a second time with `tsconfig.web.json` (no `@types/node`, so a
stray `Buffer` or `node:` import fails there), and runs the parity suites that
put every shared fixture through both builds. This job is the other half —
proof that the build runs on runtimes that have no `node:crypto` at all.

```yaml
  # The /web entry point's runtime claims (README "WebCrypto-only
  # runtimes"): the built dist/web runs the same smoke on Node's WebCrypto,
  # on the Vercel Edge runtime (@edge-runtime/vm, a devDependency) and on
  # Cloudflare workerd configured with NO compatibility flags — the
  # configuration where node:crypto does not exist. workerd comes from npm
  # at a pinned version; bump the pin in node/package.json's
  # test:runtimes:web.
  node-runtimes-web:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0
        with:
          node-version: "22"
          package-manager-cache: false
      - run: npm ci && npm run test:runtimes:web
        working-directory: node
```

## Why it looks like this

- **No `permissions:` block.** The workflow-level `permissions: contents:
  read` already applies and this job needs nothing more, so adding one would
  only repeat it. Every other test job in the file does the same.
- **`persist-credentials: false`** on the checkout: nothing here pushes, and
  zizmor flags a credential-persisting checkout that does not need one.
- **Action SHAs pinned with the tag in a comment**, copied from the pins the
  rest of `ci.yml` already uses, so dependabot moves all of them together and
  a retagged `@v7` cannot change what runs.
- **`timeout-minutes: 15`**, the same budget as `node-runtimes`; the three
  runners together take well under a minute once `npx` has fetched workerd.
- **`npm ci`, not `npm install`**: the committed lockfile is the contract,
  and `@edge-runtime/vm` is in it.
- **No cache.** `package-manager-cache: false` matches the neighbouring
  jobs.
- **Node 22 rather than a matrix.** The Node version here is only the host
  for the three runners; the version matrix that matters for the library
  lives in the `node` job.
